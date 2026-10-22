"""CUW2026 engine services recovered statically; no implicit device or service I/O.

Native images are identity inputs only and are never loaded or executed.
"""

from __future__ import annotations

import configparser
import hashlib
import io
import json
import os
import re
import stat
import struct
import zipfile
from collections.abc import Callable, Mapping
from contextlib import contextmanager, nullcontext
from dataclasses import dataclass, field
from itertools import pairwise
from pathlib import Path, PurePosixPath
from threading import Event, Lock, get_ident
from time import monotonic
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scripts.calibration_2026 import NativeUSBSource2026
    from scripts.cuw_file_services import FileReadResult2026
    from scripts.cuw_large import LargeSource2026, NativeLargeContainer2026
    from scripts.programming_2026_common import NotificationBool

from scripts.cuw_services import (
    CompletionNotice,
    NoticeConfig,
    NoticeEvent,
    ReproKey,
    RKSAccess,
    RKSData,
    ServiceError,
    _cleanup,
    _Deadline,
    _text,
    _xml,
)
from scripts.j2534_2026 import J2534Device2026
from scripts.local_files import read_regular
from scripts.native_modules import NativeModuleIdentity, identify_native_module

MAX_BYTES = 64 * 1024 * 1024
MARKER = b"[datacompression]"
_RKS_SOFTWARE_TOKEN = object()
_GATEWAY_AUTH_TOKEN = object()


def _aes128_ecb_block(key: bytes, block: bytes) -> bytes:
    """15520/157c0 gateway use of the shared concrete AES128 ECB primitive."""
    from scripts.programming_2026_common import native_aes128_ecb_block

    return native_aes128_ecb_block(key, block)


@dataclass(frozen=True)
class GatewayAuthentication2026:
    engine_sha256: str
    _key: bytes = field(repr=False)
    _token: object = field(repr=False, compare=False)

    def __post_init__(self):
        if self._token is not _GATEWAY_AUTH_TOKEN:
            raise TypeError(
                "Gateway authentication requires authenticated CUW2026 bytes"
            )

    def calculate(self, seed: bytes) -> bytes:
        return _aes128_ecb_block(self._key, seed)


def gateway_authentication2026(engine_bytes: bytes) -> GatewayAuthentication2026:
    """1b700 mode0 private credential provenance; no literal credential in source."""
    identity = identity_2026(engine_bytes, "CUW.dll")
    pe = struct.unpack_from("<I", engine_bytes, 0x3C)[0]
    count, optional_size = (
        struct.unpack_from("<H", engine_bytes, pe + 6)[0],
        struct.unpack_from("<H", engine_bytes, pe + 20)[0],
    )
    section = pe + 24 + optional_size
    encoded = None
    for index in range(count):
        start = section + index * 40
        rva, size, offset = struct.unpack_from("<III", engine_bytes, start + 12)
        if rva <= 0x7ABF8 and 0x7ABF8 + 64 <= rva + size:
            encoded = engine_bytes[offset + 0x7ABF8 - rva : offset + 0x7ABF8 - rva + 64]
            break
    if encoded is None:
        raise ValueError("Authenticated gateway credential span is unmapped")
    decoded = bytes(
        ((((a >> 2 & 3) + (a >> 4) * 4) * 4 + (b >> 4) + 0x1E) * 4 + (b >> 2 & 3)) & 255
        for a, b in zip(encoded[::2], encoded[1::2])
    )
    if not re.fullmatch(b"[0-9a-fA-F]{32}", decoded):
        raise ValueError("Authenticated gateway credential encoding differs")
    return GatewayAuthentication2026(
        identity.sha256, bytes.fromhex(decoded.decode("ascii")), _GATEWAY_AUTH_TOKEN
    )


def gateway_wire2026(authentication: GatewayAuthentication2026, runtime) -> None:
    """CUW1b0f0 gateway wire sequence, using actual private AES context."""
    from scripts.programming_2026_common import CanDiag2026, NativeRuntime2026

    if (
        type(authentication) is not GatewayAuthentication2026
        or type(runtime) is not NativeRuntime2026
    ):
        raise TypeError("Concrete authenticated gateway context and runtime required")
    diag = CanDiag2026(runtime)
    request, response = bytes.fromhex("000007505f"), bytes.fromhex("000007585f")
    identifier = None
    configuration = {"ioctl": 2, "parameters": ((0x1E, 1),)}
    try:
        runtime.call_owned(
            "control_io", "control_io", release_values=configuration, **configuration
        )
        identifier = diag.start_filter(request, response)
        seed_response = diag.call(
            request, response, b"\x27\x4f", b"\x67\x4f", minimum=18, error_code=0x10
        )
        key = authentication.calculate(seed_response[2:18])
        runtime.call("wait", milliseconds=100)
        diag.call(
            request,
            response,
            b"\x27\x50" + key,
            b"\x67\x50\x34",
            minimum=3,
            error_code=0x11,
        )
        runtime.call("wait", milliseconds=100)
        for _ in range(3):
            diag.write(bytes.fromhex("00000720a027"))
            runtime.call("wait", milliseconds=100)
        diag.call(request, response, b"\x10\x02", b"\x50", minimum=1, error_code=0x32)
    finally:
        # Native1b2ab restores configuration before releasing its filter.
        try:
            if runtime.owns_resource("control_io", **configuration):
                runtime.release("control_io", **configuration)
        finally:
            if identifier is not None:
                runtime.release("stop_filter", identifier=identifier)


@dataclass(frozen=True)
class RKSSoftwareIdentity2026:
    """Private RKS.ini SoftwareID, not an operator-provided tester identifier."""

    source_sha256: str
    _software_id64: bytes | None = field(repr=False)
    _token: object = field(repr=False, compare=False)

    def __post_init__(self):
        if self._token is not _RKS_SOFTWARE_TOKEN:
            raise TypeError("RKS SoftwareID must originate from encoded RKS.ini")

    @property
    def software_id32(self) -> bytes:
        """Exact32-byte span read through59ab0's native SoftwareID pointer."""
        return self.software_id64[:32]

    @property
    def software_id64(self) -> bytes:
        """Writer43a0 reads32 bytes; the remaining compatibility bytes are unused."""
        if self._software_id64 is None:
            raise NotImplementedError(
                "Native SoftwareID32-byte span includes unrecovered heap memory"
            )
        return self._software_id64


def decode_rks_configuration2026(source: bytes) -> bytes:
    """1e6e0→1c420: decode known file bytes and its literal trailing zero."""
    if not isinstance(source, bytes) or len(source) > 1024 * 1024:
        raise ValueError("Bounded encoded RKS.ini bytes required")
    odd = len(source) % 2
    pairs = source + bytes(odd)
    decoded = bytes(
        (((a >> 2 & 3) + (a >> 4) * 4) * 4 + (b >> 4) + 0x1E) * 4 + (b >> 2 & 3) & 255
        for a, b in zip(pairs[::2], pairs[1::2])
    )
    if odd and b"\0" not in decoded:
        raise NotImplementedError(
            "Odd RKS.ini strlen requires unknown native heap bytes"
        )
    return decoded


def rks_software_identity2026(source: bytes) -> RKSSoftwareIdentity2026:
    """55490/1c420 source adapter for an initially empty RKS configuration."""
    decoded = decode_rks_configuration2026(source).split(b"\0", 1)[0]
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    try:
        parser.read_string(decoded.decode("latin1"))
    except configparser.Error:
        raise ValueError("Malformed private RKS.ini configuration") from None
    if parser.defaults():
        raise ValueError("RKS.ini inherited default fields are unsupported")
    required = (
        "IFVersion",
        "SoftwareID",
        "SoftwareVersion",
        "LicenseKey",
        "SUBARU_LicenseKey",
        "SUZUKI_LicenseKey",
        "DAIHATSU_LicenseKey",
        "VehicleIdentificationNumber",
        "RequesterKind",
        "KeypairID",
        "DAIHATSU_KeypairID",
    )
    if not parser.has_section("ReproKeyRequest") or any(
        not parser.get("ReproKeyRequest", name, fallback="") for name in required
    ):
        raise ValueError("All eleven native RKS request fields must be nonempty")
    value = parser.get("ReproKeyRequest", "SoftwareID").encode("latin1")
    version = parser.get("ReproKeyRequest", "SoftwareVersion").encode("latin1")
    span = None
    if len(value) >= 31:
        # >=32 supplies every copied byte;31 supplies31 bytes plus its terminator.
        span = value[:64].ljust(64, b"\0")
    elif len(value) <= 15 and len(version) <= 15:
        # 54f50 zero-initializes both adjacent MSVC strings.59ab0 passes the
        # SoftwareID c_str directly;43a0 reads32 bytes across its SSO object.
        span = (
            value.ljust(16, b"\0")
            + struct.pack("<II", len(value), 15)
            + version[:8].ljust(8, b"\0")
            + bytes(32)
        )
    return RKSSoftwareIdentity2026(
        hashlib.sha256(source).hexdigest(), span, _RKS_SOFTWARE_TOKEN
    )


class CUWEngineError(ValueError):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class EngineConfiguration2026:
    arguments: bytes = field(repr=False)
    cpu_maximum: int
    scalar_a: float
    scalar_b: float
    flags: tuple[int, int, int]
    zero_counters: tuple[tuple[int, ...], ...]
    unresolved_cpu_indices: tuple[int, ...]
    unresolved_source_indices: tuple[tuple[int, ...], ...]
    cpu_flags: tuple[bool, ...]
    source_cpu_flags: tuple[tuple[bool, ...], ...]


def configure_2026(
    arguments: bytes, *, calibration_loaded: bool = False
) -> EngineConfiguration2026:
    """ConfigureCUWDLL@32 actual stack layout and shared-buffer initialization.

    Two DWORDs are unused by the recovered body; exact argument bytes retain them.
    The doubles remain uninterpreted until their consumers establish their meaning.
    """
    if (
        not isinstance(arguments, bytes)
        or len(arguments) != 32
        or type(calibration_loaded) is not bool
    ):
        raise ValueError("Exact32-byte CUW configuration arguments required")
    maximum, _, first, second, flags, _ = struct.unpack("<IIddII", arguments)
    if calibration_loaded:
        raise CUWEngineError(7, "Cannot configure CUW after loading calibration")
    if not 1 <= maximum <= 4096:
        raise ValueError("CPU maximum exceeds host allocation bound")
    zero, unresolved, cleared = (0,) * maximum, (-1,) * maximum, (False,) * maximum
    return EngineConfiguration2026(
        arguments,
        maximum,
        first,
        second,
        (flags & 255, flags >> 8 & 255, flags >> 16 & 255),
        (zero,) * 4,
        unresolved,
        (unresolved,) * 16,
        cleared,
        (cleared,) * 16,
    )


def native_vin(data: bytes) -> bytes:
    """SetVIN@4 checks input length first, then stops at NUL,0xFF or question mark."""
    if not isinstance(data, bytes) or len(data) > 4096:
        raise ValueError("Bounded native VIN bytes required")
    value = data.split(b"\0", 1)[0]
    if len(value) > 17:
        raise CUWEngineError(0x1773, "Native VIN exceeds17 bytes")
    for index, byte in enumerate(value):
        if byte in (0xFF, 0x3F):
            return value[:index]
    return value


def id_conversion_rows(data: bytes, count: int) -> tuple[tuple[int, bytes], ...] | None:
    """SetIDConversionDatas@8:21-byte source rows,4-byte hex prefix and ID at+9.

    Count0 deliberately means no mutation, preserving the prior conversion table.
    Native strtol accepts a partial/empty hexadecimal prefix; retain that behavior.
    """
    if (
        type(count) is not int
        or not 0 <= count <= 4096
        or not isinstance(data, bytes)
        or len(data) != count * 21
    ):
        raise ValueError("Exact bounded21-byte ID conversion rows required")
    if count == 0:
        return None
    rows = []
    for offset in range(0, len(data), 21):
        match = re.match(
            rb"[\t\n\v\f\r ]*([+-]?)(?:0[xX])?([0-9a-fA-F]+)", data[offset : offset + 4]
        )
        number = int(match[2], 16) * (-1 if match[1] == b"-" else 1) if match else 0
        tail = data[offset + 9 : offset + 21]
        end = tail.find(b"\0")
        if end < 0:
            raise ValueError("Native ID conversion row lacks bounded terminator")
        rows.append((number & 0xFFFF, tail[: min(end, 11)]))
    return tuple(rows)


@dataclass(frozen=True)
class NativeContinuationBackup2026:
    """3c410's engine-owned alternate status fields and four copied vectors."""

    progress_base: int
    current_cpu: int
    cpu_offset: int
    cycle: bool
    elapsed_ms: tuple[int, ...]
    counts: tuple[int, ...]
    percentages: tuple[int, ...]
    error_counts: tuple[int, ...]


@dataclass(frozen=True)
class EngineStatus2026:
    """Source-named CUW2026 globals consumed by actual public status branches.

    These are observations from the controller, never a provider's success flag.
    Status-only evaluation does not start or finish a programming operation.
    """

    phase: int = 0  # DAT_1008cfb8
    error: int = 0  # DAT_1008cfc8
    fatal: bool = False  # DAT_1008cfd0
    receiving: bool = False  # DAT_1008cfe2
    receiving_prompt: bool = False  # DAT_1008d2a0
    complete: bool = False  # DAT_1008d34c
    battery_cycle: bool = False  # DAT_1008d348, alternate DAT_1008dad4
    recovery_status: int = 0  # FUN_100344a0(...,1)
    key_handle: bool = False  # DAT_1008d3e8
    key_state: int = 0  # DAT_1008d3ec
    configured_authorization: bool = False  # DAT_1008db1c
    contact_type: str = ""  # calibration+1c -> metadata+a0, FUN_10019840

    def __post_init__(self):
        for name in ("phase", "error", "recovery_status", "key_state"):
            value = getattr(self, name)
            if type(value) is not int or not -(2**31) <= value < 2**31:
                raise ValueError("Signed32-bit native engine status required")
        for name in (
            "fatal",
            "receiving",
            "receiving_prompt",
            "complete",
            "battery_cycle",
            "key_handle",
            "configured_authorization",
        ):
            if type(getattr(self, name)) is not bool:
                raise ValueError("Boolean native engine status required")
        if not isinstance(self.contact_type, str) or len(self.contact_type) > 128:
            raise ValueError("Bounded native contact type required")

    def receiving_status(self) -> tuple[int, bool]:
        """1005f1b0 result and whether native calls its error-cleanup helper."""
        if self.error == 2:
            return 0xFA4, False
        if self.fatal:
            return 0x7D2, True
        if self.phase != 0:
            return 0x138B, False
        if self.receiving:
            return 1, False
        if self.receiving_prompt:
            return 2, False
        return (0x138C, True) if self.error != 0 else (0, False)

    def receiving_result_status(self) -> int:
        """Both1005f7c0 and1005f910 guard their result arrays with this condition."""
        return 0x138D if self.phase == 0 and (self.receiving or self.error != 0) else 0

    def reprogramming_status(self) -> tuple[int, bool]:
        """1005dea0 status decision; output-array marshalling is a separate contract."""
        if self.fatal:
            result = 0x7D2
        elif self.phase in (0, 4) and not self.complete:
            result = 0xBBA
        elif self.key_handle and self.key_state:
            result = 3
        elif self.error == 0x60:
            result = 0x1B64
        elif self.recovery_status == 2:
            result = 0xBBC
        elif self.recovery_status == 1:
            result = 0x238C if self.error == 0x408 else 0xBBB
        elif self.recovery_status != 0:
            result = 0xBBA
        elif self.battery_cycle:
            result = 2
        elif self.complete:
            result = 0
        else:
            result = (
                4
                if (
                    not self.receiving
                    and self.configured_authorization
                    and self.contact_type in ("P5-Unified", "Phase6", "Ethernet")
                )
                else 1
            )
        return result, result in (0x7D2, 0xBBC, 0xBBB)

    def key_request_status(self) -> int:
        """100643d0 preserves native key-state priority and unknown-state result."""
        if not self.key_handle or not self.key_state:
            return 0x1B5A
        return {
            1: 2,
            2: 1,
            3: 1,
            4: 3,
            5: 4,
            6: 0x1B63,
            7: 0x1B5C,
            8: 0x1B62,
            9: 0x1B5D,
            10: 0x1B5B,
        }.get(self.key_state, 0x1B5A)

    def clear_status_allowed(self, force: bool, *, controller_mode: int) -> bool:
        """Exact10064240 gate before native status-clear mutation."""
        if type(force) is not bool or type(controller_mode) is not int:
            raise ValueError("Native force flag and controller mode required")
        return controller_mode == 1 or not (
            self.receiving
            or (
                not force
                and not self.complete
                and self.phase not in (0, 4)
                and not self.fatal
            )
        )


def identity_2026(data: bytes, name: str) -> NativeModuleIdentity:
    if not isinstance(data, bytes) or not 0 < len(data) <= MAX_BYTES:
        raise ValueError("Bounded immutable module bytes required")
    identity = identify_native_module(hashlib.sha256(data).hexdigest(), name)
    if identity.cuw_builds != ("2026",):
        raise ValueError("Exact CUW2026 identity required")
    return identity


_DH_STATE_TOKEN = object()


class DHControllerState2026:
    """Engine-created native DH state; completed progress cannot be supplied."""

    def __init__(self, token, identity, metadata, maximum, *, engine=None):
        from scripts.calibration_2026 import native2026_global_cpu_index

        if token is not _DH_STATE_TOKEN or type(engine) is not CUWEngine2026:
            raise TypeError("DH state must originate from a loaded CUW2026 engine")
        self._engine = engine
        self.engine_sha256 = identity.sha256
        self.metadata = metadata
        self.source_sha256 = metadata.source_sha256
        self.node, self.selection_cpu_index = metadata.node, metadata.cpu_index
        self.cpu_index = self.global_cpu_index = native2026_global_cpu_index(metadata)
        self._progress: tuple[int, ...] = (0,) * maximum
        self._transferred_bytes: tuple[int, ...] = (0,) * maximum
        self._dh_flash_size: int | None = None
        self._getter_stage = 0
        self._writable_cid = False
        self._alternate_can_address = False
        self._central_gateway_type = 0
        self._error_kind = self._primary_error = self._passthru_error = 0
        self._notification: NotificationBool | None = None
        self._native_comm_phase = 0
        self._divided_image_index = 0
        self._native_context_964 = False
        self._use_new_password = False
        self._wait_remaining_ms = 0
        self._write_complete = False
        self._flashing_ended = False

    @property
    def engine(self):
        if self._engine.dh_state is not self:
            raise ValueError("Native state is no longer bound to its engine")
        return self._engine

    @property
    def native_cpu_index(self) -> int:
        """Ordered358 progress index; global_cpu_index remains parser-facing."""
        engine = self.engine
        if engine._worker is None:
            return self.global_cpu_index
        return engine.worker.source_state.current_global_cpu_index

    def native_index_for_source_cpu(self, index: int) -> int:
        """Map an actual parser CPU to its issued native progress-array position."""
        from scripts.calibration_2026 import native2026_cpu_values

        native2026_cpu_values(self.metadata, index)
        engine = self.engine
        if engine._worker is None:
            return index
        return engine.worker.native_index_for_source_cpu(index)

    @property
    def notification(self):
        if self._notification is None:
            raise ValueError("Configure source-bound CUW persistence before writing")
        return self._notification

    @property
    def programming_active(self) -> bool:
        return bool(self.notification)

    @property
    def comm_phase(self) -> int:
        return self._native_comm_phase

    @property
    def use_new_password(self) -> bool:
        return self._use_new_password

    @property
    def wait_remaining_ms(self) -> int:
        return self._wait_remaining_ms

    def set_wait_remaining_ms(self, value: int) -> None:
        if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
            raise ValueError("Native unsigned countdown milliseconds required")
        self._wait_remaining_ms = value

    @property
    def write_complete(self) -> bool:
        return self._write_complete

    def set_write_complete(self, value: bool) -> None:
        if type(value) is not bool:
            raise TypeError("Native write-complete Boolean required")
        self._write_complete = value

    @property
    def flashing_ended(self) -> bool:
        return self._flashing_ended

    def set_flashing_ended(self, value: bool) -> None:
        if type(value) is not bool:
            raise TypeError("Native per-call flashing-ended Boolean required")
        self._flashing_ended = value

    def set_use_new_password(self, value: bool) -> None:
        if type(value) is not bool:
            raise TypeError("Native password-selection Boolean required")
        self._use_new_password = value

    def mark_flash_code_failed(self) -> None:
        """DHUDS native fault writes1 to context+978 (communication phase)."""
        self._native_comm_phase = 1

    @property
    def divided_image_index(self) -> int:
        return self._divided_image_index

    def advance_divided_image(self, expected: int) -> None:
        cpu = self.metadata.cpu
        files = cpu.files if cpu is not None else ()
        if (
            self.global_cpu_index != 0
            or type(expected) is not int
            or expected != self._divided_image_index
            or not 0 <= expected < len(files)
        ):
            raise ValueError("Bounded actualCPU0 divided-image transition required")
        self._divided_image_index += 1

    def reset_divided_image(self) -> None:
        self._divided_image_index = 0

    def resume_divided_image_count(self) -> None:
        """DHUDS2120 adds completed Format4 images without changing percent."""
        from scripts.calibration_2026 import native2026_archive

        cpu = self.metadata.cpu
        if (
            self.metadata.format_version != 4
            or self.global_cpu_index != 0
            or cpu is None
            or not cpu.files
            or not 0 <= self._divided_image_index < len(cpu.files)
        ):
            raise ValueError("Actual CPU0 Format4 divided-image resume required")
        total = native2026_archive(self.metadata).flash_size
        remaining = tuple(
            native2026_archive(self.metadata, file_index=index).flash_size
            for index in range(1, len(cpu.files))
        )
        first = total - sum(remaining)
        if first < 0:
            raise ValueError("Native divided-image lengths exceed aggregate size")
        prefix = sum((first, *remaining)[: self._divided_image_index])
        self._transferred_bytes = (
            (self._transferred_bytes[0] + prefix) & 0xFFFFFFFF,
            *self._transferred_bytes[1:],
        )

    def notify_divided_image(self) -> None:
        from scripts.cuw_persistence import CUWPersistence

        notification = self.notification
        owner = notification.context
        if type(owner) is not CUWPersistence or owner.notification is not notification:
            raise ValueError(
                "Actual CUW persistence handler must own divided-image state"
            )
        owner.update_divided_image(self._divided_image_index)

    def record_uds_transfer(self, count: int) -> None:
        from scripts.calibration_2026 import native2026_archive

        if type(count) is not int or not 0 <= count <= 0xFFFFFFFF:
            raise ValueError("Native unsigned acknowledged transfer count required")
        total = native2026_archive(self.metadata).flash_size
        if not 0 < total <= 0xFFFFFFFF:
            raise ValueError("Positive source-bound native flash size required")
        index = self.native_cpu_index
        transferred = (self._transferred_bytes[index] + count) & 0xFFFFFFFF
        counts, percentages = list(self._transferred_bytes), list(self._progress)
        counts[index], percentages[index] = (
            transferred,
            (100 * transferred // total) & 0xFFFFFFFF,
        )
        self._transferred_bytes, self._progress = tuple(counts), tuple(percentages)

    def reset_usb_progress(self) -> None:
        self._progress = (0, *self._progress[1:])

    def complete_usb_progress(self, response: bytes) -> None:
        if type(response) is not bytes or not response.startswith(b"\x5a\xb1\x00"):
            raise ValueError("Actual native USB5ab100 completion response required")
        self._progress = (100, *self._progress[1:])

    @property
    def native_context_964(self) -> bool:
        return self._native_context_964

    def mark_native_retry(self) -> None:
        """Concrete native error/recovery paths set engine+3c0, never a JSON flag."""
        self._native_context_964 = True

    def _set_native_vector(self, field: str, cpu_index: int, value: int) -> None:
        from scripts.calibration_2026 import native2026_cpu_count

        if (
            type(cpu_index) is not int
            or not 0 <= cpu_index < native2026_cpu_count(self.metadata)
            or type(value) is not int
            or not 0 <= value <= 0xFFFFFFFF
        ):
            raise ValueError("Source-bound global CPU index and native DWORD required")
        values = list(getattr(self, field))
        values[cpu_index] = value
        setattr(self, field, tuple(values))

    def set_native_count(self, cpu_index: int, value: int) -> None:
        """Concrete family math mutates the native count before its observer."""
        self._set_native_vector("_transferred_bytes", cpu_index, value)

    def set_native_percentage(self, cpu_index: int, value: int) -> None:
        """Native DWORD percentages may exceed100; they do not certify completion."""
        self._set_native_vector("_progress", cpu_index, value)

    @property
    def progress(self) -> tuple[int, ...]:
        return self._progress

    @property
    def transferred_bytes(self) -> tuple[int, ...]:
        return self._transferred_bytes

    def reset_dh_count(self) -> None:
        """CommonFlash4080 mutation, performed before the count notification."""
        values = list(self._transferred_bytes)
        values[self.native_cpu_index] = 0
        self._transferred_bytes = tuple(values)

    def reset_dh_progress(self) -> None:
        """CommonFlash4080 mutation, performed before the percent notification."""
        values = list(self._progress)
        values[self.native_cpu_index] = 0
        self._progress = tuple(values)

    def record_dh_transfer(
        self, count: int, offset: int, total: int, *, verification: bool, checksum: bool
    ) -> None:
        """DH2070 stores bytes/progress only after the concrete76 reply succeeds.

        Progress100 can precede later native exit/verification failure. It is
        therefore an observation, never a claim of completed programming.
        """
        from scripts.calibration_2026 import native2026_archive

        if (
            any(type(value) is not int for value in (count, offset, total))
            or not 0 <= count <= 0xFFFFFFFF
            or not 0 <= offset <= total <= 0xFFFFFFFF
            or total == 0
            or type(verification) is not bool
            or type(checksum) is not bool
        ):
            raise ValueError("Bounded native DH transfer fields required")
        flash_size = self._dh_flash_size
        if flash_size is None:
            flash_size = native2026_archive(self.metadata).flash_size
        if total != flash_size:
            raise ValueError("DH transfer total differs from bound native flash size")
        progress = 100 * offset // total
        if not checksum:
            progress = progress // 2 + (50 if verification else 0)
        counts, percentages = list(self._transferred_bytes), list(self._progress)
        index = self.native_cpu_index
        counts[index] = (counts[index] + count) & 0xFFFFFFFF
        percentages[index] = progress
        self._dh_flash_size = flash_size
        self._transferred_bytes, self._progress = tuple(counts), tuple(percentages)

    def _gateway_transfer(self, offset: int, total: int) -> None:
        from scripts.calibration_2026 import (
            native2026_archive,
            native2026_metadata_for_cpu,
        )

        if (
            type(offset) is not int
            or type(total) is not int
            or not 0 <= offset <= total <= 0xFFFFFFFF
            or total == 0
            or total
            != native2026_archive(
                native2026_metadata_for_cpu(self.metadata, 0)
            ).flash_size
        ):
            raise ValueError("Gateway transfer requires bound globalCPU0 flash size")

    def record_gateway_count(self, offset: int, total: int) -> None:
        """Gateway1070 stores the offset before invoking its count observer."""
        self._gateway_transfer(offset, total)
        self._transferred_bytes = (offset, *self._transferred_bytes[1:])

    def record_gateway_progress(self, offset: int, total: int) -> None:
        """Gateway1070 stores percent after the count observer returns."""
        self._gateway_transfer(offset, total)
        self._progress = (100 * offset // total, *self._progress[1:])

    def record_multirom_transfer(self, count: int, binding) -> None:
        """MultiROM1970 uses both decimal EachWriteDataSize entries, not flash size."""
        from scripts.programming_2026_common import NativeParameterBinding2026

        if (
            type(binding) is not NativeParameterBinding2026
            or binding.module_name != "TCUWCanDHMultiROMFlashWriter.dll"
            or binding.metadata != self.metadata
            or type(count) is not int
            or not 0 <= count <= 0xFFFFFFFF
        ):
            raise ValueError("Actual selected MultiROM parameter binding required")
        fields = binding.lines("EachWriteDataSize")
        if len(fields) != 2:
            raise ValueError("Exactly two native MultiROM partition lengths required")
        sizes = []
        for value in fields:
            parsed = re.match(r"\s*([+-]?[0-9]+)", value)
            if parsed is None or not 0 < int(parsed[1]) <= 0x7FFFFFFF:
                raise ValueError(
                    "Positive signed native MultiROM decimal length required"
                )
            sizes.append(int(parsed[1]))
        total = sum(sizes)
        transferred = self._transferred_bytes[0] + count
        if total > 0xFFFFFFFF or transferred > total:
            raise ValueError("MultiROM transfer exceeds source-bound partition lengths")
        self._transferred_bytes = (transferred, *self._transferred_bytes[1:])
        self._progress = (100 * transferred // total, *self._progress[1:])

    @property
    def getter_stage(self) -> int:
        return self._getter_stage

    @property
    def writable_cid(self) -> bool:
        return self._writable_cid

    @property
    def alternate_can_address(self) -> bool:
        return self._alternate_can_address

    @property
    def central_gateway_type(self) -> int:
        return self._central_gateway_type

    @property
    def error_kind(self) -> int:
        return self._error_kind

    @property
    def primary_error(self) -> int:
        return self._primary_error

    @property
    def passthru_error(self) -> int:
        return self._passthru_error

    def record_native_error(
        self, kind: int | None, primary: int, passthru: int | None = None
    ) -> None:
        """Preserve native catch fields; getter catches leave the kind unchanged."""
        values = [primary]
        if kind is not None:
            values.append(kind)
        if passthru is not None:
            values.append(passthru)
        if any(
            type(value) is not int or not 0 <= value <= 0xFFFFFFFF for value in values
        ):
            raise ValueError("Native error fields must be unsigned DWORDs")
        if kind is not None:
            self._error_kind = kind
        self._primary_error = primary
        if passthru is not None:
            self._passthru_error = passthru

    def set_central_gateway_type(self, value: int) -> None:
        if type(value) is not int or value not in (1, 2):
            raise ValueError("Native DH gateway type must be1 or2")
        self._central_gateway_type = value

    def advance_getter_stage(self, expected: int, following: int) -> None:
        """Called by concrete getters after their actual verified stage succeeds."""
        if (
            type(expected) is not int
            or type(following) is not int
            or self._getter_stage != expected
            or not 0 <= expected < 4
            or following != expected + 1
        ):
            raise ValueError("Invalid native DH getter stage transition")
        self._getter_stage = following

    def mark_writable_cid(self) -> None:
        self._writable_cid = True


class SuzukiControllerState2026:
    """Persistent typCUWData+a5c; a nonzero value is not programming success."""

    def __init__(self, token, identity, metadata, *, error_state=None):
        from scripts.calibration_2026 import native2026_global_cpu_index

        if token is not _DH_STATE_TOKEN:
            raise TypeError("Suzuki state must originate from a loaded CUW2026 engine")
        self.engine_sha256 = identity.sha256
        self.metadata = metadata
        self.source_sha256 = metadata.source_sha256
        self.node, self.selection_cpu_index = metadata.node, metadata.cpu_index
        self.cpu_index = self.global_cpu_index = native2026_global_cpu_index(metadata)
        self._value = 0
        self._error_state = error_state

    @property
    def error_kind(self) -> int:
        return self._bound_errors().error_kind

    @property
    def primary_error(self) -> int:
        return self._bound_errors().primary_error

    @property
    def passthru_error(self) -> int:
        return self._bound_errors().passthru_error

    def _bound_errors(self) -> DHControllerState2026:
        if type(self._error_state) is not DHControllerState2026:
            raise ValueError("Engine-owned native error storage is not bound")
        return self._error_state

    @property
    def notification(self):
        return self._bound_errors().notification

    def record_native_error(
        self, kind: int | None, primary: int, passthru: int | None = None
    ) -> None:
        self._bound_errors().record_native_error(kind, primary, passthru)

    @property
    def value(self) -> int:
        return self._value

    @property
    def native_context_964(self) -> bool:
        return self._bound_errors().native_context_964

    def compare_prepare_cid(self, current_cid: bytes, readback_cid: bytes) -> None:
        """Actual SuzukiPrepare32f0 byte-string comparison, after native reads."""
        if any(
            not isinstance(value, bytes) or len(value) > 4096 or b"\0" in value
            for value in (current_cid, readback_cid)
        ):
            raise ValueError("Bounded native CID strings required")
        self._value = int(current_cid != readback_cid)

    def clear_after_prepare_fault(self) -> None:
        """SuzukiPrepare3eb9 restores0 after failed identifier reads."""
        self._value = 0

    def mark_usb_retry_fault(self) -> None:
        """USBFlash158c assigns2 after exhausted native reset retries."""
        self._value = 2


class DCMGetterState2026:
    """A view of the engine's actual59ab0 imported identifier/contact buffers."""

    def __init__(self, token, engine):
        if token is not _DH_STATE_TOKEN:
            raise TypeError("DCM getter state requires a loaded native engine phase")
        self._engine = engine
        self._metadata = engine.native_metadata

    @property
    def metadata(self):
        return self._metadata

    def validate_current(self) -> None:
        self._engine._require_owned_phase()
        if self._engine.native_metadata != self._metadata:
            raise ValueError("DCM context target changed after binding")

    @property
    def first_identifier_record(self) -> bytes:
        return self._engine._working_identifier_records[0]

    @property
    def contact_buffer(self) -> bytes:
        return self._engine._working_contact_buffer

    @property
    def progress(self) -> tuple[int, ...]:
        return self._engine.dh_state.progress

    def apply_success(self) -> None:
        from scripts.programming_2026_p6 import dcmprl_getter_host_records

        self.validate_current()
        first, contact = dcmprl_getter_host_records(
            self.first_identifier_record,
            self.contact_buffer,
            first_cpu_percent=self.progress[0],
            prl=self._engine.native_metadata.vehicle.get("kindofecu", "") == "8",
        )
        records = self._engine._working_identifier_records
        self._engine._working_identifier_records = (first, *records[1:])
        self._engine._working_contact_buffer = contact


class CUWEngine2026:
    """Source-bound synchronous phase host; native whole-engine closure is pending.

    Only the concrete replay implementation can execute a phase. Its selected
    module and CUW input are checked before any recorded native action occurs.
    A completed phase is deliberately never promoted to completed programming.
    """

    def __init__(
        self,
        engine_bytes: bytes,
        *,
        common_definitions=None,
        persistence=None,
        general_parameters=None,
    ):
        from scripts.programming_2026_common import (
            CommonDefinitions2026,
            NativeGeneralParameters2026,
        )

        if common_definitions is None:
            common_definitions = CommonDefinitions2026()
        elif type(common_definitions) is not CommonDefinitions2026:
            raise TypeError("Concrete CUW2026 CommonDefinitions required")
        self.identity = identity_2026(engine_bytes, "CUW.dll")
        self._gateway_authentication = gateway_authentication2026(engine_bytes)
        from scripts.programming_2026_common import NativeCentralGatewayKey2026

        self._central_gateway_key = NativeCentralGatewayKey2026.from_native_module(
            engine_bytes
        )
        self.common_definitions = common_definitions
        if (
            general_parameters is not None
            and type(general_parameters) is not NativeGeneralParameters2026
        ):
            raise TypeError("Concrete native General parser parameters required")
        self._general_parameters = general_parameters
        self._issued_sil_transfer = None
        self.configuration: EngineConfiguration2026 | None = None
        self._source: bytes | None = None
        self._large_container: NativeLargeContainer2026 | None = None
        self._owned_large_containers: dict[int, NativeLargeContainer2026] = {}
        self._owned_usb_sources = {}
        self._metadata = None
        self._dh_state: DHControllerState2026 | None = None
        self._suzuki_state: SuzukiControllerState2026 | None = None
        self._lock = Lock()
        self._phase_state_lock = Lock()
        self._cancelled = Event()
        self._phase_finished = Event()
        self._phase_finished.set()
        self._active = False
        self._phase_thread: int | None = None
        self._worker_phase: int | None = None
        self._repro_gateway_node = 0
        self._gateway_classifier_cache = 0
        self._native_error_output = (0, 0)
        self._native_fatal_output = False
        self._native_control_fatal_output = False
        self._write_complete_output = False
        self._native_cycle_output = False
        self._continuation_backup = None
        self._native_prepare_handshake = 0
        self._logical_block_index = 0
        self._native_error_kind_output = 0
        self._native_previous_error_kind_output = 0
        self._worker = None
        self._interface_pair = None
        self._thread_job = None
        self._worker_replacement_thread = None
        self._controller_execution = None
        self._retry_controller = None
        self._frontend_parameters = None
        self._file_sources = None
        self._native_delta_active = False
        self._file_read_region = 0
        self._file_logger = None
        self._diagnostic_context = 0
        self._cid_selection_initialized = False
        self._worker_target_sources = {}
        self._pending_worker_cid_selection = None
        self._prepare_prefix_owner = None
        self._cleanup_controller = None
        self._cleanup_retired_dh_state = None
        self._gateway_startup = None
        self._vin = b""
        self._online_modal_state = 0
        self._online_controller = None
        self._shrink_flag = False
        self._rks_configuration = None
        self._identifier_records: tuple[bytes, ...] = ()
        self._received_identifiers: tuple[bytes, ...] = ()
        self._received_hardware = b""
        self._working_hardware = b""
        self._identifier_context_epoch = 0
        self._last_completed_standalone_getter = None
        self._working_identifier_records: tuple[bytes, ...] = ()
        self._working_contact_buffer = bytes(33)
        self._persistence = None
        if persistence is not None:
            self.bind_persistence(persistence)

    def _validate_persistence_source(
        self, metadata, *, state_snapshot=None, file_sources=None
    ) -> None:
        from scripts.calibration_2026 import (
            NativeUSBSource2026,
            native2026_global_cpu_index,
        )
        from scripts.cuw_large import LargeSource2026
        from scripts.cuw_persistence import ReproInfoState, calibration_source_identity

        if self._persistence is None:
            return
        self._persistence.validate_engine_owner(self)
        state = self._persistence.state if state_snapshot is None else state_snapshot
        if type(state) is not ReproInfoState:
            raise TypeError("Concrete native recovery state snapshot required")
        state.validate()
        sources = self._file_sources if file_sources is None else file_sources
        associated = sources is not None and any(
            item.source_container is metadata.source_container
            for item in (*sources.files, *sources.output_files)
        )
        if associated:
            self._persistence.validate_file_source_association(
                sources, metadata, state_snapshot=state
            )
        else:
            index = state.calibration_file_index
            if (
                not 0 <= index < len(state.calibrations)
                or calibration_source_identity(state.calibrations[index].source_bytes)[
                    1
                ]
                != metadata.source_sha256
            ):
                raise ValueError("Persistence calibration bytes differ from loaded CUW")
            source = state.calibrations[index].source_bytes
            if (
                type(source) is LargeSource2026
                and source.container is not metadata.source_container
            ) or (
                type(source) is NativeUSBSource2026
                and source is not metadata.source_container
            ):
                raise ValueError(
                    "Persistence streamed source differs from the engine-owned container"
                )
        expected_cpu = native2026_global_cpu_index(metadata)
        if self._worker is not None:
            expected_cpu = self.worker.source_state.current_global_cpu_index
        if state.write_cpu_index != expected_cpu:
            raise ValueError(
                "Persistence current CPU differs from the actual engine target"
            )

    def validate_persistence_binding(self, persistence, *, state_snapshot=None) -> None:
        if persistence is not self._persistence:
            raise ValueError("Persistence is not bound to this actual engine")
        if self._metadata is None:
            # Constructor binding reserves the owner; source validation waits for
            # load, and notification writes remain forbidden before that load.
            raise ValueError("Load CUW before validating persistence source")
        self._validate_persistence_source(
            self.native_metadata, state_snapshot=state_snapshot
        )

    def bind_general_parameters(self, parameters) -> None:
        from scripts.programming_2026_common import NativeGeneralParameters2026

        if type(parameters) is not NativeGeneralParameters2026:
            raise TypeError("Concrete native General parser parameters required")
        if not self._lock.acquire(blocking=False):
            raise ValueError("CUW phase is active")
        try:
            if self._metadata is not None:
                raise ValueError("Bind parser parameters before loading calibration")
            self._general_parameters = parameters
            if (
                self._frontend_parameters is not None
                and self._frontend_parameters.general != parameters
            ):
                self._frontend_parameters = None
        finally:
            self._lock.release()

    def _parser_profile(self, metadata):
        from scripts.calibration_2026 import native2026_with_parser_parameters

        historical = metadata.format_version < 101 and metadata.format_version not in (
            10,
            12,
        )
        if self._general_parameters is None:
            if historical:
                raise ValueError(
                    "Historical native CUW parsing requires actual General parameters"
                )
            return metadata
        return native2026_with_parser_parameters(metadata, self._general_parameters)

    def bind_persistence(self, persistence) -> None:
        from scripts.cuw_persistence import CUWPersistence

        if type(persistence) is not CUWPersistence:
            raise TypeError("Concrete CUW recovery persistence required")
        if not self._lock.acquire(blocking=False):
            raise ValueError("CUW phase is active")
        previous = self._persistence
        try:
            if previous is not None and previous is not persistence:
                raise ValueError("CUW persistence cannot be replaced across phases")
            self._persistence = persistence
            if self._metadata is not None:
                self._validate_persistence_source(self._metadata)
                persistence.bind_engine_source(self)
                self.dh_state._notification = persistence.notification
        except (Exception, KeyboardInterrupt):
            self._persistence = previous
            raise
        finally:
            self._lock.release()

    def begin_file_read(self, region_one_based: int, *, mode: int = 1) -> None:
        """5ccf0 sets the log context/region and conditionally runs38880."""
        if type(region_one_based) is not int or not 1 <= region_one_based <= 4:
            raise ValueError("Native public one-based region must be1..4")
        if type(mode) is not int:
            raise TypeError("Native file-read mode integer required")
        if not self._lock.acquire(blocking=False):
            raise ValueError("CUW phase is active")
        try:
            self._diagnostic_context = 300
            self._file_read_region = region_one_based - 1
            if (
                mode == 1
                and not self._cid_selection_initialized
                and self._persistence is not None
            ):
                self._persistence.delete_recovery()
        finally:
            self._lock.release()

    @property
    def file_sources(self):
        return self._file_sources

    def set_log_function(self, logger) -> None:
        """65390 retains the issued CUW log function or native NULL."""
        from scripts.cuw_file_services import validate_file_logger_2026

        if logger is not None:
            validate_file_logger_2026(logger, self)
        self._file_logger = logger

    def emit_file_log(self, identifier: int, value: bytes) -> None:
        """Emit through the installed native file logger and actual context300."""
        logger = self._file_logger
        if logger is not None:
            logger.emit(self._diagnostic_context, identifier, value)

    def read_reprogramming_data_file(
        self,
        source: bytes | LargeSource2026 | NativeUSBSource2026,
        mode: int,
        region: int,
        caller_header: bytes,
        caller_cpus: tuple[bytes, ...],
        *,
        date_formatter: Callable[[tuple[int, int, int]], bytes] | None = None,
        source_name: str = "input.cuw",
        source_files: Mapping[str, bytes] | None = None,
        cancelled: Callable[[], bool] = lambda: False,
    ) -> FileReadResult2026:
        """Dispatch1005ccf0 through the concrete source-issued FILE wrapper."""
        from scripts.cuw_file_services import read_reprogramming_data_file_2026

        return read_reprogramming_data_file_2026(
            self,
            source,
            mode,
            region,
            caller_header,
            caller_cpus,
            date_formatter=date_formatter,
            source_name=source_name,
            source_files=source_files,
            cancelled=cancelled,
        )

    @property
    def native_delta_active(self) -> bool:
        """DATdab4 starts false at30be0 and46010 sets it without38880 reset."""
        return self._native_delta_active

    def bind_file_sources(self, sources):
        """Commit only141's source-issued43ee0/46010 FILE set, without reparsing."""
        from scripts.calibration_2026 import NativeUSBSource2026, native2026_cpu_count
        from scripts.cuw_file_services import validate_file_sources_2026
        from scripts.cuw_large import NativeLargeContainer2026

        validate_file_sources_2026(sources, self)
        if not self._lock.acquire(blocking=False):
            raise ValueError("CUW phase is active")
        try:
            if self.configuration is None:
                raise ValueError("Configure CUW before binding native FILE sources")
            if self._worker is not None:
                raise ValueError(
                    "Finish and release the native worker before replacing FILE sources"
                )
            if any(
                native2026_cpu_count(item) > self.configuration.cpu_maximum
                for item in sources.files
            ):
                raise ValueError("FILE CPU count exceeds configured native capacity")
            metadata = sources.selected_metadata
            if any(
                self._parser_profile(item) != item
                for item in (*sources.files, *sources.output_files)
            ):
                raise ValueError(
                    "Issued FILE parser parameters differ from the current engine source"
                )
            previous = self._large_container
            previous_fields = (
                self._source,
                self._metadata,
                self._dh_state,
                self._suzuki_state,
                self._large_container,
                self._file_sources,
                self._shrink_flag,
                self._native_delta_active,
                dict(self._worker_target_sources),
            )
            scope = (
                nullcontext()
                if self._persistence is None
                else self._persistence._file_source_binding(sources)
            )
            try:
                with scope:
                    self._validate_persistence_source(metadata, file_sources=sources)
                    state = DHControllerState2026(
                        _DH_STATE_TOKEN,
                        self.identity,
                        metadata,
                        self.configuration.cpu_maximum,
                        engine=self,
                    )
                    suzuki = SuzukiControllerState2026(
                        _DH_STATE_TOKEN, self.identity, metadata, error_state=state
                    )
                    if self._persistence is not None:
                        state._notification = self._persistence.notification
                    self._source, self._metadata = sources.selected_source, metadata
                    if type(metadata.source_container) is NativeLargeContainer2026:
                        self._source = None
                    elif type(metadata.source_container) is NativeUSBSource2026:
                        self._source = metadata.source_container.raw
                    self._dh_state, self._suzuki_state = state, suzuki
                    self._large_container = (
                        metadata.source_container
                        if type(metadata.source_container) is NativeLargeContainer2026
                        else None
                    )
                    self._file_sources = sources
                    if sources.delta_archive:
                        self._native_delta_active = True
                    self._worker_target_sources.clear()
                    self._shrink_flag = metadata.initial_shrink_flag
                    if self._persistence is not None:
                        self._persistence.bind_engine_source(self)
            except BaseException:
                (
                    self._source,
                    self._metadata,
                    self._dh_state,
                    self._suzuki_state,
                    self._large_container,
                    self._file_sources,
                    self._shrink_flag,
                    self._native_delta_active,
                    self._worker_target_sources,
                ) = previous_fields
                raise
            if self._large_container is not None:
                self._owned_large_containers[id(self._large_container)] = (
                    self._large_container
                )
            usb = (
                metadata.source_container
                if type(metadata.source_container) is NativeUSBSource2026
                else None
            )
            if usb is not None:
                self._owned_usb_sources[id(usb)] = usb
            self._close_unselected_usb_sources(usb)
            if previous is not None and previous is not self._large_container:
                previous.close()
                self._owned_large_containers.pop(id(previous), None)
            return metadata
        finally:
            self._lock.release()

    def _accept_worker_file_reset(self, old_sources, new_sources, *, worker) -> None:
        """4b900 commits only141's exact replacement issued for this worker."""
        from scripts.calibration_2026 import (
            native2026_cpu_count,
            native2026_global_cpu_index,
        )
        from scripts.cuw_file_services import validate_file_reset_2026

        self._require_owned_phase()
        if worker is not self.worker or old_sources is not self._file_sources:
            raise ValueError("Actual current FILE owner and worker required")
        validate_file_reset_2026(old_sources, new_sources, worker)
        metadata = new_sources.selected_metadata
        if (
            self.configuration is None
            or native2026_cpu_count(metadata) > self.configuration.cpu_maximum
        ):
            raise ValueError("Replacement FILE exceeds configured native CPU capacity")
        if self._parser_profile(metadata) != metadata:
            raise ValueError(
                "Replacement FILE parser parameters differ from engine source"
            )
        self._file_sources = new_sources
        self._source, self._metadata = new_sources.selected_source, metadata
        index = native2026_global_cpu_index(metadata)
        for state in (self.dh_state, self.suzuki_state):
            state.metadata = metadata
            state.source_sha256 = metadata.source_sha256
            state.node, state.selection_cpu_index = metadata.node, metadata.cpu_index
            state.cpu_index = state.global_cpu_index = index
        self.dh_state._dh_flash_size = None
        self._issued_sil_transfer = None
        self._shrink_flag = metadata.initial_shrink_flag
        worker._file_reset_selected(new_sources)
        self.bind_cleanup_controller().accept_file_reset(old_sources, new_sources)

    def file_general_boolean(self, metadata, name: str) -> bool:
        """5ccf0 reads global General for an actual current/issued output FILE."""
        from scripts.programming_2026_common import NativeCallbackLookupError

        if name not in ("EngineTypeFlag", "FlagToOutputAllAttachedInformation"):
            raise ValueError("Actual public-file General Boolean required")
        candidates = (
            () if self._file_sources is None else self._file_sources.output_files
        )
        if metadata is not self._metadata and not any(
            metadata is item for item in candidates
        ):
            raise ValueError("Actual bound FILE metadata required")
        if self._general_parameters is None:
            raise NativeCallbackLookupError()
        from scripts.calibration_2026 import native2026_cpu_values

        return self._general_parameters.boolean_with_keys(
            metadata.vehicle.get("kindofecu", ""),
            native2026_cpu_values(metadata, 0).get("cputype", ""),
            metadata.vehicle.get("contacttype", ""),
            name,
        )

    @property
    def frontend_parameters(self):
        if self._frontend_parameters is not None:
            self._frontend_parameters.validate_source()
        return self._frontend_parameters

    def bind_frontend_parameters(self, parameters) -> None:
        """34050 binds the literal frontend tables independently of family rows."""
        from scripts.programming_2026_common import NativeFrontendParameters2026

        if type(parameters) is not NativeFrontendParameters2026:
            raise TypeError("Concrete native frontend parameter source required")
        parameters.validate_source()
        if not self._lock.acquire(blocking=False):
            raise ValueError("CUW phase is active")
        try:
            if self._worker is not None and parameters is not self._frontend_parameters:
                raise ValueError(
                    "Bind frontend sources before issuing the native worker"
                )
            if self._general_parameters is None:
                if self._metadata is not None:
                    raise ValueError(
                        "Bind global frontend parameters before loading CUW"
                    )
                self._general_parameters = parameters.general
            elif self._general_parameters != parameters.general:
                raise ValueError(
                    "Frontend General differs from the engine-owned source"
                )
            self._frontend_parameters = parameters
        finally:
            self._lock.release()

    def calibration_type(self, cpu_index: int) -> int:
        """34680's actual global-table lookup for the public CPU output DWORD."""
        from scripts.calibration_2026 import (
            native2026_cpu_values,
            native2026_node_index,
            native2026_node_values,
        )
        from scripts.programming_2026_common import NativeCallbackLookupError

        owned = self._active and self._phase_thread == get_ident()
        if not owned and not self._lock.acquire(blocking=False):
            raise ValueError("CUW phase is active")
        try:
            metadata = self.native_metadata
            native2026_cpu_values(metadata, cpu_index)
            contact = metadata.vehicle.get("contacttype", "")
            if contact in ("P5-Unified", "Phase6", "Ethernet"):
                if self._frontend_parameters is None:
                    raise NativeCallbackLookupError()
                self._frontend_parameters.validate_source()
                node = native2026_node_values(
                    metadata, native2026_node_index(metadata, cpu_index)
                )
                ethernet = contact == "Ethernet"
                table = self._frontend_parameters.parameter(
                    "LogicalAddressTable.ini" if ethernet else "CanIDTable.ini"
                )
                key = node.get("logicaladdress" if ethernet else "diagid", "")
                value = table.long_with_keys("CalibrationType", key, "", "")
                if value is None:
                    raise NativeCallbackLookupError()
                return value
            if self._general_parameters is None:
                raise NativeCallbackLookupError()
            # 34680 uses the first raw CPUType for the historical General lookup.
            return self._general_parameters.long_with_keys(
                metadata.vehicle.get("kindofecu", ""),
                native2026_cpu_values(metadata, 0).get("cputype", ""),
                contact,
                "CalibrationType",
            )
        finally:
            if not owned:
                self._lock.release()

    @property
    def rks_configuration(self):
        """The single54f50/55490 configuration shared by native consumers."""
        from scripts.cuw_online import NativeRKSConfiguration2026

        with self._phase_state_lock:
            if self._rks_configuration is None:
                self._rks_configuration = NativeRKSConfiguration2026(self)
            return self._rks_configuration

    def load_rks_configuration(self, source: bytes) -> RKSSoftwareIdentity2026:
        """55490 keeps all previous globals when a native import returns false."""
        if not self._lock.acquire(blocking=False):
            raise ValueError("CUW phase is active")
        try:
            store = self.rks_configuration
            store.load(source)
            return store.software_identity
        finally:
            self._lock.release()

    @property
    def rks_software_identity(self) -> RKSSoftwareIdentity2026:
        return self.rks_configuration.software_identity

    @property
    def source_container(self):
        return self.native_metadata.source_container

    @property
    def persistence(self):
        return self._persistence

    @property
    def vin(self) -> bytes:
        return self._vin

    def set_vin(self, data: bytes) -> bytes:
        """63990 copies the actual SetVIN bytes into engine and recovery state."""
        from dataclasses import replace

        value = native_vin(data)
        owned = self._active and self._phase_thread == get_ident()
        if not owned and not self._lock.acquire(blocking=False):
            raise ValueError("CUW phase is active")
        try:
            if self._persistence is not None:
                candidate = replace(self._persistence.state, vin=value.decode("latin1"))
                candidate.validate()
                self._persistence.state.vin = candidate.vin
            self._vin = value
            return value
        finally:
            if not owned:
                self._lock.release()

    @property
    def online_modal_state(self) -> int:
        return self._online_modal_state

    def _publish_online_modal(self, controller, state: int) -> None:
        """Only the actual bound113 controller publishes native engine+43c."""
        from scripts.cuw_online import OnlineKeyController2026

        if type(controller) is not OnlineKeyController2026:
            raise TypeError("Concrete native online controller required")
        if type(state) is not int or not 0 <= state <= 10:
            raise ValueError("Native online modal state0..10 required")
        worker = self.worker
        if controller.worker is not worker or worker.engine is not self:
            raise ValueError("Online controller belongs to another engine worker")
        if (
            self._online_controller is not None
            and self._online_controller is not controller
            and self._online_controller.request_status != 0x1B5A
        ):
            raise ValueError("Another native online request is active")
        self._online_controller = controller
        self._online_modal_state = state

    @property
    def thread_job(self):
        return self._thread_job

    def bind_thread_job(self, controller):
        """Issue145's concrete outer/child native-thread owner."""
        from scripts.cuw_engine_threads import _issue_engine_thread_job

        self.bind_worker(controller)
        if not self._lock.acquire(blocking=False):
            raise ValueError("CUW phase is active")
        try:
            if self._thread_job is not None and self._thread_job.state.stop_requested:
                return self._reissue_thread_job_locked(controller, self._thread_job)
            job = _issue_engine_thread_job(self, controller)
            if self._thread_job is not None and self._thread_job is not job:
                raise ValueError("Another native thread owner is already bound")
            self._thread_job = job
            return job
        finally:
            self._lock.release()

    def _reissue_thread_job_locked(self, controller, old_job):
        """Recreate59070 only after the real5f030 worker deletion boundary."""
        from scripts.cuw_engine_threads import _issue_engine_thread_job
        from scripts.cuw_engine_worker import (
            _finalize_engine_worker_replacement,
            _replace_engine_worker,
            _rollback_engine_worker_replacement,
        )
        from scripts.cuw_online import OnlineKeyController2026

        old_job.validate_owner(self, controller)
        if (
            self._active
            or self.native_phase != 0
            or not self.native_cancelled()
            or old_job.native_worker_exists
            or old_job.host_stop_requested
            or not old_job.state.stop_requested
        ):
            raise ValueError("Actual completed native CID stop required for reissue")
        old = self.worker
        if old.source_state.continuation_pending:
            raise ValueError("Finish the actual worker continuation before reissue")
        owners = []
        online = controller.runtime.bound_online_controller2026()
        for owner in (
            self._cleanup_controller,
            self._retry_controller,
            self._gateway_startup,
            self._online_controller,
            online,
        ):
            if owner is None or any(owner is item for item in owners):
                continue
            if owner.worker is not old:
                if type(owner) is OnlineKeyController2026 and owner.closed:
                    continue
                raise ValueError(
                    "Worker-dependent native owner differs from the current worker"
                )
            owners.append(owner)
        if self._retry_controller is not None and self._retry_controller.query_pending:
            raise ValueError("Finish the native retry query before worker reissue")
        self._worker_replacement_thread = get_ident()
        replacement = None
        pending_selection = self._pending_worker_cid_selection
        try:
            replacement = _replace_engine_worker(self, controller, old)
            if pending_selection is not None:
                if pending_selection[0] is not old:
                    raise ValueError("Pending CID selection belongs to another worker")
                self._pending_worker_cid_selection = (
                    replacement,
                    *pending_selection[1:],
                )
            for owner in owners:
                owner.rebind_worker(old, replacement)
            self._thread_job = None
            job = _issue_engine_thread_job(self, controller)
            self._thread_job = job
            _finalize_engine_worker_replacement(self, old, replacement)
            return job
        except BaseException as error:
            self._thread_job = old_job
            self._pending_worker_cid_selection = pending_selection
            if replacement is not None:
                try:
                    _rollback_engine_worker_replacement(self, old, replacement)
                except BaseException as cleanup_error:  # noqa: BLE001 - retain the original transaction failure
                    error.add_note("Worker rollback: " + type(cleanup_error).__name__)
                for owner in reversed(owners):
                    if owner.worker is replacement:
                        try:
                            owner.rebind_worker(replacement, old)
                        except BaseException as cleanup_error:  # noqa: BLE001 - finish every owner rollback
                            error.add_note(
                                "Owner rollback: " + type(cleanup_error).__name__
                            )
            raise
        finally:
            self._worker_replacement_thread = None

    @property
    def interface_pair(self):
        """The authenticated48 engine/control interface pair, if bound."""
        if self._interface_pair is not None:
            self._interface_pair.validate_views()
        return self._interface_pair

    def bind_interface_pair(self, pair) -> None:
        """Bind distinct native CFE8 and ControlCommPhase J2534 views."""
        from scripts.j2534_2026 import J2534InterfacePair2026

        if type(pair) is not J2534InterfacePair2026:
            raise TypeError("Concrete source-issued J2534 interface pair required")
        pair.validate_views()
        owned = self._active and self._phase_thread == get_ident()
        if not owned and not self._lock.acquire(blocking=False):
            raise ValueError("CUW phase is active")
        try:
            if self._interface_pair is not None and self._interface_pair is not pair:
                raise ValueError("Another native J2534 interface pair is already bound")
            if self._worker is not None and (
                pair.control is not self._worker.controller.runtime_device()
            ):
                raise ValueError("Pair control view differs from the actual controller")
            self._interface_pair = pair
        finally:
            if not owned:
                self._lock.release()

    def engine_runtime_device(self) -> J2534Device2026:
        """Return CFE8 only from the actual bound engine/control pair."""
        pair = self.interface_pair
        if pair is None:
            raise ValueError("Bind the distinct native J2534 interface pair first")
        if self._worker is not None and (
            pair.control is not self._worker.controller.runtime_device()
        ):
            raise ValueError("Actual paired ControlCommPhase worker required")
        return pair.engine

    def bind_worker(self, controller):
        """Issue one exact native worker for the loaded source/controller pair."""
        from scripts.cuw_engine_worker import _issue_engine_worker

        owned = self._active and self._phase_thread == get_ident()
        if not owned and not self._lock.acquire(blocking=False):
            raise ValueError("CUW phase is active")
        try:
            if self._interface_pair is not None:
                self._interface_pair.validate_views()
                if self._interface_pair.control is not controller.runtime_device():
                    raise ValueError(
                        "Bound pair control differs from the actual controller"
                    )
            worker = _issue_engine_worker(self, controller)
            worker.validate_source(self)
            self._worker = worker
            if self._cleanup_controller is None:
                from scripts.cuw_engine_cleanup import _issue_engine_cleanup

                self._cleanup_controller = _issue_engine_cleanup(self, worker)
            return worker
        finally:
            if not owned:
                self._lock.release()

    @property
    def worker(self):
        if self._worker is None:
            raise ValueError("Bind the actual CUW engine worker before this operation")
        self._worker.validate_source(self)
        return self._worker

    @property
    def source_sha256(self) -> str | None:
        return self._metadata.source_sha256 if self._metadata is not None else None

    @property
    def native_metadata(self):
        if self._metadata is None:
            raise ValueError("Load CUW2026 before obtaining current calibration state")
        return self._metadata

    @property
    def notification(self):
        """The shared native engine+3a0 Boolean for every programming family."""
        self._validate_persistence_source(self.native_metadata)
        return self.dh_state.notification

    @property
    def last_block_notification(self):
        self._validate_persistence_source(self.native_metadata)
        if self._persistence is None:
            raise ValueError(
                "Configure actual CUW persistence before changing last-block state"
            )
        return self._persistence.last_block_notification

    def make_sil_transfer(self, selection):
        from scripts.programming_2026_common import NativeParameterBinding2026
        from scripts.programming_2026_sil import SILTransferState2026

        self._require_owned_phase()
        if (
            type(selection) is not NativeParameterBinding2026
            or selection.metadata != self.native_metadata
        ):
            raise ValueError("Actual SIL selection must match current engine target")
        state = self.dh_state

        def signed(value):
            return value if value < 0x80000000 else value - 0x100000000

        if self._worker_phase == 2:
            writing = bool(self.notification)
            last_block = bool(self.last_block_notification)
        else:
            writing = (
                bool(self.notification) if self._persistence is not None else False
            )
            last_block = (
                bool(self.last_block_notification)
                if self._persistence is not None
                else False
            )
        transfer = SILTransferState2026(
            use_new_password=state.use_new_password,
            writing=writing,
            last_block=last_block,
            error=signed(state.primary_error),
            j2534_error=signed(state.passthru_error),
            status=signed(state.error_kind),
            wait_end_ms=state.wait_remaining_ms,
            reset_requested=state.native_context_964,
            metadata_state=self.native_metadata,
            engine=self,
        )

        def observe(name, value):
            self._require_owned_phase()
            if name == "writing":
                self.notification.assign(value)
            elif name == "last_block":
                self.last_block_notification.assign(value)
            elif name == "wait_end_ms":
                state.set_wait_remaining_ms(value)
            self.apply_sil_transfer(transfer)

        transfer.observer = observe
        self._issued_sil_transfer = transfer
        return transfer

    def apply_sil_transfer(self, transfer) -> None:
        from scripts.programming_2026_sil import SILTransferState2026

        self._require_owned_phase()
        if (
            type(transfer) is not SILTransferState2026
            or transfer is not self._issued_sil_transfer
            or transfer.engine is not self
            or transfer.metadata_state != self.native_metadata
        ):
            raise TypeError("Engine-issued SIL transfer required")
        transfer.validate()
        state = self.dh_state
        state.record_native_error(
            transfer.status & 0xFFFFFFFF,
            transfer.error & 0xFFFFFFFF,
            transfer.j2534_error & 0xFFFFFFFF,
        )
        state._use_new_password = transfer.use_new_password
        state._native_context_964 = transfer.reset_requested
        state.set_wait_remaining_ms(transfer.wait_end_ms)

    def make_sil_progress(self, selection):
        from scripts.calibration_2026 import native2026_archive
        from scripts.programming_2026_common import NativeParameterBinding2026
        from scripts.programming_2026_sil import SILProgress2026

        self._require_owned_phase()
        if (
            type(selection) is not NativeParameterBinding2026
            or selection.metadata != self.native_metadata
        ):
            raise ValueError("Actual SIL selection must match current engine target")
        state, index = self.dh_state, self.dh_state.native_cpu_index

        def observe(name, value):
            self._require_owned_phase()
            if self._issued_sil_transfer is not None:
                self.apply_sil_transfer(self._issued_sil_transfer)
            if name == "count":
                state.set_native_count(index, value)
            elif name == "percent":
                state.set_native_percentage(index, value)
            else:
                raise ValueError("Unknown native SIL progress field")

        archive = native2026_archive(self.native_metadata)
        size = archive.flash_size
        if selection.module_name == "TCUWSilHINOFlashWriterForAMT.dll":
            if archive.data is None:
                raise ValueError("Actual materialized HINO DATA archive required")
            size = len(archive.data)
        elif (
            selection.module_name == "TCUWSilDCMPRLFlashWriter.dll"
            and self.native_metadata.cpu.values.get("cputype", "") == "34"
        ):
            size = 4356
        return SILProgress2026(
            size,
            count=state.transferred_bytes[index],
            percent=state.progress[index],
            observer=observe,
        )

    @property
    def comm_phase(self) -> int:
        return self.dh_state.comm_phase

    def set_comm_phase(self, value: int, *, controller) -> None:
        from scripts.programming_2026_common import ControlCommPhase2026

        if (
            type(controller) is not ControlCommPhase2026
            or type(value) is not int
            or value not in (0, 1, 2, 3)
        ):
            raise ValueError("Actual native controller communication phase required")
        owned = self._active and self._phase_thread == get_ident()
        if not owned and not self._lock.acquire(blocking=False):
            raise ValueError("CUW phase is active")
        try:
            self.dh_state._native_comm_phase = value
        finally:
            if not owned:
                self._lock.release()

    def metadata_for(self, node: int, cpu_index: int):
        """Reselect an actual CPU while retaining native CPU/target mutations."""
        from scripts.calibration_2026 import (
            native2026_global_cpu_index,
            native2026_metadata,
            native2026_metadata_for_cpu,
        )

        current = self.native_metadata
        if current.runtime_projection is not None:
            if type(node) is not int or type(cpu_index) is not int or cpu_index < 0:
                raise ValueError("Actual rebuilt node and local CPU index required")
            indices = tuple(
                index
                for index, node_index in enumerate(current.cpu_node_indices)
                if node_index + 1 == node
            )
            if cpu_index >= len(indices):
                raise ValueError("CPU is absent from the rebuilt native node")
            return native2026_metadata_for_cpu(current, indices[cpu_index])
        selector = native2026_metadata(
            current.source_container,
            node=node,
            cpu_index=cpu_index,
            region=current.region,
        )
        return native2026_metadata_for_cpu(
            current, native2026_global_cpu_index(selector)
        )

    @property
    def continuation_backup(self) -> NativeContinuationBackup2026 | None:
        return self._continuation_backup

    def _begin_continuation_backup(self, *, worker) -> None:
        """3c410 captures actual fields before publishing DAC4's active byte."""
        self._require_owned_phase()
        if worker is not self.worker:
            raise ValueError("Actual current native worker required")
        if self._continuation_backup is not None:
            raise ValueError("Native continuation backup is already active")
        state = worker.source_state
        errors = self.bind_cleanup_controller().state.vectors.get(0xD33C, ())
        self._continuation_backup = NativeContinuationBackup2026(
            state.progress_base,
            state.current_global_cpu_index,
            state.cpu_offset,
            self.native_cycle_output,
            state.phase_elapsed_ms,
            self.dh_state.transferred_bytes,
            self.dh_state.progress,
            tuple(errors),
        )

    def _end_continuation_backup(self, *, worker) -> None:
        """3c5b0 clears the alternate fields and their copied vectors."""
        self._require_owned_phase()
        if worker is not self.worker:
            raise ValueError("Actual current native worker required")
        self._continuation_backup = None

    def _resume_worker_logical_cpu(self, *, worker, retry):
        """3ffa0 consumes only its issued option byte and actual logical CPU state."""
        from scripts.calibration_2026 import (
            NativeLogicalResume2026,
            native2026_global_cpu_index,
            native2026_is_logical_cpu,
            native2026_logical_resume_cpu,
            native2026_metadata_for_cpu,
        )

        self._require_owned_phase()
        if worker is not self.worker:
            raise ValueError("Actual current native worker required")
        self._validate_retry_controller(retry)
        metadata = self.native_metadata
        index = native2026_global_cpu_index(metadata)
        if not native2026_is_logical_cpu(metadata, index):
            raise ValueError("Native logical resume requires the actual19710 predicate")
        if retry.source_state.native_option_eb48:
            result = native2026_logical_resume_cpu(metadata, index)
            metadata = result.metadata
            index, size = result.remapped_cpu_index, result.calculated_flash_size
        else:
            if not metadata.logical_blocks:
                raise ValueError(
                    "Native logical resume requires the selected node blocks"
                )
            index, size = metadata.logical_blocks[0].cpu_index, 0
        metadata = native2026_metadata_for_cpu(metadata, index)
        self._worker_target_sources[id(metadata.source_container)] = metadata
        self._metadata = metadata
        for state in (self.dh_state, self.suzuki_state):
            state.metadata = metadata
            state.source_sha256 = metadata.source_sha256
            state.node, state.selection_cpu_index = metadata.node, metadata.cpu_index
            state.cpu_index = state.global_cpu_index = index
        self.dh_state._dh_flash_size = None
        self._issued_sil_transfer = None
        return NativeLogicalResume2026(metadata, index, size)

    def _select_received_worker_cids(self, *, worker):
        """34e10 retains authored matches without running the later3e710 rebuild."""
        from scripts.calibration_2026 import native2026_match_received_cids

        self._require_owned_phase()
        if worker is not self.worker:
            raise ValueError("Actual current native worker required")
        if self.configuration is None or self._general_parameters is None:
            raise ValueError("Bound native configuration and General required")
        self._cid_selection_initialized = True
        result = native2026_match_received_cids(
            self.native_metadata,
            self.received_identifiers,
            self.identifier_records,
            self._general_parameters,
            configuration=self.configuration,
            shrink_flag=self.shrink_flag,
            received_hardware=self.received_hardware,
        )
        if not result.check_target:
            self._pending_worker_cid_selection = None
            return None
        self._pending_worker_cid_selection = (
            worker,
            result,
            self.native_metadata,
        )
        return result

    def _apply_worker_cid_selection(self, result, *, worker):
        """36800 applies3e710 after34e10 has retained its authored selection."""
        from scripts.calibration_2026 import (
            native2026_cid_rebuild_allowed,
            native2026_metadata_for_cpu,
            native2026_rebind_cid_match,
            native2026_rebuild_received_cids,
            native2026_unrebuilt_selection,
        )

        self._require_owned_phase()
        pending = self._pending_worker_cid_selection
        if (
            worker is not self.worker
            or self._worker_phase not in (1, 2)
            or pending is None
            or pending[0] is not worker
            or pending[1] is not result
            or pending[2] is not result.metadata
        ):
            raise ValueError("Actual pending34e10 selection required at36800")
        result = native2026_rebind_cid_match(result, self.native_metadata)
        if not native2026_cid_rebuild_allowed(self.native_metadata):
            selected = native2026_unrebuilt_selection(result)
            self._pending_worker_cid_selection = None
            return selected
        result = native2026_rebuild_received_cids(
            self.native_metadata, result, self._general_parameters
        )
        current = worker.source_state.current_global_cpu_index
        metadata = native2026_metadata_for_cpu(result.rebuilt_metadata, current)
        assert self.configuration is not None
        if len(result.ordered_to_authored) > self.configuration.cpu_maximum:
            raise ValueError("Native rebuilt CPU vector exceeds configured capacity")
        self._worker_target_sources[id(metadata.source_container)] = metadata
        self._metadata = metadata
        for state in (self.dh_state, self.suzuki_state):
            state.metadata = metadata
            state.source_sha256 = metadata.source_sha256
            state.node, state.selection_cpu_index = metadata.node, metadata.cpu_index
            state.cpu_index = state.global_cpu_index = current
        self.dh_state._dh_flash_size = None
        self._issued_sil_transfer = None
        self._pending_worker_cid_selection = None
        return result

    def _select_worker_rebuilt_cpu(self, index: int, *, worker) -> None:
        """36800 tail substitutes actual D30C only when numeric D308 is zero."""
        from scripts.calibration_2026 import native2026_metadata_for_cpu

        self._require_owned_phase()
        if worker is not self.worker or self._worker_phase not in (1, 2):
            raise ValueError("Actual preparing worker required for CPU offset")
        source = worker.source_state
        if (
            type(index) is not int
            or source.current_global_cpu_index != 0
            or index != source.cpu_offset
        ):
            raise ValueError("Native zero-current CPU and issued D30C offset required")
        metadata = native2026_metadata_for_cpu(self.native_metadata, index)
        self._metadata = metadata
        self._worker_target_sources[id(metadata.source_container)] = metadata
        for state in (self.dh_state, self.suzuki_state):
            state.metadata = metadata
            state.source_sha256 = metadata.source_sha256
            state.node, state.selection_cpu_index = metadata.node, metadata.cpu_index
            state.cpu_index = state.global_cpu_index = index
        self.dh_state._dh_flash_size = None
        self._issued_sil_transfer = None

    def _append_worker_target(self, metadata, cpu_index: int, *, worker):
        """3e710 appends only47's image-derived current target using owned General."""
        from scripts.calibration_2026 import (
            native2026_append_current_target,
            native2026_global_cpu_index,
            native2026_metadata_for_cpu,
        )
        from scripts.programming_2026_common import NativeCallbackLookupError

        self._require_owned_phase()
        if worker is not self.worker or not (
            metadata is self._metadata
            or any(metadata is item for item in worker.loaded_metadata)
        ):
            raise ValueError("Actual worker-owned FILE metadata required")
        if self._general_parameters is None:
            raise NativeCallbackLookupError()
        updated, target_index = native2026_append_current_target(
            metadata, cpu_index, self._general_parameters
        )
        self._worker_target_sources[id(metadata.source_container)] = updated
        if metadata.source_container is self.native_metadata.source_container:
            selected = native2026_metadata_for_cpu(
                updated, native2026_global_cpu_index(self.native_metadata)
            )
            self._metadata = selected
            self.dh_state.metadata = self.suzuki_state.metadata = selected
            self._issued_sil_transfer = None
        return updated, target_index

    def general_parameter_boolean(
        self, kind: str, cpu: str, contact: str, name: str, *, controller=None
    ) -> bool:
        """Slot19/58580 reads the actual bound global Parameter.ini, throwing2."""
        from scripts.programming_2026_common import (
            ControlCommPhase2026,
            NativeCallbackLookupError,
        )

        if controller is None:
            self._require_owned_phase()
        elif type(controller) is not ControlCommPhase2026:
            raise TypeError("Concrete native controller parameter caller required")
        else:
            _ = self.native_metadata
        if self._general_parameters is None:
            raise NativeCallbackLookupError()
        return self._general_parameters.boolean_with_keys(kind, cpu, contact, name)

    def bind_gateway_startup(self):
        """Retain the concrete134 source producer and its actual CUW AES binding."""
        from scripts.cuw_gateway_startup import _issue_gateway_startup

        owned = self._active and self._phase_thread == get_ident()
        if not owned and not self._lock.acquire(blocking=False):
            raise ValueError("CUW phase is active")
        try:
            worker = self.worker
            worker.runtime.bind_central_gateway_key(self._central_gateway_key)
            if self._gateway_startup is None:
                self._gateway_startup = _issue_gateway_startup(self, worker)
            self._gateway_startup.validate_owner(self, worker)
            return self._gateway_startup
        finally:
            if not owned:
                self._lock.release()

    def bind_cleanup_controller(self):
        """135's actual resource owner exists from worker issuance onward."""
        if self._cleanup_controller is None:
            raise ValueError("Bind the actual engine worker before native cleanup")
        self._cleanup_controller.validate_owner(self, self._worker)
        return self._cleanup_controller

    def _validate_cleanup_controller(self, cleanup) -> None:
        from scripts.cuw_engine_cleanup import EngineCleanup2026

        if (
            type(cleanup) is not EngineCleanup2026
            or cleanup is not self._cleanup_controller
        ):
            raise ValueError("Actual source-issued engine cleanup required")
        cleanup.validate_owner(self, self._worker)

    def _apply_cleanup_retry_decision(self, cleanup) -> None:
        """405c3 clears399 before waking a pending retry; it preserves39a."""
        self._validate_cleanup_controller(cleanup)
        with self._phase_state_lock:
            self._write_complete_output = False

    def _cleanup_wait_for_worker(self, cleanup) -> None:
        """Join145's issued threads, then confirm the actual phase unwind."""
        self._validate_cleanup_controller(cleanup)
        with self._phase_state_lock:
            if self._active and self._phase_thread == get_ident():
                raise ValueError("Native worker cannot join itself during cleanup")
            finished = self._phase_finished
            self._cancelled.set()
        runtime = cleanup.worker.runtime
        if self._thread_job is not None:
            while True:
                try:
                    self._thread_job.stop_native(timeout=min(0.05, runtime.check()))
                    break
                except TimeoutError:
                    runtime.check()
        while not finished.wait(min(0.05, runtime.check())):
            pass
        runtime.check()

    def _delete_cleanup_file_source(self, cleanup, metadata) -> None:
        self._validate_cleanup_controller(cleanup)
        container = metadata.source_container
        usb = self._owned_usb_sources.get(id(container))
        if usb is container:
            container.close()
            del self._owned_usb_sources[id(container)]
        owned = self._owned_large_containers.get(id(container))
        if owned is container:
            container.close()
            del self._owned_large_containers[id(container)]
            if self._large_container is container:
                self._large_container = None

    def _delete_cleanup_target(self, cleanup) -> None:
        """40580 deletes the selected CFE4 target at its literal resource slot."""
        self._validate_cleanup_controller(cleanup)
        self._cleanup_retired_dh_state = self._dh_state
        self._metadata = self._source = self._dh_state = self._suzuki_state = None
        self._pending_worker_cid_selection = None
        self._last_completed_standalone_getter = None

    def _apply_cleanup_globals(self, cleanup) -> None:
        """40580 source defaults are(4,0,0,0) at authenticatedRVA7dcc0."""
        self._validate_cleanup_controller(cleanup)
        self._worker_phase = None
        self._native_fatal_output = False
        self._native_control_fatal_output = False
        self._native_error_kind_output = self._native_previous_error_kind_output = 0
        self._native_error_output = (0, 0)
        self._write_complete_output = False
        self._native_cycle_output = False
        self._continuation_backup = None
        self._logical_block_index = 0

    def _apply_cleanup_late_globals(self, cleanup) -> None:
        """40580 reaches VIN/modal resets only after both false notifications."""
        self._validate_cleanup_controller(cleanup)
        self._online_modal_state = 0
        self._vin = b""
        self._received_hardware = b""

    def _apply_cleanup_vectors(self, cleanup) -> None:
        """40580 clears identifier vectors after the concrete device Clear."""
        self._validate_cleanup_controller(cleanup)
        state = self._cleanup_retired_dh_state
        if state is not None:
            state._progress = (0,) * len(state._progress)
            state._transferred_bytes = (0,) * len(state._transferred_bytes)
            self._cleanup_retired_dh_state = None
        self._identifier_records = self._received_identifiers = ()
        self._working_identifier_records = ()
        self._working_contact_buffer = bytes(33)
        self._working_hardware = b""

    def bind_retry_controller(self):
        """Issue119's concrete callback3/query controller for the current worker."""
        from scripts.cuw_retry import _issue_retry_controller

        owned = self._active and self._phase_thread == get_ident()
        if not owned and not self._lock.acquire(blocking=False):
            raise ValueError("CUW phase is active")
        try:
            if self._retry_controller is None:
                self._retry_controller = _issue_retry_controller(self, self.worker)
                if self._active:
                    self._retry_controller.worker_started()
            return self._retry_controller
        finally:
            if not owned:
                self._lock.release()

    def _validate_retry_controller(self, controller) -> None:
        from scripts.cuw_retry import RetryController2026

        if (
            type(controller) is not RetryController2026
            or controller is not self._retry_controller
            or controller.engine is not self
            or controller.worker is not self.worker
        ):
            raise ValueError("Actual source-issued engine retry controller required")

    @property
    def native_cycle_output(self) -> bool:
        """Engine398/DATd348 is shared by worker IG logic and retry processing."""
        return self._native_cycle_output

    def _publish_retry_cycle(self, controller) -> None:
        """3ffa0's kind1/2 and completed file-reset branches assign398=true."""
        self._require_owned_phase()
        self._validate_retry_controller(controller)
        self._native_cycle_output = True

    def _publish_worker_cycle(self, worker) -> None:
        """3ec30/3f620 publish the actual source-selected IG transition flag."""
        self._require_owned_phase()
        if worker is not self.worker:
            raise ValueError("Actual source-issued worker required")
        self._native_cycle_output = worker.control_state.ig_off_pending

    def _publish_retry_decision(self, controller, value: bool) -> None:
        """3ffa0 modal/recovery branches publish engine399 without a UI query."""
        self._require_owned_phase()
        self._validate_retry_controller(controller)
        if type(value) is not bool:
            raise TypeError("Actual native retry decision Boolean required")
        self._write_complete_output = value

    def _accept_retry_decision(
        self, controller, native_result: int, native_option: int
    ) -> None:
        """5e950 publishes globals before signalling the waiting native worker."""
        self._validate_retry_controller(controller)
        if (
            type(native_result) is not int
            or not -0x80000000 <= native_result <= 0xFFFFFFFF
            or type(native_option) is not int
            or not 0 <= native_option <= 255
        ):
            raise ValueError("Actual native query result int and option byte required")
        with self._phase_state_lock:
            if not controller.query_pending:
                raise ValueError("No actual native retry query is pending")
            self._native_error_kind_output = self._native_previous_error_kind_output = 0
            self._native_error_output = (0, 0)
            self._online_modal_state = 0
            self._write_complete_output = native_result == 1

    def check_j2534_connection(self) -> int:
        """5d830's source constructor guard, then the concrete119 device probe."""
        from scripts.cuw_retry import check_j2534_connection_2026

        if self._metadata is None or self._interface_pair is None:
            return 0xFA3
        return check_j2534_connection_2026(self)

    def inform_result_of_query_retry(
        self, native_result: int, native_option: int
    ) -> int:
        """Public5e950 returns3005 until the actual retry controller asks a query."""
        if self._retry_controller is None:
            return 0xBBD
        return self._retry_controller.inform_result(native_result, native_option)

    @property
    def native_prepare_handshake(self) -> int:
        """Slot18/58570 reads controller+be8;59070 initializes it to0."""
        _ = self.native_metadata
        return (
            self.worker.native_prepare_handshake
            if self._worker is not None
            else self._native_prepare_handshake
        )

    @property
    def native_writer_target_index(self) -> int:
        """Field73c needs the actual CID-selected engine2f4 target vector."""
        return self.worker.native_writer_target_index

    @property
    def native_initial_command_retry980(self) -> bool:
        """Field980 needs the actual5a835 gateway/recovery state transition."""
        return self.worker.native_initial_command_retry980

    @property
    def native_getter_cpu_type984(self) -> str:
        """Retained engine3cc string needs the actual36800/worker producer."""
        return self.worker.native_getter_cpu_type984

    def validate_address_groups(self, selection, groups) -> None:
        """Validate actual Control4c10 field748 against this engine's imported source."""
        from scripts.programming_2026_common import NativeParameterBinding2026
        from scripts.programming_2026_vendor import native2026_write_address_groups

        if type(selection) is not NativeParameterBinding2026:
            raise TypeError("Concrete native writer parameter binding required")
        metadata = self.native_metadata
        if selection.metadata != metadata:
            raise ValueError("Writer addresses differ from the actual engine target")
        expected = native2026_write_address_groups(metadata.source_container, selection)
        if type(groups) is not tuple or groups != expected:
            raise ValueError(
                "Writer field748 differs from native source-produced addresses"
            )

    def _require_owned_phase(self) -> None:
        if not self._active or self._phase_thread != get_ident():
            raise ValueError(
                "Native context mutation requires its active concrete phase"
            )

    def _import_identifier_context(self) -> None:
        """59ab0 zeroes34records and contact, then copies existing12byte records."""
        self._identifier_context_epoch += 1
        self._last_completed_standalone_getter = None
        self._working_identifier_records = self._identifier_records + (bytes(12),) * (
            34 - len(self._identifier_records)
        )
        self._working_contact_buffer = bytes(33)
        self._working_hardware = b""
        self.dh_state._flashing_ended = False

    @property
    def dcm_getter_state(self) -> DCMGetterState2026:
        self._require_owned_phase()
        if len(self._working_identifier_records) != 34:
            raise ValueError("Native identifier context has not been imported")
        return DCMGetterState2026(_DH_STATE_TOKEN, self)

    @property
    def identifier_records(self) -> tuple[bytes, ...]:
        return self._identifier_records

    @property
    def received_identifiers(self) -> tuple[bytes, ...]:
        return self._received_identifiers

    @property
    def received_hardware(self) -> bytes:
        """5a050 copies the actual getter typData994 C string into D4C4."""
        return self._received_hardware

    def apply_mmc_getter_hardware(self, identity, value: bytes) -> None:
        """MMC18e0 copies its first15e0/F111 response to typData994 before F188."""
        self._require_owned_phase()
        if (
            not isinstance(identity, NativeModuleIdentity)
            or identify_native_module(identity.sha256, "TCUWCanMMCCIDGetter.dll")
            != identity
            or identity.cuw_builds != ("2026",)
        ):
            raise ValueError("Exact native2026 MMC CID getter required")
        if self._worker_phase != 0 or len(self._working_identifier_records) != 34:
            raise ValueError("Imported actual GetCID phase required for hardware")
        if type(value) is not bytes or len(value) > 24 or b"\0" in value:
            raise ValueError("Native MMC hardware C string is at most24 bytes")
        self._working_hardware = value

    def apply_sil_getter_context(self, identity, contact_type: str | None) -> None:
        """SIL DCMPRL Version15b0 writes9e9 independently of the returned CID BOOL."""
        self._require_owned_phase()
        if (
            not isinstance(identity, NativeModuleIdentity)
            or identify_native_module(identity.sha256, "TCUWSilDCMPRLVersionGetter.dll")
            != identity
            or identity.cuw_builds != ("2026",)
        ):
            raise ValueError("Exact native2026 SIL DCMPRL Version getter required")
        if contact_type is None:
            return
        if (
            contact_type != "SIL"
            or self.native_metadata.vehicle.get("kindofecu", "") != "8"
            or self.dh_state.progress[0] != 0
        ):
            raise ValueError(
                "SIL contact differs from the actual native getter context"
            )
        self._working_contact_buffer = b"SIL\0" + self._working_contact_buffer[4:]

    def apply_can_cid_queries(
        self, identity, query_ids: tuple[bytes, ...], query_cpu_indices: tuple[int, ...]
    ) -> None:
        """CanCID1240 partial query-record writes; no success/count inference."""
        self._require_owned_phase()
        if (
            not isinstance(identity, NativeModuleIdentity)
            or identify_native_module(identity.sha256, "TCUWCanCIDGetter.dll")
            != identity
            or identity.cuw_builds != ("2026",)
        ):
            raise ValueError("Exact native2026 CanCID getter required")
        if (
            type(query_ids) is not tuple
            or type(query_cpu_indices) is not tuple
            or len(query_ids) != len(query_cpu_indices)
            or len(query_ids) > 34
        ):
            raise ValueError(
                "Bounded aligned actual query-record observations required"
            )
        records = list(self._working_identifier_records)
        for index, (query, cpu_index) in enumerate(zip(query_ids, query_cpu_indices)):
            if (
                type(query) is not bytes
                or not re.fullmatch(b"(?:[0-9A-F]{4}|[0-9A-F]{6})", query)
                or type(cpu_index) is not int
                or cpu_index != 0
            ):
                raise ValueError(
                    "Native CanCID CPU0 and uppercase2/3byte query ID required"
                )
            value = query + b"\0"
            records[index] = bytes(4) + value + records[index][4 + len(value) :]
        self._working_identifier_records = tuple(records)

    def commit_received_identifiers(
        self, values: tuple[bytes, ...], *, controller
    ) -> None:
        """6f20/5a050 consumes the actual final vector, even when getterBOOL is false."""
        from scripts.programming_2026_common import ControlCommPhase2026

        if (
            type(controller) is not ControlCommPhase2026
            or type(values) is not tuple
            or len(values) > 34
            or any(
                type(value) is not bytes or len(value) > 33 or b"\0" in value
                for value in values
            )
        ):
            raise ValueError(
                "Concrete controller and bounded final native CID vector required"
            )
        owned = self._active and self._phase_thread == get_ident()
        if self._worker is not None and controller is not self.worker.controller:
            raise ValueError("CID result controller differs from the actual worker")
        if not owned and not self._lock.acquire(blocking=False):
            raise ValueError("CUW phase is active")
        try:
            if len(self._working_identifier_records) != 34:
                raise ValueError(
                    "Import native identifier context before consuming results"
                )
            self._received_identifiers = values
            self._identifier_records = self._working_identifier_records[: len(values)]
            self._received_hardware = self._working_hardware
        finally:
            if not owned:
                self._lock.release()

    def select_target(self, node: int, cpu_index: int, *, controller) -> None:
        """A concrete controller advances its native current target, preserving state."""
        from scripts.calibration_2026 import native2026_global_cpu_index
        from scripts.programming_2026_common import ControlCommPhase2026

        if type(controller) is not ControlCommPhase2026:
            raise TypeError("Concrete CUW2026 controller required for target advance")
        if self._worker is not None and controller is not self.worker.controller:
            raise ValueError("Target controller differs from the actual worker")
        owned = self._active and self._phase_thread == get_ident()
        if not owned and not self._lock.acquire(blocking=False):
            raise ValueError("CUW phase is active")
        try:
            selected = self.metadata_for(node, cpu_index)
            global_index = native2026_global_cpu_index(selected)
            self._metadata = selected
            for state in (self.dh_state, self.suzuki_state):
                state.metadata = selected
                state.node, state.selection_cpu_index = (
                    selected.node,
                    selected.cpu_index,
                )
                state.cpu_index = state.global_cpu_index = global_index
            self.dh_state._dh_flash_size = None
            if self._worker is not None:
                self.worker._target_selected(selected)
                self.bind_cleanup_controller().target_selected(selected)
            if self._persistence is not None and (
                self._worker is None or self.worker.persist_current_cpu
            ):
                persisted_index = (
                    global_index
                    if self._worker is None
                    else self.worker.source_state.current_global_cpu_index
                )
                self._persistence.update_cpu(persisted_index)
        finally:
            if not owned:
                self._lock.release()

    def _select_worker_metadata(self, metadata, *, controller, worker) -> None:
        """Apply an issued multi-FILE target without resetting shared native arrays."""
        from scripts.calibration_2026 import (
            Native2026Metadata,
            native2026_cpu_count,
            native2026_global_cpu_index,
            native2026_metadata,
            native2026_validate_runtime_metadata,
            native2026_with_cpu_type,
        )

        if worker is not self.worker or controller is not worker.controller:
            raise ValueError("Actual engine worker/controller lease required")
        if type(metadata) is not Native2026Metadata:
            raise TypeError("Concrete native worker metadata required")
        native2026_validate_runtime_metadata(metadata)
        loaded = worker.loaded_metadata
        if self._file_sources is not None:
            loaded = (*loaded, *self._file_sources.files)
        if not any(
            metadata.source_container is item.source_container for item in loaded
        ):
            raise ValueError("Worker target source is outside its issued FILE vector")
        mutation = self._worker_target_sources.get(id(metadata.source_container))
        if mutation is None:
            expected = native2026_metadata(
                metadata.source_container,
                node=metadata.node,
                cpu_index=metadata.cpu_index,
                region=self.native_metadata.region,
            )
        else:
            from scripts.calibration_2026 import native2026_metadata_for_cpu

            expected = native2026_metadata_for_cpu(
                mutation, native2026_global_cpu_index(metadata)
            )
        expected = self._parser_profile(expected)
        for index, value in metadata.cpu_type_overrides.items():
            expected = native2026_with_cpu_type(expected, index, value)
        if metadata != expected:
            raise ValueError("Worker target differs from its actual source metadata")
        if (
            self.configuration is None
            or native2026_cpu_count(metadata) > self.configuration.cpu_maximum
        ):
            raise ValueError("Worker target exceeds configured CPU capacity")
        owned = self._active and self._phase_thread == get_ident()
        if not owned and not self._lock.acquire(blocking=False):
            raise ValueError("CUW phase is active")
        try:
            index = native2026_global_cpu_index(metadata)
            self._metadata = metadata
            from scripts.calibration_2026 import NativeUSBSource2026
            from scripts.cuw_large import NativeLargeContainer2026

            if type(metadata.source_container) is NativeUSBSource2026:
                self._owned_usb_sources[id(metadata.source_container)] = (
                    metadata.source_container
                )
            if type(metadata.source_container) is NativeLargeContainer2026:
                self._large_container = metadata.source_container
                self._owned_large_containers[id(self._large_container)] = (
                    self._large_container
                )
            else:
                self._large_container = None
            for state in (self.dh_state, self.suzuki_state):
                state.metadata = metadata
                state.source_sha256 = metadata.source_sha256
                state.node, state.selection_cpu_index = (
                    metadata.node,
                    metadata.cpu_index,
                )
                state.cpu_index = state.global_cpu_index = index
            self.dh_state._dh_flash_size = None
            self._shrink_flag = metadata.initial_shrink_flag
            worker._target_selected(metadata)
            self.bind_cleanup_controller().target_selected(metadata)
        finally:
            if not owned:
                self._lock.release()

    @property
    def shrink_flag(self) -> bool:
        return self._shrink_flag

    def apply_cpu_type(self, cpu_index: int, cpu_type: str) -> None:
        """Actual CF6850 state update, supplied only by concrete family code."""
        from scripts.calibration_2026 import native2026_with_cpu_type

        owned = self._active and self._phase_thread == get_ident()
        if not owned and not self._lock.acquire(blocking=False):
            raise ValueError("CUW phase is active")
        try:
            metadata = native2026_with_cpu_type(
                self.native_metadata, cpu_index, cpu_type
            )
            self._metadata = metadata
            self.dh_state.metadata = self.suzuki_state.metadata = metadata
        finally:
            if not owned:
                self._lock.release()

    def apply_shrink_flag(self, value: bool) -> None:
        if type(value) is not bool:
            raise TypeError("Native shrink flag must be Boolean")
        owned = self._active and self._phase_thread == get_ident()
        if not owned and not self._lock.acquire(blocking=False):
            raise ValueError("CUW phase is active")
        try:
            _ = self.native_metadata
            self._shrink_flag = value
        finally:
            if not owned:
                self._lock.release()

    def calibration_export(self):
        from scripts.calibration_2026 import native2026_export_state

        return native2026_export_state(
            self.native_metadata, shrink_flag=self._shrink_flag
        )

    def gateway_callback(self, runtime) -> bool:
        owned = self._active and self._phase_thread == get_ident()
        if not owned and not self._lock.acquire(blocking=False):
            raise ValueError("CUW phase is active")
        try:
            return self._gateway_callback_native(runtime)
        finally:
            if not owned:
                self._lock.release()

    def _gateway_callback_native(self, runtime) -> bool:
        """Callback15/5b350 catches native errors and preserves unspecified fields."""
        from scripts.j2534_2026 import NativePassThruError2026
        from scripts.programming_2026_common import (
            CommonResponseError,
            NativeException2026,
            NativePassThruException2026,
        )

        state = self.dh_state
        try:
            gateway_wire2026(self._gateway_authentication, runtime)
        except NativePassThruError2026 as exc:
            state.record_native_error(None, exc.native_error_code, exc.passthru_status)
            return False
        except NativePassThruException2026 as exc:
            state.record_native_error(
                None,
                exc.native_error_code & 0xFFFFFFFF,
                None
                if exc.passthru_status is None
                else exc.passthru_status & 0xFFFFFFFF,
            )
            return False
        except CommonResponseError as exc:
            state.record_native_error(None, exc.code)
            return False
        except NativeException2026:
            state.record_native_error(None, 9999)
            return False
        return True

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def close(self) -> None:
        if not self._lock.acquire(blocking=False):
            raise ValueError("Cancel and finish the active CUW phase before closing")
        try:
            with self._phase_state_lock:
                if self._prepare_prefix_owner is not None:
                    raise ValueError("Finish the native prepare prefix before closing")
            if self._thread_job is not None:
                self._thread_job.stop()
            if self._online_controller is not None:
                self._online_controller.close()
            if self._retry_controller is not None:
                self._retry_controller.close()
            if self._worker is not None:
                self._worker.close()
            from scripts.cuw_engine_cleanup import _revoke_engine_cleanup
            from scripts.cuw_gateway_startup import _revoke_gateway_startup

            _revoke_engine_cleanup(self)
            _revoke_gateway_startup(self)
            for container in tuple(self._owned_large_containers.values()):
                container.close()
            self._owned_large_containers.clear()
            self._close_unselected_usb_sources()
            self._large_container = None
            self._source = self._metadata = self._dh_state = self._suzuki_state = None
            self._shrink_flag = False
            self._persistence = None
            self._worker = None
            self._thread_job = None
            self._interface_pair = None
            self._retry_controller = None
            self._cleanup_controller = None
            self._cleanup_retired_dh_state = None
            self._file_sources = None
            self._worker_target_sources.clear()
            self._pending_worker_cid_selection = None
            self._last_completed_standalone_getter = None
            self._gateway_startup = None
            self._online_controller = None
            self._online_modal_state = 0
            self._worker_phase = None
            self._continuation_backup = None
        finally:
            self._lock.release()

    @property
    def active(self) -> bool:
        return self._active

    @property
    def native_phase(self) -> int:
        """30be0 initializes DATcfb8 from exact source DWORD4 at RVA7dcc0."""
        return 4 if self._worker_phase is None else self._worker_phase

    @property
    def worker_phase(self) -> int | None:
        return self._worker_phase

    @property
    def repro_gateway_node(self) -> int:
        return self._repro_gateway_node

    @property
    def native_gateway_cache(self) -> int:
        """ED0C is the actual ReproInfo byte, separate from59070's working BF9."""
        value = (
            self._gateway_classifier_cache
            if self._persistence is None
            else self._persistence.state.repro_gw_node
        )
        if type(value) is not int or not 0 <= value <= 255:
            raise ValueError("Native ED0C gateway cache must be a byte")
        return value

    def _assign_gateway_classifier_cache(self, value: int) -> None:
        if type(value) is not int or not 0 <= value <= 255:
            raise ValueError("Native ED0C gateway cache must be a byte")
        self._gateway_classifier_cache = value
        if self._persistence is not None:
            self._persistence.state.repro_gw_node = value

    def _publish_gateway_classifier_cache(self, producer) -> None:
        """1ad30 stores the issued classifier before authentication may fail."""
        from scripts.cuw_gateway_startup import GatewayStartup2026

        self._require_owned_phase()
        if (
            type(producer) is not GatewayStartup2026
            or producer is not self._gateway_startup
        ):
            raise TypeError("Actual issued gateway startup required")
        producer.validate_owner(self, self.worker)
        if not producer._running:
            raise ValueError("Native1ad30 classifier assignment is not active")
        value = producer.source_state.classification
        if not 1 <= value <= 255:
            raise ValueError("Native classifier must produce a nonzero byte")
        self._assign_gateway_classifier_cache(value)

    def _publish_gateway_cache_from_worker(self, *, worker) -> None:
        """58ab0 callback36 copies actual working BF9 into ED0C."""
        self._require_owned_phase()
        if worker is not self.worker:
            raise ValueError("Actual source-issued worker required for gateway cache")
        self._assign_gateway_classifier_cache(self.repro_gateway_node)

    def _publish_callback_24_gateway_cache(self, *, worker, value: int) -> None:
        """58ab0 callback24 assigns its raw byte to persistent ED0C."""
        self._require_owned_phase()
        if worker is not self.worker:
            raise ValueError("Actual source-issued worker required for gateway cache")
        self._assign_gateway_classifier_cache(value)

    def _reset_gateway_classifier_cache_for_cleanup(self, cleanup) -> None:
        """23630 zeroes ED0C as part of the actual recovery aggregate reset."""
        self._validate_cleanup_controller(cleanup)
        if self._persistence is not None and self._persistence.state.repro_gw_node != 0:
            raise ValueError("Reset the actual recovery aggregate before its cache")
        self._gateway_classifier_cache = 0

    @property
    def logical_block_index(self) -> int:
        return self._logical_block_index

    def set_logical_block_index(self, ordinal: int) -> None:
        """Slot28/58870→5b670 copies the actual current logical-block ordinal."""
        self._require_owned_phase()
        if type(ordinal) is not int or not 0 <= ordinal < len(
            self.native_metadata.logical_blocks
        ):
            raise ValueError("Actual selected-node logical-block ordinal required")
        self._logical_block_index = ordinal

    @property
    def native_fatal_output(self) -> bool:
        """CFD0 constructor/reset flag, distinct from controller58 and copiedD34B."""
        return self._native_fatal_output

    @property
    def native_error_kind_output(self) -> int:
        return self._native_error_kind_output

    @property
    def native_previous_error_kind_output(self) -> int:
        return self._native_previous_error_kind_output

    def notify_native_error_kind(self) -> None:
        """Slot5/582e0→5b090 copies working750 to engine+0c, independently ofslot6."""
        owned = self._active and self._phase_thread == get_ident()
        if not owned and not self._lock.acquire(blocking=False):
            raise ValueError("CUW phase is active")
        try:
            self._native_error_kind_output = self.dh_state.error_kind
        finally:
            if not owned:
                self._lock.release()

    def _initialize_native_prepare_outputs(self, *, worker) -> None:
        """36800 prefix resets copied globals, preserving primary in3a0a0 recovery."""
        self._require_native_prepare_prefix(worker)
        recovery = worker.control_state.recovery_mode
        self._native_error_kind_output = 0
        self._native_previous_error_kind_output = 0
        self._native_error_output = (self._native_error_output[0] if recovery else 0, 0)
        self._write_complete_output = False
        self._native_cycle_output = False
        self._online_modal_state = 0
        self._worker_phase = 1

    def _require_native_prepare_prefix(self, worker) -> None:
        """Authorize only36800 prefix writes, including its external1→3 entry."""
        if worker is not self.worker:
            raise ValueError("Actual source-issued worker required for prepare entry")
        if self._active and self._phase_thread == get_ident():
            return
        prefix = self._prepare_prefix_owner
        if (
            prefix is None
            or prefix[0] != get_ident()
            or prefix[1] is not worker
            or prefix[2] is not self._thread_job
        ):
            raise ValueError("Actual owned36800 prepare prefix required")

    @contextmanager
    def prepare_reentry_execution(self, job):
        """5db20 may enter36800's prefix while the previous native child runs."""
        from scripts.cuw_engine_threads import EngineThreadJob2026

        if type(job) is not EngineThreadJob2026 or job is not self._thread_job:
            raise TypeError("Actual issued native thread job required")
        job.validate_owner(self)
        worker = self.worker
        if (
            job.worker is not worker
            or not job.native_worker_exists
            or job.is_native_thread
            or worker.native_prepare_handshake != 1
            or worker.control_state.recovery_mode
        ):
            raise ValueError("Actual external native prepare reentry required")
        with self._phase_state_lock:
            if self._prepare_prefix_owner is not None:
                raise ValueError("Native prepare prefix is already executing")
            self._prepare_prefix_owner = (get_ident(), worker, job)
        try:
            yield worker
        finally:
            with self._phase_state_lock:
                self._prepare_prefix_owner = None

    def _retain_native_error_kind(self, *, worker) -> None:
        """3ffa0 retains engine+0c in engine+10 before the actual wait/resume."""
        if worker is not self.worker:
            raise ValueError("Actual engine worker required for error-kind retention")
        self._native_previous_error_kind_output = self._native_error_kind_output

    def native_recovery_status(self, *, previous: bool = False) -> int:
        """344a0 evaluates copied error kind and the actual CPU/node transition."""
        from scripts.calibration_2026 import (
            native2026_cpu_values,
            native2026_global_cpu_index,
        )
        from scripts.programming_2026_common import NativeCallbackLookupError

        if type(previous) is not bool:
            raise TypeError("Native current/previous error-kind selector required")
        kind = (
            self._native_previous_error_kind_output
            if previous
            else self._native_error_kind_output
        )
        if kind >= 0x80000000:
            kind -= 0x100000000
        if kind == 4:
            return 2
        if kind != 1:
            return 2 if kind == 5 else kind
        source = self.worker.source_state
        current = source.current_global_cpu_index
        if current == source.cpu_offset:
            return 1
        metadata = self.worker.metadata_for_native_cpu(current)
        contact = metadata.vehicle.get("contacttype", "")
        if contact in ("P5-Unified", "Phase6", "Ethernet"):
            previous_metadata = self.worker.metadata_for_native_cpu(current - 1)
            return 2 if metadata.node == previous_metadata.node else 1
        if self._general_parameters is None:
            raise NativeCallbackLookupError()
        changed = self._general_parameters.boolean_with_keys(
            metadata.vehicle.get("kindofecu", ""),
            native2026_cpu_values(metadata, native2026_global_cpu_index(metadata)).get(
                "cputype", ""
            ),
            contact,
            "CPUTypeWithModeChangeAtCPUTypeChangeFlag",
        )
        return 1 if changed else 2

    def get_info_for_repro_log(self, previous: bytes) -> tuple[int, bytes]:
        """65a40 preserves the caller's buffer on native10001, including padding."""
        if type(previous) is not bytes or len(previous) != 0x2160:
            raise ValueError(
                "Actual caller-owned0x2160 programming-log buffer required"
            )
        if self._metadata is None:
            return 10001, previous
        if self._worker is None:
            status = EngineStatus2026(
                phase=self.native_phase,
                error=self._native_error_output[0],
                recovery_status=self.native_recovery_status(previous=True),
            )
            if status.receiving_status()[0] != 0x138C and status.reprogramming_status()[
                0
            ] not in (0xBBB, 0xBBC):
                return 10001, previous
        value = self.worker.write_programming_log(previous)
        return (10001, previous) if value is None else (0, value)

    @property
    def native_error_output(self) -> tuple[int, int]:
        return self._native_error_output

    def notify_native_errors(self, ignored_argument: int = 0) -> None:
        """Slot6/5b0a0 copies working errors; the caller's extra code is ignored."""
        if type(ignored_argument) is not int or not 0 <= ignored_argument <= 0xFFFFFFFF:
            raise ValueError("Native callback argument must be an unsigned DWORD")
        owned = self._active and self._phase_thread == get_ident()
        if not owned and not self._lock.acquire(blocking=False):
            raise ValueError("CUW phase is active")
        try:
            self._native_error_output = (
                self.dh_state.primary_error,
                self.dh_state.passthru_error,
            )
        finally:
            if not owned:
                self._lock.release()

    @property
    def write_complete_output(self) -> bool:
        return self._write_complete_output

    def restore_divided_image_context(self) -> None:
        """4c10 callback46 copies native ED6C into the current C60 working index."""
        self._require_owned_phase()
        _ = self.worker
        if self._persistence is None:
            value = 0
        else:
            self._validate_persistence_source(self.native_metadata)
            value = self._persistence.state.write_target_divided_cpu_image_index
        self.dh_state._divided_image_index = value

    def notify_next_cpu(self) -> None:
        """Slot1/581a0 requires the actual normal or mixed-CPU worker continuation."""
        self._require_owned_phase()
        if self._thread_job is not None and self._thread_job.is_child_thread:
            self._thread_job.dispatch_next_cpu()
            return
        self.worker.notify_next_cpu()

    def notify_logical_cpu_boundary(self, index: int) -> None:
        """P6's in-export callback1 uses the same concrete outer-thread handoff."""
        self._require_owned_phase()
        if self._thread_job is not None and self._thread_job.is_child_thread:
            self._thread_job.dispatch_logical_cpu_boundary(index)
            return
        self.worker.notify_logical_cpu_boundary(index)

    @property
    def native_control_fatal_output(self) -> bool:
        """D34B is callback9's local58 copy, independent of engine CFD0."""
        return self._native_control_fatal_output

    def publish_control_fatal(self, *, worker) -> None:
        """5b0e0 copies controller localfatal58 into engine+39b."""
        self._require_owned_phase()
        if worker is not self.worker:
            raise ValueError("Actual current native worker required")
        self._native_control_fatal_output = worker.control_state.fatal

    def publish_native_fatal(self, *, worker) -> None:
        """5b1b0 copies59070+80 through its+7c pointer to CUW CFD0."""
        self._require_owned_phase()
        if worker is not self.worker:
            raise ValueError("Actual current native worker required")
        self._native_fatal_output = worker.native_fatal_input80

    def publish_control_failed(self, controller) -> None:
        """4780 callback7 copies the issued controller's local75c into399."""
        self._require_owned_phase()
        worker = self.worker
        if controller is not worker.controller:
            raise ValueError("Actual engine control-phase owner required")
        self._write_complete_output = worker.control_state.failed

    def notify_write_complete(self) -> None:
        """Slot7/5b0c0 copies the working75c Boolean to engine+399."""
        owned = self._active and self._phase_thread == get_ident()
        if not owned and not self._lock.acquire(blocking=False):
            raise ValueError("CUW phase is active")
        try:
            self._write_complete_output = self.dh_state.write_complete
        finally:
            if not owned:
                self._lock.release()

    def set_repro_gateway_node(self, value: int) -> None:
        """Concrete UnifiedPrepare classification updates the shared native enum."""
        if type(value) is not int or not 0 <= value <= 255:
            raise ValueError("Native reprogramming gateway byte must be0..255")
        if not self._active or self._phase_thread != get_ident():
            raise ValueError("Gateway classification requires an active concrete phase")
        self._repro_gateway_node = value

    def _publish_cached_gateway_kind(self, *, worker) -> None:
        """58b40 callback37 returns cached ED0C;5c30 copies its byte into BF9."""
        self._require_owned_phase()
        if worker is not self.worker:
            raise ValueError("Actual source-issued worker required for gateway cache")
        value = self.native_gateway_cache
        if type(value) is not int or not 0 <= value <= 255:
            raise ValueError("Native gateway cache must retain its raw byte")
        self._repro_gateway_node = value

    @property
    def dh_state(self) -> DHControllerState2026:
        if self._dh_state is None:
            raise ValueError("Load CUW2026 before obtaining native DH state")
        return self._dh_state

    @property
    def suzuki_state(self) -> SuzukiControllerState2026:
        if self._suzuki_state is None:
            raise ValueError("Load CUW2026 before obtaining native Suzuki state")
        return self._suzuki_state

    def configure(self, arguments: bytes) -> EngineConfiguration2026:
        if not self._lock.acquire(blocking=False):
            raise ValueError("CUW phase is active")
        try:
            configuration = configure_2026(
                arguments, calibration_loaded=self._metadata is not None
            )
            self.common_definitions.num_cpu_maxnum = configuration.cpu_maximum
            self.configuration = configuration
            return configuration
        finally:
            self._lock.release()

    def load_cuw(
        self, data: bytes, *, node: int = 1, cpu_index: int = 0, region: int = 0
    ):
        """Bind immutable2026 metadata transactionally; no older parser fallback."""
        from scripts.calibration_2026 import (
            native2026_cpu_count,
            native2026_metadata,
            parse_cuw_2026,
        )

        if not self._lock.acquire(blocking=False):
            raise ValueError("CUW phase is active")
        try:
            if self.configuration is None:
                raise ValueError("Configure CUW before binding calibration")
            if self._worker is not None:
                raise ValueError(
                    "Close the engine before replacing its bound worker source"
                )
            metadata = native2026_metadata(
                parse_cuw_2026(data), node=node, cpu_index=cpu_index, region=region
            )
            metadata = self._parser_profile(metadata)
            if native2026_cpu_count(metadata) > self.configuration.cpu_maximum:
                raise ValueError("Calibration exceeds configured CPU capacity")
            self._validate_persistence_source(metadata)
            state = DHControllerState2026(
                _DH_STATE_TOKEN,
                self.identity,
                metadata,
                self.configuration.cpu_maximum,
                engine=self,
            )
            suzuki = SuzukiControllerState2026(
                _DH_STATE_TOKEN, self.identity, metadata, error_state=state
            )
            if self._persistence is not None:
                state._notification = self._persistence.notification
            previous = self._large_container
            self._source, self._metadata, self._dh_state = data, metadata, state
            self._file_sources = None
            self._worker_target_sources.clear()
            self._suzuki_state = suzuki
            if self._persistence is not None:
                self._persistence.bind_engine_source(self)
            self._shrink_flag = metadata.initial_shrink_flag
            self._large_container = None
            self._close_unselected_usb_sources()
            if previous is not None:
                previous.close()
                self._owned_large_containers.pop(id(previous), None)
            return metadata
        finally:
            self._lock.release()

    def load_large_cuw(
        self,
        path: str | Path,
        *,
        node: int = 1,
        cpu_index: int = 0,
        region: int = 0,
        cancelled: Callable[[], bool] | None = None,
    ):
        """Own the actual large-file producer's pinned source until replacement/close."""
        from scripts.calibration_2026 import native2026_cpu_count, native2026_metadata
        from scripts.cuw_large import native_large_cuw_2026

        if not self._lock.acquire(blocking=False):
            raise ValueError("CUW phase is active")
        container = None
        try:
            if self.configuration is None:
                raise ValueError("Configure CUW before binding calibration")
            if self._worker is not None:
                raise ValueError(
                    "Close the engine before replacing its bound worker source"
                )
            container = native_large_cuw_2026(path, cancelled=cancelled)
            metadata = native2026_metadata(
                container, node=node, cpu_index=cpu_index, region=region
            )
            metadata = self._parser_profile(metadata)
            if native2026_cpu_count(metadata) > self.configuration.cpu_maximum:
                raise ValueError("Calibration exceeds configured CPU capacity")
            self._validate_persistence_source(metadata)
            state = DHControllerState2026(
                _DH_STATE_TOKEN,
                self.identity,
                metadata,
                self.configuration.cpu_maximum,
                engine=self,
            )
            suzuki = SuzukiControllerState2026(
                _DH_STATE_TOKEN, self.identity, metadata, error_state=state
            )
            if self._persistence is not None:
                state._notification = self._persistence.notification
            previous = self._large_container
            self._source = None
            self._metadata, self._dh_state, self._suzuki_state = metadata, state, suzuki
            self._file_sources = None
            self._worker_target_sources.clear()
            if self._persistence is not None:
                self._persistence.bind_engine_source(self)
            self._shrink_flag = metadata.initial_shrink_flag
            self._large_container, container = container, None
            self._owned_large_containers[id(self._large_container)] = (
                self._large_container
            )
            self._close_unselected_usb_sources()
            if previous is not None:
                previous.close()
                self._owned_large_containers.pop(id(previous), None)
            return metadata
        finally:
            try:
                if container is not None:
                    container.close()
            finally:
                self._lock.release()

    def load_native_usb(
        self, source, *, node: int = 1, cpu_index: int = 0, region: int = 0
    ):
        """Adopt47's issued USB file lease only after a successful native load."""
        from scripts.calibration_2026 import (
            NativeUSBSource2026,
            native2026_cpu_count,
            native2026_metadata,
        )

        if type(source) is not NativeUSBSource2026:
            raise TypeError("Issued native USB source required")
        if not self._lock.acquire(blocking=False):
            raise ValueError("CUW phase is active")
        try:
            if self.configuration is None:
                raise ValueError("Configure CUW before binding calibration")
            if self._worker is not None:
                raise ValueError(
                    "Close the engine before replacing its bound worker source"
                )
            metadata = self._parser_profile(
                native2026_metadata(
                    source, node=node, cpu_index=cpu_index, region=region
                )
            )
            if native2026_cpu_count(metadata) > self.configuration.cpu_maximum:
                raise ValueError("Calibration exceeds configured CPU capacity")
            self._validate_persistence_source(metadata)
            state = DHControllerState2026(
                _DH_STATE_TOKEN,
                self.identity,
                metadata,
                self.configuration.cpu_maximum,
                engine=self,
            )
            suzuki = SuzukiControllerState2026(
                _DH_STATE_TOKEN, self.identity, metadata, error_state=state
            )
            if self._persistence is not None:
                state._notification = self._persistence.notification
            previous = self._large_container
            self._source, self._metadata = source.raw, metadata
            self._dh_state, self._suzuki_state = state, suzuki
            self._large_container, self._file_sources = None, None
            self._worker_target_sources.clear()
            self._shrink_flag = metadata.initial_shrink_flag
            self._owned_usb_sources[id(source)] = source
            if self._persistence is not None:
                self._persistence.bind_engine_source(self)
            self._close_unselected_usb_sources(source)
            if previous is not None:
                previous.close()
                self._owned_large_containers.pop(id(previous), None)
            return metadata
        finally:
            self._lock.release()

    def _close_unselected_usb_sources(self, keep=None) -> None:
        for key, source in tuple(self._owned_usb_sources.items()):
            if source is not keep:
                source.close()
                del self._owned_usb_sources[key]

    def load_native_large(
        self, container, *, node: int = 1, cpu_index: int = 0, region: int = 0
    ):
        """Accept an issued large source; successful commit transfers close ownership."""
        from scripts.calibration_2026 import native2026_cpu_count, native2026_metadata
        from scripts.cuw_large import validate_large_container_2026

        validate_large_container_2026(container)
        if not self._lock.acquire(blocking=False):
            raise ValueError("CUW phase is active")
        try:
            if self.configuration is None:
                raise ValueError("Configure CUW before binding calibration")
            if self._worker is not None:
                raise ValueError(
                    "Close the engine before replacing its bound worker source"
                )
            metadata = native2026_metadata(
                container, node=node, cpu_index=cpu_index, region=region
            )
            metadata = self._parser_profile(metadata)
            if native2026_cpu_count(metadata) > self.configuration.cpu_maximum:
                raise ValueError("Calibration exceeds configured CPU capacity")
            self._validate_persistence_source(metadata)
            state = DHControllerState2026(
                _DH_STATE_TOKEN,
                self.identity,
                metadata,
                self.configuration.cpu_maximum,
                engine=self,
            )
            suzuki = SuzukiControllerState2026(
                _DH_STATE_TOKEN, self.identity, metadata, error_state=state
            )
            if self._persistence is not None:
                state._notification = self._persistence.notification
            previous = self._large_container
            self._source = None
            self._metadata, self._dh_state, self._suzuki_state = metadata, state, suzuki
            self._file_sources = None
            self._worker_target_sources.clear()
            if self._persistence is not None:
                self._persistence.bind_engine_source(self)
            self._shrink_flag = metadata.initial_shrink_flag
            self._large_container = container
            self._owned_large_containers[id(container)] = container
            self._close_unselected_usb_sources()
            if previous is not None and previous is not container:
                previous.close()
                self._owned_large_containers.pop(id(previous), None)
            return metadata
        finally:
            # A failed bind never closes a source that still belongs to its caller.
            self._lock.release()

    def cancel(self) -> bool:
        """Request cooperative cancellation of the active concrete native phase."""
        with self._phase_state_lock:
            if not self._active:
                return False
            self._cancelled.set()
            return True

    def stop_receiving_cid(
        self,
        *,
        timeout: float = 30,
        cancelled: Callable[[], bool] = lambda: False,
    ) -> int:
        """5f030 status and native cancel flag; host bounds replace infinite join."""
        job = self._thread_job
        job_exists = job is not None and job.native_worker_exists
        with self._phase_state_lock:
            if self.native_phase != 0:
                return 0x138A
            if not self._active and not job_exists:
                return 1
            if self._phase_thread == get_ident():
                raise ValueError("CID worker cannot join itself")
            if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
                raise TypeError("Finite positive CID stop timeout required")
            if not callable(cancelled):
                raise TypeError("Callable host stop cancellation required")
            budget = _Deadline(timeout, cancelled, monotonic)
            finished = self._phase_finished
            active = self._active
            self._cancelled.set()
        if job is not None and (job_exists or active):
            while True:
                try:
                    job.stop_native(timeout=min(0.05, budget.remaining()))
                    break
                except TimeoutError:
                    budget.remaining()
        while not finished.wait(min(0.05, budget.remaining())):
            pass
        budget.remaining()
        return 0

    def native_cancelled(self) -> bool:
        """Actual typCallBacks[12] observation of the owned controller cancel flag."""
        return self._cancelled.is_set()

    def process_before_reprogramming(self, parameters, device) -> int:
        """CUW64c00 normal-file branch; VBF worker handoff remains unsupported."""
        from scripts.calibration_2026 import native2026_cpu_values
        from scripts.programming_2026_common import NativeGeneralParameters2026

        if not self._lock.acquire(blocking=False):
            raise ValueError("CUW phase is active")
        try:
            metadata = self._metadata
            if metadata is None:
                return 3008
            if (
                type(parameters) is not NativeGeneralParameters2026
                or type(device) is not J2534Device2026
            ):
                raise TypeError("Concrete global parameters and J2534 device required")
            first_cpu = native2026_cpu_values(metadata, 0)
            enabled = parameters.boolean_with_keys(
                metadata.vehicle.get("kindofecu", ""),
                first_cpu.get("cputype", ""),
                metadata.vehicle.get("contacttype", ""),
                "FlagToChangeWFSE",
            )
            if enabled:
                if device.device_id is None:
                    raise ValueError("Open J2534 device required for WFSE voltage")
                device.set_programming_voltage(15, 0xFFFFFFFE)
            if ".vbf" in first_cpu.get("cpuimagename", ""):
                raise NotImplementedError("Native VBF worker handoff is not yet ported")
            return 0
        finally:
            self._lock.release()

    def judge_usb_repro_suzuki(self) -> tuple[int, bool]:
        """CUW65830 status and Boolean out value, from loaded native metadata."""
        metadata = self._metadata
        if metadata is None:
            return 9101, False
        return 0, (
            metadata.format_version == 12
            and metadata.vehicle.get("kindofecu", "") == "0795"
        )

    def run_phase(self, phase: int, session):
        """CUW3cb90:0 CID,1 prepare,2 write/recovery; no second family dispatcher."""
        from scripts.programming_replay import ProgrammingReplay

        if type(session) is not ProgrammingReplay or type(phase) is not int:
            raise TypeError("Concrete programming replay and native phase required")
        operations = {0: ("get_cid",), 1: ("prepare",), 2: ("write", "recovery")}
        if phase not in operations or session.operation not in operations[phase]:
            raise ValueError("Native phase differs from captured operation")
        self._require_native_phase_idle()
        if not self._lock.acquire(blocking=False):
            raise ValueError("CUW phase is active")
        original_cancelled = session.trace.cancelled
        try:
            metadata = self._metadata
            if (
                metadata is None
                or session.container.digest != self.source_sha256
                or session.node != metadata.node
                or session.used
                or session.trace.position
            ):
                raise ValueError("Fresh replay bound to loaded CUW/node required")
            identity = session.selected_identity()
            if identity.cuw_builds != ("2026",):
                raise ValueError("Exact CUW2026 selected module required")
            self._validate_persistence_source(metadata)
            session.bind_engine2026(self)
            with self._phase_state_lock:
                self._cancelled.clear()
                self._phase_finished = Event()
                self._active = True
                self._phase_thread = get_ident()
                self._worker_phase = phase
            self.dh_state._native_comm_phase = phase
            self._import_identifier_context()
            report = session.run()
            if report.get("programming_completed") is not False:
                raise ValueError("Phase runner cannot certify whole programming")
            return report
        finally:
            session.trace.cancelled = original_cancelled
            with self._phase_state_lock:
                self._active = False
                self._phase_thread = None
                self._phase_finished.set()
            self._lock.release()

    @contextmanager
    def thread_callback_execution(self, job):
        """3cb90 executes the parked child's callback on the actual outer thread."""
        from scripts.cuw_engine_threads import EngineThreadJob2026

        if type(job) is not EngineThreadJob2026 or job is not self._thread_job:
            raise ValueError("Actual bound native thread owner required")
        job.validate_owner(self)
        child_ident = job.validate_callback_handoff()
        outer_ident = get_ident()
        with self._phase_state_lock:
            if not self._active or self._phase_thread != child_ident:
                raise ValueError("Actual parked native child phase required")
            self._phase_thread = outer_ident
        try:
            yield
        finally:
            with self._phase_state_lock:
                if self._active and self._phase_thread == outer_ident:
                    self._phase_thread = child_ident

    @staticmethod
    def _require_prepare_dispatch(worker, phase: int) -> None:
        if (
            phase == 1
            and worker.native_prepare_handshake == 1
            and not worker.control_state.recovery_mode
        ):
            raise ValueError(
                "Consume the native prepare reentry before dispatching its phase"
            )

    def _require_native_phase_idle(self) -> None:
        if self._thread_job is not None and self._thread_job.native_work_pending:
            raise ValueError("Native worker has not reached its late idle checkpoint")

    def reserve_phase(self, controller, phase: int):
        """Reserve the real engine phase before145 starts its native worker thread."""
        from scripts.cuw_engine_threads import _issue_thread_phase_lease
        from scripts.programming_2026_common import ControlCommPhase2026

        if type(controller) is not ControlCommPhase2026:
            raise TypeError("Concrete native controller required")
        if type(phase) is not int or phase not in (0, 1, 2):
            raise ValueError("Native outer worker phase must be0..2")
        worker = self.bind_worker(controller)
        self._require_prepare_dispatch(worker, phase)
        if not self._lock.acquire(blocking=False):
            raise ValueError("CUW phase is active")
        try:
            self._require_native_phase_idle()
            self._validate_persistence_source(self.native_metadata)
            lease = _issue_thread_phase_lease(self, controller, phase)
            with self._phase_state_lock:
                self._cancelled.clear()
                self._phase_finished = Event()
                self._active, self._phase_thread, self._worker_phase = True, None, phase
            return lease
        except BaseException:
            self._lock.release()
            raise

    def release_reserved_phase(self, lease) -> None:
        """Roll back a145 reservation only when Thread.start did not adopt it."""
        from scripts.cuw_engine_threads import validate_thread_phase_lease

        validate_thread_phase_lease(lease, self)
        with self._phase_state_lock:
            if (
                lease.state != "reserved"
                or not self._active
                or self._phase_thread is not None
            ):
                raise ValueError("Unadopted native worker reservation required")
            lease._release()
            self._active = False
            self._worker_phase = None
            self._phase_finished.set()
        self._lock.release()

    @contextmanager
    def controller_execution(self, controller, phase: int, *, lease=None):
        """Own one concrete outer worker while b3e0 dispatches family exports."""
        from scripts.programming_2026_common import ControlCommPhase2026

        if type(controller) is not ControlCommPhase2026:
            raise TypeError("Concrete native controller required")
        if type(phase) is not int or phase not in (0, 1, 2):
            raise ValueError("Native outer worker phase must be0..2")
        if lease is None:
            worker = self.bind_worker(controller)
            self._require_prepare_dispatch(worker, phase)
            if not self._lock.acquire(blocking=False):
                raise ValueError("CUW phase is active")
            try:
                self._require_native_phase_idle()
            except BaseException:
                self._lock.release()
                raise
        else:
            from scripts.cuw_engine_threads import validate_thread_phase_lease

            validate_thread_phase_lease(lease, self, controller=controller, phase=phase)
            if not self._active or self._phase_thread is not None:
                raise ValueError("Unadopted native worker reservation required")
            worker = self._worker
            if worker is None or worker.controller is not controller:
                raise ValueError("Reserved native worker identity changed")
            self._require_prepare_dispatch(worker, phase)
            lease._adopt()
        runtime = controller.runtime
        original_native_cancelled = runtime.native_cancelled
        try:
            self._validate_persistence_source(self.native_metadata)
            with self._phase_state_lock:
                if lease is None:
                    self._cancelled.clear()
                    self._phase_finished = Event()
                self._active, self._phase_thread, self._worker_phase = (
                    True,
                    get_ident(),
                    phase,
                )
            self._controller_execution = controller
            runtime.native_cancelled = self.native_cancelled
            try:
                if self._retry_controller is not None:
                    self._retry_controller.worker_started()
                worker._phase_started(phase)
                self._import_identifier_context()
                yield worker
                worker._phase_finished(phase)
            except (Exception, KeyboardInterrupt) as error:
                try:
                    worker._phase_failed(error)
                except (Exception, KeyboardInterrupt) as cleanup_error:  # noqa: BLE001 - preserve the original failure
                    error.add_note(
                        "Worker failure cleanup: " + type(cleanup_error).__name__
                    )
                raise
        finally:
            if self._retry_controller is not None and not (
                self._thread_job is not None and self._thread_job.is_child_thread
            ):
                self._retry_controller.worker_stopped()
            runtime.native_cancelled = original_native_cancelled
            self._controller_execution = None
            with self._phase_state_lock:
                self._active, self._phase_thread = False, None
                self._phase_finished.set()
            if lease is not None:
                lease._release()
            self._lock.release()

    def run_bound_phase(self, phase: int, session, runtime):
        """One concrete export within the controller's shared chronological runtime."""
        from scripts.programming_2026_common import NativeRuntime2026
        from scripts.programming_replay import ProgrammingReplay

        operations = {
            0: ("get_cid",),
            1: ("prepare",),
            2: ("write", "recovery"),
            3: ("change_gateway",),
        }
        if self._controller_execution is not None:
            operations[2] = (*operations[2], "probe")
        if (
            type(session) is not ProgrammingReplay
            or type(runtime) is not NativeRuntime2026
        ):
            raise TypeError("Concrete replay and shared native runtime required")
        if (
            type(phase) is not int
            or phase not in operations
            or session.operation not in operations[phase]
        ):
            raise ValueError("Native phase differs from captured operation")
        if self._controller_execution is not None:
            self._require_owned_phase()
            controller = self._controller_execution
            if (
                runtime is not controller.runtime
                or session._controller2026 is not controller
            ):
                raise ValueError("Export differs from its actual outer controller")
            if (self._worker_phase == 0) != (phase == 0):
                raise ValueError(
                    "Export differs from the actual CID/programming worker"
                )
            metadata = self.native_metadata
            self._validate_persistence_source(metadata)
            if (
                session.container.digest != self.source_sha256
                or session.node != metadata.node
                or session.used
            ):
                raise ValueError("Unused replay bound to loaded CUW/node required")
            session.bind_runtime2026(runtime)
            session.bind_engine2026(self)
            self.dh_state._native_comm_phase = phase
            return session.run_bound2026(runtime)
        self._require_native_phase_idle()
        if not self._lock.acquire(blocking=False):
            raise ValueError("CUW phase is active")
        original_trace_cancelled = session.trace.cancelled
        original_runtime_cancelled = runtime.cancelled
        original_native_cancelled = runtime.native_cancelled
        try:
            metadata = self.native_metadata
            self._validate_persistence_source(metadata)
            if (
                session.container.digest != self.source_sha256
                or session.node != metadata.node
                or session.used
            ):
                raise ValueError("Unused replay bound to loaded CUW/node required")
            # Bind while the original trace/runtime boundary identities still match.
            session.bind_runtime2026(runtime)
            session.bind_engine2026(self)
            runtime.native_cancelled = self.native_cancelled
            with self._phase_state_lock:
                self._cancelled.clear()
                self._phase_finished = Event()
                self._active, self._phase_thread, self._worker_phase = (
                    True,
                    get_ident(),
                    1 if phase == 3 else phase,
                )
            self.dh_state._native_comm_phase = phase
            parent = session.alternate_parent2026() if phase == 0 else None
            previous_getter = self._last_completed_standalone_getter
            if parent is None:
                self._import_identifier_context()
            elif (
                previous_getter is None
                or previous_getter[0] is not parent
                or previous_getter[1] is not runtime
                or previous_getter[2] != self._identifier_context_epoch
                or previous_getter[3] is not session._controller2026
                or previous_getter[4] is not self.native_metadata
            ):
                raise ValueError("Actual immediately preceding empty getter required")
            self._last_completed_standalone_getter = None
            worker = self._worker
            if worker is not None and worker.runtime is not runtime:
                raise ValueError("Native export runtime differs from its issued worker")
            try:
                if self._retry_controller is not None:
                    self._retry_controller.worker_started()
                if worker is not None:
                    worker._phase_started(phase)
                report = session.run_bound2026(runtime)
                if worker is not None:
                    worker._phase_finished(phase)
                if (
                    phase == 0
                    and parent is None
                    and session._controller2026 is not None
                ):
                    values = report.get("identifiers", report.get("cids"))
                    if type(values) in (tuple, list) and not values:
                        self._last_completed_standalone_getter = (
                            session,
                            runtime,
                            self._identifier_context_epoch,
                            session._controller2026,
                            self.native_metadata,
                        )
                return report
            except (Exception, KeyboardInterrupt) as error:
                if worker is not None:
                    try:
                        worker._phase_failed(error)
                    except (Exception, KeyboardInterrupt) as cleanup_error:  # noqa: BLE001 - preserve the original phase failure
                        error.add_note(
                            "Worker failure cleanup: " + type(cleanup_error).__name__
                        )
                raise
        finally:
            if self._retry_controller is not None:
                self._retry_controller.worker_stopped()
            session.trace.cancelled = original_trace_cancelled
            runtime.cancelled = original_runtime_cancelled
            runtime.native_cancelled = original_native_cancelled
            with self._phase_state_lock:
                self._active, self._phase_thread = False, None
                self._phase_finished.set()
            self._lock.release()


def process_after_reprogramming(controller) -> int:
    """CUW654d0 queries ControlCommPhase and disconnects only while sending."""
    from scripts.programming_2026_common import ControlCommPhase2026

    if type(controller) is not ControlCommPhase2026:
        raise TypeError("Concrete CUW2026 ControlCommPhase required")
    if controller.is_sending_sync_periodic_msg_to_ecu():
        controller.disconnect_j2534_connection()
    return 0


def native_protocol(contact_type: str, diag_comm_protocol: str = "") -> int:
    """CUW10033b40 plus actual CommonDefinitions CANFD string'02'."""
    if any(
        not isinstance(value, str) or len(value) > 128
        for value in (contact_type, diag_comm_protocol)
    ):
        raise ValueError("Bounded native communication protocol fields required")
    if contact_type == "SIL":
        return 3
    if contact_type == "Ethernet":
        return 0x800F
    return (
        0x8012
        if contact_type in ("P5-Unified", "Phase6") and diag_comm_protocol == "02"
        else 6
    )


def connect_j2534(
    device: J2534Device2026 | None,
    contact_type: str | None,
    diag_comm_protocol: str = "",
) -> int:
    """Public4007 guard, concrete native device connection and1000ms timeout."""
    if device is None or contact_type is None:
        return 0xFA7
    if not isinstance(device, J2534Device2026):
        raise TypeError("Concrete CUW2026 J2534 implementation required")
    protocol = native_protocol(contact_type, diag_comm_protocol)
    if device.driver is not None:
        device.connect_native(protocol)
    else:
        device.connect(protocol)
    device.timeout = 1000
    return 0


def disconnect_j2534(device: J2534Device2026) -> int:
    if not isinstance(device, J2534Device2026):
        raise TypeError("Concrete CUW2026 J2534 implementation required")
    if device.channel_id is None:
        return 0xFA8
    device.disconnect()
    return 0


def _bytes(data: bytes) -> None:
    if not isinstance(data, bytes) or not 0 < len(data) <= MAX_BYTES:
        raise ValueError("Nonempty immutable input within 64 MiB required")


@dataclass(frozen=True)
class ZIPHeader:
    status: int
    text: str = field(repr=False)
    source_sha256: str
    marker_offset: int | None


def read_file_header(data: bytes) -> ZIPHeader:
    """AccessZIP.ReadFileHeader: mixed-case ASCII marker, Shift-JIS prefix.

    Marker at zero retains native status2 (the native sentinel is zero).
    A truncated marker suffix is rejected rather than indexing beyond the input.
    """
    _bytes(data)
    offset = data.lower().find(MARKER)
    return ZIPHeader(
        0 if offset > 0 else 2,
        data[:offset].decode("cp932", errors="replace") if offset > 0 else "",
        hashlib.sha256(data).hexdigest(),
        offset if offset >= 0 else None,
    )


def read_header_buffer(data: bytes, output: bytearray, *, encoding: str) -> int:
    """Mixed wrapper's strncpy_s(...,_TRUNCATE); nonzero status leaves output alone."""
    if not isinstance(output, bytearray) or not 1 <= len(output) <= 1024 * 1024:
        raise ValueError("Bounded nonempty mutable native output buffer required")
    result = read_file_header(data)
    if result.status == 0:
        text = result.text.encode(encoding, errors="replace").split(b"\0", 1)[0]
        data = text[: len(output) - 1] + b"\0"
        output[: len(data)] = data
    return result.status


@dataclass(frozen=True)
class ZIPMember:
    name: str
    data: bytes = field(repr=False)


def extract_zip(
    data: bytes,
    source_name: str,
    *,
    cancelled: Callable[[], bool] = lambda: False,
) -> tuple[ZIPMember, ...]:
    """Native compressed CUW stripping and ZIP extraction, returning exact bytes.

    The native .cuwc/.scuw branch skips the marker and exactly one following byte.
    Output safety bounds deliberately reject traversal, duplicates and symlinks.
    """
    _bytes(data)
    if not isinstance(source_name, str) or not 0 < len(source_name) <= 4096:
        raise ValueError("Bounded source filename required")
    if source_name.lower().endswith((".cuwc", ".scuw")):
        marker = data.lower().find(MARKER)
        if marker >= 0:
            data = data[marker + len(MARKER) + 1 :]
    result = []
    total = 0
    seen = set()
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        if len(archive.infolist()) > 4096:
            raise ValueError("ZIP member count exceeds bound")
        for info in archive.infolist():
            if cancelled():
                raise InterruptedError("ZIP extraction cancelled")
            path = PurePosixPath(info.filename)
            mode = info.external_attr >> 16
            if (
                not info.filename
                or len(info.filename) > 1024
                or "\\" in info.filename
                or ":" in info.filename
                or "\0" in info.filename
                or path.is_absolute()
                or any(
                    part in ("", ".", "..")
                    for part in info.filename.rstrip("/").split("/")
                )
                or stat.S_ISLNK(mode)
                or path.as_posix().casefold() in seen
                or info.flag_bits & 1
            ):
                raise ValueError("Unsafe or ambiguous ZIP member")
            seen.add(path.as_posix().casefold())
            total += info.file_size
            if total > MAX_BYTES or info.file_size < 0:
                raise ValueError("ZIP expanded bytes exceed bound")
            if info.is_dir():
                continue
            with archive.open(info) as member:
                output = member.read(info.file_size + 1)
            if len(output) != info.file_size:
                raise ValueError("ZIP member size mismatch")
            result.append(ZIPMember(path.as_posix(), output))
    return tuple(result)


def _directory(path: Path) -> int:
    """Open each parent without following symlinks; caller closes returned fd."""
    absolute = path.absolute()
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in absolute.parts[1:]:
            if part in (".", ".."):
                raise ValueError("Dot components forbidden in output path")
            child = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def write_new_file(path: str | Path, data: bytes) -> None:
    """Exclusive bounded output; never overwrite or follow an output symlink."""
    if not isinstance(data, bytes) or len(data) > MAX_BYTES:
        raise ValueError("Bounded immutable output required")
    target = Path(path)
    if target.name in ("", ".", ".."):
        raise ValueError("Output filename required")
    parent = _directory(target.parent)
    created = False
    try:
        descriptor = os.open(
            target.name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=parent,
        )
        created = True
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        if created:
            os.unlink(target.name, dir_fd=parent)
        raise
    finally:
        os.close(parent)


def write_new_tree(
    members: tuple[ZIPMember, ...],
    destination: str | Path,
    *,
    cancelled: Callable[[], bool] = lambda: False,
) -> tuple[dict, ...]:
    """Write a new owned output tree; failed/cancelled copies remove only our files."""
    if not isinstance(members, tuple) or not 0 < len(members) <= 4096:
        raise ValueError("Bounded immutable output members required")
    seen = set()
    total = 0
    for member in members:
        if not isinstance(member, ZIPMember) or not isinstance(member.data, bytes):
            raise TypeError("Immutable output members required")
        path = PurePosixPath(member.name)
        if (
            not member.name
            or len(member.name) > 1024
            or path.is_absolute()
            or "\\" in member.name
            or ":" in member.name
            or "\0" in member.name
            or any(part in ("", ".", "..") for part in member.name.split("/"))
            or member.name.casefold() in seen
        ):
            raise ValueError("Unsafe or duplicate output member")
        seen.add(member.name.casefold())
        total += len(member.data)
        if total > MAX_BYTES:
            raise ValueError("Output tree exceeds byte bound")
    target = Path(destination)
    if target.name in ("", ".", ".."):
        raise ValueError("New output directory required")
    parent = _directory(target.parent)
    root = None
    directories: dict[str, int] = {}
    created = []
    made_root = False
    manifest = []
    try:
        if cancelled():
            raise InterruptedError("Output copy cancelled")
        os.mkdir(target.name, mode=0o700, dir_fd=parent)
        made_root = True
        root = os.open(
            target.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent
        )
        directories[""] = root
        for member in members:
            if cancelled():
                raise InterruptedError("Output copy cancelled")
            parts = member.name.split("/")
            for length in range(1, len(parts)):
                directory = "/".join(parts[:length])
                if directory not in directories:
                    if len(directories) >= 4096:
                        raise ValueError("Output directory count exceeds host bound")
                    owner = directories["/".join(parts[: length - 1])]
                    os.mkdir(parts[length - 1], mode=0o700, dir_fd=owner)
                    created.append((owner, parts[length - 1], True))
                    directories[directory] = os.open(
                        parts[length - 1],
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                        dir_fd=owner,
                    )
            owner = directories["/".join(parts[:-1])]
            descriptor = os.open(
                parts[-1],
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=owner,
            )
            created.append((owner, parts[-1], False))
            with os.fdopen(descriptor, "wb") as output:
                for offset in range(0, len(member.data), 65536):
                    if cancelled():
                        raise InterruptedError("Output copy cancelled")
                    output.write(member.data[offset : offset + 65536])
                output.flush()
                os.fsync(output.fileno())
            manifest.append(
                {
                    "name": member.name,
                    "size": len(member.data),
                    "sha256": hashlib.sha256(member.data).hexdigest(),
                }
            )
        os.fsync(root)
        return tuple(manifest)
    except BaseException:
        if root is not None:
            for owner, name, directory in reversed(created):
                if directory:
                    os.rmdir(name, dir_fd=owner)
                else:
                    os.unlink(name, dir_fd=owner)
        if made_root:
            os.rmdir(target.name, dir_fd=parent)
        raise
    finally:
        for descriptor in directories.values():
            os.close(descriptor)
        os.close(parent)


def usb_payload_bytes(
    source: bytes,
    *,
    offset: int,
    length: int,
    crc_offset: int,
    expected_crc: int,
    cancelled: Callable[[], bool] = lambda: False,
) -> bytes:
    """Actual CReproDataFileCopier Copy region and big-endian stored-CRC comparison.

    This compares the source header word to the parsed calibration CRC exactly as
    native does; it does not replace that check with a different checksum scheme.
    """
    _bytes(source)
    for value in (offset, length, crc_offset, expected_crc):
        if type(value) is not int or not 0 <= value <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError("Native unsigned copy span/CRC required")
    if (
        expected_crc > 0xFFFFFFFF
        or not 0 < length <= MAX_BYTES
        or offset > len(source) - length
        or crc_offset > len(source) - 4
    ):
        raise ValueError("Native USB copy span leaves source")
    if int.from_bytes(source[crc_offset : crc_offset + 4], "big") != expected_crc:
        raise ValueError("Native USB copy stored CRC mismatch")
    output = bytearray()
    for position in range(offset, offset + length, 0x500000):
        if cancelled():
            raise InterruptedError("Native USB payload copy cancelled")
        output.extend(source[position : min(position + 0x500000, offset + length)])
    return bytes(output)


def usb_copy_status(native_state: int) -> int:
    """10065970 translates copier0/1/2/3 into9106/1/9105/0."""
    if type(native_state) is not int or not -(2**31) <= native_state < 2**31:
        raise ValueError("Signed32-bit native copy state required")
    return {0: 0x2392, 1: 1, 2: 0x2391}.get(native_state, 0)


def import_repro_key_2026(data: bytes, *, source: str) -> ReproKey:
    """XDocument.Element(Signature).Value includes descendant text in2026."""
    if not isinstance(source, str) or not 0 < len(source) <= 4096:
        raise ValueError("Bounded repro-key source required")
    try:
        root = _xml(data)
    except ServiceError as error:
        raise ServiceError(8, "Malformed repro key XML") from error
    if root.tag != "Signature":
        raise ServiceError(8, "Signature root missing")
    value = "".join(root.itertext())
    if len(value) != 512:
        raise ServiceError(9, "Repro signature must contain exactly 512 characters")
    if re.fullmatch("[0-9a-zA-Z]+", value, re.ASCII) is None:
        raise ServiceError(10, "Repro signature contains invalid characters")
    return ReproKey(value, source, hashlib.sha256(data).hexdigest())


class RKSAccess2026(RKSAccess):
    """2026 managed caller; browser ownership/deadlines use the shared host seam."""

    def import_key(self, path: str | Path) -> ReproKey:
        try:
            data = read_regular(path, limit=1024 * 1024)
        except FileNotFoundError as error:
            raise ServiceError(7, "Repro key file missing") from error
        return import_repro_key_2026(data, source=str(path))


def rks_data_from_native(data: bytes, *, encoding: str) -> RKSData:
    """Inline ANSI field offsets from2026 SetDataForReproKey's actual CIL."""
    if not isinstance(data, bytes) or not 128 <= len(data) <= 4096:
        raise ValueError("Bounded native repro-key data struct required")
    offsets = (0, 3, 38, 53, 100, 118, 120, 127, len(data))
    fields = []
    for start, stop in pairwise(offsets):
        end = data.find(b"\0", start, stop)
        if end < 0:
            raise ValueError("Native repro-key field lacks in-field terminator")
        fields.append(data[start:end].decode(encoding))
    return RKSData(*fields)


class CommunicationLogNativeFault(Exception):
    """Captured native C++ exception, distinct from host/programming failures."""


def set_communication_log_mode(runtime, mode: int) -> int:
    """Actual MsgDatCommWrapper signed32 mode/result and native-exception result0."""
    if type(mode) is not int or not -(2**31) <= mode < 2**31:
        raise ValueError("Signed32-bit communication log mode required")
    try:
        result = runtime.call("set_communication_log_mode", mode=mode)
    except CommunicationLogNativeFault:
        return 0
    if type(result) is not int or not -(2**31) <= result < 2**31:
        raise ValueError("Signed32-bit native logging result required")
    return result


def notification_font_heights(
    first: bytes,
    second: bytes,
    width: int,
    height: int,
    measure: Callable[[bytes], tuple[int, int]],
) -> tuple[int, int]:
    """Actual2026 Arial sizing:0.9 width scale,1.3 shorter-text height ceiling."""
    if any(
        not isinstance(value, bytes) or len(value) > 4096 for value in (first, second)
    ):
        raise ValueError("Bounded native notification text bytes required")
    if any(
        type(value) is not int or not 0 < value <= 65536 for value in (width, height)
    ):
        raise ValueError("Bounded positive screen dimensions required")

    def fit(text):
        extent = measure(text)
        if (
            not isinstance(extent, tuple)
            or len(extent) != 2
            or any(
                type(value) is not int or not 0 <= value <= 2**31 - 1
                for value in extent
            )
        ):
            raise ValueError("Native text-extent pair required")
        return min(
            height // 2, int(extent[1] / extent[0] * width * 0.9) if extent[0] else 0
        )

    if len(second) < len(first):
        first_height = fit(first)
        return first_height, min(int(first_height * 1.3), fit(second))
    second_height = fit(second)
    return min(int(second_height * 1.3), fit(first)), second_height


class CompletionNotice2026(CompletionNotice):
    """2026 native pulse/event controller over the common visual host primitives.

    Unsupported sound modes have no delay on the color2 phase in native code.
    The cooperative loop retains that transition without spawning a worker thread.
    """

    def run(self, config: NoticeConfig) -> str:
        if not isinstance(config, NoticeConfig):
            raise TypeError("Completion notice configuration required")
        _text(config.title, 4096)
        _text(config.message, 4096)
        if (
            any(
                type(value) is not int or not 0 <= value <= 0xFFFFFF
                for value in (config.color1, config.color2)
            )
            or type(config.interval_ms) is not int
            or not 1 <= config.interval_ms <= 60000
            or type(config.sound_mode) is not int
            or not -(2**31) <= config.sound_mode < 2**31
        ):
            raise ValueError("Invalid native notification configuration")
        with self._lock:
            if self.state != "new":
                raise RuntimeError("Completion notice execution is terminal")
            budget = _Deadline(self.timeout, self.cancelled, self.clock)
            self.state = "showing"
            window = None
            original = None
            try:
                anchor = self.host.cursor(
                    timeout=budget.remaining(), cancelled=budget.stopped
                )
                if (
                    not isinstance(anchor, tuple)
                    or len(anchor) != 2
                    or any(type(value) is not int for value in anchor)
                ):
                    raise ValueError("Invalid initial cursor location")
                window = self.host.create_window(
                    config.title,
                    config.message,
                    fullscreen=True,
                    topmost=True,
                    timeout=budget.remaining(),
                    cancelled=budget.stopped,
                )
                _text(window, 256, required=True)
                self.window = window
                phase, next_pulse = 1, self.clock()
                for _ in range(120000):
                    budget.remaining()
                    if self.window is None:
                        raise InterruptedError("Completion notice was closed")
                    now = self.clock()
                    if now >= next_pulse:
                        self.host.render(
                            window,
                            config.color2 if phase else config.color1,
                            config.title,
                            config.message,
                            timeout=budget.remaining(),
                            cancelled=budget.stopped,
                        )
                        if phase and config.sound_mode in (0, 1):
                            self.host.beep(
                                config.sound_mode,
                                1728,
                                config.interval_ms,
                                timeout=budget.remaining(),
                                cancelled=budget.stopped,
                            )
                        delay = (
                            config.interval_ms / 1000
                            if not phase or config.sound_mode in (0, 1)
                            else 0
                        )
                        next_pulse = now + delay
                        phase ^= 1
                        if delay == 0:
                            continue
                    event = self.host.poll_event(
                        window,
                        timeout=min(
                            0.05,
                            budget.remaining(),
                            max(0.001, next_pulse - self.clock()),
                        ),
                        cancelled=budget.stopped,
                    )
                    budget.remaining()
                    if event is not None:
                        if not isinstance(event, NoticeEvent) or event.window != window:
                            raise ValueError("Notice event belongs to another window")
                        if event.kind in ("key", "left-click", "right-click", "close"):
                            self.state = "dismissed"
                            return event.kind
                        if (
                            event.kind != "move"
                            or type(event.x) is not int
                            or type(event.y) is not int
                        ):
                            raise ValueError("Unknown completion notice event")
                        if (
                            abs(event.x - anchor[0]) > 50
                            or abs(event.y - anchor[1]) > 50
                        ):
                            self.state = "dismissed"
                            return "move"
                raise TimeoutError("Completion notice polling work budget exhausted")
            except BaseException as error:
                original = error
                self.state = "uncertain"
                raise
            finally:
                if window is not None:
                    _cleanup(self.close, original)


def serialize_object(value: object, *, indented: bool = False) -> str:
    """Newtonsoft.JsonWrapper maps Boolean formatting to enum None0/Indented1.

    Accept only JSON primitives; CLR reflection/converters require separate ports.
    """
    if type(indented) is not bool:
        raise TypeError("Boolean JSON formatting flag required")

    # Count expanded visits, including repeated containers: a small DAG can
    # otherwise expand exponentially both here and inside json.dumps.
    remaining_nodes, remaining_bytes = 4096, MAX_BYTES

    def charge(amount):
        nonlocal remaining_bytes
        remaining_bytes -= amount
        if remaining_bytes < 0:
            raise ValueError("JSON encoded-size budget exceeded")

    def validate(item, depth=0):
        nonlocal remaining_nodes
        remaining_nodes -= 1
        if remaining_nodes < 0:
            raise ValueError("JSON expanded value count exceeds bound")
        if depth > 32:
            raise ValueError("JSON depth exceeds bound")
        # Includes separators, CRLF and the maximum indentation at this depth.
        charge(2 * depth + 8)
        if item is None or type(item) in (str, int, float, bool):
            if type(item) is str:
                # Each character needs at most6 UTF8 bytes after JSON escaping.
                charge(6 * len(item) + 2)
            elif type(item) is int:
                if item.bit_length() > 4096:
                    raise ValueError("JSON integer exceeds host bound")
                charge(1235)
            else:
                charge(32)
            return
        if type(item) is list and len(item) <= 4096:
            for child in item:
                validate(child, depth + 1)
            return
        if (
            type(item) is dict
            and len(item) <= 4096
            and all(type(key) is str for key in item)
        ):
            for key, child in item.items():
                charge(6 * len(key) + 2 * depth + 8)
                validate(child, depth + 1)
            return
        raise TypeError("JSON primitive value required")

    validate(value)
    output = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        indent=2 if indented else None,
        separators=None if indented else (",", ":"),
    )
    if len(output.encode("utf-8")) > MAX_BYTES:
        raise ValueError("JSON output exceeds bound")
    return output.replace("\n", "\r\n") if indented else output


def vehicle_info_from_memory(
    memory: bytes,
    address: int,
    format_type: int,
    *,
    encoding: str,
    base: int = 0,
) -> dict:
    """2026 writer's actual32-bit pointer structs, interpreted without dereferencing.

    Encoding is explicit: native String(sbyte*) uses the Windows ANSI codepage.
    The owned immutable memory image must contain all pointed-to strings/arrays.
    """
    _bytes(memory)
    if any(
        type(value) is not int or not 0 <= value <= 0xFFFFFFFF
        for value in (address, base)
    ):
        raise ValueError("Unsigned32-bit native address/base required")
    if type(format_type) is not int or not 0 <= format_type <= 0xFFFFFFFF:
        raise ValueError("Unsigned32-bit vehicle-info format required")
    if not isinstance(encoding, str) or not encoding:
        raise ValueError("Explicit native ANSI encoding required")
    budget = [4096, MAX_BYTES]

    def span(pointer, size):
        offset = pointer - base
        if offset < 0 or size < 0 or offset > len(memory) - size:
            raise ValueError("Native vehicle-info pointer leaves supplied memory")
        return offset

    def word(pointer):
        return struct.unpack_from("<I", memory, span(pointer, 4))[0]

    def text(pointer):
        pointer = word(pointer)
        if pointer == 0:
            return ""
        offset = span(pointer, 1)
        end = memory.find(b"\0", offset, min(offset + 4097, len(memory)))
        if end < 0:
            raise ValueError("Native vehicle-info string missing bounded terminator")
        budget[1] -= end - offset
        if budget[1] < 0:
            raise ValueError("Native vehicle-info string budget exceeded")
        return memory[offset:end].decode(encoding)

    def array(row, count_offset, pointer_offset, stride, convert):
        count = word(row + count_offset)
        budget[0] -= count
        if budget[0] < 0:
            raise ValueError("Native vehicle-info array exceeds host bound")
        pointer = word(row + pointer_offset)
        if count:
            span(pointer, count * stride)
        return [convert(pointer + index * stride) for index in range(count)]

    def ecu(row):
        span(row, 44)
        result: dict = {
            name: text(row + index * 4)
            for index, name in enumerate(
                ("ecuAssyNo", "hwPartNo", "addressType", "diagAddress", "serialNo")
            )
        }
        result["swinList"] = array(row, 20, 24, 4, lambda item: {"swin": text(item)})
        result["swNoList"] = array(
            row,
            28,
            32,
            8,
            lambda item: {"swNo": text(item), "writeFlg": text(item + 4)},
        )
        result["cBest"] = array(row, 36, 40, 4, lambda item: {"cBestData": text(item)})
        return result

    span(address, 32)
    req = address + 8
    request = {"vinNo": text(req), "ecuInfo": array(req, 4, 8, 44, ecu)}
    if format_type != 1:
        request["dcmLocalWriteTime"] = text(req + 12)
        request["localWriteTime"] = text(req + 16)
    request["ifHash"] = text(req + 20)
    return {
        "sendVehicleInfo": {"SoftwareID": text(address), "ID": text(address + 4)},
        "reqData": request,
    }


def export_vehicle_info(
    path: str | Path,
    memory: bytes,
    address: int,
    format_type: int,
    *,
    encoding: str,
    base: int = 0,
) -> bool:
    value = vehicle_info_from_memory(
        memory, address, format_type, encoding=encoding, base=base
    )
    output = serialize_object(value, indented=True).encode("utf-8")
    try:
        write_new_file(path, output)
    except FileExistsError:
        return False
    return True
