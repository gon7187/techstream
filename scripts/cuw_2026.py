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
from dataclasses import dataclass, field, replace
from itertools import pairwise
from pathlib import Path, PurePosixPath
from threading import Event, Lock, RLock, current_thread, get_ident
from time import monotonic
from typing import TYPE_CHECKING, Any, Literal, Protocol, cast, runtime_checkable

if TYPE_CHECKING:
    from scripts.calibration_2026 import Native2026Metadata, NativeUSBSource2026
    from scripts.cuw_engine_cleanup import EngineCleanup2026
    from scripts.cuw_engine_threads import EngineThreadJob2026, ThreadPhaseLease2026
    from scripts.cuw_engine_worker import EngineWorker2026
    from scripts.cuw_file_services import (
        FileReadResult2026,
        FileSourceSet2026,
        NativeFileView2026,
        _NativeWaitTimingStep2026,
    )
    from scripts.cuw_large import LargeSource2026, NativeLargeContainer2026
    from scripts.programming_2026_common import (
        CommonDefinitions2026,
        ControlCommPhase2026,
        NativeFrontendParameters2026,
        NotificationBool,
    )

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

_NATIVE_CUW_SOURCE_2026 = (
    "C:\\Shimojo\\local\\CUW.dll\\V1.15.0.3(\x83r\x83\x8b\x83h\x97p)"
    "\\CUW\\CUW\\CPassThruCtrlr.cpp"
)
from scripts.j2534_2026 import J2534Device2026
from scripts.local_files import read_regular
from scripts.native_modules import NativeModuleIdentity, identify_native_module

MAX_BYTES = 64 * 1024 * 1024
MARKER = b"[datacompression]"
_RKS_SOFTWARE_TOKEN = object()
_GATEWAY_AUTH_TOKEN = object()
_WAIT_TIMING_ADMISSION_TOKEN = object()


@dataclass(frozen=True)
class _PersistenceCPUTransition2026:
    producer: str
    origin: object
    worker: object
    persistence: object
    state: object
    metadata: object
    file_sources: object
    container: object
    digest: str
    node: int
    persisted_cpu: int
    before_cpu: int
    after_cpu: int


@dataclass(frozen=True, eq=False)
class _PersistenceFileFlowTransition2026:
    producer: str
    origin: object
    worker: object
    persistence: object
    state: object
    old_sources: object
    new_sources: object
    before_flow: int
    after_flow: int
    persisted_file_index: int
    flow_view: NativeFileView2026
    current_pointer_view: NativeFileView2026
    mapped_reset_origin: object | None = None


@dataclass(frozen=True, eq=False)
class _FileAdmissionOrigin2026:
    engine: object
    worker: object
    persistence: object
    state: object
    sources: object
    admission_view: object
    flow_view: object
    source_container: object
    digest: str
    thread_id: int


@dataclass(frozen=True, eq=False)
class _NativeGetterStopOrigin2026:
    engine: CUWEngine2026
    job: EngineThreadJob2026
    worker: EngineWorker2026
    controller: ControlCommPhase2026
    generation: object
    sequence: int
    lease: ThreadPhaseLease2026 | None
    issuer_thread: int
    producer: Literal["5f030", "40580"]
    cleanup: EngineCleanup2026 | None


@dataclass(eq=False)
class _JudgeFlashableInvocation2026:
    engine: CUWEngine2026
    worker: EngineWorker2026
    region: int
    thread_id: int
    configuration: object
    reset_epoch: int
    file_sources: object
    persistence: object
    persistence_state: object
    flow_index: int
    global_cpu_index: int
    persisted_cpu: int | None
    persisted_file: int | None
    entered: bool = False
    commit_started: bool = False
    commit_completed: bool = False
    commit_origin: object | None = None
    candidate: NativeFileView2026 | None = None
    committed_index: int | None = None
    memory_published: bool = False
    reset_origin: object | None = None
    reset_old_sources: object | None = None
    reset_new_sources: object | None = None
    reset_branch: Literal["mapped", "direct"] | None = None
    reset_pointer_view: object | None = None


@runtime_checkable
class _JudgeFileResetOriginValidator2026(Protocol):
    def _validate_judge_file_reset_stage2026(
        self, origin: object, old_sources: object, new_sources: object
    ) -> str: ...

    def _apply_judge_file_reset_before_pointer2026(self, origin: object) -> None: ...

    def _validate_judge_file_reset_publication2026(
        self, origin: object, old_sources: object, new_sources: object
    ) -> tuple[Native2026Metadata, NativeFileView2026]: ...

    def _publish_judge_file_reset_projection2026(self, origin: object) -> None: ...

    def _apply_judge_file_reset_after_pointer2026(self, origin: object) -> None: ...

    def _validate_judge_mode1_recovery_23b10_2026(
        self, origin: object
    ) -> tuple[object, object, int, Native2026Metadata, str, object]: ...


@runtime_checkable
class _FileFlowOriginValidator2026(Protocol):
    engine: Any
    source_state: Any
    _flow_file_index2026: int
    _getter_reset_epoch2026: int

    def _validate_file_flow_transition_origin2026(
        self,
        origin,
        *,
        producer,
        old_sources,
        new_sources,
        before_flow,
        after_flow,
        flow_view,
        current_pointer_view,
    ) -> None: ...

    def _validate_file_projection_origin2026(
        self, origin, view
    ) -> Native2026Metadata: ...

    def _validate_file_flow_clear_origin2026(self, origin) -> None: ...


@runtime_checkable
class _JudgeCommitOriginValidator2026(Protocol):
    def _validate_judge_commit_origin_62330_2026(
        self, origin: object, candidate: NativeFileView2026 | None
    ) -> None: ...


@runtime_checkable
class _NativeFlashabilityJudge2026(Protocol):
    def _judge_flashable_62330_2026(
        self, region: int
    ) -> NativeFlashabilityResult2026: ...


@runtime_checkable
class _JudgeFileProjectionOriginValidator2026(Protocol):
    def _validate_judge_file_projection_origin_2026(
        self, view: NativeFileView2026, *, worker, region: int, invocation: object
    ) -> Native2026Metadata: ...


@runtime_checkable
class _JudgeCommitProjectionOriginValidator2026(Protocol):
    def _validate_judge_commit_projection_origin_2026(
        self, view: NativeFileView2026, *, worker, origin: object
    ) -> Native2026Metadata: ...


@runtime_checkable
class _JudgePointerMirrorPublisher2026(Protocol):
    def _publish_judge_pointer_mirror_32ff0_2026(self, origin: object) -> None: ...


@dataclass(frozen=True)
class NativeFlashabilityRow2026:
    raw: bytes

    def __post_init__(self):
        if type(self.raw) is not bytes or len(self.raw) != 333:
            raise ValueError("Native flashability row must contain exactly333 bytes")


@dataclass(frozen=True)
class NativeFlashabilityResult2026:
    status: int
    flashable: bool
    rows: tuple[NativeFlashabilityRow2026, ...]
    row_count: int
    file_sources: object | None
    admission_source_sha256: str
    live_file_kind: Literal["none", "plain", "part", "whole"]
    live_file_index: int | None
    live_file_sha256: str | None
    flow_file_index: int
    recovery_file_index: int

    def __post_init__(self):
        if (
            type(self.status) is not int
            or not 0 <= self.status <= 0xFFFFFFFF
            or type(self.flashable) is not bool
            or type(self.rows) is not tuple
            or any(type(row) is not NativeFlashabilityRow2026 for row in self.rows)
            or type(self.row_count) is not int
            or self.row_count != len(self.rows)
            or type(self.admission_source_sha256) is not str
            or self.live_file_kind not in ("none", "plain", "part", "whole")
            or (
                self.live_file_index is not None
                and type(self.live_file_index) is not int
            )
            or (
                self.live_file_sha256 is not None
                and type(self.live_file_sha256) is not str
            )
            or type(self.flow_file_index) is not int
            or self.flow_file_index < 0
            or type(self.recovery_file_index) is not int
            or self.recovery_file_index < 0
        ):
            raise ValueError("Concrete native flashability result required")


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


@dataclass(frozen=True, eq=False)
class _InitialGetterReset40580_2026:
    """One cold34050 reset, awaiting its first unpublished worker projection."""

    engine: CUWEngine2026
    common_definitions: CommonDefinitions2026
    configuration: EngineConfiguration2026 | None
    parameters: NativeFrontendParameters2026
    maximum: int
    epoch: int


@dataclass(frozen=True, eq=False)
class _NativeWaitTimingAdmission2026:
    """One source-issued cold wait-timing trajectory and its one-shot cell."""

    engine: CUWEngine2026
    sources: FileSourceSet2026
    frontend: NativeFrontendParameters2026
    general: object
    catalog_sha256: tuple[tuple[str, str], ...]
    initial_reset: _InitialGetterReset40580_2026 = field(repr=False)
    initial_reset_epoch: int
    steps: tuple[_NativeWaitTimingStep2026, ...] = field(repr=False)
    phase6_transform: object | None = field(repr=False)
    table_stages: object = field(repr=False)
    _token: object = field(repr=False, compare=False)
    _lock: Any = field(default_factory=RLock, repr=False, compare=False)
    _consumed: bool = field(default=False, repr=False, compare=False)
    _query_cid_copy_count: int = field(default=0, repr=False, compare=False)

    def __post_init__(self):
        if self._token is not _WAIT_TIMING_ADMISSION_TOKEN:
            raise TypeError("Native wait timing admission is source-issued")


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


def _native_receiving_status_5f1b0_2026(
    phase: int, error: int, fatal: bool, receiving: bool, prompt: bool
) -> tuple[int, bool]:
    """Evaluate only the original receiving-status branches over native fields."""
    if (
        type(phase) is not int
        or not -(2**31) <= phase < 2**31
        or type(error) is not int
        or not 0 <= error <= 0xFFFFFFFF
        or any(type(value) is not bool for value in (fatal, receiving, prompt))
    ):
        raise ValueError("Native receiving-status source fields required")
    if error == 2:
        return 0xFA4, False
    if fatal:
        return 0x7D2, True
    if phase != 0:
        return 0x138B, False
    if receiving:
        return 1, False
    if prompt:
        return 2, False
    return (0x138C, True) if error != 0 else (0, False)


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
        for name in ("phase", "recovery_status", "key_state"):
            value = getattr(self, name)
            if type(value) is not int or not -(2**31) <= value < 2**31:
                raise ValueError("Signed32-bit native engine status required")
        if type(self.error) is not int or not 0 <= self.error <= 0xFFFFFFFF:
            raise ValueError("Unsigned DWORD native engine error required")
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
        return _native_receiving_status_5f1b0_2026(
            self.phase,
            self.error,
            self.fatal,
            self.receiving,
            self.receiving_prompt,
        )

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
_FILE_FLOW_PRODUCERS2026 = frozenset(
    {
        "43cd0-admission",
        "4b900-mode2",
        "3d120-fanout",
        "3d120-next",
        "3d120-end",
        "3ec30-next",
        "3ec30-end",
        "3f620-next",
        "3f620-end",
        "46be0-mode1",
    }
)


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
        self._dh_flash_size_metadata = None
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
    def _family_metadata(self):
        engine = self.engine
        if engine._controller_export_target2026 is not None:
            return engine.family_metadata
        return self.metadata

    @property
    def _family_native_cpu_index(self) -> int:
        engine = self.engine
        if engine._controller_export_target2026 is not None:
            return engine.family_cpu_index
        return self.native_cpu_index

    def _family_progress_vectors(self) -> tuple[list[int], list[int]]:
        engine = self.engine
        if engine._controller_export_target2026 is None:
            return list(self._transferred_bytes), list(self._progress)
        controller = engine._controller_execution
        target = engine._controller_export_target2026
        if controller is None:
            raise ValueError("Native CONTROL export scope has expired")
        target.validate(engine, controller)
        context = controller.native_control_context2026(engine)
        return list(context.count_scratch), list(context.percentage_scratch)

    def _store_family_progress_vectors(
        self, counts: list[int], percentages: list[int]
    ) -> None:
        engine = self.engine
        if engine._controller_export_target2026 is None:
            self._transferred_bytes = tuple(counts)
            self._progress = tuple(percentages)
            return
        controller = engine._controller_execution
        target = engine._controller_export_target2026
        if controller is None:
            raise ValueError("Native CONTROL export scope has expired")
        target.validate(engine, controller)
        context = controller.native_control_context2026(engine)
        if len(counts) != len(context.count_scratch) or len(percentages) != len(
            context.percentage_scratch
        ):
            raise ValueError("CONTROL output vector length changed while issued")
        for index, value in enumerate(counts):
            context._store_count2026(target, index, value)
        for index, value in enumerate(percentages):
            context._store_percentage2026(target, index, value)

    @property
    def native_cpu_index(self) -> int:
        """Ordered358 progress index; global_cpu_index remains parser-facing."""
        engine = self.engine
        if engine._controller_export_target2026 is not None:
            return engine.family_cpu_index
        if engine._worker is None:
            return self.global_cpu_index
        return engine.worker.source_state.current_global_cpu_index

    def native_index_for_source_cpu(self, index: int) -> int:
        """Map an actual parser CPU to its issued native progress-array position."""
        from scripts.calibration_2026 import native2026_cpu_values

        native2026_cpu_values(self._family_metadata, index)
        engine = self.engine
        if engine._controller_export_target2026 is not None:
            controller = engine._controller_execution
            if controller is None:
                raise ValueError("Native CONTROL export scope has expired")
            return controller.native_control_context2026(
                engine
            ).native_index_for_source_cpu(index)
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
        metadata = self._family_metadata
        cpu_index = (
            self._family_native_cpu_index
            if self.engine._controller_export_target2026 is not None
            else self.global_cpu_index
        )
        cpu = metadata.cpu
        files = cpu.files if cpu is not None else ()
        if (
            cpu_index != 0
            or type(expected) is not int
            or expected != self._divided_image_index
            or not 0 <= expected < len(files)
        ):
            raise ValueError("Bounded actualCPU0 divided-image transition required")
        self._divided_image_index += 1
        self.engine._publish_control_divided_index2026(self._divided_image_index)

    def reset_divided_image(self) -> None:
        self._divided_image_index = 0
        self.engine._publish_control_divided_index2026(0)

    def resume_divided_image_count(self) -> None:
        """DHUDS2120 adds completed Format4 images without changing percent."""
        from scripts.calibration_2026 import native2026_archive

        metadata = self._family_metadata
        cpu_index = (
            self._family_native_cpu_index
            if self.engine._controller_export_target2026 is not None
            else self.global_cpu_index
        )
        cpu = metadata.cpu
        if (
            metadata.format_version != 4
            or cpu_index != 0
            or cpu is None
            or not cpu.files
            or not 0 <= self._divided_image_index < len(cpu.files)
        ):
            raise ValueError("Actual CPU0 Format4 divided-image resume required")
        total = native2026_archive(metadata).flash_size
        remaining = tuple(
            native2026_archive(metadata, file_index=index).flash_size
            for index in range(1, len(cpu.files))
        )
        first = total - sum(remaining)
        if first < 0:
            raise ValueError("Native divided-image lengths exceed aggregate size")
        prefix = sum((first, *remaining)[: self._divided_image_index])
        counts, percentages = self._family_progress_vectors()
        counts[0] = (counts[0] + prefix) & 0xFFFFFFFF
        self._store_family_progress_vectors(counts, percentages)

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
        total = native2026_archive(self._family_metadata).flash_size
        if not 0 < total <= 0xFFFFFFFF:
            raise ValueError("Positive source-bound native flash size required")
        index = self.native_cpu_index
        counts, percentages = self._family_progress_vectors()
        transferred = (counts[index] + count) & 0xFFFFFFFF
        counts[index], percentages[index] = (
            transferred,
            (100 * transferred // total) & 0xFFFFFFFF,
        )
        self._store_family_progress_vectors(counts, percentages)

    def reset_usb_progress(self) -> None:
        counts, percentages = self._family_progress_vectors()
        percentages[0] = 0
        self._store_family_progress_vectors(counts, percentages)

    def complete_usb_progress(self, response: bytes) -> None:
        if type(response) is not bytes or not response.startswith(b"\x5a\xb1\x00"):
            raise ValueError("Actual native USB5ab100 completion response required")
        counts, percentages = self._family_progress_vectors()
        percentages[0] = 100
        self._store_family_progress_vectors(counts, percentages)

    @property
    def native_context_964(self) -> bool:
        return self._native_context_964

    def mark_native_retry(self) -> None:
        """Concrete native error/recovery paths set engine+3c0, never a JSON flag."""
        self._native_context_964 = True

    def _set_native_vector(self, field: str, cpu_index: int, value: int) -> None:
        from scripts.calibration_2026 import native2026_cpu_count

        metadata = self._family_metadata
        if (
            type(cpu_index) is not int
            or not 0 <= cpu_index < native2026_cpu_count(metadata)
            or type(value) is not int
            or not 0 <= value <= 0xFFFFFFFF
        ):
            raise ValueError("Source-bound global CPU index and native DWORD required")
        counts, percentages = self._family_progress_vectors()
        values = counts if field == "_transferred_bytes" else percentages
        values[cpu_index] = value
        if field == "_transferred_bytes":
            counts = values
        else:
            percentages = values
        self._store_family_progress_vectors(counts, percentages)

    def set_native_count(self, cpu_index: int, value: int) -> None:
        """Concrete family math mutates the native count before its observer."""
        self._set_native_vector("_transferred_bytes", cpu_index, value)

    def set_native_percentage(self, cpu_index: int, value: int) -> None:
        """Native DWORD percentages may exceed100; they do not certify completion."""
        self._set_native_vector("_progress", cpu_index, value)

    @property
    def progress(self) -> tuple[int, ...]:
        engine = self._engine
        if engine._controller_export_target2026 is None:
            return self._progress
        engine = self.engine
        if engine._controller_export_target2026 is not None:
            if engine._controller_execution is None:
                raise ValueError("Native CONTROL export scope has expired")
            return engine._controller_execution.native_control_context2026(
                engine
            ).percentage_scratch
        return self._progress

    @property
    def transferred_bytes(self) -> tuple[int, ...]:
        engine = self._engine
        if engine._controller_export_target2026 is None:
            return self._transferred_bytes
        engine = self.engine
        if engine._controller_export_target2026 is not None:
            if engine._controller_execution is None:
                raise ValueError("Native CONTROL export scope has expired")
            return engine._controller_execution.native_control_context2026(
                engine
            ).count_scratch
        return self._transferred_bytes

    def reset_dh_count(self) -> None:
        """CommonFlash4080 mutation, performed before the count notification."""
        values, percentages = self._family_progress_vectors()
        values[self.native_cpu_index] = 0
        self._store_family_progress_vectors(values, percentages)

    def reset_dh_progress(self) -> None:
        """CommonFlash4080 mutation, performed before the percent notification."""
        counts, values = self._family_progress_vectors()
        values[self.native_cpu_index] = 0
        self._store_family_progress_vectors(counts, values)

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
        metadata = self._family_metadata
        flash_size = (
            self._dh_flash_size if self._dh_flash_size_metadata == metadata else None
        )
        if flash_size is None:
            flash_size = native2026_archive(metadata).flash_size
        if total != flash_size:
            raise ValueError("DH transfer total differs from bound native flash size")
        progress = 100 * offset // total
        if not checksum:
            progress = progress // 2 + (50 if verification else 0)
        counts, percentages = self._family_progress_vectors()
        index = self._family_native_cpu_index
        counts[index] = (counts[index] + count) & 0xFFFFFFFF
        percentages[index] = progress
        self._dh_flash_size = flash_size
        self._dh_flash_size_metadata = metadata
        self._store_family_progress_vectors(counts, percentages)

    def _gateway_transfer(self, offset: int, total: int) -> None:
        from scripts.calibration_2026 import (
            native2026_archive,
            native2026_metadata_for_cpu,
        )

        engine = self.engine
        metadata = self._family_metadata
        if engine._controller_export_target2026 is not None:
            controller = engine._controller_execution
            if controller is None:
                raise ValueError("Native CONTROL export scope has expired")
            metadata = controller.native_control_context2026(engine).metadata_for_cpu(0)
        else:
            metadata = native2026_metadata_for_cpu(self.metadata, 0)
        if (
            type(offset) is not int
            or type(total) is not int
            or not 0 <= offset <= total <= 0xFFFFFFFF
            or total == 0
            or total != native2026_archive(metadata).flash_size
        ):
            raise ValueError("Gateway transfer requires bound globalCPU0 flash size")

    def record_gateway_count(self, offset: int, total: int) -> None:
        """Gateway1070 stores the offset before invoking its count observer."""
        self._gateway_transfer(offset, total)
        counts, percentages = self._family_progress_vectors()
        counts[0] = offset
        self._store_family_progress_vectors(counts, percentages)

    def record_gateway_progress(self, offset: int, total: int) -> None:
        """Gateway1070 stores percent after the count observer returns."""
        self._gateway_transfer(offset, total)
        counts, percentages = self._family_progress_vectors()
        percentages[0] = 100 * offset // total
        self._store_family_progress_vectors(counts, percentages)

    def record_multirom_transfer(self, count: int, binding) -> None:
        """MultiROM1970 uses both decimal EachWriteDataSize entries, not flash size."""
        from scripts.programming_2026_common import NativeParameterBinding2026

        if (
            type(binding) is not NativeParameterBinding2026
            or binding.module_name != "TCUWCanDHMultiROMFlashWriter.dll"
            or binding.metadata != self._family_metadata
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
        counts, percentages = self._family_progress_vectors()
        transferred = counts[0] + count
        if total > 0xFFFFFFFF or transferred > total:
            raise ValueError("MultiROM transfer exceeds source-bound partition lengths")
        counts[0] = transferred
        percentages[0] = 100 * transferred // total
        self._store_family_progress_vectors(counts, percentages)

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
        engine = self.engine
        if engine._controller_export_target2026 is not None:
            if engine._controller_execution is None:
                raise ValueError("Native CONTROL export scope has expired")
            return engine.worker.control_state.source_mode
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
        engine = self.engine
        if engine._controller_export_target2026 is not None:
            if engine._controller_execution is None:
                raise ValueError("Native CONTROL export scope has expired")
            engine.worker._publish_control_gateway_type2026(self)

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
        self._ssmid_cache2026 = 0
        self._dh_type_cache2026 = 0
        self._control_retry_cache2026 = False
        self._control_phase_cache2026 = 2
        self._control_alternate_cache2026 = False
        self._control_divided_index_cache2026 = 0
        self._native_error_output = (0, 0)
        self._native_fatal_output = False
        self._native_control_fatal_output = False
        self._native_receiving_cfe2_2026 = False
        self._native_receiving_prompt2026 = False
        self._native_outer_cfe0_2026 = False
        self._native_be54_pending2026 = False
        self._getter_protocol_4fc_2026: str | None = ""
        self._write_complete_output = False
        self._native_cycle_output = False
        self._continuation_backup = None
        self._native_prepare_handshake = 0
        self._logical_block_index = 0
        self._native_error_kind_output = 0
        self._native_previous_error_kind_output = 0
        self._native_cfc4_2026 = 0
        self._native_prepare_d314_2026 = 0
        self._native_recovery_file_index2026: int | None = None
        self._native_recovery_d9d4_2026: int | None = None
        self._native_recovery_target2026: int | None = None
        self._phase6_second_select2026 = None
        self._wait_current_pointer_metadata2026 = None
        self._worker = None
        self._interface_pair = None
        self._thread_job = None
        self._worker_replacement_thread = None
        self._controller_execution = None
        self._retry_controller = None
        self._frontend_parameters = None
        self._file_sources = None
        self._wait_current_igoffon2026: int = 0
        self._wait_igoffon_by_file2026: tuple[int, ...] = (0,) * 16
        self._wait_igoffon_aggregate2026 = 0
        self._wait_current_battery_disconnected2026: int = 0
        self._wait_battery_disconnected_by_file2026: tuple[int, ...] = (0,) * 16
        self._wait_reserved_battery_disconnected2026 = 0
        self._wait_current_battery_connected2026: int = 0
        self._wait_battery_connected_by_file2026: tuple[int, ...] = (0,) * 16
        self._wait_reserved_battery_connected2026 = 0
        self._wait_battery_voltage_raw2026 = 0
        self._wait_d4e8_battery_voltage2026 = 0.0
        self._wait_pending_admission2026: _NativeWaitTimingAdmission2026 | None = None
        self._wait_admission_stage2026 = None
        self._wait_admission_cursor2026: int | None = None
        self._wait_admission_owner2026 = None
        self._wait_active_admission2026: _NativeWaitTimingAdmission2026 | None = None
        self._wait_timing_epoch2026 = 0
        self._wait_general_keys2026: tuple[str, ...] = ()
        self._wait_image_keys2026: tuple[str, ...] = ()
        self._wait_selected_general2026 = None
        self._wait_selected_image2026 = None
        self._native_delta_active = False
        self._file_read_region = 0
        self._file_logger = None
        self._diagnostic_context = 0
        self._cid_selection_initialized = False
        self._worker_target_sources = {}
        self._pending_worker_cid_selection = None
        self._prepare_prefix_owner = None
        self._prepare_prefix_vbf_request2026 = None
        self._prepare_prefix_vbf_cpu_origin2026 = None
        self._ordinary_prepare_scope2026 = None
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
        self._identifier_context_importing = False
        self._native_control_context2026 = None
        self._controller_export_target2026 = None
        self._last_completed_standalone_getter = None
        self._working_identifier_records: tuple[bytes, ...] = ()
        self._working_contact_buffer = bytes(33)
        self._persistence = None
        self._persistence_cpu_transition2026: _PersistenceCPUTransition2026 | None = (
            None
        )
        self._persistence_file_flow_transition2026: (
            _PersistenceFileFlowTransition2026 | None
        ) = None
        self._pending_file_admission_origin2026: _FileAdmissionOrigin2026 | None = None
        self._file_admission_owner_thread2026: int | None = None
        self._pending_getter_stop_origin2026: _NativeGetterStopOrigin2026 | None = None
        self._judge_flashable_invocation2026: _JudgeFlashableInvocation2026 | None = (
            None
        )
        self._initial_getter_reset_epoch2026 = 0
        self._pending_initial_getter_reset2026: _InitialGetterReset40580_2026 | None = (
            None
        )
        self._initial_getter_reset_binding2026: (
            tuple[_InitialGetterReset40580_2026, EngineWorker2026, int] | None
        ) = None
        if persistence is not None:
            self.bind_persistence(persistence)

    def _validate_persistence_source(
        self, metadata, *, state_snapshot=None, file_sources=None
    ) -> None:
        self._reject_failed_cold_file_admission2026()
        from scripts.calibration_2026 import (
            NativeUSBSource2026,
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
            live_worker = self._worker
            if live_worker is not None:
                live_worker.validate_source(self)
                self._persistence._validate_file_source_membership(
                    sources,
                    metadata,
                    state_snapshot=state,
                )
            else:
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
        worker = self._worker
        if worker is None:
            return
        worker.validate_source(self)
        expected_cpu = worker.source_state.current_global_cpu_index
        if state.write_cpu_index != expected_cpu and not (
            self._persistence_cpu_transition_valid2026(
                metadata, state, sources, expected_cpu, state_snapshot=state_snapshot
            )
        ):
            raise ValueError(
                "Persistence current CPU differs from the actual engine target"
            )
        expected_file = worker._flow_file_index2026
        if state.calibration_file_index != expected_file and not (
            self._persistence_file_flow_transition_valid2026(
                state, sources, expected_file, state_snapshot=state_snapshot
            )
        ):
            raise ValueError("Persistence FILE index differs from the actual D71C flow")

    def _invalidate_persistence_cpu_transition2026(self) -> None:
        self._persistence_cpu_transition2026 = None

    def _invalidate_persistence_file_flow_transition2026(self) -> None:
        self._persistence_file_flow_transition2026 = None

    def _persistence_file_flow_transition_valid2026(
        self,
        state,
        sources: FileSourceSet2026 | None,
        expected_flow: int,
        *,
        state_snapshot=None,
    ) -> bool:
        record = self._persistence_file_flow_transition2026
        persistence = self._persistence
        worker = self._worker
        snapshot = state if state_snapshot is None else state_snapshot
        if (
            record is None
            or persistence is None
            or worker is None
            or sources is None
            or record.producer not in _FILE_FLOW_PRODUCERS2026
            or record.persistence is not persistence
            or record.state is not persistence.state
            or record.worker is not worker
            or record.new_sources is not sources
            or sources is not self._file_sources
            or record.persisted_file_index != persistence.state.calibration_file_index
            or record.persisted_file_index != snapshot.calibration_file_index
            or record.after_flow != expected_flow
            or worker._flow_file_index2026 != record.after_flow
        ):
            return False
        from scripts.cuw_file_services import (
            FileSourceSet2026,
            validate_file_sources_2026,
            validate_file_view_2026,
        )

        try:
            mapped_history = record.mapped_reset_origin is not None
            flow_sources = sources
            if mapped_history:
                if (
                    type(record.old_sources) is not FileSourceSet2026
                    or type(record.flow_view.sources) is not FileSourceSet2026
                ):
                    return False
                validate_file_sources_2026(record.old_sources, self)
                flow_sources = record.flow_view.sources
                validate_file_sources_2026(flow_sources, self)
            validate_file_view_2026(
                record.flow_view,
                flow_sources,
            )
            validate_file_view_2026(record.current_pointer_view, sources)
        except (TypeError, ValueError):
            return False
        return not (
            (not mapped_history and record.flow_view.sources is not sources)
            or record.current_pointer_view.sources is not sources
            or (
                mapped_history
                and (
                    type(record.flow_view.file_index) is not int
                    or not 0 <= record.flow_view.file_index < 16
                    or record.flow_view.file_index != expected_flow
                )
            )
            or (
                not mapped_history
                and sources.has_file_vector
                and record.flow_view.file_index != expected_flow
            )
            or (
                not mapped_history
                and not sources.has_file_vector
                and (expected_flow != 0 or record.flow_view.kind != "none")
            )
            or record.current_pointer_view.source_container
            is not self.native_metadata.source_container
            or record.current_pointer_view.source_sha256
            != self.native_metadata.source_sha256
        )

    @staticmethod
    def _persistence_file_views2026(sources, metadata, flow_index):
        from scripts.cuw_file_services import validate_file_view_2026

        if sources.has_file_vector:
            flow_view = sources.file_view2026(flow_index)
            matches = tuple(
                index
                for index, item in enumerate(sources.files)
                if item.source_container is metadata.source_container
            )
            if len(matches) > 1:
                raise ValueError("Actual current FILE pointer is ambiguous")
            pointer_view = (
                sources.file_view2026(matches[0])
                if matches
                else sources.admission_view2026()
            )
        else:
            flow_view = pointer_view = sources.admission_view2026()
        validate_file_view_2026(flow_view, sources)
        validate_file_view_2026(pointer_view, sources)
        return flow_view, pointer_view

    def _record_file_flow_transition2026(
        self,
        *,
        worker,
        origin,
        producer,
        old_sources,
        new_sources,
        before_flow,
        after_flow,
        flow_view,
        current_pointer_view,
    ) -> None:
        from scripts.cuw_file_services import validate_file_view_2026

        persistence = self._persistence
        if producer != "43cd0-admission":
            self._require_owned_phase()
        if (
            worker is not self._worker
            or worker.engine is not self
            or persistence is None
            or self._metadata is None
        ):
            raise ValueError("Current persistence-owned worker required")
        if any(
            type(value) is not int or value < 0 for value in (before_flow, after_flow)
        ):
            raise ValueError("Non-negative native D71C flow indices required")
        if old_sources is None or new_sources is not self._file_sources:
            raise ValueError("Actual current FILE source set required")
        if producer != "4b900-mode2" and old_sources is not new_sources:
            raise ValueError("Non-reset FILE flow must retain the issued source set")
        validate_file_view_2026(flow_view, new_sources)
        validate_file_view_2026(current_pointer_view, new_sources)
        if (
            (
                old_sources.has_file_vector
                and not 0 <= before_flow < len(old_sources.files)
            )
            or (not old_sources.has_file_vector and before_flow != 0)
            or (
                new_sources.has_file_vector
                and not 0 <= after_flow < len(new_sources.files)
            )
            or (new_sources.has_file_vector and flow_view.file_index != after_flow)
            or (
                not new_sources.has_file_vector
                and (after_flow != 0 or flow_view.kind != "none")
            )
            or current_pointer_view.source_container
            is not self.native_metadata.source_container
            or current_pointer_view.source_sha256 != self.native_metadata.source_sha256
        ):
            raise ValueError("Native FILE flow views differ from the committed state")
        persistence._validate_file_source_membership(new_sources, self.native_metadata)
        if producer == "43cd0-admission":
            pending = self._pending_file_admission_origin2026
            persistence = self._persistence
            if (
                pending is None
                or persistence is None
                or origin is not pending
                or pending.engine is not self
                or pending.worker is not worker
                or pending.persistence is not self._persistence
                or pending.state is not persistence.state
                or pending.sources is not self._file_sources
                or self._file_admission_owner_thread2026 != get_ident()
                or pending.thread_id != get_ident()
                or self._worker is not worker
                or persistence.state.calibration_file_index == 0
                or pending.source_container is not self.native_metadata.source_container
                or pending.digest != self.native_metadata.source_sha256
                or pending.admission_view is not new_sources.admission_view2026()
                or old_sources is not new_sources
                or new_sources is not self._file_sources
                or before_flow != 0
                or after_flow != 0
                or worker._flow_file_index2026 != 0
                or flow_view is not pending.flow_view
                or current_pointer_view is not pending.admission_view
            ):
                raise ValueError("Exact pending first-bind FILE admission required")
            validate_file_view_2026(flow_view, new_sources)
            validate_file_view_2026(current_pointer_view, new_sources)
            if (
                new_sources.has_file_vector
                and flow_view is not new_sources.file_view2026(0)
            ):
                raise ValueError("Admission flow view must be the actual slot zero")
            self._persistence_file_flow_transition2026 = (
                _PersistenceFileFlowTransition2026(
                    producer,
                    origin,
                    worker,
                    self._persistence,
                    persistence.state,
                    old_sources,
                    new_sources,
                    before_flow,
                    after_flow,
                    persistence.state.calibration_file_index,
                    flow_view,
                    current_pointer_view,
                )
            )
            self._pending_file_admission_origin2026 = None
            return
        if producer not in _FILE_FLOW_PRODUCERS2026:
            raise ValueError("Unsupported native D71C flow producer")
        if producer == "46be0-mode1":
            raise ValueError(
                "46be0-mode1 proofs are issued only at the direct reset source store"
            )
        persistence = self._persistence
        if persistence is None:
            raise ValueError("Persistence-owned FILE flow witness required")
        if producer == "4b900-mode2":
            from scripts.cuw_file_services import validate_file_reset_2026

            validate_file_reset_2026(old_sources, new_sources, worker)
            if origin is not new_sources:
                raise ValueError("Actual committed mode2 FILE reset required")
        else:
            if not isinstance(worker, _FileFlowOriginValidator2026):
                raise TypeError("Worker file-flow origin validator is unavailable")
            worker._validate_file_flow_transition_origin2026(
                origin,
                producer=producer,
                old_sources=old_sources,
                new_sources=new_sources,
                before_flow=before_flow,
                after_flow=after_flow,
                flow_view=flow_view,
                current_pointer_view=current_pointer_view,
            )
        if (
            worker is not self.worker
            or new_sources is not self._file_sources
            or worker._flow_file_index2026 != after_flow
        ):
            raise ValueError("Actual committed native FILE flow required")
        if after_flow == persistence.state.calibration_file_index:
            self._invalidate_persistence_file_flow_transition2026()
            return
        self._persistence_file_flow_transition2026 = _PersistenceFileFlowTransition2026(
            producer,
            origin,
            worker,
            persistence,
            persistence.state,
            old_sources,
            new_sources,
            before_flow,
            after_flow,
            persistence.state.calibration_file_index,
            flow_view,
            current_pointer_view,
        )

    def _clear_file_flow_transition2026(self, *, worker, origin) -> None:
        if not isinstance(worker, _JudgeCommitOriginValidator2026):
            raise TypeError("Worker judge-commit origin validator is unavailable")
        if not isinstance(worker, _FileFlowOriginValidator2026):
            raise TypeError("Worker file-flow clear validator is unavailable")
        persistence = self._persistence
        if (
            worker is not self._worker
            or persistence is None
            or self._active
            or self._phase_thread is not None
            or persistence.state.calibration_file_index != worker._flow_file_index2026
        ):
            raise ValueError("Idle authenticated D71C persistence commit required")
        invocation = self._judge_flashable_invocation2026
        if (
            type(invocation) is not _JudgeFlashableInvocation2026
            or invocation.commit_origin is not origin
        ):
            raise ValueError("Exact consumed native49010 origin required")
        self._validate_judge_commit_stage_49010_2026(
            origin, worker=worker, candidate=invocation.candidate
        )
        worker._validate_file_flow_clear_origin2026(origin)
        self._invalidate_persistence_file_flow_transition2026()

    def _validate_judge_flashable_orchestration2026(self, worker, region: int):
        """Issue the one lexical 62330 invocation marker to its source worker."""
        invocation = self._judge_flashable_invocation2026
        if (
            type(invocation) is not _JudgeFlashableInvocation2026
            or invocation.engine is not self
            or invocation.worker is not worker
            or invocation.thread_id != get_ident()
            or invocation.region != region
            or invocation.entered
            or invocation.commit_started
            or worker is not self._worker
            or self._active
            or self._phase_thread is not None
        ):
            raise ValueError("Exact current native flashability orchestration required")
        invocation.entered = True
        return invocation

    def _require_judge_flashable_invocation2026(self, worker, region: int):
        invocation = self._judge_flashable_invocation2026
        committed = (
            type(invocation) is _JudgeFlashableInvocation2026
            and invocation.memory_published
        )
        if type(invocation) is _JudgeFlashableInvocation2026:
            if invocation.commit_started and not invocation.memory_published:
                raise ValueError("Incomplete native49010 commit stage")
            if committed:
                self._validate_judge_commit_stage_49010_2026(
                    invocation.commit_origin,
                    worker=worker,
                    candidate=invocation.candidate,
                )
        if type(invocation) is _JudgeFlashableInvocation2026:
            expected_flow = (
                invocation.committed_index if committed else invocation.flow_index
            )
            expected_persisted_file = (
                invocation.committed_index if committed else invocation.persisted_file
            )
        else:
            expected_flow = None
            expected_persisted_file = None
        if (
            type(invocation) is not _JudgeFlashableInvocation2026
            or invocation.engine is not self
            or invocation.worker is not worker
            or invocation.thread_id != get_ident()
            or invocation.region != region
            or invocation.configuration is not self.configuration
            or invocation.reset_epoch != worker._getter_reset_epoch2026
            or invocation.file_sources is not self._file_sources
            or invocation.persistence is not self._persistence
            or invocation.persistence_state
            is not (None if self._persistence is None else self._persistence.state)
            or expected_flow != worker._flow_file_index2026
            or invocation.global_cpu_index
            != worker.source_state.current_global_cpu_index
            or (
                self._persistence is not None
                and (
                    invocation.persisted_cpu != self._persistence.state.write_cpu_index
                    or expected_persisted_file
                    != self._persistence.state.calibration_file_index
                )
            )
            or not invocation.entered
            or worker is not self._worker
            or self._active
            or self._phase_thread is not None
        ):
            raise ValueError("Current native flashability invocation required")
        return invocation

    def _accept_judge_file_projection_32ff0_2026(
        self, view: NativeFileView2026, *, worker
    ) -> None:
        """Publish an actual transient 32ff0 selection inside native62330."""
        from scripts.calibration_2026 import (
            Native2026Metadata,
            native2026_cpu_count,
            native2026_global_cpu_index,
            native2026_validate_runtime_metadata,
        )
        from scripts.cuw_engine_worker import EngineWorker2026
        from scripts.cuw_file_services import (
            NativeFileView2026,
            validate_file_sources_2026,
            validate_file_view_2026,
        )

        if type(worker) is not EngineWorker2026 or worker is not self._worker:
            raise ValueError("Current native judge worker required")
        invocation = self._judge_flashable_invocation2026
        if type(invocation) is not _JudgeFlashableInvocation2026:
            raise ValueError("Current native flashability invocation required")
        invocation = self._require_judge_flashable_invocation2026(
            worker, invocation.region
        )
        sources = self._file_sources
        persistence = self._persistence
        previous = self.native_metadata
        if (
            type(view) is not NativeFileView2026
            or sources is None
            or view.sources is not sources
            or view.kind == "none"
            or self._judge_flashable_invocation2026 is not invocation
        ):
            raise ValueError("Actual named 32ff0 judge projection required")
        if (
            worker._flow_file_index2026 != invocation.flow_index
            or worker.source_state.current_global_cpu_index
            != invocation.global_cpu_index
            or (
                persistence is not None
                and (
                    persistence.state.write_cpu_index != invocation.persisted_cpu
                    or persistence.state.calibration_file_index
                    != invocation.persisted_file
                )
            )
        ):
            raise ValueError("32ff0 projection changed an unrelated native index")
        self._validate_persistence_source(previous)
        validate_file_sources_2026(sources, self)
        validate_file_view_2026(view, sources)
        if not isinstance(worker, _JudgeFileProjectionOriginValidator2026):
            raise TypeError("Worker judge projection validator is unavailable")
        projected = worker._validate_judge_file_projection_origin_2026(
            view,
            worker=worker,
            region=invocation.region,
            invocation=invocation,
        )
        if type(projected) is not Native2026Metadata:
            raise TypeError("Judge projection validator must return native metadata")
        native2026_validate_runtime_metadata(projected)
        if (
            projected.source_container is not view.source_container
            or projected.source_sha256 != view.source_sha256
            or projected.region != view.metadata.region
            or self._parser_profile(projected) != projected
            or self.configuration is None
            or native2026_cpu_count(projected) > self.configuration.cpu_maximum
            or projected.node != view.metadata.node
            or native2026_global_cpu_index(projected)
            != worker.source_state.current_global_cpu_index
        ):
            raise ValueError("Judge projection metadata differs from its FILE")
        current_cpu = worker.source_state.current_global_cpu_index
        if persistence is not None:
            persisted_cpu = persistence.state.write_cpu_index
            if persisted_cpu != current_cpu:
                if not self._persistence_cpu_transition_valid2026(
                    previous, persistence.state, sources, current_cpu
                ):
                    raise ValueError("Judge FILE selection requires its CPU witness")
                cpu_proof = self._persistence_cpu_transition2026
                assert cpu_proof is not None
                next_cpu_proof = replace(
                    cpu_proof,
                    metadata=projected,
                    file_sources=sources,
                    container=projected.source_container,
                    digest=projected.source_sha256,
                    node=projected.node,
                )
            else:
                next_cpu_proof = None
            flow = worker._flow_file_index2026
            persisted_file = persistence.state.calibration_file_index
            if persisted_file != flow:
                if not self._persistence_file_flow_transition_valid2026(
                    persistence.state, sources, flow
                ):
                    raise ValueError("Judge FILE selection requires its FILE witness")
                proof = self._persistence_file_flow_transition2026
                assert proof is not None
                next_file_proof = replace(proof, current_pointer_view=view)
            else:
                next_file_proof = None
        else:
            next_cpu_proof = None
            next_file_proof = None

        if persistence is not None:
            persistence._validate_file_source_membership(sources, projected)

        if not isinstance(worker, _JudgePointerMirrorPublisher2026):
            raise TypeError("Worker judge pointer mirror publisher is unavailable")
        self._publish_judge_file_projection_tuple_32ff0_2026(
            view, projected, next_cpu_proof, next_file_proof, worker, invocation
        )

    def _publish_judge_file_projection_tuple_32ff0_2026(
        self, view, projected, cpu_proof, file_proof, worker, origin
    ) -> None:
        """Publish one prevalidated metadata/pointer/proof tuple without callbacks."""
        worker._publish_judge_pointer_mirror_32ff0_2026(origin)
        dh, suzuki = self.dh_state, self.suzuki_state
        self._metadata = projected
        dh.metadata = suzuki.metadata = projected
        dh.source_sha256 = suzuki.source_sha256 = projected.source_sha256
        dh.node = suzuki.node = projected.node
        dh.selection_cpu_index = suzuki.selection_cpu_index = projected.cpu_index
        self._persistence_cpu_transition2026 = cpu_proof
        self._persistence_file_flow_transition2026 = file_proof
        self._worker_target_sources[id(view.source_container)] = projected

    def _accept_judge_file_reset_4b900_2026(
        self, old_sources, new_sources, *, worker, origin: object
    ) -> None:
        """Orchestrate the authenticated mode1 reset at its native boundaries."""
        from scripts.calibration_2026 import (
            Native2026Metadata,
            NativeUSBSource2026,
            native2026_cpu_count,
            native2026_global_cpu_index,
            native2026_validate_runtime_metadata,
        )
        from scripts.cuw_engine_worker import EngineWorker2026
        from scripts.cuw_file_services import (
            FileSourceSet2026,
            NativeFileView2026,
            validate_file_sources_2026,
            validate_file_view_2026,
        )
        from scripts.cuw_large import NativeLargeContainer2026
        from scripts.cuw_persistence import CUWPersistence, ReproInfoState

        if type(worker) is not EngineWorker2026 or worker is not self._worker:
            raise ValueError("Current native judge worker required")
        invocation = self._judge_flashable_invocation2026
        if type(invocation) is not _JudgeFlashableInvocation2026:
            raise ValueError("Current native flashability invocation required")
        invocation = self._require_judge_flashable_invocation2026(
            worker, invocation.region
        )
        if (
            type(old_sources) is not FileSourceSet2026
            or type(new_sources) is not FileSourceSet2026
            or old_sources is not self._file_sources
            or invocation.file_sources is not old_sources
            or invocation.commit_started
            or invocation.commit_origin is not None
            or invocation.reset_epoch != worker._getter_reset_epoch2026
        ):
            raise ValueError("Exact current mode1 FILE reset tuple required")
        validate_file_sources_2026(old_sources, self)
        validate_file_sources_2026(new_sources, self)
        if not isinstance(worker, _JudgeFileResetOriginValidator2026):
            raise TypeError("Worker mode1 reset validator is unavailable")
        stage = worker._validate_judge_file_reset_stage2026(
            origin, old_sources, new_sources
        )
        direct = old_sources.delta_archive and old_sources.delta_map_size == 0
        branch: Literal["mapped", "direct"] = "direct" if direct else "mapped"
        if not direct and not old_sources.delta_map_size:
            raise ValueError("Mode1 reset requires its actual mapped or direct source")
        persistence = self._persistence
        if (
            type(persistence) is not CUWPersistence
            or type(persistence.state) is not ReproInfoState
        ):
            raise ValueError("Bound native recovery state required for judge reset")
        persistence.validate_engine_owner(self)
        previous = self.native_metadata
        self._validate_persistence_source(previous)
        before_flow = worker._flow_file_index2026
        before_cpu = worker.source_state.current_global_cpu_index
        persisted_file = persistence.state.calibration_file_index
        persisted_cpu = persistence.state.write_cpu_index
        replacement_successors = (
            persistence._prepare_file_source_replacement_successors2026(
                old_sources, new_sources
            )
        )
        if (
            invocation.flow_index != before_flow
            or invocation.global_cpu_index != before_cpu
            or invocation.persisted_file != persisted_file
            or invocation.persisted_cpu != persisted_cpu
        ):
            raise ValueError("Mode1 reset changed a captured native index")
        if (persisted_cpu == before_cpu) != (
            self._persistence_cpu_transition2026 is None
        ) or (persisted_file == before_flow) != (
            self._persistence_file_flow_transition2026 is None
        ):
            raise ValueError("Equal native persistence indices require no witness")

        if branch == "direct" and stage == "flow_pending":
            if (
                invocation.reset_origin is not None
                or not old_sources.has_file_vector
                or not old_sources.files
                or not 0 <= before_flow < len(old_sources.files)
            ):
                raise ValueError("Direct46be0 reset requires a pristine named table")
            if not isinstance(worker, _FileFlowOriginValidator2026):
                raise TypeError("Worker direct reset flow validator is unavailable")
            from scripts.cuw_file_services import validate_file_view_2026

            matches = tuple(
                index
                for index, item in enumerate(old_sources.files)
                if item.source_container is previous.source_container
                and item.source_sha256 == previous.source_sha256
            )
            if len(matches) > 1:
                raise ValueError("Direct reset current A48 pointer is ambiguous")
            pointer_view = (
                old_sources.file_view2026(matches[0])
                if matches
                else old_sources.admission_view2026()
            )
            flow_view = old_sources.file_view2026(0)
            validate_file_view_2026(flow_view, old_sources)
            validate_file_view_2026(pointer_view, old_sources)
            if (
                pointer_view.source_container is not previous.source_container
                or pointer_view.source_sha256 != previous.source_sha256
            ):
                raise ValueError("Direct reset A48 view differs from the live FILE")
            next_file_proof = None
            if persisted_file != 0:
                next_file_proof = _PersistenceFileFlowTransition2026(
                    "46be0-mode1",
                    origin,
                    worker,
                    persistence,
                    persistence.state,
                    old_sources,
                    old_sources,
                    before_flow,
                    0,
                    persisted_file,
                    flow_view,
                    pointer_view,
                )
            invocation.reset_origin = origin
            invocation.reset_old_sources = old_sources
            invocation.reset_new_sources = new_sources
            invocation.reset_branch = "direct"
            worker._flow_file_index2026 = 0
            invocation.flow_index = 0
            self._persistence_file_flow_transition2026 = next_file_proof
            worker._apply_judge_file_reset_before_pointer2026(origin)
            stage = worker._validate_judge_file_reset_stage2026(
                origin, old_sources, new_sources
            )

        if branch == "mapped" and stage == "prepared":
            if invocation.reset_origin is not None:
                raise ValueError("Overlapping mode1 reset point rejected")
            invocation.reset_origin = origin
            invocation.reset_old_sources = old_sources
            invocation.reset_new_sources = new_sources
            invocation.reset_branch = "mapped"
            worker._apply_judge_file_reset_before_pointer2026(origin)
            stage = worker._validate_judge_file_reset_stage2026(
                origin, old_sources, new_sources
            )

        if (
            stage != "pointer_ready"
            or invocation.reset_origin is not origin
            or invocation.reset_old_sources is not old_sources
            or invocation.reset_new_sources is not new_sources
            or invocation.reset_branch != branch
        ):
            raise ValueError("Mode1 reset is not at its authenticated pointer boundary")

        projected, pointer_view = worker._validate_judge_file_reset_publication2026(
            origin, old_sources, new_sources
        )
        if (
            type(projected) is not Native2026Metadata
            or type(pointer_view) is not NativeFileView2026
        ):
            raise TypeError(
                "Mode1 publication validator must return native metadata and view"
            )
        native2026_validate_runtime_metadata(projected)
        validate_file_view_2026(pointer_view, new_sources)
        if (
            self.configuration is None
            or native2026_cpu_count(projected) > self.configuration.cpu_maximum
            or self._parser_profile(projected) != projected
            or projected.source_container is not pointer_view.source_container
            or projected.source_sha256 != pointer_view.source_sha256
            or projected.region != pointer_view.metadata.region
            or projected.node != pointer_view.metadata.node
            or native2026_global_cpu_index(projected) != before_cpu
        ):
            raise ValueError("Mode1 runtime metadata differs from its current FILE")
        persistence._validate_file_source_membership_successor2026(
            replacement_successors, projected
        )

        next_cpu_proof = None
        if persisted_cpu != before_cpu:
            if not self._persistence_cpu_transition_valid2026(
                previous, persistence.state, old_sources, before_cpu
            ):
                raise ValueError("Mode1 FILE reset requires its CPU witness")
            cpu_proof = self._persistence_cpu_transition2026
            assert cpu_proof is not None
            next_cpu_proof = replace(
                cpu_proof,
                metadata=projected,
                file_sources=new_sources,
                container=projected.source_container,
                digest=projected.source_sha256,
                node=projected.node,
            )
        if branch == "mapped":
            next_file_proof = None
            if persisted_file != before_flow:
                if not self._persistence_file_flow_transition_valid2026(
                    persistence.state, old_sources, before_flow
                ):
                    raise ValueError("Mapped mode1 reset requires its FILE witness")
                file_proof = self._persistence_file_flow_transition2026
                assert file_proof is not None
                next_file_proof = replace(
                    file_proof,
                    new_sources=new_sources,
                    current_pointer_view=pointer_view,
                    mapped_reset_origin=origin,
                )
        else:
            next_file_proof = None
            if persisted_file != worker._flow_file_index2026:
                file_proof = self._persistence_file_flow_transition2026
                if (
                    file_proof is None
                    or file_proof.producer != "46be0-mode1"
                    or file_proof.origin is not origin
                    or file_proof.old_sources is not old_sources
                    or file_proof.new_sources is not old_sources
                    or file_proof.after_flow != worker._flow_file_index2026
                ):
                    raise ValueError("Direct mode1 reset lost its early flow witness")
                no_table_view = new_sources.admission_view2026()
                next_file_proof = replace(
                    file_proof,
                    new_sources=new_sources,
                    flow_view=no_table_view,
                    current_pointer_view=no_table_view,
                    mapped_reset_origin=None,
                )

        worker._publish_judge_file_reset_projection2026(origin)
        self._file_sources = new_sources
        self._source = new_sources.selected_source
        if type(projected.source_container) is NativeLargeContainer2026:
            self._source = None
            self._large_container = projected.source_container
        elif type(projected.source_container) is NativeUSBSource2026:
            self._source = projected.source_container.raw
            self._large_container = None
        else:
            self._large_container = None
        self._metadata = projected
        dh, suzuki = self.dh_state, self.suzuki_state
        dh.metadata = suzuki.metadata = projected
        dh.source_sha256 = suzuki.source_sha256 = projected.source_sha256
        dh.node = suzuki.node = projected.node
        dh.selection_cpu_index = suzuki.selection_cpu_index = projected.cpu_index
        self._worker_target_sources[id(projected.source_container)] = projected
        self._persistence_cpu_transition2026 = next_cpu_proof
        self._persistence_file_flow_transition2026 = next_file_proof
        persistence._publish_file_source_replacement_successors2026(
            replacement_successors
        )
        invocation.file_sources = new_sources
        invocation.flow_index = worker._flow_file_index2026
        invocation.global_cpu_index = before_cpu
        invocation.persisted_cpu = persisted_cpu
        invocation.persisted_file = persisted_file
        invocation.reset_pointer_view = pointer_view
        worker._apply_judge_file_reset_after_pointer2026(origin)
        invocation.reset_origin = None
        invocation.reset_old_sources = None
        invocation.reset_new_sources = None
        invocation.reset_branch = None
        invocation.reset_pointer_view = None

    def _apply_judge_mode1_recovery_23b10_2026(self, origin, *, worker) -> None:
        """Commit23b10 only from the authenticated late mapped-reset source point."""
        from scripts.calibration_2026 import Native2026Metadata
        from scripts.cuw_engine_worker import EngineWorker2026
        from scripts.cuw_file_services import (
            FileSourceSet2026,
            NativeFileView2026,
            validate_file_sources_2026,
            validate_file_view_2026,
        )
        from scripts.cuw_persistence import (
            CUWPersistence,
            ReproInfoState,
            _NativeRecoverySourceReplacement2026,
        )

        invocation = self._judge_flashable_invocation2026
        sources = self._file_sources
        persistence = self._persistence
        if (
            type(worker) is not EngineWorker2026
            or worker is not self._worker
            or type(invocation) is not _JudgeFlashableInvocation2026
            or invocation.engine is not self
            or invocation.worker is not worker
            or invocation.thread_id != get_ident()
            or invocation.reset_origin is not origin
            or invocation.reset_branch != "mapped"
            or invocation.reset_new_sources is not sources
            or type(sources) is not FileSourceSet2026
            or type(invocation.reset_pointer_view) is not NativeFileView2026
            or type(persistence) is not CUWPersistence
            or type(persistence.state) is not ReproInfoState
        ):
            raise ValueError("Exact current mapped23b10 source point required")
        if type(sources) is not FileSourceSet2026:
            raise ValueError("Current mapped23b10 FILE set required")
        if not isinstance(worker, _JudgeFileResetOriginValidator2026):
            raise TypeError("Native23b10 source validator is unavailable")
        (
            old_sources,
            new_sources,
            original_index,
            whole_metadata,
            replacement_path,
            replacement_source,
        ) = worker._validate_judge_mode1_recovery_23b10_2026(origin)
        pointer_view = invocation.reset_pointer_view
        if (
            type(old_sources) is not FileSourceSet2026
            or type(new_sources) is not FileSourceSet2026
            or type(pointer_view) is not NativeFileView2026
        ):
            raise TypeError("Authenticated23b10 FILE tuple required")
        validate_file_sources_2026(new_sources, self)
        validate_file_view_2026(pointer_view, new_sources)
        if (
            old_sources is not invocation.reset_old_sources
            or new_sources is not sources
            or type(original_index) is not int
            or original_index < 0
            or type(whole_metadata) is not Native2026Metadata
            or pointer_view.kind != "whole"
            or pointer_view.original_recovery_index != original_index
            or pointer_view.source_container is not whole_metadata.source_container
            or pointer_view.source_sha256 != whole_metadata.source_sha256
            or self.native_metadata is not whole_metadata
            or persistence.state.calibration_file_index != invocation.persisted_file
        ):
            raise ValueError("23b10 replacement differs from its current WHOLE FILE")
        names, originals, _ = new_sources.recovery_sources()
        if (
            original_index >= len(names)
            or original_index >= len(originals)
            or type(replacement_path) is not str
            or not replacement_path
        ):
            raise ValueError("23b10 replacement source association is incomplete")
        from scripts.cuw_persistence import calibration_source_identity

        calibration_source_identity(replacement_source)
        binding = _NativeRecoverySourceReplacement2026(
            self,
            persistence,
            persistence.state,
            new_sources,
            origin,
            original_index,
            names[original_index],
            originals[original_index],
            replacement_path,
            replacement_source,
            whole_metadata,
        )
        persistence._replace_calibration_from_judge_23b10_2026(binding)

    def _accept_judge_committed_file_projection_32ff0_2026(
        self, view: NativeFileView2026, *, worker, origin: object
    ) -> None:
        """Publish only the chosen FILE projection after its native49010 commit."""
        from scripts.calibration_2026 import (
            Native2026Metadata,
            native2026_cpu_count,
            native2026_global_cpu_index,
            native2026_validate_runtime_metadata,
        )
        from scripts.cuw_engine_worker import (
            EngineWorker2026,
            _NativeJudgeCommitOrigin2026,
        )
        from scripts.cuw_file_services import (
            FileSourceSet2026,
            validate_file_sources_2026,
            validate_file_view_2026,
        )
        from scripts.cuw_persistence import CUWPersistence, ReproInfoState

        invocation = self._judge_flashable_invocation2026
        sources = self._file_sources
        persistence = self._persistence
        previous = self.native_metadata
        if (
            type(worker) is not EngineWorker2026
            or worker is not self._worker
            or type(origin) is not _NativeJudgeCommitOrigin2026
            or type(invocation) is not _JudgeFlashableInvocation2026
            or invocation.engine is not self
            or invocation.worker is not worker
            or invocation.thread_id != get_ident()
            or not invocation.commit_started
            or not invocation.commit_completed
            or invocation.commit_origin is not origin
            or invocation.candidate is not view
            or invocation.committed_index is None
            or type(sources) is not FileSourceSet2026
            or type(persistence) is not CUWPersistence
            or type(persistence.state) is not ReproInfoState
            or worker._flow_file_index2026 != invocation.committed_index
            or worker.source_state.current_global_cpu_index
            != invocation.global_cpu_index
            or persistence.state.write_cpu_index != invocation.persisted_cpu
            or persistence.state.calibration_file_index != invocation.committed_index
        ):
            raise ValueError("Exact committed native FILE projection required")
        validate_file_sources_2026(sources, self)
        validate_file_view_2026(view, sources)
        if not isinstance(worker, _JudgeCommitProjectionOriginValidator2026):
            raise TypeError("Worker final judge projection validator is unavailable")
        projected = worker._validate_judge_commit_projection_origin_2026(
            view, worker=worker, origin=origin
        )
        if type(projected) is not Native2026Metadata:
            raise TypeError("Commit projection validator must return native metadata")
        native2026_validate_runtime_metadata(projected)
        if (
            projected.source_container is not view.source_container
            or projected.source_sha256 != view.source_sha256
            or projected.region != view.metadata.region
            or projected.node != view.metadata.node
            or self._parser_profile(projected) != projected
            or self.configuration is None
            or native2026_cpu_count(projected) > self.configuration.cpu_maximum
            or native2026_global_cpu_index(projected)
            != worker.source_state.current_global_cpu_index
        ):
            raise ValueError("Committed metadata differs from its chosen FILE")
        persistence._validate_file_source_membership(sources, projected)

        next_cpu_proof = None
        persisted_cpu = persistence.state.write_cpu_index
        current_cpu = worker.source_state.current_global_cpu_index
        if persisted_cpu != current_cpu:
            if not self._persistence_cpu_transition_valid2026(
                previous, persistence.state, sources, current_cpu
            ):
                raise ValueError("Chosen FILE projection requires its CPU witness")
            cpu_proof = self._persistence_cpu_transition2026
            assert cpu_proof is not None
            next_cpu_proof = replace(
                cpu_proof,
                metadata=projected,
                file_sources=sources,
                container=projected.source_container,
                digest=projected.source_sha256,
                node=projected.node,
            )
        elif self._persistence_cpu_transition2026 is not None:
            raise ValueError("Equal committed CPU retains a stale CPU witness")
        if persistence.state.calibration_file_index != worker._flow_file_index2026:
            raise ValueError("49010 did not commit the chosen FILE flow")
        if self._persistence_file_flow_transition2026 is not None:
            raise ValueError("49010 left a stale FILE flow witness")
        if not isinstance(worker, _JudgePointerMirrorPublisher2026):
            raise TypeError("Worker judge pointer mirror publisher is unavailable")
        self._publish_judge_file_projection_tuple_32ff0_2026(
            view, projected, next_cpu_proof, None, worker, origin
        )

    def _commit_judge_file_49010_2026(
        self, candidate: NativeFileView2026 | None, *, worker, origin: object
    ) -> None:
        """Commit only the actual chosen62330 candidate and its ED54 index."""
        from scripts.cuw_engine_worker import EngineWorker2026
        from scripts.cuw_file_services import (
            NativeFileView2026,
            validate_file_sources_2026,
            validate_file_view_2026,
        )
        from scripts.cuw_persistence import CUWPersistence, ReproInfoState

        if type(worker) is not EngineWorker2026 or worker is not self._worker:
            raise ValueError("Current native judge worker required")
        invocation = self._judge_flashable_invocation2026
        if (
            type(invocation) is not _JudgeFlashableInvocation2026
            or not invocation.entered
            or invocation.commit_started
            or invocation.engine is not self
            or invocation.worker is not worker
            or invocation.thread_id != get_ident()
            or worker is not self._worker
            or self._active
            or self._phase_thread is not None
        ):
            raise ValueError("Once-only native49010 orchestration required")
        sources = self._file_sources
        if candidate is None:
            if sources is not None or worker._flow_file_index2026 != 0:
                raise ValueError(
                    "CandidateNone requires the actual no-FileSourceSet branch"
                )
            flow_index = 0
        else:
            if (
                type(candidate) is not NativeFileView2026
                or sources is None
                or candidate.sources is not sources
            ):
                raise ValueError("Source-issued chosen FILE candidate required")
            validate_file_sources_2026(sources, self)
            validate_file_view_2026(candidate, sources)
            if sources.has_file_vector:
                index = candidate.file_index
                if (
                    type(index) is not int
                    or not 0 <= index < len(sources.files)
                    or candidate is not sources.file_view2026(index)
                ):
                    raise ValueError("Chosen FILE candidate is outside the live table")
                flow_index = index
            elif (
                candidate is not sources.admission_view2026()
                or candidate.kind != "none"
            ):
                raise ValueError("No-vector judge candidate must be its current FILE")
            else:
                flow_index = 0

        persistence = self._persistence
        if (
            type(persistence) is not CUWPersistence
            or type(persistence.state) is not ReproInfoState
        ):
            raise ValueError("Native49010 commit requires its bound recovery state")
        persistence.validate_engine_owner(self)
        self._validate_persistence_source(self.native_metadata)
        if not isinstance(worker, _JudgeCommitOriginValidator2026):
            raise TypeError("Worker judge-commit origin validator is unavailable")
        worker._validate_judge_commit_origin_62330_2026(origin, candidate)
        invocation.commit_started = True
        invocation.commit_origin = origin
        invocation.candidate = candidate
        invocation.committed_index = flow_index
        worker._flow_file_index2026 = flow_index
        if candidate is not None:
            if sources is None:
                raise ValueError("Chosen FILE lost its authenticated source set")
            validate_file_view_2026(candidate, sources)
        persistence.state.calibration_file_index = flow_index
        invocation.memory_published = True
        self._validate_judge_commit_stage_49010_2026(
            origin, worker=worker, candidate=candidate
        )
        self._clear_file_flow_transition2026(worker=worker, origin=origin)
        if persistence.state.logged:
            persistence.persist()
        invocation.commit_completed = True

    def _validate_judge_commit_stage_49010_2026(
        self, origin: object, *, worker, candidate: NativeFileView2026 | None
    ) -> None:
        """Validate the consumed H origin only after D71C and ED54 are committed."""
        from scripts.cuw_engine_worker import EngineWorker2026
        from scripts.cuw_persistence import CUWPersistence, ReproInfoState

        invocation = self._judge_flashable_invocation2026
        persistence = self._persistence
        if (
            type(invocation) is not _JudgeFlashableInvocation2026
            or invocation.engine is not self
            or invocation.worker is not worker
            or invocation.thread_id != get_ident()
            or worker is not self._worker
            or type(worker) is not EngineWorker2026
            or not invocation.commit_started
            or invocation.commit_origin is not origin
            or invocation.candidate is not candidate
            or not invocation.memory_published
            or invocation.committed_index is None
            or worker._flow_file_index2026 != invocation.committed_index
            or type(persistence) is not CUWPersistence
            or type(persistence.state) is not ReproInfoState
            or persistence.state.calibration_file_index != invocation.committed_index
        ):
            raise ValueError("Exact consumed49010 commit stage required")

    def _accept_getter_file_projection_32ff0_2026(
        self, view: NativeFileView2026, *, worker, origin
    ) -> None:
        if not isinstance(worker, _FileFlowOriginValidator2026):
            raise TypeError("Worker file projection validator is unavailable")
        from scripts.calibration_2026 import (
            Native2026Metadata,
            native2026_cpu_count,
            native2026_global_cpu_index,
            native2026_validate_runtime_metadata,
        )
        from scripts.cuw_file_services import validate_file_view_2026

        sources = self._file_sources
        persistence = self._persistence
        previous = self.native_metadata
        if (
            worker is not self._worker
            or sources is None
            or worker.engine is not self
            or self.configuration is None
        ):
            raise ValueError("Current source-owned worker and FILE table required")
        self._require_owned_phase()
        self._validate_persistence_source(previous)
        validate_file_view_2026(view, sources)
        projected = worker._validate_file_projection_origin2026(origin, view)
        if type(projected) is not Native2026Metadata:
            raise TypeError("Worker projection validator must return native metadata")
        native2026_validate_runtime_metadata(projected)
        if (
            projected.source_container is not view.source_container
            or projected.source_sha256 != view.source_sha256
            or projected.region != view.metadata.region
            or self._parser_profile(projected) != projected
            or native2026_cpu_count(projected) > self.configuration.cpu_maximum
            or projected.node != view.metadata.node
            or native2026_global_cpu_index(projected)
            != worker.source_state.current_global_cpu_index
        ):
            raise ValueError("Authenticated FILE projection metadata differs")
        if persistence is not None:
            if (
                persistence.state.write_cpu_index
                != worker.source_state.current_global_cpu_index
            ):
                raise ValueError(
                    "FILE projection cannot authorize a native CPU transition"
                )
            flow = worker._flow_file_index2026
            persisted_file = persistence.state.calibration_file_index
            if persisted_file != flow:
                if not self._persistence_file_flow_transition_valid2026(
                    persistence.state, sources, flow
                ):
                    raise ValueError("Current FILE flow witness is required")
                current_proof = self._persistence_file_flow_transition2026
                assert current_proof is not None
                next_file_proof = replace(current_proof, current_pointer_view=view)
            else:
                next_file_proof = None
        else:
            next_file_proof = None

        dh, suzuki = self.dh_state, self.suzuki_state
        previous_projection = (
            self._metadata,
            dh.metadata,
            dh.source_sha256,
            dh.node,
            dh.selection_cpu_index,
            suzuki.metadata,
            suzuki.source_sha256,
            suzuki.node,
            suzuki.selection_cpu_index,
            self._persistence_cpu_transition2026,
            self._persistence_file_flow_transition2026,
        )
        self._metadata = projected
        dh.metadata = suzuki.metadata = projected
        dh.source_sha256 = suzuki.source_sha256 = projected.source_sha256
        dh.node = suzuki.node = projected.node
        dh.selection_cpu_index = suzuki.selection_cpu_index = projected.cpu_index
        self._persistence_cpu_transition2026 = None
        self._persistence_file_flow_transition2026 = next_file_proof
        try:
            self._validate_persistence_source(projected)
            if not isinstance(worker, _JudgePointerMirrorPublisher2026):
                raise TypeError("Worker getter pointer mirror publisher is unavailable")
            worker._publish_judge_pointer_mirror_32ff0_2026(origin)
        except BaseException:
            (
                self._metadata,
                dh.metadata,
                dh.source_sha256,
                dh.node,
                dh.selection_cpu_index,
                suzuki.metadata,
                suzuki.source_sha256,
                suzuki.node,
                suzuki.selection_cpu_index,
                self._persistence_cpu_transition2026,
                self._persistence_file_flow_transition2026,
            ) = previous_projection
            raise

    def _persistence_cpu_transition_valid2026(
        self, metadata, state, sources, expected_cpu, *, state_snapshot=None
    ) -> bool:
        record = self._persistence_cpu_transition2026
        persistence = self._persistence
        worker = self._worker
        snapshot = state if state_snapshot is None else state_snapshot
        if (
            record is None
            or persistence is None
            or worker is None
            or record.producer not in ("141-reset", "vbf-prefix", "ordinary-36800")
            or record.persistence is not persistence
            or record.state is not persistence.state
            or record.metadata is not metadata
            or metadata is not self._metadata
            or record.file_sources is not sources
            or sources is not self._file_sources
            or record.worker is not worker
            or record.container is not metadata.source_container
            or record.digest != metadata.source_sha256
            or record.node != metadata.node
            or record.persisted_cpu != persistence.state.write_cpu_index
            or record.persisted_cpu != snapshot.write_cpu_index
            or record.after_cpu != expected_cpu
            or worker.source_state.current_global_cpu_index != record.after_cpu
        ):
            return False
        if record.producer == "141-reset":
            return record.origin is sources
        if record.producer == "ordinary-36800":
            from scripts.cuw_engine_threads import _OrdinaryPrepareOrigin2026

            job = self._thread_job
            return (
                job is not None
                and type(record.origin) is _OrdinaryPrepareOrigin2026
                and record.origin.binding.engine is self
                and record.origin.binding.worker is worker
                and record.origin.binding.source_set is sources
                and record.origin.binding.generation is job._native_start_generation2026
            )
        from scripts.cuw_engine_threads import (
            VbfProcessBeforeRequest2026,
            _vbf_record,
        )

        if type(record.origin) is not VbfProcessBeforeRequest2026:
            return False
        try:
            vbf_record = _vbf_record(record.origin)
        except ValueError:
            return False
        fields = vbf_record.fields
        if fields["engine"] is not self:
            return False
        if fields["state"] == "parked":
            origin = vbf_record.cpu_successor_origin
            successor = vbf_record.cpu_successor
            return (
                origin is not None
                and origin.request is record.origin
                and origin.projected_metadata is metadata
                and origin.file_sources is sources
                and origin.persisted_cpu == record.persisted_cpu
                and successor is not None
                and successor.engine_store.origin is origin
                and successor.engine_store.persistence_transition is record
                and successor.worker_global_cpu_index == expected_cpu
            )
        return (
            fields["state"] in ("prepared", "queued", "reserved", "adopted")
            and fields["metadata"] is metadata
            and fields["file_sources"] is sources
            and fields["cpu_index"] == expected_cpu
        )

    def _issue_persistence_cpu_transition2026(
        self,
        *,
        producer: str,
        origin: object,
        metadata,
        persisted_cpu: int,
        before_cpu: int,
        after_cpu: int,
    ) -> None:
        persistence = self._persistence
        worker = self._worker
        if persistence is None or worker is None or persisted_cpu == after_cpu:
            return
        self._persistence_cpu_transition2026 = _PersistenceCPUTransition2026(
            producer,
            origin,
            worker,
            persistence,
            persistence.state,
            metadata,
            self._file_sources,
            metadata.source_container,
            metadata.source_sha256,
            metadata.node,
            persisted_cpu,
            before_cpu,
            after_cpu,
        )

    def _persistence_cpu_changed2026(self, persistence, old_cpu: int, new_cpu: int):
        if persistence is self._persistence and old_cpu != new_cpu:
            self._invalidate_persistence_cpu_transition2026()

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
            self._reject_failed_cold_file_admission2026()
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

    def _cold_file_persistence_binding_live2026(self) -> bool:
        stage = cast(Any, self._wait_admission_stage2026)
        admission = stage[0] if type(stage) is tuple and stage else None
        return (
            type(stage) is tuple
            and len(stage) == 3
            and type(stage[0]) is _NativeWaitTimingAdmission2026
            and stage[0]._consumed
            and stage[0].engine is self
            and stage[1] == "persistence_binding"
            and stage[2] == get_ident()
            and self._wait_admission_owner2026 == (stage[0].sources, get_ident())
            and self._wait_admission_cursor2026 == len(stage[0].steps)
            and self._file_sources is cast(Any, admission).table_stages.final
        )

    def _reject_failed_cold_file_admission2026(self) -> None:
        if (
            self._wait_admission_cursor2026 is not None
            and self._wait_active_admission2026 is None
            and not self._cold_file_persistence_binding_live2026()
        ):
            raise ValueError(
                "Consumed cold FILE admission is sealed after source failure"
            )

    def bind_persistence(self, persistence) -> None:
        from scripts.cuw_persistence import CUWPersistence

        self._reject_failed_cold_file_admission2026()
        if type(persistence) is not CUWPersistence:
            raise TypeError("Concrete CUW recovery persistence required")
        if not self._lock.acquire(blocking=False):
            raise ValueError("CUW phase is active")
        previous = self._persistence
        previous_owner = persistence._engine
        try:
            if previous is not None and previous is not persistence:
                raise ValueError("CUW persistence cannot be replaced across phases")
            self._persistence = persistence
            if self._metadata is not None:
                self._validate_persistence_source(self._metadata)
                persistence.bind_engine_source(self)
                self.dh_state._notification = persistence.notification
            else:
                persistence._associate_engine_owner2026(self)
        except (Exception, KeyboardInterrupt):
            self._persistence = previous
            persistence._engine = previous_owner
            raise
        finally:
            self._lock.release()

    def begin_file_read(self, region_one_based: int, *, mode: int = 1) -> None:
        """5ccf0 sets the log context/region and conditionally runs38880."""
        self._reject_failed_cold_file_admission2026()
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
        self._reject_failed_cold_file_admission2026()
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

    def native_wait_time_for_igoffon2026(self, selector: int) -> int:
        """641a0 exposes the stored native wait DWORDs without lazy lookup."""
        if type(selector) is not int or not -(2**31) <= selector < 2**31:
            raise ValueError("Signed32-bit native wait selector required")
        if selector == 1 and self._write_complete_output:
            sources = self._file_sources
            names = () if sources is None else sources.table_file_names
            if any(type(name) is str and name for name in names):
                return self._wait_igoffon_aggregate2026
        if selector == 2:
            return self._wait_current_battery_disconnected2026
        if selector == 3:
            return self._wait_current_battery_connected2026
        return self._wait_current_igoffon2026 if selector == 1 else 0

    def _restore_file_waits_32ff0_2026(self, *, worker, origin) -> None:
        """Consume114's exact late32ff0 slot/capability receipt in source order."""
        from scripts.cuw_engine_worker import EngineWorker2026

        if type(worker) is not EngineWorker2026:
            raise TypeError("Exact native wait restore worker required")
        slot, admission, epoch = worker._consume_file_wait_restore_origin_32ff0_2026(
            origin, engine=self
        )
        sources = self._file_sources
        if (
            sources is None
            or type(slot) is not int
            or not 0 <= slot < 16
            or type(admission) is not _NativeWaitTimingAdmission2026
            or admission is not self._wait_active_admission2026
            or admission is not sources._wait_timing_admission2026
            or type(epoch) is not int
            or epoch <= 0
            or epoch != self._wait_timing_epoch2026
            or type(self._wait_igoffon_by_file2026) is not tuple
            or type(self._wait_battery_disconnected_by_file2026) is not tuple
            or type(self._wait_battery_connected_by_file2026) is not tuple
            or any(
                len(vector) != 16
                for vector in (
                    self._wait_igoffon_by_file2026,
                    self._wait_battery_disconnected_by_file2026,
                    self._wait_battery_connected_by_file2026,
                )
            )
        ):
            raise ValueError("Current successful admission slot required")
        self._wait_current_igoffon2026 = self._wait_igoffon_by_file2026[slot]
        self._wait_current_battery_disconnected2026 = (
            self._wait_battery_disconnected_by_file2026[slot]
        )
        self._wait_current_battery_connected2026 = (
            self._wait_battery_connected_by_file2026[slot]
        )

    def _publish_suzuki_igoffon_wait_58e20_2026(self, origin) -> None:
        """Consume the selected bound Suzuki event before its provider call."""
        controller = self._controller_execution
        if controller is None:
            raise ValueError("Exact selected Suzuki runtime scope is unavailable")
        runtime = controller.runtime
        value = runtime._consume_suzuki_igoffon_wait_origin_58e20_2026(
            origin, engine=self
        )
        if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
            raise ValueError("Native Suzuki wait DWORD required")
        self._wait_current_igoffon2026 = value
        self._wait_igoffon_aggregate2026 = value

    def bind_file_sources(self, sources):
        """Commit only141's source-issued43ee0/46010 FILE set, without reparsing."""
        from scripts.calibration_2026 import NativeUSBSource2026, native2026_cpu_count
        from scripts.cuw_file_services import validate_file_sources_2026
        from scripts.cuw_large import NativeLargeContainer2026

        self._reject_failed_cold_file_admission2026()
        validate_file_sources_2026(sources, self)
        if not self._lock.acquire(blocking=False):
            raise ValueError("CUW phase is active")
        admission = None
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
            suffix = PurePosixPath(
                sources.source_name.replace("\\", "/")
            ).suffix.casefold()
            admission = sources._wait_timing_admission2026
            cold_source_bind = self._metadata is None and self._file_sources is None
            if (
                cold_source_bind
                and suffix in (".json", ".scuw", ".cuwc")
                and admission is None
            ):
                raise ValueError(
                    "Raw named FILE admission requires its timing capability"
                )
            if admission is not None:
                if not cold_source_bind:
                    raise ValueError("Cold raw wait-timing admission is required")
                self._validate_wait_timing_admission2026(sources)
                if self._persistence is not None:
                    with self._persistence._lock:
                        self._persistence._prepare_file_source_binding_candidate2026(
                            admission.table_stages.final
                        )
                self._wait_admission_owner2026 = (sources, get_ident())
            previous = self._large_container
            if admission is not None:
                self._bind_cold_wait_timing_2026(admission)
            else:
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
                        self._validate_persistence_source(
                            metadata, file_sources=sources
                        )
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
                        self._invalidate_persistence_cpu_transition2026()
                        self._source, self._metadata = sources.selected_source, metadata
                        if type(metadata.source_container) is NativeLargeContainer2026:
                            self._source = None
                        elif type(metadata.source_container) is NativeUSBSource2026:
                            self._source = metadata.source_container.raw
                        self._dh_state, self._suzuki_state = state, suzuki
                        self._large_container = (
                            metadata.source_container
                            if type(metadata.source_container)
                            is NativeLargeContainer2026
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
            return self.native_metadata if admission is not None else metadata
        finally:
            self._wait_admission_owner2026 = None
            self._lock.release()

    def _bind_cold_wait_timing_2026(self, admission) -> None:
        """Consume and execute one complete cold source transaction monotonically."""
        sources = admission.sources
        stages = cast(Any, admission.table_stages)
        if self._file_read_region != sources.selected_metadata.region:
            raise ValueError("Cold FILE read region differs from selected source")
        admission = self._consume_file_wait_timing_admission2026(sources)
        try:
            self._execute_wait_timing_admission2026(admission, admission.steps)
            if admission.phase6_transform is not None:
                self._apply_phase6_transform_4a850_2026(
                    admission.phase6_transform,
                    admission=admission,
                    sources=sources,
                )
            transform = cast(Any, admission.phase6_transform)
            expected_copy_points = sum(
                step.operation == "32ff0" for step in admission.steps
            ) + int(transform is not None and transform.mapped_reorder is not None)
            if admission._query_cid_copy_count != expected_copy_points:
                raise ValueError("Cold32ff0 query/CID source points were incomplete")
            if (
                self._file_sources is not stages.final
                or self._metadata is not stages.final.selected_metadata
                or self._wait_current_pointer_metadata2026 is not self._metadata
            ):
                raise ValueError("Cold FILE trajectory did not reach its final pointer")
            self._wait_admission_stage2026 = (
                admission,
                "trajectory_complete",
                get_ident(),
            )
            if self._persistence is not None:
                self._wait_admission_stage2026 = (
                    admission,
                    "persistence_binding",
                    get_ident(),
                )
                with self._persistence._file_source_binding(stages.final):
                    self._persistence.bind_engine_source(self)
            self._invalidate_persistence_cpu_transition2026()
            self._wait_timing_epoch2026 += 1
            self._wait_active_admission2026 = admission
            self._wait_pending_admission2026 = None
            self._wait_admission_stage2026 = None
            self._wait_admission_cursor2026 = None
        except BaseException:
            # The consumed cursor is a durable fault seal. Native writes and
            # the last coherent source tuple remain exactly where they stopped.
            self._wait_active_admission2026 = None
            stage = cast(Any, self._wait_admission_stage2026)
            if (
                type(stage) is tuple
                and len(stage) == 3
                and stage[0] is admission
                and stage[1] == "persistence_binding"
            ):
                self._wait_admission_stage2026 = (
                    admission,
                    "fault_sealed",
                    get_ident(),
                )
            raise

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
        persistence = self._persistence
        persisted_cpu = None
        before_cpu = None
        replacement_successors = None
        if persistence is not None:
            self._validate_persistence_source(self.native_metadata)
            replacement_successors = (
                persistence._prepare_file_source_replacement_successors2026(
                    old_sources, new_sources
                )
            )
            persistence._validate_file_source_membership_successor2026(
                replacement_successors, metadata
            )
            persisted_cpu = persistence.state.write_cpu_index
            before_cpu = worker.source_state.current_global_cpu_index
        before_flow = worker._flow_file_index2026
        previous_engine_fields = (
            self._file_sources,
            self._source,
            self._metadata,
            self.dh_state.metadata,
            self.dh_state.source_sha256,
            self.dh_state.node,
            self.dh_state.selection_cpu_index,
            self.dh_state.cpu_index,
            self.dh_state.global_cpu_index,
            self.dh_state._dh_flash_size,
            self.suzuki_state.metadata,
            self.suzuki_state.source_sha256,
            self.suzuki_state.node,
            self.suzuki_state.selection_cpu_index,
            self.suzuki_state.cpu_index,
            self.suzuki_state.global_cpu_index,
            self._issued_sil_transfer,
            self._shrink_flag,
            self._persistence_cpu_transition2026,
            self._persistence_file_flow_transition2026,
        )
        self._invalidate_persistence_cpu_transition2026()
        self._invalidate_persistence_file_flow_transition2026()
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
        try:
            worker._file_reset_selected(new_sources)
        except BaseException:
            # C0 validates before publishing. Restore the engine side only
            # while that same source set is still uncommitted by the worker.
            if worker._file_sources is old_sources:
                (
                    self._file_sources,
                    self._source,
                    self._metadata,
                    self.dh_state.metadata,
                    self.dh_state.source_sha256,
                    self.dh_state.node,
                    self.dh_state.selection_cpu_index,
                    self.dh_state.cpu_index,
                    self.dh_state.global_cpu_index,
                    self.dh_state._dh_flash_size,
                    self.suzuki_state.metadata,
                    self.suzuki_state.source_sha256,
                    self.suzuki_state.node,
                    self.suzuki_state.selection_cpu_index,
                    self.suzuki_state.cpu_index,
                    self.suzuki_state.global_cpu_index,
                    self._issued_sil_transfer,
                    self._shrink_flag,
                    self._persistence_cpu_transition2026,
                    self._persistence_file_flow_transition2026,
                ) = previous_engine_fields
            elif persistence is not None:
                assert replacement_successors is not None
                persistence._publish_file_source_replacement_successors2026(
                    replacement_successors
                )
            raise
        if persistence is not None:
            assert persisted_cpu is not None and before_cpu is not None
            assert replacement_successors is not None
            persistence._publish_file_source_replacement_successors2026(
                replacement_successors
            )
            self._issue_persistence_cpu_transition2026(
                producer="141-reset",
                origin=new_sources,
                metadata=self.native_metadata,
                persisted_cpu=persisted_cpu,
                before_cpu=before_cpu,
                after_cpu=worker.source_state.current_global_cpu_index,
            )
            flow_view, pointer_view = self._persistence_file_views2026(
                new_sources, self.native_metadata, worker._flow_file_index2026
            )
            self._record_file_flow_transition2026(
                worker=worker,
                origin=new_sources,
                producer="4b900-mode2",
                old_sources=old_sources,
                new_sources=new_sources,
                before_flow=before_flow,
                after_flow=worker._flow_file_index2026,
                flow_view=flow_view,
                current_pointer_view=pointer_view,
            )
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

        self._reject_failed_cold_file_admission2026()

        if type(parameters) is not NativeFrontendParameters2026:
            raise TypeError("Concrete native frontend parameter source required")
        parameters.validate_source()
        if not self._lock.acquire(blocking=False):
            raise ValueError("CUW phase is active")
        try:
            self._reject_failed_cold_file_admission2026()
            if self._worker is not None and parameters is not self._frontend_parameters:
                raise ValueError(
                    "Bind frontend sources before issuing the native worker"
                )
            publish_general = self._general_parameters is None
            if self._general_parameters is None:
                if self._metadata is not None:
                    raise ValueError(
                        "Bind global frontend parameters before loading CUW"
                    )
            elif self._general_parameters != parameters.general:
                raise ValueError(
                    "Frontend General differs from the engine-owned source"
                )
            if self._initial_getter_reset_cold2026():
                from scripts.programming_2026_common import CommonDefinitions2026

                if type(self.common_definitions) is not CommonDefinitions2026:
                    raise TypeError("Concrete native CommonDefinitions required")
                configuration = self.configuration
                maximum = self.common_definitions.num_cpu_maxnum
                if configuration is None:
                    if maximum != 0:
                        raise ValueError(
                            "Unconfigured initial getter reset requires constructor M0"
                        )
                else:
                    if (
                        type(configuration) is not EngineConfiguration2026
                        or configuration.cpu_maximum != maximum
                        or len(configuration.arguments) != 32
                        or struct.unpack_from("<I", configuration.arguments)[0]
                        != maximum
                    ):
                        raise ValueError(
                            "Configured initial getter reset capacity is inconsistent"
                        )
                epoch = self._initial_getter_reset_epoch2026 + 1
                origin = _InitialGetterReset40580_2026(
                    self,
                    self.common_definitions,
                    configuration,
                    parameters,
                    maximum,
                    epoch,
                )
                self._initial_getter_reset_epoch2026 = epoch
                self._pending_initial_getter_reset2026 = origin
            if publish_general:
                self._general_parameters = parameters.general
            self._frontend_parameters = parameters
        finally:
            self._lock.release()

    def _issue_file_wait_timing_admission2026(
        self, sources, steps, *, phase6_transform=None, table_stages=None
    ):
        """Mint the one raw-source C44 capability after frontend binding."""
        from scripts.cuw_file_services import (
            FileSourceSet2026,
            _NativeColdFileTableStages2026,
            _NativePhase6Reorder67c602026,
            _NativePhase6Transform4a8502026,
            _NativeWaitTimingSource2026,
            _NativeWaitTimingStep2026,
        )
        from scripts.programming_2026_common import NativeFrontendParameters2026

        self._reject_failed_cold_file_admission2026()
        if (
            type(sources) is not FileSourceSet2026
            or sources.engine is not self
            or type(steps) is not tuple
            or not steps
            or any(type(step) is not _NativeWaitTimingStep2026 for step in steps)
            or type(table_stages) is not _NativeColdFileTableStages2026
            or (
                phase6_transform is not None
                and type(phase6_transform) is not _NativePhase6Transform4a8502026
            )
        ):
            raise TypeError("Exact raw native wait-timing trajectory required")
        if phase6_transform is not None:
            if (
                type(phase6_transform.raw_files) is not tuple
                or type(phase6_transform.raw_names) is not tuple
                or type(phase6_transform.raw_sources) is not tuple
                or type(phase6_transform.edges) is not tuple
                or type(phase6_transform.post_4a850_files) is not tuple
                or type(phase6_transform.post_4a850_names) is not tuple
                or type(phase6_transform.post_4a850_sources) is not tuple
                or len(phase6_transform.raw_files) != len(phase6_transform.raw_names)
                or len(phase6_transform.raw_files) != len(phase6_transform.raw_sources)
                or len(phase6_transform.post_4a850_files)
                != len(phase6_transform.post_4a850_names)
                or len(phase6_transform.post_4a850_files)
                != len(phase6_transform.post_4a850_sources)
            ):
                raise ValueError("Exact immutable Phase6 transform rows required")
            reorder = phase6_transform.mapped_reorder
            if reorder is not None and (
                type(reorder) is not _NativePhase6Reorder67c602026
                or reorder.post_4a850_files is not phase6_transform.post_4a850_files
                or reorder.post_4a850_names is not phase6_transform.post_4a850_names
                or reorder.post_4a850_sources is not phase6_transform.post_4a850_sources
            ):
                raise ValueError("Nested67c60 event must retain exact4a850 tuples")
        stage_sources = tuple(
            stage
            for stage in (
                table_stages.initial,
                table_stages.post_4a850,
                table_stages.post_67c60,
                table_stages.final,
            )
            if stage is not None
        )
        if (
            table_stages.final is not sources
            or table_stages.initial.engine is not self
            or (phase6_transform is None) != (table_stages.post_4a850 is None)
            or (
                (phase6_transform is None or phase6_transform.mapped_reorder is None)
                != (table_stages.post_67c60 is None)
            )
            or (
                phase6_transform is None
                and (
                    table_stages.initial is not sources
                    or table_stages.post_4a850 is not None
                    or table_stages.post_67c60 is not None
                )
            )
            or (
                phase6_transform is not None
                and phase6_transform.mapped_reorder is None
                and (
                    table_stages.initial is sources
                    or table_stages.post_4a850 is not sources
                )
            )
            or (
                phase6_transform is not None
                and phase6_transform.mapped_reorder is not None
                and len({id(stage) for stage in stage_sources}) != len(stage_sources)
            )
        ):
            raise ValueError("Exact registered cold FILE table stages required")
        from scripts.cuw_file_services import validate_file_sources_2026

        for stage_source in stage_sources:
            if stage_source.engine is not self:
                raise ValueError("Cold FILE derivative belongs to another engine")
            validate_file_sources_2026(stage_source, self)
            if (
                stage_source.source_name != sources.source_name
                or stage_source.admission_sha256 != sources.admission_sha256
                or stage_source.admission_source is not sources.admission_source
                or stage_source.recovery_file_names != sources.recovery_file_names
                or len(stage_source.recovery_file_sources)
                != len(sources.recovery_file_sources)
                or any(
                    left is not right
                    for left, right in zip(
                        stage_source.recovery_file_sources,
                        sources.recovery_file_sources,
                        strict=True,
                    )
                )
                or stage_source.recovery_multi_count != sources.recovery_multi_count
                or len(stage_source.delta_groups) != len(sources.delta_groups)
                or any(
                    left[:2] != right[:2] or left[2] is not right[2]
                    for left, right in zip(
                        stage_source.delta_groups, sources.delta_groups, strict=True
                    )
                )
                or any(
                    left is not right
                    for left, right in zip(
                        stage_source.delta_map_entries,
                        sources.delta_map_entries,
                        strict=True,
                    )
                )
            ):
                raise ValueError("Cold FILE stages changed immutable source lineage")
        if not self._lock.acquire(blocking=False):
            raise ValueError("CUW phase is active")
        try:
            frontend = self._frontend_parameters
            general = self._general_parameters
            initial_reset = self._pending_initial_getter_reset2026
            self._validate_cold_wait_reset_origin2026(initial_reset, frontend)
            initial_reset = cast(_InitialGetterReset40580_2026, initial_reset)
            if (
                type(frontend) is not NativeFrontendParameters2026
                or general is not frontend.general
                or self._initial_getter_reset_binding2026 is not None
                or self._file_sources is not None
                or self._metadata is not None
                or self._worker is not None
                or self._thread_job is not None
                or self._worker_replacement_thread is not None
                or self._controller_execution is not None
                or self._native_control_context2026 is not None
                or self._controller_export_target2026 is not None
                or self._retry_controller is not None
                or self._gateway_startup is not None
                or self._online_controller is not None
                or self._native_delta_active
                or self._active
                or self._phase_thread is not None
                or self._wait_pending_admission2026 is not None
                or self._wait_active_admission2026 is not None
            ):
                raise ValueError("Cold bound frontend admission is required")
            frontend.validate_source()
            source_ids = {id(item): item for item in sources.files}
            source_ids.update({id(item): item for item in sources.output_files})
            source_ids.update({id(item): item for _, _, item in sources.delta_groups})
            for step in steps:
                if step.operation not in ("46010", "32130", "43cd0", "41940", "32ff0"):
                    raise ValueError("Unsupported native wait-timing source event")
                if type(step.sources) is not tuple or any(
                    type(item) is not _NativeWaitTimingSource2026
                    for item in step.sources
                ):
                    raise TypeError("Exact native wait-timing source records required")
                for item in step.sources:
                    if type(item.source_name) is not str or not item.source_name:
                        raise ValueError("Native wait-timing source name is required")
                    if type(item.source) is not bytes or not item.source:
                        raise ValueError("Native wait-timing source bytes are required")
                    if item.metadata is not None:
                        if source_ids.get(id(item.metadata)) is not item.metadata:
                            transform_sources = (
                                ()
                                if phase6_transform is None
                                else phase6_transform.raw_files
                                + phase6_transform.post_4a850_files
                                + (
                                    ()
                                    if phase6_transform.mapped_reorder is None
                                    else phase6_transform.mapped_reorder.post_67c60_files
                                )
                            )
                            if not any(
                                item.metadata is candidate
                                for candidate in transform_sources
                            ):
                                raise ValueError(
                                    "Wait-timing metadata is outside the issued source set"
                                )
                        if item.metadata.source_sha256 != hashlib.sha256(
                            item.source
                        ).hexdigest() and not (
                            phase6_transform is not None
                            and any(
                                item.metadata is candidate
                                for candidate in phase6_transform.post_4a850_files
                            )
                        ):
                            raise ValueError("Wait-timing metadata differs from source")
                if step.operation == "32ff0":
                    if (
                        step.slot != 0
                        or type(step.value) is not bool
                        or len(step.sources) > 1
                        or (
                            step.value
                            and sources.source_name.casefold().endswith(".cuwc")
                        )
                        or (
                            not step.value
                            and not sources.source_name.casefold().endswith(".cuwc")
                        )
                    ):
                        raise ValueError("Exact cold32ff0 slot and Boolean required")
                elif step.slot is not None or step.value is not None:
                    raise ValueError("Unexpected wait-timing source operands")
            capability = _NativeWaitTimingAdmission2026(
                self,
                sources,
                frontend,
                general,
                tuple(sorted(frontend.source_sha256.items())),
                initial_reset,
                initial_reset.epoch,
                steps,
                phase6_transform,
                table_stages,
                _WAIT_TIMING_ADMISSION_TOKEN,
            )
            for stage_source in stage_sources:
                attached = stage_source._wait_timing_admission2026
                if attached is not None:
                    raise ValueError("Cold FILE derivative already has a capability")
            for stage_source in stage_sources:
                object.__setattr__(
                    stage_source, "_wait_timing_admission2026", capability
                )
            self._wait_pending_admission2026 = capability
            return capability
        finally:
            self._lock.release()

    def _validate_cold_wait_reset_origin2026(self, origin, frontend) -> None:
        """Revalidate the exact constructor-cold reset lineage for this admission."""
        from scripts.programming_2026_common import (
            CommonDefinitions2026,
            NativeFrontendParameters2026,
        )

        if (
            type(origin) is not _InitialGetterReset40580_2026
            or origin is not self._pending_initial_getter_reset2026
            or origin.engine is not self
            or origin.common_definitions is not self.common_definitions
            or type(self.common_definitions) is not CommonDefinitions2026
            or type(origin.parameters) is not NativeFrontendParameters2026
            or origin.parameters is not frontend
            or type(frontend) is not NativeFrontendParameters2026
            or type(origin.epoch) is not int
            or origin.epoch <= 0
            or origin.epoch != self._initial_getter_reset_epoch2026
            or self._initial_getter_reset_binding2026 is not None
            or type(origin.maximum) is not int
            or origin.maximum < 0
        ):
            raise ValueError("Exact pending cold getter-reset origin required")
        if origin.configuration is None:
            if origin.maximum != 0:
                raise ValueError("Cold reset origin must retain constructor M0")
        elif (
            type(origin.configuration) is not EngineConfiguration2026
            or origin.configuration.cpu_maximum != origin.maximum
            or len(origin.configuration.arguments) != 32
            or struct.unpack_from("<I", origin.configuration.arguments)[0]
            != origin.maximum
        ):
            raise ValueError("Cold reset origin configuration lineage is invalid")
        current_configuration = self.configuration
        current_maximum = self.common_definitions.num_cpu_maxnum
        if current_configuration is None:
            if current_maximum != 0:
                raise ValueError("Cold current configuration must retain M0")
        elif (
            type(current_configuration) is not EngineConfiguration2026
            or current_configuration.cpu_maximum != current_maximum
            or len(current_configuration.arguments) != 32
            or struct.unpack_from("<I", current_configuration.arguments)[0]
            != current_maximum
        ):
            raise ValueError("Cold current configuration lineage is invalid")
        origin.parameters.validate_source()
        frontend.validate_source()

    def _validate_wait_timing_admission2026(self, sources):
        from scripts.cuw_file_services import _NativeColdFileTableStages2026
        from scripts.programming_2026_common import NativeFrontendParameters2026

        capability = sources._wait_timing_admission2026
        if (
            type(capability) is not _NativeWaitTimingAdmission2026
            or capability._token is not _WAIT_TIMING_ADMISSION_TOKEN
            or capability.engine is not self
            or capability.sources is not sources
            or type(capability.table_stages) is not _NativeColdFileTableStages2026
            or capability.table_stages.final is not sources
            or self._wait_pending_admission2026 is not capability
            or capability._consumed
            or type(capability._query_cid_copy_count) is not int
            or capability._query_cid_copy_count != 0
            or type(self._frontend_parameters) is not NativeFrontendParameters2026
            or capability.frontend is not self._frontend_parameters
            or capability.general is not self._general_parameters
            or capability.general is not capability.frontend.general
            or capability.initial_reset is not self._pending_initial_getter_reset2026
            or capability.initial_reset_epoch != self._initial_getter_reset_epoch2026
            or capability.initial_reset.engine is not self
            or capability.initial_reset.parameters is not capability.frontend
            or capability.initial_reset.common_definitions
            is not self.common_definitions
            or capability.initial_reset.epoch != capability.initial_reset_epoch
            or capability.catalog_sha256
            != tuple(sorted(capability.frontend.source_sha256.items()))
        ):
            raise ValueError("Exact unconsumed source wait-timing capability required")
        self._validate_cold_wait_reset_origin2026(
            capability.initial_reset, capability.frontend
        )
        capability.frontend.validate_source()
        return capability

    def _consume_file_wait_timing_admission2026(self, sources):
        """Consume immediately before the first native FILE source write."""
        if self._wait_admission_owner2026 != (sources, get_ident()):
            raise ValueError("Exact live cold FILE bind transaction required")
        capability = self._validate_wait_timing_admission2026(sources)
        with capability._lock:
            if capability._consumed:
                raise ValueError("Native wait-timing capability was already consumed")
            object.__setattr__(capability, "_consumed", True)
        self._wait_pending_admission2026 = None
        self._wait_active_admission2026 = None
        self._wait_admission_stage2026 = capability
        self._wait_admission_cursor2026 = 0
        return capability

    def _wait_timing_source_step_41940_2026(self, admission, metadata, *, point):
        previous = cast(Any, self._wait_admission_stage2026)
        thread_id = get_ident()
        if self._wait_admission_owner2026 != (admission.sources, thread_id):
            raise ValueError("Exact cold FILE bind thread required")
        if (
            type(previous) is tuple
            and len(previous) in (4, 6)
            and previous[0] is admission
            and type(previous[1]) is int
            and previous[1] < len(admission.steps)
            and previous[2] == thread_id
            and previous[1] == self._wait_admission_cursor2026
            and admission.steps[previous[1]] is previous[3]
        ):
            source_step = previous[3]
            if point == "32130":
                if source_step.operation == "43cd0" and len(previous) == 6:
                    slot, record = previous[4], previous[5]
                    valid = (
                        type(slot) is int
                        and 0 <= slot < len(source_step.sources)
                        and source_step.sources[slot] is record
                        and record.metadata is metadata
                    )
                else:
                    valid = source_step.operation == "32130" and (
                        len(source_step.sources) == 1
                        and source_step.sources[0].metadata is metadata
                    )
            elif point == "41940":
                valid = (
                    source_step.operation == "41940"
                    and len(source_step.sources) == 1
                    and source_step.sources[0].metadata is metadata
                )
            elif point == "32ff0":
                valid = source_step.operation == "32ff0" and (
                    (
                        source_step.sources
                        and source_step.sources[0].metadata is metadata
                    )
                    or (not source_step.sources and self._metadata is metadata)
                )
            else:
                valid = False
            if not valid:
                raise ValueError("Exact active cold wait-timing source step required")
        elif (
            type(previous) is tuple
            and len(previous) == 3
            and previous[0] is admission
            and previous[1] is admission.phase6_transform
            and previous[2] == thread_id
            and point == "phase6_second32ff0"
        ):
            source_step = cast(Any, previous[1])
            pending = self._phase6_second_select2026
            if (
                type(pending) is not tuple
                or len(pending) != 3
                or pending[0] is not admission
                or pending[1] is not source_step
                or pending[2] != thread_id
                or source_step.mapped_reorder is None
                or source_step.mapped_reorder.second_select[2] is not metadata
            ):
                raise ValueError("Exact active mapped Phase6 selector required")
        else:
            raise ValueError("A live cold wait-timing transaction is required")
        self._wait_admission_stage2026 = (
            admission,
            metadata,
            point,
            thread_id,
            previous,
        )
        try:
            return self._select_frontend_parameters_41940_2026(metadata)
        finally:
            self._wait_admission_stage2026 = previous

    def _select_frontend_parameters_41940_2026(self, metadata):
        """Run the source-bound shared41940 selection and retain its key copies."""
        from scripts.calibration_2026 import (
            native2026_cpu_count,
            native2026_cpu_values,
            native2026_node_count,
            native2026_node_values,
        )
        from scripts.programming_2026_common import (
            NativeFrontendParameters2026,
            NativeParameter2026,
            NativePassThruException2026,
        )

        frontend = self._frontend_parameters
        if (
            type(frontend) is not NativeFrontendParameters2026
            or self._general_parameters is not frontend.general
            or metadata is None
        ):
            raise ValueError("Bound frontend and exact native metadata required")
        stage = cast(Any, self._wait_admission_stage2026)
        if (
            type(stage) is tuple
            and len(stage) == 5
            and type(stage[0]) is _NativeWaitTimingAdmission2026
            and stage[0]._consumed
            and stage[1] is metadata
            and stage[3] == get_ident()
            and self._wait_admission_owner2026 == (stage[0].sources, get_ident())
        ):
            from scripts.cuw_file_services import _NativePhase6Transform4a8502026

            admission = cast(_NativeWaitTimingAdmission2026, stage[0])
            prior = cast(Any, stage[4])
            step = None
            if (
                type(prior) is tuple
                and len(prior) in (4, 6)
                and prior[0] is admission
                and prior[1] == self._wait_admission_cursor2026
                and prior[2] == get_ident()
                and 0 <= prior[1] < len(admission.steps)
                and admission.steps[prior[1]] is prior[3]
                and stage[2] in ("32130", "41940", "32ff0")
            ):
                candidate = cast(Any, prior[3])
                records = candidate.sources
                if candidate.operation == "43cd0" and len(prior) == 6:
                    slot, record = prior[4], prior[5]
                    matches = (
                        type(slot) is int
                        and 0 <= slot < len(records)
                        and records[slot] is record
                        and record.metadata is metadata
                    )
                elif candidate.operation == "32ff0" and not records:
                    matches = self._metadata is metadata
                else:
                    matches = any(record.metadata is metadata for record in records)
                expected_operation = (
                    candidate.operation in ("32130", "43cd0")
                    if stage[2] == "32130"
                    else candidate.operation == stage[2]
                )
                if expected_operation and matches:
                    step = candidate
            if step is None and stage[2] == "phase6_second32ff0":
                pending = self._phase6_second_select2026
                transform = cast(
                    _NativePhase6Transform4a8502026 | None,
                    prior[1] if type(prior) is tuple and len(prior) == 3 else None,
                )
                reorder = None if transform is None else transform.mapped_reorder
                if (
                    type(prior) is tuple
                    and len(prior) == 3
                    and prior[0] is admission
                    and prior[2] == get_ident()
                    and type(pending) is tuple
                    and len(pending) == 3
                    and pending[0] is admission
                    and pending[1] is transform
                    and pending[2] == get_ident()
                    and reorder is not None
                    and reorder.second_select[2] is metadata
                ):
                    step = True
            if step is None:
                raise ValueError("Metadata is outside the pending cold source point")
        else:
            worker = self._worker
            if worker is None:
                raise ValueError("Authenticated41940 source point required")
            worker._validate_frontend_selection_41940_2026(metadata, engine=self)
        frontend.validate_source()

        kind = metadata.vehicle.get("kindofecu", "")
        contact = metadata.vehicle.get("contacttype", "")
        cpu_count = native2026_cpu_count(metadata)
        if contact in ("P5-Unified", "Phase6", "Ethernet"):
            general_cpus = (0,)
        else:
            general_cpus = tuple(range(cpu_count)) + (0,)
        general = frontend.general._parameter()
        if type(general) is not NativeParameter2026:
            raise TypeError("Native General parameter primitive required")
        for position, cpu_index in enumerate(general_cpus):
            cpu = native2026_cpu_values(metadata, cpu_index).get("cputype", "")
            self._wait_general_keys2026 = (kind, cpu, contact)
            if not general.set_keys(kind, cpu, contact):
                line = 0x2B7F if position == len(general_cpus) - 1 else 0x2B72
                raise NativePassThruException2026(9999, _NATIVE_CUW_SOURCE_2026, line)
        image = None
        key_column = "diagid"
        if contact in ("P5-Unified", "Phase6"):
            image = frontend.parameter("CanIDTable.ini")
            key_column = "diagid"
        elif contact == "Ethernet":
            image = frontend.parameter("LogicalAddressTable.ini")
            key_column = "logicaladdress"
        if image is not None:
            if type(image) is not NativeParameter2026:
                raise TypeError("Native image parameter primitive required")
            node_indices = tuple(range(native2026_node_count(metadata))) + (0,)
            for position, node_index in enumerate(node_indices):
                node = native2026_node_values(metadata, node_index)
                key = node.get(key_column, "")
                self._wait_image_keys2026 = (key,)
                row = image.search_row(image.key_column, key)
                image.row_index = row
                if row < 0:
                    if contact in ("P5-Unified", "Phase6"):
                        line = 0x2B9A if position == len(node_indices) - 1 else 0x2B90
                    else:
                        line = 0x2BB4 if position == len(node_indices) - 1 else 0x2BAA
                    raise NativePassThruException2026(
                        9999, _NATIVE_CUW_SOURCE_2026, line
                    )
        self._wait_selected_general2026 = general
        self._wait_selected_image2026 = image
        return general, image

    def _check_wait_timing_resources_490b0_2026(self, metadata) -> None:
        from scripts.calibration_2026 import (
            native2026_node_count,
            native2026_node_values,
        )
        from scripts.programming_2026_common import (
            NativeFrontendParameters2026,
            NativePassThruException2026,
        )

        if metadata.vehicle.get("contacttype", "") != "P5-Unified":
            return
        count = native2026_node_count(metadata)
        if count <= 0:
            return
        frontend = self._frontend_parameters
        if type(frontend) is not NativeFrontendParameters2026:
            raise ValueError("Bound native frontend resource catalog required")
        names = {name.casefold() for name in frontend.sources}
        for node_index in range(count):
            node = native2026_node_values(metadata, node_index)
            required = node.get("requiredspecreprover", "")
            if (
                type(required) is not str
                or re.fullmatch(r"[A-Za-z0-9_-]{0,128}", required, re.ASCII) is None
            ):
                raise CUWEngineError(9999, "Native490b0 resource name is unsupported")
            suffix = "" if required == "02" else required
            requested = ("P5-Unified" + suffix + ".ini").casefold()
            if requested not in names:
                raise NativePassThruException2026(9999, _NATIVE_CUW_SOURCE_2026, 0x3719)

    @staticmethod
    def _wait_timing_dword_2026(value: int) -> int:
        if type(value) is not int or not -(2**31) <= value < 2**31:
            raise CUWEngineError(2, "Native wait timing LONG lookup failed")
        return value & 0xFFFFFFFF

    def _load_wait_timing_32130_2026(self, admission, record) -> None:
        from scripts.calibration_2026 import native2026_cpu_count, native2026_cpu_values
        from scripts.programming_2026_common import NativeCallbackLookupError

        metadata = record.metadata
        if metadata is None:
            raise ValueError("Native32130 metadata source is required")
        self._wait_timing_source_step_41940_2026(admission, metadata, point="32130")
        self._check_wait_timing_resources_490b0_2026(metadata)
        general = self._wait_selected_general2026
        if general is None:
            raise ValueError("Exact selected General parameter is unavailable")
        cpu_count = native2026_cpu_count(metadata)
        maxima = [0, 0, 0]
        minimum_voltage = 0
        names = (
            "WaitTimeForIGOFFON",
            "WaitTimeAfterBatteryDisconnected",
            "WaitTimeAfterBatteryConnected",
            "BatteryVoltageUpperThreshold",
        )
        for cpu_index in range(cpu_count):
            cpu = native2026_cpu_values(metadata, cpu_index).get("cputype", "")
            kind = metadata.vehicle.get("kindofecu", "")
            contact = metadata.vehicle.get("contacttype", "")
            values = []
            for name in names:
                value = general.long_with_keys(name, kind, cpu, contact)
                if value is None:
                    raise NativeCallbackLookupError()
                values.append(self._wait_timing_dword_2026(value))
            for index in range(3):
                maxima[index] = max(maxima[index], values[index])
            voltage = values[3]
            if voltage and (minimum_voltage == 0 or voltage < minimum_voltage):
                minimum_voltage = voltage
        self._wait_current_igoffon2026 = maxima[0]
        self._wait_current_battery_disconnected2026 = maxima[1]
        self._wait_current_battery_connected2026 = maxima[2]
        self._wait_battery_voltage_raw2026 = minimum_voltage
        self._wait_d4e8_battery_voltage2026 = minimum_voltage / 1000.0

    def _complete_cold_32ff0_query_cid_copy2026(
        self, admission, step, stage_sources, metadata
    ) -> bool:
        """Validate the bounded empty query/CID copy point after 41940."""
        thread_id = get_ident()
        transaction = self._wait_admission_stage2026
        reset = admission.initial_reset
        self._validate_cold_wait_reset_origin2026(reset, admission.frontend)
        phase6_point = type(transaction) is tuple and len(transaction) == 3
        if phase6_point:
            expected_cursor = len(admission.steps)
            expected_copy_count = sum(
                candidate.operation == "32ff0" for candidate in admission.steps
            )
        else:
            expected_cursor = (
                transaction[1]
                if type(transaction) is tuple
                and len(transaction) == 4
                and type(transaction[1]) is int
                else -1
            )
            expected_copy_count = sum(
                candidate.operation == "32ff0"
                for candidate in admission.steps[:expected_cursor]
            )
        if phase6_point:
            source_step_metadata_valid = (
                admission.phase6_transform is not None
                and admission.phase6_transform.mapped_reorder is not None
                and admission.phase6_transform.mapped_reorder.second_select[2]
                is metadata
            )
        else:
            source_step_metadata_valid = not step.sources or (
                step.sources[0].metadata is metadata
            )
        if (
            type(transaction) is tuple
            and len(transaction) == 4
            and transaction[0] is admission
            and type(transaction[1]) is int
            and transaction[2] == thread_id
            and transaction[3] is step
        ):
            source_point_valid = (
                self._wait_admission_cursor2026 == transaction[1]
                and 0 <= transaction[1] < len(admission.steps)
                and admission.steps[transaction[1]] is step
            )
        else:
            phase6_transaction = self._phase6_second_select2026
            transform = admission.phase6_transform
            source_point_valid = (
                type(transaction) is tuple
                and len(transaction) == 3
                and transaction[0] is admission
                and transaction[1] is transform
                and transaction[2] == thread_id
                and type(phase6_transaction) is tuple
                and len(phase6_transaction) == 3
                and phase6_transaction[0] is admission
                and phase6_transaction[1] is transform
                and phase6_transaction[2] == thread_id
                and transform is not None
                and transform.mapped_reorder is not None
                and self._wait_admission_cursor2026 == len(admission.steps)
                and any(candidate is step for candidate in admission.steps)
                and transform.mapped_reorder.second_select[2] is metadata
            )
        if (
            not source_point_valid
            or admission.engine is not self
            or not admission._consumed
            or self._wait_admission_owner2026 != (admission.sources, thread_id)
            or self._wait_admission_cursor2026 != expected_cursor
            or self._wait_pending_admission2026 is not None
            or self._wait_active_admission2026 is not None
            or self._file_sources is not stage_sources
            or self._metadata is not metadata
            or self._wait_current_pointer_metadata2026 is not metadata
            or step.operation != "32ff0"
            or step.slot != 0
            or type(step.value) is not bool
            or not source_step_metadata_valid
            or stage_sources.selected_metadata is not metadata
            or stage_sources.engine is not self
            or type(self._native_delta_active) is not bool
            or type(stage_sources.delta_map_size) is not int
            or stage_sources.delta_map_size < 0
            or type(reset) is not _InitialGetterReset40580_2026
            or self._pending_initial_getter_reset2026 is not reset
            or reset.engine is not self
            or reset.parameters is not admission.frontend
            or reset.common_definitions is not self.common_definitions
            or type(reset.epoch) is not int
            or reset.epoch <= 0
            or reset.epoch != admission.initial_reset_epoch
            or reset.epoch != self._initial_getter_reset_epoch2026
            or self._initial_getter_reset_binding2026 is not None
            or self._file_read_region != stage_sources.selected_metadata.region
            or self._worker is not None
            or self._thread_job is not None
            or self._worker_replacement_thread is not None
            or self._controller_execution is not None
            or self._native_control_context2026 is not None
            or self._controller_export_target2026 is not None
            or self._retry_controller is not None
            or self._gateway_startup is not None
            or self._online_controller is not None
            or self._active
            or self._phase_thread is not None
            or not self._phase_finished.is_set()
            or self._cancelled.is_set()
            or type(admission._query_cid_copy_count) is not int
            or admission._query_cid_copy_count != expected_copy_count
        ):
            raise ValueError("Exact live cold32ff0 copy point required")
        if (
            self._identifier_records
            or self._received_identifiers
            or self._working_identifier_records
            or self._received_hardware
            or self._working_hardware
            or self._working_contact_buffer != bytes(33)
            or self._identifier_context_epoch != 0
            or self._identifier_context_importing
            or self._last_completed_standalone_getter is not None
            or self._native_prepare_handshake != 0
        ):
            raise ValueError("Cold query/CID vectors were already populated")

        # The native copy branch is empty-to-empty; the opposite branch skips
        # both calls. Neither has a modeled Python data mutation at this point.
        copy_branch = stage_sources.delta_map_size != 0 or not self._native_delta_active
        with admission._lock:
            if admission._query_cid_copy_count != expected_copy_count:
                raise ValueError("Cold32ff0 query/CID point was replayed")
            object.__setattr__(
                admission,
                "_query_cid_copy_count",
                expected_copy_count + 1,
            )
        return copy_branch

    def _execute_wait_timing_admission2026(self, admission, steps) -> None:
        cursor = self._wait_admission_cursor2026
        if (
            self._wait_admission_stage2026 is not admission
            or self._wait_admission_owner2026 != (admission.sources, get_ident())
            or type(cursor) is not int
            or type(steps) is not tuple
            or steps != admission.steps[cursor : cursor + len(steps)]
            or any(
                left is not right
                for left, right in zip(steps, admission.steps[cursor:], strict=False)
            )
        ):
            raise ValueError("Exact consumed cold timing capability required")
        for step_index, step in enumerate(steps, start=cursor):
            self._wait_admission_stage2026 = (
                admission,
                step_index,
                get_ident(),
                step,
            )
            if step.operation == "46010":
                self._native_delta_active = True
            elif step.operation == "32130":
                if len(step.sources) != 1:
                    raise ValueError("Exact32130 source record required")
                self._load_wait_timing_32130_2026(admission, step.sources[0])
            elif step.operation == "43cd0":
                if type(step.sources) is not tuple or len(step.sources) > 16:
                    raise ValueError("Bounded native43cd0 source walk required")
                aggregate_ig = 0
                aggregate_voltage = 0
                for slot, record in enumerate(step.sources):
                    if record.metadata is None:
                        raise ValueError("Actual43e20 metadata source required")
                    transaction = self._wait_admission_stage2026
                    self._wait_admission_stage2026 = (
                        admission,
                        step_index,
                        get_ident(),
                        step,
                        slot,
                        record,
                    )
                    try:
                        self._load_wait_timing_32130_2026(admission, record)
                    finally:
                        self._wait_admission_stage2026 = transaction
                    if slot >= 16:
                        raise ValueError("Native wait timing vector exceeds16 slots")
                    ig = self._wait_current_igoffon2026
                    disconnected = self._wait_current_battery_disconnected2026
                    connected = self._wait_current_battery_connected2026
                    ig_vector = list(self._wait_igoffon_by_file2026)
                    disconnected_vector = list(
                        self._wait_battery_disconnected_by_file2026
                    )
                    connected_vector = list(self._wait_battery_connected_by_file2026)
                    ig_vector[slot] = ig
                    disconnected_vector[slot] = disconnected
                    connected_vector[slot] = connected
                    self._wait_igoffon_by_file2026 = tuple(ig_vector)
                    self._wait_battery_disconnected_by_file2026 = tuple(
                        disconnected_vector
                    )
                    self._wait_battery_connected_by_file2026 = tuple(connected_vector)
                    aggregate_ig = max(aggregate_ig, ig)
                    voltage = self._wait_battery_voltage_raw2026
                    if voltage and (
                        aggregate_voltage == 0 or voltage < aggregate_voltage
                    ):
                        aggregate_voltage = voltage
                self._wait_igoffon_aggregate2026 = aggregate_ig
                self._wait_d4e8_battery_voltage2026 = aggregate_voltage / 1000.0
                self._wait_battery_voltage_raw2026 = aggregate_voltage
            elif step.operation == "41940":
                if len(step.sources) != 1 or step.sources[0].metadata is None:
                    raise ValueError("Exact41940 source metadata required")
                if self._file_sources is None:
                    self._publish_cold_file_table_2026(
                        admission.table_stages.initial, admission=admission
                    )
                    if (
                        admission.table_stages.initial.selected_metadata
                        is not step.sources[0].metadata
                    ):
                        raise ValueError(
                            "Direct SCUW whole pointer differs from its stage"
                        )
                elif (
                    self._wait_current_pointer_metadata2026
                    is not step.sources[0].metadata
                ):
                    raise ValueError("41940 cannot republish a different current FILE")
                self._wait_timing_source_step_41940_2026(
                    admission, step.sources[0].metadata, point="41940"
                )
            elif step.operation == "32ff0":
                if self._file_sources is None:
                    pointer_sources = admission.table_stages.initial
                elif (
                    admission.table_stages.post_67c60 is not None
                    and self._file_sources is admission.table_stages.post_67c60
                ):
                    pointer_sources = admission.table_stages.final
                else:
                    raise ValueError("32ff0 is outside its exact FILE table stage")
                pointer_metadata = pointer_sources.selected_metadata
                if step.sources and step.sources[0].metadata is not pointer_metadata:
                    raise ValueError("Exact cold32ff0 pointer differs from its stage")
                self._publish_cold_file_table_2026(pointer_sources, admission=admission)
                self._wait_timing_source_step_41940_2026(
                    admission,
                    pointer_metadata,
                    point="32ff0",
                )
                self._complete_cold_32ff0_query_cid_copy2026(
                    admission,
                    step,
                    pointer_sources,
                    pointer_metadata,
                )
                slot = step.slot
                if type(slot) is not int or not 0 <= slot < 16:
                    raise ValueError("Exact cold32ff0 vector slot required")
                self._wait_current_igoffon2026 = self._wait_igoffon_by_file2026[slot]
                self._wait_current_battery_disconnected2026 = (
                    self._wait_battery_disconnected_by_file2026[slot]
                )
                self._wait_current_battery_connected2026 = (
                    self._wait_battery_connected_by_file2026[slot]
                )
            self._wait_admission_cursor2026 = step_index + 1
            self._wait_admission_stage2026 = (
                admission
                if self._wait_admission_cursor2026 < len(admission.steps)
                else None
            )

    def _publish_cold_file_table_2026(
        self, stage_sources, *, admission: _NativeWaitTimingAdmission2026
    ) -> None:
        """Publish only the exact D55C table/pointer reached by the cold source."""
        from scripts.calibration_2026 import (
            NativeUSBSource2026,
            native2026_validate_runtime_metadata,
        )
        from scripts.cuw_file_services import (
            FileSourceSet2026,
            _NativeColdFileTableStages2026,
            validate_file_sources_2026,
        )
        from scripts.cuw_large import NativeLargeContainer2026

        stages = admission.table_stages
        if (
            type(admission) is not _NativeWaitTimingAdmission2026
            or type(stages) is not _NativeColdFileTableStages2026
            or type(stage_sources) is not FileSourceSet2026
            or admission.engine is not self
            or not admission._consumed
            or admission.sources is not stages.final
            or stage_sources._wait_timing_admission2026 is not admission
            or self._wait_active_admission2026 is not None
            or self._wait_admission_owner2026 != (admission.sources, get_ident())
        ):
            raise ValueError("Exact consumed cold FILE stage required")
        stage = cast(Any, self._wait_admission_stage2026)
        cursor = self._wait_admission_cursor2026
        if type(cursor) is not int:
            raise ValueError("Live cold FILE source cursor required")

        pointer_metadata = None
        if stage_sources is stages.initial:
            if (
                self._file_sources is not None
                or self._metadata is not None
                or self._wait_current_pointer_metadata2026 is not None
                or type(stage) is not tuple
                or len(stage) not in (4, 6)
                or stage[0] is not admission
                or stage[2] != get_ident()
                or type(stage[1]) is not int
                or not 0 <= stage[1] < len(admission.steps)
            ):
                raise ValueError("Initial cold FILE pointer source point required")
            source_step = admission.steps[stage[1]]
            if stage[3] is not source_step:
                raise ValueError("Initial cold FILE step identity changed")
            if source_step.operation == "32ff0":
                suffix = PurePosixPath(
                    admission.sources.source_name.replace("\\", "/")
                ).suffix.casefold()
                if (
                    source_step.slot != 0
                    or type(source_step.value) is not bool
                    or (source_step.value is True) != (suffix == ".json")
                    or suffix not in (".json", ".cuwc")
                    or len(source_step.sources) != 1
                ):
                    raise ValueError("Exact initial cold32ff0 source required")
            elif source_step.operation == "41940":
                if (
                    not admission.sources.source_name.casefold().endswith(".scuw")
                    or cursor != stage[1]
                    or stage[1] == 0
                    or admission.steps[stage[1] - 1].operation != "32130"
                ):
                    raise ValueError("Exact direct SCUW whole-pointer source required")
            else:
                raise ValueError(
                    "Initial cold FILE publication is outside source order"
                )
            pointer_metadata = stages.initial.selected_metadata
        elif stage_sources is stages.post_4a850:
            transform = admission.phase6_transform
            if (
                transform is None
                or type(stage) is not tuple
                or len(stage) != 3
                or stage[0] is not admission
                or stage[1] is not transform
                or stage[2] != get_ident()
                or self._file_sources is not stages.initial
            ):
                raise ValueError("Exact successful4a850 FILE publication required")
            pointer_metadata = cast(Any, stages.post_4a850).selected_metadata
        elif stage_sources is stages.post_67c60:
            transform = admission.phase6_transform
            if (
                transform is None
                or cast(Any, transform).mapped_reorder is None
                or type(stage) is not tuple
                or len(stage) != 3
                or stage[0] is not admission
                or stage[1] is not transform
                or stage[2] != get_ident()
                or self._file_sources is not stages.post_4a850
                or self._wait_current_pointer_metadata2026 is not self._metadata
            ):
                raise ValueError("Exact successful67c60 FILE publication required")
            pointer_metadata = self._metadata
        elif stage_sources is stages.final:
            transform = admission.phase6_transform
            reorder = None if transform is None else cast(Any, transform).mapped_reorder
            if (
                reorder is None
                or type(stage) is not tuple
                or len(stage) != 3
                or stage[0] is not admission
                or stage[1] is not transform
                or stage[2] != get_ident()
                or self._file_sources is not stages.post_67c60
                or reorder.second_select[2] is not stages.final.selected_metadata
            ):
                raise ValueError("Exact second32ff0 FILE publication required")
            pointer_metadata = stages.final.selected_metadata
        else:
            raise ValueError("Unissued cold FILE table stage")

        validate_file_sources_2026(stage_sources, self)
        if pointer_metadata is None:
            raise ValueError("Cold FILE stage has no current pointer")
        native2026_validate_runtime_metadata(pointer_metadata)
        old_metadata = self._metadata
        if stage_sources is stages.post_67c60:
            if pointer_metadata is not old_metadata:
                raise ValueError("67c60 cannot change the current FILE pointer")
        elif (
            stage_sources is not stages.initial
            and stage_sources is not stages.final
            and stage_sources.selected_metadata is not pointer_metadata
        ):
            raise ValueError("Cold FILE successor pointer differs from its stage")

        # Construct every fallible object before publishing the tuple.
        new_source = stage_sources.selected_source
        new_container = None
        if isinstance(pointer_metadata.source_container, NativeUSBSource2026):
            new_source = pointer_metadata.source_container.raw
        if type(pointer_metadata.source_container) is NativeLargeContainer2026:
            new_source = None
            new_container = pointer_metadata.source_container
        owned_large = dict(self._owned_large_containers)
        if new_container is not None:
            owned_large[id(new_container)] = new_container
        owned_usb = dict(self._owned_usb_sources)
        if isinstance(pointer_metadata.source_container, NativeUSBSource2026):
            owned_usb[id(pointer_metadata.source_container)] = (
                pointer_metadata.source_container
            )
        if self._dh_state is None:
            if self.configuration is None:
                raise ValueError("Configured native FILE binding is required")
            dh_state = DHControllerState2026(
                _DH_STATE_TOKEN,
                self.identity,
                pointer_metadata,
                self.configuration.cpu_maximum,
                engine=self,
            )
            suzuki_state = SuzukiControllerState2026(
                _DH_STATE_TOKEN, self.identity, pointer_metadata, error_state=dh_state
            )
            if self._persistence is not None:
                dh_state._notification = self._persistence.notification
        else:
            dh_state, suzuki_state = self._dh_state, self._suzuki_state

        # These are the single coherent source tuple for every table consumer.
        self._file_sources = stage_sources
        self._metadata = pointer_metadata
        self._source = new_source
        self._large_container = new_container
        self._owned_large_containers = owned_large
        self._owned_usb_sources = owned_usb
        self._dh_state = dh_state
        self._suzuki_state = suzuki_state
        self._wait_current_pointer_metadata2026 = pointer_metadata
        self._shrink_flag = pointer_metadata.initial_shrink_flag
        for state in (cast(Any, dh_state), cast(Any, suzuki_state)):
            state.metadata = pointer_metadata
            state.source_sha256 = pointer_metadata.source_sha256
            state.node = pointer_metadata.node
            state.selection_cpu_index = pointer_metadata.cpu_index

    def _validate_phase6_transform2026(self, transform, admission, sources):
        from scripts.calibration import CalibrationContainer
        from scripts.calibration_2026 import (
            NativeCompositeSource2026,
            native2026_validate_runtime_metadata,
        )
        from scripts.cuw_file_services import (
            _NativePhase6Reorder67c602026,
            _NativePhase6Transform4a8502026,
        )

        if (
            type(transform) is not _NativePhase6Transform4a8502026
            or admission.phase6_transform is not transform
            or admission.sources is not sources
            or self._wait_active_admission2026 is not None
            or self._wait_admission_owner2026 != (sources, get_ident())
            or self._wait_admission_cursor2026 != len(admission.steps)
            or self._wait_admission_stage2026 is not None
            or self._wait_current_pointer_metadata2026 is None
        ):
            raise ValueError("Exact current Phase6 transform source point required")
        rows = (transform.raw_files, transform.raw_names, transform.raw_sources)
        if any(type(row) is not tuple for row in rows) or not (
            len(transform.raw_files)
            == len(transform.raw_names)
            == len(transform.raw_sources)
        ):
            raise ValueError("Exact immutable raw Phase6 table required")
        recovery_names, recovery_sources, _ = sources.recovery_sources()
        for name, raw, metadata in zip(
            transform.raw_names,
            transform.raw_sources,
            transform.raw_files,
            strict=True,
        ):
            from_recovery = any(
                name == recovery_name and raw is recovery_source
                for recovery_name, recovery_source in zip(
                    recovery_names, recovery_sources, strict=True
                )
            )
            from_current_table = any(
                name == current_name
                and raw is current_source
                and metadata is current_metadata
                for current_name, current_source, current_metadata in zip(
                    sources.file_names, sources.file_sources, sources.files, strict=True
                )
            )
            from_parsed_member = (
                type(metadata.source_container) is CalibrationContainer
                and metadata.source_container.attached.data is raw
            )
            if (
                type(name) is not str
                or not name
                or type(raw) is not bytes
                or not raw
                or metadata.source_sha256 != hashlib.sha256(raw).hexdigest()
                or not (from_recovery or from_current_table or from_parsed_member)
            ):
                raise ValueError("Raw Phase6 slot lacks exact recovery provenance")
        if not sources.has_file_vector or not any(
            item.vehicle.get("contacttype", "") == "Phase6"
            for item in transform.raw_files
        ):
            raise ValueError("Actual Phase6 FILE-vector source branch required")
        if len(transform.post_4a850_files) != len(transform.post_4a850_names) or len(
            transform.post_4a850_files
        ) != len(transform.post_4a850_sources):
            raise ValueError("Malformed post-4a850 FILE/name/source table")

        current: dict[int, tuple[object, object]] = {
            index: (metadata, source)
            for index, (metadata, source) in enumerate(
                zip(transform.raw_files, transform.raw_sources, strict=True)
            )
        }
        removed: set[int] = set()

        for ordinal, edge in enumerate(transform.edges):
            if type(edge) is not tuple or len(edge) != 10:
                raise ValueError("Exact Phase6 producer edge required")
            (
                issued_ordinal,
                left_slot,
                right_slot,
                left_metadata,
                right_metadata,
                result_metadata,
                left_name,
                left_source,
                right_name,
                right_source,
            ) = edge
            if (
                issued_ordinal != ordinal
                or type(left_slot) is not int
                or type(right_slot) is not int
                or not 0 <= left_slot < len(current)
                or not 0 <= right_slot < len(current)
                or left_slot == right_slot
                or left_slot in removed
                or right_slot in removed
                or current[left_slot][0] is not left_metadata
                or current[left_slot][1] is not left_source
                or transform.raw_files[right_slot] is not right_metadata
                or transform.raw_sources[right_slot] is not right_source
                or transform.raw_names[left_slot] != left_name
                or transform.raw_names[right_slot] != right_name
                or type(result_metadata.source_container)
                is not NativeCompositeSource2026
                or result_metadata.source_container.left is not left_metadata
                or result_metadata.source_container.right is not right_metadata
                or result_metadata.source_container.metadata is not result_metadata
            ):
                raise ValueError("Phase6 edge differs from its issued operands")
            native2026_validate_runtime_metadata(result_metadata)
            if result_metadata.source_sha256 != result_metadata.source_container.digest:
                raise ValueError("Phase6 composite digest is not source-issued")
            current[left_slot] = (result_metadata, result_metadata.source_container)
            removed.add(right_slot)

        expected_files = tuple(
            current[index][0] for index in current if index not in removed
        )
        expected_sources = tuple(
            current[index][1] for index in current if index not in removed
        )
        expected_names = tuple(
            transform.raw_names[index] for index in current if index not in removed
        )
        if (
            len(expected_files) != len(transform.post_4a850_files)
            or any(
                a is not b
                for a, b in zip(expected_files, transform.post_4a850_files, strict=True)
            )
            or any(
                a is not b
                for a, b in zip(
                    expected_sources, transform.post_4a850_sources, strict=True
                )
            )
            or expected_names != transform.post_4a850_names
        ):
            raise ValueError("Post-4a850 table is not the ordered edge result")

        reorder = transform.mapped_reorder
        if reorder is not None:
            if (
                type(reorder) is not _NativePhase6Reorder67c602026
                or reorder.post_4a850_files is not transform.post_4a850_files
                or reorder.post_4a850_names is not transform.post_4a850_names
                or reorder.post_4a850_sources is not transform.post_4a850_sources
                or len(reorder.post_67c60_files) != len(reorder.post_67c60_names)
                or len(reorder.post_67c60_files) != len(reorder.post_67c60_sources)
                or len(reorder.map_entries) != len(sources.delta_map_entries)
                or any(
                    left[0] is not right[0] or left[1] != right[1]
                    for left, right in zip(
                        reorder.map_entries, sources.delta_map_entries, strict=True
                    )
                )
            ):
                raise ValueError("Exact nested67c60 transform required")
            from scripts.calibration_2026 import native2026_node_values

            def row_key(metadata):
                node = native2026_node_values(metadata)
                return node.get("diagid", "") or node.get("logicaladdress", "")

            map_by_id = {
                id(member): group for member, group in sources.delta_map_entries
            }
            keys = []
            for metadata in transform.post_4a850_files:
                value = row_key(metadata)
                if (
                    metadata.vehicle.get("contacttype", "") == "Phase6"
                    and value in keys
                ):
                    keys.insert(keys.index(value), value)
                else:
                    keys.append(value)
            ordered = []
            consumed = set()
            for value in keys:
                anchor = None
                for ordinal, metadata in enumerate(transform.post_4a850_files):
                    if ordinal in consumed or row_key(metadata) != value:
                        continue
                    row = (
                        metadata,
                        transform.post_4a850_sources[ordinal],
                        transform.post_4a850_names[ordinal],
                    )
                    if (
                        anchor is not None
                        and metadata.vehicle.get("contacttype", "") == "Phase6"
                        and id(metadata) not in map_by_id
                    ):
                        position = next(
                            position
                            for position, existing in enumerate(ordered)
                            if existing[0] is anchor
                        )
                        ordered.insert(position, row)
                    else:
                        ordered.append(row)
                        if anchor is None:
                            anchor = metadata
                    consumed.add(ordinal)
            if len(ordered) != len(reorder.post_67c60_files) or any(
                expected[0] is not actual
                or expected[1] is not actual_source
                or expected[2] != actual_name
                for (expected, actual, actual_source, actual_name) in zip(
                    ordered,
                    reorder.post_67c60_files,
                    reorder.post_67c60_sources,
                    reorder.post_67c60_names,
                    strict=True,
                )
            ):
                raise ValueError("67c60 table is not the issued native reorder")
            select = reorder.second_select
            if (
                type(select) is not tuple
                or len(select) != 5
                or select[0] != 0
                or select[1] is not True
                or select[2] is not sources.selected_metadata
                or select[3] is not sources.selected_source
                or select[4] != sources.selected_name
            ):
                raise ValueError("Exact post-68190 second32ff0 selection required")
            if not any(
                (metadata is select[2] and source is select[3] and name == select[4])
                for metadata, source, name in zip(
                    reorder.post_67c60_files,
                    reorder.post_67c60_sources,
                    reorder.post_67c60_names,
                    strict=True,
                )
            ) and not any(
                (
                    select[2] is group[2]
                    and select[3] is group_source
                    and select[4] == group_name
                )
                for group, group_source, group_name in zip(
                    sources.delta_groups,
                    sources.delta_group_sources,
                    sources.delta_group_names,
                    strict=True,
                )
            ):
                raise ValueError("Mapped second selector has no issued source row")
            final_files = reorder.post_67c60_files
            final_names = reorder.post_67c60_names
            final_sources = reorder.post_67c60_sources
        else:
            final_files = transform.post_4a850_files
            final_names = transform.post_4a850_names
            final_sources = transform.post_4a850_sources
        if (
            len(final_files) != len(sources.files)
            or final_names != sources.file_names
            or any(
                expected is not actual
                for expected, actual in zip(final_files, sources.files, strict=True)
            )
            or any(
                expected is not actual
                for expected, actual in zip(
                    final_sources, sources.file_sources, strict=True
                )
            )
        ):
            raise ValueError("Final Phase6 table differs from the issued FILE set")
        if not any(
            self._wait_current_pointer_metadata2026 is item
            for item in transform.raw_files
        ) and not any(
            self._wait_current_pointer_metadata2026 is group[2]
            for group in sources.delta_groups
        ):
            raise ValueError("Initial Phase6 selector did not use its raw pointer")

    def _apply_phase6_transform_4a850_2026(
        self, transform, *, admission, sources
    ) -> None:
        """Publish the issued4a850 table, then its separate optional mapped tail."""
        from scripts.calibration_2026 import native2026_validate_phase6_pair

        self._validate_phase6_transform2026(transform, admission, sources)
        raw_pointer = self._wait_current_pointer_metadata2026
        pointer_slot = next(
            (
                index
                for index, metadata in enumerate(transform.raw_files)
                if metadata is raw_pointer
            ),
            None,
        )
        current_pointer = raw_pointer
        if pointer_slot is not None:
            for edge in transform.edges:
                if edge[1] == pointer_slot:
                    current_pointer = edge[5]
        self._wait_admission_stage2026 = (admission, transform, get_ident())
        if current_pointer is not raw_pointer:
            if (
                admission.table_stages.post_4a850.selected_metadata
                is not current_pointer
            ):
                raise ValueError(
                    "4a850 pointer successor differs from its issued stage"
                )
        elif admission.table_stages.post_4a850.selected_metadata is not raw_pointer:
            raise ValueError("4a850 preserved pointer differs from its issued stage")
        self._publish_cold_file_table_2026(
            admission.table_stages.post_4a850, admission=admission
        )

        reorder = transform.mapped_reorder
        if reorder is None:
            self._wait_admission_stage2026 = (admission, "phase6_complete", get_ident())
            return

        # 67c60 is a separate source publication; a later validation failure
        # intentionally retains the reached reordered table.
        self._publish_cold_file_table_2026(
            admission.table_stages.post_67c60, admission=admission
        )
        from scripts.calibration_2026 import native2026_node_values

        map_by_metadata = {
            id(metadata): group for metadata, group in reorder.map_entries
        }

        def phase6_key(metadata):
            node = native2026_node_values(metadata)
            return node.get("diagid", ""), node.get("logicaladdress", "")

        index = 0
        while index < len(reorder.post_67c60_files):
            anchor = reorder.post_67c60_files[index]
            key = phase6_key(anchor)
            if anchor.vehicle.get("contacttype", "") != "Phase6":
                index += 1
                continue
            candidates = []
            while (
                index < len(reorder.post_67c60_files)
                and phase6_key(reorder.post_67c60_files[index]) == key
            ):
                metadata = reorder.post_67c60_files[index]
                group_index = map_by_metadata.get(id(metadata))
                if group_index is None:
                    if candidates:
                        # 675e0 performs its map lookup for every row after
                        # the first candidate; preserve the native bounds
                        # failure instead of treating a second unmapped row
                        # as another direct candidate.
                        from scripts.programming_2026_common import (
                            NativeException2026,
                        )

                        raise NativeException2026("invalid map<K, T> key")
                    candidates.append(metadata)
                    index += 1
                    continue
                if not 0 <= group_index < len(sources.delta_groups):
                    raise ValueError("67c60 map references an unknown group")
                group_start, group_width, whole = sources.delta_groups[group_index]
                if (
                    group_width <= 0
                    or group_start < 0
                    or index + group_width > len(reorder.post_67c60_files)
                    or any(
                        map_by_metadata.get(
                            id(reorder.post_67c60_files[group_position])
                        )
                        != group_index
                        for group_position in range(index, index + group_width)
                    )
                ):
                    raise ValueError("67c60 group width differs from its table")
                candidates.append(whole)
                index += group_width
            for left_index, left in enumerate(candidates):
                for right in candidates[left_index + 1 :]:
                    try:
                        native2026_validate_phase6_pair(left, right)
                    except ValueError as error:
                        if str(error).startswith("Not combinable:"):
                            from scripts.programming_2026_common import (
                                NativeException2026,
                            )

                            raise NativeException2026("Not combinable.") from error
                        raise

        _, _, selected, _, _ = reorder.second_select
        step = next(
            (
                item
                for item in admission.steps
                if item.operation == "32ff0" and item.slot == 0 and item.value is True
            ),
            None,
        )
        if step is None or selected is not sources.selected_metadata:
            raise ValueError("Mapped Phase6 lacks its issued second32ff0 source point")
        self._phase6_second_select2026 = (admission, transform, get_ident())
        self._wait_admission_stage2026 = (admission, transform, get_ident())
        if selected is not admission.table_stages.final.selected_metadata:
            raise ValueError("Second32ff0 pointer differs from final table stage")
        self._publish_cold_file_table_2026(
            admission.table_stages.final, admission=admission
        )
        try:
            self._wait_timing_source_step_41940_2026(
                admission, selected, point="phase6_second32ff0"
            )
            self._complete_cold_32ff0_query_cid_copy2026(
                admission,
                step,
                admission.table_stages.final,
                selected,
            )
        finally:
            self._phase6_second_select2026 = None
        self._wait_current_igoffon2026 = self._wait_igoffon_by_file2026[0]
        self._wait_current_battery_disconnected2026 = (
            self._wait_battery_disconnected_by_file2026[0]
        )
        self._wait_current_battery_connected2026 = (
            self._wait_battery_connected_by_file2026[0]
        )
        self._wait_admission_stage2026 = (admission, "phase6_complete", get_ident())

    def _initial_getter_reset_cold2026(self) -> bool:
        """Recognize only a source-pristine34050 entry under the engine lock."""
        pending_reset = self._pending_initial_getter_reset2026
        if (
            type(self._initial_getter_reset_epoch2026) is not int
            or self._initial_getter_reset_epoch2026 < 0
            or self._initial_getter_reset_binding2026 is not None
            or (
                pending_reset is not None
                and (
                    type(pending_reset) is not _InitialGetterReset40580_2026
                    or pending_reset.engine is not self
                    or type(pending_reset.epoch) is not int
                    or pending_reset.epoch <= 0
                    or pending_reset.epoch != self._initial_getter_reset_epoch2026
                )
            )
        ):
            return False
        if (
            self._source is not None
            or self._metadata is not None
            or self._large_container is not None
            or self._owned_large_containers
            or self._owned_usb_sources
            or self._dh_state is not None
            or self._suzuki_state is not None
            or self._worker is not None
            or self._thread_job is not None
            or self._worker_replacement_thread is not None
            or self._controller_execution is not None
            or self._active
            or self._phase_thread is not None
            or not self._phase_finished.is_set()
            or self._cancelled.is_set()
            or self._interface_pair is not None
            or self._retry_controller is not None
            or self._controller_export_target2026 is not None
            or self._file_sources is not None
            or self._native_delta_active
            or self._cleanup_controller is not None
            or self._cleanup_retired_dh_state is not None
            or self._gateway_startup is not None
            or self._online_controller is not None
            or self._online_modal_state != 0
            or self._pending_file_admission_origin2026 is not None
            or self._file_admission_owner_thread2026 is not None
            or self._pending_getter_stop_origin2026 is not None
            or self._persistence_cpu_transition2026 is not None
            or self._persistence_file_flow_transition2026 is not None
            or self._worker_target_sources
            or self._pending_worker_cid_selection is not None
            or self._prepare_prefix_owner is not None
            or self._prepare_prefix_vbf_request2026 is not None
            or self._issued_sil_transfer is not None
            or self._vin
            or self._shrink_flag
            or self._rks_configuration is not None
            or self._identifier_records
            or self._received_identifiers
            or self._received_hardware
            or self._working_hardware
            or self._identifier_context_epoch != 0
            or self._identifier_context_importing
            or self._native_control_context2026 is not None
            or self._last_completed_standalone_getter is not None
            or self._working_identifier_records
            or self._working_contact_buffer != bytes(33)
            or self._diagnostic_context != 0
            or self._file_read_region != 0
            or self._file_logger is not None
            or self._cid_selection_initialized
            or self._repro_gateway_node != 0
            or self._gateway_classifier_cache != 0
            or self._ssmid_cache2026 != 0
            or self._dh_type_cache2026 != 0
            or self._control_retry_cache2026
            or self._control_phase_cache2026 != 2
            or self._control_alternate_cache2026
            or self._control_divided_index_cache2026 != 0
            or self._native_error_output != (0, 0)
            or self._native_fatal_output
            or self._native_control_fatal_output
            or self._write_complete_output
            or self._native_cycle_output
            or self._continuation_backup is not None
            or self._native_prepare_handshake != 0
            or self._logical_block_index != 0
            or self._native_error_kind_output != 0
            or self._native_previous_error_kind_output != 0
            or self._worker_phase is not None
        ):
            return False
        persistence = self._persistence
        if persistence is not None:
            from scripts.cuw_persistence import CUWPersistence, ReproInfoState

            if (
                type(persistence) is not CUWPersistence
                or self.persistence is not persistence
            ):
                return False
            persistence.validate_engine_owner(self)
            if (
                persistence._cleanup_lease is not None
                or persistence._cleanup_assignment is not None
                or type(persistence.state) is not ReproInfoState
                or not CUWPersistence._same_cleanup_fields(
                    persistence.state, ReproInfoState(())
                )
            ):
                return False
        return True

    def _validate_initial_getter_reset_40580_2026(
        self, origin: object, *, worker: EngineWorker2026
    ) -> int:
        """Read-only check for the lexical, unpublished first-worker projection."""
        from scripts.cuw_engine_worker import EngineWorker2026
        from scripts.programming_2026_common import (
            CommonDefinitions2026,
            NativeFrontendParameters2026,
        )

        if type(origin) is not _InitialGetterReset40580_2026:
            raise TypeError("Exact source-issued initial getter reset required")
        binding = self._initial_getter_reset_binding2026
        if (
            self._pending_initial_getter_reset2026 is not origin
            or self._initial_getter_reset_epoch2026 != origin.epoch
            or type(origin.epoch) is not int
            or origin.epoch <= 0
            or origin.engine is not self
            or origin.common_definitions is not self.common_definitions
            or type(self.common_definitions) is not CommonDefinitions2026
            or type(worker) is not EngineWorker2026
            or binding is None
            or binding[0] is not origin
            or binding[1] is not worker
            or binding[2] != get_ident()
            or self._worker is not None
            or worker._engine is not self
            or self._thread_job is not None
            or self._worker_replacement_thread is not None
            or self._active
            or self._phase_thread is not None
            or type(origin.parameters) is not NativeFrontendParameters2026
            or type(self._frontend_parameters) is not NativeFrontendParameters2026
            or self._general_parameters != self._frontend_parameters.general
        ):
            raise ValueError("Exact lexical first-bind initial reset required")
        origin.parameters.validate_source()
        self._frontend_parameters.validate_source()
        if type(origin.maximum) is not int or origin.maximum < 0:
            raise ValueError("Captured historical getter capacity is invalid")
        if origin.configuration is None:
            if origin.maximum != 0:
                raise ValueError("Unconfigured initial reset must retain M0")
        elif (
            type(origin.configuration) is not EngineConfiguration2026
            or type(origin.maximum) is not int
            or origin.maximum < 0
            or len(origin.configuration.arguments) != 32
            or origin.configuration.cpu_maximum != origin.maximum
            or struct.unpack_from("<I", origin.configuration.arguments)[0]
            != origin.maximum
        ):
            raise ValueError("Historical configured getter capacity is invalid")
        configuration = self.configuration
        maximum = self.common_definitions.num_cpu_maxnum
        if configuration is None:
            if maximum != 0:
                raise ValueError("Current unconfigured CommonDefinitions must be M0")
        elif (
            type(configuration) is not EngineConfiguration2026
            or configuration.cpu_maximum != maximum
            or len(configuration.arguments) != 32
            or struct.unpack_from("<I", configuration.arguments)[0] != maximum
        ):
            raise ValueError("Current configured getter capacity is inconsistent")
        if self._metadata is None:
            raise ValueError("Loaded native source is required for initial worker bind")
        worker.validate_source(self)
        if self._persistence is not None:
            self._validate_persistence_source(self._metadata)
        return origin.maximum

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
        old_source_state = old.source_state
        old_flow_index = old._flow_file_index2026
        old_metadata = self.native_metadata
        old_sources = self._file_sources
        old_persistence = self._persistence
        old_state = None if old_persistence is None else old_persistence.state
        old_persisted_cpu = None if old_state is None else old_state.write_cpu_index
        old_persisted_file = (
            None if old_state is None else old_state.calibration_file_index
        )
        # A reissue cannot repair an already-invalid native/persistence pair.
        self._validate_persistence_source(self.native_metadata)
        cpu_proof = self._persistence_cpu_transition2026
        file_proof = self._persistence_file_flow_transition2026
        cpu_proof_valid = (
            bool(
                cpu_proof is not None
                and self._persistence_cpu_transition_valid2026(
                    self.native_metadata,
                    self._persistence.state,
                    self._file_sources,
                    old.source_state.current_global_cpu_index,
                )
            )
            if self._persistence is not None
            else False
        )
        file_proof_valid = (
            bool(
                file_proof is not None
                and self._persistence_file_flow_transition_valid2026(
                    self._persistence.state,
                    self._file_sources,
                    old._flow_file_index2026,
                )
            )
            if self._persistence is not None
            else False
        )
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
            if (
                replacement._file_sources is not old_sources
                or self._file_sources is not old_sources
            ):
                raise ValueError("Worker reissue changed the issued FILE source set")
            if replacement._flow_file_index2026 != old_flow_index:
                raise ValueError("Worker reissue changed native D71C flow")
            if (
                replacement.source_state.current_global_cpu_index
                != old_source_state.current_global_cpu_index
            ):
                raise ValueError("Worker reissue changed native CPU selection")
            if self.native_metadata is not old_metadata:
                raise ValueError("Worker reissue changed engine metadata")
            if (
                self._persistence is not old_persistence
                or (
                    old_persistence is not None
                    and old_persistence.state is not old_state
                )
                or (
                    old_state is not None
                    and old_state.write_cpu_index != old_persisted_cpu
                )
                or (
                    old_state is not None
                    and old_state.calibration_file_index != old_persisted_file
                )
            ):
                raise ValueError(
                    "Worker reissue changed persistence identity or values"
                )
            if cpu_proof_valid and cpu_proof is not None:
                assert self._persistence is not None
                self._persistence_cpu_transition2026 = replace(
                    cpu_proof, worker=replacement
                )
                if not self._persistence_cpu_transition_valid2026(
                    self.native_metadata,
                    self._persistence.state,
                    self._file_sources,
                    replacement.source_state.current_global_cpu_index,
                ):
                    raise ValueError("CPU witness successor did not validate")
            else:
                self._persistence_cpu_transition2026 = None
            if file_proof_valid and file_proof is not None:
                assert self._persistence is not None
                self._persistence_file_flow_transition2026 = replace(
                    file_proof, worker=replacement
                )
                if not self._persistence_file_flow_transition_valid2026(
                    self._persistence.state,
                    self._file_sources,
                    replacement._flow_file_index2026,
                ):
                    raise ValueError("FILE witness successor did not validate")
            else:
                self._persistence_file_flow_transition2026 = None
            self._validate_persistence_source(self.native_metadata)
            _finalize_engine_worker_replacement(self, old, replacement)
            return job
        except BaseException as error:
            self._thread_job = old_job
            self._persistence_cpu_transition2026 = cpu_proof
            self._persistence_file_flow_transition2026 = file_proof
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
            self._reject_failed_cold_file_admission2026()
            if self._interface_pair is not None:
                self._interface_pair.validate_views()
                if self._interface_pair.control is not controller.runtime_device():
                    raise ValueError(
                        "Bound pair control differs from the actual controller"
                    )
            previous_worker = self._worker
            if previous_worker is not None:
                previous_worker.validate_source(self)
                return _issue_engine_worker(self, controller)
            if (
                self._active
                or self._thread_job is not None
                or self._worker_replacement_thread is not None
                or self._pending_file_admission_origin2026 is not None
            ):
                raise ValueError("Idle first worker binding required")
            persistence = self._persistence
            state = None if persistence is None else persistence.state
            sources = self._file_sources
            if persistence is not None:
                self._validate_persistence_source(self.native_metadata)
            worker = _issue_engine_worker(self, controller)
            old_cpu = self._persistence_cpu_transition2026
            old_file = self._persistence_file_flow_transition2026
            old_cleanup = self._cleanup_controller
            old_admission = self._pending_file_admission_origin2026
            old_admission_thread = self._file_admission_owner_thread2026
            initial_reset = self._pending_initial_getter_reset2026
            try:
                if initial_reset is not None:
                    self._initial_getter_reset_binding2026 = (
                        initial_reset,
                        worker,
                        get_ident(),
                    )
                    try:
                        worker._apply_initial_getter_reset_40580_2026(initial_reset)
                    finally:
                        self._initial_getter_reset_binding2026 = None
                self._worker = worker
                worker.validate_source(self)
                if persistence is not None and sources is not None:
                    assert state is not None
                    persisted_index = state.calibration_file_index
                    if persisted_index != 0:
                        flow_view = (
                            sources.file_view2026(0)
                            if sources.has_file_vector
                            else sources.admission_view2026()
                        )
                        pointer_view = sources.admission_view2026()
                        self._pending_file_admission_origin2026 = (
                            _FileAdmissionOrigin2026(
                                self,
                                worker,
                                persistence,
                                state,
                                sources,
                                pointer_view,
                                flow_view,
                                self.native_metadata.source_container,
                                self.native_metadata.source_sha256,
                                get_ident(),
                            )
                        )
                        self._file_admission_owner_thread2026 = get_ident()
                        self._record_file_flow_transition2026(
                            worker=worker,
                            origin=self._pending_file_admission_origin2026,
                            producer="43cd0-admission",
                            old_sources=sources,
                            new_sources=sources,
                            before_flow=0,
                            after_flow=0,
                            flow_view=flow_view,
                            current_pointer_view=pointer_view,
                        )
                if persistence is not None:
                    self._validate_persistence_source(self.native_metadata)
                if self._cleanup_controller is None:
                    from scripts.cuw_engine_cleanup import _issue_engine_cleanup

                    self._cleanup_controller = _issue_engine_cleanup(self, worker)
                if old_admission is None:
                    self._file_admission_owner_thread2026 = None
                if initial_reset is not None:
                    if self._pending_initial_getter_reset2026 is not initial_reset:
                        raise ValueError("Initial getter reset origin changed in bind")
                    self._pending_initial_getter_reset2026 = None
                return worker
            except BaseException:
                self._initial_getter_reset_binding2026 = None
                self._pending_file_admission_origin2026 = old_admission
                self._file_admission_owner_thread2026 = old_admission_thread
                self._persistence_cpu_transition2026 = old_cpu
                self._persistence_file_flow_transition2026 = old_file
                self._worker = None
                self._cleanup_controller = old_cleanup
                worker.close()
                raise
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
    def family_metadata(self):
        """Metadata projected by the currently scoped native CONTROL export."""
        target = self._controller_export_target2026
        if target is None:
            return self.native_metadata
        controller = self._controller_execution
        if controller is None:
            raise ValueError("Native CONTROL export scope has expired")
        target.validate(self, controller)
        self._require_owned_phase()
        return target.metadata

    @property
    def family_source_container(self):
        return self.family_metadata.source_container

    @property
    def family_cpu_index(self) -> int:
        target = self._controller_export_target2026
        if target is None:
            from scripts.calibration_2026 import native2026_global_cpu_index

            return native2026_global_cpu_index(self.native_metadata)
        _ = self.family_metadata
        return target.cpu_index

    @property
    def family_target_index(self) -> int:
        target = self._controller_export_target2026
        if target is None:
            return self.native_writer_target_index
        _ = self.family_metadata
        return target.target_index

    @contextmanager
    def controller_export_target(self, controller, target):
        """Scope one authentic CONTROL target to its current owned export thread."""
        from scripts.programming_2026_common import (
            ControlCommPhase2026,
            NativeControlExportTarget2026,
        )

        if (
            type(controller) is not ControlCommPhase2026
            or controller is not self._controller_execution
            or type(target) is not NativeControlExportTarget2026
        ):
            raise ValueError("Actual controller and issued CONTROL target required")
        self._require_owned_phase()
        target.validate(self, controller)
        if self._controller_export_target2026 is not None:
            raise ValueError("Nested native CONTROL target scopes are forbidden")
        self._controller_export_target2026 = target
        try:
            yield target
        finally:
            if self._controller_export_target2026 is not target:
                self._controller_export_target2026 = None
                raise ValueError("Native CONTROL target scope ownership changed")
            self._controller_export_target2026 = None

    def _record_getter_protocol_ingress2026(self, stage) -> None:
        """Record the exact native raw CONTROL export's4fc write footprint."""
        from scripts import programming_2026_common
        from scripts.cuw_engine_worker import EngineWorker2026
        from scripts.programming_2026_common import (
            ControlCommPhase2026,
            NativeControlExportTarget2026,
        )
        from scripts.programming_replay import ProgrammingReplay

        if type(stage) is not ProgrammingReplay:
            raise TypeError("Concrete bound CONTROL replay stage required")
        controller = stage._controller2026
        target = stage._control_target2026
        export = stage._control_export2026
        if (
            stage._engine2026 is not self
            or type(controller) is not ControlCommPhase2026
            or type(target) is not NativeControlExportTarget2026
            or type(export) is not str
            or not self._active
            or self._phase_thread != get_ident()
            or self._controller_execution is not controller
            or self._controller_export_target2026 is not target
        ):
            raise ValueError("Active source-issued CONTROL export stage required")
        worker = self.worker
        if (
            type(worker) is not EngineWorker2026
            or worker.controller is not controller
            or controller.native_control_context2026(self) is not target._context
        ):
            raise ValueError("Current native CONTROL worker and target required")
        dispatch = programming_2026_common._control_export_dispatch2026(target, export)
        lease = controller._native_control_export_lease2026
        record = programming_2026_common._NATIVE_CONTROL_HELPER_LEASES_2026.get(
            id(lease)
        )
        if (
            lease is None
            or record is None
            or record[0] is not lease
            or record[1]["stage"] is not stage
            or record[1]["target"] is not target
            or record[1]["engine"] is not self
            or record[1]["controller"] is not controller
            or record[1]["export"] != export
            or dispatch["module"] != target.module_binding.module_name
        ):
            raise ValueError("Registered active raw CONTROL export lease required")
        if (
            export == "StartGetCID"
            and record[1]["helper"] == "6f20"
            and record[1]["module"] == "TCUWCanCIDGetter.dll"
            and record[1]["identity"].sha256
            == "3b0527a86cc74a3d1c6c686d39f71a8424cce699871a48c5454f8c315e2a89b6"
            and target.binding.operation == "get_cid"
        ):
            return
        self._getter_protocol_4fc_2026 = None

    def _record_getter_protocol_recovery_389c0_2026(self, persistence) -> None:
        """Invalidate4fc only at the accepted loaded-recovery source commit."""
        from scripts.cuw_persistence import CUWPersistence, ReproInfoState

        if (
            type(persistence) is not CUWPersistence
            or self._persistence is not persistence
            or self._metadata is None
        ):
            raise ValueError("Accepted engine-bound recovery source required")
        persistence.validate_engine_owner(self)
        state = persistence.state
        if type(state) is not ReproInfoState:
            raise TypeError("Concrete bound recovery state required")
        state.validate()
        if state.loaded:
            self._validate_persistence_source(self._metadata)
            self._getter_protocol_4fc_2026 = None

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
        self._invalidate_persistence_cpu_transition2026()
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
        index = worker._current_file_index
        masks = worker._getter_configured_masks_4f0_2026
        flow_cids = worker._getter_flow_received_cids2026
        flow_records = worker._getter_flow_query_records2026
        if (
            type(index) is not int
            or not 0 <= index < 16
            or type(masks) is not tuple
            or len(masks) != 16
            or type(masks[index]) is not tuple
            or len(masks[index]) != self.configuration.cpu_maximum
            or any(type(value) is not bool for value in masks[index])
            or type(flow_cids) is not tuple
            or type(flow_records) is not tuple
            or len(flow_cids) != 16
            or len(flow_records) != 16
            or any(type(value) is not tuple for value in flow_cids)
            or any(type(value) is not tuple for value in flow_records)
            or type(self.received_identifiers) is not tuple
        ):
            raise ValueError("Exact native matcher vectors required")
        sources = self._file_sources
        configured_metadata = self.native_metadata
        if sources is not None and sources.has_file_vector:
            from scripts.cuw_file_services import validate_file_sources_2026

            validate_file_sources_2026(sources, self)
            if (
                not 0 <= index < len(sources.files)
                or worker._file_sources is not sources
            ):
                raise ValueError("Actual indexed34e10 FILE source required")
            table_metadata = sources.files[index]
            loaded_metadata = worker._all_loaded_metadata[index]
            loaded_is_table_file = (
                loaded_metadata.source_container is table_metadata.source_container
                and loaded_metadata.source_sha256 == table_metadata.source_sha256
            )
            if not loaded_is_table_file:
                from scripts.cuw_file_services import validate_file_view_2026

                pointer_view = worker._capture_pointer_view2026(self.native_metadata)
                if (
                    pointer_view is None
                    or pointer_view.kind != "whole"
                    or pointer_view.file_index != index
                    or loaded_metadata.source_container
                    is not pointer_view.source_container
                    or loaded_metadata.source_sha256 != pointer_view.source_sha256
                ):
                    raise ValueError("Actual indexed34e10 FILE source required")
                validate_file_view_2026(pointer_view, sources)
            configured_metadata = self._worker_target_sources.get(
                id(table_metadata.source_container), table_metadata
            )
            if (
                configured_metadata.source_container
                is not table_metadata.source_container
                or configured_metadata.source_sha256 != table_metadata.source_sha256
            ):
                raise ValueError("Indexed4b0f0 metadata differs from its FILE source")
            selected_cids = flow_cids[index]
            selected_records = flow_records[index]
        elif worker._file_sources is not sources:
            raise ValueError("Current worker FILE source set differs from engine")
        else:
            # Per-FILE caches serve named tables. Current-only34e10 consumes
            # the live global reception vectors instead.
            selected_cids = self.received_identifiers
            selected_records = self.identifier_records
        if (
            type(selected_cids) is not tuple
            or type(selected_records) is not tuple
            or len(selected_cids) != len(selected_records)
            or any(
                type(value) is not bytes or b"\0" in value for value in selected_cids
            )
            or any(
                type(value) is not bytes or len(value) != 12 or b"\0" not in value[4:]
                for value in selected_records
            )
        ):
            raise ValueError("Exact selected34e10 reception vectors required")
        self._cid_selection_initialized = True
        result = native2026_match_received_cids(
            self.native_metadata,
            selected_cids,
            selected_records,
            self._general_parameters,
            configuration=self.configuration,
            shrink_flag=self.shrink_flag,
            received_hardware=self.received_hardware,
            configured_cpu_flags=masks[index],
            live_received_identifiers=self.received_identifiers,
            configured_metadata=configured_metadata,
        )
        if not result.check_target:
            self._pending_worker_cid_selection = None
            return result
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
        self._invalidate_persistence_cpu_transition2026()
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
        from scripts.calibration_2026 import (
            NativeCPUSelection2026,
            native2026_metadata_for_cpu,
        )

        owned_phase = self._active and self._phase_thread == get_ident()
        prefix_owner = self._prepare_prefix_owner == (
            get_ident(),
            worker,
            self._thread_job,
        )
        external_prefix = (
            prefix_owner and self._prepare_prefix_vbf_cpu_origin2026 is not None
        )
        if external_prefix:
            owned_phase = False
        if not owned_phase and not (
            prefix_owner and self._prepare_prefix_vbf_cpu_origin2026 is not None
        ):
            self._require_owned_phase()
        if not owned_phase:
            from scripts.cuw_engine_threads import (
                _vbf_record,
                _VbfCPUSuccessorOrigin2026,
            )

            job = self._thread_job
            origin = self._prepare_prefix_vbf_cpu_origin2026
            vbf_record = (
                _vbf_record(origin.request)
                if type(origin) is _VbfCPUSuccessorOrigin2026
                else None
            )
            if (
                job is None
                or origin is None
                or type(origin) is not _VbfCPUSuccessorOrigin2026
                or vbf_record is None
                or vbf_record is not origin.record
                or vbf_record.cpu_successor_origin is not origin
                or vbf_record.cpu_engine_store is not None
                or vbf_record.cpu_successor is not None
                or origin.request is not self._prepare_prefix_vbf_request2026
                or origin.job is not job
                or origin.engine is not self
                or origin.controller is not job.controller
                or origin.worker is not worker
                or origin.issuer_thread != get_ident()
                or origin.after_global_cpu != index
                or origin.before_global_cpu != 0
                or origin.d30c != index
                or origin.parked_metadata is not self.native_metadata
                or origin.source_container is not self.native_metadata.source_container
                or origin.source_digest != self.native_metadata.source_sha256
                or origin.source_node != self.native_metadata.node
                or origin.before_metadata_cpu_index != self.native_metadata.cpu_index
                or origin.after_metadata_cpu_index
                != origin.projected_metadata.cpu_index
                or origin.file_sources is not self._file_sources
                or origin.parked_file_index != worker._current_file_index
                or origin.received_identifiers
                != worker._identifiers_for_file(origin.parked_file_index)
            ):
                raise ValueError("Exact external VBF CPU successor required")
            canonical_projection = native2026_metadata_for_cpu(
                self.native_metadata, index
            )
            if (
                origin.projected_metadata != canonical_projection
                or origin.projected_metadata.source_container
                is not self.native_metadata.source_container
            ):
                raise ValueError("Canonical external VBF CPU projection required")
        if worker is not self.worker or self._worker_phase not in (1, 2):
            raise ValueError("Actual preparing worker required for CPU offset")
        if not owned_phase and self._worker_phase != 1:
            raise ValueError("External VBF FULL36800 tail requires phase1")
        source = worker.source_state
        if (
            type(index) is not int
            or source.current_global_cpu_index != 0
            or index != source.cpu_offset
        ):
            raise ValueError("Native zero-current CPU and issued D30C offset required")
        metadata = (
            origin.projected_metadata
            if not owned_phase
            else native2026_metadata_for_cpu(self.native_metadata, index)
        )
        persistence = self._persistence
        persisted_cpu = None
        before_cpu = source.current_global_cpu_index
        if persistence is not None:
            self._validate_persistence_source(self.native_metadata)
            persisted_cpu = persistence.state.write_cpu_index
            if not owned_phase and (
                origin.persistence is not persistence
                or origin.persistence_state is not persistence.state
                or origin.persisted_cpu != persisted_cpu
            ):
                raise ValueError("Exact parked VBF persistence snapshot required")
        elif not owned_phase and (
            origin.persistence is not None
            or origin.persistence_state is not None
            or origin.persisted_cpu is not None
        ):
            raise ValueError("Parked VBF persistence identity changed")
        if not owned_phase and (
            source.current_global_cpu_index != origin.before_global_cpu
            or source.cpu_offset != origin.d30c
            or self.dh_state.global_cpu_index != origin.before_global_cpu
            or self.suzuki_state.global_cpu_index != origin.before_global_cpu
            or self.dh_state.selection_cpu_index != origin.before_selection_cpu_index
            or self.suzuki_state.selection_cpu_index
            != origin.before_selection_cpu_index
            or worker._current_file_index != origin.parked_file_index
            or worker._selections_by_file[origin.parked_file_index]
            is not origin.retained_selection
            or worker._selection_rebuild_pending is not origin.pending_selection
            or (
                origin.pending_selection is not None
                and (
                    type(origin.pending_selection) is not NativeCPUSelection2026
                    or origin.pending_selection.rebuilt_metadata
                    is not origin.parked_metadata
                    or origin.pending_selection.cpu_offset != origin.d30c
                )
            )
        ):
            raise ValueError("Exact parked VBF CPU source state required")
        self._invalidate_persistence_cpu_transition2026()
        self._metadata = metadata
        self._worker_target_sources[id(metadata.source_container)] = metadata
        for state in (self.dh_state, self.suzuki_state):
            state.metadata = metadata
            state.source_sha256 = metadata.source_sha256
            state.node, state.selection_cpu_index = metadata.node, metadata.cpu_index
            state.cpu_index = state.global_cpu_index = index
        self.dh_state._dh_flash_size = None
        self._issued_sil_transfer = None
        if not owned_phase and persistence is not None:
            assert persisted_cpu is not None and origin is not None
            if persisted_cpu != index:
                self._issue_persistence_cpu_transition2026(
                    producer="vbf-prefix",
                    origin=origin.request,
                    metadata=metadata,
                    persisted_cpu=persisted_cpu,
                    before_cpu=before_cpu,
                    after_cpu=index,
                )
        if not owned_phase:
            job._record_vbf_cpu_store_36800_2026(origin, worker=worker)

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
            self._invalidate_persistence_cpu_transition2026()
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
        from scripts.cuw_engine_threads import _NativeGetterStopReceipt2026

        self._validate_cleanup_controller(cleanup)
        with self._phase_state_lock:
            if self._active and self._phase_thread == get_ident():
                raise ValueError("Native worker cannot join itself during cleanup")
        while True:
            runtime = cleanup.worker.runtime
            runtime.check()
            job = self._thread_job
            acquired = False
            receipt = None
            terminal_without_receipt = False
            try:
                if job is not None:
                    acquired = job._lock.acquire(timeout=runtime.check())
                    if not acquired:
                        continue
                with self._phase_state_lock:
                    if job is not self._thread_job:
                        continue
                    if self._active and self._phase_thread == get_ident():
                        raise ValueError(
                            "Native worker cannot join itself during cleanup"
                        )
                    finished = self._phase_finished
                    self._validate_cleanup_controller(cleanup)
                    if job is not None:
                        from scripts.cuw_engine_threads import EngineThreadJob2026

                        if type(job) is not EngineThreadJob2026:
                            raise TypeError("Concrete native thread job required")
                        job._reject_self_join()
                    if job is not None and job.native_worker_exists:
                        job.validate_owner(self, cleanup.worker.controller)
                        job.worker.validate_source(self)
                        receipt = job._getter_stop_receipt2026
                        if receipt is not None and (
                            type(receipt) is not _NativeGetterStopReceipt2026
                            or receipt.producer != "40580"
                            or receipt.job is not job
                            or receipt.worker is not job.worker
                            or receipt.controller is not job.controller
                            or getattr(receipt.origin, "cleanup", None) is not cleanup
                        ):
                            raise ValueError("Retained cleanup stop receipt is foreign")
                        record = job._completion_records.get(job._sequence)
                        outer = job._outer
                        child = job._child
                        child_terminal = (
                            child is None and job._child_exit is None
                        ) or (
                            child is not None
                            and not child.is_alive()
                            and type(job._child_exit) is int
                            and job._child_exit in (0, 1)
                        )
                        terminal = (
                            job._stop
                            and outer is not None
                            and not outer.is_alive()
                            and type(job._outer_exit) is int
                            and job._outer_exit in (0, 1)
                            and job._lease is None
                            and job._sequence > 0
                            and record is not None
                            and record.sequence == job._sequence
                            and job._active_record is record
                            and record.completed.is_set()
                            and job._completed.is_set()
                            and child_terminal
                            and not self._active
                            and self._phase_thread is None
                            and finished.is_set()
                            and self._pending_getter_stop_origin2026 is None
                        )
                        if terminal:
                            self._cancelled.set()
                            terminal_without_receipt = receipt is None
                            break
                        if job._host_stop:
                            raise ValueError("Host-stopped cleanup tuple is partial")
                        if (
                            job._child is None
                            or self._worker is not job.worker
                            or job.worker.controller is not job.controller
                            or job._host_stop
                            or job._outer is None
                            or not job._outer.is_alive()
                            or job._outer_exit is not None
                        ):
                            raise ValueError("Cleanup stop source tuple is stale")
                        if receipt is None:
                            if self._pending_getter_stop_origin2026 is not None:
                                raise ValueError(
                                    "Getter stop origin is already pending"
                                )
                            origin = _NativeGetterStopOrigin2026(
                                self,
                                job,
                                job.worker,
                                job.controller,
                                job._native_start_generation2026,
                                job._sequence,
                                job._lease,
                                get_ident(),
                                "40580",
                                cleanup,
                            )
                            self._pending_getter_stop_origin2026 = origin
                            try:
                                receipt = job._record_getter_stop_14_2026(
                                    producer="40580", origin=origin
                                )
                            finally:
                                if self._pending_getter_stop_origin2026 is origin:
                                    self._pending_getter_stop_origin2026 = None
                        else:
                            job._validate_getter_stop_stage2026(receipt)
                    self._cancelled.set()
                    break
            finally:
                if acquired and job is not None:
                    job._lock.release()
        runtime = cleanup.worker.runtime
        if job is not None and receipt is not None:
            child = job._request_getter_child_stop_2026(receipt)
            while True:
                runtime.check()
                if not child.is_alive():
                    break
                child.join(min(0.05, runtime.check()))
            runtime.check()
            outer, publish_event = job._request_getter_outer_stop_2026(receipt)
            if publish_event:
                self._publish_getter_stop_event_2026(job, receipt)
            while True:
                runtime.check()
                if not outer.is_alive():
                    break
                outer.join(min(0.05, runtime.check()))
            runtime.check()
            self._complete_getter_stop_2026(job, receipt)
        elif job is not None and terminal_without_receipt:
            job.stop_native(timeout=min(0.05, runtime.check()))
        while not finished.wait(min(0.05, runtime.check())):
            pass
        runtime.check()

    def _consume_getter_stop_origin2026(
        self, origin: object, *, job, producer: str
    ) -> None:
        """Consume the exact lexical5f030/40580 origin under its held locks."""
        from scripts.cuw_engine_cleanup import EngineCleanup2026
        from scripts.cuw_engine_threads import (
            EngineThreadJob2026,
            ThreadPhaseLease2026,
        )
        from scripts.cuw_engine_worker import EngineWorker2026
        from scripts.programming_2026_common import ControlCommPhase2026

        if type(origin) is not _NativeGetterStopOrigin2026:
            raise TypeError("Concrete lexical getter-stop origin required")
        if producer not in ("5f030", "40580"):
            raise ValueError("Unsupported native getter-stop producer")
        if (
            self._pending_getter_stop_origin2026 is not origin
            or origin.engine is not self
            or origin.job is not job
            or origin.producer != producer
            or origin.issuer_thread != get_ident()
            or type(job) is not EngineThreadJob2026
            or type(origin.worker) is not EngineWorker2026
            or type(origin.controller) is not ControlCommPhase2026
            or job is not self._thread_job
            or job.worker is not origin.worker
            or job.controller is not origin.controller
            or self._worker is not origin.worker
            or origin.worker.engine is not self
            or origin.worker.controller is not origin.controller
            or origin.generation is None
            or origin.generation is not job._native_start_generation2026
            or job._host_stop
            or job._outer is None
            or not job._outer.is_alive()
            or job._outer_exit is not None
            or job._sequence != origin.sequence
            or job._lease is not origin.lease
        ):
            raise ValueError("Getter-stop origin no longer owns the current CStart")
        job.validate_owner(self, origin.controller)
        origin.worker.validate_source(self)
        if producer == "5f030" and self.native_phase != 0:
            raise ValueError("5f030 getter-stop origin requires native phase zero")
        if producer == "40580":
            if type(origin.cleanup) is not EngineCleanup2026:
                raise ValueError("40580 getter-stop origin requires exact cleanup")
            self._validate_cleanup_controller(origin.cleanup)
            if origin.cleanup.worker is not origin.worker:
                raise ValueError("Cleanup stop origin belongs to another worker")
        elif origin.cleanup is not None:
            raise ValueError("5f030 getter-stop origin cannot carry cleanup")

        lease = origin.lease
        if lease is not None:
            if type(lease) is not ThreadPhaseLease2026:
                raise TypeError("Concrete thread-phase lease required")
            job._validate_getter_stop_lease2026(lease, origin.sequence, producer)
        else:
            record = job._completion_records.get(origin.sequence)
            if (
                origin.sequence < 0
                or (origin.sequence == 0 and record is not None)
                or (origin.sequence > 0 and record is not job._active_record)
            ):
                raise ValueError("Idle getter-stop origin lost its CStart sequence")
        self._pending_getter_stop_origin2026 = None

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
        self._invalidate_persistence_cpu_transition2026()
        self._invalidate_persistence_file_flow_transition2026()
        self._pending_file_admission_origin2026 = None
        self._file_admission_owner_thread2026 = None
        self._cleanup_retired_dh_state = self._dh_state
        self._metadata = self._source = self._dh_state = self._suzuki_state = None
        self._pending_worker_cid_selection = None
        self._last_completed_standalone_getter = None

    def _apply_cleanup_globals(self, cleanup) -> None:
        """40580 source defaults are(4,0,0,0) at authenticatedRVA7dcc0."""
        self._validate_cleanup_controller(cleanup)
        self._worker_phase = None
        self._native_outer_cfe0_2026 = False
        self._native_receiving_cfe2_2026 = False
        self._native_receiving_prompt2026 = False
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
        if self._persistence is None:
            self._ssmid_cache2026 = 0
            self._dh_type_cache2026 = 0
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
        # CONTROL writer bindings follow the held export target even when an
        # earlier callback has moved the engine's outer FILE selection.
        metadata = self.family_metadata
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

    def _import_identifier_context(
        self, *, actual_control_import: bool = False
    ) -> None:
        """59ab0 zeroes34records and contact, then copies existing12byte records."""
        if actual_control_import:
            self._require_owned_phase()
            controller = self._controller_execution
            if (
                controller is None
                or self._worker is None
                or self._worker.controller is not controller
                or self._native_control_context2026 is not None
                or self._identifier_context_importing
            ):
                raise ValueError("Once-only owned native CONTROL import required")
        self._identifier_context_importing = actual_control_import
        try:
            self._identifier_context_epoch += 1
            self._last_completed_standalone_getter = None
            self._working_identifier_records = self._identifier_records + (
                bytes(12),
            ) * (34 - len(self._identifier_records))
            self._working_contact_buffer = bytes(33)
            self._working_hardware = b""
            self.dh_state._flashing_ended = False
            if actual_control_import:
                capture = self.worker.capture_control_file2026(controller)
                self._native_control_context2026 = (
                    controller._begin_native_control_context2026(self, capture)
                )
        finally:
            self._identifier_context_importing = False

    def _end_native_control_context2026(self, controller, prior_error=None) -> None:
        context = self._native_control_context2026
        if context is None:
            return
        try:
            controller._end_native_control_context2026(self, context)
        except BaseException as error:
            if prior_error is None:
                raise
            prior_error.add_note("CONTROL context cleanup: " + type(error).__name__)
        finally:
            self._native_control_context2026 = None

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
            if selected is not self._metadata:
                self._invalidate_persistence_cpu_transition2026()
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
            current_metadata = self._metadata
            if current_metadata is None:
                raise ValueError("Current worker FILE metadata is unavailable")
            changed_pointer = (
                metadata.source_container is not current_metadata.source_container
            )
            if changed_pointer:
                self._invalidate_persistence_file_flow_transition2026()
            if (
                metadata is not current_metadata
                or index != worker.source_state.current_global_cpu_index
            ):
                self._invalidate_persistence_cpu_transition2026()
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
            self._invalidate_persistence_cpu_transition2026()
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
                self._pending_getter_stop_origin2026 = None
            self._pending_initial_getter_reset2026 = None
            self._initial_getter_reset_binding2026 = None
            self._invalidate_persistence_cpu_transition2026()
            self._invalidate_persistence_file_flow_transition2026()
            self._pending_file_admission_origin2026 = None
            self._file_admission_owner_thread2026 = None
            if self._thread_job is not None:
                self._thread_job.stop()
            if self._online_controller is not None:
                self._online_controller.close()
            if self._retry_controller is not None:
                self._retry_controller.close()
            if self._worker is not None:
                self._worker.controller._close_control_pool2026(self)
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
            self._wait_current_pointer_metadata2026 = None
            self._wait_pending_admission2026 = None
            self._wait_admission_stage2026 = None
            self._wait_admission_cursor2026 = None
            self._wait_admission_owner2026 = None
            self._wait_active_admission2026 = None
            self._wait_current_igoffon2026 = 0
            self._wait_igoffon_by_file2026 = (0,) * 16
            self._wait_igoffon_aggregate2026 = 0
            self._wait_current_battery_disconnected2026 = 0
            self._wait_battery_disconnected_by_file2026 = (0,) * 16
            self._wait_current_battery_connected2026 = 0
            self._wait_battery_connected_by_file2026 = (0,) * 16
            self._wait_battery_voltage_raw2026 = 0
            self._wait_d4e8_battery_voltage2026 = 0.0
            self._wait_general_keys2026 = ()
            self._wait_image_keys2026 = ()
            self._wait_selected_general2026 = None
            self._wait_selected_image2026 = None
            self._native_delta_active = False
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
    def native_receiving_cfe2_2026(self) -> bool:
        return self._native_receiving_cfe2_2026

    @property
    def native_receiving_prompt2026(self) -> bool:
        return self._native_receiving_prompt2026

    def native_receiving_status2026(self) -> tuple[int, bool]:
        """Read the exact5f1b0 receiving branch without inventing a status bag."""
        return _native_receiving_status_5f1b0_2026(
            self.native_phase,
            self._native_error_output[0],
            self._native_fatal_output,
            self._native_receiving_cfe2_2026,
            self._native_receiving_prompt2026,
        )

    def _validate_getter_entry_origin_34cb0_2026(
        self, job, origin, *, after_worker_reset: bool
    ) -> None:
        from scripts.cuw_engine_threads import _NativeGetterNextEntryOrigin2026

        if type(origin) is _NativeGetterNextEntryOrigin2026:
            worker = self._worker
            expected_epoch = origin.reset_epoch + int(after_worker_reset)
            if (
                worker is None
                or origin.progress != "projection"
                or worker._getter_reset_epoch2026 != expected_epoch
            ):
                raise ValueError("Exact native G reset source stage required")
            job._validate_getter_next_entry_3d120_2026(origin, worker=worker)
            return
        job._validate_getter_entry_34cb0_2026(origin)

    def _clear_getter_entry_errors_34cb0_2026(self, origin: object) -> None:
        job = self._thread_job
        if job is None:
            raise ValueError("Current native getter entry required")
        self._validate_getter_entry_origin_34cb0_2026(
            job, origin, after_worker_reset=False
        )
        self._native_error_output = (0, 0)

    def _publish_getter_entry_phase_prompt_34cb0_2026(self, origin: object) -> None:
        job = self._thread_job
        if job is None:
            raise ValueError("Current native getter entry required")
        self._validate_getter_entry_origin_34cb0_2026(
            job, origin, after_worker_reset=False
        )
        self._received_identifiers = ()
        self._identifier_records = ()
        self._working_identifier_records = ()
        self._worker_phase = 0
        self._native_receiving_prompt2026 = False

    def _publish_getter_entry_busy_34cb0_2026(self, origin: object) -> None:
        job = self._thread_job
        if job is None:
            raise ValueError("Current native getter entry required")
        from scripts.cuw_engine_threads import _NativeGetterNextEntryOrigin2026

        if type(origin) is _NativeGetterNextEntryOrigin2026:
            self._validate_getter_entry_origin_34cb0_2026(
                job, origin, after_worker_reset=True
            )
            if (
                not self._native_outer_cfe0_2026
                or self._native_be54_pending2026
                or self._worker_phase != 0
            ):
                raise ValueError("Exact live native G busy source state required")
            self._native_be54_pending2026 = True
            self._native_receiving_cfe2_2026 = True
            return
        job._validate_getter_entry_34cb0_2026(origin)
        if self._native_outer_cfe0_2026:
            self._native_be54_pending2026 = True
        job._publish_getter_entry_schedule_34cb0_2026(origin)
        if not self._native_outer_cfe0_2026:
            self._native_outer_cfe0_2026 = True
        self._native_receiving_cfe2_2026 = True

    def _set_receiving_prompt_3dde0_2026(self, decision: object) -> None:
        """Publish D2A0 only for the registered, actually dispatched stop route."""
        from scripts.cuw_engine_threads import (
            EngineThreadJob2026,
            _NativeGetterDecision2026,
        )

        if type(decision) is not _NativeGetterDecision2026:
            raise TypeError("Exact source-issued getter decision required")
        job = decision.job
        if (
            type(job) is not EngineThreadJob2026
            or job is not self._thread_job
            or decision.worker is not self._worker
            or not self._active
            or self._phase_thread != get_ident()
            or self._controller_execution is not job.controller
            or job._outer is not current_thread()
        ):
            raise ValueError("Actual outer stop-decision dispatch required")
        job._validate_getter_decision_2026(decision, route="stop_3dde0")
        self._native_receiving_prompt2026 = True

    def _apply_getter_protocol_173d0_2026(self, origin: object, *, worker):
        """Apply the exact late getter protocol mutation to the current FILE."""
        from dataclasses import replace
        from types import MappingProxyType

        from scripts.calibration_2026 import (
            _issue_metadata,
            native2026_global_cpu_index,
            native2026_validate_runtime_metadata,
        )
        from scripts.cuw_engine_threads import EngineThreadJob2026
        from scripts.cuw_engine_worker import EngineWorker2026
        from scripts.cuw_persistence import CUWPersistence, ReproInfoState

        if type(worker) is not EngineWorker2026 or worker is not self._worker:
            raise ValueError("Current native getter worker required")
        job = self._thread_job
        if type(job) is not EngineThreadJob2026 or job.worker is not worker:
            raise ValueError("Current native getter job required")
        self._require_owned_phase()
        job._validate_getter_protocol_tail_173d0_2026(origin, worker=worker)

        metadata = self.native_metadata
        native2026_validate_runtime_metadata(metadata)
        persistence = self._persistence
        if type(persistence) is not CUWPersistence or persistence.state is None:
            raise ValueError("Authenticated getter persistence state required")
        persistence.validate_engine_owner(self)
        state = persistence.state
        if type(state) is not ReproInfoState:
            raise TypeError("Concrete getter persistence state required")
        state.validate()
        self._validate_persistence_source(metadata)

        protocol = self._getter_protocol_4fc_2026
        if type(protocol) is not str or protocol != "":
            raise ValueError("Native getter protocol lineage is unknown")
        current_cpu = native2026_global_cpu_index(metadata)
        if state.write_cpu_index != current_cpu:
            raise ValueError("Getter protocol mutation requires aligned CPU state")
        source_container = metadata.source_container
        source_sha256 = metadata.source_sha256
        vehicle = MappingProxyType({**metadata.vehicle, "contacttype": protocol})
        updated = _issue_metadata(replace(metadata, vehicle=vehicle))
        native2026_validate_runtime_metadata(updated)
        if (
            updated.source_container is not source_container
            or updated.source_sha256 != source_sha256
            or updated.node != metadata.node
            or updated.cpu_index != metadata.cpu_index
        ):
            raise ValueError("173d0 changed the current FILE source identity")

        dh, suzuki = self.dh_state, self.suzuki_state
        self._metadata = updated
        dh.metadata = suzuki.metadata = updated
        dh.source_sha256 = suzuki.source_sha256 = source_sha256
        dh.node = suzuki.node = updated.node
        dh.selection_cpu_index = suzuki.selection_cpu_index = updated.cpu_index
        self._worker_target_sources[id(source_container)] = updated
        self._invalidate_persistence_cpu_transition2026()
        state.contact_type_at_success_get_cid = protocol
        return updated

    def _publish_getter_stop_event_2026(self, job, receipt: object) -> None:
        """Publish only the source5f030/40580 post-child-join BE54 write."""
        from scripts.cuw_engine_threads import (
            EngineThreadJob2026,
            _NativeGetterStopReceipt2026,
        )

        if (
            type(job) is not EngineThreadJob2026
            or job is not self._thread_job
            or type(receipt) is not _NativeGetterStopReceipt2026
        ):
            raise ValueError("Current native getter job required")
        job.validate_owner(self, job.controller)
        job._validate_getter_stop_stage2026(receipt)
        native_event = self._native_outer_cfe0_2026
        if native_event:
            self._native_be54_pending2026 = True
        job._publish_getter_stop_schedule_2026(receipt, native_event=native_event)

    def _publish_vbf_tail_36800_2026(self, job, request: object) -> None:
        """Publish only FULL36800's actual pre-queue native scheduling tail."""
        from scripts.cuw_engine_threads import (
            EngineThreadJob2026,
            validate_vbf_process_before2026,
        )

        if type(job) is not EngineThreadJob2026 or job is not self._thread_job:
            raise ValueError("Current native VBF job required")
        with job._lock:
            job.validate_owner(self, job.controller)
            request = validate_vbf_process_before2026(request, job, states=("parked",))
            job._validate_vbf_issuer2026(request)
            worker = job.worker
            if (
                worker is not self._worker
                or worker.engine is not self
                or worker.controller is not job.controller
                or worker.native_prepare_handshake != 1
                or self._prepare_prefix_owner != (get_ident(), worker, job)
                or not self._native_outer_cfe0_2026
            ):
                raise ValueError("Actual FULL36800 native scheduling tail required")
            worker.validate_source(self)
            self._native_be54_pending2026 = True
            self._native_receiving_cfe2_2026 = True

    def _complete_getter_stop_2026(self, job, receipt: object) -> None:
        """Apply only the exact final5f030 stores;40580 resets after FILE release."""
        from scripts.cuw_engine_threads import (
            EngineThreadJob2026,
            _NativeGetterStopReceipt2026,
        )

        if (
            type(job) is not EngineThreadJob2026
            or job is not self._thread_job
            or type(receipt) is not _NativeGetterStopReceipt2026
            or receipt.job is not job
            or receipt.worker is not self._worker
        ):
            raise ValueError("Exact current getter stop receipt required")
        with job._lock:
            job._validate_getter_stop_stage2026(receipt)
            stage = job._getter_stop_stage2026
            if (
                stage is None
                or stage.stage != "outer_requested"
                or not stage.schedule_published
                or stage.child is None
                or stage.child.is_alive()
                or stage.outer is None
                or stage.outer.is_alive()
                or type(job._child_exit) is not int
                or job._child_exit not in (0, 1)
                or type(job._outer_exit) is not int
                or job._outer_exit not in (0, 1)
            ):
                raise ValueError(
                    "Native getter stop has not reached its terminal source point"
                )
            if (
                receipt.producer == "40580"
                and self._wait_pending_admission2026 is not None
            ):
                raise ValueError("40580 reset cannot overlap a cold source capability")
            if receipt.producer == "5f030":
                self._native_outer_cfe0_2026 = False
                self._native_receiving_cfe2_2026 = False
            elif receipt.producer != "40580":
                raise ValueError("Unsupported native getter stop producer")
            job._complete_getter_stop_2026(receipt)
            if receipt.producer == "40580":
                self._reset_native_wait_timing_40580_2026()

    def _reset_native_wait_timing_40580_2026(self) -> None:
        """Apply only the actual late40580 constructor-shaped timing reset."""
        self._wait_current_igoffon2026 = 0
        self._wait_igoffon_by_file2026 = (0,) * 16
        self._wait_igoffon_aggregate2026 = 0
        self._wait_current_battery_disconnected2026 = 0
        self._wait_battery_disconnected_by_file2026 = (0,) * 16
        self._wait_reserved_battery_disconnected2026 = 0
        self._wait_current_battery_connected2026 = 0
        self._wait_battery_connected_by_file2026 = (0,) * 16
        self._wait_reserved_battery_connected2026 = 0
        self._wait_d4e8_battery_voltage2026 = 0.0
        self._wait_active_admission2026 = None
        self._wait_timing_epoch2026 += 1

    def _probe_native_be54_3cb90_2026(self, retirement: object) -> bool:
        """Sample the manual native event at its actual outer-retirement point."""
        job = self._thread_job
        if job is None:
            raise ValueError("Current native outer retirement required")
        job._validate_native_retirement_3cb90_2026(retirement)
        signaled = self._native_be54_pending2026
        if not signaled:
            self._native_receiving_cfe2_2026 = False
        return signaled

    def _reset_native_be54_3cb90_2026(self, retirement: object) -> None:
        """Reset BE54 only after the actual source wait observed its signal."""
        job = self._thread_job
        if job is None:
            raise ValueError("Current native outer retirement required")
        job._validate_native_retirement_3cb90_2026(retirement)
        if not self._native_be54_pending2026:
            raise ValueError("Native BE54 is not signaled at reset")
        self._native_be54_pending2026 = False

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

    @property
    def native_ssmid_cache2026(self) -> int:
        value = (
            self._ssmid_cache2026
            if self._persistence is None
            else self._persistence.state.ssmid
        )
        if type(value) is not int or not 0 <= value <= 255:
            raise ValueError("Native ED29 SSMID cache must be a byte")
        return value

    @property
    def native_dh_type_cache2026(self) -> int:
        value = (
            self._dh_type_cache2026
            if self._persistence is None
            else self._persistence.state.dh_central_gw_type
        )
        if type(value) is not int or not 0 <= value <= 255:
            raise ValueError("Native ED8A DH type cache must be a byte")
        return value

    def _validate_control_cache_publisher2026(self, worker) -> None:
        if worker is not self.worker or self._controller_execution is None:
            raise ValueError("Actual active CONTROL worker required for cache publish")
        controller = self._controller_execution
        context = controller.native_control_context2026(self)
        context.validate(self, self._controller_execution)
        if self._controller_export_target2026 is not None:
            raise ValueError("Post-export cache publish requires an ended export scope")
        from scripts.programming_2026_common import (
            _control_helper_entry2026,
            _control_helper_primary_return_seen2026,
        )

        helper_lease = _control_helper_entry2026(context)
        if not _control_helper_primary_return_seen2026(context, helper_lease, "8990"):
            raise ValueError("Completed 8990 primary BOOL return required")
        worker._validate_control_postexport_cache2026(context)

    def _validate_control_cache_helper2026(
        self, worker, helper: str, *, primary_return: bool
    ):
        if worker is not self.worker or self._controller_execution is None:
            raise ValueError("Actual active CONTROL worker required for cache callback")
        controller = self._controller_execution
        context = controller.native_control_context2026(self)
        context.validate(self, controller)
        if self._controller_export_target2026 is not None:
            raise ValueError("CONTROL cache callback follows export-scope teardown")
        from scripts.programming_2026_common import (
            _control_helper_entry2026,
            _control_helper_primary_return_seen2026,
        )

        lease = _control_helper_entry2026(context)
        if primary_return and not _control_helper_primary_return_seen2026(
            context, lease, helper
        ):
            raise ValueError(f"Completed {helper} primary return required")
        if not primary_return:
            from scripts.programming_2026_common import (
                _control_helper_primary_return_seen2026,
            )

            if _control_helper_primary_return_seen2026(context, lease, helper):
                raise ValueError(f"Active {helper} getter entry required")
            # The entry lookup authenticates the actual helper identity; the
            # receipt is not available yet at its in-helper callback site.
        worker._validate_control_output_context2026(context)
        return controller, context

    @property
    def native_control_retry_cache2026(self) -> bool:
        value = (
            self._control_retry_cache2026
            if self._persistence is None
            else self._persistence.state.use_new_software_password
        )
        if type(value) is not bool:
            raise ValueError("Native EC99 retry cache must be Boolean")
        return value

    def _publish_control_retry_cache2026(self, *, worker) -> None:
        self._validate_control_cache_helper2026(worker, "4c10", primary_return=True)
        value = worker.control_state.initial_command_retry
        if type(value) is not bool:
            raise ValueError("Source worker retry cache must be Boolean")
        self._control_retry_cache2026 = value
        if self._persistence is not None:
            self._persistence.state.use_new_software_password = value

    @property
    def native_control_phase_cache2026(self) -> int:
        value = (
            self._control_phase_cache2026
            if self._persistence is None
            else self._persistence.state.comm_phase
        )
        if type(value) is not int or not 0 <= value <= 0xFF:
            raise ValueError("Native ECFC communication-phase cache must be a byte")
        return value

    def _publish_control_phase_cache2026(self, *, worker) -> None:
        self._validate_control_cache_helper2026(worker, "4c10", primary_return=True)
        value = self.dh_state.comm_phase
        if type(value) is not int or not 0 <= value <= 0xFF:
            raise ValueError("Live native communication phase must be a byte")
        self._control_phase_cache2026 = value
        if self._persistence is not None:
            self._persistence.state.comm_phase = value

    @property
    def native_control_alternate_cache2026(self) -> bool:
        value = (
            self._control_alternate_cache2026
            if self._persistence is None
            else self._persistence.state.sequence_changed_for_get_cid
        )
        if type(value) is not bool:
            raise ValueError("Native ED28 alternate-getter cache must be Boolean")
        return value

    def _publish_control_alternate_cache2026(self, *, worker) -> None:
        controller, _context = self._validate_control_cache_helper2026(
            worker, "6f20", primary_return=False
        )
        value = controller.alternate_cid_used
        if type(value) is not bool:
            raise ValueError("Source alternate-getter state must be Boolean")
        self._control_alternate_cache2026 = value
        if self._persistence is not None:
            self._persistence.state.sequence_changed_for_get_cid = value

    @property
    def native_control_divided_index2026(self) -> int:
        value = (
            self._control_divided_index_cache2026
            if self._persistence is None
            else self._persistence.state.write_target_divided_cpu_image_index
        )
        if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
            raise ValueError("Native ED6C divided-image index must be a DWORD")
        return value

    def _publish_control_divided_index2026(self, value: int) -> None:
        if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
            raise ValueError("Native ED6C divided-image index must be a DWORD")
        self._control_divided_index_cache2026 = value
        if self._persistence is not None:
            self._persistence.update_divided_image(value)

    def _publish_control_ssmid_cache2026(self, *, worker) -> None:
        self._validate_control_cache_publisher2026(worker)
        controller = self._controller_execution
        if controller is None:
            raise ValueError("Active CONTROL controller required for cache publish")
        context = controller.native_control_context2026(self)
        value = worker.publish_control_callback_28_2026(context)
        if type(value) is not int or not 0 <= value <= 255:
            raise ValueError("Worker C25 SSMID must be a raw byte")
        self._ssmid_cache2026 = value
        if self._persistence is not None:
            self._persistence.state.ssmid = value

    def _publish_control_dh_type_cache2026(self, *, worker) -> None:
        self._validate_control_cache_publisher2026(worker)
        controller = self._controller_execution
        if controller is None:
            raise ValueError("Active CONTROL controller required for cache publish")
        context = controller.native_control_context2026(self)
        value = worker.publish_control_callback_2f2026(context)
        if type(value) is not int or not 0 <= value <= 255:
            raise ValueError("Worker C08 low byte must be a raw byte")
        self._dh_type_cache2026 = value
        if self._persistence is not None:
            self._persistence.state.dh_central_gw_type = value

    def _reset_control_callback_caches_for_cleanup2026(self, cleanup) -> None:
        self._validate_cleanup_controller(cleanup)
        if self._persistence is not None and (
            self._persistence.state.ssmid != 0
            or self._persistence.state.dh_central_gw_type != 0
            or self._persistence.state.use_new_software_password
            or self._persistence.state.comm_phase != 2
            or self._persistence.state.sequence_changed_for_get_cid
            or self._persistence.state.write_target_divided_cpu_image_index != 0
        ):
            raise ValueError("Reset the actual recovery aggregate before its caches")
        self._ssmid_cache2026 = 0
        self._dh_type_cache2026 = 0
        self._control_retry_cache2026 = False
        self._control_phase_cache2026 = 2
        self._control_alternate_cache2026 = False
        self._control_divided_index_cache2026 = 0

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
            self.family_metadata.logical_blocks
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

    def _initialize_native_prepare_outputs(self, *, worker, started_ms: int) -> None:
        """Apply the literal36800 clock/output sequence once for every source path."""
        self._require_native_prepare_prefix(worker)
        if type(started_ms) is not int or not 0 <= started_ms <= 86_400_000:
            raise ValueError("Bounded native36800 clock value required")
        recovery = worker.control_state.recovery_mode
        if type(recovery) is not bool:
            raise ValueError("Native36800 recovery source predicate required")
        # 41eb0 clears D348/D349 before the copied CFB0 error fields.
        self._native_cycle_output = False
        self._write_complete_output = False
        self._native_error_kind_output = 0
        self._native_previous_error_kind_output = 0
        self._native_cfc4_2026 = 0
        # D314 is the canonical source clock; retry/checkpoint code reads it.
        self._native_prepare_d314_2026 = started_ms
        self._native_error_output = (self._native_error_output[0] if recovery else 0, 0)
        self._online_modal_state = 0
        self._worker_phase = 1
        retry = self._retry_controller
        if retry is not None:
            retry._initialize_prepare_state(worker, started_ms)

    @contextmanager
    def ordinary_prepare_execution_36800_2026(self, job, binding):
        """Hold one exact job.start lexical owner across the pre-child36800 prefix."""
        from scripts.cuw_engine_threads import (
            EngineThreadJob2026,
            _has_vbf_request2026,
            _OrdinaryPrepareStartBinding2026,
        )
        from scripts.cuw_engine_worker import EngineWorker2026

        if type(job) is not EngineThreadJob2026 or job is not self._thread_job:
            raise ValueError("Current ordinary36800 job required")
        if (
            type(binding) is not _OrdinaryPrepareStartBinding2026
            or binding.job is not job
            or binding.engine is not self
            or type(binding.worker) is not EngineWorker2026
            or binding.worker is not self._worker
            or binding.controller is not job.controller
            or binding.issuer_thread != get_ident()
            or job._ordinary_prepare_binding2026 is not binding
            or not job._ordinary_prepare_starting2026
            or job._ordinary_prepare_origin2026 is not None
        ):
            raise ValueError("Exact ordinary36800 job.start binding required")
        if not self._lock.acquire(blocking=False):
            raise ValueError("CUW phase is active")
        acquired = True
        scope = object()
        origin = None
        worker = cast(EngineWorker2026, binding.worker)
        owner = (get_ident(), worker, job)
        try:
            with self._phase_state_lock:
                if (
                    self._active
                    or self._phase_thread is not None
                    or not self._phase_finished.is_set()
                    or self._ordinary_prepare_scope2026 is not None
                    or self._prepare_prefix_owner is not None
                ):
                    raise ValueError("Native36800 engine must be idle")
            if (
                self._worker is not binding.worker
                or self._thread_job is not job
                or self._controller_execution is not None
                or self._metadata is not binding.source_metadata
                or self.native_metadata.source_container is not binding.source_container
                or self.native_metadata.source_sha256 != binding.source_digest
                or self._file_sources is not binding.source_set
                or self.configuration is not binding.configuration
                or worker._getter_reset_epoch2026 != binding.reset_epoch
                or worker._flow_file_index2026 != binding.flow_index
                or worker._capture_flow_view2026() is not binding.flow_view
                or worker._capture_pointer_view2026(self.native_metadata)
                is not binding.pointer_view
                or self._native_outer_cfe0_2026 is not binding.cfe0
                or self._native_be54_pending2026 is not binding.be54
                or self._native_receiving_cfe2_2026 is not binding.cfe2
                or binding.cfe2
                or (binding.cfe0 and binding.be54)
                or job._pending_getter_next_entry_3d120_2026 is not None
                or job._getter_continuation2026 is not binding.continuation
                or job._getter_stop_receipt2026 is not binding.stop_receipt
                or job._getter_stop_receipt2026 is not None
                or _has_vbf_request2026(job)
            ):
                raise ValueError("Ordinary36800 source admission changed")
            origin = job._issue_ordinary_prepare_origin2026(binding, scope=scope)
            if origin is None or origin.scope is not scope:
                raise ValueError("Exact ordinary36800 lexical origin required")
            self._ordinary_prepare_scope2026 = (job, binding, origin, scope)
            job._validate_ordinary_prepare_origin_36800_2026(origin)
            self._prepare_prefix_owner = owner
            yield origin
            if origin.stage not in ("early_return", "scheduled"):
                raise ValueError(
                    "Ordinary36800 prefix did not reach a terminal source stage"
                )
        except BaseException:
            # The exact job abort path owns cleanup once an origin exists.
            if origin is not None:
                acquired = False
            else:
                if self._ordinary_prepare_scope2026 is not None:
                    slot = self._ordinary_prepare_scope2026
                    if slot[0] is job and slot[1] is binding:
                        self._ordinary_prepare_scope2026 = None
                if self._prepare_prefix_owner == owner:
                    self._prepare_prefix_owner = None
                if acquired:
                    self._lock.release()
                    acquired = False
            raise
        else:
            if origin is not None and origin.stage == "early_return":
                if self._ordinary_prepare_scope2026 is not None:
                    slot = self._ordinary_prepare_scope2026
                    if slot[0] is job and slot[1] is binding:
                        self._ordinary_prepare_scope2026 = None
                if self._prepare_prefix_owner == owner:
                    self._prepare_prefix_owner = None
                if acquired:
                    self._lock.release()
                    acquired = False
            elif origin is not None and origin.stage == "scheduled":
                if self._ordinary_prepare_scope2026 is not None:
                    slot = self._ordinary_prepare_scope2026
                    if slot[0] is job and slot[1] is binding:
                        self._ordinary_prepare_scope2026 = None
                if self._prepare_prefix_owner == owner:
                    self._prepare_prefix_owner = None
                # Ownership of _lock was transferred to the reserved phase lease.
                acquired = False
        finally:
            if acquired:
                self._lock.release()

    def _validate_ordinary_prepare_engine_origin2026(self, job, origin) -> None:
        from scripts.cuw_engine_threads import EngineThreadJob2026

        if type(job) is not EngineThreadJob2026 or job is not self._thread_job:
            raise ValueError("Current ordinary36800 job required")
        job._validate_ordinary_prepare_origin_36800_2026(origin)
        slot = self._ordinary_prepare_scope2026
        if (
            type(slot) is not tuple
            or len(slot) != 4
            or slot[0] is not job
            or slot[1] is not origin.binding
            or slot[2] is not origin
            or slot[3] is not origin.scope
            or origin.binding.worker is not self._worker
            or origin.binding.engine is not self
            or origin.binding.issuer_thread != get_ident()
            or self._prepare_prefix_owner != (get_ident(), origin.binding.worker, job)
        ):
            raise ValueError("Exact ordinary36800 engine lexical scope required")

    def _initialize_ordinary_prepare_outputs_36800_2026(
        self, origin, *, worker, started_ms: int
    ) -> None:
        """Apply the literal36800 clock/output stores after the clock source point."""
        job = self._thread_job
        if job is None:
            raise ValueError("Current ordinary36800 job required")
        self._validate_ordinary_prepare_engine_origin2026(job, origin)
        if worker is not self._worker:
            raise ValueError("Current ordinary36800 worker required")
        worker._validate_ordinary_output_point_36800_2026(origin, started_ms)
        self._initialize_native_prepare_outputs(worker=worker, started_ms=started_ms)

    def _begin_ordinary_recovery_36800_2026(self, origin, *, worker) -> int:
        """Publish recovery phase/D9D4 and return the actual persisted EC94 CPU."""
        job = self._thread_job
        if job is None:
            raise ValueError("Current ordinary36800 job required")
        self._validate_ordinary_prepare_engine_origin2026(job, origin)
        worker._validate_ordinary_recovery_point_36800_2026(origin)
        persistence = self._persistence
        if (
            worker is not self._worker
            or origin.stage != "recovery"
            or origin.phase not in (1, 2)
            or self._worker_phase != origin.phase
            or persistence is None
        ):
            raise ValueError("Bound native phase-two recovery state required")
        self._worker_phase = 2
        origin.phase = 2
        self._validate_persistence_source(self.native_metadata)
        state = persistence.state
        from scripts.programming_2026_common import NotificationBool

        notification = persistence.notification
        if (
            type(notification) is not NotificationBool
            or self.dh_state._notification is not notification
        ):
            raise ValueError("Registered native D350 recovery callback required")
        # NotificationBool.assign stores the value before invoking its handler.
        notification.assign(True)
        # D350 is a live callback: EC94, ED58 and the selected FILE are read
        # afterwards because that callback may update the bound persistence.
        state = persistence.state
        cpu_index = state.write_cpu_index
        file_index = state.calibration_file_index
        if (
            type(cpu_index) is not int
            or type(file_index) is not int
            or not 0 <= file_index < len(state.calibrations)
        ):
            raise ValueError("Authenticated recovery EC94/current FILE required")
        self._native_recovery_file_index2026 = file_index
        progress_base = state.offset_of_write_cpu_multi_cal_index
        if type(progress_base) is not int or progress_base < 0:
            raise ValueError("Native D9D4 progress base required")
        worker._progress_base = progress_base
        self._native_recovery_d9d4_2026 = progress_base
        return cpu_index

    def _finish_ordinary_recovery_36800_2026(self, origin, *, worker) -> None:
        """Publish source-ordered live recovery flags/progress after19710."""
        job = self._thread_job
        if job is None:
            raise ValueError("Current ordinary36800 job required")
        self._validate_ordinary_prepare_engine_origin2026(job, origin)
        worker._validate_ordinary_recovery_point_36800_2026(origin)
        if worker is not self._worker or origin.stage != "recovery":
            raise ValueError("Exact ordinary36800 recovery source point required")
        persistence = self._persistence
        if persistence is None:
            raise ValueError("Bound native recovery state required")
        state = persistence.state
        if (
            type(state.writing_end_block) is not bool
            or type(state.use_new_software_password) is not bool
        ):
            raise ValueError("Native live EC9A/EC99 Boolean values required")
        d360 = persistence.last_block_notification
        from scripts.programming_2026_common import NotificationBool

        if type(d360) is not NotificationBool:
            raise ValueError("Registered native D360 callback required")
        d360.assign(state.writing_end_block)
        d360_value = bool(d360)
        state = persistence.state
        if type(state.use_new_software_password) is not bool:
            raise ValueError("Native live EC99 Boolean value required")
        self.dh_state._use_new_password = (
            True if d360_value else state.use_new_software_password
        )
        target = worker.source_state.current_global_cpu_index
        if type(target) is not int or not 0 <= target <= len(self.dh_state._progress):
            raise ValueError("Native recovery D308 target exceeds capacity")
        if target:
            progress = list(self.dh_state._progress)
            for index in range(target):
                progress[index] = 100
            self.dh_state._progress = tuple(progress)
        self._native_recovery_target2026 = target

    def _apply_ordinary_cid_selection_3e710_2026(self, origin, step, *, worker) -> None:
        """Publish one source-yielded3e710 metadata rebuild with its proof successor."""
        from scripts.calibration_2026 import (
            Native2026Metadata,
            NativeCIDRebuildMetadata2026,
            native2026_cpu_count,
            native2026_validate_runtime_metadata,
        )

        job = self._thread_job
        if job is None:
            raise ValueError("Current ordinary36800 job required")
        self._validate_ordinary_prepare_engine_origin2026(job, origin)
        if worker is not self._worker or type(step) is not NativeCIDRebuildMetadata2026:
            raise ValueError("Actual ordinary3e710 metadata step required")
        worker._validate_ordinary_cid_point_3e710_2026(origin, step)

        old_metadata = self.native_metadata
        sources = self._file_sources
        persistence = self._persistence
        before_cpu = worker.source_state.current_global_cpu_index
        if type(before_cpu) is not int or before_cpu < 0:
            raise ValueError("Current native3e710 CPU required")
        metadata = worker._ordinary_file_metadata_for_cursor_3e710_2026(
            step.metadata, before_cpu
        )
        if type(metadata) is not Native2026Metadata:
            raise TypeError("Concrete rebuilt native CPU metadata required")
        native2026_validate_runtime_metadata(metadata)
        if (
            metadata.source_container is not old_metadata.source_container
            or metadata.source_sha256 != old_metadata.source_sha256
            or metadata.region != old_metadata.region
        ):
            raise ValueError("Native3e710 rebuild changed the current FILE")
        worker._prepare_ordinary_cid_mirror_3e710_2026(origin, step, metadata)

        next_cpu_proof = None
        if persistence is not None:
            self._validate_persistence_source(old_metadata)
            state = persistence.state
            persisted_cpu = state.write_cpu_index
            if type(persisted_cpu) is not int:
                raise ValueError("Native persisted EC94 must be an integer")
            if persisted_cpu != before_cpu:
                if not self._persistence_cpu_transition_valid2026(
                    old_metadata, state, sources, before_cpu, state_snapshot=state
                ):
                    raise ValueError("Existing D308 proof is required before3e710")
                previous = self._persistence_cpu_transition2026
                if previous is None:
                    raise ValueError("Existing D308 proof disappeared")
                next_cpu_proof = replace(
                    previous,
                    worker=worker,
                    persistence=persistence,
                    state=state,
                    metadata=metadata,
                    file_sources=sources,
                    container=metadata.source_container,
                    digest=metadata.source_sha256,
                    node=metadata.node,
                    after_cpu=before_cpu,
                )
            else:
                if self._persistence_cpu_transition2026 is not None:
                    raise ValueError("Equal native CPU must not retain a D308 proof")
            if sources is not None:
                persistence._validate_file_source_membership(
                    sources, metadata, state_snapshot=state
                )

        self._invalidate_persistence_cpu_transition2026()
        self._worker_target_sources[id(metadata.source_container)] = metadata
        self._metadata = metadata
        resolved_cpu = before_cpu < native2026_cpu_count(metadata)
        for state in (self.dh_state, self.suzuki_state):
            state.metadata = metadata
            state.source_sha256 = metadata.source_sha256
            if resolved_cpu:
                state.node = metadata.node
                state.selection_cpu_index = metadata.cpu_index
        self._persistence_cpu_transition2026 = next_cpu_proof
        self._issued_sil_transfer = None
        worker._publish_ordinary_cid_mirror_3e710_2026(origin)
        point = worker._ordinary_cid_point2026
        job._refresh_ordinary_prepare_projection2026(origin, point=point)

    def _publish_ordinary_cpu_36800_2026(
        self, origin, *, worker, cpu_index: int
    ) -> None:
        """Commit one reached D308 store with its independent CPU witness."""
        from scripts.calibration_2026 import (
            native2026_cpu_count,
            native2026_validate_runtime_metadata,
        )

        job = self._thread_job
        if job is None:
            raise ValueError("Current ordinary36800 job required")
        self._validate_ordinary_prepare_engine_origin2026(job, origin)
        if worker is not self._worker:
            raise ValueError("Current ordinary36800 worker required")
        old_metadata, before_cpu = worker._validate_ordinary_cpu_point_36800_2026(
            origin, cpu_index
        )
        metadata = worker._ordinary_file_metadata_for_cursor_3e710_2026(
            old_metadata, cpu_index
        )
        worker._prepare_ordinary_cpu_mirror_36800_2026(origin, metadata, cpu_index)
        persistence = self._persistence
        persisted_cpu: int | None = None
        if persistence is not None:
            self._validate_persistence_source(self.native_metadata)
            persisted_cpu = persistence.state.write_cpu_index
            if type(persisted_cpu) is not int:
                raise ValueError("Native persisted EC94 must be an integer")
        native2026_validate_runtime_metadata(metadata)
        if (
            metadata.source_container is not self.native_metadata.source_container
            or metadata.source_sha256 != self.native_metadata.source_sha256
            or metadata.region != self.native_metadata.region
        ):
            raise ValueError("Ordinary D308 CPU projection changed its FILE")
        next_proof = None
        if (
            persistence is not None
            and type(persisted_cpu) is int
            and persisted_cpu != cpu_index
        ):
            next_proof = _PersistenceCPUTransition2026(
                "ordinary-36800",
                origin,
                worker,
                persistence,
                persistence.state,
                metadata,
                self._file_sources,
                metadata.source_container,
                metadata.source_sha256,
                metadata.node,
                persisted_cpu,
                before_cpu,
                cpu_index,
            )
        self._invalidate_persistence_cpu_transition2026()
        self._worker_target_sources[id(metadata.source_container)] = metadata
        self._metadata = metadata
        dh = self.dh_state
        suzuki = self.suzuki_state
        resolved_cpu = cpu_index < native2026_cpu_count(metadata)
        for state in (dh, suzuki):
            state.metadata = metadata
            state.source_sha256 = metadata.source_sha256
            if resolved_cpu:
                state.node = metadata.node
                state.selection_cpu_index = metadata.cpu_index
            state.cpu_index = state.global_cpu_index = cpu_index
        dh._dh_flash_size = None
        self._issued_sil_transfer = None
        self._persistence_cpu_transition2026 = next_proof
        point = worker._ordinary_cpu_point2026
        worker._publish_ordinary_cpu_mirror_36800_2026(origin)
        job._refresh_ordinary_prepare_projection2026(origin, point=point)

    def _reserve_ordinary_prepare_phase_36800_2026(self, job, origin, record):
        """Promote the held lexical engine lock into the source-derived phase lease."""
        from scripts.cuw_engine_threads import (
            _CompletionRecord2026,
            _issue_thread_phase_lease,
            _OrdinaryPrepareOrigin2026,
        )

        if type(origin) is not _OrdinaryPrepareOrigin2026:
            raise TypeError("Exact ordinary36800 origin required")
        self._validate_ordinary_prepare_engine_origin2026(job, origin)
        if (
            origin.stage != "prepared"
            or type(record) is not _CompletionRecord2026
            or record.sequence != origin.binding.sequence
            or origin.record is not None
            or origin.lease is not None
            or self._worker_phase != origin.phase
            or origin.phase not in (1, 2)
        ):
            raise ValueError("Completed ordinary36800 source prefix required")
        self._require_native_phase_idle()
        self._validate_persistence_source(self.native_metadata)
        lease = _issue_thread_phase_lease(self, job.controller, origin.phase)
        try:
            with self._phase_state_lock:
                if (
                    self._active
                    or self._phase_thread is not None
                    or not self._phase_finished.is_set()
                    or self._thread_job is not job
                ):
                    raise ValueError("Ordinary36800 reservation owner changed")
                self._cancelled.clear()
                self._phase_finished = Event()
                self._active = True
                self._phase_thread = None
                # Keep the actual source phase1/2; do not rewrite it at reserve.
            origin.record = record
            origin.lease = lease
            job._advance_ordinary_prepare_origin2026(origin, "reserved")
            return lease
        except BaseException:
            lease._release()
            raise

    def _publish_ordinary_prepare_tail_36800_2026(self, origin) -> None:
        """Publish the literal CFE0/BE54/CFE2 tail for a reserved ordinary call."""
        job = self._thread_job
        if job is None:
            raise ValueError("Current ordinary36800 job required")
        self._validate_ordinary_prepare_engine_origin2026(job, origin)
        if (
            origin.stage != "reserved"
            or origin.lease is None
            or origin.record is None
            or origin.lease.state != "reserved"
            or not self._active
            or self._phase_thread is not None
            or self._worker_phase != origin.phase
            or self._native_receiving_cfe2_2026
        ):
            raise ValueError("Exact reserved ordinary36800 scheduling tail required")
        job._prepare_ordinary_outer_carrier2026(origin)
        # 36c09 CreateThread is represented by the persistent native outer
        # carrier; 36c14 publishes CFE0 only after that carrier exists.
        if not self._native_outer_cfe0_2026:
            if not job.native_worker_exists:
                raise ValueError("Native ordinary outer carrier is unavailable")
            self._native_outer_cfe0_2026 = True
        else:
            self._native_be54_pending2026 = True
        self._native_receiving_cfe2_2026 = True
        job._advance_ordinary_prepare_origin2026(origin, "scheduled")

    def _abort_ordinary_prepare_36800_2026(self, origin) -> None:
        """Revoke only an unpublished ordinary host reservation, preserving writes."""
        from scripts.cuw_engine_threads import (
            EngineThreadJob2026,
            _OrdinaryPrepareOrigin2026,
            _OrdinaryPrepareStartBinding2026,
        )

        if type(origin) is not _OrdinaryPrepareOrigin2026:
            raise TypeError("Exact ordinary36800 origin required")
        job = self._thread_job
        binding = origin.binding
        scope = self._ordinary_prepare_scope2026
        if (
            type(job) is not EngineThreadJob2026
            or type(binding) is not _OrdinaryPrepareStartBinding2026
            or binding.job is not job
            or binding.engine is not self
            or binding.generation is not job._native_start_generation2026
            or binding.issuer_thread != get_ident()
            or job._ordinary_prepare_origin2026 is not origin
            or job._ordinary_prepare_binding2026 is not binding
            or not job._ordinary_prepare_starting2026
            or type(scope) is not tuple
            or len(scope) != 4
            or scope[0] is not job
            or scope[1] is not binding
            or scope[2] is not origin
            or scope[3] is not origin.scope
            or self._prepare_prefix_owner != (get_ident(), binding.worker, job)
        ):
            raise ValueError("Exact unpublished ordinary36800 scope required")
        lease = origin.lease
        if lease is None:
            if (
                origin.record is not None
                or self._active
                or self._phase_thread is not None
                or origin.stage in ("scheduled", "early_return")
            ):
                raise ValueError("Unreserved ordinary36800 lexical abort required")
        elif (
            lease.engine is not self
            or lease.controller is not job.controller
            or lease.state != "reserved"
            or not self._active
            or self._phase_thread is not None
            or self._worker_phase != origin.phase
            or origin.stage not in ("prepared", "reserved", "scheduled")
            or origin.record is None
        ):
            raise ValueError("Unadopted ordinary36800 reservation required")
        try:
            job._abort_ordinary_prepare_36800_2026(origin)
        finally:
            if lease is not None and lease.state == "reserved":
                lease._release()
                with self._phase_state_lock:
                    self._active = False
                    self._phase_thread = None
                    self._worker_phase = origin.phase
                    self._phase_finished.set()
            if self._ordinary_prepare_scope2026 is scope:
                self._ordinary_prepare_scope2026 = None
            if self._prepare_prefix_owner == (get_ident(), binding.worker, job):
                self._prepare_prefix_owner = None
            if self._lock.locked():
                self._lock.release()

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
                fatal=self._native_fatal_output,
                receiving=self._native_receiving_cfe2_2026,
                receiving_prompt=self._native_receiving_prompt2026,
                recovery_status=self.native_recovery_status(previous=True),
            )
            if self.native_receiving_status2026()[
                0
            ] != 0x138C and status.reprogramming_status()[0] not in (0xBBB, 0xBBC):
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
        if self._persistence is not None:
            self._validate_persistence_source(self.native_metadata)
        value = self.native_control_divided_index2026
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
            self._reject_failed_cold_file_admission2026()
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
            self._reject_failed_cold_file_admission2026()
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
            self._invalidate_persistence_cpu_transition2026()
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
            self._reject_failed_cold_file_admission2026()
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
            self._invalidate_persistence_cpu_transition2026()
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
            self._reject_failed_cold_file_admission2026()
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
            self._invalidate_persistence_cpu_transition2026()
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
            self._reject_failed_cold_file_admission2026()
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
            self._invalidate_persistence_cpu_transition2026()
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
        with self._phase_state_lock:
            if self.native_phase != 0:
                return 0x138A
            initial_job = self._thread_job
            # A fresh stop is admitted by CFE2. A retained incomplete 5f030
            # transaction is the sole continuation case after 3cb90 clears it.
            if not self._native_receiving_cfe2_2026:
                initial_receipt = (
                    None
                    if initial_job is None
                    else initial_job._getter_stop_receipt2026
                )
                initial_stage = (
                    None if initial_job is None else initial_job._getter_stop_stage2026
                )
                if (
                    initial_receipt is None
                    or initial_stage is None
                    or initial_stage.receipt is not initial_receipt
                    or initial_stage.stage == "completed"
                ):
                    return 1
            if initial_job is None:
                raise ValueError("Busy native getter has no current CStart")
            if not self._active and not initial_job.native_worker_exists:
                raise ValueError("Busy native getter lost its current CStart")
            if self._phase_thread == get_ident():
                raise ValueError("CID worker cannot join itself")
            if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
                raise TypeError("Finite positive CID stop timeout required")
            if not callable(cancelled):
                raise TypeError("Callable host stop cancellation required")
            budget = _Deadline(timeout, cancelled, monotonic)

        while True:
            budget.remaining()
            job = self._thread_job
            acquired = False
            receipt = None
            try:
                if job is None:
                    raise ValueError("Busy native getter has no current CStart")
                acquired = job._lock.acquire(timeout=budget.remaining())
                if not acquired:
                    continue
                with self._phase_state_lock:
                    if job is not self._thread_job:
                        continue
                    if self.native_phase != 0:
                        return 0x138A
                    job_exists = job is not None and job.native_worker_exists
                    if not self._active and not job_exists:
                        raise ValueError("Busy native getter lost its current CStart")
                    if self._phase_thread == get_ident():
                        raise ValueError("CID worker cannot join itself")
                    finished = self._phase_finished
                    from scripts.cuw_engine_threads import (
                        EngineThreadJob2026,
                        _NativeGetterStopReceipt2026,
                    )

                    if type(job) is not EngineThreadJob2026:
                        raise TypeError("Concrete native thread job required")
                    job._reject_self_join()
                    job.validate_owner(self, job.controller)
                    job.worker.validate_source(self)
                    receipt = job._getter_stop_receipt2026
                    stage = job._getter_stop_stage2026
                    if not self._native_receiving_cfe2_2026 and receipt is None:
                        return 1
                    if (
                        not self._native_receiving_cfe2_2026
                        and stage is not None
                        and stage.receipt is receipt
                        and stage.stage == "completed"
                    ):
                        return 1
                    if (
                        self._worker is not job.worker
                        or job.worker.controller is not job.controller
                        or job._host_stop
                        or job._outer is None
                    ):
                        raise ValueError("CID stop source tuple is stale")
                    if not job._outer.is_alive() or job._outer_exit is not None:
                        stage = job._getter_stop_stage2026
                        if (
                            receipt is None
                            or stage is None
                            or stage.receipt is not receipt
                            or stage.stage != "outer_requested"
                            or stage.outer is not job._outer
                            or job._outer.is_alive()
                            or type(job._outer_exit) is not int
                            or job._outer_exit not in (0, 1)
                        ):
                            raise ValueError("CID stop source tuple is stale")
                    if receipt is not None:
                        if (
                            type(receipt) is not _NativeGetterStopReceipt2026
                            or receipt.producer != "5f030"
                            or receipt.job is not job
                            or receipt.worker is not job.worker
                            or receipt.controller is not job.controller
                        ):
                            raise ValueError("Retained native getter stop is foreign")
                        job._validate_getter_stop_stage2026(receipt)
                        stage = job._getter_stop_stage2026
                        if stage is None or stage.stage not in (
                            "child_requested",
                            "outer_requested",
                        ):
                            raise ValueError("Retained native getter stop is complete")
                        if not self._native_receiving_cfe2_2026 and (
                            receipt.producer != "5f030"
                        ):
                            raise ValueError(
                                "Only retained 5f030 may resume after CFE2 clear"
                            )
                    else:
                        if self._pending_getter_stop_origin2026 is not None:
                            raise ValueError("Getter stop origin is already pending")
                        origin = _NativeGetterStopOrigin2026(
                            self,
                            job,
                            job.worker,
                            job.controller,
                            job._native_start_generation2026,
                            job._sequence,
                            job._lease,
                            get_ident(),
                            "5f030",
                            None,
                        )
                        self._pending_getter_stop_origin2026 = origin
                        try:
                            receipt = job._record_getter_stop_14_2026(
                                producer="5f030", origin=origin
                            )
                        finally:
                            if self._pending_getter_stop_origin2026 is origin:
                                self._pending_getter_stop_origin2026 = None
                    self._cancelled.set()
                    break
            finally:
                if acquired and job is not None:
                    job._lock.release()

        assert job is not None and receipt is not None
        child = job._request_getter_child_stop_2026(receipt)
        while child.is_alive():
            child.join(min(0.05, budget.remaining()))
        budget.remaining()
        outer, publish_event = job._request_getter_outer_stop_2026(receipt)
        if publish_event:
            self._publish_getter_stop_event_2026(job, receipt)
        while outer.is_alive():
            outer.join(min(0.05, budget.remaining()))
        while not finished.wait(min(0.05, budget.remaining())):
            pass
        budget.remaining()
        self._complete_getter_stop_2026(job, receipt)
        return 0

    def native_cancelled(self) -> bool:
        """Actual typCallBacks[12] observation of the owned controller cancel flag."""
        return self._cancelled.is_set()

    def process_before_reprogramming(self, parameters, device) -> int:
        """64c00's normal-file path or bounded source-issued VBF resume."""
        from scripts.calibration_2026 import native2026_cpu_values
        from scripts.programming_2026_common import (
            NativeGeneralParameters2026,
            is_native_exception2026,
        )

        metadata = self._metadata
        if metadata is None:
            return 3008
        first_cpu = native2026_cpu_values(metadata, 0)
        is_vbf = ".vbf" in first_cpu.get("cpuimagename", "")

        if not is_vbf:
            if not self._lock.acquire(blocking=False):
                raise ValueError("CUW phase is active")
            try:
                if (
                    type(parameters) is not NativeGeneralParameters2026
                    or type(device) is not J2534Device2026
                ):
                    raise TypeError(
                        "Concrete global parameters and J2534 device required"
                    )
                enabled = parameters.boolean_with_keys(
                    metadata.vehicle.get("kindofecu", ""),
                    first_cpu.get("cputype", ""),
                    metadata.vehicle.get("contacttype", ""),
                    "FlagToChangeWFSE",
                )
                if enabled:
                    if device.device_id is None:
                        raise ValueError("Open J2534 device required for WFSE voltage")
                    try:
                        device.set_programming_voltage(15, 0xFFFFFFFE)
                    except BaseException as error:
                        if is_native_exception2026(error):
                            status = self.check_j2534_connection()
                            return status if status else 3008
                        raise
                return 0
            finally:
                self._lock.release()

        if (
            type(parameters) is not NativeGeneralParameters2026
            or type(device) is not J2534Device2026
        ):
            raise TypeError("Concrete global parameters and J2534 device required")
        # This lookup throws the native literal2 callback error outside64c00's catch.
        enabled = parameters.boolean_with_keys(
            metadata.vehicle.get("kindofecu", ""),
            first_cpu.get("cputype", ""),
            metadata.vehicle.get("contacttype", ""),
            "FlagToChangeWFSE",
        )
        job = self._thread_job
        request = None
        queued = False
        try:
            if enabled:
                if device is not self.engine_runtime_device():
                    raise ValueError("Actual paired engine J2534 device required")
                if device.device_id is None:
                    raise ValueError("Open J2534 device required for WFSE voltage")
                device.set_programming_voltage(15, 0xFFFFFFFE)
            if job is None:
                raise NotImplementedError(
                    "Cold VBF execution requires the actual persistent native worker"
                )
            request = job._begin_vbf_process_before2026()
            worker = self.worker
            worker._acknowledge_vbf_process_before2026(job, request)
            job._wait_vbf_process_before2026(request)
            with self.prepare_vbf_resume_execution(job, request):
                request = worker._prepare_vbf_resume2026(job, request)
            session = request.previous_session._next_vbf_prepare2026(job, request)
            job._queue_vbf_prepare2026(request, session)
            queued = True
            return 0
        except BaseException as error:
            if job is not None and request is not None and not queued:
                try:
                    job._abandon_vbf_process_before2026(request)
                except BaseException as cleanup_error:  # noqa: BLE001 - preserve the triggering fault
                    error.add_note(
                        "VBF request cleanup: " + type(cleanup_error).__name__
                    )
            if is_native_exception2026(error):
                status = self.check_j2534_connection()
                return status if status else 3008
            raise

    @contextmanager
    def prepare_vbf_resume_execution(self, job, request):
        """Authorize only114's FULL36800 body on the external receipt issuer."""
        from scripts.cuw_engine_threads import (
            EngineThreadJob2026,
            validate_vbf_process_before2026,
        )

        if type(job) is not EngineThreadJob2026 or job is not self._thread_job:
            raise TypeError("Actual issued native thread job required")
        job.validate_owner(self)
        request = validate_vbf_process_before2026(request, job, states=("parked",))
        worker = self.worker
        if (
            job.worker is not worker
            or not job.native_worker_exists
            or job.is_native_thread
        ):
            raise ValueError("Actual external parked-child VBF resume required")
        with job._lock:
            request = validate_vbf_process_before2026(request, job, states=("parked",))
            job._validate_vbf_issuer2026(request)
            with worker._lock:
                origin = job._issue_vbf_cpu_successor_36800_2026(request, worker=worker)
        with self._phase_state_lock:
            conflict = self._prepare_prefix_owner is not None
            if not conflict:
                owner = (get_ident(), worker, job)
                self._prepare_prefix_owner = owner
                self._prepare_prefix_vbf_request2026 = request
                self._prepare_prefix_vbf_cpu_origin2026 = origin
        if conflict:
            if origin is not None:
                job._retire_vbf_cpu_successor_36800_2026(origin)
            raise ValueError("Native prepare prefix is already executing")
        try:
            yield worker
        finally:
            with self._phase_state_lock:
                if self._prepare_prefix_owner is owner:
                    self._prepare_prefix_owner = None
                    self._prepare_prefix_vbf_request2026 = None
                    self._prepare_prefix_vbf_cpu_origin2026 = None
            if origin is not None:
                job._retire_vbf_cpu_successor_36800_2026(origin)

    def judge_usb_repro_suzuki(self) -> tuple[int, bool]:
        """CUW65830 status and Boolean out value, from loaded native metadata."""
        metadata = self._metadata
        if metadata is None:
            return 9101, False
        return 0, (
            metadata.format_version == 12
            and metadata.vehicle.get("kindofecu", "") == "0795"
        )

    def judge_flashable(self, region: int) -> NativeFlashabilityResult2026:
        """Run the source 62330 traversal and its exact once-only 49010 commit."""
        self._reject_failed_cold_file_admission2026()
        if type(region) is not int or region not in (1, 2, 3, 4):
            raise ValueError("Native flashability region must be1..4")
        if not self._lock.acquire(blocking=False):
            raise ValueError("CUW phase is active")
        invocation = None
        try:
            with self._phase_state_lock:
                if self._active or self._phase_thread is not None:
                    raise ValueError("Native flashability requires an idle engine")
            self._require_native_phase_idle()
            from scripts.cuw_engine_threads import (
                EngineThreadJob2026,
                _has_vbf_request2026,
            )

            job = self._thread_job
            if job is not None:
                if type(job) is not EngineThreadJob2026 or job.engine is not self:
                    raise ValueError("Current concrete native worker job required")
                if (
                    job.native_work_pending
                    or _has_vbf_request2026(job)
                    or job._pending_getter_next_entry_3d120_2026 is not None
                ):
                    raise ValueError("Pending native work blocks flashability judging")
            if (
                self._pending_file_admission_origin2026 is not None
                or self._pending_initial_getter_reset2026 is not None
                or self._pending_getter_stop_origin2026 is not None
                or self._worker_replacement_thread is not None
            ):
                raise ValueError("Pending native engine origin blocks file judging")
            worker = self.worker
            worker.validate_source(self)
            metadata = self.native_metadata
            self._validate_persistence_source(metadata)
            if not isinstance(worker, _NativeFlashabilityJudge2026):
                raise TypeError("Native 62330 judge is unavailable")
            if self._judge_flashable_invocation2026 is not None:
                raise ValueError("Nested native flashability invocation rejected")
            persistence = self._persistence
            invocation = _JudgeFlashableInvocation2026(
                self,
                worker,
                region,
                get_ident(),
                self.configuration,
                worker._getter_reset_epoch2026,
                self._file_sources,
                persistence,
                None if persistence is None else persistence.state,
                worker._flow_file_index2026,
                worker.source_state.current_global_cpu_index,
                None if persistence is None else persistence.state.write_cpu_index,
                (
                    None
                    if persistence is None
                    else persistence.state.calibration_file_index
                ),
            )
            self._judge_flashable_invocation2026 = invocation
            result = worker._judge_flashable_62330_2026(region)
            if type(result) is not NativeFlashabilityResult2026:
                raise TypeError("Native 62330 result must use its frozen result type")
            if not invocation.entered or (
                invocation.commit_started and not invocation.commit_completed
            ):
                raise ValueError(
                    "Native 62330 traversal did not complete its source tail"
                )
            self._validate_flashability_result2026(result, worker)
            return result
        finally:
            if self._judge_flashable_invocation2026 is invocation:
                self._judge_flashable_invocation2026 = None
            self._lock.release()

    def _validate_flashability_result2026(self, result, worker) -> None:
        from scripts.cuw_file_services import NativeFileView2026

        sources = self._file_sources
        metadata = self.native_metadata
        if result.file_sources is not sources:
            raise ValueError("Native flashability result changed its FILE source set")
        admission_digest = (
            metadata.source_sha256 if sources is None else sources.admission_sha256
        )
        if result.admission_source_sha256 != admission_digest:
            raise ValueError("Native flashability result changed its admission source")
        flow_index = worker._flow_file_index2026
        persistence = self._persistence
        recovery_index = (
            0 if persistence is None else persistence.state.calibration_file_index
        )
        if (
            result.flow_file_index != flow_index
            or result.recovery_file_index != recovery_index
        ):
            raise ValueError("Native flashability result omitted final D71C or ED54")
        if sources is None:
            expected_kind, expected_index, expected_digest = (
                "none",
                None,
                metadata.source_sha256,
            )
        elif not sources.has_file_vector:
            view = sources.admission_view2026()
            if (
                view.source_container is not metadata.source_container
                or view.source_sha256 != metadata.source_sha256
            ):
                raise ValueError("Current-only FILE pointer differs from admission")
            expected_kind, expected_index, expected_digest = (
                "none",
                None,
                view.source_sha256,
            )
        else:
            matches = tuple(
                index
                for index, item in enumerate(sources.files)
                if item.source_container is metadata.source_container
                and item.source_sha256 == metadata.source_sha256
            )
            if len(matches) == 1:
                view = sources.file_view2026(matches[0])
            else:
                whole_matches = []
                for start, _width, whole in sources.delta_groups:
                    group = sources.group_view2026(start)
                    if (
                        group is not None
                        and whole.source_container is metadata.source_container
                        and whole.source_sha256 == metadata.source_sha256
                    ):
                        whole_matches.append(group.whole)
                if len(whole_matches) != 1:
                    raise ValueError("Current native FILE pointer is not in its table")
                view = whole_matches[0]
            if type(view) is not NativeFileView2026:
                raise TypeError("Native FILE pointer view is not concrete")
            expected_kind, expected_index, expected_digest = (
                view.kind,
                view.file_index,
                view.source_sha256,
            )
        if (
            result.live_file_kind != expected_kind
            or result.live_file_index != expected_index
            or result.live_file_sha256 != expected_digest
        ):
            raise ValueError("Native flashability result differs from the live FILE")

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
    def _require_prepare_dispatch(worker, phase: int, *, job=None, lease=None) -> None:
        if (
            phase == 1
            and worker.native_prepare_handshake == 1
            and not worker.control_state.recovery_mode
        ):
            if job is not None and lease is not None:
                job._validate_ordinary_prepare_dispatch_36800_2026(worker, phase, lease)
                return
            raise ValueError(
                "Consume the native prepare reentry before dispatching its phase"
            )

    def _require_native_phase_idle(self) -> None:
        if self._thread_job is not None and self._thread_job.native_work_pending:
            raise ValueError("Native worker has not reached its late idle checkpoint")

    def reserve_phase(self, controller, phase: int, *, _vbf_request=None):
        """Reserve the real engine phase before145 starts its native worker thread."""
        from scripts.cuw_engine_threads import (
            _has_vbf_request2026,
            _issue_thread_phase_lease,
            validate_vbf_process_before2026,
        )
        from scripts.programming_2026_common import ControlCommPhase2026

        if type(controller) is not ControlCommPhase2026:
            raise TypeError("Concrete native controller required")
        if type(phase) is not int or phase not in (0, 1, 2):
            raise ValueError("Native outer worker phase must be0..2")
        worker = self.bind_worker(controller)
        if _vbf_request is None:
            job = self._thread_job
            if job is not None and _has_vbf_request2026(job):
                raise ValueError(
                    "Outstanding source-issued VBF resume blocks ordinary phase"
                )
            self._require_prepare_dispatch(worker, phase)
        elif phase != 1:
            raise ValueError("VBF resume receipt only admits native phase1")
        if not self._lock.acquire(blocking=False):
            raise ValueError("CUW phase is active")
        try:
            self._require_native_phase_idle()
            self._validate_persistence_source(self.native_metadata)
            if _vbf_request is not None:
                job = self._thread_job
                if job is None:
                    raise ValueError("Actual VBF thread job required for reservation")
                _vbf_request = validate_vbf_process_before2026(
                    _vbf_request, job, states=("queued",)
                )
            lease = _issue_thread_phase_lease(
                self,
                controller,
                phase,
                _vbf_request=_vbf_request,
            )
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
            request = lease.vbf_request
            lease._release()
            try:
                if request is not None:
                    job = self._thread_job
                    if job is None:
                        raise ValueError("VBF phase lease lost its native job")
                    job._release_vbf_phase2026(request, lease)
            finally:
                self._active = False
                self._worker_phase = None
                self._phase_finished.set()
                self._lock.release()

    def _reserve_getter_entry_34cb0_2026(self, job, session, record):
        """Reserve first raw-CONTROL entry without publishing its native phase."""
        from scripts.cuw_engine_threads import (
            EngineThreadJob2026,
            _GetterEntryStartBinding2026,
            _issue_thread_phase_lease,
        )

        if type(job) is not EngineThreadJob2026 or job is not self._thread_job:
            raise ValueError("Current native getter job required")
        previous_phase = job._validate_getter_entry_reservation2026(session, record)
        binding = job._getter_entry_binding2026
        if (
            type(binding) is not _GetterEntryStartBinding2026
            or binding.session is not session
            or binding.record is not record
        ):
            raise ValueError("Exact lexical getter binding required")
        binding.previous_phase = previous_phase
        if not self._lock.acquire(blocking=False):
            raise ValueError("CUW phase is active")
        try:
            if job is not self._thread_job or job.worker is not self._worker:
                raise ValueError("Getter reservation owner changed")
            self._require_native_phase_idle()
            self._validate_persistence_source(self.native_metadata)
            if self._worker_phase != previous_phase:
                raise ValueError("Getter reservation phase snapshot changed")
            lease = _issue_thread_phase_lease(self, job.controller, 0)
            with self._phase_state_lock:
                if job is not self._thread_job or self._active:
                    lease._release()
                    raise ValueError("Getter reservation lost engine ownership")
                self._cancelled.clear()
                self._phase_finished = Event()
                self._active = True
                self._phase_thread = None
                # 34cb0 writes the native phase only after its reset prefix.
            return lease
        except BaseException:
            self._lock.release()
            raise

    def _abort_getter_entry_34cb0_2026(self, origin: object) -> None:
        """Release only an unpublished first-entry reservation; keep source writes."""
        from scripts.cuw_engine_threads import (
            EngineThreadJob2026,
            _NativeGetterEntryOrigin2026,
        )

        if type(origin) is not _NativeGetterEntryOrigin2026:
            raise TypeError("Exact native getter first-entry origin required")
        job = origin.job
        if type(job) is not EngineThreadJob2026 or job is not self._thread_job:
            raise ValueError("Current native getter job required for abort")
        job._validate_getter_entry_34cb0_2026(origin)
        lease = origin.lease
        if (
            origin.engine is not self
            or job._lease is not lease
            or lease.state != "reserved"
            or lease.phase != 0
            or self._phase_thread is not None
            or not self._active
            or self._worker_phase != origin.previous_phase
        ):
            raise ValueError("Unpublished getter reservation required for abort")
        job._abort_getter_entry_34cb0_2026(origin)
        lease._release()
        with self._phase_state_lock:
            self._active = False
            self._phase_thread = None
            self._worker_phase = origin.previous_phase
            self._phase_finished.set()
        self._lock.release()

    def _abort_getter_entry_reservation_34cb0_2026(
        self, job, session, record, lease
    ) -> None:
        """Revoke a reserved raw getter if opaque origin construction failed."""
        from scripts.cuw_engine_threads import EngineThreadJob2026

        if type(job) is not EngineThreadJob2026 or job is not self._thread_job:
            raise ValueError("Current native getter job required for abort")
        binding = job._getter_entry_binding2026
        previous_phase = None if binding is None else binding.previous_phase
        if (
            (type(previous_phase) is not int and previous_phase is not None)
            or self._worker_phase != previous_phase
            or self._phase_thread is not None
            or not self._active
            or lease.state != "reserved"
            or lease.phase != 0
        ):
            raise ValueError("Unpublished getter reservation required for abort")
        consumed_phase = job._abort_getter_entry_reservation2026(session, record, lease)
        if consumed_phase != previous_phase:
            raise ValueError("Getter reservation phase changed during abort")
        lease._release()
        with self._phase_state_lock:
            self._active = False
            self._phase_thread = None
            self._worker_phase = previous_phase
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
        from scripts.cuw_engine_threads import _has_vbf_request2026

        if lease is None:
            worker = self.bind_worker(controller)
            job = self._thread_job
            if job is not None and _has_vbf_request2026(job):
                raise ValueError(
                    "Outstanding source-issued VBF resume blocks ordinary phase"
                )
            self._require_prepare_dispatch(worker, phase)
            if not self._lock.acquire(blocking=False):
                raise ValueError("CUW phase is active")
            try:
                self._require_native_phase_idle()
            except BaseException:
                self._lock.release()
                raise
            request = None
            job = None
        else:
            from scripts.cuw_engine_threads import (
                validate_thread_phase_lease,
                validate_vbf_process_before2026,
            )

            validate_thread_phase_lease(lease, self, controller=controller, phase=phase)
            if not self._active or self._phase_thread is not None:
                raise ValueError("Unadopted native worker reservation required")
            worker = self._worker
            if worker is None or worker.controller is not controller:
                raise ValueError("Reserved native worker identity changed")
            job = self._thread_job
            request = lease.vbf_request
            if request is None:
                if job is not None and _has_vbf_request2026(job):
                    raise ValueError(
                        "Outstanding source-issued VBF resume blocks ordinary phase"
                    )
                self._require_prepare_dispatch(worker, phase, job=job, lease=lease)
            else:
                if job is None or phase != 1:
                    raise ValueError("Actual phase1 VBF resume lease required")
                request = validate_vbf_process_before2026(
                    request, job, states=("reserved",), lease=lease
                )
        runtime = controller.runtime
        original_native_cancelled = runtime.native_cancelled
        primary_error: BaseException | None = None
        try:
            if lease is not None:
                lease._adopt()
                if request is not None:
                    if job is None:
                        raise ValueError("VBF phase lease lost its native job")
                    request = job._consume_vbf_phase2026(request, lease)
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
                # 3cb90 copies the requested outer phase into worker BD0;
                # 59ab0 imports that byte into CONTROL +978 before raw Execute.
                self.dh_state._native_comm_phase = phase
                if request is None:
                    worker._phase_started(phase)
                else:
                    worker._phase_started(phase, _vbf_request=request)
                self._import_identifier_context(actual_control_import=True)
                yield worker
                self._end_native_control_context2026(controller)
                worker._phase_finished(phase)
            except BaseException as error:
                primary_error = error
                self._end_native_control_context2026(controller, error)
                try:
                    worker._phase_failed(error)
                except BaseException as cleanup_error:  # noqa: BLE001 - preserve the original failure
                    error.add_note(
                        "Worker failure cleanup: " + type(cleanup_error).__name__
                    )
                raise
        except BaseException as error:
            primary_error = error
            raise
        finally:
            self._end_native_control_context2026(controller)
            self._controller_export_target2026 = None
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
                try:
                    lease._release()
                    if request is not None:
                        if job is None:
                            raise ValueError("VBF phase lease lost its native job")
                        job._release_vbf_phase2026(request, lease)
                except BaseException as cleanup_error:
                    if primary_error is None:
                        raise
                    primary_error.add_note(
                        "Native phase lease cleanup: " + type(cleanup_error).__name__
                    )
                finally:
                    self._lock.release()
            else:
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
