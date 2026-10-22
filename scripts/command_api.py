"""Typed native CommandAPI result composition and explicit host provider joins.

No Windows ABI emulation or device discovery. Individually recovered logical
facade routes coexist with explicit host joins; the whole API remains open.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from scripts.active_replay import ActiveReplay
from scripts.active_tests import (
    ActiveSupport,
    ActiveTest,
    ActiveTestCatalog,
    ActiveTestInitialization,
)
from scripts.data_monitor import MonitorPacket, MonitorSetup, run_monitor_commands
from scripts.database_resources import (
    AdsDdrReport,
    DdrP5Report,
    DdrPacketLog,
    DdrRecordSamples,
    DdrReport,
    NativeRamReader,
    capture_ads_ddr_report,
    capture_ddr_p5_report,
    capture_ddr_p5_saved_log,
    capture_ddr_record_samples,
    capture_ddr_report,
    capture_ddr_saved_log,
    ddr_report_support_values,
)
from scripts.drive_recorder import NativeDrsExecutor, NativeVimClient
from scripts.freeze_p5 import P5FreezeSignal, P5FreezeState, P5SignalMetadata, P5Value
from scripts.local_files import read_regular
from scripts.monitor_support import MonitorSupportCache
from scripts.native_communication import NativeCommunication
from scripts.profiles import VehicleCatalog, VehicleProfile
from scripts.signal_display import render_signal
from scripts.text_resources import ResourceText, TextResources
from scripts.toyota import ToyotaCodecError
from scripts.toyota_analysis import (
    COMMON12_SHA256,
    COMMON18_SHA256,
    DCM35_SHA256,
    ROB18_SHA256,
    AnalysisResult,
    DcmAnalysis,
    DcmAnalysisResult,
    DcmP5Analysis,
    PlainAnalysis,
    PlainAnalysisResult,
    PlainFreezeData,
    PlainTimestamp,
    RoBAnalysis,
    RoBAnalysisResult,
    RoBValue,
)
from scripts.toyota_saved_ffd import (
    ADS_IMAGE_SOURCE_SHA256,
    ADS_OPERATION_SOURCE_SHA256,
    IMAGE_P4_SOURCE_SHA256,
    IMAGE_P5_SOURCE_SHA256,
    LCS_SOURCE_SHA256,
    PCS_OPERATION_SOURCE_SHA256,
    RC_IMAGE_SOURCE_SHA256,
    TSS3_SOURCE_SHA256,
    AdsImageRequest18,
    AdsImageSavedResult,
    AdsImageSource,
    AdsSavedOperationResult,
    ImageP4SavedResult,
    ImageP4Source,
    ImageP5Request18,
    ImageP5SavedResult,
    ImageP5Source,
    PcsOperationSource,
    PcsSavedOperationResult,
    RcImageRequest18,
    RcImageSavedResult,
    RcImageSource,
    SavedFfdSource,
    Tss3SavedFreeze,
    Tss3SavedOperationResult,
    capture_ads_image_saved,
    capture_ads_saved_operations,
    capture_image_p4_saved,
    capture_image_p5_saved,
    capture_lcs_saved_operations,
    capture_pcs_saved_operations,
    capture_rc_image_saved,
    capture_tss3_saved_operations,
)
from scripts.toyota_session import Cancelled, Limits, ToyotaSession
from scripts.toyota_workflows import ToyotaWorkflows

SOURCE_SHA256 = {
    12: "2f96c51899bab6b9a1dd6cadc51dcd40bc885ed600c1c497d64786fdb9a7130c",
    18: "43913a3baeef678b70dd3f7a533575824d9d88e2acb61acb23702983e5b337f3",
}


PLAIN_NORMAL_SHA256 = {
    12: (
        "1e8424cef67f9566ce9128f6d2a571429b2394ac288fe8b168375253e4886e15",
        "6acb323475cf41520d4d05ff48484fccd6e4ebb4c95691927e583143fdea0f7f",
        "8887ae4549e49df00a199162272c5a5036f58752af12470aa19a15212bcf2fec",
    ),
    18: (
        "10dc84495bca356be967e7c055734bc9f5b31d5e3ea64ebea996d85d3f42473f",
        "2e6669768703dd2e3a1d29fb516f76db5324d3ac0c7ea6a292d610b9a672ad2e",
        "053f22b16e5feb7d7dd3b55ad6fdd12e545a0562cc87bf6cb9b7694c5229fd06",
    ),
}


def _uint(value: int, maximum: int, name: str) -> None:
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError(f"{name} is outside its native unsigned range")


@dataclass(frozen=True)
class CommandSource:
    version: int
    sha256: str

    def __post_init__(self) -> None:
        if (
            type(self.version) is not int
            or SOURCE_SHA256.get(self.version) != self.sha256
        ):
            raise ValueError("Unreconciled CommandAPI source/version")

    @classmethod
    def from_file(cls, path: str | Path, *, version: int) -> CommandSource:
        """Identify BYOD bytes without loading the PE or calling its exports."""
        return cls(
            version,
            hashlib.sha256(read_regular(path, limit=8 * 1024 * 1024)).hexdigest(),
        )


@dataclass(frozen=True)
class CommandStatus:
    """Native receive +0x14 status selects +0x18 returned error code."""

    status: int = 0
    error: int = 0

    def __post_init__(self) -> None:
        _uint(self.status, 0xFFFFFFFF, "Receive status")
        _uint(self.error, 0xFFFFFFFF, "Receive error")

    @property
    def return_code(self) -> int:
        return self.error if self.status else 0


@dataclass(frozen=True)
class VinReply:
    """CGetVINRcv logical fields; length includes its terminal byte.

    Payload is an owned byte copy, never a native pointer. Error replies need no
    valid payload because the facade does not dereference it on that branch.
    """

    state: CommandStatus
    length: int
    payload: bytes

    def __post_init__(self) -> None:
        _uint(self.length, 0xFFFF, "VIN receive length")
        if not isinstance(self.state, CommandStatus) or type(self.payload) is not bytes:
            raise TypeError("VIN requires typed status and immutable bytes")
        if (
            not self.state.status
            and self.length > 1
            and len(self.payload) < self.length - 1
        ):
            raise ValueError("VIN pointer extent is shorter than its reported length")


@dataclass(frozen=True)
class VinResult:
    return_code: int
    value: bytes

    def __post_init__(self) -> None:
        _uint(self.return_code, 0xFFFFFFFF, "Facade return code")
        if type(self.value) is not bytes:
            raise TypeError("VIN result must own immutable bytes")


@dataclass(frozen=True)
class VimSupportResult:
    return_code: int
    support: int

    def __post_init__(self) -> None:
        _uint(self.return_code, 0xFFFFFFFF, "Facade return code")
        _uint(self.support, 255, "VIM support byte")


@dataclass(frozen=True)
class VimInformation:
    """API result fields +04/+06/+08/+0a/+0c/+10, six received uint16s.

    Native widens the last two to uint32 slots; no field names are guessed.
    """

    field04: int = 0
    field06: int = 0
    field08: int = 0
    field0a: int = 0
    field0c: int = 0
    field10: int = 0

    def __post_init__(self) -> None:
        for value in (
            self.field04,
            self.field06,
            self.field08,
            self.field0a,
            self.field0c,
            self.field10,
        ):
            _uint(value, 65535, "VIM information field")


@dataclass(frozen=True)
class VimInformationResult:
    return_code: int
    information: VimInformation

    def __post_init__(self) -> None:
        _uint(self.return_code, 0xFFFFFFFF, "Facade return code")
        if not isinstance(self.information, VimInformation):
            raise TypeError("VIM information requires a typed owned value")


@dataclass(frozen=True)
class ActiveFacadeEntry:
    """16-byte logical API item: signal+00, CString+04/+08, DWORD+0c."""

    signal_id: int
    name: bytes
    short_name: bytes
    control_value: int

    def __post_init__(self) -> None:
        _uint(self.signal_id, 65535, "Active facade signal")
        _uint(self.control_value, 0xFFFFFFFF, "Active facade control/help field")
        if type(self.name) is not bytes or type(self.short_name) is not bytes:
            raise TypeError("Active facade strings require owned bytes")


@dataclass(frozen=True)
class ActiveFacadeGroup:
    name: bytes
    signal_ids: tuple[int, ...]

    def __post_init__(self) -> None:
        if type(self.name) is not bytes or type(self.signal_ids) is not tuple:
            raise TypeError("Active facade group requires owned bytes and tuple IDs")
        for value in self.signal_ids:
            _uint(value, 65535, "Active group member")


@dataclass(frozen=True)
class ActiveFacadeResult:
    return_code: int
    entries: tuple[ActiveFacadeEntry, ...] = ()
    groups: tuple[ActiveFacadeGroup, ...] = ()
    description: bytes = b""

    def __post_init__(self) -> None:
        _uint(self.return_code, 0xFFFFFFFF, "Facade return code")
        if type(self.entries) is not tuple or not all(
            isinstance(x, ActiveFacadeEntry) for x in self.entries
        ):
            raise TypeError("Active facade result requires typed entries")
        if type(self.groups) is not tuple or not all(
            isinstance(x, ActiveFacadeGroup) for x in self.groups
        ):
            raise TypeError("Active facade result requires typed groups")
        if type(self.description) is not bytes:
            raise TypeError("Active facade description requires owned bytes")


@dataclass(frozen=True)
class TranslationFacadeEntry:
    """Native 8-byte logical item: CString+00 and received WORD+04."""

    value: bytes
    attribute: int

    def __post_init__(self) -> None:
        if type(self.value) is not bytes:
            raise TypeError("Translation result requires owned byte string")
        _uint(self.attribute, 65535, "Translation result attribute")


@dataclass(frozen=True)
class TranslationFacadeResult:
    return_code: int
    entries: tuple[TranslationFacadeEntry, ...] = ()

    def __post_init__(self) -> None:
        _uint(self.return_code, 0xFFFFFFFF, "Facade return code")
        if type(self.entries) is not tuple or not all(
            isinstance(x, TranslationFacadeEntry) for x in self.entries
        ):
            raise TypeError("Translation result requires typed entries")


@dataclass(frozen=True)
class EcuGroupEntry:
    identifier: int
    name: bytes

    def __post_init__(self) -> None:
        _uint(self.identifier, 65535, "ECU group identifier")
        if type(self.name) is not bytes:
            raise TypeError("ECU group name requires owned native bytes")


@dataclass(frozen=True)
class EcuGroupResult:
    return_code: int
    entries: tuple[EcuGroupEntry, ...] = ()

    def __post_init__(self) -> None:
        _uint(self.return_code, 0xFFFFFFFF, "Facade return code")
        if type(self.entries) is not tuple or not all(
            isinstance(x, EcuGroupEntry) for x in self.entries
        ):
            raise TypeError("ECU groups require typed entries")


# Whole47c-byte API row offsets, in the source CCmdDdrInfo list order.
DDR_EXTENSION_ARRAY_OFFSETS = (
    0x374,
    0x388,
    0x39C,
    0x3B0,
    0x44C,
    0x460,
    0x3D4,
    0x3E8,
    0x3FC,
    0x410,
)
DDR_EXTENSION_SOURCE_ARRAY_OFFSETS = (
    0x4DC,
    0x4F0,
    0x504,
    0x518,
    0x52C,
    0x540,
    0x5FC,
    0x610,
    0x624,
    0x638,
)
DDR_EXTENSION_FLAG_OFFSETS = tuple(range(0x3C4, 0x3D2)) + tuple(range(0x474, 0x47B))
DDR_EXTENSION_NESTED_OFFSETS = (0x424, 0x438)


@dataclass(frozen=True)
class DdrExtensionValues:
    """Actual52730 logical lists/bytes; offsets above retain native identities.

    Arrays follow SOURCE_ARRAY_OFFSETS; flags follow source55c+12*n (14)
    then67c+12*n (7); nested lists are source64c/660. This is the extension
    of an existing DDR row, not a finished CCmdDdrInfo or serialized GFC row.
    """

    arrays: tuple[bytes, ...]
    flags: bytes
    nested: tuple[tuple[bytes, ...], tuple[bytes, ...]]

    def __post_init__(self) -> None:
        if (
            type(self.arrays) is not tuple
            or len(self.arrays) != 10
            or any(type(x) is not bytes for x in self.arrays)
        ):
            raise TypeError("DDR extension requires ten owned byte arrays")
        if type(self.flags) is not bytes or len(self.flags) != 21:
            raise TypeError("DDR extension requires twenty-one native bytes")
        if (
            type(self.nested) is not tuple
            or len(self.nested) != 2
            or any(
                type(group) is not tuple or any(type(x) is not bytes for x in group)
                for group in self.nested
            )
        ):
            raise TypeError("DDR extension requires two typed byte-array lists")
        if (
            sum(map(len, self.nested)) > 100_000
            or sum(map(len, self.arrays)) + sum(len(x) for g in self.nested for x in g)
            > 64 * 1024 * 1024
        ):
            raise ValueError("DDR extension exceeds host materialization budget")


@dataclass(frozen=True)
class EcuGroupContext:
    """Explicit CShareData9/12 WORD slots and actual primitive lookup statuses."""

    vehicle_key: int | None
    default_group: int | None
    vehicle_lookup_status: int = 0
    default_lookup_status: int = 0

    def __post_init__(self) -> None:
        for value in (self.vehicle_key, self.default_group):
            if value is not None:
                _uint(value, 65535, "Shared group WORD")
        _uint(self.vehicle_lookup_status, 0xFFFFFFFF, "GetData9 status")
        _uint(self.default_lookup_status, 0xFFFFFFFF, "GetData12 status")


@dataclass(frozen=True)
class SelectedEcuGroup:
    identifier: int
    name_id: int
    name: str
    source_row: bytes


@dataclass(frozen=True)
class EcuGroupSelection:
    return_code: int
    entries: tuple[SelectedEcuGroup, ...]
    context: EcuGroupContext
    source_sha256: str


@dataclass(frozen=True)
class DcmP5FacadeRecord:
    time_status: int
    time_words: tuple[int, ...]
    operation_code: int
    function_name: str
    content_name: str
    network_status: int
    network_names: tuple[str, ...]


@dataclass(frozen=True)
class DcmP5FacadeGroup:
    display_id: int
    name: str
    records: tuple[DcmP5FacadeRecord, ...]


@dataclass(frozen=True)
class DcmP5FacadeResult:
    return_code: int
    groups: tuple[DcmP5FacadeGroup, ...] = ()


@dataclass(frozen=True)
class P5FacadeDisplayInfo:
    pattern_id: int
    label: str
    low: int
    high: int
    flag: int = 0
    core_words: tuple[int, int] = (2, 0)

    def __post_init__(self) -> None:
        for value in (self.pattern_id, self.low, self.high):
            _uint(value, 0xFFFFFFFF, "P5 display info DWORD")
        _uint(self.flag, 255, "P5 display info flag")
        if (
            type(self.label) is not str
            or self.flag != 0
            or type(self.core_words) is not tuple
            or any(type(value) is not int for value in self.core_words)
            or self.core_words != (2, 0)
        ):
            raise ValueError("P5 display info has invalid source fields")


@dataclass(frozen=True)
class P5FacadeConversion:
    """Owned conversion at API signal+18; native pointers are not serialized."""

    multiplier: int = 0
    divisor: int = 0
    offset: int = 0
    unit_id: int = 0
    sign_mode: int = 0
    width: int = 0
    patterns: tuple[P5FacadeDisplayInfo, ...] = ()
    threshold: int = 0
    threshold_high: int = 0
    minimum_raw: int = 0
    maximum_raw: int = 0
    core_words: tuple[int, int] = (1, 0)

    def __post_init__(self) -> None:
        for value in (
            self.multiplier,
            self.divisor,
            self.offset,
            self.threshold,
            self.threshold_high,
            self.minimum_raw,
            self.maximum_raw,
        ):
            _uint(value, 0xFFFFFFFF, "P5 conversion DWORD")
        for value in (self.unit_id, self.width):
            _uint(value, 65535, "P5 conversion WORD")
        _uint(self.sign_mode, 255, "P5 conversion signing BYTE")
        if (
            type(self.core_words) is not tuple
            or any(type(value) is not int for value in self.core_words)
            or self.core_words != (1, 0)
            or type(self.patterns) is not tuple
            or not all(type(row) is P5FacadeDisplayInfo for row in self.patterns)
        ):
            raise TypeError("P5 conversion requires typed owned display info")


@dataclass(frozen=True)
class P5FacadeValue:
    """Native16-byte item: DWORD raw, CString display, BYTE index, DWORD kind."""

    value: int
    display: str
    index: int
    kind: int

    def __post_init__(self) -> None:
        _uint(self.value, 0xFFFFFFFF, "P5 facade raw DWORD")
        _uint(self.index, 255, "P5 facade time BYTE")
        _uint(self.kind, 0xFFFFFFFF, "P5 facade kind DWORD")
        if type(self.display) is not str:
            raise TypeError("P5 facade display requires owned source text")


@dataclass(frozen=True)
class P5FacadeSignal:
    """Logical0x6c P5 signal, including owned conversion and rendered values."""

    pid: int = 0
    name_id: int = 0
    name: str = ""
    unit_name_id: int = 0
    unit: str = ""
    order: int = 0
    selector: int = 0
    precision: int = 0
    conversion: P5FacadeConversion = P5FacadeConversion()
    values: tuple[P5FacadeValue, ...] = ()

    def __post_init__(self) -> None:
        _uint(self.pid, 65535, "P5 facade PID")
        for value in (self.name_id, self.unit_name_id):
            _uint(value, 0xFFFFFFFF, "P5 facade label ID")
        for value in (self.order, self.selector, self.precision):
            _uint(value, 255, "P5 facade signal BYTE")
        if (
            type(self.name) is not str
            or type(self.unit) is not str
            or type(self.conversion) is not P5FacadeConversion
        ):
            raise TypeError("P5 signal requires typed owned metadata")
        if type(self.values) is not tuple or not all(
            type(value) is P5FacadeValue for value in self.values
        ):
            raise TypeError("P5 signal requires typed owned values")


@dataclass(frozen=True)
class P5FacadeDiagnostic:
    """Logical0x4b4 plain result; neutral names retain unnamed native bytes."""

    diag_type: int
    status: int
    code: int
    signature: str
    name_id: int
    name: str
    division_id: int
    division_name: str
    existence_flags: int
    native_byte24: int
    normal_numbers: tuple[int, ...]
    extended_numbers: tuple[int, ...]
    stored_all: int
    signals: tuple[P5FacadeSignal, ...]
    timestamp_flags: int
    timestamps: tuple[P5FacadeSignal, ...]
    odometer_flags: int
    odometer: P5FacadeSignal
    native_byte220: int
    native_word222: int
    native_byte224: int
    absolute_flags: int
    absolute: tuple[P5FacadeSignal, ...]

    def __post_init__(self) -> None:
        for value in (
            self.diag_type,
            self.status,
            self.code,
            self.name_id,
            self.division_id,
            self.existence_flags,
            self.stored_all,
            self.timestamp_flags,
            self.odometer_flags,
            self.absolute_flags,
        ):
            _uint(value, 0xFFFFFFFF, "P5 facade diagnostic DWORD")
        for value in (self.native_byte24, self.native_byte220, self.native_byte224):
            _uint(value, 255, "P5 facade diagnostic BYTE")
        _uint(self.native_word222, 65535, "P5 facade diagnostic WORD")
        if any(
            type(value) is not str
            for value in (self.signature, self.name, self.division_name)
        ):
            raise TypeError("P5 diagnostics require owned source text")
        for values in (self.normal_numbers, self.extended_numbers):
            if type(values) is not tuple:
                raise TypeError("P5 snapshot numbers require owned tuples")
            for value in values:
                _uint(value, 255, "P5 facade snapshot BYTE")
        for values, size in (
            (self.signals, None),
            (self.timestamps, 3),
            (self.absolute, 6),
        ):
            if (
                type(values) is not tuple
                or size is not None
                and len(values) != size
                or not all(type(value) is P5FacadeSignal for value in values)
            ):
                raise TypeError("P5 diagnostic blocks require typed native extents")
        if type(self.odometer) is not P5FacadeSignal:
            raise TypeError("P5 odometer requires typed owned metadata")


@dataclass(frozen=True)
class P5FacadeDiagnostic12:
    """Original12 logical0x228 plain result; neutral names retain unnamed native bytes."""

    diag_type: int
    status: int
    code: int
    signature: str
    name_id: int
    name: str
    division_id: int
    division_name: str
    existence_flags: int
    native_byte24: int
    normal_numbers: tuple[int, ...]
    extended_numbers: tuple[int, ...]
    stored_all: int
    signals: tuple[P5FacadeSignal, ...]
    timestamp_flags: int
    timestamps: tuple[P5FacadeSignal, ...]
    odometer_flags: int
    odometer: P5FacadeSignal
    native_byte220: int
    native_word222: int
    native_byte224: int

    def __post_init__(self) -> None:
        for value in (
            self.diag_type,
            self.status,
            self.code,
            self.name_id,
            self.division_id,
            self.existence_flags,
            self.stored_all,
            self.timestamp_flags,
            self.odometer_flags,
        ):
            _uint(value, 0xFFFFFFFF, "P5 facade diagnostic DWORD")
        for value in (self.native_byte24, self.native_byte220, self.native_byte224):
            _uint(value, 255, "P5 facade diagnostic BYTE")
        _uint(self.native_word222, 65535, "P5 facade diagnostic WORD")
        if any(
            type(value) is not str
            for value in (self.signature, self.name, self.division_name)
        ):
            raise TypeError("P5 diagnostics require owned source text")
        for values in (self.normal_numbers, self.extended_numbers):
            if type(values) is not tuple:
                raise TypeError("P5 snapshot numbers require owned tuples")
            for value in values:
                _uint(value, 255, "P5 facade snapshot BYTE")
        for values, size in (
            (self.signals, None),
            (self.timestamps, 3),
        ):
            if (
                type(values) is not tuple
                or size is not None
                and len(values) != size
                or not all(type(value) is P5FacadeSignal for value in values)
            ):
                raise TypeError("P5 diagnostic blocks require typed native extents")
        if type(self.odometer) is not P5FacadeSignal:
            raise TypeError("P5 odometer requires typed owned metadata")


@dataclass(frozen=True)
class P5DiagnosticAttachment:
    native_id: int = 0
    data: bytes = b""

    def __post_init__(self) -> None:
        _uint(self.native_id, 0xFFFFFFFF, "P5 attachment native ID")
        if type(self.data) is not bytes or len(self.data) > 64 * 1024 * 1024:
            raise ValueError("P5 attachment requires bounded owned file bytes")


@dataclass(frozen=True)
class P5DiagnosticFacadeResult:
    return_code: int
    diagnostics: tuple[P5FacadeDiagnostic, ...] = ()
    attachment: P5DiagnosticAttachment | None = None

    def __post_init__(self) -> None:
        _uint(self.return_code, 0xFFFFFFFF, "P5 diagnostic facade return code")
        if type(self.diagnostics) is not tuple or not all(
            type(row) is P5FacadeDiagnostic for row in self.diagnostics
        ):
            raise TypeError("P5 diagnostics require typed owned rows")
        if (
            self.attachment is not None
            and type(self.attachment) is not P5DiagnosticAttachment
        ):
            raise TypeError("P5 diagnostic attachment requires a typed owned value")


@dataclass(frozen=True)
class P5DiagnosticFacadeResult12:
    return_code: int
    diagnostics: tuple[P5FacadeDiagnostic12, ...] = ()

    def __post_init__(self) -> None:
        _uint(self.return_code, 0xFFFFFFFF, "Original12 P5 return code")
        if type(self.diagnostics) is not tuple or not all(
            type(row) is P5FacadeDiagnostic12 for row in self.diagnostics
        ):
            raise TypeError("Original12 P5 requires typed0x228 rows")


@dataclass(frozen=True)
class DcmFacadeValue:
    value: int
    name: str
    content: str
    unit: str
    format: int


@dataclass(frozen=True)
class DcmFacadeRecord:
    address: int
    items: tuple[DcmFacadeValue, ...]


@dataclass(frozen=True)
class DcmFacadeGroup:
    pid: int
    format: int
    name: str
    records: tuple[DcmFacadeRecord, ...]


@dataclass(frozen=True)
class DcmFlatFacadeRecord:
    byte00: int
    dword04: int
    dword08: int
    dword0c: int
    words10: tuple[int, ...]


@dataclass(frozen=True)
class DcmFacadeResult:
    return_code: int
    flat_records: tuple[DcmFlatFacadeRecord, ...] = ()
    current_words: tuple[int, ...] = (0,) * 5
    current_valid: int = 0
    groups: tuple[DcmFacadeGroup, ...] = ()


@dataclass(frozen=True)
class RoBFacadeValue:
    """Native16-byte value: CString name, DWORD, CString unit, WORD format."""

    name: str = ""
    value: int = 0
    unit: str = ""
    format: int = 0x4000

    def __post_init__(self) -> None:
        if type(self.name) is not str or type(self.unit) is not str:
            raise TypeError("RoB facade labels require owned source Unicode")
        _uint(self.value, 0xFFFFFFFF, "RoB facade value")
        _uint(self.format, 65535, "RoB facade format")


@dataclass(frozen=True)
class RoBFacadeRecord:
    operation_code: int
    label: str
    values: tuple[RoBFacadeValue, ...]
    help: str
    help_type: int


@dataclass(frozen=True)
class RoBFacadeGroup:
    display_id: int
    data_id: int
    name: str
    records: tuple[RoBFacadeRecord, ...]


@dataclass(frozen=True)
class RoBFacadeResult:
    return_code: int
    groups: tuple[RoBFacadeGroup, ...] = ()
    current: tuple[RoBFacadeValue, ...] = (RoBFacadeValue(),) * 3
    time_words: tuple[int, ...] = (0,) * 6


@dataclass(frozen=True)
class SavedOperationFacadeValue:
    scalar: int
    text: str = ""
    status: int = 0

    def __post_init__(self) -> None:
        _uint(self.scalar, 0xFFFFFFFF, "Saved operation native scalar")
        if type(self.text) is not str:
            raise TypeError("Saved operation facade text requires source Unicode")
        _uint(self.status, 255, "Saved operation native value status")


# Exact logical fields of the native0x6c SignalItem row. Container addresses,
# vtables and padding have no portable data meaning and are replaced by tuples.
SAVED_OPERATION_WORD_OFFSETS = (0x00, 0x1C, 0x1E, 0x2C, 0x30)
SAVED_OPERATION_DWORD_OFFSETS = (0x04, 0x20, 0x24, 0x28, 0x48, 0x4C, 0x50, 0x54)
SAVED_OPERATION_BYTE_OFFSETS = (0x14, 0x15, 0x2E)
SAVED_OPERATION_STRING_OFFSETS = (0x08, 0x0C, 0x10)


@dataclass(frozen=True)
class SavedOperationFacadeMetadata:
    """Source-reset row fields; conversion core WORD+1c remains1, not0."""

    words: tuple[int, ...] = (0, 1, 0, 0, 0)
    dwords: tuple[int, ...] = (0,) * 8
    bytes: tuple[int, ...] = (0,) * 3
    strings: tuple[str, ...] = ("", "", "")
    display_entries: tuple[()] = ()

    def __post_init__(self) -> None:
        for values, size, maximum in (
            (self.words, 5, 65535),
            (self.dwords, 8, 0xFFFFFFFF),
            (self.bytes, 3, 255),
        ):
            if type(values) is not tuple or len(values) != size:
                raise TypeError("Saved operation metadata has invalid field extents")
            for value in values:
                _uint(value, maximum, "Saved operation metadata field")
        if (
            type(self.strings) is not tuple
            or len(self.strings) != 3
            or any(type(value) is not str for value in self.strings)
            or type(self.display_entries) is not tuple
            or self.display_entries != ()
        ):
            raise TypeError(
                "Saved operation metadata requires owned native strings/empty display list"
            )


@dataclass(frozen=True)
class SavedOperationFacadeFreeze:
    """Owned native0x6c logical row: reset metadata and first received scalar."""

    values: tuple[SavedOperationFacadeValue, ...]
    metadata: SavedOperationFacadeMetadata = SavedOperationFacadeMetadata()

    def __post_init__(self) -> None:
        if type(self.values) is not tuple or not all(
            type(value) is SavedOperationFacadeValue for value in self.values
        ):
            raise TypeError("Saved operation freeze requires typed owned values")
        if type(self.metadata) is not SavedOperationFacadeMetadata:
            raise TypeError("Saved operation freeze requires typed owned metadata")


@dataclass(frozen=True)
class SavedOperationFacadeResult:
    return_code: int
    freezes: tuple[SavedOperationFacadeFreeze, ...] = ()

    def __post_init__(self) -> None:
        _uint(self.return_code, 0xFFFFFFFF, "Saved operation facade return code")
        if type(self.freezes) is not tuple or not all(
            type(freeze) is SavedOperationFacadeFreeze for freeze in self.freezes
        ):
            raise TypeError("Saved operation result requires typed owned freezes")


@dataclass(frozen=True)
class PlainFacadeItem:
    address: int
    opcode: int
    content: str
    name: str
    value: int
    unit: str
    format: int

    def __post_init__(self) -> None:
        _uint(self.address, 0xFFFFFFFF, "Plain item address")
        _uint(self.opcode, 255, "Plain item opcode")
        _uint(self.value, 0xFFFFFFFF, "Plain item value")
        _uint(self.format, 65535, "Plain item format")
        if any(type(text) is not str for text in (self.content, self.name, self.unit)):
            raise TypeError("Plain item requires source text")


@dataclass(frozen=True)
class PlainFacadeGroup:
    identifier: int
    display_type: int
    pid: int
    name: str
    items: tuple[PlainFacadeItem, ...]

    def __post_init__(self) -> None:
        _uint(self.identifier, 0xFFFFFFFF, "Plain group identifier")
        _uint(self.display_type, 0xFFFFFFFF, "Plain group display type")
        _uint(self.pid, 255, "Plain group PID")
        if (
            type(self.name) is not str
            or type(self.items) is not tuple
            or not all(type(item) is PlainFacadeItem for item in self.items)
        ):
            raise TypeError("Plain group requires owned typed items/text")


@dataclass(frozen=True)
class PlainFacadeFreezeValue:
    scalar: int
    display: str
    status: int

    def __post_init__(self) -> None:
        _uint(self.scalar, 0xFFFFFFFF, "Plain freeze scalar")
        _uint(self.status, 255, "Plain freeze status BYTE")
        if type(self.display) is not str:
            raise TypeError("Plain freeze display requires owned text")


@dataclass(frozen=True)
class PlainFacadeFreezeMetadata:
    """ConvertFrz06ad0 logical0x6c; labels are strings, not P5 label IDs."""

    pid: int
    name: str
    short_name: str
    unit: str
    selector: int
    precision: int
    conversion: P5FacadeConversion
    values: tuple[PlainFacadeFreezeValue, ...]
    native_dword04: int = 0

    def __post_init__(self) -> None:
        _uint(self.pid, 65535, "Plain freeze PID")
        _uint(self.selector, 255, "Plain freeze selector")
        _uint(self.precision, 255, "Plain freeze precision")
        if self.native_dword04 != 0 or type(self.native_dword04) is not int:
            raise ValueError("Plain freeze DWORD04 remains native reset")
        if any(
            type(text) is not str for text in (self.name, self.short_name, self.unit)
        ):
            raise TypeError("Plain freeze labels require owned text")
        if type(self.conversion) is not P5FacadeConversion:
            raise TypeError("Plain freeze requires typed conversion")
        if type(self.values) is not tuple or not all(
            type(value) is PlainFacadeFreezeValue for value in self.values
        ):
            raise TypeError("Plain freeze requires typed native values")


@dataclass(frozen=True)
class PlainFacadeTimestamp:
    """Logical0x160 timestamp projection, including actual P3 ctor defaults."""

    dword00: int = 0
    dword04: int = 0
    scalars: tuple[int, ...] = (0, 0, 0)
    metadata: tuple[SavedOperationFacadeMetadata | PlainFacadeFreezeMetadata, ...] = (
        SavedOperationFacadeMetadata(),
        SavedOperationFacadeMetadata(),
        SavedOperationFacadeMetadata(),
    )
    auxiliary: tuple[int, ...] = (0, 0)

    def __post_init__(self) -> None:
        _uint(self.dword00, 0xFFFFFFFF, "Plain timestamp DWORD00")
        _uint(self.dword04, 0xFFFFFFFF, "Plain timestamp DWORD04")
        for values, extent in ((self.scalars, 3), (self.auxiliary, 2)):
            if type(values) is not tuple or len(values) != extent:
                raise TypeError("Plain timestamp requires native tuple extents")
            for value in values:
                _uint(value, 0xFFFFFFFF, "Plain timestamp DWORD")
        if (
            type(self.metadata) is not tuple
            or len(self.metadata) != 3
            or not all(
                type(value) in (SavedOperationFacadeMetadata, PlainFacadeFreezeMetadata)
                for value in self.metadata
            )
        ):
            raise TypeError("Plain timestamp requires three typed native metadata rows")


@dataclass(frozen=True)
class PlainFacadeTSItem:
    address: int
    opcode: int
    content: str
    name: str
    unit: str
    format: int
    timestamp: PlainFacadeTimestamp

    def __post_init__(self) -> None:
        _uint(self.address, 0xFFFFFFFF, "Plain TS address")
        _uint(self.opcode, 255, "Plain TS opcode")
        _uint(self.format, 65535, "Plain TS format")
        if any(type(text) is not str for text in (self.content, self.name, self.unit)):
            raise TypeError("Plain TS item requires owned text")
        if type(self.timestamp) is not PlainFacadeTimestamp:
            raise TypeError("Plain TS item requires typed timestamp")


@dataclass(frozen=True)
class PlainFacadeTSGroup:
    identifier: int
    display_type: int
    pid: int
    name: str
    items: tuple[PlainFacadeTSItem, ...]

    def __post_init__(self) -> None:
        _uint(self.identifier, 0xFFFFFFFF, "Plain TS group identifier")
        _uint(self.display_type, 0xFFFFFFFF, "Plain TS group display type")
        _uint(self.pid, 255, "Plain TS group PID")
        if (
            type(self.name) is not str
            or type(self.items) is not tuple
            or not all(type(item) is PlainFacadeTSItem for item in self.items)
        ):
            raise TypeError("Plain TS group requires typed owned items/text")


@dataclass(frozen=True)
class PlainFacadeResult:
    return_code: int
    groups: tuple[PlainFacadeGroup, ...] = ()
    current: tuple[RoBFacadeValue, ...] = ()
    calendar: tuple[int, ...] = (0,) * 6
    coefficient: int = 0
    ts_groups: tuple[PlainFacadeTSGroup, ...] = ()
    current_timestamp: PlainFacadeTimestamp = PlainFacadeTimestamp()

    def __post_init__(self) -> None:
        _uint(self.return_code, 0xFFFFFFFF, "Plain facade return code")
        _uint(self.coefficient, 255, "Plain facade coefficient BYTE")
        if type(self.calendar) is not tuple or len(self.calendar) != 6:
            raise TypeError("Plain calendar requires six native WORDs")
        for value in self.calendar:
            _uint(value, 65535, "Plain calendar WORD")
        for values, kind in (
            (self.groups, PlainFacadeGroup),
            (self.current, RoBFacadeValue),
        ):
            if type(values) is not tuple or not all(
                type(value) is kind for value in values
            ):
                raise TypeError("Plain facade requires typed owned groups/current")
        if type(self.ts_groups) is not tuple or not all(
            type(group) is PlainFacadeTSGroup for group in self.ts_groups
        ):
            raise TypeError("Plain TS groups require typed owned items")
        if type(self.current_timestamp) is not PlainFacadeTimestamp:
            raise TypeError("Plain facade requires typed current timestamp")


@dataclass(frozen=True)
class ImageFacadeResult:
    return_code: int
    freezes: tuple[SavedOperationFacadeFreeze, ...] = ()
    native_fields18: tuple[int, ...] = ()

    def __post_init__(self) -> None:
        _uint(self.return_code, 0xFFFFFFFF, "Image facade return code")
        if type(self.freezes) is not tuple or not all(
            type(row) is SavedOperationFacadeFreeze for row in self.freezes
        ):
            raise TypeError("Image facade requires typed owned freezes")
        if type(self.native_fields18) is not tuple or len(self.native_fields18) not in (
            0,
            3,
        ):
            raise TypeError("Image facade requires version-specific DWORD fields")
        for value in self.native_fields18:
            _uint(value, 0xFFFFFFFF, "Image facade native DWORD")


class CommandAPI:
    """One source identity and explicit cancellation for local composition.

    compose_* methods implement recovered logical result transformations.
    get_* routes select/execute concrete providers and compose those results.
    selected_* joins preserve domain values where facade marshalling stays open.
    """

    def __init__(
        self,
        source: CommandSource,
        *,
        cancelled: Callable[[], bool] = lambda: False,
    ) -> None:
        if type(source) is not CommandSource:
            raise TypeError("CommandAPI requires a reconciled source identity")
        self.source = source
        self._source_identity = source
        self.cancelled = cancelled
        self.closed = False

    def _check(self) -> None:
        if self.closed:
            raise ValueError("CommandAPI is closed")
        if self.cancelled():
            raise Cancelled("CommandAPI cancelled")
        if (
            type(self.source) is not CommandSource
            or self.source != self._source_identity
        ):
            raise ValueError("CommandAPI source context changed")

    def _require18(self) -> None:
        self._check()
        if self.source.version != 18:
            raise NotImplementedError(
                "Result field composition is not yet reconciled for12"
            )

    def compose_vin(self, reply: VinReply, *, previous: bytes = b"") -> VinResult:
        """GetVINAPI12 92fa0 /18 b4100: status, copy, ASCII scan, lifetime."""
        self._check()
        if not isinstance(reply, VinReply) or type(previous) is not bytes:
            raise TypeError("VIN composition requires typed reply and previous bytes")
        if reply.state.status:
            return VinResult(reply.state.return_code, previous)
        if reply.length <= 1:
            return VinResult(0, b"")
        # CString copies through NUL; the separate native loop validates only
        # length-1 bytes, so an unvalidated suffix is preserved deliberately.
        copied = reply.payload.split(b"\0", 1)[0]
        if len(copied) < reply.length - 1:
            raise ValueError("VIN length crosses a CString terminator")
        prefix = copied[: reply.length - 1]
        value = (
            copied
            if all(48 <= c <= 57 or 65 <= c <= 90 or 97 <= c <= 122 for c in prefix)
            else b""
        )
        self._check()
        return VinResult(0, value)

    def compose_vim_support(
        self,
        state: CommandStatus,
        support: int,
        *,
        previous: int = 0,
    ) -> VimSupportResult:
        """GetVimSupport18 b3e60 copies only the low byte on success."""
        self._require18()
        if not isinstance(state, CommandStatus):
            raise TypeError("VIM support requires typed receive status")
        _uint(previous, 255, "Previous VIM support")
        if state.status:
            return VimSupportResult(state.return_code, previous)
        _uint(support, 0xFFFFFFFF, "VIM receive support")
        return VimSupportResult(0, support & 255)

    def compose_vim_information(
        self,
        state: CommandStatus,
        information: VimInformation,
        *,
        previous: VimInformation | None = None,
    ) -> VimInformationResult:
        """VIM information12 92ca0 /18 b3b60: six copies; error retention."""
        self._check()
        previous = VimInformation() if previous is None else previous
        if (
            not isinstance(state, CommandStatus)
            or not isinstance(information, VimInformation)
            or not isinstance(previous, VimInformation)
        ):
            raise TypeError("VIM information composition requires typed values")
        return VimInformationResult(
            state.return_code, previous if state.status else information
        )

    def compose_active_list(
        self,
        state: CommandStatus,
        entries: tuple[ActiveFacadeEntry | None, ...],
        groups: tuple[ActiveFacadeGroup, ...],
        description: bytes,
        *,
        mode: int,
        previous: ActiveFacadeResult | None = None,
    ) -> ActiveFacadeResult:
        """ActiveList12 12420 /18 14420: actual lists, ID filter, ownership."""
        self._check()
        _uint(mode, 0xFFFFFFFF, "Active facade mode")
        if not isinstance(state, CommandStatus):
            raise TypeError("Active facade requires typed receive status")
        previous = ActiveFacadeResult(0) if previous is None else previous
        if not isinstance(previous, ActiveFacadeResult):
            raise TypeError("Active facade requires a typed previous result")
        if state.status:
            return ActiveFacadeResult(
                state.return_code,
                previous.entries,
                previous.groups,
                previous.description,
            )
        if type(entries) is not tuple or not all(
            x is None or isinstance(x, ActiveFacadeEntry) for x in entries
        ):
            raise TypeError(
                "Active facade requires typed received entries or native NULL"
            )
        ActiveFacadeResult(0, (), groups, description)
        # Bound host materialization; native containers do not supply a safe cap.
        if (
            len(entries) + len(groups) + sum(len(g.signal_ids) for g in groups)
            > 100_000
        ):
            raise ValueError("Active facade materialization exceeds host item budget")

        def visible(value: int) -> bool:
            return mode == 1 or not (8000 <= value <= 9999 or 40000 <= value <= 41999)

        retained = tuple(
            ActiveFacadeEntry(
                x.signal_id,
                x.name.split(b"\0", 1)[0],
                x.short_name.split(b"\0", 1)[0],
                x.control_value,
            )
            for x in entries
            if x is not None and visible(x.signal_id)
        )
        memberships = tuple(
            ActiveFacadeGroup(
                g.name.split(b"\0", 1)[0], tuple(i for i in g.signal_ids if visible(i))
            )
            for g in groups
        )
        self._check()
        return ActiveFacadeResult(
            0, retained, memberships, description.split(b"\0", 1)[0]
        )

    def compose_translation(
        self,
        state: CommandStatus,
        entries: tuple[TranslationFacadeEntry, ...],
        *,
        previous: TranslationFacadeResult | None = None,
    ) -> TranslationFacadeResult:
        """Translation12 8f8d0 /18 ae620 appends; old output is retained."""
        self._check()
        if not isinstance(state, CommandStatus):
            raise TypeError("Translation facade requires typed receive status")
        previous = TranslationFacadeResult(0) if previous is None else previous
        if not isinstance(previous, TranslationFacadeResult):
            raise TypeError("Translation facade requires typed previous output")
        if state.status:
            return TranslationFacadeResult(state.return_code, previous.entries)
        TranslationFacadeResult(0, entries)
        if len(entries) + len(previous.entries) > 100_000:
            raise ValueError("Translation facade exceeds host item budget")
        copied = tuple(
            TranslationFacadeEntry(x.value.split(b"\0", 1)[0], x.attribute)
            for x in entries
        )
        self._check()
        return TranslationFacadeResult(0, previous.entries + copied)

    def compose_ecu_groups(
        self,
        state: CommandStatus,
        entries: tuple[EcuGroupEntry, ...],
        *,
        previous: EcuGroupResult | None = None,
    ) -> EcuGroupResult:
        """GetEcuGroupListApi18 79d70: append WORD ID/CString name pairs."""
        self._require18()
        if not isinstance(state, CommandStatus):
            raise TypeError("ECU group facade requires typed receive status")
        previous = EcuGroupResult(0) if previous is None else previous
        if not isinstance(previous, EcuGroupResult):
            raise TypeError("ECU group facade requires typed previous output")
        if state.status:
            return EcuGroupResult(state.return_code, previous.entries)
        EcuGroupResult(0, entries)
        if len(previous.entries) + len(entries) > 100_000:
            raise ValueError("ECU group facade exceeds host item budget")
        copied = tuple(
            EcuGroupEntry(x.identifier, x.name.split(b"\0", 1)[0]) for x in entries
        )
        self._check()
        return EcuGroupResult(0, previous.entries + copied)

    def compose_ddr_extension(
        self,
        value: DdrExtensionValues,
        *,
        previous: DdrExtensionValues | None = None,
    ) -> DdrExtensionValues:
        """Exact18 helper52730 appends arrays/lists and replaces byte fields."""
        self._require18()
        if not isinstance(value, DdrExtensionValues):
            raise TypeError("DDR extension requires typed native logical fields")
        if previous is None:
            previous = DdrExtensionValues((b"",) * 10, bytes(21), ((), ()))
        if not isinstance(previous, DdrExtensionValues):
            raise TypeError("DDR extension requires a typed previous row extension")
        total_bytes = sum(
            len(x) for fields in (previous, value) for x in fields.arrays
        ) + sum(
            len(x)
            for fields in (previous, value)
            for group in fields.nested
            for x in group
        )
        total_rows = sum(
            len(group) for fields in (previous, value) for group in fields.nested
        )
        if total_bytes > 64 * 1024 * 1024 or total_rows > 100_000:
            raise ValueError("DDR extension append exceeds host materialization budget")
        result = DdrExtensionValues(
            tuple(
                old + new
                for old, new in zip(previous.arrays, value.arrays, strict=True)
            ),
            value.flags,
            (
                previous.nested[0] + value.nested[0],
                previous.nested[1] + value.nested[1],
            ),
        )
        self._check()
        return result

    def compose_dcm35_analysis(
        self,
        state: CommandStatus,
        analysis: AnalysisResult | None,
        *,
        previous: DcmP5FacadeResult | None = None,
    ) -> DcmP5FacadeResult:
        """Exact18 DCM P5 result fields; source Unicode is retained explicitly."""
        self._require18()
        if not isinstance(state, CommandStatus):
            raise TypeError("Work-factor facade requires typed receive status")
        previous = DcmP5FacadeResult(0) if previous is None else previous
        if not isinstance(previous, DcmP5FacadeResult):
            raise TypeError("Work-factor facade requires typed previous output")
        # This wrapper checks ==1, unlike the nonzero tests in other facades.
        if state.status == 1:
            return DcmP5FacadeResult(state.error, previous.groups)
        if (
            not isinstance(analysis, AnalysisResult)
            or analysis.source_build != 18
            or analysis.source_sha256 != DCM35_SHA256
            or analysis.common_sha256 != COMMON18_SHA256
        ):
            raise ValueError("Work-factor result has no reconciled DCM35 source")
        if analysis.native_status:
            raise ValueError("Successful facade status conflicts with business error")
        if (
            len(analysis.groups) + sum(len(g.records) for g in analysis.groups)
            > 100_000
        ):
            raise ValueError("Work-factor facade exceeds host item budget")
        groups = []
        for group in analysis.groups:
            self._check()
            _uint(group.display_id, 0xFFFFFFFF, "Work-factor display ID")
            records = []
            for record in group.records:
                self._check()
                _uint(record.operation_code, 65535, "Work-factor operation code")
                words = [0] * 8
                if record.time_valid:
                    for index, value in enumerate(record.time_values[:6]):
                        _uint(value, 255, "Work-factor received time byte")
                        position = (0, 1, 3, 4, 5, 6)[index]
                        words[position] = value + 2000 if index == 0 else value
                network = record.network_status if record.network_valid else ("",) * 4
                if len(network) != 4 or any(type(x) is not str for x in network):
                    raise ValueError("Work-factor facade requires four network labels")
                records.append(
                    DcmP5FacadeRecord(
                        int(record.time_valid),
                        tuple(words),
                        record.operation_code,
                        record.function_name,
                        record.content_name,
                        int(record.network_valid),
                        network,
                    )
                )
            groups.append(
                DcmP5FacadeGroup(group.display_id, group.name, tuple(records))
            )
        self._check()
        return DcmP5FacadeResult(0, tuple(groups))

    def _compose_p5_signal(
        self, signal: P5FreezeSignal | None, *, main: bool
    ) -> P5FacadeSignal:
        """68c20 main values reverse selector0c; special blocks retain raw."""
        self._check()
        if type(main) is not bool:
            raise TypeError("P5 signal requires an explicit main/special branch")
        if signal is None:
            return P5FacadeSignal()
        if not isinstance(signal, P5FreezeSignal) or not isinstance(
            signal.metadata, P5SignalMetadata
        ):
            raise TypeError("P5 facade requires a typed native freeze signal")
        meta = signal.metadata
        for value in (meta.pid, meta.unit_id, meta.width):
            _uint(value, 65535, "P5 signal WORD")
        for value in (meta.order, meta.selector, meta.precision, meta.sign_mode):
            _uint(value, 255, "P5 signal BYTE")
        for value in (
            meta.name_id,
            meta.unit_name_id,
            meta.multiplier,
            meta.divisor,
            meta.offset,
            meta.threshold,
            meta.threshold_high,
            meta.minimum_raw,
            meta.maximum_raw,
        ):
            _uint(value, 0xFFFFFFFF, "P5 signal DWORD")
        if type(meta.name) is not str or type(meta.unit) is not str:
            raise TypeError("P5 facade labels require source Unicode text")
        if len(signal.values) + len(meta.patterns) > 100_000:
            raise ValueError("P5 signal exceeds host item budget")
        patterns = []
        for pattern_id, label, low, high in meta.patterns:
            for value in (pattern_id, low, high):
                _uint(value, 0xFFFFFFFF, "P5 display info DWORD")
            if type(label) is not str:
                raise TypeError("P5 display info requires source Unicode text")
            patterns.append(P5FacadeDisplayInfo(pattern_id, label, low, high))
        values = []
        for value in signal.values:
            self._check()
            if not isinstance(value, P5Value):
                raise TypeError("P5 signal requires typed received values")
            raw = value.value
            if self.source.version == 18 and main and meta.selector == 12:
                # Native6ff0 reverses ceil(width/8) bytes, at most four bytes.
                raw = 0
                for shift in range(0, min(meta.width, 32), 8):
                    raw = (raw << 8) | ((value.value >> shift) & 255)
            # Original12 ConvertData@20 has no12/26+ selectors. Its25 helper
            # produces the same sign-magnitude numeric value as the18 helper.
            selector = meta.selector
            if self.source.version == 12 and selector not in (
                1,
                2,
                3,
                4,
                5,
                6,
                7,
                8,
                9,
                10,
                11,
                13,
                19,
                20,
                21,
                22,
                23,
                24,
                25,
            ):
                selector = 0
            if selector in (4, 32) and raw & 255 >= 128:
                raise ValueError("P5 character display requires observed ANSI encoding")
            rendered = render_signal(
                raw,
                selector=selector,
                sign_mode=meta.sign_mode,
                bits=meta.width,
                multiplier=meta.multiplier,
                divisor=meta.divisor,
                offset=meta.offset,
                precision=meta.precision,
                patterns=tuple((p.low, p.label, p.low, p.high) for p in patterns),
                minimum_raw=meta.minimum_raw,
                maximum_raw=meta.maximum_raw,
                raw_words=(0, 0),
            )
            display = rendered["display"]
            if type(display) is not str:
                raise ValueError("P5 native display branch remains unresolved")
            if self.source.version == 12 and selector == 19:
                # Original12 4c10 uses "%02d:%02d";18 has unpadded minutes.
                minutes, seconds = display.split(":")
                display = f"{int(minutes):02d}:{seconds}"
            values.append(P5FacadeValue(raw, display, value.index & 255, value.kind))
        return P5FacadeSignal(
            meta.pid,
            meta.name_id,
            meta.name,
            meta.unit_name_id,
            meta.unit,
            meta.order,
            meta.selector,
            meta.precision,
            P5FacadeConversion(
                meta.multiplier,
                meta.divisor,
                meta.offset,
                meta.unit_id,
                meta.sign_mode,
                meta.width,
                tuple(patterns),
                meta.threshold,
                meta.threshold_high,
                meta.minimum_raw,
                meta.maximum_raw,
            ),
            tuple(values),
        )

    def compose_p5_diagnostics(
        self,
        status: CommandStatus,
        state: P5FreezeState | None,
        *,
        previous: P5DiagnosticFacadeResult | None = None,
    ) -> P5DiagnosticFacadeResult:
        """Original18 68c20 appends rows, including native log fault90020706."""
        self._require18()
        if not isinstance(status, CommandStatus):
            raise TypeError("P5 diagnostics require typed receive status")
        previous = P5DiagnosticFacadeResult(0) if previous is None else previous
        if not isinstance(previous, P5DiagnosticFacadeResult):
            raise TypeError("P5 diagnostics require a typed previous result")
        if status.status and status.error != 0x90020706:
            return P5DiagnosticFacadeResult(
                status.error, previous.diagnostics, previous.attachment
            )
        if (
            not isinstance(state, P5FreezeState)
            or state.source_build != 18
            or state.source_sha256 != COMMON18_SHA256
        ):
            raise ValueError("P5 diagnostics require reconciled original18 state")
        state._check()
        self._profile_version(state.profile.database.version)
        count = len(previous.diagnostics) + len(state.diagnostics)
        rows = []
        for row in state.diagnostics:
            self._check()
            for value in (
                row.diag_type,
                row.code,
                row.existence_flags,
                row.timestamp_flags,
                row.odometer_flags,
                row.absolute_flags,
            ):
                _uint(value, 0xFFFFFFFF, "P5 diagnostic DWORD")
            _uint(row.status, 255, "P5 diagnostic status")
            if type(row.stored_all) is not bool or len(row.timestamps) != 3:
                raise ValueError("P5 diagnostic state has invalid native extents")
            strings = []
            for key in ("signature", "name", "division_name"):
                value = row.metadata[key]
                if type(value) is not str:
                    raise TypeError("P5 diagnostic metadata requires source Unicode")
                strings.append(value)
            fields = []
            for key, maximum in (
                ("native_field_24", 0xFFFFFFFF),
                ("native_field_38", 0xFFFFFFFF),
                ("native_field_2de", 65535),
                ("native_field_2e0", 255),
            ):
                value = row.metadata[key]
                if type(value) is not int:
                    raise TypeError("P5 diagnostic metadata requires native integers")
                _uint(value, maximum, "P5 diagnostic metadata field")
                fields.append(value)
            numbers = []
            for source in (row.normal_numbers, row.extended_numbers):
                for value in source:
                    _uint(value, 255, "P5 diagnostic snapshot number")
                numbers.append(tuple(source))
            signals = (
                tuple(
                    signal
                    for signal in row.signals
                    if signal is not None
                    and not (8000 <= signal.pid <= 9999 or 40000 <= signal.pid <= 41999)
                )
                if row.existence_flags
                else ()
            )
            timestamps = tuple(row.timestamps) if row.timestamp_flags else (None,) * 3
            odometer = row.odometer if row.odometer_flags else None
            absolute = tuple(
                row.absolute.get(signal) if row.absolute_flags else None
                for signal in range(0x3C, 0x42)
            )
            count += len(signals) + len(row.normal_numbers) + len(row.extended_numbers)
            count += sum(
                len(signal.values) + len(signal.metadata.patterns)
                for signal in (*signals, *timestamps, odometer, *absolute)
                if signal is not None
            )
            if count > 100_000:
                raise ValueError("P5 diagnostic facade exceeds host item budget")
            rows.append(
                P5FacadeDiagnostic(
                    row.diag_type,
                    row.status,
                    row.code,
                    strings[0],
                    fields[0],
                    strings[1],
                    fields[1],
                    strings[2],
                    row.existence_flags,
                    0,  # DataLib4a680 +50 remains unchanged in this producer.
                    numbers[0],
                    numbers[1],
                    int(row.stored_all),
                    tuple(
                        self._compose_p5_signal(signal, main=True) for signal in signals
                    ),
                    row.timestamp_flags,
                    tuple(
                        self._compose_p5_signal(signal, main=False)
                        for signal in timestamps
                    ),
                    row.odometer_flags,
                    self._compose_p5_signal(odometer, main=False),
                    3,  # Common7cc2b initializes every new visible P5 diagnostic.
                    fields[2],
                    fields[3],
                    row.absolute_flags,
                    tuple(
                        self._compose_p5_signal(signal, main=False)
                        for signal in absolute
                    ),
                )
            )
        self._check()
        return P5DiagnosticFacadeResult(
            0, previous.diagnostics + tuple(rows), previous.attachment
        )

    def compose_p5_diagnostics12(
        self,
        status: CommandStatus,
        state: P5FreezeState | None,
        *,
        previous: P5DiagnosticFacadeResult12 | None = None,
    ) -> P5DiagnosticFacadeResult12:
        """Original12 53b70 appends0x228 rows only on native success."""
        self._check()
        if self.source.version != 12:
            raise ValueError("Original12 P5 schema requires source12")
        if not isinstance(status, CommandStatus):
            raise TypeError("P5 diagnostics require typed receive status")
        previous = P5DiagnosticFacadeResult12(0) if previous is None else previous
        if not isinstance(previous, P5DiagnosticFacadeResult12):
            raise TypeError("P5 diagnostics require a typed previous result")
        if status.status:
            return P5DiagnosticFacadeResult12(status.error, previous.diagnostics)
        if (
            not isinstance(state, P5FreezeState)
            or state.source_build != 12
            or state.source_sha256 != COMMON12_SHA256
        ):
            raise ValueError("P5 diagnostics require reconciled original12 state")
        state._check()
        self._profile_version(state.profile.database.version)
        count = len(previous.diagnostics) + len(state.diagnostics)
        rows = []
        for row in state.diagnostics:
            self._check()
            for value in (
                row.diag_type,
                row.code,
                row.existence_flags,
                row.timestamp_flags,
                row.odometer_flags,
            ):
                _uint(value, 0xFFFFFFFF, "P5 diagnostic DWORD")
            _uint(row.status, 255, "P5 diagnostic status")
            if type(row.stored_all) is not bool or len(row.timestamps) != 3:
                raise ValueError("P5 diagnostic state has invalid native extents")
            strings = []
            for key in ("signature", "name", "division_name"):
                value = row.metadata[key]
                if type(value) is not str:
                    raise TypeError("P5 diagnostic metadata requires source Unicode")
                strings.append(value)
            fields = []
            for key, maximum in (
                ("native_field_24", 0xFFFFFFFF),
                ("native_field_38", 0xFFFFFFFF),
                ("native_field_2de", 65535),
                ("native_field_2e0", 255),
            ):
                value = row.metadata[key]
                if type(value) is not int:
                    raise TypeError("P5 diagnostic metadata requires native integers")
                _uint(value, maximum, "P5 diagnostic metadata field")
                fields.append(value)
            numbers = []
            for source in (row.normal_numbers, row.extended_numbers):
                for value in source:
                    _uint(value, 255, "P5 diagnostic snapshot number")
                numbers.append(tuple(source))
            signals = (
                tuple(
                    signal
                    for signal in row.signals
                    if signal is not None
                    and not (8000 <= signal.pid <= 9999 or 40000 <= signal.pid <= 41999)
                )
                if row.existence_flags
                else ()
            )
            timestamps = tuple(row.timestamps) if row.timestamp_flags else (None,) * 3
            odometer = row.odometer if row.odometer_flags else None
            count += len(signals) + len(row.normal_numbers) + len(row.extended_numbers)
            count += sum(
                len(signal.values) + len(signal.metadata.patterns)
                for signal in (*signals, *timestamps, odometer)
                if signal is not None
            )
            if count > 100_000:
                raise ValueError("P5 diagnostic facade exceeds host item budget")
            rows.append(
                P5FacadeDiagnostic12(
                    row.diag_type,
                    row.status,
                    row.code,
                    strings[0],
                    fields[0],
                    strings[1],
                    fields[1],
                    strings[2],
                    row.existence_flags,
                    0,  # DataLib12 40f30 +50 remains unchanged in this producer.
                    numbers[0],
                    numbers[1],
                    int(row.stored_all),
                    tuple(
                        self._compose_p5_signal(signal, main=True) for signal in signals
                    ),
                    row.timestamp_flags,
                    tuple(
                        self._compose_p5_signal(signal, main=False)
                        for signal in timestamps
                    ),
                    row.odometer_flags,
                    self._compose_p5_signal(odometer, main=False),
                    3,  # Common12 580fb ->583eb initializes native BYTE2dc.
                    fields[2],
                    fields[3],
                )
            )
        self._check()
        return P5DiagnosticFacadeResult12(0, previous.diagnostics + tuple(rows))

    def get_diag_code_p5(
        self,
        workflow: ToyotaWorkflows,
        requested_types: int,
        freeze_flags: int,
        *,
        native_cancel_value: int,
        log_control: int = 0,
        packet_log: DdrPacketLog | None = None,
        include_attachment: bool = False,
        previous: P5DiagnosticFacadeResult | None = None,
    ) -> P5DiagnosticFacadeResult:
        """SelectedAC full18 P5 producer and plain facade, with explicit log owner."""
        self._require18()
        if not isinstance(workflow, ToyotaWorkflows) or workflow._communication is None:
            raise TypeError("P5 diagnostics require an actual native workflow")
        communication = workflow._communication
        self._communication_source(communication)
        if (
            workflow.profile is not communication.profile
            or workflow.observations.source_version != 18
        ):
            raise ValueError("P5 workflow and selected source contexts differ")
        self._saved_operation_module(communication, 0xAC, "GetDiagCodeP5_DT.dll")
        for value in (requested_types, freeze_flags, native_cancel_value, log_control):
            _uint(value, 0xFFFFFFFF, "P5 facade send DWORD")
        if type(include_attachment) is not bool:
            raise TypeError("P5 attachment output selection must be explicit")
        if previous is not None and not isinstance(previous, P5DiagnosticFacadeResult):
            raise TypeError("P5 diagnostics require a typed previous result")
        if log_control == 1:
            if type(packet_log) is not DdrPacketLog or packet_log.source_build != 18:
                raise TypeError(
                    "P5 logging requires the concrete original18 file owner"
                )
            communication.bind_comm_log(packet_log)
        status = CommandStatus()
        try:
            output = workflow.session.dtcs_p5_profile(
                workflow,
                requested_types,
                freeze_flags,
                native_cancel_value=native_cancel_value,
                log_control=log_control,
            )
        except ToyotaCodecError as error:
            self._check()
            status = CommandStatus(1, error.code)
            output = workflow.native_output
        self._check()
        state = output.get("state")
        if state is not None and not isinstance(state, P5FreezeState):
            raise TypeError("P5 producer returned an untyped diagnostic state")
        result = self.compose_p5_diagnostics(status, state, previous=previous)
        if log_control == 1:
            assert packet_log is not None
            path = packet_log.directory / "MarkMonRam_SSR.log"
            try:
                if not status.status and include_attachment:
                    attachment = P5DiagnosticAttachment()
                    try:
                        data = read_regular(path, limit=64 * 1024 * 1024)
                    except OSError:
                        pass  # Native6daa0 resets output before a failed CFile.Open.
                    else:
                        attachment = P5DiagnosticAttachment(
                            workflow.observations.native_id, data
                        )
                    result = P5DiagnosticFacadeResult(
                        result.return_code, result.diagnostics, attachment
                    )
            finally:
                try:
                    path.unlink()
                except OSError:
                    pass  # Native CFile.Remove exception is caught by the facade.
        return result

    def get_diag_code_p5_12(
        self,
        workflow: ToyotaWorkflows,
        requested_types: int,
        freeze_flags: int,
        *,
        native_cancel_value: int,
        previous: P5DiagnosticFacadeResult12 | None = None,
    ) -> P5DiagnosticFacadeResult12:
        """Source12 AC input has no18 log-control or attachment fields."""
        self._check()
        if self.source.version != 12:
            raise ValueError("Original12 P5 route requires source12")
        if not isinstance(workflow, ToyotaWorkflows) or workflow._communication is None:
            raise TypeError("P5 diagnostics require an actual native workflow")
        communication = workflow._communication
        self._communication_source(communication)
        if (
            workflow.profile is not communication.profile
            or workflow.observations.source_version != 12
        ):
            raise ValueError("P5 workflow and selected source contexts differ")
        self._saved_operation_module(communication, 0xAC, "GetDiagCodeP5_DT.dll")
        for value in (requested_types, freeze_flags, native_cancel_value):
            _uint(value, 0xFFFFFFFF, "P5 facade send DWORD")
        if previous is not None and type(previous) is not P5DiagnosticFacadeResult12:
            raise TypeError("Original12 P5 requires a typed previous result")
        status = CommandStatus()
        try:
            output = workflow.session.dtcs_p5_profile(
                workflow,
                requested_types,
                freeze_flags,
                native_cancel_value=native_cancel_value,
            )
        except ToyotaCodecError as error:
            self._check()
            status = CommandStatus(1, error.code)
            output = workflow.native_output
        self._check()
        state = output.get("state")
        if state is not None and not isinstance(state, P5FreezeState):
            raise TypeError("P5 producer returned an untyped diagnostic state")
        return self.compose_p5_diagnostics12(status, state, previous=previous)

    def p5_diagnostic_report12(
        self, result: P5DiagnosticFacadeResult12
    ) -> dict[str, Any]:
        self._check()
        if self.source.version != 12 or type(result) is not P5DiagnosticFacadeResult12:
            raise TypeError("Original12 report requires its typed0x228 result")
        return {
            "schema": "techstream.command-api.p5-diagnostics12.v1",
            "operation": "GetDiagCodeP5API",
            "source": asdict(self.source),
            "result": asdict(result),
        }

    def p5_diagnostic_report(self, result: P5DiagnosticFacadeResult) -> dict[str, Any]:
        """Public result fields only; no raw replies, log files or selected paths."""
        self._require18()
        if type(result) is not P5DiagnosticFacadeResult:
            raise TypeError("P5 report requires a typed diagnostic facade result")
        return {
            "schema": "techstream.command-api.p5-diagnostics.v1",
            "operation": "GetDiagCodeP5API",
            "source": asdict(self.source),
            "result": {
                "return_code": result.return_code,
                "diagnostics": [asdict(row) for row in result.diagnostics],
            },
        }

    def _compose_plain_freeze(
        self, freeze: PlainFreezeData
    ) -> SavedOperationFacadeMetadata | PlainFacadeFreezeMetadata:
        self._check()
        if type(freeze) is not PlainFreezeData:
            raise TypeError("Plain timestamp requires actual typed freeze metadata")
        if freeze == PlainFreezeData():
            return SavedOperationFacadeMetadata()
        if len(freeze.values) + len(freeze.patterns) > 100_000:
            raise ValueError("Plain timestamp freeze exceeds host item budget")
        patterns = tuple(
            P5FacadeDisplayInfo(identifier, label, low, high, flag)
            for identifier, label, low, high, flag in freeze.patterns
        )
        conversion = P5FacadeConversion(
            freeze.multiplier,
            freeze.divisor,
            freeze.offset,
            freeze.unit_id,
            freeze.sign_mode,
            freeze.width,
            patterns,
            freeze.threshold,
            freeze.threshold_high,
            freeze.minimum_raw,
            freeze.maximum_raw,
        )
        selector = freeze.selector
        supported = set(range(1, 14)) | set(range(19, 35))
        if self.source.version == 12:
            supported -= {12, *range(26, 35)}
        values = []
        for raw, status in freeze.values:
            self._check()
            _uint(raw, 0xFFFFFFFF, "Plain timestamp raw DWORD")
            _uint(status, 255, "Plain timestamp native status")
            if selector not in supported:
                # ConvertData's default branch does not inspect a reset width0.
                display = "-TypeErr-"
            else:
                if selector in (4, 32) and raw & 255 >= 128:
                    raise ValueError(
                        "Plain character display requires observed ANSI encoding"
                    )
                rendered = render_signal(
                    raw,
                    selector=selector,
                    sign_mode=freeze.sign_mode,
                    bits=freeze.width,
                    multiplier=freeze.multiplier,
                    divisor=freeze.divisor,
                    offset=freeze.offset,
                    precision=freeze.precision,
                    patterns=tuple((p.low, p.label, p.low, p.high) for p in patterns),
                    minimum_raw=freeze.minimum_raw,
                    maximum_raw=freeze.maximum_raw,
                    raw_words=(0, 0),
                )
                display = rendered["display"]
                if type(display) is not str:
                    raise ValueError("Plain timestamp display remains unreconciled")
                if self.source.version == 12 and selector == 19:
                    minutes, seconds = display.split(":")
                    display = f"{int(minutes):02d}:{seconds}"
            values.append(PlainFacadeFreezeValue(raw, display, status))
        return PlainFacadeFreezeMetadata(
            freeze.pid,
            freeze.name,
            freeze.short_name,
            freeze.unit,
            selector,
            freeze.precision,
            conversion,
            tuple(values),
        )

    def _compose_plain_timestamp(
        self, timestamp: PlainTimestamp
    ) -> PlainFacadeTimestamp:
        if type(timestamp) is not PlainTimestamp or len(timestamp.freezes) != 3:
            raise TypeError("Plain timestamp requires three actual freeze blocks")
        metadata = tuple(self._compose_plain_freeze(row) for row in timestamp.freezes)
        return PlainFacadeTimestamp(
            timestamp.dword00,
            timestamp.dword04,
            (
                timestamp.freezes[0].values[0][0] if timestamp.freezes[0].values else 0,
                timestamp.freezes[1].values[0][0] if timestamp.freezes[1].values else 0,
                timestamp.dword148,
            ),
            metadata,
            timestamp.auxiliary,
        )

    def compose_plain_analysis(
        self,
        status: CommandStatus,
        analysis: PlainAnalysisResult | None,
        *,
        previous: PlainFacadeResult | None = None,
    ) -> PlainFacadeResult:
        """Source12 15750 /18 23250 reset P3 output only on native success."""
        self._check()
        if type(status) is not CommandStatus:
            raise TypeError("Plain facade requires native receive status")
        previous = PlainFacadeResult(0) if previous is None else previous
        if type(previous) is not PlainFacadeResult:
            raise TypeError("Plain facade requires typed previous output")
        if status.status:
            return PlainFacadeResult(
                status.error,
                previous.groups,
                previous.current,
                previous.calendar,
                previous.coefficient,
                previous.ts_groups,
                previous.current_timestamp,
            )
        if (
            type(analysis) is not PlainAnalysisResult
            or analysis.source_build != self.source.version
            or analysis.native_status
            or analysis.source_sha256 not in PLAIN_NORMAL_SHA256[self.source.version]
            or analysis.common_sha256
            != {12: COMMON12_SHA256, 18: COMMON18_SHA256}[self.source.version]
        ):
            raise ValueError("Plain result has no matching actual normal source")
        if (
            len(analysis.groups)
            + len(analysis.current)
            + sum(len(group.items) for group in analysis.groups)
            + len(analysis.ts_groups)
            + sum(len(group.items) for group in analysis.ts_groups)
            > 100_000
        ):
            raise ValueError("Plain facade exceeds host item budget")
        groups = tuple(
            PlainFacadeGroup(
                group.identifier,
                group.display_type,
                group.pid,
                group.name,
                tuple(
                    PlainFacadeItem(
                        item.address,
                        item.opcode,
                        item.content,
                        item.name,
                        item.value,
                        item.unit,
                        item.format,
                    )
                    for item in group.items
                ),
            )
            for group in analysis.groups
        )
        current = tuple(
            RoBFacadeValue(value.name, value.value, value.unit, value.format)
            for value in analysis.current
        )
        self._check()
        ts_groups = tuple(
            PlainFacadeTSGroup(
                group.identifier,
                group.display_type,
                group.pid,
                group.name,
                tuple(
                    PlainFacadeTSItem(
                        item.address,
                        item.opcode,
                        item.content,
                        item.name,
                        item.unit,
                        item.format,
                        self._compose_plain_timestamp(item.timestamp),
                    )
                    for item in group.items
                ),
            )
            for group in analysis.ts_groups
        )
        return PlainFacadeResult(
            0,
            groups,
            current,
            analysis.calendar,
            analysis.coefficient,
            ts_groups,
            self._compose_plain_timestamp(analysis.current_timestamp),
        )

    def get_analyze_work_factor(
        self, provider: PlainAnalysis, *, previous: PlainFacadeResult | None = None
    ) -> PlainFacadeResult:
        self._check()
        if type(provider) is not PlainAnalysis:
            raise TypeError("Plain facade requires actual selected normal provider")
        self._cache_source(provider.cache)
        if provider.source_sha256 not in PLAIN_NORMAL_SHA256[self.source.version]:
            raise ValueError("Selected plain producer has no matching normal facade")
        if previous is not None and type(previous) is not PlainFacadeResult:
            raise TypeError("Plain facade requires typed previous output")
        try:
            result = provider.run()
        except ToyotaCodecError as error:
            self._check()
            return self.compose_plain_analysis(
                CommandStatus(1, error.code), None, previous=previous
            )
        self._check()
        return self.compose_plain_analysis(
            CommandStatus(int(bool(result.native_status)), result.native_status),
            result if not result.native_status else None,
            previous=previous,
        )

    def plain_analysis_report(self, result: PlainFacadeResult) -> dict[str, Any]:
        self._check()
        if type(result) is not PlainFacadeResult:
            raise TypeError("Plain report requires typed application output")
        return {
            "schema": "techstream.command-api.plain-analysis.v1",
            "operation": "GetAnalyzeWorkFactorAPI",
            "source": asdict(self.source),
            "result": asdict(result),
        }

    def compose_dcm_analysis(
        self,
        state: CommandStatus,
        analysis: DcmAnalysisResult | None,
        *,
        mode: int,
        previous: DcmFacadeResult | None = None,
    ) -> DcmFacadeResult:
        """DCM12 1b210/18 29870 flat/rich fields and gated current WORDs."""
        self._check()
        _uint(mode, 255, "DCM facade input mode")
        if not isinstance(state, CommandStatus):
            raise TypeError("DCM facade requires typed receive status")
        previous = DcmFacadeResult(0) if previous is None else previous
        if not isinstance(previous, DcmFacadeResult):
            raise TypeError("DCM facade requires a typed previous result")
        if state.status:
            return DcmFacadeResult(
                state.error,
                previous.flat_records,
                previous.current_words,
                previous.current_valid,
                previous.groups,
            )
        expected_mode = {0: 2, 1: 1, 2: 4}.get(mode, 0)
        if (
            not isinstance(analysis, DcmAnalysisResult)
            or analysis.source_build != self.source.version
            or analysis.source_sha256
            not in {
                12: (
                    "d697f922c182ec4274bed1fd6939440b8cacffc21e0450cd44a6576d179702ba",
                    "96d54db1e4bc176ccc9e22820d2a5c9be00fd36e17ed6b16c971bbf9d279d880",
                ),
                18: (
                    "75eeffb791ee55c3a334288590e4e53a796a850111bc616ee192cd39d78e1db8",
                    "65dee471c46438f8b097833eb9a1df90b252a5b7162fc7de473ef99b4e638b68",
                    "4e748d7cf69550c06aea703d3d41e468773c492cf5ddf9472588df1f6a1e4def",
                ),
            }[self.source.version]
            or analysis.common_sha256
            != {12: COMMON12_SHA256, 18: COMMON18_SHA256}[self.source.version]
            or analysis.native_status
            or analysis.mode != expected_mode
        ):
            raise ValueError("DCM result has no matching selected source/mode")
        if (
            len(analysis.groups)
            + sum(len(group.records) for group in analysis.groups)
            + sum(len(row.items) for group in analysis.groups for row in group.records)
            + len(previous.groups)
            + len(previous.flat_records)
            > 100_000
        ):
            raise ValueError("DCM facade exceeds host item budget")
        flat, groups = [], []
        for group in analysis.groups:
            self._check()
            _uint(group.pid, 65535, "DCM received group PID")
            _uint(group.format, 65535, "DCM received group format")
            records = []
            for record in group.records:
                self._check()
                _uint(record.address, 0xFFFFFFFF, "DCM received address")
                if mode == 2:
                    items = []
                    for item in record.items:
                        _uint(item.value, 0xFFFFFFFF, "DCM received value")
                        _uint(item.format, 65535, "DCM received format")
                        items.append(
                            DcmFacadeValue(
                                item.value,
                                item.name,
                                item.content,
                                item.unit,
                                item.format,
                            )
                        )
                    records.append(DcmFacadeRecord(record.address, tuple(items)))
                elif len(record.items) > 8:
                    values = tuple(item.value for item in record.items[:9])
                    for value in values:
                        _uint(value, 0xFFFFFFFF, "DCM received value")
                    flat.append(
                        DcmFlatFacadeRecord(
                            values[0] & 255,
                            values[1] & 255,
                            values[2] & 255,
                            values[3] & 255,
                            tuple(value & 65535 for value in values[4:9]),
                        )
                    )
            if mode == 2:
                groups.append(
                    DcmFacadeGroup(
                        group.pid & 255, group.format, group.name, tuple(records)
                    )
                )
        words, valid = previous.current_words, previous.current_valid
        if len(analysis.current) > 4:
            for value in analysis.current[:5]:
                _uint(value.value, 0xFFFFFFFF, "DCM received current value")
                _uint(value.format, 65535, "DCM received current format")
            words = tuple(value.value & 65535 for value in analysis.current[:5])
            valid = int(
                not any(value.format & 0x4000 for value in analysis.current[:5])
            )
        self._check()
        return DcmFacadeResult(
            0,
            previous.flat_records if mode == 2 else tuple(flat),
            words,
            valid,
            previous.groups + tuple(groups) if mode == 2 else previous.groups,
        )

    def get_analyze_work_factor_dcm(
        self,
        provider: DcmAnalysis,
        *,
        mode: int = 0,
        previous: DcmFacadeResult | None = None,
    ) -> DcmFacadeResult:
        """Selected78 actual DCM acquisition and source-specific application result."""
        self._check()
        _uint(mode, 255, "DCM facade input mode")
        if not isinstance(provider, DcmAnalysis):
            raise TypeError("DCM facade requires the concrete selected provider")
        self._profile_version(provider.profile.database.version)
        try:
            result = provider.run({0: 2, 1: 1, 2: 4}.get(mode, 0))
        except ToyotaCodecError as error:
            self._check()
            return self.compose_dcm_analysis(
                CommandStatus(1, error.code), None, mode=mode, previous=previous
            )
        self._check()
        return self.compose_dcm_analysis(
            CommandStatus(int(bool(result.native_status)), result.native_status),
            result if not result.native_status else None,
            mode=mode,
            previous=previous,
        )

    def compose_rob_analysis(
        self,
        state: CommandStatus,
        analysis: RoBAnalysisResult | None,
        *,
        previous: RoBFacadeResult | None = None,
    ) -> RoBFacadeResult:
        """Exact18 2fb90/30b50 value copies; source Unicode is not guessed ACP."""
        self._require18()
        if not isinstance(state, CommandStatus):
            raise TypeError("RoB facade requires typed receive status")
        previous = RoBFacadeResult(0) if previous is None else previous
        if not isinstance(previous, RoBFacadeResult):
            raise TypeError("RoB facade requires typed previous output")
        if state.status:
            return RoBFacadeResult(
                state.error, previous.groups, previous.current, previous.time_words
            )
        if (
            not isinstance(analysis, RoBAnalysisResult)
            or analysis.source_build != 18
            or analysis.source_sha256 != ROB18_SHA256
            or analysis.common_sha256 != COMMON18_SHA256
            or analysis.native_status
        ):
            raise ValueError("RoB result has no successful reconciled source")
        if (
            len(analysis.groups) + sum(len(g.records) for g in analysis.groups)
            > 100_000
        ):
            raise ValueError("RoB facade exceeds host materialization budget")

        def copy(value: RoBValue, *, scalar: int | None = None) -> RoBFacadeValue:
            if not isinstance(value, RoBValue):
                raise TypeError("RoB requires a concrete native scalar")
            return RoBFacadeValue(
                value.name,
                value.value if scalar is None else scalar,
                value.unit,
                value.format,
            )

        groups = []
        for group in analysis.groups:
            self._check()
            _uint(group.data_id, 65535, "RoB group ID")
            _uint(group.display_id, 0xFFFFFFFF, "RoB group display ID")
            records = []
            for record in group.records:
                self._check()
                _uint(record.operation_code, 65535, "RoB operation code")
                _uint(record.help_type, 65535, "RoB help type")
                if len(record.values) != 3:
                    raise ValueError("RoB requires native type2/3/4 scalar fields")
                happened = (
                    RoBFacadeValue(value=record.happened, format=1)
                    if record.happened is not None
                    else RoBFacadeValue()
                )
                records.append(
                    RoBFacadeRecord(
                        record.operation_code,
                        record.operation_label,
                        (
                            copy(record.values[0]),
                            copy(record.values[1], scalar=record.passed),
                            happened,
                            copy(record.values[2]),
                        ),
                        record.help,
                        record.help_type,
                    )
                )
            groups.append(
                RoBFacadeGroup(
                    group.display_id, group.data_id, group.name, tuple(records)
                )
            )
        current = (RoBFacadeValue(),) * 3
        words = (0,) * 6
        if analysis.current is not None:
            observed = analysis.current
            if len(observed.values) != 3 or len(observed.system_time) != 8:
                raise ValueError("RoB current result lacks native scalar/time fields")
            current = (
                copy(observed.values[0]),
                copy(observed.values[1], scalar=observed.adjusted_ticks),
                copy(observed.values[2]),
            )
            for value in observed.system_time:
                _uint(value, 65535, "RoB SYSTEMTIME WORD")
            # The facade copies year/month/day/hour/minute/second, omitting
            # SYSTEMTIME day-of-week and milliseconds.
            words = tuple(observed.system_time[i] for i in (0, 1, 3, 4, 5, 6))
        self._check()
        return RoBFacadeResult(0, tuple(groups), current, words)

    def get_analyze_work_factor_dcm_p5(
        self,
        provider: DcmP5Analysis,
        *,
        previous: DcmP5FacadeResult | None = None,
    ) -> DcmP5FacadeResult:
        """Selected D7 acquisition through actual provider to native facade value."""
        self._require18()
        if not isinstance(provider, DcmP5Analysis):
            raise TypeError("DCM facade requires the concrete selected provider")
        self._profile_version(provider.profile.database.version)
        try:
            result = provider.run()
        except ToyotaCodecError as error:
            self._check()
            return self.compose_dcm35_analysis(
                CommandStatus(1, error.code), None, previous=previous
            )
        self._check()
        return self.compose_dcm35_analysis(CommandStatus(), result, previous=previous)

    def get_analyze_work_factor_rob(
        self,
        provider: RoBAnalysis,
        *,
        mode: int = 1,
        current_flag: int = 1,
        previous: RoBFacadeResult | None = None,
    ) -> RoBFacadeResult:
        """Selected D6 acquisition through actual provider to native facade value."""
        self._require18()
        if not isinstance(provider, RoBAnalysis):
            raise TypeError("RoB facade requires the concrete selected provider")
        self._profile_version(provider.profile.database.version)
        try:
            result = provider.run(mode=mode, current_flag=current_flag)
        except ToyotaCodecError as error:
            self._check()
            return self.compose_rob_analysis(
                CommandStatus(1, error.code), None, previous=previous
            )
        self._check()
        return self.compose_rob_analysis(CommandStatus(), result, previous=previous)

    def analysis_report(
        self,
        result: DcmP5FacadeResult | RoBFacadeResult | DcmFacadeResult,
    ) -> dict[str, object]:
        """Saved/UI adapter: only facade fields, never raw source/transport data."""
        self._check()
        if not isinstance(result, DcmFacadeResult):
            self._require18()
        if not isinstance(
            result, (DcmP5FacadeResult, RoBFacadeResult, DcmFacadeResult)
        ):
            raise TypeError("Analysis report requires a concrete facade result")
        if isinstance(result, (DcmP5FacadeResult, RoBFacadeResult)):
            # Validate this public boundary before asdict can traverse arbitrary
            # caller-supplied objects or dataclass subclass fields.
            def owned(
                values: Any, kind: type, size: int | None = None
            ) -> tuple[Any, ...]:
                if (
                    type(values) is not tuple
                    or size is not None
                    and len(values) != size
                    or any(type(value) is not kind for value in values)
                ):
                    raise TypeError(
                        "Analysis report requires typed owned native extents"
                    )
                return values

            def labels(*values: object) -> None:
                if any(type(value) is not str for value in values):
                    raise TypeError("Analysis report requires owned source text")

            def words(values: tuple[int, ...], size: int) -> None:
                for value in owned(values, int, size):
                    _uint(value, 65535, "Analysis report WORD")

            _uint(result.return_code, 0xFFFFFFFF, "Analysis report return code")
            if type(result) is DcmP5FacadeResult:
                for group in owned(result.groups, DcmP5FacadeGroup):
                    _uint(group.display_id, 0xFFFFFFFF, "Analysis report display ID")
                    labels(group.name)
                    for row in owned(group.records, DcmP5FacadeRecord):
                        _uint(
                            row.time_status, 0xFFFFFFFF, "Analysis report time status"
                        )
                        _uint(row.operation_code, 65535, "Analysis report operation")
                        _uint(
                            row.network_status,
                            0xFFFFFFFF,
                            "Analysis report network status",
                        )
                        words(row.time_words, 8)
                        labels(row.function_name, row.content_name)
                        owned(row.network_names, str, 4)
            elif type(result) is RoBFacadeResult:
                words(result.time_words, 6)
                owned(result.current, RoBFacadeValue, 3)
                for group in owned(result.groups, RoBFacadeGroup):
                    _uint(group.display_id, 0xFFFFFFFF, "Analysis report display ID")
                    _uint(group.data_id, 65535, "Analysis report data ID")
                    labels(group.name)
                    for row in owned(group.records, RoBFacadeRecord):
                        _uint(row.operation_code, 65535, "Analysis report operation")
                        _uint(row.help_type, 65535, "Analysis report help type")
                        labels(row.label, row.help)
                        owned(row.values, RoBFacadeValue, 4)
            else:
                raise TypeError("Analysis report rejects unreviewed DTO subclasses")
        return {
            "schema": "techstream-command-analysis-v1",
            "operation": (
                "GetAnalyzeWorkFactorDcmP5API"
                if isinstance(result, DcmP5FacadeResult)
                else "GetAnalyzeWorkFactorRoBAPI"
                if isinstance(result, RoBFacadeResult)
                else "GetAnalyzeWorkFactorDcmAPI"
            ),
            "source_version": self.source.version,
            "source_sha256": self.source.sha256,
            "result": asdict(result),
        }

    def compose_pcs_operations(
        self,
        source: PcsOperationSource,
        acquired: PcsSavedOperationResult,
        *,
        previous: SavedOperationFacadeResult | None = None,
    ) -> SavedOperationFacadeResult:
        """PCS12 7db50/18 96740 copies first scalar into reset rows, appending."""
        self._check()
        if (
            not isinstance(source, PcsOperationSource)
            or source.build != self.source.version
        ):
            raise ValueError("PCS facade source differs from CommandAPI")
        if (
            not isinstance(acquired, PcsSavedOperationResult)
            or acquired.source_sha256 != source.sha256
        ):
            raise ValueError("PCS facade has no matching native producer")
        previous = SavedOperationFacadeResult(0) if previous is None else previous
        if not isinstance(previous, SavedOperationFacadeResult):
            raise TypeError("PCS facade requires a typed previous result")
        _uint(acquired.native_status, 0xFFFFFFFF, "PCS producer native status")
        if acquired.native_status:
            return SavedOperationFacadeResult(acquired.native_status, previous.freezes)
        if len(previous.freezes) + len(acquired.freezes) > 100_000:
            raise ValueError("PCS facade exceeds host item budget")
        rows = []
        for freeze in acquired.freezes:
            self._check()
            scalar = freeze.first.scalar
            _uint(scalar, 0xFFFFFFFF, "PCS received scalar")
            rows.append(
                SavedOperationFacadeFreeze((SavedOperationFacadeValue(scalar),))
            )
        return SavedOperationFacadeResult(0, previous.freezes + tuple(rows))

    def get_pcs_operation_ffd(
        self,
        communication: NativeCommunication,
        packet_log: DdrPacketLog,
        *,
        previous: SavedOperationFacadeResult | None = None,
    ) -> SavedOperationFacadeResult:
        """SelectedBA generic P4 PCS producer; the selected P5 module stays separate."""
        self._communication_source(communication)
        self._saved_operation_module(communication, 0xBA, "GetPCSOperationFFDP4_DT.dll")
        if previous is not None and not isinstance(
            previous, SavedOperationFacadeResult
        ):
            raise TypeError("PCS facade requires a typed previous result")
        if type(packet_log) is not DdrPacketLog:
            raise TypeError("PCS capture requires the concrete native file owner")
        source = PcsOperationSource(
            self.source.version, PCS_OPERATION_SOURCE_SHA256[self.source.version]
        )
        acquired = capture_pcs_saved_operations(communication, packet_log, source)
        self._check()
        return self.compose_pcs_operations(source, acquired, previous=previous)

    def pcs_operation_report(
        self, result: SavedOperationFacadeResult
    ) -> dict[str, Any]:
        """PCS plain output only; no raw phases, matching values, logs or keys."""
        self._check()
        if type(result) is not SavedOperationFacadeResult:
            raise TypeError("PCS report requires a typed facade result")
        return {
            "schema": "techstream.command-api.pcs-operation.v1",
            "operation": "GetPCSOperationFFDApi",
            "source": asdict(self.source),
            "producer_sha256": PCS_OPERATION_SOURCE_SHA256[self.source.version],
            "result": asdict(result),
        }

    def compose_image_p4(
        self,
        source: ImageP4Source,
        acquired: ImageP4SavedResult,
        *,
        previous: ImageFacadeResult | None = None,
    ) -> ImageFacadeResult:
        """ImageFFD12 68d40/18 7f8c0 first scalar, reset row, append output."""
        self._check()
        if not isinstance(source, ImageP4Source) or source.build != self.source.version:
            raise ValueError("Image facade source differs from CommandAPI")
        if (
            not isinstance(acquired, ImageP4SavedResult)
            or acquired.source_sha256 != source.sha256
        ):
            raise ValueError("Image facade has no matching native producer")
        previous = ImageFacadeResult(0) if previous is None else previous
        if not isinstance(previous, ImageFacadeResult):
            raise TypeError("Image facade requires a typed previous result")
        _uint(acquired.native_status, 0xFFFFFFFF, "Image producer native status")
        if acquired.native_status:
            return ImageFacadeResult(
                acquired.native_status, previous.freezes, previous.native_fields18
            )
        if len(previous.freezes) + len(acquired.records) > 100_000:
            raise ValueError("Image facade exceeds host item budget")
        rows = []
        for record in acquired.records:
            self._check()
            _uint(record.scalar, 65535, "Image received scalar")
            rows.append(
                SavedOperationFacadeFreeze((SavedOperationFacadeValue(record.scalar),))
            )
        return ImageFacadeResult(
            0,
            previous.freezes + tuple(rows),
            (0, 0, 0) if self.source.version == 18 else previous.native_fields18,
        )

    def compose_image_p5(
        self,
        source: ImageP5Source,
        acquired: ImageP5SavedResult,
        *,
        previous: ImageFacadeResult | None = None,
    ) -> ImageFacadeResult:
        """P5 header append; only original18 copies fresh DDR support fields."""
        self._check()
        if type(source) is not ImageP5Source or source.build != self.source.version:
            raise ValueError("P5 image facade source differs from CommandAPI")
        if (
            type(acquired) is not ImageP5SavedResult
            or acquired.source_sha256 != source.sha256
        ):
            raise ValueError("P5 image result differs from its selected source")
        previous = ImageFacadeResult(0) if previous is None else previous
        if type(previous) is not ImageFacadeResult:
            raise TypeError("P5 image requires typed previous output")
        _uint(acquired.native_status, 0xFFFFFFFF, "P5 image native status")
        _uint(acquired.ddr_status, 0xFFFFFFFF, "P5 image inner DDR status")
        if acquired.native_status:
            return ImageFacadeResult(
                acquired.native_status, previous.freezes, previous.native_fields18
            )
        if len(previous.freezes) + len(acquired.records) > 100_000:
            raise ValueError("P5 image facade exceeds host item budget")
        fields = previous.native_fields18 if self.source.version == 12 else (0, 0, 0)
        if self.source.version == 18 and not acquired.ddr_status:
            if acquired.ddr_report is None:
                raise ValueError(
                    "Successful inner DDR requires an acquired typed report"
                )
            first, _second = ddr_report_support_values(acquired.ddr_report)
            fields = (1, int(first.present), first.value)
        # A failed inner command may retain support/filter provenance. Native
        # Image7350 copies the three public fields only when its status is zero.
        rows = []
        for row in acquired.records:
            self._check()
            if row.scalar is not None:
                _uint(row.scalar, 0xFFFFFFFF, "P5 image header scalar")
                rows.append(
                    SavedOperationFacadeFreeze((SavedOperationFacadeValue(row.scalar),))
                )
        # Native retries rewind the file, but retain already appended header rows.
        # A failed inner command leaves fresh Rcv fields zero; outer success copies them.
        return ImageFacadeResult(0, previous.freezes + tuple(rows), fields)

    def get_image_ffd_p5(
        self,
        communication: NativeCommunication,
        packet_log: DdrPacketLog,
        schedule: bytes,
        request: ImageP5Request18 | None = None,
        previous: ImageFacadeResult | None = None,
    ) -> ImageFacadeResult:
        self._check()
        self._communication_source(communication)
        self._saved_operation_module(communication, 0xBB, "GetImageFFDP5_DT.dll")
        if self.source.version == 18 and type(request) is not ImageP5Request18:
            raise TypeError("P5 image requires actual typed18 caller fields")
        if self.source.version == 12 and request is not None:
            raise ValueError("Original12 P5 image has no numbers/selector input")
        if previous is not None and type(previous) is not ImageFacadeResult:
            raise TypeError("P5 image requires typed previous output")
        source = ImageP5Source(
            self.source.version, IMAGE_P5_SOURCE_SHA256[self.source.version]
        )
        acquired = capture_image_p5_saved(
            communication,
            packet_log,
            source,
            schedule,
            request,
        )
        self._check()
        return self.compose_image_p5(source, acquired, previous=previous)

    def compose_ads_image(
        self,
        source: AdsImageSource,
        acquired: AdsImageSavedResult,
        *,
        previous: ImageFacadeResult | None = None,
    ) -> ImageFacadeResult:
        """ADS201e0 clears output before execution;1120 copies present support."""
        self._require18()
        if type(source) is not AdsImageSource or source.build != 18:
            raise ValueError("ADS image requires original18 source")
        if (
            type(acquired) is not AdsImageSavedResult
            or acquired.source_sha256 != source.sha256
        ):
            raise ValueError("ADS image result differs from its selected source")
        if previous is not None and type(previous) is not ImageFacadeResult:
            raise TypeError("ADS image requires typed previous output")
        _uint(acquired.native_status, 0xFFFFFFFF, "ADS image native status")
        # Native Clear b0e20 removes the list and zeros all three public DWORDs.
        if acquired.native_status:
            return ImageFacadeResult(acquired.native_status, (), (0, 0, 0))
        fields = (0, 0, 0)
        if not acquired.ddr_provided and acquired.first_support.present:
            _uint(acquired.first_support.value, 0xFFFFFFFF, "ADS first support")
            fields = (1, 0, acquired.first_support.value)
        rows = []
        if acquired.phase is not None:
            if len(acquired.phase.freezes) > 100_000:
                raise ValueError("ADS image facade exceeds host item budget")
            for row in acquired.phase.freezes:
                self._check()
                if row.values:
                    _uint(row.values[0], 0xFFFFFFFF, "ADS image first scalar")
                    rows.append(
                        SavedOperationFacadeFreeze(
                            (SavedOperationFacadeValue(row.values[0]),)
                        )
                    )
        return ImageFacadeResult(0, tuple(rows), fields)

    def get_ads_image_ffd(
        self,
        communication: NativeCommunication,
        packet_log: DdrPacketLog,
        key: bytes,
        request: AdsImageRequest18,
        *,
        previous: ImageFacadeResult | None = None,
    ) -> ImageFacadeResult:
        self._require18()
        self._communication_source(communication)
        self._saved_operation_module(communication, 0xE1, "GetADSImageFFDP5_DT.dll")
        if type(request) is not AdsImageRequest18:
            raise TypeError("ADS image requires actual typed18 caller fields")
        if previous is not None and type(previous) is not ImageFacadeResult:
            raise TypeError("ADS image requires typed previous output")
        source = AdsImageSource(18, ADS_IMAGE_SOURCE_SHA256)
        acquired = capture_ads_image_saved(
            communication, packet_log, source, key, request
        )
        self._check()
        return self.compose_ads_image(source, acquired, previous=previous)

    def ads_image_ffd_report(self, result: ImageFacadeResult) -> dict[str, Any]:
        self._require18()
        if type(result) is not ImageFacadeResult or len(result.native_fields18) != 3:
            raise TypeError("ADS image report requires a typed facade result")
        return {
            "schema": "techstream.command-api.ads-image-ffd.v1",
            "operation": "GetADSImageFFDApi",
            "source": asdict(self.source),
            "result": asdict(result),
        }

    def compose_rc_image(
        self,
        source: RcImageSource,
        acquired: RcImageSavedResult,
        *,
        previous: ImageFacadeResult | None = None,
    ) -> ImageFacadeResult:
        """Original18 RC9c600 clears output and copies first header scalar."""
        self._require18()
        if type(source) is not RcImageSource or source.build != 18:
            raise ValueError("RC image requires original18 source")
        if (
            type(acquired) is not RcImageSavedResult
            or acquired.source_sha256 != source.sha256
        ):
            raise ValueError("RC image result differs from its selected source")
        if previous is not None and type(previous) is not ImageFacadeResult:
            raise TypeError("RC image requires typed previous output")
        _uint(acquired.native_status, 0xFFFFFFFF, "RC image native status")
        if acquired.native_status:
            return ImageFacadeResult(acquired.native_status, (), (0, 0, 0))
        fields = (0, 0, 0)
        if not acquired.ddr_provided and acquired.first_support.present:
            _uint(acquired.first_support.value, 0xFFFFFFFF, "RC first support")
            fields = (1, 0, acquired.first_support.value)
        rows = []
        if acquired.phase is not None:
            if len(acquired.phase.freezes) > 100_000:
                raise ValueError("RC image facade exceeds host item budget")
            for row in acquired.phase.freezes:
                self._check()
                if row.blocks and row.blocks[0].values:
                    scalar = row.blocks[0].values[0]
                    _uint(scalar, 0xFFFFFFFF, "RC image first header scalar")
                    rows.append(
                        SavedOperationFacadeFreeze((SavedOperationFacadeValue(scalar),))
                    )
        return ImageFacadeResult(0, tuple(rows), fields)

    def get_rc_image_ffd(
        self,
        communication: NativeCommunication,
        packet_log: DdrPacketLog,
        schedule: bytes,
        request: RcImageRequest18,
        *,
        previous: ImageFacadeResult | None = None,
    ) -> ImageFacadeResult:
        self._require18()
        self._communication_source(communication)
        self._saved_operation_module(communication, 0xEB, "GetRCImageFFDP5_DT.dll")
        if type(request) is not RcImageRequest18:
            raise TypeError("RC image requires actual typed18 caller fields")
        if previous is not None and type(previous) is not ImageFacadeResult:
            raise TypeError("RC image requires typed previous output")
        source = RcImageSource(18, RC_IMAGE_SOURCE_SHA256)
        acquired = capture_rc_image_saved(
            communication, packet_log, source, schedule, request
        )
        self._check()
        return self.compose_rc_image(source, acquired, previous=previous)

    def rc_image_ffd_report(self, result: ImageFacadeResult) -> dict[str, Any]:
        self._require18()
        if type(result) is not ImageFacadeResult or len(result.native_fields18) != 3:
            raise TypeError("RC image report requires a typed facade result")
        return {
            "schema": "techstream.command-api.rc-image-ffd.v1",
            "operation": "GetRCImageFFDApi",
            "source": asdict(self.source),
            "result": asdict(result),
        }

    def get_image_ffd(
        self,
        communication: NativeCommunication,
        packet_log: DdrPacketLog,
        schedule: bytes,
        *,
        previous: ImageFacadeResult | None = None,
    ) -> ImageFacadeResult:
        """SelectedBB generic P4 producer only; P5 filename is a separate route."""
        self._communication_source(communication)
        self._saved_operation_module(communication, 0xBB, "GetImageFFD_DT.dll")
        if previous is not None and not isinstance(previous, ImageFacadeResult):
            raise TypeError("Image facade requires a typed previous result")
        if type(packet_log) is not DdrPacketLog:
            raise TypeError("Image capture requires the concrete native file owner")
        source = ImageP4Source(
            self.source.version, IMAGE_P4_SOURCE_SHA256[self.source.version]
        )
        acquired = capture_image_p4_saved(communication, packet_log, source, schedule)
        self._check()
        return self.compose_image_p4(source, acquired, previous=previous)

    def image_ffd_report(self, result: ImageFacadeResult) -> dict[str, Any]:
        """Owned plain image result, without raw images, security or paths."""
        self._check()
        if type(result) is not ImageFacadeResult:
            raise TypeError("Image report requires a typed facade result")
        return {
            "schema": "techstream.command-api.image-ffd.v1",
            "operation": "GetImageFFDApi",
            "source": asdict(self.source),
            "result": asdict(result),
        }

    def compose_saved_operations(
        self,
        source: SavedFfdSource,
        acquired: Tss3SavedOperationResult | AdsSavedOperationResult,
        *,
        previous: SavedOperationFacadeResult | None = None,
    ) -> SavedOperationFacadeResult:
        """LCS12/18 and TSS3/18 append first scalar per nonempty native freeze.

        Metadata retains the native reset/constructor fields. Native does not
        copy acquisition group/operation identifiers into the output row.
        """
        self._check()
        if (
            not isinstance(source, SavedFfdSource)
            or source.build != self.source.version
            or source.sha256
            not in (
                LCS_SOURCE_SHA256.get(source.build),
                TSS3_SOURCE_SHA256,
                ADS_OPERATION_SOURCE_SHA256,
            )
        ):
            raise ValueError("Saved operation facade and producer sources differ")
        if not isinstance(
            acquired, (Tss3SavedOperationResult, AdsSavedOperationResult)
        ):
            raise TypeError("Saved operation facade requires concrete acquisition")
        if isinstance(acquired, AdsSavedOperationResult) != (
            source.sha256 == ADS_OPERATION_SOURCE_SHA256
        ):
            raise ValueError("Saved operation result has a different producer kind")
        previous = SavedOperationFacadeResult(0) if previous is None else previous
        if not isinstance(previous, SavedOperationFacadeResult):
            raise TypeError("Saved operation facade requires typed prior output")
        _uint(acquired.native_status, 0xFFFFFFFF, "Saved operation native status")
        if acquired.native_status:
            return SavedOperationFacadeResult(acquired.native_status, previous.freezes)
        if isinstance(acquired, AdsSavedOperationResult):
            if any(phase.source_sha256 != source.sha256 for phase in acquired.phases):
                raise ValueError("ADS operation phase has a different producer source")
            received = acquired.freezes
        else:
            if acquired.report is None:
                raise ValueError(
                    "Successful saved operation has no native freeze report"
                )
            received = acquired.report.freezes
        if len(received) + len(previous.freezes) > 100_000:
            raise ValueError("Saved operation facade exceeds host item budget")
        freezes = []
        for freeze in received:
            self._check()
            if (
                isinstance(freeze, Tss3SavedFreeze)
                and freeze.acquisition.source_sha256 != source.sha256
            ):
                raise ValueError(
                    "Saved operation freeze has a different producer source"
                )
            values = freeze.native_values
            if values:
                freezes.append(
                    SavedOperationFacadeFreeze((SavedOperationFacadeValue(values[0]),))
                )
        self._check()
        return SavedOperationFacadeResult(0, previous.freezes + tuple(freezes))

    def saved_operation_report(
        self,
        source: SavedFfdSource,
        result: SavedOperationFacadeResult,
    ) -> dict[str, object]:
        """Saved/UI logical fields only; no key, native raw reply or log path."""
        self._check()
        if (
            not isinstance(source, SavedFfdSource)
            or source.build != self.source.version
        ):
            raise ValueError("Saved operation report has a different source version")
        if type(result) is not SavedOperationFacadeResult:
            raise TypeError("Saved operation report requires a concrete facade result")
        names = {
            TSS3_SOURCE_SHA256: "GetTSS3OperationFFDApi",
            ADS_OPERATION_SOURCE_SHA256: "GetADSOperationFFDApi",
            **{sha: "GetLCSOperationFFDApi" for sha in LCS_SOURCE_SHA256.values()},
        }
        if source.sha256 not in names:
            raise ValueError("Saved operation report has no reconciled producer")
        return {
            "schema": "techstream-command-saved-operation-v1",
            "operation": names[source.sha256],
            "source_version": self.source.version,
            "source_sha256": self.source.sha256,
            "producer_sha256": source.sha256,
            "result": asdict(result),
        }

    def get_ads_operation_ffd(
        self,
        communication: NativeCommunication,
        packet_log: DdrPacketLog,
        key: bytes,
        *,
        previous: SavedOperationFacadeResult | None = None,
    ) -> SavedOperationFacadeResult:
        """Actual selected E0 security/phase3/phase4/logging to scalar facade."""
        self._require18()
        self._communication_source(communication)
        source = SavedFfdSource(18, ADS_OPERATION_SOURCE_SHA256)
        self._saved_operation_module(communication, 0xE0, "GetADSOperationFFDP5_DT.dll")
        acquired = capture_ads_saved_operations(communication, packet_log, source, key)
        self._check()
        return self.compose_saved_operations(source, acquired, previous=previous)

    def get_tss3_operation_ffd(
        self,
        communication: NativeCommunication,
        packet_log: DdrPacketLog,
        *,
        previous: SavedOperationFacadeResult | None = None,
    ) -> SavedOperationFacadeResult:
        self._require18()
        self._communication_source(communication)
        source = SavedFfdSource(18, TSS3_SOURCE_SHA256)
        self._saved_operation_module(
            communication, 0xEA, "GetTSS3OperationFFDP5_DT.dll"
        )
        acquired = capture_tss3_saved_operations(communication, packet_log, source)
        self._check()
        return self.compose_saved_operations(source, acquired, previous=previous)

    def get_lcs_operation_ffd(
        self,
        communication: NativeCommunication,
        packet_log: DdrPacketLog,
        *,
        previous: SavedOperationFacadeResult | None = None,
    ) -> SavedOperationFacadeResult:
        self._check()
        self._communication_source(communication)
        source = SavedFfdSource(
            self.source.version, LCS_SOURCE_SHA256[self.source.version]
        )
        self._saved_operation_module(communication, 0xD0, "GetLCSOperationFFDP5_DT.dll")
        acquired = capture_lcs_saved_operations(communication, packet_log, source)
        self._check()
        return self.compose_saved_operations(source, acquired, previous=previous)

    @staticmethod
    def _saved_operation_module(
        communication: NativeCommunication,
        command: int,
        name: str,
    ) -> None:
        rows = communication.profile.dll_records(command)
        if tuple(row[:80].decode("utf-16le").split("\0", 1)[0] for row in rows) != (
            name,
        ):
            raise NotImplementedError(
                "Selected saved operation has no reconciled producer"
            )

    def get_vin(
        self,
        communication: NativeCommunication,
        *,
        previous: bytes = b"",
    ) -> VinResult:
        """Selected original12/18 command51 dispatch, native wire and owned facade.

        GetVIN_DT counts8b/aggregates86; GetVIN_CAN_DT consumes the first86
        multi-receive result. No caller-provided command names select the route.
        """
        self._check()
        self._communication_source(communication)
        if type(previous) is not bytes:
            raise TypeError("Previous VIN must own immutable bytes")
        profile, cache = communication.profile, communication.cache
        modules = profile.dll_records(0x51)
        if not modules:
            return self.compose_vin(
                VinReply(CommandStatus(1, 0xC0040101), 0, b""), previous=previous
            )
        names = tuple(row[:80].decode("utf-16le").split("\0", 1)[0] for row in modules)
        if names not in (
            ("GetVIN_DT.dll",),
            ("GetVIN_CAN_DT.dll",),
            ("GetVinPSA_DT.dll",),
        ):
            raise NotImplementedError(
                "Selected command51 module has no reconciled VIN producer"
            )

        def frame(function: int):
            try:
                rows = profile.frame_records(function)
            except ValueError as error:
                if str(error) in (
                    "No selected function communication frames",
                    "No selected communication frame",
                ):
                    raise ToyotaCodecError(
                        "Selected VIN frame is absent", 0xC0040101
                    ) from error
                raise
            if len(rows) != 1:
                raise ToyotaCodecError(
                    "VIN requires exactly one selected frame", 0xC0040102
                )
            return rows[0]

        try:
            payload = b""
            if names[0] == "GetVinPSA_DT.dll":
                selected = frame(0xEA)
                reply = cache.transaction(
                    selected, selected.frame.request, cached=False
                )
                if len(reply) <= 2:
                    raise ToyotaCodecError("PSA VIN reply lacks payload", 0xA0040202)
                if reply[2]:
                    payload = reply[2:]
            else:
                count = 1
                if names[0] == "GetVIN_DT.dll":
                    selected = frame(0x8B)
                    reply = cache.transaction(
                        selected, selected.frame.request, cached=False
                    )
                    if len(reply) < 3:
                        raise ToyotaCodecError(
                            "VIN count reply lacks byte2", 0xA0040202
                        )
                    count = reply[2]
                payload = b""
                if count:
                    observed = cache.multi_receive(frame(0x86))
                    if observed.status:
                        raise ToyotaCodecError(
                            "VIN multi-receive failed", observed.status
                        )
                    if len(observed.replies) < count:
                        raise ToyotaCodecError(
                            "VIN has fewer replies than native count", 0xA0040201
                        )
                    chunks = observed.replies[:count]
                    if any(len(reply) < 3 for reply in chunks):
                        raise ToyotaCodecError(
                            "VIN reply lacks its three-byte prefix", 0xA0040202
                        )
                    joined = b"".join(reply[3:] for reply in chunks)
                    payload = bytes(
                        value
                        for index, value in enumerate(joined)
                        if value or index > 2
                    )
            if len(payload) >= 255:
                raise ValueError(
                    "VIN exceeds native255-byte zero-terminated scratch area"
                )
        except ToyotaCodecError as error:
            self._check()
            return self.compose_vin(
                VinReply(CommandStatus(1, error.code), 0, b""), previous=previous
            )
        self._check()
        return self.compose_vin(
            VinReply(CommandStatus(), len(payload) + 1, payload), previous=previous
        )

    def selected_can_vin(
        self, session: ToyotaSession, count_command: str, data_command: str
    ) -> VinResult:
        """Host join to concrete GetVIN_DT multi-receive producer, not ABI proof."""
        self._require18()
        if not isinstance(session, ToyotaSession):
            raise TypeError("An actual selected ToyotaSession is required")
        payload = session.vin_multi(count_command, data_command)
        self._check()
        return self.compose_vin(VinReply(CommandStatus(), len(payload) + 1, payload))

    def _profile_version(self, version: int) -> None:
        expected = {12: 0x0100030C, 18: 0x0100032F}[self.source.version]
        if version != expected:
            raise ValueError("Selected database and CommandAPI source versions differ")

    def selected_ecu_groups(
        self,
        catalog: VehicleCatalog,
        context: EcuGroupContext,
        *,
        exception_ids: tuple[int, ...] = (),
    ) -> EcuGroupSelection:
        """Actual GetEcuGroupList1010/1240 over selected105 rows and shared WORDs.

        Names remain source Unicode. The native ACP conversion is a separate,
        unresolved presentation boundary, not guessed from the Linux locale.
        """
        self._check()
        if not isinstance(catalog, VehicleCatalog) or not isinstance(
            context, EcuGroupContext
        ):
            raise TypeError(
                "ECU groups require selected catalog and typed shared context"
            )
        self._profile_version(catalog.management.version)
        source = catalog.management.sha256
        if context.vehicle_lookup_status:
            return EcuGroupSelection(context.vehicle_lookup_status, (), context, source)
        if context.vehicle_key is None:
            return EcuGroupSelection(0xC0040601, (), context, source)
        try:
            rows = catalog.ecu_group_records(context.vehicle_key, 1, exception_ids)
        except ToyotaCodecError as error:
            return EcuGroupSelection(error.code, (), context, source)
        if not rows:
            return EcuGroupSelection(0xC0040101, (), context, source)
        status = 0
        updated = context
        try:
            defaults = catalog.ecu_group_records(context.vehicle_key, 2, exception_ids)
        except ToyotaCodecError as error:
            status = error.code
        else:
            if not defaults:
                status = 0xC0040101
            elif context.default_lookup_status:
                status = context.default_lookup_status
            elif context.default_group is None:
                status = 0xC0040601
            else:
                updated = EcuGroupContext(
                    context.vehicle_key,
                    int.from_bytes(defaults[0][6:8], "little"),
                    context.vehicle_lookup_status,
                    context.default_lookup_status,
                )
        entries = tuple(
            SelectedEcuGroup(
                int.from_bytes(row[6:8], "little"),
                int.from_bytes(row[:4], "little"),
                catalog.language.resolve(int.from_bytes(row[:4], "little")),
                row,
            )
            for row in rows
        )
        self._check()
        return EcuGroupSelection(status, entries, updated, source)

    def selected_active_tests(
        self,
        catalog: ActiveTestCatalog,
        family: str,
        *,
        support: ActiveSupport,
    ) -> tuple[ActiveTest, ...]:
        """Typed domain list; caller keeps language/ACP provenance unchanged."""
        self._check()
        if not isinstance(catalog, ActiveTestCatalog):
            raise TypeError("An actual selected ActiveTestCatalog is required")
        self._profile_version(catalog.profile.database.version)
        result = catalog.list(family, support=support)
        self._check()
        return result

    def selected_active_initialization(
        self,
        catalog: ActiveTestCatalog,
        family: str,
        signal_id: int,
        *,
        support: ActiveSupport,
        read_value: Callable[[str, bytes], int | None] | None = None,
    ) -> ActiveTestInitialization:
        self._check()
        if not isinstance(catalog, ActiveTestCatalog):
            raise TypeError("An actual selected ActiveTestCatalog is required")
        self._profile_version(catalog.profile.database.version)
        result = catalog.initialize(
            family, signal_id, support=support, read_value=read_value
        )
        self._check()
        return result

    def selected_active_run(
        self,
        replay: ActiveReplay,
        signal_id: int,
        arguments: Mapping[str, Any],
        *,
        family: str | None = None,
    ) -> dict[str, Any]:
        self._check()
        if not isinstance(replay, ActiveReplay):
            raise TypeError("An actual chronological ActiveReplay is required")
        self._profile_version(replay.profile.database.version)
        result = replay.run_test(signal_id, dict(arguments), family=family)
        self._check()
        return result

    def selected_clear_dtc(self, workflow: ToyotaWorkflows) -> dict[str, object]:
        self._check()
        if not isinstance(workflow, ToyotaWorkflows):
            raise TypeError("An actual selected ToyotaWorkflows is required")
        if workflow.observations.source_version != self.source.version:
            raise ValueError("Workflow and CommandAPI source versions differ")
        result = workflow.clear_dtc()
        self._check()
        return result

    def selected_monitor(
        self,
        plan: MonitorSetup,
        client: NativeVimClient,
        *,
        interface_id: int,
        frame_sizes: tuple[tuple[int, int], ...],
        phase: int,
        packet_limit: int,
        limits: Limits | None = None,
    ) -> tuple[MonitorPacket, ...]:
        """Actual DMCI setup/start/read/stop; final facade view remains OPEN."""
        self._check()
        if not isinstance(plan, MonitorSetup) or not isinstance(
            client, NativeVimClient
        ):
            raise TypeError(
                "Selected monitor requires actual setup and native VIM client"
            )
        result = run_monitor_commands(
            plan,
            client,
            interface_id=interface_id,
            frame_sizes=frame_sizes,
            phase=phase,
            packet_limit=packet_limit,
            limits=limits,
            cancelled=self.cancelled,
        )
        self._check()
        return result

    def selected_ddr_samples(
        self,
        reader: NativeRamReader,
        *,
        spec_value: int,
        base_address: int,
        record_index: int,
    ) -> DdrRecordSamples | None:
        """Raw DDR record capture; never label samples a CCmdDdrInfo result."""
        self._check()
        if not isinstance(reader, NativeRamReader):
            raise TypeError("DDR requires the actual selected native RAM reader")
        self._profile_version(reader.profile.database.version)
        result = capture_ddr_record_samples(
            reader,
            spec_value=spec_value,
            base_address=base_address,
            record_index=record_index,
        )
        self._check()
        return result

    def selected_ddr_report(self, communication: NativeCommunication) -> DdrReport:
        """Actual selected normal DDR attributes, capture and CCmdDdrInfo fields."""
        self._require18()
        self._communication_source(communication)
        result = capture_ddr_report(communication)
        self._check()
        return result

    def selected_ddr_p5_report(self, cache: MonitorSupportCache) -> DdrP5Report:
        """Actual selected P5 DID acquisition and command-report composition."""
        self._require18()
        self._cache_source(cache)
        result = capture_ddr_p5_report(cache)
        self._check()
        return result

    def selected_ads_ddr_report(
        self,
        cache: MonitorSupportCache,
        key: bytes,
    ) -> AdsDdrReport:
        """Actual selected ADS security, observations and CCmdADSDdrInfo fields.

        Key bytes are confined to the producer; no key is retained in this facade.
        The caller obtains the source-bound key using selected_ads_security_key.
        """
        self._require18()
        self._cache_source(cache)
        result = capture_ads_ddr_report(cache, key)
        self._check()
        return result

    def selected_ddr_saved_log(
        self,
        communication: NativeCommunication,
        packet_log: DdrPacketLog,
    ) -> DdrReport:
        """Actual selected normal report inside the native packet-file lifecycle."""
        self._require18()
        self._communication_source(communication)
        if not isinstance(packet_log, DdrPacketLog):
            raise TypeError("DDR saved log requires the concrete native file owner")
        result = capture_ddr_saved_log(communication, packet_log)
        self._check()
        return result

    def selected_ddr_p5_saved_log(
        self,
        communication: NativeCommunication,
        packet_log: DdrPacketLog,
    ) -> DdrP5Report:
        """Actual selected P5 report, native Disconnect1 and conditional file Stop."""
        self._require18()
        self._communication_source(communication)
        if not isinstance(packet_log, DdrPacketLog):
            raise TypeError("P5 saved log requires the concrete native file owner")
        result = capture_ddr_p5_saved_log(communication, packet_log)
        self._check()
        return result

    def _cache_source(self, cache: MonitorSupportCache) -> None:
        if not isinstance(cache, MonitorSupportCache):
            raise TypeError("CommandAPI requires a concrete selected support cache")
        if cache.source_build != self.source.version:
            raise ValueError("Support cache and CommandAPI source versions differ")
        if not isinstance(cache.profile, VehicleProfile):
            raise TypeError(
                "Toyota CommandAPI requires a selected Toyota database profile"
            )
        self._profile_version(cache.profile.database.version)
        cache.check_context()

    def _communication_source(self, communication: NativeCommunication) -> None:
        if not isinstance(communication, NativeCommunication):
            raise TypeError("CommandAPI requires concrete selected communication")
        if communication.source_build != self.source.version:
            raise ValueError("Communication and CommandAPI source versions differ")
        self._cache_source(communication.cache)

    def selected_translation(
        self,
        resources: TextResources,
        identifiers: Sequence[int],
    ) -> tuple[ResourceText, ...]:
        """Concrete source-identified ordered resource lookup, no guessed empty text."""
        self._check()
        if not isinstance(resources, TextResources):
            raise TypeError("Translation requires concrete native text resources")
        result = resources.translate(identifiers)
        self._check()
        return result

    def selected_dcm_p5_analysis(self, provider: DcmP5Analysis) -> AnalysisResult:
        """Concrete DCM35 business acquisition/parser; facade assembly stays OPEN."""
        self._require18()
        if not isinstance(provider, DcmP5Analysis):
            raise TypeError(
                "Work-factor analysis requires the concrete DCM P5 provider"
            )
        self._profile_version(provider.profile.database.version)
        result = provider.run()
        self._check()
        return result

    def selected_recorder_group(
        self,
        executor: NativeDrsExecutor,
        group_id: int,
        *,
        timeout: float = 10.0,
    ) -> tuple[object, ...]:
        """Execute concrete DRS primitive state machine, preserving owned channel."""
        self._check()
        if not isinstance(executor, NativeDrsExecutor):
            raise TypeError("Recorder requires the actual native DRS executor")
        result = executor.execute_group(
            group_id, timeout=timeout, cancelled=self.cancelled
        )
        self._check()
        return result

    def close(self) -> None:
        """Close this composer; injected engines retain their own lifetimes."""
        self.closed = True
