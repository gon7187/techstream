"""Native saved FFD producers over concrete selected diagnostic primitives.

TSS3 and LCS operation groups, records and outer logging/connection lifecycle
execute natively in Python. ADS selected64-bit field/condition interpretation is present;
other saved image/operation business producers remain unreconciled.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from scripts.monitor_support import MonitorSupportCache, monitor_source_identity
from scripts.profiles import SelectedFrame, VehicleProfile
from scripts.toyota import ToyotaCodecError
from scripts.toyota_session import SessionError

if TYPE_CHECKING:
    from scripts.database_resources import (
        AdsSecurityExchange,
        DdrDataIdTransaction,
        DdrPacketLog,
    )
    from scripts.native_communication import NativeCommunication


TSS3_SOURCE_SHA256 = "8d8461cf1b1f9b9917919fa4ea366891e0867c2f3e82d56d1a27ae2990e38f86"
ADS_OPERATION_SOURCE_SHA256 = (
    "c5549207080aabc0a7d415caa610818fd0df4ca2afc78a14b3c5a6e1861d8bce"
)
LCS_SOURCE_SHA256 = {
    12: "70fd00da7f49e35cc0d23479e4ef6572859b8c044f99b1e1eba18bf90d10c24f",
    18: "f9ed3d6ba96482c019f15ce83df937038f8fcef00947069c646b8c832a0a2db6",
}


def _word(value: int) -> int:
    if type(value) is not int or not 0 <= value <= 0xFFFF:
        raise ValueError("Native selector must fit unsigned WORD")
    return value


@dataclass(frozen=True)
class SavedFfdSource:
    build: int
    sha256: str

    def __post_init__(self) -> None:
        if type(self.build) is not int or (self.build, self.sha256) not in (
            (18, TSS3_SOURCE_SHA256),
            (18, ADS_OPERATION_SOURCE_SHA256),
            *LCS_SOURCE_SHA256.items(),
        ):
            raise ValueError("Unreconciled saved FFD producer source")


@dataclass(frozen=True)
class OperationDataId:
    did: int
    payload: bytes

    def __post_init__(self) -> None:
        if (
            not _word(self.did)
            or type(self.payload) is not bytes
            or not 1 <= len(self.payload) <= 255
        ):
            raise ValueError("CCmdDataIdData requires nonzero DID and BYTE length")


@dataclass(frozen=True)
class Tss3OperationGroup:
    records: tuple[OperationDataId, ...]
    values: tuple[int, ...]


@dataclass(frozen=True)
class Tss3OperationRequest:
    group: int
    operation: int

    def __post_init__(self) -> None:
        _word(self.group)
        _word(self.operation)

    @property
    def payload(self) -> bytes:
        # TSS3Operation18 RVA1540/1772: group WORD first, operation WORD second.
        return (
            b"\xab\x13"
            + self.group.to_bytes(2, "big")
            + self.operation.to_bytes(2, "big")
        )


@dataclass(frozen=True)
class Tss3OperationAcquisition:
    request: Tss3OperationRequest
    raw_reply: bytes
    groups: tuple[Tss3OperationGroup, ...]
    source_sha256: str
    frame_provenance: str


def tss3_operation_groups(reply: bytes) -> tuple[Tss3OperationGroup, ...]:
    """18 RVA1a70..1f0c: six-byte prefix, count + DID/length/data groups.

    Truncated groups end the native loop and retain complete records. DID zero,
    zero length and duplicate DIDs are omitted; the first DID wins per group.
    RVA20b0 counts from absolute offset7 when a group count is zero.
    """
    if type(reply) is not bytes or len(reply) > 4096:
        raise ValueError("Operation receive must be immutable native frame bytes")
    if len(reply) <= 6:
        return ()
    groups = []
    position = 6
    while position < len(reply):
        count = reply[position]
        position += 1
        if count == 0:
            cursor = 7
            while cursor + 3 <= len(reply):
                cursor += 3 + reply[cursor + 2]
                if cursor > len(reply):
                    break
                count += 1
                if cursor == len(reply):
                    break
        records: dict[int, OperationDataId] = {}
        for _ in range(count):
            if position + 3 > len(reply):
                break
            did = int.from_bytes(reply[position : position + 2], "big")
            length = reply[position + 2]
            position += 3
            if position + length > len(reply):
                break
            payload = reply[position : position + length]
            position += length
            if did and length and did not in records:
                records[did] = OperationDataId(did, payload)
        if records:
            # RVA1f90: only DID0501 with length >=2 creates CCmdMultiData.
            values = tuple(
                int.from_bytes(r.payload[:2], "big")
                for r in records.values()
                if r.did == 0x0501 and len(r.payload) >= 2
            )
            groups.append(Tss3OperationGroup(tuple(records.values()), values))
    return tuple(groups)


def tss3_supported_ids(reply: bytes) -> tuple[int, ...]:
    """18 RVA1280..137c: floor((receive length-2)/2), big-endian WORDs."""
    if type(reply) is not bytes or len(reply) > 4096:
        raise ValueError("Support receive must be immutable native frame bytes")
    count = (len(reply) - 2) // 2
    if count <= 0:
        raise ToyotaCodecError("No native operation identifiers", 0x90040501)
    return tuple(
        int.from_bytes(reply[i : i + 2], "big") for i in range(2, 2 + count * 2, 2)
    )


class SavedFfdProvider:
    """Source-bound TSS3/LCS selected group/record producers.

    The outer owner composes its concrete connection and file lifecycle.
    """

    def __init__(self, support: MonitorSupportCache, source: SavedFfdSource):
        if not isinstance(support, MonitorSupportCache) or not isinstance(
            source, SavedFfdSource
        ):
            raise TypeError("Saved FFD requires concrete selected cache and source")
        if support.source_build != source.build:
            raise ValueError("Saved FFD and communication source builds differ")
        self.support, self.source = support, source
        self.identity = monitor_source_identity(support.profile, support.ecu)

    def _selected_frame(self) -> SelectedFrame:
        if (
            self.support.source_build != self.source.build
            or self.support.identity != self.identity
            or monitor_source_identity(self.support.profile, self.support.ecu)
            != self.identity
        ):
            raise SessionError("Saved FFD selected source changed")
        try:
            frames = self.support.profile.frame_records(0x66)
        except ValueError as error:
            if str(error) not in (
                "No selected function communication frames",
                "No selected communication frame",
            ):
                raise
            raise ToyotaCodecError(
                "Selected operation frame absent", 0xC0040101
            ) from error
        if not frames:
            raise ToyotaCodecError("Selected operation frame absent", 0xC0040101)
        return frames[0]

    def _require_source(self, *, lcs: bool = False) -> None:
        expected = (
            LCS_SOURCE_SHA256.get(self.source.build) if lcs else TSS3_SOURCE_SHA256
        )
        if self.source.sha256 != expected:
            raise ValueError("Selected source is not this operation producer")

    def tss3_supported_ids(self) -> tuple[int, ...]:
        self._require_source()
        frame = self._selected_frame()
        reply = self.support.transaction(
            frame, b"\xab\x11", cached=False, extended=True
        )
        return tss3_supported_ids(reply)

    def tss3_operation(self, request: Tss3OperationRequest) -> Tss3OperationAcquisition:
        self._require_source()
        if not isinstance(request, Tss3OperationRequest):
            raise TypeError("TSS3 requires typed operation selectors")
        frame = self._selected_frame()
        reply = self.support.transaction(
            frame, request.payload, cached=False, extended=True
        )
        return Tss3OperationAcquisition(
            request,
            reply,
            tss3_operation_groups(reply),
            self.source.sha256,
            frame.provenance,
        )

    def capture_tss3_operation_records(self) -> Tss3OperationReport:
        """TSS3Operation18 RVA2790: actual group/index/record business producer.

        It omits the outer Execute32f0 connection/log/disconnect owner, which is
        composed separately by capture_tss3_saved_operations.
        """
        self._require_source()
        frame = self._selected_frame()
        with self.support.temporary_scope(no_init=True):
            return self._capture_operation_records(frame, _TSS3_NON_OPERATION_GROUPS)

    def capture_lcs_operation_records(self) -> Tss3OperationReport:
        """LCS12 RVA2a70 /18 RVA2b30: three TEMP preflights, then actual records.

        Only the preflight cache sets no-init. Each AB helper constructs a fresh
        default cache, so their sends retain normal initialization semantics.
        """
        self._require_source(lcs=True)
        frame = self._selected_frame()
        with self.support.temporary_scope(no_init=True):
            for number in (1, 2, 3):
                self.support.transaction(
                    frame,
                    bytes((0x22, 0x1F, number)),
                    cached=False,
                    temporary=True,
                    extended=True,
                )
        with self.support.temporary_scope():
            return self._capture_operation_records(frame, frozenset())

    def _capture_operation_records(
        self, frame: SelectedFrame, excluded: frozenset[int]
    ) -> Tss3OperationReport:
        suppressed: list[tuple[bytes, int]] = []
        freezes: list[Tss3SavedFreeze] = []
        retained = 0
        raw = self.support.transaction(frame, b"\xab\x11", cached=False, extended=True)
        groups = tss3_supported_ids(raw)
        if excluded and all(group in excluded for group in groups):
            raise ToyotaCodecError("Native list has no operation groups", 0x90040501)
        for group in groups:
            if group in excluded:
                continue
            request = b"\xab\x12" + group.to_bytes(2, "big")
            try:
                raw = self.support.transaction(
                    frame, request, cached=False, extended=True
                )
                numbers = tss3_operation_numbers(raw)
            except ToyotaCodecError as error:
                if error.code not in _OPERATION_SUPPRESSED:
                    raise
                suppressed.append((request, error.code))
                continue
            failed = False
            for number in numbers:
                selection = Tss3OperationRequest(group, number)
                try:
                    raw = self.support.transaction(
                        frame, selection.payload, cached=False, extended=True
                    )
                except ToyotaCodecError as error:
                    if error.code not in _OPERATION_SUPPRESSED:
                        raise
                    suppressed.append((selection.payload, error.code))
                    if failed:
                        break
                    failed = True
                    continue
                failed = False
                rows = tss3_operation_groups(raw)
                if not any(row.values for row in rows) or not 0 < number <= 255:
                    continue
                retained += len(raw)
                if retained > 32 * 1024 * 1024 or len(freezes) >= 100_000:
                    raise SessionError(
                        "Saved operation result exceeds host storage allowance"
                    )
                acquisition = Tss3OperationAcquisition(
                    selection, raw, rows, self.source.sha256, frame.provenance
                )
                freezes.append(Tss3SavedFreeze(number, group, acquisition))
        return Tss3OperationReport(groups, tuple(freezes), tuple(suppressed))


ADS_DDR_SOURCE_SHA256 = (
    "28a4474c71344970c3e9736af1d835215d0aac02d4f31cee832101981f1246df"
)


@dataclass(frozen=True)
class AdsOperationGroup:
    records: tuple[tuple[int, bytes], ...]
    values: tuple[int, ...]


@dataclass(frozen=True)
class AdsOperationFreeze:
    phase: int
    group: int
    operation: int
    raw_reply: bytes
    groups: tuple[AdsOperationGroup, ...]

    @property
    def native_values(self) -> tuple[int, ...]:
        return tuple(value for group in self.groups for value in group.values)


@dataclass(frozen=True)
class AdsOperationPhase:
    phase: int
    groups: tuple[int, ...]
    freezes: tuple[AdsOperationFreeze, ...]
    suppressed_errors: tuple[tuple[bytes, int], ...]
    source_sha256: str
    frame_provenance: str


@dataclass(frozen=True)
class AdsSavedOperationResult:
    native_status: int
    phases: tuple[AdsOperationPhase, ...]
    security: AdsSecurityExchange | None
    readiness: tuple[DdrDataIdTransaction, ...]
    disconnect_status: int
    log_path: str

    @property
    def freezes(self) -> tuple[AdsOperationFreeze, ...]:
        return tuple(freeze for phase in self.phases for freeze in phase.freezes)


def capture_ads_saved_operations(
    communication: NativeCommunication,
    packet_log: DdrPacketLog,
    source: SavedFfdSource,
    key: bytes,
) -> AdsSavedOperationResult:
    """ADSOperation18 Execute1010: security/ready→phase3→log switch→phase4.

    Key material is explicit BYOD input, obtainable with selected_ads_security_key;
    the native key and vendor resource text are never embedded in this module.
    """
    from scripts.database_resources import (
        DdrP5DataIdReader,
        DdrPacketLog,
        cancel_ads_security,
    )
    from scripts.native_communication import NativeCommunication, NativeFrameController

    if (
        not isinstance(communication, NativeCommunication)
        or not isinstance(communication.operations, NativeFrameController)
        or type(packet_log) is not DdrPacketLog
        or packet_log.operations is not communication.operations
        or not isinstance(source, SavedFfdSource)
        or source.sha256 != ADS_OPERATION_SOURCE_SHA256
        or communication.source_build != 18
    ):
        raise ValueError("ADS operation requires concrete18 communication/log/source")
    cache = communication.cache
    cache.check_context()
    started = packet_log.start(22)
    status, disconnected, stopped = 0, 0, 0
    phases: list[AdsOperationPhase] = []
    security = None
    reader = None
    primary: BaseException | None = None
    try:
        try:
            connection = communication.connection_no_buffer(0, 11)
            if connection.status:
                raise ToyotaCodecError("ADS connection failed", connection.status)
            SavedFfdProvider(cache, source)._selected_frame()
            with cache.temporary_scope(no_init=True):
                security = cancel_ads_security(cache, key)
                reader = DdrP5DataIdReader(cache, enable_list=False, no_init=True)
                state, _ = reader.read_no_enable_list(0x1C08, 1)
                if state != 1:
                    raise ToyotaCodecError("ADS readiness support absent", 0x90040501)
                state, ready = reader.read_no_enable_list(0x1C08, 6)
                if state != 2 or not ready or ready[0] != 0:
                    raise ToyotaCodecError(
                        "ADS readiness status unavailable", 0x90040501
                    )
                first_status = 0
                try:
                    phases.append(capture_ads_operation_phase(cache, source, 3))
                except ToyotaCodecError as error:
                    if error.code not in _OPERATION_SUPPRESSED | {0x90040501}:
                        raise
                    first_status = error.code
                if started == 0:
                    started = packet_log.change(23)
                    if started:
                        packet_log.stop()  # Native ignores this immediate stop status.
                try:
                    phases.append(capture_ads_operation_phase(cache, source, 4))
                except ToyotaCodecError as error:
                    if error.code not in _OPERATION_SUPPRESSED | {0x90040501}:
                        raise
                    status = first_status
        except ToyotaCodecError as error:
            status = error.code
    except BaseException as error:
        primary = error
        raise
    finally:
        disconnected, stopped = _cleanup_saved_operation(
            communication, packet_log, started, primary
        )
    return AdsSavedOperationResult(
        status or started or stopped,
        tuple(phases),
        security,
        tuple(reader.transactions) if reader else (),
        disconnected,
        str(packet_log.path),
    )


def ads_operation_groups(reply: bytes) -> tuple[AdsOperationGroup, ...]:
    """ADSOperation18 RVA23f0/2ae0: grouped Ext DID records after eight bytes.

    DIDs6000..6fff have a four-byte length; other DIDs have a one-byte length.
    Zero-count fallback restarts at absolute offset9, including in later groups.
    """
    if type(reply) is not bytes or len(reply) > 65535:
        raise ValueError("ADS operation receive must be owned native frame bytes")

    def entry(position: int) -> tuple[int, int, int] | None:
        if position + 2 > len(reply):
            return None
        did = int.from_bytes(reply[position : position + 2], "big")
        width = 4 if 0x6000 <= did <= 0x6FFF else 1
        end = position + 2 + width
        if end > len(reply):
            return None
        return did, int.from_bytes(reply[position + 2 : end], "big"), end

    groups: list[AdsOperationGroup] = []
    position = 8
    while position < len(reply):
        count = reply[position]
        position += 1
        if count == 0:
            cursor = 9
            while cursor < len(reply):
                parsed = entry(cursor)
                if parsed is None or parsed[2] + parsed[1] > len(reply):
                    break
                count += 1
                cursor = parsed[2] + parsed[1]
        records: dict[int, bytes] = {}
        for _ in range(count):
            parsed = entry(position)
            if parsed is None:
                break
            did, length, position = parsed
            if position + length > len(reply):
                break
            payload = reply[position : position + length]
            position += length
            if did and length and did not in records:
                records[did] = payload
        if not records:
            # Native23f0 exits the outer loop when this parsed list is empty.
            break
        values = tuple(
            int.from_bytes(payload[:2], "big")
            for did, payload in records.items()
            if did == 0x0501 and len(payload) >= 2
        )
        groups.append(AdsOperationGroup(tuple(records.items()), values))
    return tuple(groups)


# Native3b10 scans42 WORDs, including adjacent vtable words; ASM verifies bound.
_ADS_OPERATION_GROUPS = frozenset(
    (
        0x2815,
        0x2817,
        0x2818,
        0x2819,
        0x281A,
        0x281B,
        0x281C,
        0x281D,
        0x281E,
        0x281F,
        0x2830,
        0x2831,
        0x2832,
        0x2833,
        0x2834,
        0x2835,
        0x2836,
        0x2837,
        0x2838,
        0x2839,
        0x283A,
        0,
        13216,
        4096,
        13264,
        4096,
        15184,
        4096,
        0,
        0,
        65535,
        65535,
        0,
        0,
        16633,
        4096,
        0,
        0,
        65535,
        65535,
        16717,
        4096,
    )
)


def capture_ads_operation_phase(
    cache: MonitorSupportCache, source: SavedFfdSource, phase: int
) -> AdsOperationPhase:
    """ADS18 RVA33d0 phase3/4 business; outer owner must acquire security/ready.

    This is the actual group→DWORD index→Ext payload producer, not the complete
    two-phase Execute owner. Every read uses its passed no-init cache flags.
    """
    if (
        type(cache) is not MonitorSupportCache
        or not isinstance(source, SavedFfdSource)
        or source.sha256 != ADS_OPERATION_SOURCE_SHA256
        or cache.source_build != 18
        or type(phase) is not int
        or phase not in (3, 4)
    ):
        raise ValueError("ADS operation phase requires exact18 source and phase3/4")
    provider = SavedFfdProvider(cache, source)
    frame = provider._selected_frame()
    base = 0x21 if phase == 3 else 0x31

    def read(request: bytes) -> bytes:
        return cache.transaction(
            frame, request, cached=False, extended=True, capacity=65535
        )

    raw = read(bytes((0xAB, base)))
    # Native unsigned subtraction on a short prefix would allocate unboundedly.
    if len(raw) < 2:
        raise ToyotaCodecError("ADS operation support prefix is short", 0xA0040202)
    groups = tuple(
        int.from_bytes(raw[i : i + 2], "big") for i in range(2, len(raw) - 1, 2)
    )
    if not groups:
        raise ToyotaCodecError("ADS operation support list is empty", 0x90040501)
    accepted = False
    retained = 0
    freezes: list[AdsOperationFreeze] = []
    errors: list[tuple[bytes, int]] = []
    for group in groups:
        if group not in _ADS_OPERATION_GROUPS:
            continue
        accepted = True
        request = bytes((0xAB, base + 1)) + group.to_bytes(2, "big")
        try:
            raw = read(request)
        except ToyotaCodecError as error:
            if error.code not in _OPERATION_SUPPRESSED:
                raise
            errors.append((request, error.code))
            continue
        if len(raw) < 4:
            raise ToyotaCodecError(
                "ADS operation DWORD index prefix is short", 0xA0040202
            )
        # RVA3360 comparator uses unsigned jbe; qsort then removes adjacent equal.
        numbers = sorted(
            {int.from_bytes(raw[i : i + 4], "big") for i in range(4, len(raw) - 3, 4)}
        )
        failed = False
        for number in numbers:
            request = (
                bytes((0xAB, base + 2))
                + group.to_bytes(2, "big")
                + number.to_bytes(4, "big")
            )
            try:
                raw = read(request)
            except ToyotaCodecError as error:
                if error.code not in _OPERATION_SUPPRESSED:
                    raise
                errors.append((request, error.code))
                if failed:
                    break
                failed = True
                continue
            failed = False
            rows = ads_operation_groups(raw)
            if not 0 < number < 0xF000 or not any(row.values for row in rows):
                continue
            retained += len(raw)
            if retained > 32 * 1024 * 1024 or len(freezes) >= 100_000:
                raise SessionError("ADS operation result exceeds host allowance")
            freezes.append(AdsOperationFreeze(phase, group, number, raw, rows))
    if not accepted:
        raise ToyotaCodecError("ADS support list has no operation groups", 0x90040501)
    return AdsOperationPhase(
        phase, groups, tuple(freezes), tuple(errors), source.sha256, frame.provenance
    )


def ads_extract_bits64(payload: bytes, first: int, last: int) -> int:
    """ADS18 RVA9350: MSB-first extraction into the native unsigned64 pair."""
    if type(payload) is not bytes or not payload:
        raise ValueError("ADS bit extraction requires immutable nonempty bytes")
    _word(first)
    _word(last)
    if last < first:
        raise ToyotaCodecError("ADS bit range is reversed", 0xC0000001)
    if last >= len(payload) * 8:
        raise ToyotaCodecError("ADS bit range exceeds owned bytes", 0xC0040102)
    value = int.from_bytes(payload[first // 8 : last // 8 + 1], "big")
    return (value >> (7 - last % 8)) & ((1 << min(last - first + 1, 64)) - 1)


@dataclass(frozen=True)
class AdsDdrBitCondition:
    """Hydrated DB259 row WORD6/8, BYTE11 and variable DID prefix."""

    first: int
    last: int
    kind: int
    variable: bytes

    def __post_init__(self) -> None:
        _word(self.first)
        _word(self.last)
        if type(self.kind) is not int or not 0 <= self.kind <= 255:
            raise ValueError("ADS support condition kind must fit BYTE")
        if type(self.variable) is not bytes or len(self.variable) < 2:
            raise ToyotaCodecError("ADS support condition lacks DID bytes", 0xC0040102)

    def enabled(self, observations: tuple[OperationDataId, ...]) -> bool:
        """ADS18 RVA36c0: first matching DID, only predicate7/nonzero64."""
        did = int.from_bytes(self.variable[:2], "big")
        observed = next((r for r in observations if r.did == did), None)
        if observed is None:
            return False
        if self.kind != 7:
            raise ToyotaCodecError("ADS support predicate is invalid", 0xC0040102)
        return ads_extract_bits64(observed.payload, self.first, self.last) != 0


@dataclass(frozen=True)
class AdsDdrValueDefinition:
    """Selected DB286 definition and its concrete DB25A/259 dependencies."""

    resource: bytes
    support_mode: int
    condition: AdsDdrBitCondition | None = None

    def __post_init__(self) -> None:
        if type(self.resource) is not bytes or len(self.resource) != 60:
            raise ToyotaCodecError(
                "ADS value requires a sixty-byte resource", 0xC0040102
            )
        if type(self.support_mode) is not int or not 0 <= self.support_mode <= 255:
            raise ValueError("ADS DID support mode must fit BYTE")
        if self.condition is not None and not isinstance(
            self.condition, AdsDdrBitCondition
        ):
            raise TypeError("ADS requires a concrete bit condition")
        if bool(int.from_bytes(self.resource[38:40], "little")) != (
            self.condition is not None
        ):
            raise ToyotaCodecError("ADS support dependency is unresolved", 0xC0040101)

    @property
    def identifier(self) -> int:
        return int.from_bytes(self.resource[36:38], "little")

    @property
    def did(self) -> int:
        return int.from_bytes(self.resource[52:54], "little")

    @property
    def timeline(self) -> int:
        return self.resource[59]

    def decode(self, observations: tuple[OperationDataId, ...]) -> int | None:
        """ADS18 RVA2ca0/3300: selected payload bounds and native support bit."""
        observed = next((r for r in observations if r.did == self.did), None)
        if observed is None:
            return None
        first = int.from_bytes(self.resource[42:44], "little")
        last = int.from_bytes(self.resource[44:46], "little")
        if ((last // 8 + 1) & 255) == ((first // 8) & 255):
            raise ToyotaCodecError("ADS native byte extent is invalid", 0xC0040102)
        if last >= len(observed.payload) * 8:
            return None
        if self.support_mode not in (0, 1, 2):
            # Native reports C0040102 here but returns0 with enabled=false.
            return None
        if self.support_mode == 1:
            index = last // 8 - 1
            if index < 0:
                raise ToyotaCodecError(
                    "ADS support bit precedes owned payload", 0xC0040102
                )
            mask = 0x80 >> (last % 8)
            if observed.payload[index] & mask != mask:
                return None
        if self.condition is not None and (
            self.condition.kind != 7 or not self.condition.enabled(observations)
        ):
            return None
        return ads_extract_bits64(observed.payload, first, last)


def ads_ddr_value_definitions(
    profile: VehicleProfile, did: int
) -> tuple[AdsDdrValueDefinition, ...]:
    """ADS18 RVA3170/3300 uses actual hydrated DB286→25A→259 queries."""
    _word(did)
    if profile.database.version != 0x0100032F:
        raise ValueError("ADS definitions require the original18 resource factory")
    rows = profile.ddr_behavior_records()
    if not rows:
        raise ToyotaCodecError("ADS behavior definitions are absent", 0xC0040101)
    identifiers = dict.fromkeys(
        int.from_bytes(row[36:38], "little")
        for row in rows
        if int.from_bytes(row[52:54], "little") == did
    )
    definitions = []
    for identifier in identifiers:
        selected = profile.ddr_behavior_records(identifier)
        if len(selected) != 1:
            raise ToyotaCodecError("ADS value definition is not singular", 0xC0040102)
        resource = selected[0]
        support = profile.rob_data_id_records(int.from_bytes(resource[52:54], "little"))
        if not support:
            raise ToyotaCodecError("ADS DID support definition is absent", 0xC0040101)
        condition = None
        reference = int.from_bytes(resource[38:40], "little")
        if reference:
            bits = profile.rob_bit_records(reference)
            if not bits:
                raise ToyotaCodecError("ADS DID bit definition is absent", 0xC0040101)
            row = bits[0]
            condition = AdsDdrBitCondition(
                int.from_bytes(row[6:8], "little"),
                int.from_bytes(row[8:10], "little"),
                row[11],
                profile.rob_bit_variable(row),
            )
        definitions.append(AdsDdrValueDefinition(resource, support[0][6], condition))
    return tuple(definitions)


def decode_ads_ddr_group(
    profile: VehicleProfile, observations: tuple[OperationDataId, ...]
) -> tuple[tuple[AdsDdrValueDefinition, int], ...]:
    """ADS18 RVA25f0→2ca0: concrete selected fields from actual DID payloads."""
    decoded = []
    for observation in observations:
        for definition in ads_ddr_value_definitions(profile, observation.did):
            value = definition.decode(observations)
            if value is not None:
                decoded.append((definition, value))
    return tuple(decoded)


@dataclass(frozen=True)
class Tss3SavedFreeze:
    operation: int
    group: int
    acquisition: Tss3OperationAcquisition

    @property
    def native_values(self) -> tuple[int, ...]:
        return tuple(value for row in self.acquisition.groups for value in row.values)


@dataclass(frozen=True)
class Tss3OperationReport:
    groups: tuple[int, ...]
    freezes: tuple[Tss3SavedFreeze, ...]
    suppressed_errors: tuple[tuple[bytes, int], ...]


def tss3_operation_numbers(reply: bytes) -> tuple[int, ...]:
    """TSS3Operation18 RVA21d0: skip4 bytes, BEWORDs, ascending unique list."""
    if type(reply) is not bytes or len(reply) > 4096:
        raise ValueError("Operation index must be immutable native frame bytes")
    if len(reply) < 4:
        raise ToyotaCodecError("Operation index lacks its native prefix", 0xA0040202)
    return tuple(
        sorted(
            {
                int.from_bytes(reply[i : i + 2], "big")
                for i in range(4, len(reply) - 1, 2)
            }
        )
    )


# GetTSS3OperationFFDP5_DT18 RVA30d0 scans exactly these15 WORDs at RVA91d4.
_TSS3_NON_OPERATION_GROUPS = frozenset(
    (
        0x2270,
        0x2271,
        0x2272,
        0x2273,
        0x2274,
        0x2296,
        0x2297,
        0x2298,
        0x2299,
        0x227C,
        0x227D,
        0x229A,
        0x22B0,
        0x22B1,
        0x22B2,
    )
)
_OPERATION_SUPPRESSED = frozenset(
    (
        0x91010009,
        0x90020321,
        0x90020323,
        0xA0040201,
        0xA0040202,
        0x90020327,
        0x91020320,
        0x91020310,
        0x91020322,
    )
)


@dataclass(frozen=True)
class Tss3SavedOperationResult:
    native_status: int
    report: Tss3OperationReport | None
    disconnect_status: int
    log_path: str


def _cleanup_saved_operation(
    communication: NativeCommunication,
    packet_log: DdrPacketLog,
    started: int,
    primary: BaseException | None,
) -> tuple[int, int]:
    disconnected, stopped = 0, 0
    cleanup: BaseException | None = None
    try:
        disconnected = communication.disconnect(1)
    except BaseException as error:  # noqa: BLE001 -- attempt independent log cleanup
        cleanup = error
    try:
        if started == 0:
            stopped = packet_log.stop()
    except BaseException as error:  # noqa: BLE001 -- retain original interruption
        if cleanup is None:
            cleanup = error
    if cleanup is not None:
        if primary is None:
            raise cleanup
        primary.add_note(f"Saved-operation cleanup raised {type(cleanup).__name__}")
    return disconnected, stopped


def capture_tss3_saved_operations(
    communication: NativeCommunication,
    packet_log: DdrPacketLog,
    source: SavedFfdSource,
) -> Tss3SavedOperationResult:
    """TSS3Operation18 Execute32f0 actual connection→producer→file lifecycle.

    Native ignores Disconnect's returned status; it is retained separately here.
    A logging failure is returned only if the diagnostic business status is zero.
    Cancellation and host bounds propagate after independent cleanup attempts.
    """
    if not isinstance(source, SavedFfdSource) or source.sha256 != TSS3_SOURCE_SHA256:
        raise ValueError("TSS3 operation source required")
    return _capture_saved_operations(communication, packet_log, source, lcs=False)


def capture_lcs_saved_operations(
    communication: NativeCommunication,
    packet_log: DdrPacketLog,
    source: SavedFfdSource,
) -> Tss3SavedOperationResult:
    """LCS12 Execute2740 /18 Execute2800, concrete connection/log lifecycle."""
    if not isinstance(source, SavedFfdSource) or source.sha256 != LCS_SOURCE_SHA256.get(
        source.build
    ):
        raise ValueError("LCS operation source required")
    return _capture_saved_operations(communication, packet_log, source, lcs=True)


def _capture_saved_operations(
    communication: NativeCommunication,
    packet_log: DdrPacketLog,
    source: SavedFfdSource,
    *,
    lcs: bool,
) -> Tss3SavedOperationResult:
    from scripts.database_resources import DdrPacketLog
    from scripts.native_communication import NativeCommunication, NativeFrameController

    if (
        not isinstance(communication, NativeCommunication)
        or not isinstance(communication.operations, NativeFrameController)
        or type(packet_log) is not DdrPacketLog
        or packet_log.operations is not communication.operations
        or not isinstance(source, SavedFfdSource)
        or communication.source_build != source.build
    ):
        raise ValueError(
            "Saved operation requires one concrete selected controller/log/source"
        )
    cache = communication.cache
    cache.check_context()
    provider = SavedFfdProvider(cache, source)
    started = packet_log.start(0x13 if lcs else 0x19)
    status, disconnected, stopped = 0, 0, 0
    report = None
    primary: BaseException | None = None
    try:
        connection = communication.connection_no_buffer(0, 1)
        if connection.status:
            status = connection.status
        else:
            try:
                report = (
                    provider.capture_lcs_operation_records()
                    if lcs
                    else provider.capture_tss3_operation_records()
                )
            except ToyotaCodecError as error:
                status = error.code
    except BaseException as error:
        primary = error
        raise
    finally:
        disconnected, stopped = _cleanup_saved_operation(
            communication, packet_log, started, primary
        )
    return Tss3SavedOperationResult(
        status or started or stopped, report, disconnected, str(packet_log.path)
    )


IMAGE_P4_SOURCE_SHA256 = {
    12: "b089067764563ce510efa12fc555b540d100702889271374708cab3159ec1f9f",
    18: "83e4ebb3c0be97e5e4e3cc2a14b1d91a1a571d3263a329a91fbf54252ad75e02",
}


@dataclass(frozen=True)
class ImageP4Source:
    build: int
    sha256: str

    def __post_init__(self) -> None:
        if (
            type(self.build) is not int
            or IMAGE_P4_SOURCE_SHA256.get(self.build) != self.sha256
        ):
            raise ValueError("Image P4 requires a reconciled original12/18 producer")


def selected_image_p4_schedule(source: ImageP4Source, module: bytes) -> bytes:
    """Read the private six-byte schedule from exact BYOD producer bytes.

    Original12 RVA81dc /18 RVA7190. No module is loaded or executed and no OEM
    schedule bytes are embedded in authored code or exposed by saved adapters.
    """
    import hashlib
    import struct

    if (
        not isinstance(source, ImageP4Source)
        or type(module) is not bytes
        or hashlib.sha256(module).hexdigest() != source.sha256
    ):
        raise ValueError("Image security material requires exact supplied producer PE")
    rva = 0x81DC if source.build == 12 else 0x7190
    pe = struct.unpack_from("<I", module, 60)[0]
    sections = pe + 24 + struct.unpack_from("<H", module, pe + 20)[0]
    for index in range(struct.unpack_from("<H", module, pe + 6)[0]):
        _, address, size, offset = struct.unpack_from(
            "<4I", module, sections + 40 * index + 8
        )
        if address <= rva and rva + 6 <= address + size:
            return module[offset + rva - address : offset + rva - address + 6]
    raise ValueError("Image security schedule is outside authenticated producer PE")


def image_p4_security_key(seed: bytes, schedule: bytes) -> bytes:
    """Native12 RVA2b60 /18 RVA1fe0 sequential six-byte rotate/add transform."""
    if (
        type(seed) is not bytes
        or type(schedule) is not bytes
        or len(seed) != 6
        or len(schedule) != 6
    ):
        raise ValueError("Image P4 security requires six-byte seed and schedule")
    result = bytearray()
    for index, value in enumerate(seed):
        selected = value & 7
        if selected >= 6:
            selected -= 6
        other = result[selected] if selected < index else seed[selected]
        rotation = 1 + ((value >> (schedule[index] & 31)) & 3)
        result.append((((value << rotation) | (value >> (8 - rotation))) + other) & 255)
    return bytes(result)


@dataclass(frozen=True)
class ImageP4SecurityExchange:
    seed_reply: bytes
    key_reply: bytes | None


def capture_image_p4_security(
    cache: MonitorSupportCache, source: ImageP4Source, schedule: bytes
) -> ImageP4SecurityExchange:
    """Producer12 1f80/18 14a0: selected E5 seed, optional E6 six-byte key."""
    if not isinstance(source, ImageP4Source) or cache.source_build != source.build:
        raise ValueError("Image P4 security source does not match selected context")
    # Validate the private BYOD schedule even when the ECU returns a zero seed.
    image_p4_security_key(bytes(6), schedule)
    cache.check_context()

    def selected(function: int) -> SelectedFrame:
        try:
            frames = cache.profile.frame_records(function)
        except ValueError as error:
            if str(error) not in (
                "No selected function communication frames",
                "No selected communication frame",
            ):
                raise
            raise ToyotaCodecError(
                "Image P4 security frame is absent", 0xC0040101
            ) from error
        if not frames:
            raise ToyotaCodecError("Image P4 security frame is absent", 0xC0040101)
        return frames[0]

    frame = selected(0xE5)
    seed_reply = cache.transaction(
        frame, frame.frame.request, cached=False, temporary=True
    )
    # Original checks >6 then reads through byte7. Bound the unsafe 7-byte case.
    if len(seed_reply) < 8:
        raise ToyotaCodecError("Image P4 security seed is truncated", 0xA0040202)
    seed = seed_reply[2:8]
    if not any(seed):
        return ImageP4SecurityExchange(seed_reply, None)
    frame = selected(0xE6)
    request = bytearray(frame.frame.request)
    if len(request) < 8:
        raise ToyotaCodecError("Image P4 key frame is truncated", 0xC0040102)
    request[2:8] = image_p4_security_key(seed, schedule)
    key_reply = cache.transaction(frame, bytes(request), cached=False, temporary=True)
    return ImageP4SecurityExchange(seed_reply, key_reply)


@dataclass(frozen=True)
class ImageP4Signal:
    logical_pid: int
    selector: int
    freeze: bytes
    value: int = 0


def image_p4_signal_definitions(profile: VehicleProfile) -> tuple[ImageP4Signal, ...]:
    """Native12 RVA15b0/18 Common4e590: hydrated ALL DB200→DB201.

    Native requires exactly ten filtered rows, not ten unique selectors. Each
    current row's WORD4 selects DB201, preserving duplicate-group association.
    """
    groups = profile.signal_group_records()
    if not groups:
        raise ToyotaCodecError("Image P4 SignalGroup table is empty", 0xC0040101)
    result = []
    for group in groups:
        if not 0x2A <= group[8] <= 0x33:
            continue
        checks = profile.signal_check_records(int.from_bytes(group[4:6], "little"))
        if len(checks) != 1:
            raise ToyotaCodecError(
                "Image P4 SignalCheck group is not singular", 0xC0040102
            )
        pid = int.from_bytes(checks[0][2:4], "little")
        result.append(ImageP4Signal(pid, group[8], b""))
    if len(result) != 10:
        raise ToyotaCodecError(
            "Image P4 requires ten native information rows", 0xC0040102
        )
    return tuple(result)


def capture_image_p4_information(
    cache: MonitorSupportCache,
) -> tuple[ImageP4Signal, ...]:
    """Common18 4e280: definitions, support, raw ECU values, then image flag.

    Each stage queries the selected database again in native order. In
    particular, support discovery precedes Freeze metadata faults.
    """
    from dataclasses import replace

    from scripts.signal_conversion import extract_bits
    from scripts.toyota_session import comm_ecu_support_p4, expand_supported_pid

    cache.check_context()
    if not isinstance(cache.profile, VehicleProfile):
        raise TypeError("Image information requires selected vehicle metadata")
    signals = image_p4_signal_definitions(cache.profile)
    masks = cache.support_bits(1)
    enabled = cache.enabled_pids(family="p4", kind=1)
    support = []
    for signal in signals:
        cache.check_context()
        rows = cache.profile.freeze_records(pid=0x100, logical_pid=signal.logical_pid)
        if len(rows) != 1:
            raise ToyotaCodecError("Image P4 Freeze group is not singular", 0xC0040102)
        row = rows[0]
        mode = row[77]
        if mode == 0:
            record = bytearray(12)
            record[2:6], record[8] = row[62:66], row[79]
            supported = comm_ecu_support_p4(bytes(record), enabled, masks)
        elif mode in (1, 2):
            supported = mode == 1
        else:
            raise ToyotaCodecError("Image P4 support mode is invalid", 0xA0040004)
        support.append(supported)
    if not all(support):
        raise ToyotaCodecError("Image P4 information is unsupported", 0x90040501)
    acquired = []
    for signal in signals:
        cache.check_context()
        rows = cache.profile.freeze_records(pid=0x100, logical_pid=signal.logical_pid)
        if not rows:
            raise ToyotaCodecError("Image P4 Freeze group is empty", 0xC0040101)
        row = rows[0]
        frames = cache.profile.frame_records(0x6B)
        if len(frames) != 1 or len(frames[0].frame.request) < 2:
            raise ToyotaCodecError("Image P4 requires one ECU read frame", 0xC0040102)
        frame = frames[0]
        request = bytearray(frame.frame.request)
        request[1] = row[79]
        reply = cache.transaction(frame, bytes(request), cached=False, temporary=True)
        size = (len(reply) - 2) & 255
        start = len(request)
        if len(reply) < 2 or start + size > len(reply):
            raise ToyotaCodecError("Image P4 reply data is truncated", 0xA0040202)
        positions = masks.get(row[79])
        if positions is None:
            raise ToyotaCodecError("Image P4 support data is absent", 0xC0040001)
        payload = expand_supported_pid(reply[start : start + size], positions)
        begin, end = (
            int.from_bytes(row[62:64], "little"),
            int.from_bytes(row[64:66], "little"),
        )
        if begin > end or end >= len(payload) * 8:
            raise ToyotaCodecError("Image P4 selected field is invalid", 0xA0040202)
        acquired.append(
            replace(signal, freeze=row, value=extract_bits(payload, begin, end))
        )
    flags = [item.value for item in acquired if item.selector in (0x2A, 0x2B)]
    if not flags or any(value != 2 for value in flags):
        raise ToyotaCodecError("Image P4 has no saved image", 0x90040501)
    return tuple(acquired)


@dataclass(frozen=True)
class ImageP4RamLayout:
    address: int
    count: int
    stride: int
    trailer: int

    @property
    def length(self) -> int:
        return self.count * self.stride


def image_p4_ram_layout(signals: tuple[ImageP4Signal, ...]) -> ImageP4RamLayout:
    """Producer12 2530/18 1a50: last matching selector wins, BYTE truncation."""
    before = count = image_size = address = trailer = 0
    if not signals:
        raise ToyotaCodecError("Image P4 information is empty", 0xC0040102)
    for signal in signals:
        value = signal.value
        if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
            raise ValueError("Image P4 signal must fit native DWORD")
        if signal.selector == 0x2C:
            before = value & 255
        elif signal.selector == 0x2E:
            count = value & 255
        elif signal.selector == 0x31:
            image_size = {1: 0x3480, 2: 0x2800, 3: 0x7EC}.get(value & 255, 0)
        elif signal.selector == 0x32:
            address = value
        elif signal.selector == 0x33:
            trailer = value & 255
    layout = ImageP4RamLayout(
        address, count, image_size * before + 4 + trailer, trailer
    )
    if not layout.length:
        raise ToyotaCodecError("Image P4 RAM length is zero", 0xA0040201)
    if layout.length > 32 * 1024 * 1024 or address + layout.length > 0xFFFFFFFF:
        raise ValueError("Image P4 RAM exceeds host byte/address bounds")
    return layout


@dataclass(frozen=True)
class ImageP4SavedRecord:
    raw: bytes
    scalar: int


def image_p4_saved_records(
    layout: ImageP4RamLayout, raw: bytes, category: int
) -> tuple[ImageP4SavedRecord, ...]:
    """Producer12 2530/18 1a50 actual per-record scalar association."""
    if type(raw) is not bytes or len(raw) != layout.length:
        raise ToyotaCodecError("Image P4 RAM result length differs", 0xA0040202)
    offset, required = (4, 6) if category == 0x178 else (0, 2)
    return tuple(
        ImageP4SavedRecord(
            raw[start : start + layout.stride],
            int.from_bytes(raw[start + offset : start + offset + 2], "big")
            if layout.trailer >= required
            else 0xFFFF,
        )
        for start in range(0, layout.length, layout.stride)
    )


@dataclass(frozen=True)
class ImageP4SavedResult:
    native_status: int
    signals: tuple[ImageP4Signal, ...]
    security: ImageP4SecurityExchange | None
    layout: ImageP4RamLayout | None
    records: tuple[ImageP4SavedRecord, ...]
    source_sha256: str
    log_path: str


def capture_image_p4_saved(
    communication: NativeCommunication,
    packet_log: DdrPacketLog,
    source: ImageP4Source,
    schedule: bytes,
) -> ImageP4SavedResult:
    """Original12/18 ImageFFD_DT Execute1010, including saved RAM consumer.

    Native retains the connection; this producer stops its log but does not
    introduce a Disconnect call absent from both originals.
    """
    from scripts.database_resources import DdrPacketLog, NativeRamReader, RamFrame
    from scripts.native_communication import NativeCommunication, NativeFrameController

    if (
        not isinstance(communication, NativeCommunication)
        or not isinstance(communication.profile, VehicleProfile)
        or not isinstance(packet_log, DdrPacketLog)
        or not isinstance(source, ImageP4Source)
        or communication.source_build != source.build
        or packet_log.source_build != source.build
        or not isinstance(communication.operations, NativeFrameController)
        or packet_log.operations is not communication.operations
    ):
        raise ValueError(
            "Image P4 requires one concrete selected controller/log/source"
        )
    image_p4_security_key(bytes(6), schedule)
    cache = communication.cache
    cache.check_context()
    started = packet_log.start(1)
    status = stopped = 0
    signals: tuple[ImageP4Signal, ...] = ()
    security = None
    layout = None
    records: tuple[ImageP4SavedRecord, ...] = ()
    primary: BaseException | None = None
    try:
        try:
            cache.invalidate_a8(1)
            connection = communication.connection_no_buffer(0, 1)
            status = connection.status
            if not status:
                # Metadata owns one fresh local cache; the subsequent security
                # and RAM stages share a separate default local cache.
                with cache.temporary_scope():
                    signals = capture_image_p4_information(cache)
                with cache.temporary_scope():
                    security = capture_image_p4_security(cache, source, schedule)
                    layout = image_p4_ram_layout(signals)
                    frame = RamFrame(
                        b"\x01\x00\x01\x00" + layout.address.to_bytes(4, "little")
                    )
                    reader = NativeRamReader.from_communication(
                        communication, frame=frame, block_size=0x38
                    )
                    raw = reader.read_end_trim(layout.length)
                    records = image_p4_saved_records(
                        layout, raw, cache.profile.category
                    )
        except ToyotaCodecError as error:
            status = error.code
    except BaseException as error:
        primary = error
        raise
    finally:
        if not started:
            try:
                stopped = packet_log.stop()
            except BaseException as cleanup:
                if primary is None:
                    raise
                primary.add_note(
                    f"Image P4 log cleanup failed: {type(cleanup).__name__}"
                )
    return ImageP4SavedResult(
        status or started or stopped,
        signals,
        security,
        layout,
        records,
        source.sha256,
        str(packet_log.path),
    )


PCS_OPERATION_SOURCE_SHA256 = {
    12: "633169490436920cfa88039cfc63e14202fc8f01b20f5bbeefeed68d25596fe4",
    18: "7c4a921471cb9da33e3ddc22ec38209dfb751f509c6b901a463faefc869be52c",
}


@dataclass(frozen=True)
class PcsOperationSource:
    build: int
    sha256: str

    def __post_init__(self) -> None:
        if (
            type(self.build) is not int
            or PCS_OPERATION_SOURCE_SHA256.get(self.build) != self.sha256
        ):
            raise ValueError(
                "PCS operation requires a reconciled original12/18 producer"
            )


@dataclass(frozen=True)
class PcsOperationRecord:
    number: int
    pid: int
    raw_reply: bytes
    expanded: bytes


@dataclass(frozen=True)
class PcsOperationPhase:
    phase: int
    scalar: int
    records: tuple[PcsOperationRecord, ...]
    suppressed_errors: tuple[tuple[int, int, int], ...]


def _pcs_item_value(cache: MonitorSupportCache, record: bytes, number: int) -> int:
    from scripts.signal_conversion import extract_bits
    from scripts.toyota_session import expand_supported_pid

    if (
        type(record) is not bytes
        or len(record) != 12
        or type(number) is not int
        or not 0 <= number <= 255
    ):
        raise ValueError("PCS item requires one native CommEcuData row and BYTE number")
    frames = cache.profile.frame_records(0x11)
    if len(frames) != 1 or len(frames[0].frame.request) < 4:
        raise ToyotaCodecError("PCS item requires one four-byte frame", 0xC0040102)
    frame = frames[0]
    request = bytearray(frame.frame.request)
    request[1], request[3] = number, record[8]
    reply = cache.transaction(frame, bytes(request), cached=False, temporary=True)
    start, size = len(request) - 2, (len(reply) - 4) & 255
    if len(reply) < 4 or start + size > len(reply):
        raise ToyotaCodecError("PCS item reply is truncated", 0xA0040202)
    positions = cache.support_bits(1).get(record[8])
    if positions is None:
        raise ToyotaCodecError("PCS item support data is absent", 0xC0040001)
    payload = expand_supported_pid(reply[start : start + size], positions)
    begin, end = (
        int.from_bytes(record[2:4], "little"),
        int.from_bytes(record[4:6], "little"),
    )
    if begin > end or end >= len(payload) * 8:
        raise ToyotaCodecError("PCS item selected field is invalid", 0xA0040202)
    return extract_bits(payload, begin, end)


def capture_pcs_item(
    cache: MonitorSupportCache, source: PcsOperationSource, record: bytes, number: int
) -> int:
    """Common12 20780/20fb0,18 26000/26830 support then raw PCS item."""
    from scripts.toyota_session import comm_ecu_support_p4

    if not isinstance(source, PcsOperationSource) or cache.source_build != source.build:
        raise ValueError("PCS item source does not match selected context")
    cache.check_context()
    masks = cache.support_bits(1)
    enabled = cache.pcs_operation_pids(kind=3, control=number)
    if not comm_ecu_support_p4(record, enabled, masks):
        raise ToyotaCodecError("PCS item is unsupported", 0x90040501)
    return _pcs_item_value(cache, record, number)


def capture_pcs_operation_phase(
    cache: MonitorSupportCache,
    source: PcsOperationSource,
    number: int,
    phase: int,
    *,
    repeats: int = 0,
    pid_count: int = 0,
    enabled: dict[int, int] | None = None,
) -> PcsOperationPhase:
    """PCS producer18 2350: actual PID records and phase2/3 receive chronology."""
    from scripts.toyota_session import expand_supported_pid

    if not isinstance(source, PcsOperationSource) or cache.source_build != source.build:
        raise ValueError("PCS operation source does not match selected context")
    if (
        type(number) is not int
        or not 0 <= number <= 255
        or type(phase) is not int
        or phase not in (1, 2, 3)
    ):
        raise ValueError("PCS operation number/phase is invalid")
    if any(
        type(value) is not int or not 0 <= value <= 255
        for value in (repeats, pid_count)
    ):
        raise ValueError("PCS operation counters must fit BYTE")
    if phase == 1 and enabled is None:
        raise ValueError(
            "PCS first phase requires its actual selected enabled PID list"
        )
    cache.check_context()
    if not isinstance(cache.profile, VehicleProfile):
        raise TypeError("PCS operation requires selected vehicle metadata")
    rows = cache.profile.pcs_operation_pid_records(1 if phase == 1 else 2)
    if not rows:
        raise ToyotaCodecError("PCS operation PID group is empty", 0xC0040101)
    if phase == 1:
        count, repeat, current, increment = len(rows) & 255, 1, number, 0
    else:
        count, repeat = min(len(rows), pid_count), repeats
        current, increment = (
            (number | 0xF0, -0x10) if phase == 2 else (number | 0x10, 0x10)
        )
    scalar = 0xFFFF
    records, suppressed = [], []
    retained_bytes = 0
    for _ in range(repeat):
        failed = False
        for row in rows[:count]:
            cache.check_context()
            pid = row[2]
            if phase == 1 and pid not in (enabled or {}):
                continue
            frames = cache.profile.frame_records(0x11)
            if len(frames) != 1 or len(frames[0].frame.request) < 4:
                raise ToyotaCodecError(
                    "PCS operation requires one four-byte frame", 0xC0040102
                )
            frame = frames[0]
            request = bytearray(frame.frame.request)
            request[1], request[3] = current, pid
            try:
                reply = cache.transaction(
                    frame, bytes(request), cached=False, temporary=True
                )
            except ToyotaCodecError as error:
                if phase == 1:
                    raise
                suppressed.append((current, pid, error.code))
                if failed:
                    break
                failed = True
                continue
            failed = False
            start, size = len(request) - 2, (len(reply) - 4) & 255
            if len(reply) < 4 or start + size > len(reply):
                raise ToyotaCodecError(
                    "PCS operation reply data is truncated", 0xA0040202
                )
            payload = reply[start : start + size]
            if reply[3] == 0xE1 and reply[1] in (0x0D, 0x0E, 0x0F):
                if len(payload) < 4:
                    raise ToyotaCodecError(
                        "PCS operation scalar is truncated", 0xA0040202
                    )
                scalar = int.from_bytes(payload[2:4], "big")
            masks = cache.support_bits(1)
            positions = masks.get(pid)
            if positions is None:
                raise ToyotaCodecError(
                    "PCS operation support data is absent", 0xC0040001
                )
            expanded = expand_supported_pid(payload, positions)
            retained_bytes += len(reply) + len(expanded)
            if retained_bytes > 32 * 1024 * 1024:
                raise SessionError("PCS operation retained data budget exhausted")
            records.append(PcsOperationRecord(current, pid, reply, expanded))
        current = (current + increment) & 255
    return PcsOperationPhase(phase, scalar, tuple(records), tuple(suppressed))


@dataclass(frozen=True)
class PcsSavedFreeze:
    number: int
    matched_value: int
    first: PcsOperationPhase
    second: PcsOperationPhase | None = None
    third: PcsOperationPhase | None = None


@dataclass(frozen=True)
class PcsSavedOperationResult:
    native_status: int
    freezes: tuple[PcsSavedFreeze, ...]
    source_sha256: str
    log_path: str


def capture_pcs_saved_operations(
    communication: NativeCommunication,
    packet_log: DdrPacketLog,
    source: PcsOperationSource,
) -> PcsSavedOperationResult:
    """Original12/18 PCS Execute1010: actual selected plan through saved output."""
    from dataclasses import replace

    from scripts.database_resources import DdrPacketLog
    from scripts.native_communication import NativeCommunication, NativeFrameController

    if (
        not isinstance(communication, NativeCommunication)
        or not isinstance(packet_log, DdrPacketLog)
        or not isinstance(source, PcsOperationSource)
        or communication.source_build != source.build
        or packet_log.source_build != source.build
        or not isinstance(communication.operations, NativeFrameController)
        or packet_log.operations is not communication.operations
    ):
        raise ValueError(
            "PCS operation requires one concrete selected controller/log/source"
        )
    cache, profile = communication.cache, communication.profile
    if not isinstance(profile, VehicleProfile):
        raise TypeError("PCS operation requires a selected vehicle database profile")
    cache.check_context()
    started = packet_log.start(0)
    status = stopped = 0
    freezes: list[PcsSavedFreeze] = []
    primary: BaseException | None = None
    try:
        try:
            cache.invalidate_a8(1)
            connection = communication.connection_no_buffer(0, 1)
            status = connection.status
            if not status:
                with cache.temporary_scope():
                    reference = {0x178: 0x520B, 0xDC: 0x520C}.get(profile.category, 0)
                    support = cache.get_comm_support_bit(reference, temporary=True)
                    if not support.supported:
                        raise ToyotaCodecError(
                            "PCS operation is unsupported", 0x90040501
                        )
                    groups = profile.signal_group_records(0x25)
                    if not groups:
                        raise ToyotaCodecError("PCS SignalGroup is empty", 0xC0040101)
                    checks = profile.signal_check_records(
                        int.from_bytes(groups[0][4:6], "little")
                    )
                    if len(checks) != 1:
                        raise ToyotaCodecError(
                            "PCS SignalCheck group is not singular", 0xC0040102
                        )
                    logical_pid = int.from_bytes(checks[0][2:4], "little")
                    selected = profile.freeze_records(
                        pid=0x100, logical_pid=logical_pid
                    )
                    if len(selected) != 1:
                        raise ToyotaCodecError(
                            "PCS Freeze group is not singular", 0xC0040102
                        )
                    freeze = selected[0]
                    operations = profile.operation_freeze_records()
                    if not operations:
                        raise ToyotaCodecError(
                            "PCS operation Freeze table is empty", 0xC0040101
                        )
                    found = False
                    for operation in operations:
                        cache.check_context()
                        number = operation[5]
                        row = bytearray(12)
                        row[2:6], row[8] = freeze[62:66], freeze[79]
                        value = _pcs_item_value(cache, bytes(row), number)
                        patterns = profile.pattern_records(
                            int.from_bytes(freeze[70:72], "little")
                        )
                        if not patterns:
                            raise ToyotaCodecError(
                                "PCS PatDisp group is empty", 0xC0040101
                            )
                        matches = any(
                            int.from_bytes(pattern[10:12], "little") == value & 0xFFFF
                            if source.build == 12
                            else int.from_bytes(pattern[4:8], "little") == value
                            for pattern in patterns
                        )
                        if not matches:
                            continue
                        found = True
                        cache.support_bits(1)
                        enabled = cache.pcs_operation_pids(kind=1)
                        first = capture_pcs_operation_phase(
                            cache, source, number, 1, enabled=enabled
                        )
                        freezes.append(PcsSavedFreeze(number, value, first))
                        if len(freezes) > 100_000:
                            raise SessionError("PCS saved freeze budget exhausted")
                        for phase in (2, 3):
                            cache.check_context()
                            rows = profile.comm_ecu_records(
                                0x0A if phase == 2 else 0x0B
                            )
                            if not rows:
                                raise ToyotaCodecError(
                                    "PCS repetition item is empty", 0xC0040101
                                )
                            repeats = (
                                capture_pcs_item(cache, source, rows[0], number) & 255
                            )
                            rows = profile.comm_ecu_records(0x0C)
                            if not rows:
                                raise ToyotaCodecError(
                                    "PCS PID-count item is empty", 0xC0040101
                                )
                            count = (
                                capture_pcs_item(cache, source, rows[0], number) & 255
                            )
                            acquired = capture_pcs_operation_phase(
                                cache,
                                source,
                                number,
                                phase,
                                repeats=repeats,
                                pid_count=count,
                            )
                            freezes[-1] = replace(
                                freezes[-1],
                                **(
                                    {"second": acquired}
                                    if phase == 2
                                    else {"third": acquired}
                                ),
                            )
                    if not found:
                        status = 0x90040501
        except ToyotaCodecError as error:
            status = error.code
    except BaseException as error:
        primary = error
        raise
    finally:
        if not started:
            try:
                stopped = packet_log.stop()
            except BaseException as cleanup:
                if primary is None:
                    raise
                primary.add_note(f"PCS log cleanup failed: {type(cleanup).__name__}")
    return PcsSavedOperationResult(
        status or started or stopped,
        tuple(freezes),
        source.sha256,
        str(packet_log.path),
    )


if TYPE_CHECKING:
    from scripts.database_resources import DdrP5Report, DdrP5SupportValue, DdrReport


IMAGE_P5_SOURCE_SHA256 = {
    12: "d4eb7f901ca477611d5217ca4b8fa1ac6c92c0f0d512ba02cd55727b63f47308",
    18: "a07c58caaad25ea5492196d2ccd3fdf5f480ff77af6b21291851adb418e611bd",
}


@dataclass(frozen=True)
class ImageP5Source:
    build: int
    sha256: str

    def __post_init__(self) -> None:
        if (
            type(self.build) is not int
            or IMAGE_P5_SOURCE_SHA256.get(self.build) != self.sha256
        ):
            raise ValueError(
                "Generic P5 image requires reconciled original12/18 producer"
            )


@dataclass(frozen=True)
class ImageEcuReference:
    native_id: int
    state: int

    def __post_init__(self) -> None:
        if (
            type(self.native_id) is not int
            or not 0 <= self.native_id <= 0xFFFFFFFF
            or type(self.state) is not int
            or not 0 <= self.state <= 255
        ):
            raise ValueError("Image ECU reference requires native DWORD+8/BYTE+20")


@dataclass(frozen=True)
class ImageP5Request18:
    numbers: tuple[int, ...]
    selector: int
    ecu_info: tuple[ImageEcuReference, ...] = ()

    def __post_init__(self) -> None:
        if (
            type(self.numbers) is not tuple
            or len(self.numbers) > 100_000
            or any(
                type(number) is not int or not 0 <= number <= 255
                for number in self.numbers
            )
        ):
            raise ValueError("P5 image numbers require a bounded native BYTE list")
        if type(self.selector) is not int or not 0 <= self.selector <= 255:
            raise ValueError("P5 image selector must retain native BYTE")
        if (
            type(self.ecu_info) is not tuple
            or len(self.ecu_info) > 100_000
            or not all(isinstance(row, ImageEcuReference) for row in self.ecu_info)
        ):
            raise TypeError("P5 image requires bounded typed caller ECU references")

    @property
    def ddr_category(self) -> int:
        """Image18 9d40: exact two fields consumed from each caller ECU object."""
        return (
            0x1BC
            if any(row.native_id == 0x1BC and row.state == 1 for row in self.ecu_info)
            else 0xBC
        )


COMMON_IMAGE18_SHA256 = (
    "07547a9e47378d37c3ef7d96c2f33f6c62c4151626d98d3f3ff03b7c74909de7"
)


def selected_image_p5_schedule(common_module: bytes, *, build: int = 18) -> bytes:
    """BYOD schedule:Common18 4ac40/B1910 or ImageP5_12 9420/1236C."""
    import hashlib
    import struct

    expected = (
        COMMON_IMAGE18_SHA256 if build == 18 else IMAGE_P5_SOURCE_SHA256.get(build)
    )
    rva = 0xB1910 if build == 18 else 0x1236C
    if (
        type(build) is not int
        or build not in (12, 18)
        or (
            type(common_module) is not bytes
            or hashlib.sha256(common_module).hexdigest() != expected
        )
    ):
        raise ValueError("P5 image security requires exact supplied versioned PE")
    pe = struct.unpack_from("<I", common_module, 60)[0]
    sections = pe + 24 + struct.unpack_from("<H", common_module, pe + 20)[0]
    for index in range(struct.unpack_from("<H", common_module, pe + 6)[0]):
        _, address, size, offset = struct.unpack_from(
            "<4I", common_module, sections + index * 40 + 8
        )
        if address <= rva and rva + 6 <= address + size:
            start = offset + rva - address
            return common_module[start : start + 6]
    raise ValueError("P5 image security schedule is outside authenticated source PE")


def _image_p5_read(
    cache: MonitorSupportCache,
    frame: SelectedFrame,
    request: bytes,
    mask: bytes,
    expected: bytes,
    minimum: int,
    *,
    check_expected: bool = True,
) -> bytes:
    """CCmdImgOpeDdr SetFrame→SndRcvExt with literal replacement masks."""
    from scripts.toyota import CommandFrame

    cache.check_context()
    reply = cache.transaction(frame, request, cached=False, extended=True)
    if len(reply) < minimum:
        raise ToyotaCodecError("P5 image reply is truncated", 0xA0040202)
    if check_expected:
        CommandFrame(request, mask, expected).check_mask(reply)
    return reply


def capture_image_p5_security(
    cache: MonitorSupportCache,
    frame: SelectedFrame,
    schedule: bytes,
) -> ImageP4SecurityExchange:
    """Common18 4a170: concrete replacement-frame SecLv49 seed/key exchange.

    This is one shared acquisition stage, not an image-provider completion claim.
    Original wire tables B17ec/B17f0/B17f8 and B1800/B1804/B1808.
    """
    if cache.source_build not in (12, 18):
        raise ValueError("Image security requires original12/18 source")
    selected = cache.profile.frame_records(0x66)
    if not selected or frame != selected[0]:
        raise ValueError(
            "P5 image security requires the first selected function66 frame"
        )
    image_p4_security_key(bytes(6), schedule)
    seed_reply = _image_p5_read(
        cache, frame, b"\x27\x03", b"\xff\xff" + bytes(6), b"\x67\x03" + bytes(6), 8
    )
    seed = seed_reply[2:8]
    if not any(seed):
        return ImageP4SecurityExchange(seed_reply, None)
    request = b"\x27\x04" + image_p4_security_key(seed, schedule)
    key_reply = _image_p5_read(cache, frame, request, b"\xff\xff", b"\x67\x04", 2)
    return ImageP4SecurityExchange(seed_reply, key_reply)


def capture_image_p5_memorized(
    cache: MonitorSupportCache, frame: SelectedFrame, selector: int | None = None
) -> tuple[int, ...]:
    """Common18 49790/49bc0/49d50/49f10 selected generic image availability.

    Source wire tables B17b0/B17b4/B17b8 replace the selected frame's payload
    and checks. Selector1 covers five native images,2 six,3/4 seven.
    """
    if cache.source_build == 12:
        if selector is not None:
            raise ValueError("Original12 image availability has no caller selector")
        selector = 1
    elif cache.source_build != 18:
        raise ValueError("Image availability requires original12/18 source")
    if type(selector) is not int or not 0 <= selector <= 255:
        raise ValueError("Image selector must fit native BYTE")
    selected = cache.profile.frame_records(0x66)
    if not selected or frame != selected[0]:
        raise ValueError("P5 image availability requires first selected function66")
    reply = _image_p5_read(
        cache,
        frame,
        bytes.fromhex("221201"),
        bytes((255,)) * 3,
        bytes.fromhex("621201"),
        9,
        check_expected=False,
    )
    if reply[3] != 2 or selector not in (1, 2, 3, 4):
        raise ToyotaCodecError("P5 image availability is unsupported", 0x90040501)
    count = 5 if selector == 1 else 6 if selector == 2 else 7
    if len(reply) < 4 + count:
        raise ToyotaCodecError("P5 image flags are truncated", 0xA0040202)
    result = tuple(
        index + 1 for index, flag in enumerate(reply[4 : 4 + count]) if flag == 2
    )
    if not result:
        raise ToyotaCodecError("P5 image has no memorized snapshot", 0x90040501)
    return result


@dataclass(frozen=True)
class ImageP5Information:
    format: int
    header_size: int
    record_lengths: tuple[tuple[int, int], ...]
    addresses: tuple[int, ...]
    counts: tuple[int, ...]
    raw_specification: bytes
    customization_replies: tuple[bytes, bytes]
    raw_information: bytes
    build: int = 18


def image_p5_information(
    specification: bytes,
    information: bytes,
    customization: tuple[bytes, bytes] = (b"", b""),
    *,
    build: int = 18,
) -> ImageP5Information:
    """Common18 4bda0/4cb30/4ceb0 exact native field associations."""
    if (
        type(specification) is not bytes
        or type(information) is not bytes
        or len(specification) < 11
    ):
        raise ToyotaCodecError("P5 image specification is truncated", 0xA0040202)
    if type(build) is not int or build not in (12, 18):
        raise ValueError("P5 image information requires original12/18 build")
    format = specification[3]
    if format not in ((1,) if build == 12 else (1, 2, 3, 4)):
        raise ToyotaCodecError("P5 image format is unsupported", 0x90040501)
    minimum = {1: 70, 2: 95, 3: 96, 4: 96}[format]
    if len(information) < minimum:
        raise ToyotaCodecError("P5 image information is truncated", 0xA0040202)
    header = information[6]
    if header < 8:
        raise ToyotaCodecError("P5 image header size is unsupported", 0x90040501)

    def value(offset: int) -> int:
        return int.from_bytes(information[offset : offset + 4], "big")

    common = {
        0x0F00: value(7),
        0x1000: value(11),
        0x1300: value(19),
        0x1402: value(23),
        0x1403: value(23),
        0x1900: value(31),
    }
    if build == 18:
        common[0x1202] = 0 if format == 1 else value(15)
    for identifier in (0x1203, 0x1204, 0x1205):
        common[identifier] = value(15)
    common[0x120E] = value(27) if format == 1 else value(15)
    if build == 18:
        common[0x1B00] = 0 if format == 1 else value(74)
        common[0x1E00] = value(78) if format in (3, 4) else 0
    elif any(header >= value(offset) for offset in range(7, 35, 4)):
        raise ToyotaCodecError(
            "Original12 image lengths must exceed header", 0x90040501
        )
    addresses = tuple(value(offset) for offset in (35, 39, 43, 47, 51))
    counts = tuple(information[65:70])
    if format != 1:
        addresses += (value(82),)
        counts += (information[94],)
    if format in (3, 4):
        addresses += (value(86),)
        counts += (information[95],)
    return ImageP5Information(
        format,
        header,
        tuple(sorted(common.items())),
        addresses,
        counts,
        specification,
        customization,
        information,
        build,
    )


def capture_image_p5_information(
    cache: MonitorSupportCache, frame: SelectedFrame
) -> ImageP5Information:
    """Common18 4ad20→native spec validator→customize1/2→information."""
    if (
        cache.source_build not in (12, 18)
        or frame != cache.profile.frame_records(0x66)[0]
    ):
        raise ValueError("P5 information requires original12/18 selected function66")
    spec = _image_p5_read(
        cache,
        frame,
        bytes.fromhex("221203"),
        b"\xff" * 3,
        bytes.fromhex("621203"),
        11,
        check_expected=False,
    )
    format = spec[3]
    if format not in ((1,) if cache.source_build == 12 else (1, 2, 3, 4)):
        raise ToyotaCodecError("P5 image format is unsupported", 0x90040501)
    count = 6 if format == 1 else 7 if format == 2 else 8
    if len(spec) < 5 + count:
        raise ToyotaCodecError(
            "P5 image specification fields are truncated", 0xA0040202
        )
    expected = bytearray(count)
    expected[2] = 2 if format == 4 else 1
    if spec[5 : 5 + count] != bytes(expected):
        raise ToyotaCodecError(
            "P5 image specification fields are unsupported", 0x90040501
        )
    # Native customization calls prepare DID masks but do not compare them.
    # CommCacheSndRcvExt validates only the positive service byte here.
    first = bytes.fromhex("221204" if format == 1 else "22201a")
    customization = tuple(
        _image_p5_read(
            cache,
            frame,
            request,
            b"\xff" * 3,
            bytes((request[0] | 0x40,)) + request[1:],
            1,
            check_expected=False,
        )
        for request in (first, bytes.fromhex("222090"))
    )
    info = _image_p5_read(
        cache,
        frame,
        bytes.fromhex("221202"),
        b"\xff" * 3,
        bytes.fromhex("621202"),
        1,
        check_expected=False,
    )
    return image_p5_information(
        spec, info, (customization[0], customization[1]), build=cache.source_build
    )


@dataclass(frozen=True)
class ImageP5BodyRead:
    address: int
    length: int
    reply: bytes
    native_status: int


@dataclass(frozen=True)
class ImageP5RecordAcquisition:
    number: int
    relative_offset: int
    next_offset: int
    header: bytes
    record_type: int
    scalar: int | None
    timestamp: int
    checksum_valid: bool
    excluded: bool
    retry: bool
    body: tuple[ImageP5BodyRead, ...]
    native_status: int = 0


def capture_image_p5_record(
    cache: MonitorSupportCache,
    frame: SelectedFrame,
    information: ImageP5Information,
    number: int,
    relative_offset: int,
    first_ddr: DdrP5SupportValue,
    second_ddr: DdrP5SupportValue | None = None,
) -> ImageP5RecordAcquisition:
    """ImageP5_18 8980 /12 A460: header/checksum/filter then body reads.

    Filter18 9b40 uses the first DDR scalar. Filter12 B5D0 additionally uses
    the second support's low29 timestamp when the first scalar is equal.
    A fatal body status preserves the already appended header scalar in the
    typed partial result. Native log rollback/retry belongs to the outer.
    """
    from scripts.database_resources import DdrP5SupportValue
    from scripts.native_communication import CommunicationError
    from scripts.toyota_session import NativeStatus

    if (
        cache.source_build not in (12, 18)
        or frame != cache.profile.frame_records(0x66)[0]
    ):
        raise ValueError("P5 record requires original12/18 selected function66")
    if not isinstance(information, ImageP5Information) or not isinstance(
        first_ddr, DdrP5SupportValue
    ):
        raise TypeError("P5 record requires typed native information and DDR support")
    if information.build != cache.source_build:
        raise ValueError("Image information belongs to another native build")
    if cache.source_build == 12 and not isinstance(second_ddr, DdrP5SupportValue):
        raise TypeError("Original12 image filter requires both DDR support values")
    if type(number) is not int or not 1 <= number <= len(information.addresses):
        raise ValueError("P5 record number has no native information address")
    if type(relative_offset) is not int or not 0 <= relative_offset <= 0xFFFFFFFF:
        raise ValueError("P5 relative record address must fit DWORD")
    if (
        type(first_ddr.present) is not bool
        or type(first_ddr.value) is not int
        or not 0 <= first_ddr.value <= 0xFFFFFFFF
    ):
        raise ValueError("P5 DDR support value is malformed")
    if cache.source_build == 12:
        assert second_ddr is not None
        if (
            type(second_ddr.present) is not bool
            or type(second_ddr.value) is not int
            or not 0 <= second_ddr.value <= 0xFFFFFFFF
        ):
            raise ValueError("Second native DDR support value is malformed")
    address = information.addresses[number - 1] + relative_offset
    size = information.header_size
    if not 8 <= size <= 255 or address + size > 0xFFFFFFFF:
        raise ValueError("P5 header exceeds host address/byte bounds")

    # Producer wire tables11570/1157c, mask11574/11580 and check11578/11584.
    def request(at: int, count: int) -> bytes:
        return bytes.fromhex("231501") + at.to_bytes(4, "big") + bytes((count,))

    header = _image_p5_read(
        cache, frame, request(address, size), b"\xff", b"\x63", 1, check_expected=False
    )
    if len(header) != size + 1:
        raise ToyotaCodecError("P5 image header length differs", 0xA0040202)
    kind = int.from_bytes(header[1:3], "big")
    lengths = dict(information.record_lengths)
    if kind not in lengths:
        raise ToyotaCodecError("P5 image record type is unsupported", 0x90040501)
    length = lengths[kind]
    if (
        type(length) is not int
        or not size <= length <= 32 * 1024 * 1024
        or address + length > 0xFFFFFFFF
    ):
        raise SessionError("P5 image record exceeds host byte/address bounds")
    checksum = sum(header[1 : size - 3]) & 255 == header[size - 3]
    scalar = int.from_bytes(header[3:5], "big")
    timestamp = int.from_bytes(header[5:9], "big")
    difference = (first_ddr.value - scalar) & 0xFFFFFFFF
    allowed = (
        not first_ddr.present
        or first_ddr.value == 0xFFFF
        or bool(difference & 0x80000000)
    )
    if cache.source_build == 12:
        assert second_ddr is not None
        if not second_ddr.present:
            allowed = True
        elif (
            first_ddr.present
            and first_ddr.value != 0xFFFF
            and first_ddr.value == scalar
        ):
            difference = (
                (second_ddr.value & 0x1FFFFFFF) - (timestamp & 0x1FFFFFFF)
            ) & 0xFFFFFFFF
            allowed = bool(difference & 0x80000000)
    excluded = checksum and not allowed
    retry = not checksum
    body = []
    native_status = 0
    for offset in range(size, length, 255):
        cache.check_context()
        count = min(255, length - offset)
        try:
            reply = _image_p5_read(
                cache,
                frame,
                request(address + offset, count),
                b"\xff",
                b"\x63",
                1,
                check_expected=False,
            )
        except ToyotaCodecError as error:
            # Original12 A460 returns every body failure. Original18 8980
            # continues only NRC21/23 and marks the image for one outer retry.
            retryable = cache.source_build == 18 and error.code in (
                0x90020321,
                0x90020323,
            )
            if retryable:
                retry = True
            else:
                native_status = error.code
            raw = (
                error.response
                if isinstance(error, CommunicationError)
                else error.reply
                if isinstance(error, NativeStatus)
                else b""
            )
            body.append(ImageP5BodyRead(address + offset, count, raw, error.code))
            if native_status:
                break
        else:
            body.append(ImageP5BodyRead(address + offset, count, reply, 0))
    return ImageP5RecordAcquisition(
        number,
        relative_offset,
        (relative_offset + length) & 0xFFFFFFFF,
        header,
        kind,
        scalar if checksum and allowed else None,
        timestamp,
        checksum,
        excluded,
        retry,
        tuple(body),
        native_status,
    )


@dataclass(frozen=True)
class RcImageP5Information:
    format: int
    numbers: tuple[int, ...]
    raw_specification: bytes
    raw_availability: bytes
    security: ImageP4SecurityExchange
    raw_encryption_method: bytes


def capture_rc_image_p5_information(
    cache: MonitorSupportCache, frame: SelectedFrame, schedule: bytes
) -> RcImageP5Information:
    """Common18 51df0: RC spec→availability→security→encryption-method.

    The source only checks the returned service byte for the three DID reads;
    it checks the explicit seed/key masks in SecurityUnlock. This stage does
    not implement the RC indexed block producer or its saved consumer.
    """
    if cache.source_build != 18:
        raise ValueError("RC image information requires original18")
    selected = cache.profile.frame_records(0x66)
    if not selected or frame != selected[0]:
        raise ValueError("RC image requires first selected function66")
    specification = _image_p5_read(
        cache,
        frame,
        bytes.fromhex("221103"),
        b"\xff" * 3,
        bytes.fromhex("621103"),
        5,
        check_expected=False,
    )
    if specification[3] != 2:
        raise ToyotaCodecError("RC image format is unsupported", 0x90040501)
    availability = _image_p5_read(
        cache,
        frame,
        bytes.fromhex("221126"),
        b"\xff" * 3,
        bytes.fromhex("621126"),
        6,
        check_expected=False,
    )
    if availability[3] != 1:
        raise ToyotaCodecError(
            "RC image availability format is unsupported", 0x90040501
        )
    numbers = tuple(
        index + 1 for index, flag in enumerate(availability[4:6]) if flag == 2
    )
    if not numbers:
        raise ToyotaCodecError("RC image has no memorized snapshot", 0x90040501)
    security = capture_image_p5_security(cache, frame, schedule)
    encryption = _image_p5_read(
        cache,
        frame,
        bytes.fromhex("222031"),
        b"\xff" * 3,
        bytes.fromhex("622031"),
        4,
        check_expected=False,
    )
    return RcImageP5Information(
        2, numbers, specification, availability, security, encryption
    )


@dataclass(frozen=True)
class Tss3ImageP5Information:
    format: int
    numbers: tuple[int, ...]
    raw_specification: bytes
    raw_availability: bytes
    security: ImageP4SecurityExchange
    raw_encryption_method: bytes


def capture_tss3_image_p5_information(
    cache: MonitorSupportCache, frame: SelectedFrame, schedule: bytes
) -> Tss3ImageP5Information:
    """Common18 500b0: distinct format5/7 specification and snapshot selectors."""
    if cache.source_build != 18:
        raise ValueError("TSS3 image information requires original18")
    selected = cache.profile.frame_records(0x66)
    if not selected or frame != selected[0]:
        raise ValueError("TSS3 image requires first selected function66")
    specification = _image_p5_read(
        cache,
        frame,
        bytes.fromhex("221103"),
        b"\xff" * 3,
        bytes.fromhex("621103"),
        15,
        check_expected=False,
    )
    format = specification[3]
    if format not in (5, 7):
        raise ToyotaCodecError("TSS3 image format is unsupported", 0x90040501)
    count = 10 if format == 5 else 11
    if len(specification) < count + 5:
        raise ToyotaCodecError("TSS3 image specification is truncated", 0xA0040202)
    expected = bytearray(count)
    expected[1], expected[6] = 2, 1
    if specification[5 : count + 5] != bytes(expected):
        raise ToyotaCodecError("TSS3 image specification is unsupported", 0x90040501)
    availability = _image_p5_read(
        cache,
        frame,
        bytes.fromhex("221101"),
        b"\xff" * 3,
        bytes.fromhex("621101"),
        14,
        check_expected=False,
    )
    if availability[3] != 2:
        raise ToyotaCodecError(
            "TSS3 image availability format is unsupported", 0x90040501
        )
    if len(availability) < count + 4:
        raise ToyotaCodecError("TSS3 image availability is truncated", 0xA0040202)
    numbers = tuple(
        index + 1 for index, flag in enumerate(availability[4 : count + 4]) if flag == 2
    )
    if not numbers:
        raise ToyotaCodecError("TSS3 image has no memorized snapshot", 0x90040501)
    security = capture_image_p5_security(cache, frame, schedule)
    encryption = _image_p5_read(
        cache,
        frame,
        bytes.fromhex("222081"),
        b"\xff" * 3,
        bytes.fromhex("622081"),
        4,
        check_expected=False,
    )
    return Tss3ImageP5Information(
        format, numbers, specification, availability, security, encryption
    )


@dataclass(frozen=True)
class PvmImageP5Information:
    format: int
    header_size: int
    native_dwords: tuple[int, ...]
    counts: tuple[int, ...]
    numbers: tuple[int, ...]
    security: ImageP4SecurityExchange
    raw_specification: bytes
    customization_replies: tuple[bytes, bytes]
    raw_information: bytes


def capture_pvm_image_p5_information(
    cache: MonitorSupportCache, frame: SelectedFrame, schedule: bytes
) -> PvmImageP5Information:
    """Common18 49630 legacy PVM path; the21CY path remains separate.

    Native4f9a0 copies seven four-byte groups from reply7..34 and seven counts
    from137..143. Keep these literal field associations without assigning
    unverified record-type or address meanings to the groups.
    """
    if cache.source_build != 18:
        raise ValueError("PVM image information requires original18")
    selected = cache.profile.frame_records(0x66)
    if not selected or frame != selected[0]:
        raise ValueError("PVM image requires first selected function66")
    security = capture_image_p5_security(cache, frame, schedule)
    availability = _image_p5_read(
        cache,
        frame,
        bytes.fromhex("221101"),
        b"\xff" * 3,
        bytes.fromhex("621101"),
        11,
        check_expected=False,
    )
    if availability[3] != 2:
        raise ToyotaCodecError(
            "PVM image availability format is unsupported", 0x90040501
        )
    numbers = tuple(
        index + 1 for index, flag in enumerate(availability[4:11]) if flag == 2
    )
    if not numbers:
        raise ToyotaCodecError("PVM image has no memorized snapshot", 0x90040501)
    specification = _image_p5_read(
        cache,
        frame,
        bytes.fromhex("221103"),
        b"\xff" * 3,
        bytes.fromhex("621103"),
        13,
        check_expected=False,
    )
    if specification[3] != 1 or specification[5:13] != bytes(8):
        raise ToyotaCodecError("PVM image specification is unsupported", 0x90040501)
    customization = tuple(
        _image_p5_read(
            cache,
            frame,
            request,
            b"\xff" * 3,
            bytes((0x62,)) + request[1:],
            1,
            check_expected=False,
        )
        for request in (bytes.fromhex("222032"), bytes.fromhex("222033"))
    )
    information = _image_p5_read(
        cache,
        frame,
        bytes.fromhex("221102"),
        b"\xff" * 3,
        bytes.fromhex("621102"),
        144,
        check_expected=False,
    )
    if information[6] < 8:
        raise ToyotaCodecError("PVM image header is unsupported", 0x90040501)
    return PvmImageP5Information(
        1,
        information[6],
        tuple(
            int.from_bytes(information[offset : offset + 4], "big")
            for offset in range(7, 35, 4)
        ),
        tuple(information[137:144]),
        numbers,
        security,
        specification,
        (customization[0], customization[1]),
        information,
    )


@dataclass(frozen=True)
class AdsImageP5Information:
    format: int
    native_dwords: tuple[int, ...]
    counts: tuple[int, ...]
    numbers: tuple[int, ...]
    security: AdsSecurityExchange
    raw_specification: bytes
    raw_information: bytes


def capture_ads_image_p5_information(
    cache: MonitorSupportCache, frame: SelectedFrame, key: bytes
) -> AdsImageP5Information:
    """Common18 4d290: ADS availability→canonical AES security→spec→info.

    Native ADS omits reply bounds before indexed accesses. Host guards require
    the five flag bytes, all five spec fields and the last information count.
    The indexed image record producer and saved consumer remain separate.
    """
    from scripts.database_resources import cancel_ads_security

    if cache.source_build != 18:
        raise ValueError("ADS image information requires original18")
    selected = cache.profile.frame_records(0x66)
    if not selected or frame != selected[0]:
        raise ValueError("ADS image requires first selected function66")
    availability = _image_p5_read(
        cache,
        frame,
        bytes.fromhex("221c05"),
        b"\xff" * 3,
        bytes.fromhex("621c05"),
        9,
        check_expected=False,
    )
    if availability[3] != 2:
        raise ToyotaCodecError(
            "ADS image availability format is unsupported", 0x90040501
        )
    numbers = tuple(
        index + 1 for index, flag in enumerate(availability[4:9]) if flag == 2
    )
    if not numbers:
        raise ToyotaCodecError("ADS image has no memorized snapshot", 0x90040501)
    security = cancel_ads_security(cache, key)
    specification = _image_p5_read(
        cache,
        frame,
        bytes.fromhex("221c07"),
        b"\xff" * 3,
        bytes.fromhex("621c07"),
        10,
        check_expected=False,
    )
    if specification[3] != 1 or specification[5:10] != bytes(5):
        raise ToyotaCodecError("ADS image specification is unsupported", 0x90040501)
    information = _image_p5_read(
        cache,
        frame,
        bytes.fromhex("221c06"),
        b"\xff" * 3,
        bytes.fromhex("621c06"),
        39,
        check_expected=False,
    )
    return AdsImageP5Information(
        1,
        tuple(
            int.from_bytes(information[offset : offset + 4], "big")
            for offset in range(4, 24, 4)
        ),
        tuple(information[34:39]),
        numbers,
        security,
        specification,
        information,
    )


@dataclass(frozen=True)
class Pvm21ImageP5Information:
    numbers: tuple[int, ...]
    security: ImageP4SecurityExchange
    raw_availability: bytes
    raw_specification: bytes
    raw_second_specification: bytes
    raw_encryption_method: bytes


def capture_pvm21_image_p5_information(
    cache: MonitorSupportCache, frame: SelectedFrame, schedule: bytes
) -> Pvm21ImageP5Information:
    """Common18 51290:21CY has two images and a distinct second spec read."""
    if cache.source_build != 18:
        raise ValueError("PVM21CY image information requires original18")
    selected = cache.profile.frame_records(0x66)
    if not selected or frame != selected[0]:
        raise ValueError("PVM21CY image requires first selected function66")
    security = capture_image_p5_security(cache, frame, schedule)
    availability = _image_p5_read(
        cache,
        frame,
        bytes.fromhex("221126"),
        b"\xff" * 3,
        bytes.fromhex("621126"),
        6,
        check_expected=False,
    )
    if availability[3] != 2:
        raise ToyotaCodecError("PVM21CY availability format is unsupported", 0x90040501)
    numbers = tuple(
        index + 1 for index, flag in enumerate(availability[4:6]) if flag == 2
    )
    if not numbers:
        raise ToyotaCodecError("PVM21CY has no memorized snapshot", 0x90040501)
    specification = _image_p5_read(
        cache,
        frame,
        bytes.fromhex("221103"),
        b"\xff" * 3,
        bytes.fromhex("621103"),
        4,
        check_expected=False,
    )
    second = _image_p5_read(
        cache,
        frame,
        bytes.fromhex("221128"),
        b"\xff" * 3,
        bytes.fromhex("621128"),
        5,
        check_expected=False,
    )
    if second[3:5] != bytes(2):
        raise ToyotaCodecError(
            "PVM21CY second specification is unsupported", 0x90040501
        )
    encryption = _image_p5_read(
        cache,
        frame,
        bytes.fromhex("222031"),
        b"\xff" * 3,
        bytes.fromhex("622031"),
        1,
        check_expected=False,
    )
    return Pvm21ImageP5Information(
        numbers, security, availability, specification, second, encryption
    )


_ADS_IMAGE_GROUPS = frozenset(
    (0x2820, 0x282B, 0x282C, 0x282D, 0x282E, 0, 0x10F0, 0x1000, 0x1AC0)
)
_ADS_IMAGE_NUMBER_TYPES = (
    (1, 0x3300),
    (2, 0x3501),
    (2, 0x3502),
    (3, 0x3D00),
    (4, 0x3E00),
    (5, 0x4600),
)


@dataclass(frozen=True)
class AdsImageRecord:
    group: int
    index: int
    raw_reply: bytes
    groups: tuple[AdsOperationGroup, ...]
    record_types: tuple[int, ...]

    @property
    def values(self) -> tuple[int, ...]:
        return tuple(value for group in self.groups for value in group.values)


def _ads_image_frame(cache: MonitorSupportCache, frame: SelectedFrame) -> None:
    selected = cache.profile.frame_records(0x66)
    if cache.source_build != 18 or not selected or frame != selected[0]:
        raise ValueError("ADS image records require original18 first selected66")


def capture_ads_image_groups(
    cache: MonitorSupportCache, frame: SelectedFrame
) -> tuple[int, ...]:
    """ADSImage18 2d30/2720: retain ordered native WORD support occurrences.

    Native2720 scans ten WORDs at114E8, including the adjacent vtable words.
    """
    _ads_image_frame(cache, frame)
    raw = _image_p5_read(
        cache, frame, b"\xab\x21", b"\xff\xff", b"\xeb\x21", 2, check_expected=False
    )
    groups = tuple(
        int.from_bytes(raw[offset : offset + 2], "big")
        for offset in range(2, len(raw) - 1, 2)
    )
    if not groups:
        raise ToyotaCodecError("ADS image support list is empty", 0x90040501)
    return groups


def capture_ads_image_indices(
    cache: MonitorSupportCache, frame: SelectedFrame, group: int
) -> tuple[int, ...]:
    """ADSImage18 41f0/4830: unsigned DWORD sort then adjacent deduplication."""
    _ads_image_frame(cache, frame)
    if type(group) is not int or not 0 <= group <= 65535:
        raise ValueError("ADS image group must fit WORD")
    raw = _image_p5_read(
        cache,
        frame,
        b"\xab\x22" + group.to_bytes(2, "big"),
        b"\xff\xff",
        b"\xeb\x22",
        4,
        check_expected=False,
    )
    return tuple(
        sorted(
            {
                int.from_bytes(raw[offset : offset + 4], "big")
                for offset in range(4, len(raw) - 3, 4)
            }
        )
    )


def capture_ads_image_record(
    cache: MonitorSupportCache, frame: SelectedFrame, group: int, index: int
) -> AdsImageRecord:
    """ADSImage18 3240/3800/3e80: actual AB23 and exact shared Ext DID parser.

    Both image3800 and operation23f0 use the same absolute-offset9 fallback,
    four-byte6000..6FFF lengths, first duplicate DID and0501 WORD scalar.
    Image additionally collects every5004 WORD for outer image-type selection.
    """
    _ads_image_frame(cache, frame)
    if (
        type(group) is not int
        or not 0 <= group <= 65535
        or type(index) is not int
        or not 0 <= index <= 0xFFFFFFFF
    ):
        raise ValueError("ADS image requires WORD group and DWORD index")
    raw = _image_p5_read(
        cache,
        frame,
        b"\xab\x23" + group.to_bytes(2, "big") + index.to_bytes(4, "big"),
        b"\xff\xff",
        b"\xeb\x23",
        1,
        check_expected=False,
    )
    parsed = ads_operation_groups(raw)
    types = tuple(
        int.from_bytes(payload[:2], "big")
        for entry in parsed
        for did, payload in entry.records
        if did == 0x5004 and len(payload) >= 2
    )
    return AdsImageRecord(group, index, raw, parsed, types)


@dataclass(frozen=True)
class ImageP5SavedResult:
    native_status: int
    records: tuple[ImageP5RecordAcquisition, ...]
    information: ImageP5Information | None
    security: ImageP4SecurityExchange | None
    ddr_report: DdrReport | DdrP5Report | None
    ddr_status: int
    source_sha256: str
    log_path: str
    disconnect_status: int


def _image_log_position(
    packet_log: DdrPacketLog, rollback: bool, offset: int
) -> tuple[int, int]:
    """Image18 9CA0/Image12 B6C0: primitive failure stops file; stop fault wins."""
    if rollback:
        status, value = packet_log.set_pointer(offset), offset
    else:
        status, observed = packet_log.get_size()
        value = offset if observed is None else observed
    if status:
        status = packet_log.stop() or status
    return status, value


def capture_image_p5_saved(
    communication: NativeCommunication,
    packet_log: DdrPacketLog,
    source: ImageP5Source,
    schedule: bytes,
    request: ImageP5Request18 | None = None,
) -> ImageP5SavedResult:
    """ImageFFDP5_DT18 Execute7240→7350, with concrete internal DDR/log owner.

    Original12 accepts only the native ECU input, acquires all five available
    snapshots and uses its own inline helpers and internal normal DDR route.
    Original18 requires actual typed snapshot numbers/selector/ECU references.
    Retries truncate file bytes without removing appended header scalars.
    """
    from scripts.database_resources import (
        DdrP5SupportValue,
        DdrPacketLog,
        DdrPartialReportError,
        capture_internal_ddr_report,
        ddr_report_support_values,
    )
    from scripts.native_communication import NativeCommunication, NativeFrameController

    if (
        not isinstance(communication, NativeCommunication)
        or not isinstance(communication.profile, VehicleProfile)
        or not isinstance(packet_log, DdrPacketLog)
        or not isinstance(source, ImageP5Source)
        or communication.source_build != source.build
        or packet_log.source_build != source.build
        or not isinstance(communication.operations, NativeFrameController)
        or packet_log.operations is not communication.operations
    ):
        raise ValueError(
            "Generic P5 image requires concrete versioned controller/log/input"
        )
    if source.build == 18 and not isinstance(request, ImageP5Request18):
        raise TypeError("Original18 image requires actual typed caller fields")
    if source.build == 12 and request is not None:
        raise ValueError("Original12 image caller has no snapshot/selector input")
    image_p4_security_key(bytes(6), schedule)
    cache = communication.cache
    cache.check_context()
    if request is not None and not request.numbers:
        return ImageP5SavedResult(
            0xC0040001, (), None, None, None, 0, source.sha256, str(packet_log.path), 0
        )
    logged = packet_log.start(1)
    status = disconnected = ddr_status = 0
    information = security = report = None
    records = []
    first, second = DdrP5SupportValue(170, False, 0), DdrP5SupportValue(171, False, 0)
    primary: BaseException | None = None
    try:
        try:
            try:
                report = capture_internal_ddr_report(
                    communication,
                    p5=request is not None and request.ddr_category == 0x1BC,
                )
                first, second = ddr_report_support_values(report)
            except ToyotaCodecError as error:
                # Native caller deliberately ignores this inner command's status.
                ddr_status = error.code
                if isinstance(error, DdrPartialReportError):
                    report = error.partial_report
                    first, second = ddr_report_support_values(report)
            connection = communication.connection_no_buffer(0, 1)
            status = connection.status
            if not status:
                with cache.temporary_scope(no_init=True):
                    frames = cache.profile.frame_records(0x66)
                    if not frames:
                        raise ToyotaCodecError(
                            "P5 image function66 is absent", 0xC0040101
                        )
                    frame = frames[0]
                    numbers = capture_image_p5_memorized(
                        cache, frame, request.selector if request is not None else None
                    )
                    security = capture_image_p5_security(cache, frame, schedule)
                    information = capture_image_p5_information(cache, frame)
                    image_offset = 0
                    if not logged:
                        logged, image_offset = _image_log_position(
                            packet_log, False, image_offset
                        )
                    acquired_bytes = 0
                    for number in numbers:
                        if request is not None and number not in request.numbers:
                            continue
                        for attempt in range(2):
                            relative, record_offset, retry_image = (
                                0,
                                image_offset,
                                False,
                            )
                            for _ in range(information.counts[number - 1]):
                                cache.check_context()
                                try:
                                    acquired = capture_image_p5_record(
                                        cache,
                                        frame,
                                        information,
                                        number,
                                        relative,
                                        first,
                                        second,
                                    )
                                except ToyotaCodecError as error:
                                    status, retry_image = error.code, True
                                    break
                                records.append(acquired)
                                acquired_bytes += len(acquired.header) + sum(
                                    len(item.reply) for item in acquired.body
                                )
                                if acquired_bytes > 32 * 1024 * 1024:
                                    raise SessionError(
                                        "P5 image capture exceeds host byte allowance"
                                    )
                                relative = acquired.next_offset
                                retry_image |= acquired.retry
                                status = acquired.native_status
                                if status:
                                    retry_image = True
                                    break
                                if not logged:
                                    logged, record_offset = _image_log_position(
                                        packet_log, acquired.excluded, record_offset
                                    )
                            if not logged:
                                logged, image_offset = _image_log_position(
                                    packet_log, retry_image, image_offset
                                )
                            if status or not retry_image or attempt:
                                break
                        if status:
                            break
        except ToyotaCodecError as error:
            status = error.code
    except BaseException as error:
        primary = error
        raise
    finally:
        try:
            disconnected = communication.disconnect(1)
        except BaseException as cleanup:
            if primary is None:
                raise
            primary.add_note(f"P5 image disconnect failed: {type(cleanup).__name__}")
        finally:
            if not logged:
                try:
                    logged = packet_log.stop()
                except BaseException as cleanup:
                    if primary is None:
                        raise
                    primary.add_note(
                        f"P5 image log cleanup failed: {type(cleanup).__name__}"
                    )
    return ImageP5SavedResult(
        status or logged,
        tuple(records),
        information,
        security,
        report,
        ddr_status,
        source.sha256,
        str(packet_log.path),
        disconnected,
    )


@dataclass(frozen=True)
class AdsImageRecordPhase:
    native_status: int
    freezes: tuple[AdsImageRecord, ...]
    records: tuple[AdsImageRecord, ...]
    suppressed_errors: tuple[tuple[bytes, int], ...]
    log_status: int


def capture_ads_image_record_phase(
    cache: MonitorSupportCache,
    frame: SelectedFrame,
    packet_log: DdrPacketLog,
    numbers: tuple[int, ...],
    first_ddr: DdrP5SupportValue,
    *,
    log_status: int = 0,
) -> AdsImageRecordPhase:
    """ADSImage18 1d00: supported groups, indices, type/counter filter and logs.

    Constructor-local result lists are retained across suppressed receive errors.
    The caller owns security, internal DDR, top-level logging and disconnect.
    """
    from scripts.database_resources import DdrP5SupportValue, DdrPacketLog

    _ads_image_frame(cache, frame)
    if not isinstance(packet_log, DdrPacketLog) or packet_log.source_build != 18:
        raise TypeError("ADS image phase requires concrete native18 packet file")
    if type(numbers) is not tuple or any(
        type(value) is not int or not 0 <= value <= 255 for value in numbers
    ):
        raise ValueError("ADS image requires actual caller BYTE number list")
    if (
        not isinstance(first_ddr, DdrP5SupportValue)
        or type(first_ddr.present) is not bool
        or type(first_ddr.value) is not int
        or not 0 <= first_ddr.value <= 0xFFFFFFFF
    ):
        raise ValueError("ADS image requires typed native first DDR support")
    groups = capture_ads_image_groups(cache, frame)
    accepted, status, offset, retained = False, 0, 0, 0
    freezes, records, errors = [], [], []
    for group in groups:
        cache.check_context()
        if group not in _ADS_IMAGE_GROUPS:
            continue
        accepted = True
        request = b"\xab\x22" + group.to_bytes(2, "big")
        try:
            indices = capture_ads_image_indices(cache, frame, group)
        except ToyotaCodecError as error:
            if error.code not in _OPERATION_SUPPRESSED:
                status = error.code
                break
            errors.append((request, error.code))
            continue
        if not indices:
            continue
        if not log_status:
            log_status, offset = _image_log_position(packet_log, False, offset)
        failed = False
        processed: set[int] = set()
        for index in indices:
            cache.check_context()
            request = b"\xab\x23" + group.to_bytes(2, "big") + index.to_bytes(4, "big")
            try:
                record = capture_ads_image_record(cache, frame, group, index)
            except ToyotaCodecError as error:
                if error.code not in _OPERATION_SUPPRESSED:
                    status = error.code
                    break
                errors.append((request, error.code))
                if not log_status:
                    log_status, offset = _image_log_position(packet_log, True, offset)
                if failed:
                    break
                failed = True
                continue
            failed = False
            records.append(record)
            retained += len(record.raw_reply)
            if retained > 32 * 1024 * 1024:
                raise SessionError("ADS image record phase exceeds host byte allowance")
            if not record.record_types or record.record_types[0] not in {
                row[1] for row in _ADS_IMAGE_NUMBER_TYPES
            }:
                status = 0x90040501
                if not log_status:
                    log_status, offset = _image_log_position(packet_log, True, offset)
                break
            kind = record.record_types[0]
            if not any(
                number in numbers and native_kind == kind
                for number, native_kind in _ADS_IMAGE_NUMBER_TYPES
            ):
                if not log_status:
                    log_status, offset = _image_log_position(packet_log, True, offset)
                break
            rollback = False
            if 0 < index <= 0xEFFF:
                scalar = record.values[0] if record.values else None
                allowed = scalar is not None and (
                    not first_ddr.present
                    or first_ddr.value == 0xFFFF
                    or bool(((first_ddr.value - scalar) & 0xFFFFFFFF) & 0x80000000)
                )
                if allowed:
                    freezes.append(record)
                    processed.add(index & 0xFFFF)
                else:
                    rollback = True
            else:
                # Native4850 compares index highWORD with lowWORD of a stored
                # CCmdDwordId value (GetAt object+8), not the stored highWORD.
                rollback = index == 0 or (index >> 16) not in processed
            if not log_status:
                log_status, offset = _image_log_position(packet_log, rollback, offset)
        if status:
            break
    if not accepted:
        status = 0x90040501
    return AdsImageRecordPhase(
        status, tuple(freezes), tuple(records), tuple(errors), log_status
    )


ADS_IMAGE_SOURCE_SHA256 = (
    "ec49f3bd9b70cbe8e112a0314f2e0137030335ea6788ae654cbe16754f89b41f"
)


@dataclass(frozen=True)
class AdsImageSource:
    build: int
    sha256: str

    def __post_init__(self) -> None:
        if (
            type(self.build) is not int
            or self.build != 18
            or self.sha256 != ADS_IMAGE_SOURCE_SHA256
        ):
            raise ValueError("ADS image requires exact original18 producer")


@dataclass(frozen=True)
class AdsImageRequest18:
    numbers: tuple[int, ...]
    ecu_info: tuple[ImageEcuReference, ...] = ()
    ddr_support: DdrP5SupportValue | None = None

    def __post_init__(self) -> None:
        from scripts.database_resources import DdrP5SupportValue

        ImageP5Request18(self.numbers, 0, self.ecu_info)
        if self.ddr_support is not None and (
            not isinstance(self.ddr_support, DdrP5SupportValue)
            or type(self.ddr_support.present) is not bool
            or type(self.ddr_support.value) is not int
            or not 0 <= self.ddr_support.value <= 0xFFFFFFFF
        ):
            raise ValueError("ADS provided native DDR support is malformed")

    @property
    def ddr_category(self) -> int:
        return (
            0x1BC
            if any(row.native_id == 0x1BC and row.state == 1 for row in self.ecu_info)
            else 0xBC
        )


@dataclass(frozen=True)
class AdsImageSavedResult:
    native_status: int
    phase: AdsImageRecordPhase | None
    information: AdsImageP5Information | None
    first_support: DdrP5SupportValue
    ddr_report: DdrReport | DdrP5Report | None
    ddr_status: int
    ddr_provided: bool
    source_sha256: str
    log_path: str
    disconnect_status: int


def capture_ads_image_saved(
    communication: NativeCommunication,
    packet_log: DdrPacketLog,
    source: AdsImageSource,
    key: bytes,
    request: AdsImageRequest18,
) -> AdsImageSavedResult:
    """ADSImage18 Execute1010→1120: internal DDR→info→native indexed records."""
    from scripts.database_resources import (
        DdrP5SupportValue,
        DdrPacketLog,
        DdrPartialReportError,
        capture_internal_ddr_report,
        ddr_report_support_values,
    )
    from scripts.native_communication import NativeCommunication, NativeFrameController

    if (
        not isinstance(communication, NativeCommunication)
        or not isinstance(communication.profile, VehicleProfile)
        or not isinstance(packet_log, DdrPacketLog)
        or not isinstance(source, AdsImageSource)
        or communication.source_build != 18
        or packet_log.source_build != 18
        or not isinstance(communication.operations, NativeFrameController)
        or packet_log.operations is not communication.operations
        or not isinstance(request, AdsImageRequest18)
    ):
        raise ValueError(
            "ADS image requires one selected18 controller/log/source/input"
        )
    if type(key) is not bytes or len(key) != 16:
        raise ValueError("ADS image requires explicit sixteen-byte AES material")
    cache = communication.cache
    cache.check_context()
    provided = request.ddr_support is not None
    first = request.ddr_support or DdrP5SupportValue(170, False, 0)
    if not request.numbers:
        return AdsImageSavedResult(
            0xC0040001,
            None,
            None,
            first,
            None,
            0,
            provided,
            source.sha256,
            str(packet_log.path),
            0,
        )
    logged = packet_log.start(24)
    status = ddr_status = disconnected = stopped = 0
    phase = information = report = None
    primary: BaseException | None = None
    try:
        try:
            if not provided:
                try:
                    report = capture_internal_ddr_report(
                        communication, p5=request.ddr_category == 0x1BC
                    )
                    first = ddr_report_support_values(report)[0]
                except ToyotaCodecError as error:
                    ddr_status = error.code
                    if isinstance(error, DdrPartialReportError):
                        report = error.partial_report
                        first = ddr_report_support_values(report)[0]
            connected = communication.connection_no_buffer(0, 1)
            status = connected.status
            if not status:
                with cache.temporary_scope(no_init=True):
                    frames = cache.profile.frame_records(0x66)
                    if not frames:
                        raise ToyotaCodecError(
                            "ADS image function66 is absent", 0xC0040101
                        )
                    frame = frames[0]
                    information = capture_ads_image_p5_information(cache, frame, key)
                    phase = capture_ads_image_record_phase(
                        cache,
                        frame,
                        packet_log,
                        request.numbers,
                        first,
                        log_status=logged,
                    )
                    status, logged = phase.native_status, phase.log_status
        except ToyotaCodecError as error:
            status = error.code
    except BaseException as error:
        primary = error
        raise
    finally:
        disconnected, stopped = _cleanup_saved_operation(
            communication, packet_log, logged, primary
        )
    return AdsImageSavedResult(
        status or logged or stopped,
        phase,
        information,
        first,
        report,
        ddr_status,
        provided,
        source.sha256,
        str(packet_log.path),
        disconnected,
    )


@dataclass(frozen=True)
class RcImageSubgroup:
    before: int
    regular: int
    after: int


@dataclass(frozen=True)
class RcImageGroup:
    number: int
    protocol_id: int
    native_count: int
    subgroups: tuple[RcImageSubgroup, ...]
    enabled: bool


@dataclass(frozen=True)
class RcImageIndexInformation:
    groups: tuple[RcImageGroup, RcImageGroup]
    suppressed_errors: tuple[tuple[int, int], ...]
    raw_replies: tuple[tuple[bytes, bytes], ...]


def capture_rc_image_indices(
    cache: MonitorSupportCache, frame: SelectedFrame, numbers: tuple[int, ...]
) -> RcImageIndexInformation:
    """RC18 1160→11e0→16a0→1a10→1fd0→21f0→24f0→1df0/1f10."""
    from dataclasses import replace

    _ads_image_frame(cache, frame)
    if type(numbers) is not tuple or any(
        type(number) is not int or number not in (1, 2) for number in numbers
    ):
        raise ValueError("RC image caller numbers must index the two native groups")
    raw_replies, errors = [], []

    def read(request: bytes, minimum: int = 1) -> bytes:
        reply = _image_p5_read(
            cache,
            frame,
            request,
            b"\xff" * min(3, len(request)),
            bytes((request[0] | 0x40,)) + request[1:3],
            minimum,
            check_expected=False,
        )
        raw_replies.append((request, reply))
        return reply

    identifiers = read(bytes.fromhex("221129"), 3)
    if (len(identifiers) - 3) // 2 != 2:
        raise ToyotaCodecError("RC image protocol identifier count differs", 0x90040501)
    ids = tuple(
        int.from_bytes(identifiers[offset : offset + 2], "big") for offset in (3, 5)
    )
    counts = read(bytes.fromhex("22112c"), 1)
    if len(counts) != 5:
        raise ToyotaCodecError("RC image subgroup count length differs", 0x90040501)
    # Exact constructor constants124A0: per-group DID112F/1132 and caps2/3.
    maximum = (2, 3)
    groups, accepted = [], 0
    for index, did in enumerate((0x112F, 0x1132)):
        count = min(counts[3 + index], maximum[index])
        entries: tuple[RcImageSubgroup, ...] = ()
        try:
            reply = read(b"\x22" + did.to_bytes(2, "big"))
        except ToyotaCodecError as error:
            errors.append((did, error.code))
            count = 0
        else:
            actual = ((len(reply) - 3) & 0xFFFFFFFF) // 3
            if (actual * 3 + 3) & 0xFFFFFFFF != len(reply):
                actual = 0
            if actual & 255 == count:
                entries = tuple(
                    RcImageSubgroup(
                        reply[offset], min(reply[offset + 1], 10), reply[offset + 2]
                    )
                    for offset in range(3, 3 + actual * 3, 3)
                )
                accepted += 1
            else:
                count = 0
        groups.append(RcImageGroup(index + 1, ids[index], count, entries, False))
    if not accepted:
        raise ToyotaCodecError("RC image has no valid subgroup information", 0x90040501)
    read(bytes.fromhex("221130"))
    read(bytes.fromhex("221133"))
    support = read(bytes.fromhex("ab31"), 2)
    available = tuple(
        int.from_bytes(support[offset : offset + 2], "big")
        for offset in range(2, len(support) - 1, 2)
    )
    if not available:
        raise ToyotaCodecError("RC image support list is empty", 0x90040501)
    enabled = set()
    for identifier in available:
        for group in groups:
            if group.protocol_id == identifier:
                enabled.add(group.number)
                break
    groups = [replace(group, enabled=group.number in enabled) for group in groups]
    if not any(group.enabled for group in groups) or not any(
        groups[number - 1].enabled for number in numbers
    ):
        raise ToyotaCodecError("RC image caller has no supported group", 0x90040501)
    return RcImageIndexInformation(
        (groups[0], groups[1]), tuple(errors), tuple(raw_replies)
    )


def rc_image_regular_index(block: int, subgroup: int, occurrence: int) -> int:
    """RC18 3780 literal native WORD arithmetic."""
    if any(
        type(value) is not int or not 0 <= value <= 255
        for value in (block, subgroup, occurrence)
    ):
        raise ValueError("RC regular index inputs must fit BYTE")
    return (block * 0x200 + subgroup * 10 - 10 + occurrence) & 0xFFFF


def rc_image_adjacent_index(block: int, subgroup: int, before: int, after: int) -> int:
    """RC18 37b0 literal native DWORD arithmetic."""
    if any(
        type(value) is not int or not 0 <= value <= 255
        for value in (block, subgroup, before, after)
    ):
        raise ValueError("RC adjacent index inputs must fit BYTE")
    return (
        ((block * 0x200 - 9 + subgroup * 10) * 0x10000)
        + ((before - 1 + after) & 0xFFFF)
    ) & 0xFFFFFFFF


@dataclass(frozen=True)
class RcImageBlock:
    protocol_id: int
    index: int
    raw_reply: bytes
    values: tuple[int, ...]
    native_status: int = 0


@dataclass(frozen=True)
class RcImageAcquisition:
    number: int
    subgroup: int
    regular: bool
    before: int
    after: int
    blocks: tuple[RcImageBlock, ...]


@dataclass(frozen=True)
class RcImageRecordPhase:
    information: RcImageIndexInformation
    freezes: tuple[RcImageAcquisition, ...]
    acquisitions: tuple[RcImageAcquisition, ...]
    log_status: int


def capture_rc_image_record_phase(
    cache: MonitorSupportCache,
    frame: SelectedFrame,
    packet_log: DdrPacketLog,
    numbers: tuple[int, ...],
    first_ddr: DdrP5SupportValue,
    *,
    log_status: int = 0,
) -> RcImageRecordPhase:
    """RC18 A590: caller-ordered groups and regular/adjacent seven-block reads.

    Only a complete accepted seven-block acquisition appends a freeze. Native
    receive failures roll back that record's actual packet-file bytes and keep
    scanning; host interruption and budgets propagate through the outer owner.
    """
    from scripts.database_resources import DdrP5SupportValue, DdrPacketLog
    from scripts.native_communication import CommunicationError
    from scripts.toyota_session import NativeStatus

    if not isinstance(packet_log, DdrPacketLog) or packet_log.source_build != 18:
        raise TypeError("RC image records require concrete native18 packet file")
    if (
        not isinstance(first_ddr, DdrP5SupportValue)
        or type(first_ddr.present) is not bool
        or type(first_ddr.value) is not int
        or not 0 <= first_ddr.value <= 0xFFFFFFFF
    ):
        raise ValueError("RC image requires typed native first DDR support")
    information = capture_rc_image_indices(cache, frame, numbers)
    offset = 0
    if not log_status:
        log_status, offset = _image_log_position(packet_log, False, offset)
    freezes, acquisitions = [], []
    retained = 0
    for number in numbers:
        group = information.groups[number - 1]
        if not group.enabled:
            continue
        for subgroup_index, counts in enumerate(
            group.subgroups[: group.native_count], 1
        ):
            occurrences = [
                (True, occurrence, 0) for occurrence in range(1, counts.regular + 1)
            ]
            occurrences += [
                (False, before, 0) for before in range(1, counts.before + 1)
            ]
            occurrences += [
                (False, counts.before, after) for after in range(1, counts.after + 1)
            ]
            for regular, before, after in occurrences:
                cache.check_context()
                blocks: list[RcImageBlock] = []
                accepted = False
                for block in range(1, 8):
                    index = (
                        rc_image_regular_index(block, subgroup_index, before)
                        if regular
                        else rc_image_adjacent_index(
                            block, subgroup_index, before, after
                        )
                    )
                    request = (
                        b"\xab\x33"
                        + group.protocol_id.to_bytes(2, "big")
                        + index.to_bytes(4, "big")
                    )
                    try:
                        raw = _image_p5_read(
                            cache,
                            frame,
                            request,
                            b"\xff\xff",
                            b"\xeb\x33",
                            1,
                            check_expected=False,
                        )
                    except ToyotaCodecError as error:
                        raw = (
                            error.response
                            if isinstance(error, CommunicationError)
                            else error.reply
                            if isinstance(error, NativeStatus)
                            else b""
                        )
                        blocks.append(
                            RcImageBlock(group.protocol_id, index, raw, (), error.code)
                        )
                        break
                    retained += len(raw)
                    if retained > 32 * 1024 * 1024:
                        raise SessionError(
                            "RC image records exceed host byte allowance"
                        )
                    values = (
                        tuple(
                            value
                            for item in ads_operation_groups(raw)
                            for value in item.values
                        )
                        if block == 1
                        else ()
                    )
                    blocks.append(RcImageBlock(group.protocol_id, index, raw, values))
                    if block == 1:
                        scalar = values[0] if values else None
                        accepted = scalar is not None and (
                            not first_ddr.present
                            or first_ddr.value == 0xFFFF
                            or bool(
                                ((first_ddr.value - scalar) & 0xFFFFFFFF) & 0x80000000
                            )
                        )
                        if not accepted:
                            break
                acquired = RcImageAcquisition(
                    number, subgroup_index, regular, before, after, tuple(blocks)
                )
                acquisitions.append(acquired)
                complete = (
                    accepted and len(blocks) == 7 and not blocks[-1].native_status
                )
                if complete:
                    freezes.append(acquired)
                if not log_status:
                    log_status, offset = _image_log_position(
                        packet_log, not complete, offset
                    )
    return RcImageRecordPhase(
        information, tuple(freezes), tuple(acquisitions), log_status
    )


RC_IMAGE_SOURCE_SHA256 = (
    "20767568f6a7df0df5c64cbee72730fee3d9400c484b0310edde63eb6baab81c"
)


@dataclass(frozen=True)
class RcImageSource:
    build: int
    sha256: str

    def __post_init__(self) -> None:
        if (
            type(self.build) is not int
            or self.build != 18
            or self.sha256 != RC_IMAGE_SOURCE_SHA256
        ):
            raise ValueError("RC image requires exact original18 producer")


@dataclass(frozen=True)
class RcImageRequest18:
    numbers: tuple[int, ...]
    ecu_info: tuple[ImageEcuReference, ...] = ()
    ddr_support: DdrP5SupportValue | None = None

    def __post_init__(self) -> None:
        from scripts.database_resources import DdrP5SupportValue

        ImageP5Request18(self.numbers, 0, self.ecu_info)
        if any(number not in (1, 2) for number in self.numbers):
            raise ValueError("RC image requires native group number one or two")
        if self.ddr_support is not None and (
            not isinstance(self.ddr_support, DdrP5SupportValue)
            or type(self.ddr_support.present) is not bool
            or type(self.ddr_support.value) is not int
            or not 0 <= self.ddr_support.value <= 0xFFFFFFFF
        ):
            raise ValueError("ADS provided native DDR support is malformed")

    @property
    def ddr_category(self) -> int:
        return (
            0x1BC
            if any(row.native_id == 0x1BC and row.state == 1 for row in self.ecu_info)
            else 0xBC
        )


@dataclass(frozen=True)
class RcImageSavedResult:
    native_status: int
    phase: RcImageRecordPhase | None
    information: RcImageP5Information | None
    first_support: DdrP5SupportValue
    ddr_report: DdrReport | DdrP5Report | None
    ddr_status: int
    ddr_provided: bool
    source_sha256: str
    log_path: str
    disconnect_status: int


def capture_rc_image_saved(
    communication: NativeCommunication,
    packet_log: DdrPacketLog,
    source: RcImageSource,
    schedule: bytes,
    request: RcImageRequest18,
) -> RcImageSavedResult:
    """RCImage18 Execute9C50→9D60: internal DDR→info→native indexed records."""
    from scripts.database_resources import (
        DdrP5SupportValue,
        DdrPacketLog,
        DdrPartialReportError,
        capture_internal_ddr_report,
        ddr_report_support_values,
    )
    from scripts.native_communication import NativeCommunication, NativeFrameController

    if (
        not isinstance(communication, NativeCommunication)
        or not isinstance(communication.profile, VehicleProfile)
        or not isinstance(packet_log, DdrPacketLog)
        or not isinstance(source, RcImageSource)
        or communication.source_build != 18
        or packet_log.source_build != 18
        or not isinstance(communication.operations, NativeFrameController)
        or packet_log.operations is not communication.operations
        or not isinstance(request, RcImageRequest18)
    ):
        raise ValueError("RC image requires one selected18 controller/log/source/input")
    if type(schedule) is not bytes or len(schedule) != 6:
        raise ValueError("RC image requires explicit six-byte schedule")
    cache = communication.cache
    cache.check_context()
    provided = request.ddr_support is not None
    first = request.ddr_support or DdrP5SupportValue(170, False, 0)
    if not request.numbers:
        return RcImageSavedResult(
            0xC0040001,
            None,
            None,
            first,
            None,
            0,
            provided,
            source.sha256,
            str(packet_log.path),
            0,
        )
    logged = packet_log.start(26)
    status = ddr_status = disconnected = stopped = 0
    phase = information = report = None
    primary: BaseException | None = None
    try:
        try:
            if not provided:
                try:
                    report = capture_internal_ddr_report(
                        communication, p5=request.ddr_category == 0x1BC
                    )
                    first = ddr_report_support_values(report)[0]
                except ToyotaCodecError as error:
                    ddr_status = error.code
                    if isinstance(error, DdrPartialReportError):
                        report = error.partial_report
                        first = ddr_report_support_values(report)[0]
            connected = communication.connection_no_buffer(0, 1)
            status = connected.status
            if not status:
                with cache.temporary_scope(no_init=True):
                    frames = cache.profile.frame_records(0x66)
                    if not frames:
                        raise ToyotaCodecError(
                            "RC image function66 is absent", 0xC0040101
                        )
                    frame = frames[0]
                    information = capture_rc_image_p5_information(
                        cache, frame, schedule
                    )
                    phase = capture_rc_image_record_phase(
                        cache,
                        frame,
                        packet_log,
                        request.numbers,
                        first,
                        log_status=logged,
                    )
                    logged = phase.log_status
        except ToyotaCodecError as error:
            status = error.code
    except BaseException as error:
        primary = error
        raise
    finally:
        disconnected, stopped = _cleanup_saved_operation(
            communication, packet_log, logged, primary
        )
    return RcImageSavedResult(
        status or logged or stopped,
        phase,
        information,
        first,
        report,
        ddr_status,
        provided,
        source.sha256,
        str(packet_log.path),
        disconnected,
    )


@dataclass(frozen=True)
class Tss3ImageSubgroup:
    before: int
    regular: int
    after: int


@dataclass(frozen=True)
class Tss3ImageGroup:
    number: int
    protocol_id: int
    native_count: int
    subgroups: tuple[Tss3ImageSubgroup, ...]
    enabled: bool


@dataclass(frozen=True)
class Tss3ImageIndexInformation:
    groups: tuple[Tss3ImageGroup, ...]
    suppressed_errors: tuple[tuple[int, int], ...]
    raw_replies: tuple[tuple[bytes, bytes], ...]


def capture_tss3_image_indices(
    cache: MonitorSupportCache,
    frame: SelectedFrame,
    numbers: tuple[int, ...],
    format: int,
) -> Tss3ImageIndexInformation:
    """TSS3Image18 1160→11e0→16a0→1a10→1fd0→21f0→24f0→1df0/1f10."""
    from dataclasses import replace

    _ads_image_frame(cache, frame)
    if type(format) is not int or format not in (5, 7):
        raise ToyotaCodecError("TSS3 image index format is unsupported", 0x90040501)
    size = 10 if format == 5 else 11
    if type(numbers) is not tuple or any(
        type(number) is not int or not 1 <= number <= size for number in numbers
    ):
        raise ValueError(
            "TSS3 image caller numbers must index the format-selected native groups"
        )
    raw_replies, errors = [], []

    def read(request: bytes, minimum: int = 1) -> bytes:
        reply = _image_p5_read(
            cache,
            frame,
            request,
            b"\xff" * min(3, len(request)),
            bytes((request[0] | 0x40,)) + request[1:3],
            minimum,
            check_expected=False,
        )
        raw_replies.append((request, reply))
        return reply

    identifiers = read(bytes.fromhex("221104"), 3)
    if (len(identifiers) - 3) // 2 != size:
        raise ToyotaCodecError(
            "TSS3 image protocol identifier count differs", 0x90040501
        )
    ids = tuple(
        int.from_bytes(identifiers[offset : offset + 2], "big")
        for offset in range(3, 3 + size * 2, 2)
    )
    counts = read(bytes.fromhex("221107"), 1)
    if len(counts) != 3 + size:
        raise ToyotaCodecError("TSS3 image subgroup count length differs", 0x90040501)
    # Original18 .rdata134A8/134C0: constructor DIDs and BYTE caps.
    maximum = (1, 5, 1, 5, 2, 1, 30, 10, 3, 10, 3)
    groups, accepted = [], 0
    for index, did in enumerate(range(0x110A, 0x110A + size * 3, 3)):
        count = min(counts[3 + index], maximum[index])
        entries: tuple[Tss3ImageSubgroup, ...] = ()
        try:
            reply = read(b"\x22" + did.to_bytes(2, "big"))
        except ToyotaCodecError as error:
            errors.append((did, error.code))
            count = 0
        else:
            actual = ((len(reply) - 3) & 0xFFFFFFFF) // 3
            if (actual * 3 + 3) & 0xFFFFFFFF != len(reply):
                actual = 0
            if actual & 255 == count:
                entries = tuple(
                    Tss3ImageSubgroup(
                        reply[offset], min(reply[offset + 1], 10), reply[offset + 2]
                    )
                    for offset in range(3, 3 + actual * 3, 3)
                )
                accepted += 1
            else:
                count = 0
        groups.append(Tss3ImageGroup(index + 1, ids[index], count, entries, False))
    if not accepted:
        raise ToyotaCodecError(
            "TSS3 image has no valid subgroup information", 0x90040501
        )
    support = read(bytes.fromhex("ab31"), 2)
    available = tuple(
        int.from_bytes(support[offset : offset + 2], "big")
        for offset in range(2, len(support) - 1, 2)
    )
    if not available:
        raise ToyotaCodecError("TSS3 image support list is empty", 0x90040501)
    enabled = set()
    for identifier in available:
        for group in groups:
            if group.protocol_id == identifier:
                enabled.add(group.number)
                break
    groups = [replace(group, enabled=group.number in enabled) for group in groups]
    if not any(group.enabled for group in groups) or not any(
        groups[number - 1].enabled for number in numbers
    ):
        raise ToyotaCodecError("TSS3 image caller has no supported group", 0x90040501)
    return Tss3ImageIndexInformation(tuple(groups), tuple(errors), tuple(raw_replies))


def tss3_image_regular_index(block: int, subgroup: int, occurrence: int) -> int:
    """TSS3Image18 3780 literal native WORD arithmetic."""
    if any(
        type(value) is not int or not 0 <= value <= 255
        for value in (block, subgroup, occurrence)
    ):
        raise ValueError("RC regular index inputs must fit BYTE")
    return (block * 0x200 + subgroup * 10 - 10 + occurrence) & 0xFFFF


def tss3_image_adjacent_index(
    block: int, subgroup: int, before: int, after: int
) -> int:
    """TSS3Image18 37b0 literal native DWORD arithmetic."""
    if any(
        type(value) is not int or not 0 <= value <= 255
        for value in (block, subgroup, before, after)
    ):
        raise ValueError("RC adjacent index inputs must fit BYTE")
    return (
        ((block * 0x200 - 9 + subgroup * 10) * 0x10000)
        + ((before - 1 + after) & 0xFFFF)
    ) & 0xFFFFFFFF


@dataclass(frozen=True)
class Tss3ImageBlock:
    protocol_id: int
    index: int
    raw_reply: bytes
    values: tuple[int, ...]
    native_status: int = 0


@dataclass(frozen=True)
class Tss3ImageAcquisition:
    number: int
    subgroup: int
    regular: bool
    before: int
    after: int
    blocks: tuple[Tss3ImageBlock, ...]


@dataclass(frozen=True)
class Tss3ImageRecordPhase:
    information: Tss3ImageIndexInformation
    freezes: tuple[Tss3ImageAcquisition, ...]
    acquisitions: tuple[Tss3ImageAcquisition, ...]
    log_status: int


def capture_tss3_image_record_phase(
    cache: MonitorSupportCache,
    frame: SelectedFrame,
    packet_log: DdrPacketLog,
    numbers: tuple[int, ...],
    first_ddr: DdrP5SupportValue,
    *,
    format: int,
    log_status: int = 0,
) -> Tss3ImageRecordPhase:
    """TSS3Image18 A590: caller-ordered groups and regular/adjacent twenty-two-block reads.

    Only a complete accepted twenty-two-block acquisition appends a freeze. Native
    receive failures roll back that record's actual packet-file bytes and keep
    scanning; host interruption and budgets propagate through the outer owner.
    """
    from scripts.database_resources import DdrP5SupportValue, DdrPacketLog
    from scripts.native_communication import CommunicationError
    from scripts.toyota_session import NativeStatus

    if not isinstance(packet_log, DdrPacketLog) or packet_log.source_build != 18:
        raise TypeError("TSS3 image records require concrete native18 packet file")
    if (
        not isinstance(first_ddr, DdrP5SupportValue)
        or type(first_ddr.present) is not bool
        or type(first_ddr.value) is not int
        or not 0 <= first_ddr.value <= 0xFFFFFFFF
    ):
        raise ValueError("TSS3 image requires typed native first DDR support")
    information = capture_tss3_image_indices(cache, frame, numbers, format)
    offset = 0
    if not log_status:
        log_status, offset = _image_log_position(packet_log, False, offset)
    freezes, acquisitions = [], []
    retained = 0
    for number in numbers:
        group = information.groups[number - 1]
        if not group.enabled:
            continue
        for subgroup_index, counts in enumerate(
            group.subgroups[: group.native_count], 1
        ):
            occurrences = [
                (True, occurrence, 0) for occurrence in range(1, counts.regular + 1)
            ]
            occurrences += [
                (False, before, 0) for before in range(1, counts.before + 1)
            ]
            occurrences += [
                (False, counts.before, after) for after in range(1, counts.after + 1)
            ]
            for regular, before, after in occurrences:
                cache.check_context()
                blocks: list[Tss3ImageBlock] = []
                accepted = False
                for block in range(1, 23):
                    index = (
                        tss3_image_regular_index(block, subgroup_index, before)
                        if regular
                        else tss3_image_adjacent_index(
                            block, subgroup_index, before, after
                        )
                    )
                    request = (
                        b"\xab\x33"
                        + group.protocol_id.to_bytes(2, "big")
                        + index.to_bytes(4, "big")
                    )
                    try:
                        raw = _image_p5_read(
                            cache,
                            frame,
                            request,
                            b"\xff\xff",
                            b"\xeb\x33",
                            1,
                            check_expected=False,
                        )
                    except ToyotaCodecError as error:
                        raw = (
                            error.response
                            if isinstance(error, CommunicationError)
                            else error.reply
                            if isinstance(error, NativeStatus)
                            else b""
                        )
                        blocks.append(
                            Tss3ImageBlock(
                                group.protocol_id, index, raw, (), error.code
                            )
                        )
                        break
                    retained += len(raw)
                    if retained > 32 * 1024 * 1024:
                        raise SessionError(
                            "TSS3 image records exceed host byte allowance"
                        )
                    values = (
                        tuple(
                            value
                            for item in ads_operation_groups(raw)
                            for value in item.values
                        )
                        if block == 1
                        else ()
                    )
                    blocks.append(Tss3ImageBlock(group.protocol_id, index, raw, values))
                    if block == 1:
                        scalar = values[0] if values else None
                        accepted = scalar is not None and (
                            not first_ddr.present
                            or first_ddr.value == 0xFFFF
                            or bool(
                                ((first_ddr.value - scalar) & 0xFFFFFFFF) & 0x80000000
                            )
                        )
                        if not accepted:
                            break
                acquired = Tss3ImageAcquisition(
                    number, subgroup_index, regular, before, after, tuple(blocks)
                )
                acquisitions.append(acquired)
                complete = (
                    accepted and len(blocks) == 22 and not blocks[-1].native_status
                )
                if complete:
                    freezes.append(acquired)
                if not log_status:
                    log_status, offset = _image_log_position(
                        packet_log, not complete, offset
                    )
    return Tss3ImageRecordPhase(
        information, tuple(freezes), tuple(acquisitions), log_status
    )
