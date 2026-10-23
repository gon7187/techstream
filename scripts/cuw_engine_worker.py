"""Source-bound CUW2026 multi-file/node/CPU worker state.

The worker is issued once by :class:`CUWEngine2026`.  It owns the native fields
that sit between the engine and ControlCommPhase; transport callbacks never
decide that a phase or a programming operation succeeded.
"""

from __future__ import annotations

import math
import threading
import weakref
from collections.abc import Iterator
from contextlib import nullcontext
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Literal, cast

from scripts.calibration_2026 import (
    Native2026Metadata,
    native2026_cpu_count,
    native2026_cpu_targets,
    native2026_cpu_type,
    native2026_cpu_values,
    native2026_global_cpu_index,
    native2026_metadata,
    native2026_metadata_for_cpu,
    parse_cuw_2026,
)


@dataclass
class _NativeJudgeRows2026:
    """Caller-owned5ffc0 outputs, unchanged by native early returns."""

    check_target: bool = False
    rows: tuple = ()
    count: int = 0


@dataclass(frozen=True)
class _NativeJudgeSelectionCache2026:
    """34e10/35b50/47e60 target and unmatched-CID fields, without FILE selection."""

    targets: tuple[int, ...] = ()
    unmatched_ids: tuple[bytes, ...] = ()
    unmatched_companions: tuple[bytes, ...] = ()
    authored_count: int = 0


@dataclass(frozen=True, eq=False)
class _NativeOrdinaryCPUPoint2026:
    origin: object
    metadata: Native2026Metadata
    before: int
    after: int
    site: Literal["recovery_ec94", "first_19710", "shared_offset", "second_19710"]
    thread_id: int
    before_node: int
    before_cpu_index: int


@dataclass(eq=False)
class _NativeOrdinaryCIDPoint2026:
    origin: object
    iterator: Iterator[object]
    metadata: Native2026Metadata
    entry_metadata: Native2026Metadata
    thread_id: int
    before_node: int
    before_cpu_index: int
    step: object | None = None


def _native_a48_cache_slot2026(sources, index: int) -> int | None:
    """Resolve43ee0's shared archive-cache ordinal from an original PART pointer."""
    metadata = sources.files[index]
    for member, group_index in sources.delta_map_entries:
        if member.source_container is metadata.source_container:
            return group_index
    if sources.delta_archive and sources.delta_map_size == 0:
        return index
    return None


def _native_flashability_row2026(
    *,
    old_cid: bytes,
    new_cid: bytes,
    companion: bytes,
    eligible: bool,
    description: bytes,
    terminal: bool,
) -> bytes:
    """Pack the exact5ffc0 333-byte row with bounded native C strings."""
    fields = (
        (old_cid, 0x22),
        (new_cid, 0x22),
        (companion, 7),
        (description, 0x100),
    )
    if (
        any(type(value) is not bytes for value, _ in fields)
        or any(b"\0" in value or len(value) >= width for value, width in fields)
        or type(eligible) is not bool
        or type(terminal) is not bool
    ):
        raise ValueError("Bounded native5ffc0 row fields required")
    raw = bytearray(333)
    offsets = (0, 0x22, 0x44, 0x4C)
    for (value, _), offset in zip(fields, offsets, strict=True):
        raw[offset : offset + len(value)] = value
    raw[0x4B] = int(eligible)
    raw[0x14C] = int(terminal)
    return bytes(raw)


def _native_flashability_stable_rows62330_2026(
    rows: tuple[bytes, ...],
) -> tuple[bytes, ...]:
    """Apply the four stable native62330 row passes and their exact keys."""
    if type(rows) is not tuple or any(
        type(row) is not bytes or len(row) != 333 for row in rows
    ):
        raise ValueError("Exact native62330 temporary row vector required")
    result: list[bytes] = []
    seen_old: set[tuple[bytes, bytes]] = set()
    seen_new: set[tuple[bytes, bytes]] = set()
    for pass_index in range(4):
        for row in rows:
            old = row[:0x22].split(b"\0", 1)[0]
            new = row[0x22:0x44].split(b"\0", 1)[0]
            companion = row[0x44:0x4B].split(b"\0", 1)[0]
            eligible = row[0x4B] != 0
            category = 0 if eligible else 1 if old and new else 2 if old else 3
            if category != pass_index:
                continue
            if pass_index in (1, 2):
                key = (old, companion)
                if key in seen_old:
                    continue
                seen_old.add(key)
            elif pass_index == 3:
                key = (new, companion)
                if key in seen_new:
                    continue
                seen_new.add(key)
            result.append(row)
            seen_old.add((old, companion))
            seen_new.add((new, companion))
    return tuple(result)


from scripts.cuw_persistence import ProgrammingLogInfo, build_programming_log_info
from scripts.programming_2026_common import NativeException2026

if TYPE_CHECKING:
    from scripts.calibration_2026 import NativeCIDMatch2026, NativeCPUSelection2026
    from scripts.cuw_2026 import (
        CUWEngine2026,
        EngineConfiguration2026,
        _JudgeFlashableInvocation2026,
    )
    from scripts.cuw_engine_threads import (
        EngineThreadJob2026,
        ThreadPhaseLease2026,
        _CompletionRecord2026,
    )
    from scripts.cuw_file_services import (
        FileSourceSet2026,
        NativeFileGroupView2026,
        NativeFileView2026,
    )
    from scripts.cuw_persistence import CUWPersistence, ReproInfoState
    from scripts.j2534_2026 import NativeCommunicationAddress
    from scripts.programming_2026_common import (
        ControlCommPhase2026,
        NativeRuntime2026,
    )
    from scripts.programming_replay import ProgrammingReplay


_ISSUE_TOKEN = object()
_ISSUE_LOCK = threading.RLock()
_ISSUED: weakref.WeakKeyDictionary[
    CUWEngine2026, weakref.ReferenceType[EngineWorker2026]
] = weakref.WeakKeyDictionary()
_REPLACEMENTS: weakref.WeakKeyDictionary[
    CUWEngine2026, tuple[EngineWorker2026, EngineWorker2026, int, str]
] = weakref.WeakKeyDictionary()


@dataclass(frozen=True)
class WorkerContinuation2026:
    """One native 581a0 yield, consumed by the outer controller after unwind."""

    sequence: int
    kind: Literal["cpu", "file", "complete"]
    file_index: int
    node: int
    cpu_index: int
    global_cpu_index: int
    target_index: int
    ig_cycle_required: bool


@dataclass(frozen=True)
class WorkerControlState2026:
    """Readonly 59ab0 copy-in fields; fatal and failed remain independent."""

    fatal: bool
    error_kind: int
    primary_error: int
    passthru_error: int
    failed: bool
    comm_phase: int
    initial_command_retry: bool
    native_context_964: bool
    use_new_password: bool
    source_mode: int
    notification: bool
    last_block_notification: bool
    native_context_970: bool
    ig_off_pending: bool
    alternate_cid: bool
    recovery_mode: bool
    native_fatal_input: bool
    lifecycle: str


@dataclass(frozen=True)
class WorkerSourceState2026:
    """Readonly 36800/3ec30/3f620 source-issued selection state."""

    current_file_index: int
    current_node: int
    current_cpu_index: int
    current_global_cpu_index: int
    cpu_offset: int
    progress_base: int
    target_indices: tuple[int, ...]
    retained_cpu_type: str
    prepare_handshake: int
    battery_voltage: float | None
    complete: bool
    phase_elapsed_ms: tuple[int, ...]
    continuation_pending: bool
    callback_24_state: int
    callback_28_state: int
    callback_47_state: int
    cpu_percentages: tuple[int, ...]
    unmatched_identifiers: tuple[bytes, ...] = field(repr=False)
    unmatched_companions: tuple[bytes, ...] = field(repr=False)
    authored_cpu_count: int
    authored_target_indices: tuple[int, ...]


@dataclass(frozen=True)
class WorkerOnlineContext2026:
    """41080 inputs originating only from the issued engine and loaded FILES."""

    engine_sha256: str
    source_sha256: str
    vin: bytes = field(repr=False)
    region: int
    kind_of_ecu: str
    is_daihatsu: bool
    all_loaded_metadata: tuple[Native2026Metadata, ...] = field(repr=False)


@dataclass(frozen=True)
class WorkerUSBRecoveryContext2026:
    """DH16e0 inputs from engine+73c and the imported software-ID vector."""

    target_calibration: bytes
    prior_software_count: int


@dataclass(frozen=True)
class _NativeGetterHistory2026:
    """One native+A34 slot; cold 4ee00 records keep their vectors empty."""

    received_cids: tuple[bytes, ...] = ()
    query_records: tuple[bytes, ...] = ()
    node_strings_28: tuple[bytes, ...] = ()
    node_strings_50: tuple[bytes, ...] = ()
    node_strings_78: tuple[bytes, ...] = ()
    node_strings_a0: tuple[bytes, ...] = ()
    cell_dword_bits_c8: tuple[int, ...] = ()
    cell_strings_d4: tuple[bytes, ...] = ()
    retained_bits_fc: tuple[bool, ...] = ()
    node_dword_bits_10c: tuple[int, ...] = ()
    name_118: bytes = b""
    name_130: bytes = b""


def _empty_getter_history_2026(maximum: int = 0) -> _NativeGetterHistory2026:
    """Construct the distinct empty or post-40580 M-shaped native record."""
    if type(maximum) is not int or maximum < 0:
        raise ValueError("Native getter capacity must be a nonnegative integer")
    return _NativeGetterHistory2026(
        node_strings_28=(b"",) * maximum,
        node_strings_50=(b"",) * maximum,
        node_strings_78=(b"",) * maximum,
        node_strings_a0=(b"",) * maximum,
        cell_dword_bits_c8=(0,) * (32 * maximum),
        cell_strings_d4=(b"",) * (32 * maximum),
        retained_bits_fc=(False,) * maximum,
        node_dword_bits_10c=(0,) * maximum,
    )


def _native_getter_c_string2026(raw: bytes, width: int) -> bytes:
    if (
        type(raw) is not bytes
        or type(width) is not int
        or width <= 0
        or len(raw) != width
    ):
        raise ValueError("Exact bounded native getter buffer required")
    return raw.split(b"\0", 1)[0]


def _native_getter_cell2026(raw: bytes) -> tuple[int, bytes]:
    if type(raw) is not bytes or len(raw) != 14:
        raise ValueError("Exact native getter cell required")
    type_bits = int.from_bytes(raw[:1], "little", signed=True) & 0xFFFFFFFF
    return type_bits, raw[1:].split(b"\0", 1)[0]


def _native_getter_requested_address2026(record: bytes):
    """Decode ED00's DWORD/logical flag and bounded eight-byte C string."""
    from scripts.cuw_persistence import RequestedAddress

    if type(record) is not bytes or len(record) != 12 or b"\0" not in record[4:]:
        raise ValueError("Exact native twelve-byte recovery address record required")
    value = record[4:].split(b"\0", 1)[0].decode("ascii")
    return RequestedAddress(value, logical=int.from_bytes(record[:4], "little") != 0)


@dataclass(frozen=True, eq=False)
class _NativeGetterObservation2026:
    """Persistent immutable values from one completed ordinary getter."""

    file_sources: FileSourceSet2026 | None
    pointer_value: tuple[str, int | None, str, int]
    flow_file_index: int
    observation_recovery_index: int
    configuration: EngineConfiguration2026
    capture_epoch: int
    ordinary_return_sequence: int
    phase_sequence: int
    decision_sequence: int
    sequence_changed_39c: bool
    received_cids: tuple[bytes, ...]
    query_records: tuple[bytes, ...]
    hardware: bytes
    node_strings_440: tuple[bytes, ...]
    node_strings_468: tuple[bytes, ...]
    node_strings_490: tuple[bytes, ...]
    node_strings_4b8: tuple[bytes, ...]
    configured_bits: tuple[bool, ...]
    retained_bits: tuple[bool, ...]
    cell_dword_bits: tuple[int, ...]
    cell_strings: tuple[bytes, ...]
    node_dword_bits: tuple[int, ...]
    name_1ba8: bytes
    name_1bc0: bytes
    communication_addresses: tuple[NativeCommunicationAddress, ...]


@dataclass(frozen=True, eq=False)
class _NativeGetterContinuation2026:
    """Immutable native next-FILE facts; this value grants no live capability."""

    worker: EngineWorker2026
    job: EngineThreadJob2026
    old_sequence: int
    old_lease: ThreadPhaseLease2026
    old_session: ProgrammingReplay
    old_completion: _CompletionRecord2026
    source_set: FileSourceSet2026
    flow_file_index: int
    flow_view: NativeFileView2026
    pointer_view: NativeFileView2026
    reset_epoch: int
    observation: _NativeGetterObservation2026
    decision_sequence: int
    capture_epoch: int
    post_tail_metadata: Native2026Metadata
    protocol_tail_value: str | None
    persistence: CUWPersistence
    persistence_state: ReproInfoState


@dataclass(frozen=True, eq=False)
class _NativeJudgeCommitOrigin2026:
    """One 62330 chosen-tail permit, consumed before49010 source writes."""

    worker: EngineWorker2026
    engine: CUWEngine2026
    invocation: object
    region: int
    thread_id: int
    file_sources: FileSourceSet2026 | None
    candidate: NativeFileView2026 | None
    before_flow: int
    before_metadata: Native2026Metadata
    persistence: CUWPersistence
    persistence_state: ReproInfoState
    status: int
    flashable: bool
    rows: tuple[bytes, ...]


@dataclass(frozen=True, eq=False)
class _NativeJudgeGroupResetOrigin2026:
    worker: EngineWorker2026
    invocation: object
    source_set: FileSourceSet2026
    group: NativeFileGroupView2026
    region: int
    whole_check: bool
    any_eligible: bool
    whole_rows: tuple[bytes, ...]
    thread_id: int


@dataclass(frozen=True, eq=False)
class _NativeJudgeDirectResetOrigin2026:
    worker: EngineWorker2026
    invocation: object
    source_set: FileSourceSet2026
    current_a48: NativeFileView2026
    region: int
    whole_check: bool
    any_eligible: bool
    whole_rows: tuple[bytes, ...]
    thread_id: int


@dataclass(eq=False)
class _NativeJudgeResetPoint2026:
    origin: object
    old_sources: FileSourceSet2026
    new_sources: FileSourceSet2026 | None
    branch: Literal["mapped", "direct"]
    stage: str
    runtime_metadata: Native2026Metadata
    current_view: NativeFileView2026
    outputs: _NativeJudgeRows2026
    row_buffer: object
    count_buffer: object
    boolean_buffer: object
    configuration: object
    reset_epoch: int
    publication: dict[str, object] | None = None
    saved_selection: _NativeJudgeSelectionCache2026 | None = None
    saved_cids: tuple[bytes, ...] = ()
    saved_match: NativeCIDMatch2026 | None = None


@dataclass(frozen=True, eq=False)
class _NativeFileWaitRestoreOrigin2026:
    worker: EngineWorker2026
    engine: CUWEngine2026
    invocation: _JudgeFlashableInvocation2026
    marker: object
    source_set: FileSourceSet2026
    metadata: Native2026Metadata
    requested_slot: int
    admission_identity: object
    timing_epoch: int
    thread_id: int


@dataclass(frozen=True)
class _NativeJudgeProjectionPoint2026:
    invocation: _JudgeFlashableInvocation2026
    view: NativeFileView2026
    site: str
    ordinal: int
    thread_id: int
    row_buffer: object
    row_count_buffer: object
    boolean_buffer: object
    rows_snapshot: tuple[bytes, ...]
    row_count_value: int
    boolean_value: bool


@dataclass(frozen=True, slots=True, eq=False)
class ControlFileCapture2026:
    """One source-issued 59ab0 FILE/order/target snapshot for an active phase."""

    _worker_ref: weakref.ReferenceType[EngineWorker2026] = field(repr=False)
    _engine: CUWEngine2026 = field(repr=False)
    _controller: ControlCommPhase2026 = field(repr=False)
    _runtime: NativeRuntime2026 = field(repr=False)
    metadata: Native2026Metadata
    native_order: tuple[int, ...]
    target_indices: tuple[int, ...]
    control_cpu_start: int
    _phase: int = field(repr=False)
    _thread_id: int = field(repr=False)
    _thread_job: object | None = field(repr=False)
    _import_epoch: int = field(repr=False)
    file_sources: FileSourceSet2026 | None
    pointer_view: NativeFileView2026 | None
    flow_view: NativeFileView2026 | None
    flow_file_index: int
    configuration: EngineConfiguration2026
    query_seed34: tuple[bytes, ...]
    configured_bits: tuple[bool, ...]
    sequence_changed_39c: bool
    job_sequence: int | None
    phase_lease: ThreadPhaseLease2026 | None
    raw_session: ProgrammingReplay | None
    completion_record: _CompletionRecord2026 | None

    def __copy__(self):
        return replace(self)

    def __deepcopy__(self, memo):
        clone = replace(self)
        memo[id(self)] = clone
        return clone

    def validate(self, engine, controller) -> None:
        from scripts.cuw_2026 import CUWEngine2026
        from scripts.cuw_engine_threads import EngineThreadJob2026
        from scripts.programming_2026_common import ControlCommPhase2026

        if (
            type(engine) is not CUWEngine2026
            or type(controller) is not ControlCommPhase2026
        ):
            raise ValueError("Active source-issued CONTROL FILE capture required")
        worker = self._worker_ref()
        current_thread_id = threading.get_ident()
        thread_owned = engine._phase_thread == current_thread_id
        if thread_owned and current_thread_id != self._thread_id:
            job = self._thread_job
            if type(job) is EngineThreadJob2026 and engine.thread_job is job:
                try:
                    job.validate_owner(engine, controller)
                    thread_owned = job.validate_callback_handoff() == self._thread_id
                except (RuntimeError, TypeError, ValueError):
                    thread_owned = False
            else:
                thread_owned = False
        if (
            type(self) is not ControlFileCapture2026
            or worker is None
            or worker._control_file_capture is not self
            or engine is not self._engine
            or controller is not self._controller
            or controller.runtime is not self._runtime
            or engine._worker is not worker
            or worker.engine is not engine
            or worker.controller is not controller
            or worker._closed
            or not engine.active
            or not thread_owned
            or engine.worker_phase != self._phase
            or worker._phase_started_ms is None
            or engine._identifier_context_epoch != self._import_epoch
        ):
            raise ValueError("Active source-issued CONTROL FILE capture required")
        if (
            type(self.flow_file_index) is not int
            or self.flow_file_index < 0
            or type(self.sequence_changed_39c) is not bool
            or type(self.query_seed34) is not tuple
            or len(self.query_seed34) != 34
            or any(
                type(record) is not bytes or len(record) != 12
                for record in self.query_seed34
            )
            or type(self.configured_bits) is not tuple
            or len(self.configured_bits) != self.configuration.cpu_maximum
            or any(type(value) is not bool for value in self.configured_bits)
        ):
            raise ValueError("Captured native getter values have invalid shapes")
        if self.file_sources is None:
            if self.pointer_view is not None or self.flow_view is not None:
                raise ValueError("Absent FILE source cannot carry native views")
        else:
            from scripts.cuw_file_services import (
                validate_file_sources_2026,
                validate_file_view_2026,
            )

            validate_file_sources_2026(self.file_sources)
            if (
                self.pointer_view is None
                or self.flow_view is None
                or self.pointer_view.sources is not self.file_sources
                or self.flow_view.sources is not self.file_sources
            ):
                raise ValueError("Captured FILE views differ from their source set")
            validate_file_view_2026(self.pointer_view, self.file_sources)
            validate_file_view_2026(self.flow_view, self.file_sources)
        job_values = (
            self.job_sequence,
            self.phase_lease,
            self.raw_session,
            self.completion_record,
        )
        if self.job_sequence is None:
            if self._thread_job is not None or any(
                value is not None for value in job_values[1:]
            ):
                raise ValueError("Standalone capture cannot retain partial job state")
        elif (
            type(self.job_sequence) is not int
            or self.job_sequence <= 0
            or any(value is None for value in job_values[1:])
            or self._thread_job is None
        ):
            raise ValueError("Captured child phase requires complete job lineage")
        else:
            job = self._thread_job
            from scripts.cuw_engine_threads import (
                EngineThreadJob2026,
                ThreadPhaseLease2026,
                _CompletionRecord2026,
            )
            from scripts.programming_replay import ProgrammingReplay

            if (
                type(job) is not EngineThreadJob2026
                or type(self.phase_lease) is not ThreadPhaseLease2026
                or type(self.raw_session) is not ProgrammingReplay
                or type(self.completion_record) is not _CompletionRecord2026
                or engine.thread_job is not job
                or job.worker is not worker
                or job._sequence != self.job_sequence
                or job._lease is not self.phase_lease
                or job._session is not self.raw_session
                or job._active_record is not self.completion_record
                or job._completion_records.get(self.job_sequence)
                is not self.completion_record
                or self.completion_record.completed.is_set()
                or self.phase_lease.state != "adopted"
                or not (job.is_child_thread or job.validate_callback_handoff())
            ):
                raise ValueError("Captured native child phase lineage expired")
        from scripts.calibration_2026 import native2026_validate_runtime_metadata

        native2026_validate_runtime_metadata(self.metadata)

    def metadata_for_cpu(self, index: int) -> Native2026Metadata:
        if type(index) is not int:
            raise TypeError("Unsigned ordered CONTROL CPU index required")
        self.validate(self._engine, self._controller)
        if not 0 <= index < len(self.native_order):
            raise ValueError("Ordered CONTROL CPU index is outside the held FILE")
        return native2026_metadata_for_cpu(self.metadata, self.native_order[index])


class NativeWorkerIntegerError2026(NativeException2026):
    """33f80's literal native integer exception, limited to source values0/1."""

    def __init__(self, code: int):
        if type(code) is not int or code not in (0, 1):
            raise ValueError("Native worker integer error must be0 or1")
        self.code = code
        super().__init__(str(code))


def _metadata_from_source(source, *, region: int) -> Native2026Metadata:
    from scripts.cuw_large import LargeSource2026

    if isinstance(source, bytes):
        return native2026_metadata(parse_cuw_2026(source), region=region)
    if type(source) is LargeSource2026:
        return native2026_metadata(source.container, region=region)
    raise TypeError("Actual bytes or authenticated large CUW source required")


def _loaded_metadata(engine: CUWEngine2026) -> tuple[Native2026Metadata, ...]:
    current = engine.native_metadata
    file_sources = engine.file_sources
    if file_sources is not None:
        from scripts.cuw_file_services import validate_file_sources_2026

        validate_file_sources_2026(file_sources, engine)
        files = list(file_sources.files)
        if not files:
            return (current,)
        matches = [
            index
            for index, item in enumerate(files)
            if item.source_container is current.source_container
        ]
        if len(matches) > 1:
            raise ValueError("Native FILE table repeats the current source")
        if not matches:
            # 32ff0(TRUE) keeps file index zero while selecting the A48 whole.
            files[0] = current
        return tuple(files)
    persistence = getattr(engine, "persistence", None)
    if persistence is None:
        persistence = getattr(engine, "_persistence", None)
    if persistence is None:
        return (current,)
    from scripts.cuw_persistence import CUWPersistence

    if type(persistence) is not CUWPersistence:
        raise TypeError("Concrete CUW recovery persistence required")
    persistence.validate_engine_owner(engine)
    persistence.state.validate()
    result = []
    for calibration in persistence.state.calibrations:
        digest = calibration.source_bytes
        metadata = _metadata_from_source(digest, region=current.region)
        if metadata.source_sha256 == current.source_sha256:
            metadata = current
        else:
            metadata = engine._parser_profile(metadata)
        result.append(metadata)
    if not result or not any(
        item.source_sha256 == current.source_sha256 for item in result
    ):
        raise ValueError("Loaded FILE vector omits the engine's current source")
    return tuple(result)


def _unresolved_selection(
    metadata: Native2026Metadata,
) -> tuple[tuple[int, ...], tuple[int, ...]]:
    """59070 constructor state before34e10→3ddf0→3e710 consumes CIDs."""
    count = native2026_cpu_count(metadata)
    return (-1,) * count, tuple(range(count))


def _replacement_engine_lock(engine: CUWEngine2026):
    """Reuse36's non-reentrant engine lock only on its authenticated owner thread."""
    if getattr(engine, "_worker_replacement_thread", None) == threading.get_ident():
        return nullcontext()
    return engine._lock


def _issue_engine_worker(
    engine: CUWEngine2026, controller: ControlCommPhase2026
) -> EngineWorker2026:
    """Engine-only factory; repeated issuance returns the same concrete worker."""
    from scripts.cuw_2026 import CUWEngine2026
    from scripts.programming_2026_common import ControlCommPhase2026

    if type(engine) is not CUWEngine2026:
        raise TypeError("Exact CUWEngine2026 owner required")
    if type(controller) is not ControlCommPhase2026:
        raise TypeError("Exact ControlCommPhase2026 owner required")
    _ = engine.native_metadata
    if engine.configuration is None:
        raise ValueError("Configure the engine before issuing its worker")
    with _ISSUE_LOCK:
        reference = _ISSUED.get(engine)
        existing = reference() if reference is not None else None
        if existing is not None:
            if existing.controller is not controller:
                raise ValueError("An engine worker cannot replace its controller")
            return existing
        carrier = engine._worker
        if carrier is not None:
            raise ValueError(
                "Actual native worker replacement is required for an existing carrier"
            )
        worker = EngineWorker2026(engine, controller, _token=_ISSUE_TOKEN)
        bound = getattr(controller, "worker", None)
        if bound is not None and bound is not worker:
            raise ValueError("ControlCommPhase already belongs to another worker")
        controller.worker = worker  # type: ignore[attr-defined]
        _ISSUED[engine] = weakref.ref(worker)
        return worker


def _replace_engine_worker(
    engine: CUWEngine2026,
    controller: ControlCommPhase2026,
    old_worker: EngineWorker2026,
) -> EngineWorker2026:
    """59070 constructs the next worker only after the previous child joined."""
    from scripts.cuw_2026 import CUWEngine2026
    from scripts.programming_2026_common import ControlCommPhase2026

    if (
        type(engine) is not CUWEngine2026
        or type(controller) is not ControlCommPhase2026
        or type(old_worker) is not EngineWorker2026
    ):
        raise TypeError("Concrete engine, controller, and previous worker required")
    with _replacement_engine_lock(engine), _ISSUE_LOCK:
        if engine.active:
            raise ValueError(
                "Finish the native child phase before replacing its worker"
            )
        if engine in _REPLACEMENTS:
            raise ValueError("Finish or roll back the pending worker replacement")
        if old_worker.engine is not engine or old_worker.controller is not controller:
            raise ValueError("Previous worker ownership differs")
        if (
            engine.worker is not old_worker
            or getattr(controller, "worker", None) is not old_worker
        ):
            raise ValueError("Previous worker is not the current issued worker")
        reference = _ISSUED.get(engine)
        if reference is None or reference() is not old_worker:
            raise ValueError("Previous worker issuance is no longer current")
        # Construct first: source-validation failure must leave the old lease usable.
        replacement = EngineWorker2026(engine, controller, _token=_ISSUE_TOKEN)
        replacement._inherit_engine_state(old_worker)
        handshake, lifecycle = (
            old_worker.native_prepare_handshake,
            old_worker.control_state.lifecycle,
        )
        old_worker.close()
        controller.worker = replacement  # type: ignore[attr-defined]
        _ISSUED[engine] = weakref.ref(replacement)
        engine._worker = replacement
        _REPLACEMENTS[engine] = (old_worker, replacement, handshake, lifecycle)
        return replacement


def _finalize_engine_worker_replacement(
    engine: CUWEngine2026,
    old_worker: EngineWorker2026,
    replacement: EngineWorker2026,
) -> None:
    """Forget the rollback checkpoint after all exact dependent owners rebound."""
    with _ISSUE_LOCK:
        checkpoint = _REPLACEMENTS.get(engine)
        if checkpoint is None or checkpoint[:2] != (old_worker, replacement):
            raise ValueError("Actual pending worker replacement required")
        if engine.worker is not replacement:
            raise ValueError("Replacement is not the engine's current worker")
        del _REPLACEMENTS[engine]


def _rollback_engine_worker_replacement(
    engine: CUWEngine2026,
    old_worker: EngineWorker2026,
    replacement: EngineWorker2026,
) -> None:
    """Restore the previous issued worker when a dependent-owner rebind fails."""
    with _replacement_engine_lock(engine), _ISSUE_LOCK:
        checkpoint = _REPLACEMENTS.get(engine)
        if checkpoint is None or checkpoint[:2] != (old_worker, replacement):
            raise ValueError("Actual pending worker replacement required")
        if engine.active or engine._worker is not replacement:
            raise ValueError("Inactive current replacement required for rollback")
        _, _, handshake, lifecycle = checkpoint
        replacement.close()
        with old_worker._lock:
            old_worker._closed = False
            old_worker._prepare_handshake = handshake
            old_worker._lifecycle = lifecycle
        controller = old_worker.controller
        controller.worker = old_worker  # type: ignore[attr-defined]
        _ISSUED[engine] = weakref.ref(old_worker)
        engine._worker = old_worker
        del _REPLACEMENTS[engine]


class EngineWorker2026:
    """One concrete 59070 worker and its multi-file continuation state."""

    def __init__(self, engine, controller, *, _token=None):
        from scripts.cuw_2026 import CUWEngine2026
        from scripts.programming_2026_common import ControlCommPhase2026

        if _token is not _ISSUE_TOKEN:
            raise TypeError("EngineWorker2026 must be issued by CUWEngine2026")
        if (
            type(engine) is not CUWEngine2026
            or type(controller) is not ControlCommPhase2026
        ):
            raise TypeError("Concrete engine and ControlCommPhase owners required")
        self._engine = engine
        self._controller = controller
        self._runtime = controller.runtime
        self._lock = threading.RLock()
        self._file_sources = engine.file_sources
        self._all_loaded_metadata = _loaded_metadata(engine)
        self._online_loaded_metadata = (
            self._all_loaded_metadata
            if self._file_sources is None
            else self._file_sources.files
        )
        self._current_file_index = self._find_current_file(engine.native_metadata)
        self._targets_by_file, self._cpu_orders_by_file = (
            self._build_selection_vectors()
        )
        self._authored_cpu_orders_by_file = self._cpu_orders_by_file
        self._unmatched_identifiers_by_file: tuple[tuple[bytes, ...], ...] = tuple(
            () for _ in self._all_loaded_metadata
        )
        self._unmatched_companions_by_file: tuple[tuple[bytes, ...], ...] = tuple(
            () for _ in self._all_loaded_metadata
        )
        self._authored_cpu_counts_by_file: tuple[int, ...] = (0,) * len(
            self._all_loaded_metadata
        )
        self._authored_target_indices_by_file = tuple(
            (-1,) * native2026_cpu_count(metadata)
            for metadata in self._all_loaded_metadata
        )
        self._selections_by_file: tuple[NativeCPUSelection2026 | None, ...] = (
            None,
        ) * len(self._all_loaded_metadata)
        self._cid_matches_by_file: tuple[NativeCIDMatch2026 | None, ...] = (
            None,
        ) * len(self._all_loaded_metadata)
        self._retained_clone_selection: NativeCPUSelection2026 | None = None
        self._selection_rebuild_pending: NativeCPUSelection2026 | None = None
        self._cid_rebuild_done_3542026 = False
        self._cid_selected_files: set[int] = set()
        current = engine.native_metadata
        self._current_node = current.node
        self._current_cpu_index = current.cpu_index
        actual_cpu_index = native2026_global_cpu_index(current)
        self._current_global_cpu_index = self._cpu_orders_by_file[
            self._current_file_index
        ].index(actual_cpu_index)
        persistence = getattr(engine, "persistence", None) or getattr(
            engine, "_persistence", None
        )
        loaded = bool(persistence is not None and persistence.state.loaded)
        self._cpu_offset = 0
        self._progress_base = 0
        self._retained_cpu_type = ""
        self._prepare_handshake = 0
        self._battery_voltage: float | None = None
        self._complete = False
        self._fatal = False
        self._native_fatal_input = False
        self._failed = False
        self._initial_command_retry = False
        self._ig_off_pending = False
        self._source_mode = 0
        self._vin = bytes(getattr(engine, "_vin", b""))
        self._recovery_ec9b = loaded
        self._recovery_ec9c = False
        self._lifecycle = "issued"
        configuration = engine.configuration
        assert configuration is not None
        maximum = configuration.cpu_maximum
        if (
            type(maximum) is not int
            or maximum < 0
            or engine.common_definitions.num_cpu_maxnum != maximum
            or len(configuration.cpu_flags) != maximum
            or len(configuration.source_cpu_flags) != 16
            or any(
                len(mask) != maximum or any(type(value) is not bool for value in mask)
                for mask in configuration.source_cpu_flags
            )
        ):
            raise ValueError("Configured native getter capacity is inconsistent")
        self._flow_file_index2026 = 0
        self._getter_sequence_changed_39c2026 = False
        self._getter_histories_a34_2026 = tuple(
            _NativeGetterHistory2026() for _ in range(16)
        )
        self._getter_flow_received_cids2026: tuple[tuple[bytes, ...], ...] = ((),) * 16
        self._getter_flow_query_records2026: tuple[tuple[bytes, ...], ...] = ((),) * 16
        self._getter_file_a48_received_cids2026: tuple[
            tuple[bytes, ...] | None, ...
        ] = (None,) * 16
        self._node_strings_4402026 = [b""] * maximum
        self._node_strings_4682026 = [b""] * maximum
        self._node_strings_4902026 = [b""] * maximum
        self._node_strings_4b82026 = [b""] * maximum
        self._cell_dword_bits_5542026 = [0] * (32 * maximum)
        self._cell_strings_5602026 = [b""] * (32 * maximum)
        self._getter_configured_masks_4f0_2026 = tuple(
            tuple(mask) for mask in configuration.source_cpu_flags
        )
        self._configured_bits_4e0_2026 = list(configuration.cpu_flags)
        self._retained_bits_5882026 = [False] * maximum
        self._node_dword_bits_1b9c2026 = [0] * maximum
        self._name_1ba8_2026 = b""
        self._name_1bc0_2026 = b""
        self._getter_ordinary_return_sequence2026 = 0
        self._getter_observation_sequence2026 = 0
        self._getter_last_observation2026: _NativeGetterObservation2026 | None = None
        self._issued_getter_continuation2026: _NativeGetterContinuation2026 | None = (
            None
        )
        self._getter_reset_epoch2026 = 0
        self._judge_invocation2026: _JudgeFlashableInvocation2026 | None = None
        self._file_wait_restore_origin2026: _NativeFileWaitRestoreOrigin2026 | None = (
            None
        )
        self._judge_wait_ready_marker2026: object | None = None
        self._frontend_selection_41940_point2026: (
            tuple[object, Native2026Metadata, int] | None
        ) = None
        self._ordinary_cpu_point2026: _NativeOrdinaryCPUPoint2026 | None = None
        self._ordinary_cpu_publication2026: (
            tuple[
                _NativeOrdinaryCPUPoint2026,
                Native2026Metadata,
                tuple[Native2026Metadata, ...],
                int,
                tuple[NativeCPUSelection2026 | None, ...],
                NativeCPUSelection2026 | None,
            ]
            | None
        ) = None
        self._ordinary_cid_point2026: _NativeOrdinaryCIDPoint2026 | None = None
        self._ordinary_cid_publication2026: (
            tuple[_NativeOrdinaryCIDPoint2026, object, dict[str, object]] | None
        ) = None
        self._judge_late_projection_point2026: (
            _NativeJudgeProjectionPoint2026 | None
        ) = None
        self._judge_pointer_publication2026: tuple[object, dict[str, object]] | None = (
            None
        )
        self._judge_reset_point2026: _NativeJudgeResetPoint2026 | None = None
        self._getter_authored_cpu_offset_a24_2026 = 0
        self._judge_file_selection_cache2026 = (_NativeJudgeSelectionCache2026(),) * 16
        self._getter_a48_received_cids2026: tuple[bytes, ...] = ()
        self._judge_file_unmatched_9fc2026: tuple[tuple[bytes, ...], ...] = ()
        self._judge_file_companions_a082026: tuple[tuple[bytes, ...], ...] = ()
        self._judge_file_counts_a142026: tuple[int, ...] = ()
        self._judge_a48_selection_by_file2026 = (_NativeJudgeSelectionCache2026(),) * 16
        self._judge_a48_match2026: NativeCIDMatch2026 | None = None
        self._judge_a48_matches_by_file2026: tuple[NativeCIDMatch2026 | None, ...] = (
            None,
        ) * 16
        self._judge_a48_selection2026 = _NativeJudgeSelectionCache2026()
        self._judge_live_selection2026 = _NativeJudgeSelectionCache2026()
        self._general_parameter_41940_2026 = None
        self._address_parameter_41940_2026 = None
        self._judge_projection_ordinal2026 = 0
        self._judge_projection_point2026: _NativeJudgeProjectionPoint2026 | None = None
        self._judge_projection_plan2026: tuple[tuple[str, object], ...] = ()
        self._judge_rows_buffer2026: list[bytes] | None = None
        self._judge_row_count_buffer2026: list[int] | None = None
        self._judge_boolean_buffer2026: list[bool] | None = None
        self._pending_judge_commit2026: _NativeJudgeCommitOrigin2026 | None = None
        self._consumed_judge_commit2026: _NativeJudgeCommitOrigin2026 | None = None
        self._imported_getter_output_ref2026 = None
        self._phase_started_ms: int | None = None
        self._control_file_capture: ControlFileCapture2026 | None = None
        # 59070 owns scratch independently from the engine's published vectors.
        control_state = engine.dh_state
        self._control_count_scratch2026 = [0] * len(control_state._transferred_bytes)
        self._control_percent_scratch2026 = list(control_state._progress)
        self._control_ssm_byte2026 = 0
        self._sbr_ssm_producer2026 = None
        self._control_return_receipt2026 = None
        self._control_scratch_reset_pending2026 = False
        self._phase_elapsed_ms = [0] * maximum
        self._continuation_sequence = 0
        self._pending_continuation: WorkerContinuation2026 | None = None
        self._delta_archive_active = engine.native_delta_active
        self._delta_archive_clone_match = bool(
            self._file_sources is not None
            and self._file_sources.current_is_retained_clone
        )
        self._gateway_startup = None
        self._cpu_percentages: list[int] = []
        self._closed = False

    def _inherit_engine_state(self, previous: EngineWorker2026) -> None:
        """Rebind59070 while preserving only the CUW-engine fields passed by pointer."""
        if (
            previous.engine is not self._engine
            or previous.controller is not self._controller
        ):
            raise ValueError("Previous worker ownership differs")
        with previous._lock, self._lock:
            previous.validate_source()
            if previous._pending_continuation is not None:
                raise ValueError(
                    "Consume the previous continuation before worker reissue"
                )
            if (
                previous._control_file_capture is not None
                or previous._control_return_receipt2026 is not None
                or previous._sbr_ssm_producer2026 is not None
                or previous._control_scratch_reset_pending2026
            ):
                raise ValueError("Retire pending CONTROL source work before reissue")
            self._file_sources = previous._file_sources
            self._all_loaded_metadata = previous._all_loaded_metadata
            self._online_loaded_metadata = previous._online_loaded_metadata
            self._current_file_index = previous._current_file_index
            self._targets_by_file = previous._targets_by_file
            self._cpu_orders_by_file = previous._cpu_orders_by_file
            self._authored_cpu_orders_by_file = previous._authored_cpu_orders_by_file
            self._unmatched_identifiers_by_file = (
                previous._unmatched_identifiers_by_file
            )
            self._unmatched_companions_by_file = previous._unmatched_companions_by_file
            self._authored_cpu_counts_by_file = previous._authored_cpu_counts_by_file
            self._authored_target_indices_by_file = (
                previous._authored_target_indices_by_file
            )
            self._selections_by_file = previous._selections_by_file
            self._cid_matches_by_file = previous._cid_matches_by_file
            self._retained_clone_selection = previous._retained_clone_selection
            self._selection_rebuild_pending = previous._selection_rebuild_pending
            self._cid_rebuild_done_3542026 = previous._cid_rebuild_done_3542026
            self._cid_selected_files = set(previous._cid_selected_files)
            self._current_node = previous._current_node
            self._current_cpu_index = previous._current_cpu_index
            self._current_global_cpu_index = previous._current_global_cpu_index
            self._cpu_offset = previous._cpu_offset
            self._progress_base = previous._progress_base
            self._retained_cpu_type = previous._retained_cpu_type
            self._battery_voltage = previous._battery_voltage
            self._complete = previous._complete
            self._ig_off_pending = self._engine.native_cycle_output
            self._recovery_ec9b = previous._recovery_ec9b
            self._recovery_ec9c = previous._recovery_ec9c
            self._phase_elapsed_ms = list(previous._phase_elapsed_ms)
            self._delta_archive_active = self._engine.native_delta_active
            self._delta_archive_clone_match = previous._delta_archive_clone_match
            self._gateway_startup = previous._gateway_startup
            self._flow_file_index2026 = previous._flow_file_index2026
            self._getter_sequence_changed_39c2026 = (
                previous._getter_sequence_changed_39c2026
            )
            self._getter_authored_cpu_offset_a24_2026 = (
                previous._getter_authored_cpu_offset_a24_2026
            )
            self._judge_file_selection_cache2026 = (
                previous._judge_file_selection_cache2026
            )
            self._getter_a48_received_cids2026 = previous._getter_a48_received_cids2026
            self._judge_file_unmatched_9fc2026 = previous._judge_file_unmatched_9fc2026
            self._judge_file_companions_a082026 = (
                previous._judge_file_companions_a082026
            )
            self._judge_file_counts_a142026 = previous._judge_file_counts_a142026
            self._judge_a48_selection_by_file2026 = (
                previous._judge_a48_selection_by_file2026
            )
            self._judge_a48_match2026 = previous._judge_a48_match2026
            self._judge_a48_matches_by_file2026 = (
                previous._judge_a48_matches_by_file2026
            )
            self._judge_a48_selection2026 = previous._judge_a48_selection2026
            self._judge_live_selection2026 = previous._judge_live_selection2026
            self._general_parameter_41940_2026 = previous._general_parameter_41940_2026
            self._address_parameter_41940_2026 = previous._address_parameter_41940_2026
            self._getter_histories_a34_2026 = previous._getter_histories_a34_2026
            self._getter_flow_received_cids2026 = tuple(
                tuple(values) for values in previous._getter_flow_received_cids2026
            )
            self._getter_flow_query_records2026 = tuple(
                tuple(values) for values in previous._getter_flow_query_records2026
            )
            self._getter_file_a48_received_cids2026 = tuple(
                None if values is None else tuple(values)
                for values in previous._getter_file_a48_received_cids2026
            )
            self._node_strings_4402026 = list(previous._node_strings_4402026)
            self._node_strings_4682026 = list(previous._node_strings_4682026)
            self._node_strings_4902026 = list(previous._node_strings_4902026)
            self._node_strings_4b82026 = list(previous._node_strings_4b82026)
            self._cell_dword_bits_5542026 = list(previous._cell_dword_bits_5542026)
            self._cell_strings_5602026 = list(previous._cell_strings_5602026)
            self._getter_configured_masks_4f0_2026 = tuple(
                tuple(mask) for mask in previous._getter_configured_masks_4f0_2026
            )
            self._configured_bits_4e0_2026 = list(previous._configured_bits_4e0_2026)
            self._retained_bits_5882026 = list(previous._retained_bits_5882026)
            self._node_dword_bits_1b9c2026 = list(previous._node_dword_bits_1b9c2026)
            self._name_1ba8_2026 = previous._name_1ba8_2026
            self._name_1bc0_2026 = previous._name_1bc0_2026
            self._getter_ordinary_return_sequence2026 = (
                previous._getter_ordinary_return_sequence2026
            )
            self._getter_observation_sequence2026 = (
                previous._getter_observation_sequence2026
            )
            self._getter_reset_epoch2026 = previous._getter_reset_epoch2026
            self._judge_invocation2026 = None
            self._pending_judge_commit2026 = None
            self._consumed_judge_commit2026 = None
            self._imported_getter_output_ref2026 = None

    def _query_seed34_2026(self) -> tuple[bytes, ...]:
        records = self._engine._working_identifier_records
        if len(records) != 34 or any(
            type(record) is not bytes or len(record) != 12 for record in records
        ):
            raise ValueError("Actual initialized34-record getter query seed required")
        return tuple(records)

    def _capture_pointer_view2026(self, metadata):
        sources = self._file_sources
        if sources is None:
            return None
        from scripts.cuw_file_services import (
            validate_file_sources_2026,
            validate_file_view_2026,
        )

        validate_file_sources_2026(sources, self._engine)
        if sources.has_file_vector:
            matches = tuple(
                index
                for index, item in enumerate(sources.files)
                if item.source_container is metadata.source_container
            )
            if len(matches) > 1:
                raise ValueError("Current pointer FILE is ambiguous in issued table")
            if matches:
                view = sources.file_view2026(matches[0])
            else:
                whole_views = tuple(
                    group.whole
                    for start, _width, whole in sources.delta_groups
                    if (group := sources.group_view2026(start)) is not None
                    and whole.source_container is metadata.source_container
                    and whole.source_sha256 == metadata.source_sha256
                )
                if len(whole_views) > 1:
                    raise ValueError("Current WHOLE pointer is ambiguous")
                view = whole_views[0] if whole_views else sources.admission_view2026()
        else:
            view = sources.admission_view2026()
        validate_file_view_2026(view, sources)
        if (
            view.source_container is not metadata.source_container
            or view.source_sha256 != metadata.source_sha256
        ):
            raise ValueError("Current pointer metadata differs from its issued view")
        return view

    def _capture_flow_view2026(self):
        sources = self._file_sources
        if sources is None:
            return None
        from scripts.cuw_file_services import (
            validate_file_sources_2026,
            validate_file_view_2026,
        )

        validate_file_sources_2026(sources, self._engine)
        if sources.has_file_vector:
            view = sources.file_view2026(self._flow_file_index2026)
        else:
            view = sources.admission_view2026()
        validate_file_view_2026(view, sources)
        return view

    def _capture_job_values2026(self):
        job = self._engine.thread_job
        if job is None:
            return None, None, None, None, None
        from scripts.cuw_engine_threads import (
            EngineThreadJob2026,
            ThreadPhaseLease2026,
            _CompletionRecord2026,
        )
        from scripts.programming_replay import ProgrammingReplay

        if type(job) is not EngineThreadJob2026 or job.worker is not self:
            raise ValueError("Current engine-thread owner differs from worker")
        if not job.is_child_thread:
            try:
                job.validate_callback_handoff()
            except (RuntimeError, TypeError, ValueError):
                return None, None, None, None, None
        lease = job._lease
        session = job._session
        completion = job._active_record
        if (
            type(lease) is not ThreadPhaseLease2026
            or type(session) is not ProgrammingReplay
            or type(completion) is not _CompletionRecord2026
            or completion is not job._completion_records.get(job._sequence)
            or completion.completed.is_set()
            or lease.state != "adopted"
        ):
            raise ValueError("Active native job capture lineage is incomplete")
        return job._sequence, lease, session, completion, job

    @property
    def engine(self) -> CUWEngine2026:
        return self._engine

    @property
    def controller(self) -> ControlCommPhase2026:
        return self._controller

    @property
    def runtime(self) -> NativeRuntime2026:
        return self._runtime

    @property
    def loaded_metadata(self) -> tuple[Native2026Metadata, ...]:
        with self._lock:
            self.validate_source()
            return self._loaded_metadata_view()

    @property
    def control_cpu_start(self) -> int:
        """Read-only ordered BC8 scalar copied into the source 59ab0 context."""
        with self._lock:
            self.validate_source()
            return self._current_global_cpu_index

    def capture_control_file2026(self, controller) -> ControlFileCapture2026:
        """Capture the held FILE only during the engine's once-only59ab0 import."""
        from scripts.cuw_2026 import CUWEngine2026
        from scripts.programming_2026_common import ControlCommPhase2026

        engine = self._engine
        with self._lock:
            if (
                type(controller) is not ControlCommPhase2026
                or controller is not self._controller
                or type(engine) is not CUWEngine2026
                or engine._worker is not self
                or getattr(engine, "_identifier_context_importing", False) is not True
                or not engine.active
                or engine._phase_thread != threading.get_ident()
                or engine.worker_phase not in (0, 1, 2)
                or self._phase_started_ms is None
                or self._lifecycle != "running"
                or self._control_file_capture is not None
                or controller.runtime is not self._runtime
            ):
                raise ValueError("Actual once-only owned 59ab0 CONTROL import required")
            file_index = self._current_file_index
            if not 0 <= file_index < len(self._all_loaded_metadata):
                raise ValueError("Current worker FILE is outside the issued vector")
            metadata = engine.native_metadata
            issued_file = self._all_loaded_metadata[file_index]
            if metadata.source_container is not issued_file.source_container:
                raise ValueError(
                    "Current engine FILE differs from the issued worker FILE"
                )
            native_order = tuple(self._cpu_orders_by_file[file_index])
            target_indices = tuple(self._targets_by_file[file_index])
            control_cpu_start = self._current_global_cpu_index
            if (
                not native_order
                or len(native_order) != len(target_indices)
                or len(set(native_order)) != len(native_order)
                or any(
                    type(value) is not int
                    or not 0 <= value < native2026_cpu_count(metadata)
                    for value in native_order
                )
                or any(type(value) is not int for value in target_indices)
                or type(control_cpu_start) is not int
                or not 0 <= control_cpu_start < len(native_order)
            ):
                raise ValueError("Ordered CONTROL FILE vectors are inconsistent")
            if (
                native2026_metadata_for_cpu(metadata, native_order[control_cpu_start])
                != metadata
            ):
                raise ValueError("BC8 start CPU differs from the held FILE mapping")
            configuration = engine.configuration
            if configuration is None:
                raise ValueError("Configured native getter context required")
            if len(self._configured_bits_4e0_2026) != configuration.cpu_maximum:
                raise ValueError("Native configured getter bitset capacity changed")
            job_values = self._capture_job_values2026()
            capture = ControlFileCapture2026(
                weakref.ref(self),
                engine,
                controller,
                self._runtime,
                metadata,
                native_order,
                target_indices,
                control_cpu_start,
                engine.worker_phase,
                threading.get_ident(),
                job_values[4],
                engine._identifier_context_epoch,
                self._file_sources,
                self._capture_pointer_view2026(metadata),
                self._capture_flow_view2026(),
                self._flow_file_index2026,
                configuration,
                self._query_seed34_2026(),
                tuple(self._configured_bits_4e0_2026),
                self._getter_sequence_changed_39c2026,
                job_values[0],
                job_values[1],
                job_values[2],
                job_values[3],
            )
            self._control_file_capture = capture
            return capture

    def _invalidate_control_file_capture2026(self) -> None:
        self._control_file_capture = None
        self._sbr_ssm_producer2026 = None
        self._control_return_receipt2026 = None
        self._imported_getter_output_ref2026 = None

    def _validate_control_output_context2026(self, context):
        """Validate shared CONTROL capability before any scratch/output access."""
        from scripts.programming_2026_common import NativeControlContext2026

        if type(context) is not NativeControlContext2026:
            raise TypeError("Exact source-issued CONTROL context required")
        context.validate(self._engine, self._controller)
        if (
            context._worker is not self
            or context._runtime is not self._runtime
            or context._capture is not self._control_file_capture
        ):
            raise ValueError("CONTROL output context differs from worker lineage")
        return context

    def _control_progress_scratch2026(self, context):
        """Return immutable observations of the worker-owned CONTROL vectors."""
        with self._lock:
            self._validate_control_output_context2026(context)
            state = self._engine.dh_state
            if len(self._control_count_scratch2026) != len(
                state._transferred_bytes
            ) or len(self._control_percent_scratch2026) != len(state._progress):
                raise ValueError("CONTROL output vector length changed while issued")
            return (
                tuple(self._control_count_scratch2026),
                tuple(self._control_percent_scratch2026),
            )

    @property
    def _previous_percentages2026(self) -> tuple[int, ...]:
        """Expose C48/C4C through its existing source-owned worker vector."""
        return tuple(self._cpu_percentages)

    def _store_control_output2026(self, context, target, index, value, *, percent):
        from scripts.programming_2026_common import NativeControlExportTarget2026

        with self._lock:
            self._validate_control_output_context2026(context)
            if (
                type(target) is not NativeControlExportTarget2026
                or target._context is not context
                or self._engine._controller_export_target2026 is not target
            ):
                raise ValueError("Active source-issued CONTROL target required")
            target.validate(self._engine, self._controller)
            scratch = (
                self._control_percent_scratch2026
                if percent
                else self._control_count_scratch2026
            )
            if type(index) is not int or not 0 <= index < len(scratch):
                raise ValueError("CONTROL output index is outside its fixed vector")
            if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
                raise ValueError("CONTROL output value must be an unsigned DWORD")
            scratch[index] = value

    def _store_control_count2026(self, context, target, index, value) -> None:
        self._store_control_output2026(context, target, index, value, percent=False)

    def _store_control_percentage2026(self, context, target, index, value) -> None:
        self._store_control_output2026(context, target, index, value, percent=True)

    def publish_control_count2026(self, context) -> None:
        with self._lock:
            self._validate_control_output_context2026(context)
            state = self._engine.dh_state
            if len(state._transferred_bytes) != len(self._control_count_scratch2026):
                raise ValueError("CONTROL count output vector length changed")
            state._transferred_bytes = tuple(self._control_count_scratch2026)

    def publish_control_percent2026(self, context) -> None:
        with self._lock:
            self._validate_control_output_context2026(context)
            state = self._engine.dh_state
            if len(state._progress) != len(self._control_percent_scratch2026):
                raise ValueError("CONTROL percentage output vector length changed")
            previous = tuple(state._progress)
            self._cpu_percentages = list(previous)
            state._progress = tuple(self._control_percent_scratch2026)

    def _loaded_metadata_view(self) -> tuple[Native2026Metadata, ...]:
        """Expose the live current FILE while retaining the issued FILE vector."""
        if not self._all_loaded_metadata:
            return ()
        current = self._engine.native_metadata
        loaded = self._all_loaded_metadata[self._current_file_index]
        if loaded.source_container is not current.source_container:
            raise ValueError("Engine source differs from the current issued FILE")
        result = list(self._all_loaded_metadata)
        result[self._current_file_index] = current
        return tuple(result)

    def _online_metadata_view(self) -> tuple[Native2026Metadata, ...]:
        """Expose the live current FILE only when it is in native table+5ec."""
        if not self._online_loaded_metadata:
            return ()
        current = self._engine.native_metadata
        return tuple(
            current if item.source_container is current.source_container else item
            for item in self._online_loaded_metadata
        )

    def metadata_for_native_cpu(self, index: int) -> Native2026Metadata:
        """Map an ordered engine+358 index to its authenticated CPU metadata."""
        if type(index) is not int:
            raise TypeError("Native ordered CPU index required")
        with self._lock:
            self.validate_source()
            order = self._cpu_orders_by_file[self._current_file_index]
            if not 0 <= index < len(order):
                raise ValueError("Native ordered CPU index is outside the current FILE")
            return native2026_metadata_for_cpu(
                self._all_loaded_metadata[self._current_file_index], order[index]
            )

    def native_index_for_source_cpu(self, index: int) -> int:
        """Map an authored/logical CPU index to the ordered engine+358 index."""
        if type(index) is not int:
            raise TypeError("Authored source CPU index required")
        with self._lock:
            self.validate_source()
            order = self._authored_cpu_orders_by_file[self._current_file_index]
            try:
                return order.index(index)
            except ValueError as error:
                raise ValueError(
                    "Authored source CPU is absent from the native CPU order"
                ) from error

    @property
    def persist_current_cpu(self) -> bool:
        """3ec30/3f620 DATdab4/clone gate for the normal issued CUW path."""
        return not self._delta_archive_active or self._delta_archive_clone_match

    def validate_source(self, engine=None) -> None:
        if self._closed:
            raise ValueError("Engine worker is closed")
        if engine is not None and engine is not self._engine:
            raise ValueError("Worker belongs to another CUW engine")
        if self._controller.runtime is not self._runtime:
            raise ValueError("Worker runtime ownership changed")
        metadata = self._engine.native_metadata
        issued = self._all_loaded_metadata
        if self._file_sources is not None:
            issued = (
                *issued,
                *self._file_sources.files,
                *(whole for _start, _width, whole in self._file_sources.delta_groups),
                *(
                    (self._file_sources.auxiliary_metadata,)
                    if self._file_sources.auxiliary_metadata is not None
                    else ()
                ),
            )
        if not any(
            item.source_container is metadata.source_container for item in issued
        ):
            raise ValueError("Engine source is outside the issued FILE vector")

    def _target_selected(self, metadata: Native2026Metadata) -> None:
        """Synchronize an engine-authorized target selection into worker fields."""
        if type(metadata) is not Native2026Metadata:
            raise TypeError("Concrete native target metadata required")
        with self._lock:
            self.validate_source()
            matches = [
                index
                for index, loaded in enumerate(self._all_loaded_metadata)
                if loaded.source_container is metadata.source_container
            ]
            if not matches and self._file_sources is not None:
                matches = [
                    index
                    for index, loaded in enumerate(self._file_sources.files)
                    if loaded.source_container is metadata.source_container
                ]
            if len(matches) != 1:
                raise ValueError("Selected target must identify one loaded FILE")
            file_index = matches[0]
            changed_file = file_index != self._current_file_index
            changed_source = (
                self._all_loaded_metadata[file_index].source_container
                is not metadata.source_container
            )
            if changed_source:
                loaded = list(self._all_loaded_metadata)
                loaded[file_index] = metadata
                self._all_loaded_metadata = tuple(loaded)
                targets = list(self._targets_by_file)
                orders = list(self._cpu_orders_by_file)
                targets[file_index], orders[file_index] = _unresolved_selection(
                    metadata
                )
                self._targets_by_file = tuple(targets)
                self._cpu_orders_by_file = tuple(orders)
                authored = list(self._authored_cpu_orders_by_file)
                authored[file_index] = orders[file_index]
                self._authored_cpu_orders_by_file = tuple(authored)
                unmatched = list(self._unmatched_identifiers_by_file)
                companions = list(self._unmatched_companions_by_file)
                counts = list(self._authored_cpu_counts_by_file)
                authored_targets = list(self._authored_target_indices_by_file)
                unmatched[file_index] = ()
                companions[file_index] = ()
                counts[file_index] = 0
                authored_targets[file_index] = (-1,) * native2026_cpu_count(metadata)
                self._unmatched_identifiers_by_file = tuple(unmatched)
                self._unmatched_companions_by_file = tuple(companions)
                self._authored_cpu_counts_by_file = tuple(counts)
                self._authored_target_indices_by_file = tuple(authored_targets)
                selections = list(self._selections_by_file)
                selections[file_index] = None
                self._selections_by_file = tuple(selections)
                self._cid_selected_files.discard(file_index)
            self._current_file_index = file_index
            self._current_node = metadata.node
            self._current_cpu_index = metadata.cpu_index
            actual_cpu_index = native2026_global_cpu_index(metadata)
            self._current_global_cpu_index = self._cpu_orders_by_file[file_index].index(
                actual_cpu_index
            )
            if changed_file:
                self._cpu_offset = 0
            if self._file_sources is not None and self._delta_archive_active:
                retained = self._file_sources.auxiliary_metadata
                self._delta_archive_clone_match = bool(
                    retained is not None
                    and retained.source_container is metadata.source_container
                )

    def _find_current_file(self, metadata: Native2026Metadata) -> int:
        matches = [
            index
            for index, item in enumerate(self._all_loaded_metadata)
            if item.source_container is metadata.source_container
        ]
        if len(matches) != 1:
            raise ValueError("Current source must identify one loaded FILE")
        return matches[0]

    def _identifiers_for_file(self, index: int) -> tuple[bytes, ...]:
        if index == self._current_file_index and self._engine.received_identifiers:
            return self._engine.received_identifiers
        if self._file_sources is not None:
            return ()
        persistence = getattr(self._engine, "persistence", None) or getattr(
            self._engine, "_persistence", None
        )
        if persistence is None:
            return ()
        values = persistence.state.calibrations[index].cids
        try:
            return tuple(value.encode("latin1") for value in values)
        except UnicodeError as error:
            raise ValueError("Recovery CID is not a native byte string") from error

    def _build_selection_vectors(
        self,
    ) -> tuple[tuple[tuple[int, ...], ...], tuple[tuple[int, ...], ...]]:
        selections = tuple(
            _unresolved_selection(metadata) for metadata in self._all_loaded_metadata
        )
        return (
            tuple(targets for targets, _ in selections),
            tuple(order for _, order in selections),
        )

    def refresh_target_selection(self) -> None:
        """Reject the old host refresh seam; native CID completion owns selection."""
        with self._lock:
            self.validate_source()
            if self._current_file_index in self._cid_selected_files:
                return
            raise ValueError("Target selection requires owned native CID completion")

    @property
    def native_writer_target_index(self) -> int:
        with self._lock:
            if self._current_file_index not in self._cid_selected_files:
                raise ValueError("Current FILE has no completed native CID selection")
            targets = self._targets_by_file[self._current_file_index]
            if not 0 <= self._current_global_cpu_index < len(targets):
                raise ValueError("Current native CPU has no target-vector slot")
            result = targets[self._current_global_cpu_index]
            if result < 0:
                raise ValueError("Current native CPU has no source target")
            return result

    @property
    def native_initial_command_retry(self) -> bool:
        return self._initial_command_retry

    @property
    def native_initial_command_retry980(self) -> bool:
        return self.native_initial_command_retry

    @property
    def native_getter_cpu_type(self) -> str:
        if not self._retained_cpu_type:
            raise ValueError("First native CPU type is empty")
        return self._retained_cpu_type

    def _validate_ordinary_output_point_36800_2026(
        self, origin, started_ms: int
    ) -> None:
        job = self._engine.thread_job
        if job is None or job.worker is not self:
            raise ValueError("Actual ordinary36800 worker required")
        job._validate_ordinary_prepare_origin_36800_2026(origin)
        if (
            origin.progress != "clock"
            or type(started_ms) is not int
            or not 0 <= started_ms < 86_400_000
            or origin.started_ms != started_ms
        ):
            raise ValueError("Actual ordinary36800 clock point required")

    def _validate_ordinary_recovery_point_36800_2026(self, origin) -> None:
        job = self._engine.thread_job
        if job is None or job.worker is not self:
            raise ValueError("Actual ordinary36800 worker required")
        job._validate_ordinary_prepare_origin_36800_2026(origin)
        if origin.progress != "recovery" or not self.control_state.recovery_mode:
            raise ValueError("Actual ordinary36800 recovery branch required")

    @staticmethod
    def _ordinary_file_metadata_for_cursor_3e710_2026(
        metadata: Native2026Metadata, cursor: int
    ) -> Native2026Metadata:
        """Keep a reached FILE write even when D308 no longer names a CPU row."""
        from scripts.calibration_2026 import native2026_validate_runtime_metadata

        native2026_validate_runtime_metadata(metadata)
        if type(cursor) is not int or not 0 <= cursor <= 0xFFFFFFFF:
            raise ValueError("Native unsigned D308 required")
        if cursor < native2026_cpu_count(metadata):
            return native2026_metadata_for_cpu(metadata, cursor)
        return metadata

    @staticmethod
    def _ordinary_is_logical_cpu_19710_2026(
        metadata: Native2026Metadata, cursor: int
    ) -> bool:
        from scripts.calibration_2026 import (
            native2026_is_logical_cpu,
            native2026_validate_runtime_metadata,
        )

        native2026_validate_runtime_metadata(metadata)
        # 19710 checks contact before reaching its CPU-dependent node getter.
        if metadata.vehicle.get("contacttype", "") not in (
            "P5-Unified",
            "Phase6",
            "Ethernet",
        ):
            return False
        return native2026_is_logical_cpu(metadata, cursor)

    def _validate_ordinary_cpu_point_36800_2026(
        self, origin, index: int
    ) -> tuple[Native2026Metadata, int]:
        job = self._engine.thread_job
        if job is None or job.worker is not self:
            raise ValueError("Actual ordinary36800 worker required")
        job._validate_ordinary_prepare_origin_36800_2026(origin)
        point = self._ordinary_cpu_point2026
        if (
            type(point) is not _NativeOrdinaryCPUPoint2026
            or point.origin is not origin
            or point.thread_id != threading.get_ident()
            or point.metadata is not self._engine.native_metadata
            or point.before != self._current_global_cpu_index
            or type(index) is not int
            or point.after != index
            or (
                point.site in ("recovery_ec94", "first_19710")
                and origin.progress != "recovery"
            )
            or (
                point.site in ("shared_offset", "second_19710")
                and origin.progress != "cid"
            )
        ):
            raise ValueError("Exact reached ordinary36800 CPU store required")
        if point.site == "recovery_ec94":
            persistence = self._engine.persistence
            if (
                not self.control_state.recovery_mode
                or persistence is None
                or index != persistence.state.write_cpu_index
            ):
                raise ValueError("Ordinary recovery CPU differs from live EC94")
        elif point.site == "shared_offset":
            if point.before != 0 or index != self._cpu_offset:
                raise ValueError("Ordinary shared CPU differs from zero-to-D30C")
        else:
            if (
                point.site == "first_19710" and not self.control_state.recovery_mode
            ) or not self._ordinary_is_logical_cpu_19710_2026(
                point.metadata, point.before
            ):
                raise ValueError("Actual ordinary19710 predicate required")
            selected = native2026_metadata_for_cpu(point.metadata, point.before)
            if (
                not selected.logical_blocks
                or index != selected.logical_blocks[0].cpu_index
            ):
                raise ValueError("Ordinary CPU differs from first image descriptor700")
        return point.metadata, point.before

    def _prepare_ordinary_cpu_mirror_36800_2026(
        self, origin, metadata: Native2026Metadata, index: int
    ) -> None:
        previous, _before = self._validate_ordinary_cpu_point_36800_2026(origin, index)
        if (
            self._ordinary_cpu_publication2026 is not None
            or type(metadata) is not Native2026Metadata
            or metadata.source_container is not previous.source_container
            or metadata
            != self._ordinary_file_metadata_for_cursor_3e710_2026(previous, index)
        ):
            raise ValueError("Exact ordinary36800 CPU mirror projection required")
        point = self._ordinary_cpu_point2026
        assert point is not None
        loaded = list(self._all_loaded_metadata)
        loaded[self._current_file_index] = metadata
        # Complete precedes the shared D308 store. Carry its immutable FILE
        # cache through this exact canonical CPU projection, not a later47e60
        # identity exception or an arbitrary same-source rebind.
        selections = list(self._selections_by_file)
        selection = selections[self._current_file_index]
        successor = (
            replace(selection, rebuilt_metadata=metadata)
            if selection is not None and selection.rebuilt_metadata is previous
            else selection
        )
        selections[self._current_file_index] = successor
        retained = self._retained_clone_selection
        if retained is selection:
            retained = successor
        elif (
            retained is not None
            and self._delta_archive_active
            and self._delta_archive_clone_match
            and retained.rebuilt_metadata is previous
        ):
            retained = replace(retained, rebuilt_metadata=metadata)
        self._ordinary_cpu_publication2026 = (
            point,
            metadata,
            tuple(loaded),
            index,
            tuple(selections),
            retained,
        )

    def _publish_ordinary_cpu_mirror_36800_2026(self, origin) -> None:
        """Assign only the tuple authenticated before36's literal CPU store."""
        publication = self._ordinary_cpu_publication2026
        if (
            publication is None
            or publication[0] is not self._ordinary_cpu_point2026
            or publication[0].origin is not origin
        ):
            raise ValueError("Exact precomputed ordinary36800 CPU mirror required")
        _point, metadata, loaded, index, selections, retained = publication
        self._ordinary_cpu_publication2026 = None
        self._all_loaded_metadata = loaded
        self._selections_by_file = selections
        self._retained_clone_selection = retained
        self._current_global_cpu_index = index
        if index < native2026_cpu_count(metadata):
            self._current_node = metadata.node
            self._current_cpu_index = metadata.cpu_index

    def _publish_ordinary_cpu_36800_2026(
        self,
        origin,
        index: int,
        site: Literal["recovery_ec94", "first_19710", "shared_offset", "second_19710"],
    ) -> None:
        if self._ordinary_cpu_point2026 is not None:
            raise ValueError("An ordinary36800 CPU store is already pending")
        point = _NativeOrdinaryCPUPoint2026(
            origin,
            self._engine.native_metadata,
            self._current_global_cpu_index,
            index,
            site,
            threading.get_ident(),
            self._current_node,
            self._current_cpu_index,
        )
        self._ordinary_cpu_point2026 = point
        try:
            self._validate_ordinary_cpu_point_36800_2026(origin, index)
            self._engine._publish_ordinary_cpu_36800_2026(
                origin, worker=self, cpu_index=index
            )
        finally:
            publication = self._ordinary_cpu_publication2026
            if publication is not None and publication[0] is point:
                self._ordinary_cpu_publication2026 = None
            if self._ordinary_cpu_point2026 is point:
                self._ordinary_cpu_point2026 = None

    def _apply_ordinary_prepare_36800_2026(self, *, origin) -> None:
        """Execute36800 before145 reserves a record or adopts the child phase."""
        from scripts.calibration_2026 import (
            native2026_cid_rebuild_allowed,
        )

        job = self._engine.thread_job
        if job is None or job.worker is not self:
            raise ValueError("Actual ordinary36800 start origin required")
        job._validate_ordinary_prepare_origin_36800_2026(origin)
        with self._lock:
            if origin.progress != "issued":
                raise ValueError("Fresh ordinary36800 source body required")
            self._retain_first_cpu_type_36800_2026()
            job._advance_ordinary_prepare_origin2026(origin, "retained_type")
            sources = self._file_sources
            if (
                sources is not None
                and any(sources.table_file_names)
                and self.control_state.recovery_mode
            ):
                device = self._engine.engine_runtime_device()
                contact = self._engine.native_metadata.vehicle.get("contacttype", "")
                wanted = (
                    1
                    if contact == "Ethernet"
                    else 0
                    if contact in ("P5-Unified", "Phase6")
                    else None
                )
                if wanted is not None and device.version != wanted:
                    device.switch_version()
            job._advance_ordinary_prepare_origin2026(origin, "device")
            self._runtime.check()
            started = self._runtime.read_local_milliseconds_of_day()
            if type(started) is not int or not 0 <= started < 86_400_000:
                raise ValueError("Native local milliseconds within day required")
            origin.started_ms = started
            job._advance_ordinary_prepare_origin2026(origin, "clock")
            self._engine._initialize_ordinary_prepare_outputs_36800_2026(
                origin, worker=self, started_ms=started
            )
            job._advance_ordinary_prepare_origin2026(origin, "outputs")
            job._advance_ordinary_prepare_origin2026(origin, "phase")
            if not self.control_state.recovery_mode and self._prepare_handshake == 1:
                self._prepare_handshake = 3
                job._advance_ordinary_prepare_origin2026(origin, "early_return")
                return
            job._advance_ordinary_prepare_origin2026(origin, "branch")
            if self.control_state.recovery_mode:
                job._advance_ordinary_prepare_origin2026(origin, "recovery")
                captured_cpu = self._engine._begin_ordinary_recovery_36800_2026(
                    origin, worker=self
                )
                self._publish_ordinary_cpu_36800_2026(
                    origin, captured_cpu, "recovery_ec94"
                )
                metadata = self._engine.native_metadata
                if self._ordinary_is_logical_cpu_19710_2026(metadata, captured_cpu):
                    selected = native2026_metadata_for_cpu(metadata, captured_cpu)
                    self._publish_ordinary_cpu_36800_2026(
                        origin, selected.logical_blocks[0].cpu_index, "first_19710"
                    )
                self._engine._finish_ordinary_recovery_36800_2026(origin, worker=self)
            else:
                job._advance_ordinary_prepare_origin2026(origin, "nonrecovery")
                if ".vbf" in native2026_cpu_values(self._engine.native_metadata, 0).get(
                    "cpuimagename", ""
                ):
                    self._prepare_handshake = 1
            if (
                native2026_cid_rebuild_allowed(self._engine.native_metadata)
                and not self._cid_rebuild_done_3542026
            ):
                self._apply_ordinary_cid_rebuild_3e710_2026(origin)
            job._advance_ordinary_prepare_origin2026(origin, "cid")
            if self._current_global_cpu_index == 0:
                self._publish_ordinary_cpu_36800_2026(
                    origin, self._cpu_offset, "shared_offset"
                )
            metadata = self._engine.native_metadata
            current = self._current_global_cpu_index
            if self._ordinary_is_logical_cpu_19710_2026(metadata, current):
                selected = native2026_metadata_for_cpu(metadata, current)
                self._publish_ordinary_cpu_36800_2026(
                    origin, selected.logical_blocks[0].cpu_index, "second_19710"
                )
            job._advance_ordinary_prepare_origin2026(origin, "cpu_tail")
            job._advance_ordinary_prepare_origin2026(origin, "prepared")

    def _retain_first_cpu_type_36800_2026(self) -> None:
        self._engine._require_native_prepare_prefix(self)
        if not self._retained_cpu_type:
            self._retained_cpu_type = native2026_cpu_type(
                self._engine.native_metadata, 0
            )

    def _initialize_36800_prefix(self, milliseconds: int) -> None:
        """Run the clock/output prefix that precedes36800's be8 early return."""
        if type(milliseconds) is not int or not 0 <= milliseconds < 86_400_000:
            raise ValueError("Native local milliseconds within day required")
        self._engine._require_native_prepare_prefix(self)
        self._retain_first_cpu_type_36800_2026()
        self._engine._initialize_native_prepare_outputs(
            worker=self, started_ms=milliseconds
        )

    def _initialize_36800(self, milliseconds: int) -> None:
        """Run the normal36800 prefix and source-gated3e710 continuation."""
        self._initialize_36800_prefix(milliseconds)
        self._apply_pending_cid_match_3e710()
        self._reapply_retained_selection_3e710()

    def _acknowledge_vbf_process_before2026(self, job, request) -> bool:
        """Publish the actual VBF1→2 handshake and its wait requirement."""
        from scripts.cuw_engine_threads import (
            EngineThreadJob2026,
            validate_vbf_process_before2026,
        )

        if type(job) is not EngineThreadJob2026:
            raise TypeError("Actual issued native thread job required")
        job.validate_owner(self._engine, self._controller)
        validate_vbf_process_before2026(request, job, states=("issued",))
        job._validate_vbf_issuer2026(request)
        with self._lock:
            self.validate_source(self._engine)
            if self.control_state.recovery_mode:
                raise ValueError("Recovery-mode VBF phase resume is unsupported")
            if (
                native2026_cpu_values(self._engine.native_metadata, 0)
                .get("cpuimagename", "")
                .find(".vbf")
                == -1
            ):
                raise ValueError("Actual first-CPU VBF source required")
            if self._prepare_handshake == 1:
                wait_required = True
                self._prepare_handshake = 2
            else:
                if not job._child_parked.is_set():
                    raise ValueError(
                        "Non-handshake VBF admission requires parked child"
                    )
                wait_required = False
        job._record_vbf_acknowledgement2026(request, wait_required=wait_required)
        return wait_required

    def _prepare_vbf_resume2026(self, job, request):
        """Run36800's prepared VBF entry after the actual child has parked."""
        from scripts.cuw_engine_threads import (
            EngineThreadJob2026,
            validate_vbf_process_before2026,
        )
        from scripts.cuw_file_services import validate_file_sources_2026

        if type(job) is not EngineThreadJob2026:
            raise TypeError("Actual issued native thread job required")
        job.validate_owner(self._engine, self._controller)
        validate_vbf_process_before2026(request, job, states=("parked",))
        job._validate_vbf_issuer2026(request)
        with self._lock:
            self.validate_source(self._engine)
            if self.control_state.recovery_mode:
                raise ValueError("Recovery-mode VBF phase resume is unsupported")
            self._engine._require_native_prepare_prefix(self)
            self._engine._validate_persistence_source(self._engine.native_metadata)
            if self._engine.file_sources is not None:
                validate_file_sources_2026(self._engine.file_sources, self._engine)
            self._retain_first_cpu_type_36800_2026()
            self._runtime.check()
            started = self._runtime.read_local_milliseconds_of_day()
            self._initialize_36800_prefix(started)
            self._prepare_handshake = 1
            self._reapply_retained_selection_3e710()
        return job._record_vbf_prepared2026(request, started_ms=started)

    def _validate_ordinary_cid_point_3e710_2026(self, origin, step) -> None:
        from scripts.calibration_2026 import native2026_cid_rebuild_allowed

        job = self._engine.thread_job
        if job is None or job.worker is not self:
            raise ValueError("Actual ordinary3e710 job required")
        job._validate_ordinary_prepare_origin_36800_2026(origin)
        point = self._ordinary_cid_point2026
        if (
            type(point) is not _NativeOrdinaryCIDPoint2026
            or point.origin is not origin
            or point.step is not step
            or step is None
            or point.metadata is not self._engine.native_metadata
            or point.thread_id != threading.get_ident()
            or origin.progress not in ("recovery", "nonrecovery")
            or self._cid_rebuild_done_3542026
            or not native2026_cid_rebuild_allowed(point.entry_metadata)
            or point.entry_metadata.source_container
            is not point.metadata.source_container
        ):
            raise ValueError("Exact current ordinary3e710 iterator step required")

    def _prepare_ordinary_cid_mirror_3e710_2026(
        self, origin, step, metadata: Native2026Metadata
    ) -> None:
        from scripts.calibration_2026 import NativeCIDRebuildMetadata2026

        self._validate_ordinary_cid_point_3e710_2026(origin, step)
        point = self._ordinary_cid_point2026
        assert point is not None
        if (
            self._ordinary_cid_publication2026 is not None
            or type(step) is not NativeCIDRebuildMetadata2026
            or type(metadata) is not Native2026Metadata
            or metadata.source_container is not point.metadata.source_container
            or metadata
            != self._ordinary_file_metadata_for_cursor_3e710_2026(
                step.metadata, self._current_global_cpu_index
            )
        ):
            raise ValueError("Exact current ordinary3e710 metadata step required")
        loaded = list(self._all_loaded_metadata)
        loaded[self._current_file_index] = metadata
        publication: dict[str, object] = {
            "_all_loaded_metadata": tuple(loaded),
        }
        if self._current_global_cpu_index < native2026_cpu_count(metadata):
            publication["_current_node"] = metadata.node
            publication["_current_cpu_index"] = metadata.cpu_index
        self._ordinary_cid_publication2026 = (point, step, publication)

    def _publish_ordinary_cid_mirror_3e710_2026(self, origin) -> None:
        """Assign the authenticated current metadata step in36's commit tail."""
        publication = self._ordinary_cid_publication2026
        point = self._ordinary_cid_point2026
        if (
            publication is None
            or point is None
            or publication[0] is not point
            or publication[1] is not point.step
            or point.origin is not origin
        ):
            raise ValueError("Exact precomputed ordinary3e710 mirror required")
        self._ordinary_cid_publication2026 = None
        for name, value in publication[2].items():
            setattr(self, name, value)

    def _store_ordinary_rebuild_targets_3e710_2026(
        self, targets: tuple[int, ...]
    ) -> None:
        self._judge_live_selection2026 = replace(
            self._judge_live_selection2026, targets=targets
        )
        values = list(self._targets_by_file)
        values[self._current_file_index] = targets[
            : native2026_cpu_count(self._engine.native_metadata)
        ]
        self._targets_by_file = tuple(values)

    def _apply_ordinary_cid_rebuild_3e710_2026(self, origin) -> None:
        from scripts.calibration_2026 import (
            NativeCIDRebuildComplete2026,
            NativeCIDRebuildMetadata2026,
            NativeCIDRebuildOffset2026,
            NativeCIDRebuildTargets2026,
            NativeCIDRebuildTargetStore2026,
            native2026_cid_rebuild_allowed,
            native2026_rebuild_current_cids_steps,
        )

        job = self._engine.thread_job
        if job is None or job.worker is not self:
            raise ValueError("Actual ordinary3e710 job required")
        job._validate_ordinary_prepare_origin_36800_2026(origin)
        if self._cid_rebuild_done_3542026:
            return
        if (
            self._ordinary_cid_point2026 is not None
            or origin.progress not in ("recovery", "nonrecovery")
            or not native2026_cid_rebuild_allowed(self._engine.native_metadata)
        ):
            raise ValueError("Exact reached ordinary3e710 source body required")
        configuration = self._engine.configuration
        if configuration is None:
            raise ValueError("Actual configured3e710 capacity required")
        maximum = configuration.cpu_maximum
        live = self._judge_live_selection2026
        iterator = native2026_rebuild_current_cids_steps(
            self._engine.native_metadata,
            live.targets,
            live.unmatched_ids,
            live.unmatched_companions,
            self._engine._general_parameters,
            configuration=configuration,
        )
        point = _NativeOrdinaryCIDPoint2026(
            origin,
            iterator,
            self._engine.native_metadata,
            self._engine.native_metadata,
            threading.get_ident(),
            self._current_node,
            self._current_cpu_index,
        )
        self._ordinary_cid_point2026 = point
        complete = False
        try:
            for step in iterator:
                if complete:
                    raise ValueError("Native3e710 emitted a step after completion")
                point.before_node = self._current_node
                point.before_cpu_index = self._current_cpu_index
                point.step = step
                self._validate_ordinary_cid_point_3e710_2026(origin, step)
                if type(step) is NativeCIDRebuildOffset2026:
                    if type(step.value) is not int or not 0 <= step.value <= maximum:
                        raise ValueError("Bounded source D30C required")
                    self._cpu_offset = step.value
                elif type(step) is NativeCIDRebuildTargets2026:
                    if len(step.indices) != maximum:
                        raise ValueError("Exact M source D2A4 target vector required")
                    self._store_ordinary_rebuild_targets_3e710_2026(step.indices)
                elif type(step) is NativeCIDRebuildMetadata2026:
                    self._engine._apply_ordinary_cid_selection_3e710_2026(
                        origin, step, worker=self
                    )
                    point.metadata = self._engine.native_metadata
                elif type(step) is NativeCIDRebuildTargetStore2026:
                    if (
                        type(step.cpu_index) is not int
                        or not 0 <= step.cpu_index < maximum
                    ):
                        raise ValueError("Actual17280 CPU slot required")
                    targets = list(self._judge_live_selection2026.targets)
                    targets[step.cpu_index] = step.target_index
                    self._store_ordinary_rebuild_targets_3e710_2026(tuple(targets))
                elif type(step) is NativeCIDRebuildComplete2026:
                    result = step.selection
                    metadata = self._engine.native_metadata
                    count = native2026_cpu_count(metadata)
                    if (
                        self._ordinary_file_metadata_for_cursor_3e710_2026(
                            result.rebuilt_metadata, self._current_global_cpu_index
                        )
                        != metadata
                        or result.rebuilt_metadata.source_container
                        is not metadata.source_container
                        or result.cpu_offset != self._cpu_offset
                        or result.target_indices
                        != self._judge_live_selection2026.targets[:count]
                    ):
                        raise ValueError(
                            "Native3e710 result differs from reached source stores"
                        )
                    selection = replace(result, rebuilt_metadata=metadata)
                    index = self._current_file_index
                    staged = {}
                    for name, value in (
                        ("_cpu_orders_by_file", tuple(range(count))),
                        ("_authored_cpu_orders_by_file", result.ordered_to_authored),
                        ("_selections_by_file", selection),
                        ("_cid_matches_by_file", None),
                    ):
                        values = list(getattr(self, name))
                        values[index] = value
                        staged[name] = tuple(values)
                    for name, value in staged.items():
                        setattr(self, name, value)
                    if self._delta_archive_active and self._delta_archive_clone_match:
                        self._retained_clone_selection = selection
                    self._cid_selected_files.add(index)
                    self._cid_rebuild_done_3542026 = True
                    complete = True
                else:
                    raise TypeError("Literal native3e710 source step required")
            if not complete:
                raise ValueError("Native3e710 body did not reach its D304 store")
        finally:
            publication = self._ordinary_cid_publication2026
            if publication is not None and publication[0] is point:
                self._ordinary_cid_publication2026 = None
            if self._ordinary_cid_point2026 is point:
                self._ordinary_cid_point2026 = None

    def _apply_pending_cid_match_3e710(self) -> None:
        """Apply the exact34e10 match only at36800's source-gated3e710 site."""
        from scripts.calibration_2026 import (
            NativeCIDMatch2026,
            native2026_cid_rebuild_allowed,
        )

        index = self._current_file_index
        current_global_cpu_index = self._current_global_cpu_index
        rebuild_allowed = native2026_cid_rebuild_allowed(self._engine.native_metadata)
        if rebuild_allowed and self._cid_rebuild_done_3542026:
            return
        match = self._cid_matches_by_file[index]
        if match is None:
            return
        if type(match) is not NativeCIDMatch2026:
            raise TypeError("Actual typed34e10 CID match required")
        result = self._engine._apply_worker_cid_selection(match, worker=self)
        if rebuild_allowed:
            self._cpu_offset = result.cpu_offset
        if current_global_cpu_index == 0 and self._cpu_offset != 0:
            self._engine._select_worker_rebuilt_cpu(self._cpu_offset, worker=self)
            current_global_cpu_index = self._cpu_offset
        metadata = self._engine.native_metadata
        result = replace(result, rebuilt_metadata=metadata)
        loaded = list(self._all_loaded_metadata)
        loaded[index] = metadata
        self._all_loaded_metadata = tuple(loaded)
        targets = list(self._targets_by_file)
        targets[index] = result.target_indices
        self._targets_by_file = tuple(targets)
        orders = list(self._cpu_orders_by_file)
        orders[index] = tuple(range(len(result.ordered_to_authored)))
        self._cpu_orders_by_file = tuple(orders)
        authored = list(self._authored_cpu_orders_by_file)
        authored[index] = result.ordered_to_authored
        self._authored_cpu_orders_by_file = tuple(authored)
        selections = list(self._selections_by_file)
        selections[index] = result
        self._selections_by_file = tuple(selections)
        matches = list(self._cid_matches_by_file)
        matches[index] = None
        self._cid_matches_by_file = tuple(matches)
        if self._delta_archive_active and self._delta_archive_clone_match:
            self._retained_clone_selection = result
        self._current_node = metadata.node
        self._current_cpu_index = metadata.cpu_index
        self._current_global_cpu_index = current_global_cpu_index
        if rebuild_allowed:
            self._cid_rebuild_done_3542026 = True

    @property
    def native_getter_cpu_type984(self) -> str:
        return self.native_getter_cpu_type

    @property
    def native_prepare_handshake(self) -> int:
        with self._lock:
            self.validate_source()
            return self._prepare_handshake

    @property
    def source_state(self) -> WorkerSourceState2026:
        with self._lock:
            self.validate_source()
            targets = (
                ()
                if not self._targets_by_file
                else self._targets_by_file[self._current_file_index]
            )
            return WorkerSourceState2026(
                self._current_file_index,
                self._current_node,
                self._current_cpu_index,
                self._current_global_cpu_index,
                self._cpu_offset,
                self._progress_base,
                targets,
                self._retained_cpu_type,
                self._prepare_handshake,
                self._battery_voltage,
                self._complete,
                tuple(self._phase_elapsed_ms),
                self._pending_continuation is not None,
                self._engine.native_gateway_cache,
                self._engine.native_ssmid_cache2026,
                self._engine.native_dh_type_cache2026,
                tuple(self._cpu_percentages),
                self._unmatched_identifiers_by_file[self._current_file_index],
                self._unmatched_companions_by_file[self._current_file_index],
                self._authored_cpu_counts_by_file[self._current_file_index],
                self._authored_target_indices_by_file[self._current_file_index],
            )

    @property
    def control_state(self) -> WorkerControlState2026:
        with self._lock:
            self.validate_source()
            state = self._engine.dh_state
            persistence = getattr(self._engine, "persistence", None) or getattr(
                self._engine, "_persistence", None
            )
            notification = last_block = False
            if persistence is not None:
                notification = bool(persistence.notification)
                last_block = bool(persistence.last_block_notification)
            return WorkerControlState2026(
                self._fatal,
                state.error_kind,
                state.primary_error,
                state.passthru_error,
                self._failed,
                state.comm_phase,
                self._initial_command_retry,
                state.native_context_964,
                state.use_new_password,
                self._source_mode,
                notification,
                last_block,
                state.flashing_ended,
                self._ig_off_pending,
                bool(self._controller.alternate_cid_used),
                self._recovery_ec9b and not self._recovery_ec9c,
                self._native_fatal_input,
                self._lifecycle,
            )

    @property
    def native_fatal_input80(self) -> bool:
        """59070 controller+80, copied to engineCFD0 only at5a835 tail."""
        return self._native_fatal_input

    def _record_outer_control_loader_failure(self, error: BaseException) -> None:
        """5a813 copies CPass+0xc to controller+60, then sets controller+80."""
        from scripts.j2534_2026 import NativePassThruError2026
        from scripts.programming_2026_common import NativePassThruException2026

        if not isinstance(
            error, (NativePassThruException2026, NativePassThruError2026)
        ):
            raise TypeError("Actual CPassThruException loader fault required")
        kind = error.native_error_code
        if type(kind) is not int or not -0x80000000 <= kind <= 0xFFFFFFFF:
            raise TypeError("Bounded native CPass error enum required")
        self._engine._require_owned_phase()
        with self._lock:
            self.validate_source()
            state = self._engine.dh_state
            state.record_native_error(
                kind & 0xFFFFFFFF, state.primary_error, state.passthru_error
            )
            self._native_fatal_input = True

    def _record_control_helper_cpass2026(
        self, context, error: BaseException, helper_lease
    ) -> None:
        """5a835 family-helper CPass catch; preserve kind/status and set native fatal."""
        from scripts import programming_2026_common
        from scripts.j2534_2026 import NativePassThruError2026
        from scripts.programming_2026_common import NativePassThruException2026

        with self._lock:
            self._validate_control_output_context2026(context)
            helper_entry = getattr(
                programming_2026_common, "_control_helper_entry2026", None
            )
            if not callable(helper_entry):
                raise TypeError("Source-issued CONTROL helper entry is unavailable")
            issued_entry = helper_entry(context)
            if helper_lease is not issued_entry:
                raise ValueError("Exact CONTROL helper-entry lease required")
            if not isinstance(
                error, (NativePassThruException2026, NativePassThruError2026)
            ):
                raise TypeError("Actual CPassThruException helper fault required")
            code = error.native_error_code
            if type(code) is not int or not -0x80000000 <= code <= 0xFFFFFFFF:
                raise TypeError("Bounded native CPass error enum required")
            state = self._engine.dh_state
            state.record_native_error(
                state.error_kind, code & 0xFFFFFFFF, state.passthru_error
            )
            self._native_fatal_input = True
            self._fatal = True

    def _begin_outer_control_loader(self) -> None:
        """5a790 clears controller+68/+70 only while comm phase bd0 is zero."""
        self._engine._require_owned_phase()
        with self._lock:
            self.validate_source()
            state = self._engine.dh_state
            if state.comm_phase == 0:
                state.record_native_error(state.error_kind, 0, 0)

    def _publish_outer_control_tail(self) -> None:
        """5b1b0 publishes+80 to CFD0, then callback9 local58 to D34B."""
        self._engine._require_owned_phase()
        with self._lock:
            self.validate_source()
            self._engine.publish_native_fatal(worker=self)
            self._engine.publish_control_fatal(worker=self)

    def online_context(self) -> WorkerOnlineContext2026:
        with self._lock:
            self.validate_source()
            metadata = self._engine.native_metadata
            vin = getattr(self._engine, "vin", self._vin)
            return WorkerOnlineContext2026(
                self._engine.identity.sha256,
                metadata.source_sha256,
                vin,
                metadata.region,
                metadata.vehicle.get("kindofecu", ""),
                self._is_daihatsu(),
                self._online_metadata_view(),
            )

    def usb_recovery_context(self) -> WorkerUSBRecoveryContext2026:
        with self._lock:
            self.validate_source()
            metadata = self._all_loaded_metadata[self._current_file_index]
            actual_cpu_index = self._cpu_orders_by_file[self._current_file_index][
                self._current_global_cpu_index
            ]
            targets = native2026_cpu_targets(metadata, actual_cpu_index)
            target_index = self.native_writer_target_index
            if not 0 <= target_index < len(targets):
                raise ValueError("Native target index is outside the current CPU")
            try:
                target = targets[target_index].calibration.encode("latin1")
            except UnicodeError as error:
                raise ValueError(
                    "Native target calibration is not a byte string"
                ) from error
            return WorkerUSBRecoveryContext2026(
                target,
                len(self._identifiers_for_file(self._current_file_index)),
            )

    def _is_daihatsu(self) -> bool:
        from scripts.cuw_file_services import compliance_2026

        return compliance_2026(self._online_metadata_view()) != 0

    def set_vin(self, data: bytes) -> bytes:
        """Compatibility entry routed through the engine's atomic 63990 setter."""
        value = self._engine.set_vin(data)
        with self._lock:
            self._vin = value
        return value

    def _set_online_modal_state(self, controller, state: int) -> None:
        if controller is not self._controller:
            raise ValueError("Online modal controller differs from worker owner")
        if type(state) is not int or not 0 <= state <= 10:
            raise ValueError("Native online modal state must be0..10")
        publisher = getattr(self._engine, "_publish_online_modal", None)
        if not callable(publisher):
            raise TypeError("Engine online modal publication is unavailable")
        publisher(controller, state)

    def set_control_error_kind(self, kind: int) -> None:
        if type(kind) is not int or not 0 <= kind <= 0xFFFFFFFF:
            raise ValueError("Native error kind must be an unsigned DWORD")
        self._engine._require_owned_phase()
        with self._lock:
            state = self._engine.dh_state
            state.record_native_error(kind, state.primary_error, state.passthru_error)

    def run_gateway_startup(self):
        """5a835's phase/General/alternate-CID gate around the real 1ad30 producer."""
        self._engine._require_owned_phase()
        with self._lock:
            self.validate_source()
            if self._engine.worker_phase != 1:
                raise ValueError("Gateway startup requires native worker phase1")
            metadata = self._engine.native_metadata
            cpu_type = native2026_cpu_type(metadata, 0)
            enabled = self._engine.general_parameter_boolean(
                metadata.vehicle.get("kindofecu", ""),
                cpu_type,
                metadata.vehicle.get("contacttype", ""),
                "FlagToChangeToReprogGWModeForCentralGW",
                controller=self._controller,
            )
            if self._controller.alternate_cid_used or not enabled:
                return None
            # 5a835 writes BE0=0 immediately before entering5b1e0.
            self._initial_command_retry = False
            persistence = getattr(self._engine, "persistence", None) or getattr(
                self._engine, "_persistence", None
            )
            if persistence is not None:
                persistence.state.is_central_gw_exist = False
            producer = self._engine.bind_gateway_startup()
            self._gateway_startup = producer
        state = producer.run()
        if state.returned:
            self._accept_gateway_startup(producer)
        elif state.output_flag:
            with self._lock:
                errors = self._engine.dh_state
                errors.record_native_error(
                    1, errors.primary_error, errors.passthru_error
                )
                self._failed = True
        return state

    def _accept_gateway_startup(self, producer) -> None:
        """Publish BE0/980 and BF9 only from a returned issued5b1e0 producer."""
        from scripts.cuw_gateway_startup import GatewayStartup2026

        if type(producer) is not GatewayStartup2026:
            raise TypeError("Actual issued gateway startup producer required")
        producer.validate_owner(self._engine, self)
        self._engine._require_owned_phase()
        with self._lock:
            if self._engine.worker_phase != 1:
                raise ValueError("Gateway startup publication requires phase1")
            state = producer.source_state
            if not state.returned or not state.output_flag:
                raise ValueError("Gateway startup has no returned source state")
            if state.classification_returned:
                if not 1 <= state.classification <= 0xFF:
                    raise ValueError("Gateway classifier byte is outside source range")
                if self._engine.repro_gateway_node != state.classification:
                    raise ValueError("Gateway wrapper did not publish its BF9 byte")
            self._initial_command_retry = True
            persistence = getattr(self._engine, "persistence", None) or getattr(
                self._engine, "_persistence", None
            )
            if persistence is not None:
                persistence.state.is_central_gw_exist = True

    def _accept_gateway_startup_failure(self, producer) -> None:
        """5b1e0 typed catch publishes only its local68/70 error fields."""
        from scripts.cuw_gateway_startup import GatewayStartup2026

        if type(producer) is not GatewayStartup2026:
            raise TypeError("Actual issued gateway startup producer required")
        producer.validate_owner(self._engine, self)
        self._engine._require_owned_phase()
        state = producer.source_state
        if (
            state.returned
            or state.primary_error is None
            or type(state.primary_error) is not int
            or state.passthru_status is not None
            and type(state.passthru_status) is not int
        ):
            raise ValueError("Gateway startup has no typed failure state")
        with self._lock:
            errors = self._engine.dh_state
            errors.record_native_error(
                errors.error_kind,
                state.primary_error,
                errors.passthru_error
                if state.passthru_status is None
                else state.passthru_status,
            )

    def _accept_gateway_cancel(self, producer) -> None:
        """5b690 copies only its typed catch fields into local68/70."""
        from scripts.cuw_gateway_startup import GatewayStartup2026

        if type(producer) is not GatewayStartup2026:
            raise TypeError("Actual issued gateway cancel producer required")
        producer.validate_owner(self._engine, self)
        self._engine._require_owned_phase()
        state = producer.cancel_state
        if (
            state.returned is not False
            or state.primary_error is None
            or type(state.primary_error) is not int
            or state.passthru_status is not None
            and type(state.passthru_status) is not int
        ):
            raise ValueError("Gateway cancel has no typed native catch state")
        with self._lock:
            errors = self._engine.dh_state
            errors.record_native_error(
                errors.error_kind, state.primary_error, state.passthru_status
            )

    def _retry_query_resume(self, retry) -> None:
        """3ffa0 post-wait FILE reset after captured5e950 input."""
        from scripts.calibration_2026 import (
            native2026_global_cpu_index,
            native2026_is_logical_cpu,
        )
        from scripts.cuw_retry import RetryController2026

        if type(retry) is not RetryController2026:
            raise TypeError("Actual source-issued retry controller required")
        self._engine._require_owned_phase()
        self._engine._validate_retry_controller(retry)
        retry_state = retry.source_state
        if retry_state.query_pending39a:
            raise ValueError("Captured retry input has not cleared engine39a")
        with self._lock:
            self.validate_source()
            sources = self._file_sources
            if (
                retry_state.native_option_eb48 != 0
                and self._delta_archive_active
                and sources is not None
                and not self._delta_archive_clone_match
                and (
                    sources.delta_map_size == 0
                    or sources.group_for_file(self._current_file_index) is not None
                )
            ):
                replacement = sources.after_group_reset(
                    self._current_file_index, worker=self
                )
                self._engine._accept_worker_file_reset(
                    sources, replacement, worker=self
                )
                self._cid_rebuild_done_3542026 = False
                self._control_scratch_reset_pending2026 = True
                retry._record_postwait_file_reset(self)
            self._restore_file_selection_47e60()
            metadata = self._engine.native_metadata
            if (
                retry_state.decision399
                and retry_state.result14 in (2, 3)
                and native2026_is_logical_cpu(
                    metadata, native2026_global_cpu_index(metadata)
                )
            ):
                # 40070 clears vector368 before either EB48 branch remaps358.
                self._phase_elapsed_ms[:] = [0] * len(self._phase_elapsed_ms)
                result = self._engine._resume_worker_logical_cpu(
                    worker=self, retry=retry
                )
                loaded = list(self._all_loaded_metadata)
                loaded[self._current_file_index] = result.metadata
                self._all_loaded_metadata = tuple(loaded)
                self._target_selected(result.metadata)
                pending = self._selection_rebuild_pending
                if pending is not None:
                    pending = replace(pending, rebuilt_metadata=result.metadata)
                    self._selection_rebuild_pending = pending
                    selections = list(self._selections_by_file)
                    selections[self._current_file_index] = pending
                    self._selections_by_file = tuple(selections)
                    if self._delta_archive_clone_match:
                        self._retained_clone_selection = pending

    def _retained_clone_metadata_for_reset(self, sources) -> Native2026Metadata | None:
        """Return34e10's typed A48 projection to141's sealed4b900 reset."""
        from scripts.calibration_2026 import (
            NativeCPUSelection2026,
            native2026_validate_runtime_metadata,
        )
        from scripts.cuw_file_services import (
            FileSourceSet2026,
            validate_file_sources_2026,
        )

        if type(sources) is not FileSourceSet2026:
            raise TypeError("Actual source-issued FILE set required")
        validate_file_sources_2026(sources, self._engine)
        with self._lock:
            self.validate_source()
            if sources is not self._file_sources or not self._delta_archive_active:
                raise ValueError("A48 cache requires the current delta FILE set")
            selection = self._retained_clone_selection
            if selection is None:
                return None
            if type(selection) is not NativeCPUSelection2026:
                raise TypeError("Actual typed34e10 A48 selection required")
            retained = sources.auxiliary_metadata
            metadata = selection.rebuilt_metadata
            native2026_validate_runtime_metadata(metadata)
            if (
                retained is None
                or metadata.source_container is not retained.source_container
                or metadata.source_sha256 != retained.source_sha256
            ):
                raise ValueError("Cached34e10 selection differs from retained A48")
            return metadata

    def _restore_file_selection_47e60(self) -> None:
        """Restore authored target/CID vectors from the exact34e10 FILE cache."""
        from scripts.calibration_2026 import NativeCPUSelection2026

        self._engine._require_owned_phase()
        with self._lock:
            self.validate_source()
            index = self._current_file_index
            selection = (
                self._retained_clone_selection
                if self._delta_archive_active and self._delta_archive_clone_match
                else self._selections_by_file[index]
            )
            if selection is None:
                return
            if type(selection) is not NativeCPUSelection2026:
                raise TypeError("Actual typed34e10 A48 selection required")
            current = self._engine.native_metadata
            if current is not selection.rebuilt_metadata:
                raise ValueError(
                    "47e60 current FILE differs from its cached projection"
                )
            targets = list(self._targets_by_file)
            targets[index] = selection.authored_target_indices
            self._targets_by_file = tuple(targets)
            orders = list(self._cpu_orders_by_file)
            orders[index] = tuple(range(native2026_cpu_count(current)))
            self._cpu_orders_by_file = tuple(orders)
            authored = list(self._authored_cpu_orders_by_file)
            authored[index] = selection.ordered_to_authored
            self._authored_cpu_orders_by_file = tuple(authored)
            unmatched = list(self._unmatched_identifiers_by_file)
            unmatched[index] = selection.unmatched_identifiers
            self._unmatched_identifiers_by_file = tuple(unmatched)
            companions = list(self._unmatched_companions_by_file)
            companions[index] = selection.unmatched_companions
            self._unmatched_companions_by_file = tuple(companions)
            counts = list(self._authored_cpu_counts_by_file)
            counts[index] = selection.authored_cpu_count
            self._authored_cpu_counts_by_file = tuple(counts)
            authored_targets = list(self._authored_target_indices_by_file)
            authored_targets[index] = selection.authored_target_indices
            self._authored_target_indices_by_file = tuple(authored_targets)
            self._cid_selected_files.discard(index)
            self._selection_rebuild_pending = selection

    def _restore_judge_file_selection_47e60_2026(self, origin) -> None:
        """Restore47e60's native live fields at the committed H tail."""
        if (
            type(origin) is not _NativeJudgeCommitOrigin2026
            or self._consumed_judge_commit2026 is not origin
            or origin.invocation is not self._judge_invocation2026
            or origin.thread_id != threading.get_ident()
        ):
            raise ValueError("Exact committed47e60 source point required")
        self._copy_judge_live_selection_47e60_2026()
        from scripts.calibration_2026 import (
            NativeCPUSelection2026,
            native2026_cid_rebuild_allowed,
        )

        metadata = self._engine.native_metadata
        if native2026_cid_rebuild_allowed(metadata):
            return
        count = native2026_cpu_count(metadata)
        if not 0 <= self._current_global_cpu_index < count:
            raise ValueError("Current H FILE has no native CPU selection row")
        live = self._judge_live_selection2026
        targets = live.targets[:count]
        selection = NativeCPUSelection2026(
            metadata,
            tuple(range(count)),
            targets,
            self._cpu_offset,
            live.unmatched_ids,
            live.unmatched_companions,
            live.authored_count,
            targets,
        )
        index = self._current_file_index
        selections = list(self._selections_by_file)
        selections[index] = selection
        self._selections_by_file = tuple(selections)
        for name in ("_cpu_orders_by_file", "_authored_cpu_orders_by_file"):
            values = list(getattr(self, name))
            values[index] = tuple(range(count))
            setattr(self, name, tuple(values))
        self._cid_selected_files.add(index)

    def _copy_judge_live_selection_47e60_2026(self) -> None:
        """The lexical group/final tail copies vectors without choosing a CPU/FILE."""
        sources = self._file_sources
        if sources is None:
            return
        current = self._capture_pointer_view2026(self._engine.native_metadata)
        if (
            sources.delta_archive
            and current is not None
            and current.kind in ("whole", "none")
        ):
            self._judge_live_selection2026 = self._judge_a48_selection2026
        elif sources.has_file_vector and any(sources.table_file_names):
            index = self._flow_file_index2026
            self._judge_live_selection2026 = _NativeJudgeSelectionCache2026(
                self._judge_file_selection_cache2026[index].targets,
                self._judge_file_unmatched_9fc2026[index],
                self._judge_file_companions_a082026[index],
                self._judge_file_counts_a142026[index],
            )

        index = self._current_file_index
        # Native47e60 copies fields, not a registered34e10 receipt. A new
        # 32ff0 FILE view must not inherit an unrelated typed match lineage.
        matches = list(self._cid_matches_by_file)
        matches[index] = None
        self._cid_matches_by_file = tuple(matches)
        selections = list(self._selections_by_file)
        selections[index] = None
        self._selections_by_file = tuple(selections)
        self._cid_selected_files.discard(index)
        self._selection_rebuild_pending = None
        live = self._judge_live_selection2026
        cpu_count = native2026_cpu_count(self._engine.native_metadata)
        if len(live.targets) < cpu_count:
            raise ValueError(
                "47e60 live target vector is smaller than the current FILE"
            )
        targets = list(self._targets_by_file)
        targets[index] = live.targets[:cpu_count]
        self._targets_by_file = tuple(targets)
        for name, value in (
            ("_unmatched_identifiers_by_file", live.unmatched_ids),
            ("_unmatched_companions_by_file", live.unmatched_companions),
            ("_authored_cpu_counts_by_file", live.authored_count),
            ("_authored_target_indices_by_file", live.targets[:cpu_count]),
        ):
            values = list(getattr(self, name))
            values[index] = value
            setattr(self, name, tuple(values))

    def _reapply_retained_selection_3e710(self) -> None:
        """Run the shared36800 D308 tail and any cached47e60 selection."""
        from scripts.calibration_2026 import (
            NativeCPUSelection2026,
            native2026_cid_rebuild_allowed,
        )

        selection = self._selection_rebuild_pending
        if selection is not None and type(selection) is not NativeCPUSelection2026:
            raise TypeError("Actual typed34e10 FILE selection required")
        metadata = self._engine.native_metadata
        if selection is not None and metadata is not selection.rebuilt_metadata:
            raise ValueError("36800 current FILE differs from cached FILE projection")
        index = self._current_file_index
        current_global_cpu_index = self._current_global_cpu_index
        if selection is not None and native2026_cid_rebuild_allowed(metadata):
            self._cpu_offset = selection.cpu_offset
        if current_global_cpu_index == 0 and self._cpu_offset != 0:
            self._engine._select_worker_rebuilt_cpu(self._cpu_offset, worker=self)
            current_global_cpu_index = self._cpu_offset
            metadata = self._engine.native_metadata
            if selection is not None:
                selection = replace(selection, rebuilt_metadata=metadata)
                selections = list(self._selections_by_file)
                selections[index] = selection
                self._selections_by_file = tuple(selections)
                if self._delta_archive_active and self._delta_archive_clone_match:
                    self._retained_clone_selection = selection
        if selection is None:
            self._current_node = metadata.node
            self._current_cpu_index = metadata.cpu_index
            self._current_global_cpu_index = current_global_cpu_index
        else:
            targets = list(self._targets_by_file)
            targets[index] = selection.target_indices
            self._targets_by_file = tuple(targets)
            orders = list(self._cpu_orders_by_file)
            orders[index] = tuple(range(len(selection.ordered_to_authored)))
            self._cpu_orders_by_file = tuple(orders)
            authored = list(self._authored_cpu_orders_by_file)
            authored[index] = selection.ordered_to_authored
            self._authored_cpu_orders_by_file = tuple(authored)
            self._cid_selected_files.add(index)
            self._current_node = metadata.node
            self._current_cpu_index = metadata.cpu_index
            self._current_global_cpu_index = current_global_cpu_index
            self._selection_rebuild_pending = None

        origin = self._engine._prepare_prefix_vbf_cpu_origin2026
        if origin is not None:
            job = self._engine.thread_job
            if job is None:
                raise ValueError("Exact external VBF CPU successor job required")
            job._complete_vbf_cpu_successor_36800_2026(origin, worker=self)

    def _file_reset_selected(self, sources) -> None:
        """Install141's exact4b900 FILE-table replacement during engine commit."""
        from scripts.cuw_file_services import (
            FileSourceSet2026,
            validate_file_reset_2026,
            validate_file_sources_2026,
        )

        if type(sources) is not FileSourceSet2026:
            raise TypeError("Actual source-issued FILE reset required")
        self._engine._require_owned_phase()
        validate_file_sources_2026(sources, self._engine)
        with self._lock:
            old_sources = self._file_sources
            if old_sources is None:
                raise ValueError("Worker has no native delta FILE source set")
            validate_file_reset_2026(old_sources, sources, self)
            if old_sources.delta_archive and old_sources.delta_map_size == 0:
                flow_file_index = 0
            else:
                old_group = old_sources.group_for_file(self._current_file_index)
                if old_group is None:
                    raise ValueError(
                        "Current old FILE has no source-authenticated group flow"
                    )
                flow_file_index = old_group[0]
            current = self._engine.native_metadata
            execution = _loaded_metadata(self._engine)
            matches = [
                index
                for index, item in enumerate(execution)
                if item.source_container is current.source_container
            ]
            if len(matches) != 1:
                raise ValueError("Reset FILE vector must contain the selected source")
            current_file_index = matches[0]
            selections = tuple(_unresolved_selection(item) for item in execution)
            targets_by_file = tuple(targets for targets, _ in selections)
            cpu_orders_by_file = tuple(order for _, order in selections)
            actual_cpu_index = native2026_global_cpu_index(current)
            current_global_cpu_index = cpu_orders_by_file[current_file_index].index(
                actual_cpu_index
            )
            if type(flow_file_index) is not int or flow_file_index < 0:
                raise ValueError("Native FILE flow index is invalid")
            if sources.has_file_vector and flow_file_index >= len(sources.files):
                raise ValueError("Native FILE flow index is outside replacement table")
            authored_target_indices = tuple(
                (-1,) * native2026_cpu_count(metadata) for metadata in execution
            )
            progress_base = sum(
                native2026_cpu_count(item) for item in execution[:current_file_index]
            )

            # Publish the complete 4b900 worker projection only after every
            # source, FILE, flow, and CPU relationship above has validated.
            self._file_sources = sources
            self._all_loaded_metadata = execution
            self._online_loaded_metadata = sources.files
            self._current_file_index = current_file_index
            self._current_node = current.node
            self._current_cpu_index = current.cpu_index
            self._targets_by_file = targets_by_file
            self._cpu_orders_by_file = cpu_orders_by_file
            self._authored_cpu_orders_by_file = cpu_orders_by_file
            self._unmatched_identifiers_by_file = tuple(() for _ in execution)
            self._unmatched_companions_by_file = tuple(() for _ in execution)
            self._authored_cpu_counts_by_file = (0,) * len(execution)
            self._authored_target_indices_by_file = authored_target_indices
            self._selections_by_file = (None,) * len(execution)
            self._cid_matches_by_file = (None,) * len(execution)
            self._cid_selected_files = set()
            self._current_global_cpu_index = current_global_cpu_index
            self._progress_base = progress_base
            self._phase_elapsed_ms[:] = [0] * len(self._phase_elapsed_ms)
            self._delta_archive_active = self._engine.native_delta_active
            self._delta_archive_clone_match = sources.current_is_retained_clone
            self._flow_file_index2026 = flow_file_index

    def begin_control_error_query(self) -> None:
        """5b810 clears local75c immediately before callback7 and callback3."""
        self._engine._require_owned_phase()
        with self._lock:
            self.validate_source()
            self._failed = False

    def import_control_error_query_decision(self, retry) -> None:
        """5b810 callback8 copies engine399, then applies its literal branch."""
        self.copy_control_retry_decision(retry)
        with self._lock:
            if self._failed:
                state = self._engine.dh_state
                state.record_native_error(state.error_kind, 0, 0)
            else:
                self._fatal = True

    def copy_control_retry_decision(self, retry) -> None:
        """5b0d0 callback8 copies engine399 into local75c without branching."""
        from scripts.cuw_retry import RetryController2026

        if type(retry) is not RetryController2026:
            raise TypeError("Actual source-issued retry controller required")
        self._engine._require_owned_phase()
        self._engine._validate_retry_controller(retry)
        with self._lock:
            self.validate_source()
            self._failed = self._engine.write_complete_output

    def _reset_getter_history_and_aux_40580_2026(self, origin) -> None:
        """Apply only the A34/43ab0 fields under an authentic reset origin."""
        from scripts.cuw_2026 import _InitialGetterReset40580_2026
        from scripts.cuw_engine_cleanup import EngineCleanup2026

        if type(origin) is _InitialGetterReset40580_2026:
            maximum = self._engine._validate_initial_getter_reset_40580_2026(
                origin, worker=self
            )
            epoch = origin.epoch
            if type(epoch) is not int or epoch <= 0:
                raise ValueError("Positive source-issued initial reset epoch required")
        elif type(origin) is EngineCleanup2026:
            origin.validate_owner(self._engine, self)
            if origin.state.trace[-3:] != [
                "global-prefix-reset",
                "device-clear",
                "vectors-reset",
            ]:
                raise ValueError(
                    "Engine cleanup has not reached worker reset chronology"
                )
            configuration = self._engine.configuration
            if configuration is None:
                raise ValueError("Configured getter capacity required at 40580 reset")
            maximum = configuration.cpu_maximum
            epoch = None
        else:
            raise TypeError("Actual initial reset or engine cleanup origin required")

        if type(maximum) is not int or maximum < 0:
            raise ValueError("Authenticated native getter capacity required")
        with self._lock:
            self._cid_rebuild_done_3542026 = False
            self._getter_histories_a34_2026 = tuple(
                _empty_getter_history_2026(maximum) for _ in range(16)
            )
            self._getter_flow_received_cids2026 = ((),) * 16
            self._getter_flow_query_records2026 = ((),) * 16
            self._getter_file_a48_received_cids2026 = (None,) * 16
            self._getter_a48_received_cids2026 = ()
            self._judge_file_selection_cache2026 = tuple(
                _NativeJudgeSelectionCache2026(targets=(-1,) * maximum)
                for _ in range(16)
            )
            self._judge_file_unmatched_9fc2026 = ()
            self._judge_file_companions_a082026 = ()
            self._judge_file_counts_a142026 = ()
            self._judge_a48_selection_by_file2026 = (
                _NativeJudgeSelectionCache2026(),
            ) * 16
            self._judge_a48_selection2026 = _NativeJudgeSelectionCache2026()
            self._judge_a48_match2026 = None
            self._judge_a48_matches_by_file2026 = (None,) * 16
            self._judge_live_selection2026 = _NativeJudgeSelectionCache2026(
                targets=(-1,) * maximum
            )
            self._getter_authored_cpu_offset_a24_2026 = 0
            self._node_strings_4402026 = [b""] * maximum
            self._node_strings_4682026 = [b""] * maximum
            self._node_strings_4902026 = [b""] * maximum
            self._node_strings_4b82026 = [b""] * maximum
            self._cell_dword_bits_5542026 = [0] * (32 * maximum)
            self._cell_strings_5602026 = [b""] * (32 * maximum)
            self._retained_bits_5882026 = [False] * maximum
            self._node_dword_bits_1b9c2026 = [0] * maximum
            self._name_1ba8_2026 = b""
            self._name_1bc0_2026 = b""
            if epoch is not None:
                self._getter_reset_epoch2026 = epoch

    def _apply_getter_entry_34cb0_2026(self, *, origin: object) -> None:
        """Consume the authenticated first-entry source prefix in native order."""
        from scripts.cuw_file_services import (
            FileSourceSet2026,
            validate_file_sources_2026,
            validate_file_view_2026,
        )

        job = self._engine.thread_job
        if job is None or job.worker is not self:
            raise ValueError("Authenticated current getter job required")
        from scripts.cuw_engine_threads import _NativeGetterNextEntryOrigin2026

        if type(origin) is _NativeGetterNextEntryOrigin2026:
            job._validate_getter_next_entry_3d120_2026(origin, worker=self)
            if origin.progress != "projection":
                raise ValueError(
                    "Named-next34cb0 requires its completed32ff0 projection"
                )
        else:
            job._validate_getter_entry_34cb0_2026(origin)

        configuration = self._engine.configuration
        if (
            configuration is None
            or configuration.cpu_maximum
            != self._engine.common_definitions.num_cpu_maxnum
        ):
            raise ValueError("Current configured getter capacity required")
        maximum = configuration.cpu_maximum
        masks = self._getter_configured_masks_4f0_2026
        if (
            type(masks) is not tuple
            or len(masks) != 16
            or any(
                type(mask) is not tuple
                or len(mask) != maximum
                or any(type(value) is not bool for value in mask)
                for mask in masks
            )
            or len(self._configured_bits_4e0_2026) != maximum
        ):
            raise ValueError("Native configured getter masks differ from capacity")
        received = self._engine.received_identifiers
        records = self._engine.identifier_records
        if (
            type(received) is not tuple
            or type(records) is not tuple
            or len(received) != len(records)
            or len(received) > 34
            or any(type(value) is not bytes or b"\0" in value for value in received)
            or any(type(value) is not bytes or len(value) != 12 for value in records)
        ):
            raise ValueError("Current canonical native getter vectors are invalid")
        histories = self._getter_histories_a34_2026
        if type(histories) is not tuple or len(histories) != 16:
            raise ValueError("Exact sixteen-entry native getter history required")
        flow_cids = self._getter_flow_received_cids2026
        if (
            type(flow_cids) is not tuple
            or len(flow_cids) != 16
            or any(
                type(values) is not tuple
                or any(type(value) is not bytes for value in values)
                for values in flow_cids
            )
        ):
            raise ValueError("Exact sixteen-entry native D724 cache required")
        flow_queries = self._getter_flow_query_records2026
        whole_cids = self._getter_file_a48_received_cids2026
        if (
            type(flow_queries) is not tuple
            or len(flow_queries) != 16
            or any(
                type(values) is not tuple
                or any(type(value) is not bytes or len(value) != 12 for value in values)
                for values in flow_queries
            )
            or type(whole_cids) is not tuple
            or len(whole_cids) != 16
            or any(
                values is not None
                and (
                    type(values) is not tuple
                    or any(type(value) is not bytes for value in values)
                )
                for values in whole_cids
            )
        ):
            raise ValueError("Exact native A28/A48 cache shape required")
        flow_index = self._flow_file_index2026
        sources = self._file_sources
        if type(flow_index) is not int or not 0 <= flow_index < 16:
            raise ValueError("Native getter flow index is outside its fixed table")
        flow_view = None
        if sources is not None:
            if type(sources) is not FileSourceSet2026:
                raise TypeError("Exact source-issued FILE set required")
            validate_file_sources_2026(sources, self._engine)
            if sources.has_file_vector:
                if flow_index >= len(sources.files):
                    raise ValueError(
                        "Native getter flow is outside the current FILE table"
                    )
                flow_view = sources.file_view2026(flow_index)
            else:
                if flow_index != 0:
                    raise ValueError(
                        "Current-only FILE source must retain native flow zero"
                    )
                flow_view = sources.admission_view2026()
            validate_file_view_2026(flow_view, sources)
            if flow_view.file_index != (
                flow_index if sources.has_file_vector else None
            ):
                raise ValueError("Current flow descriptor differs from native D71C")
        elif flow_index != 0:
            raise ValueError("No-table native getter must retain flow zero")

        names = () if sources is None else sources.table_file_names
        if len(names) > 16 or any(type(name) is not str for name in names):
            raise ValueError("Native getter filename table exceeds sixteen entries")
        switch_names_present = any(names)
        contact = self._engine.native_metadata.vehicle.get("contacttype", "")
        desired_version = (
            1
            if contact == "Ethernet"
            else 0
            if contact in ("P5-Unified", "Phase6")
            else None
        )

        # These suppliers preserve source order: published errors clear first,
        # then49b50 may fail with its native partial mutations intact.
        self._engine._clear_getter_entry_errors_34cb0_2026(origin)
        if switch_names_present and desired_version is not None:
            device = self._engine.engine_runtime_device()
            if device.version != desired_version:
                device.switch_version()

        self._engine._publish_getter_entry_phase_prompt_34cb0_2026(origin)
        configured = [False] * maximum
        if self._getter_sequence_changed_39c2026:
            configured = list(masks[flow_index])
        self._configured_bits_4e0_2026 = configured
        self._getter_reset_epoch2026 += 1
        self._engine._publish_getter_entry_busy_34cb0_2026(origin)

    def _prepare_getter_observation_3d120_2026(
        self, decision, output: object
    ) -> tuple[
        _NativeGetterObservation2026,
        EngineThreadJob2026,
        CUWPersistence,
        ReproInfoState,
    ]:
        """Validate and freeze only values present at the actual3d120 join."""
        from scripts.cuw_engine_threads import (
            EngineThreadJob2026,
            ThreadPhaseLease2026,
            _CompletionRecord2026,
            _NativeGetterDecision2026,
        )
        from scripts.cuw_file_services import (
            FileSourceSet2026,
            NativeFileView2026,
            validate_file_sources_2026,
            validate_file_view_2026,
        )
        from scripts.cuw_persistence import CUWPersistence, ReproInfoState
        from scripts.programming_2026_common import NativeControlGetterOutput2026
        from scripts.programming_replay import ProgrammingReplay

        job = self._engine.thread_job
        p6_import = (
            self._imported_phase6_getter_receipt2026(
                decision.candidate.execute_record.context,
                job,
                decision.sequence,
            )
            if type(decision) is _NativeGetterDecision2026
            else None
        )
        if (
            type(decision) is not _NativeGetterDecision2026
            or type(job) is not EngineThreadJob2026
            or decision.job is not job
            or decision.worker is not self
            or decision.route != "success_3d120"
            or decision.candidate.candidate != "success_3d120"
            or decision.candidate.execute_return is not True
            or decision.candidate.stop_receipt is not None
            or decision.prepare_handshake_be8 == 2
            or not (
                (
                    type(output) is NativeControlGetterOutput2026
                    and decision.candidate.output is output
                )
                or (
                    output is None
                    and decision.candidate.output is None
                    and p6_import is not None
                )
            )
        ):
            raise ValueError("Exact successful typed CanCID decision required")
        job._validate_getter_decision_2026(decision, route="success_3d120")
        context = decision.candidate.execute_record.context
        capture = output.capture if output is not None else context._capture
        if (
            capture is not context._capture
            or capture.file_sources is not self._file_sources
            or capture.configuration is not self._engine.configuration
            or self._getter_ordinary_return_sequence2026 <= 0
            or capture._thread_job is not job
            or capture.phase_lease is not decision.lease
            or capture.job_sequence != decision.sequence
            or capture.raw_session is not job._session
            or capture.completion_record is not job._active_record
        ):
            raise ValueError("Typed getter output differs from its actual old lineage")
        source_set = self._file_sources
        if source_set is not None:
            if (
                type(source_set) is not FileSourceSet2026
                or self._engine.file_sources is not source_set
            ):
                raise ValueError("Authenticated native FILE source required")
            validate_file_sources_2026(source_set, self._engine)
        flow_index = self._flow_file_index2026
        if type(flow_index) is not int or not 0 <= flow_index < 16:
            raise ValueError("Native getter flow is outside its fixed table")
        named_table = bool(
            source_set is not None
            and source_set.has_file_vector
            and any(source_set.table_file_names)
        )
        if (
            named_table
            and source_set is not None
            and flow_index >= len(source_set.files)
        ):
            raise ValueError("Named native getter flow is outside its current table")
        if not named_table and flow_index != 0:
            raise ValueError("Native no-table getter must retain flow zero")
        pointer_view = self._capture_pointer_view2026(self._engine.native_metadata)
        if source_set is None:
            if pointer_view is not None:
                raise ValueError("Absent FILE source cannot carry a pointer view")
            pointer_value = (
                "none",
                None,
                self._engine.native_metadata.source_sha256,
                0,
            )
        else:
            if type(pointer_view) is not NativeFileView2026:
                raise ValueError("Current native pointer descriptor required")
            validate_file_view_2026(pointer_view, source_set)
            if (
                pointer_view.source_container
                is not self._engine.native_metadata.source_container
                or pointer_view.source_sha256
                != self._engine.native_metadata.source_sha256
            ):
                raise ValueError(
                    "Current getter pointer differs from its issued descriptor"
                )
            pointer_value = (
                pointer_view.kind,
                pointer_view.file_index,
                pointer_view.source_sha256,
                pointer_view.original_recovery_index,
            )

        configuration = self._engine.configuration
        if configuration is None:
            raise ValueError("Current getter configuration required")
        maximum = configuration.cpu_maximum
        if (
            output is not None and configuration is not output.configuration
        ) or self._engine.common_definitions.num_cpu_maxnum != maximum:
            raise ValueError("Native getter configuration identity or M differs")
        self._query_seed34_2026()
        vectors = (
            self._node_strings_4402026,
            self._node_strings_4682026,
            self._node_strings_4902026,
            self._node_strings_4b82026,
        )
        if (
            any(len(vector) != maximum for vector in vectors)
            or len(self._cell_dword_bits_5542026) != 32 * maximum
            or len(self._cell_strings_5602026) != 32 * maximum
            or len(self._retained_bits_5882026) != maximum
            or len(self._node_dword_bits_1b9c2026) != maximum
            or len(self._configured_bits_4e0_2026) != maximum
            or type(self._getter_histories_a34_2026) is not tuple
            or len(self._getter_histories_a34_2026) != 16
        ):
            raise ValueError("Native getter observation differs from exact M capacity")
        histories = self._getter_histories_a34_2026
        for history in histories:
            if (
                len(history.node_strings_28) != maximum
                or len(history.node_strings_50) != maximum
                or len(history.node_strings_78) != maximum
                or len(history.node_strings_a0) != maximum
                or len(history.cell_dword_bits_c8) != 32 * maximum
                or len(history.cell_strings_d4) != 32 * maximum
                or len(history.retained_bits_fc) != maximum
                or len(history.node_dword_bits_10c) != maximum
            ):
                raise ValueError("Native A34 history differs from exact M capacity")
        persistence = self._engine._persistence
        if type(persistence) is not CUWPersistence:
            raise ValueError("Authenticated persistence aggregate required for G")
        persistence.validate_engine_owner(self._engine)
        persistence_state = persistence.state
        if type(persistence_state) is not ReproInfoState:
            raise ValueError("Authenticated RecoveryInfo state required for G")
        self._engine._validate_persistence_source(
            self._engine.native_metadata, state_snapshot=persistence_state
        )
        if source_set is not None:
            persistence._validate_file_source_membership(
                source_set, self._engine.native_metadata
            )
        if (
            type(job._lease) is not ThreadPhaseLease2026
            or job._lease is not decision.lease
            or job._lease.state != "adopted"
            or type(job._session) is not ProgrammingReplay
            or type(job._active_record) is not _CompletionRecord2026
        ):
            raise ValueError("Active old getter lineage is incomplete")

        # C58 starts from D71C. Only a literal mapped delta table replaces
        # that observation index with the current WHOLE's original ECIndex.
        recovery_index = flow_index
        received = self._engine.received_identifiers
        query = self._engine.identifier_records
        hardware = self._engine._working_hardware
        if (
            type(received) is not tuple
            or any(type(value) is not bytes for value in received)
            or type(query) is not tuple
            or len(query) != len(received)
            or any(type(value) is not bytes or len(value) != 12 for value in query)
            or type(hardware) is not bytes
        ):
            raise ValueError("Actual imported CanCID values are incomplete")
        recovery_index = flow_index
        if (
            source_set is not None
            and source_set.has_file_vector
            and source_set.delta_archive
            and source_set.delta_map_size
        ):
            if pointer_view is None:
                raise ValueError("Delta recovery cache requires the current FILE")
            recovery_index = pointer_view.original_recovery_index
        observation = _NativeGetterObservation2026(
            source_set,
            pointer_value,
            flow_index,
            recovery_index,
            configuration,
            capture._import_epoch,
            self._getter_ordinary_return_sequence2026,
            decision.sequence,
            decision.decision_sequence,
            self._getter_sequence_changed_39c2026,
            received,
            query,
            hardware,
            tuple(self._node_strings_4402026),
            tuple(self._node_strings_4682026),
            tuple(self._node_strings_4902026),
            tuple(self._node_strings_4b82026),
            tuple(self._configured_bits_4e0_2026),
            tuple(self._retained_bits_5882026),
            tuple(self._cell_dword_bits_5542026),
            tuple(self._cell_strings_5602026),
            tuple(self._node_dword_bits_1b9c2026),
            self._name_1ba8_2026,
            self._name_1bc0_2026,
            (
                output.communication_addresses
                if output is not None
                else tuple(context._controller.address_history)
            ),
        )
        return observation, job, persistence, persistence_state

    def _prepare_reproinfo_getter_write_3d120_2026(
        self,
        observation: _NativeGetterObservation2026,
        persistence: CUWPersistence,
        persistence_state: ReproInfoState,
        pointer_view: NativeFileView2026 | None,
        group: NativeFileGroupView2026 | None,
    ):
        """Preflight the exact20f20/ED00/ED70/ED2C/ED38/ED44 destination."""
        from scripts.cuw_persistence import ReproInfoState

        sources = observation.file_sources
        flow_index = observation.flow_file_index
        recovery_index = flow_index
        if (
            sources is not None
            and sources.has_file_vector
            and sources.delta_archive
            and sources.delta_map_size
        ):
            if pointer_view is None:
                raise ValueError("Delta recovery observation requires its current FILE")
            original_index = pointer_view.original_recovery_index
            if type(original_index) is not int:
                raise ValueError("Delta current FILE has no original recovery index")
            recovery_index = original_index
        if (
            type(persistence_state) is not ReproInfoState
            or persistence.state is not persistence_state
            or self._engine._persistence is not persistence
            or type(recovery_index) is not int
            or not 0 <= recovery_index < len(persistence_state.calibrations)
        ):
            raise ValueError("Actual RecoveryInfo observation destination required")
        persistence_state.validate()
        calibration = persistence_state.calibrations[recovery_index]
        maximum = observation.configuration.cpu_maximum
        if (
            len(observation.received_cids) != len(observation.query_records)
            or len(observation.node_strings_440) != maximum
            or any(
                type(value) is not bytes or b"\0" in value or len(value) > 12
                for value in observation.node_strings_440
            )
            or len(observation.retained_bits) != maximum
            or any(type(value) is not bool for value in observation.retained_bits)
            or len(observation.configured_bits) != maximum
            or any(type(value) is not bool for value in observation.configured_bits)
        ):
            raise ValueError("RecoveryInfo getter vectors differ from native capacity")
        cids = tuple(value.decode("ascii") for value in observation.received_cids)
        if any(b"\0" in value for value in observation.received_cids):
            raise ValueError("Received RecoveryInfo CID contains a native terminator")
        requested_addresses = tuple(
            _native_getter_requested_address2026(value)
            for value in observation.query_records
        )
        hardware_id = observation.hardware.decode("ascii")
        # 5a050 already decoded the raw13-byte buffers into native strings.
        assemblies = tuple(
            value.decode("ascii") for value in observation.node_strings_440
        )
        return (
            recovery_index,
            calibration,
            cids,
            requested_addresses,
            hardware_id,
            assemblies,
            observation.retained_bits,
            observation.configured_bits,
        )

    def _apply_reproinfo_getter_write_3d120_2026(
        self, persistence: CUWPersistence, persistence_state: ReproInfoState, values
    ) -> None:
        """Apply the preflighted native RecoveryInfo writes in source order."""
        (
            recovery_index,
            calibration,
            cids,
            requested_addresses,
            hardware_id,
            assemblies,
            retained,
            configured,
        ) = values
        with persistence._lock:
            if (
                self._engine._persistence is not persistence
                or persistence.state is not persistence_state
                or not 0 <= recovery_index < len(persistence_state.calibrations)
                or persistence_state.calibrations[recovery_index] is not calibration
            ):
                raise ValueError("RecoveryInfo destination changed after G preflight")
            # 20f20,24540,ED70,ED2C,ED38,ED44 are native ordered stores.
            calibration.cids = cids
            calibration.requested_addresses = requested_addresses
            persistence_state.hardware_id = hardware_id
            calibration.assembly_numbers = assemblies
            calibration.update_available = retained
            masks = list(self._getter_configured_masks_4f0_2026)
            masks[self._flow_file_index2026] = configured
            self._getter_configured_masks_4f0_2026 = tuple(masks)
            calibration.blank_ecu_flags = configured

    def _merge_getter_history_3d120_2026(
        self, flow_index: int, observation: _NativeGetterObservation2026
    ) -> None:
        """Apply the source retained-mask merge to the actual per-FILE A34 slot."""
        histories = list(self._getter_histories_a34_2026)
        if not 0 <= flow_index < len(histories):
            raise ValueError("Native A34 FILE slot is outside its fixed table")
        previous = histories[flow_index]
        strings = [
            list(previous.node_strings_28),
            list(previous.node_strings_50),
            list(previous.node_strings_78),
            list(previous.node_strings_a0),
        ]
        cells_dword = list(previous.cell_dword_bits_c8)
        cells_string = list(previous.cell_strings_d4)
        retained = list(previous.retained_bits_fc)
        node_dword = list(previous.node_dword_bits_10c)
        for cpu_index, keep in enumerate(previous.retained_bits_fc):
            if keep:
                continue
            strings[0][cpu_index] = observation.node_strings_440[cpu_index]
            strings[1][cpu_index] = observation.node_strings_468[cpu_index]
            strings[2][cpu_index] = observation.node_strings_490[cpu_index]
            strings[3][cpu_index] = observation.node_strings_4b8[cpu_index]
            cell_start = cpu_index * 32
            cells_dword[cell_start : cell_start + 32] = observation.cell_dword_bits[
                cell_start : cell_start + 32
            ]
            cells_string[cell_start : cell_start + 32] = observation.cell_strings[
                cell_start : cell_start + 32
            ]
            retained[cpu_index] = observation.retained_bits[cpu_index]
            node_dword[cpu_index] = observation.node_dword_bits[cpu_index]
        old_received = previous.received_cids
        if not observation.sequence_changed_39c:
            old_received = observation.received_cids
        histories[flow_index] = _NativeGetterHistory2026(
            old_received,
            observation.query_records,
            tuple(strings[0]),
            tuple(strings[1]),
            tuple(strings[2]),
            tuple(strings[3]),
            tuple(cells_dword),
            tuple(cells_string),
            tuple(retained),
            tuple(node_dword),
            observation.name_1ba8,
            observation.name_1bc0,
        )
        self._getter_histories_a34_2026 = tuple(histories)
        query_records = list(self._getter_flow_query_records2026)
        query_records[flow_index] = observation.query_records
        self._getter_flow_query_records2026 = tuple(query_records)
        masks = list(self._getter_configured_masks_4f0_2026)
        masks[flow_index] = observation.configured_bits
        self._getter_configured_masks_4f0_2026 = tuple(masks)

    def _clear_getter_live_auxiliary_43ab0_2026(self) -> None:
        """Apply43ab0's exact live auxiliary clear without touching4e0/A34."""
        configuration = self._engine.configuration
        if configuration is None:
            raise ValueError("Configured native getter capacity required")
        maximum = configuration.cpu_maximum
        if (
            len(self._node_strings_4402026) != maximum
            or len(self._node_strings_4682026) != maximum
            or len(self._node_strings_4902026) != maximum
            or len(self._node_strings_4b82026) != maximum
            or len(self._cell_dword_bits_5542026) != 32 * maximum
            or len(self._cell_strings_5602026) != 32 * maximum
            or len(self._retained_bits_5882026) != maximum
            or len(self._node_dword_bits_1b9c2026) != maximum
        ):
            raise ValueError("Native43ab0 scratch differs from exact M capacity")
        self._node_strings_4402026 = [b""] * maximum
        self._node_strings_4682026 = [b""] * maximum
        self._node_strings_4902026 = [b""] * maximum
        self._node_strings_4b82026 = [b""] * maximum
        self._cell_dword_bits_5542026 = [0] * (32 * maximum)
        self._cell_strings_5602026 = [b""] * (32 * maximum)
        self._retained_bits_5882026 = [False] * maximum
        self._node_dword_bits_1b9c2026 = [0] * maximum
        self._name_1ba8_2026 = b""
        self._name_1bc0_2026 = b""

    def _project_getter_file_metadata2026(self, view):
        from scripts.calibration_2026 import (
            Native2026Metadata,
            native2026_metadata_for_cpu,
            native2026_validate_runtime_metadata,
        )
        from scripts.cuw_file_services import (
            NativeFileView2026,
            validate_file_view_2026,
        )

        sources = self._file_sources
        if type(view) is not NativeFileView2026 or sources is None:
            raise ValueError("Actual named FILE projection view required")
        validate_file_view_2026(view, sources)
        cached = self._engine._worker_target_sources.get(id(view.source_container))
        base = view.metadata if cached is None else cached
        if (
            type(base) is not Native2026Metadata
            or base.source_container is not view.source_container
            or base.source_sha256 != view.source_sha256
            or base.region != view.metadata.region
            or self._engine._parser_profile(base) != base
        ):
            raise ValueError("Runtime FILE source projection is not authenticated")
        projected = native2026_metadata_for_cpu(base, self._current_global_cpu_index)
        native2026_validate_runtime_metadata(projected)
        if (
            projected.source_container is not view.source_container
            or projected.source_sha256 != view.source_sha256
            or projected.region != view.metadata.region
            or self._engine._parser_profile(projected) != projected
        ):
            raise ValueError("Projected FILE metadata differs from the source view")
        return projected

    def _apply_getter_file_projection_tail_32ff0_2026(self, origin, view) -> None:
        job = self._engine.thread_job
        if job is None or job.worker is not self:
            raise ValueError("Actual G pointer tail requires its current job")
        job._validate_getter_3d120_origin2026(
            origin, worker=self, source_stage="projection"
        )
        if (
            origin.progress != "flow"
            or origin.next_pointer_view is not view
            or origin.frontend_selection_point2026 is not None
            or origin.wait_restore_point2026 is not None
            or self._frontend_selection_41940_point2026 is not None
        ):
            raise ValueError("Exact unoccupied G32ff0 source point required")
        metadata = self._engine.native_metadata
        selection = (self, view, metadata, threading.get_ident())
        point = (origin, metadata, threading.get_ident())
        origin.frontend_selection_point2026 = selection
        self._frontend_selection_41940_point2026 = point
        try:
            self._apply_file_parameters_41940_2026()
        finally:
            if self._frontend_selection_41940_point2026 is point:
                self._frontend_selection_41940_point2026 = None
            if origin.frontend_selection_point2026 is selection:
                origin.frontend_selection_point2026 = None
        sources = self._file_sources
        if sources is not None and (
            sources.delta_map_size != 0 or not sources.delta_archive
        ):
            index = view.file_index
            if type(index) is not int:
                raise ValueError("Actual G named32ff0 FILE slot required")
            self._engine._received_identifiers = self._getter_flow_received_cids2026[
                index
            ]
            self._engine._identifier_records = self._getter_flow_query_records2026[
                index
            ]
        engine = self._engine
        identity = engine._wait_active_admission2026
        epoch = engine._wait_timing_epoch2026
        index = view.file_index
        if (
            sources is None
            or identity is None
            or sources._wait_timing_admission2026 is not identity
            or type(epoch) is not int
            or epoch <= 0
            or type(index) is not int
            or not 0 <= index < 16
        ):
            raise ValueError("G32ff0 requires its successful timing admission")
        late = (index, identity, epoch, metadata, threading.get_ident())
        origin.wait_restore_point2026 = late
        try:
            engine._restore_file_waits_32ff0_2026(worker=self, origin=origin)
        finally:
            if origin.wait_restore_point2026 is late:
                origin.wait_restore_point2026 = None

    def _fanout_getter_group_3d120_2026(
        self, group, observation: _NativeGetterObservation2026
    ) -> int:
        from scripts.cuw_file_services import (
            FileSourceSet2026,
            NativeFileGroupView2026,
            validate_file_group_view_2026,
        )

        sources = self._file_sources
        if (
            type(sources) is not FileSourceSet2026
            or type(group) is not NativeFileGroupView2026
        ):
            raise ValueError("Authenticated current native group required")
        validate_file_group_view_2026(group, sources)
        cache_slot = _native_a48_cache_slot2026(sources, group.start)
        if (
            group.start != self._flow_file_index2026
            or group.width < 1
            or group.width > 16 - group.start
            or len(self._getter_configured_masks_4f0_2026) != 16
            or cache_slot is None
            or self._getter_a48_received_cids2026 != observation.received_cids
        ):
            raise ValueError("Native A48/group fanout differs from current D71C")
        a48_cids = list(self._getter_file_a48_received_cids2026)
        a48_cids[cache_slot] = observation.received_cids
        self._getter_file_a48_received_cids2026 = tuple(a48_cids)
        histories = list(self._getter_histories_a34_2026)
        masks = list(self._getter_configured_masks_4f0_2026)
        for member in group.members:
            index = member.file_index
            if (
                type(index) is not int
                or not group.start <= index < group.start + group.width
            ):
                raise ValueError("Native fanout member is outside its source group")
            history = histories[index]
            histories[index] = replace(
                history,
                received_cids=observation.received_cids,
                query_records=observation.query_records,
            )
            masks[index] = observation.configured_bits
        self._getter_histories_a34_2026 = tuple(histories)
        query_records = list(self._getter_flow_query_records2026)
        for member in group.members:
            index = member.file_index
            if type(index) is not int:
                raise ValueError("Native group member has no actual FILE index")
            query_records[index] = observation.query_records
        self._getter_flow_query_records2026 = tuple(query_records)
        self._getter_configured_masks_4f0_2026 = tuple(masks)
        flow_cids = list(self._getter_flow_received_cids2026)
        for member in group.members:
            index = member.file_index
            if type(index) is not int:
                raise ValueError("Native group member has no actual FILE index")
            flow_cids[index] = observation.received_cids
        self._getter_flow_received_cids2026 = tuple(flow_cids)
        return group.width - 1

    def _refresh_getter_group_whole_46d60_2026(
        self,
        group: NativeFileGroupView2026 | None,
        observation: _NativeGetterObservation2026,
    ) -> None:
        """Refresh46d60's whole-group received-CID vector before67680."""
        from scripts.cuw_file_services import (
            FileSourceSet2026,
            NativeFileGroupView2026,
            validate_file_group_view_2026,
        )

        sources = self._file_sources
        if type(sources) is not FileSourceSet2026:
            raise ValueError("Actual native FILE source required for46d60")
        if group is None:
            if not (sources.delta_archive and sources.delta_map_size == 0):
                raise ValueError(
                    "Native46d60 requires its actual group or zero-map path"
                )
        else:
            if (
                type(group) is not NativeFileGroupView2026
                or not 0 <= group.start < 16
                or group.sources is not sources
                or group.start != self._flow_file_index2026
            ):
                raise ValueError("Actual mapped whole-group source required")
            validate_file_group_view_2026(group, sources)
            if group.whole.kind != "whole" or group.whole.sources is not sources:
                raise ValueError("Native46d60 whole FILE descriptor differs")
        if len(observation.received_cids) != len(observation.query_records):
            raise ValueError("Native46d60 whole CID source differs")
        self._getter_a48_received_cids2026 = observation.received_cids

    def _restore_judge_file_waits_32ff0_2026(self, marker, requested_slot: int) -> None:
        invocation = self._judge_invocation2026
        sources = self._file_sources
        engine = self._engine
        if (
            invocation is None
            or sources is None
            or self._file_wait_restore_origin2026 is not None
            or self._judge_wait_ready_marker2026 is not marker
        ):
            raise ValueError("Actual fresh H late32ff0 source point required")
        engine._require_judge_flashable_invocation2026(self, invocation.region)
        if type(requested_slot) is not int or not 0 <= requested_slot < 16:
            raise ValueError("Literal32ff0 requested FILE slot required")
        if (
            requested_slot >= len(sources.table_file_names)
            or not sources.table_file_names[requested_slot]
        ):
            self._judge_wait_ready_marker2026 = None
            return
        reset = self._judge_reset_point2026
        if reset is not None and marker is reset.origin:
            if reset.stage != "first_waits" or requested_slot != marker.group.start:
                raise ValueError("Mapped first32ff0 has not reached its wait restore")
        elif (
            type(marker) is _NativeJudgeCommitOrigin2026
            and marker is self._consumed_judge_commit2026
        ):
            engine._validate_judge_commit_stage_49010_2026(
                marker, worker=self, candidate=marker.candidate
            )
            if (
                marker.candidate is None
                or marker.candidate.file_index != requested_slot
            ):
                raise ValueError(
                    "Final32ff0 requested slot differs from its actual argument"
                )
        elif (
            type(marker) is _NativeJudgeProjectionPoint2026
            and marker is self._judge_late_projection_point2026
        ):
            if (
                marker.view.file_index != requested_slot
                or marker.ordinal + 1 != self._judge_projection_ordinal2026
            ):
                raise ValueError(
                    "Transient32ff0 wait slot differs from its source call"
                )
        else:
            raise ValueError("Late32ff0 cannot borrow another source point")
        identity = engine._wait_active_admission2026
        epoch = engine._wait_timing_epoch2026
        if (
            identity is None
            or sources._wait_timing_admission2026 is not identity
            or type(epoch) is not int
            or epoch <= 0
        ):
            raise ValueError(
                "Late32ff0 requires its successful shared timing admission"
            )
        origin = _NativeFileWaitRestoreOrigin2026(
            self,
            engine,
            invocation,
            marker,
            sources,
            engine.native_metadata,
            requested_slot,
            identity,
            epoch,
            threading.get_ident(),
        )
        self._file_wait_restore_origin2026 = origin
        try:
            engine._restore_file_waits_32ff0_2026(worker=self, origin=origin)
        finally:
            if self._file_wait_restore_origin2026 is origin:
                self._file_wait_restore_origin2026 = None
            if self._judge_wait_ready_marker2026 is marker:
                self._judge_wait_ready_marker2026 = None

    def _consume_file_wait_restore_origin_32ff0_2026(
        self, origin, *, engine
    ) -> tuple[int, object, int]:
        from scripts.cuw_engine_threads import _NativeGetterNextEntryOrigin2026
        from scripts.cuw_file_services import NativeFileView2026

        sources = self._file_sources
        if type(origin) is _NativeGetterNextEntryOrigin2026:
            if engine is not self._engine or engine.worker is not self:
                raise ValueError("Actual G32ff0 worker and engine required")
            job = engine.thread_job
            if job is None:
                raise ValueError("Actual G32ff0 worker and engine required")
            job._validate_getter_3d120_origin2026(
                origin, worker=self, source_stage="projection"
            )
            point = origin.wait_restore_point2026
            if (
                type(point) is not tuple
                or len(point) != 5
                or origin.progress != "flow"
                or origin.frontend_selection_point2026 is not None
                or self._frontend_selection_41940_point2026 is not None
                or sources is None
                or sources is not origin.source_set
                or engine.file_sources is not sources
                or type(origin.next_pointer_view) is not NativeFileView2026
                or point[0] != origin.next_pointer_view.file_index
                or type(point[0]) is not int
                or not 0 <= point[0] < 16
                or point[1] is None
                or point[1] is not engine._wait_active_admission2026
                or sources._wait_timing_admission2026 is not point[1]
                or type(point[2]) is not int
                or point[2] <= 0
                or point[2] != engine._wait_timing_epoch2026
                or point[3] is not engine.native_metadata
                or point[3] is not origin.projected_metadata
                or point[4] != threading.get_ident()
            ):
                raise ValueError("Exact live one-use G32ff0 wait point required")
            origin.wait_restore_point2026 = None
            return point[0], point[1], point[2]
        if (
            type(origin) is not _NativeFileWaitRestoreOrigin2026
            or self._file_wait_restore_origin2026 is not origin
            or origin.worker is not self
            or origin.engine is not engine
            or engine is not self._engine
            or engine.worker is not self
            or origin.invocation is not self._judge_invocation2026
            or origin.marker is not self._judge_wait_ready_marker2026
            or sources is None
            or origin.source_set is not sources
            or engine.file_sources is not sources
            or origin.metadata is not engine.native_metadata
            or origin.thread_id != threading.get_ident()
            or origin.admission_identity is not engine._wait_active_admission2026
            or sources._wait_timing_admission2026 is not origin.admission_identity
            or type(origin.timing_epoch) is not int
            or origin.timing_epoch <= 0
            or origin.timing_epoch != engine._wait_timing_epoch2026
            or type(origin.requested_slot) is not int
            or not 0 <= origin.requested_slot < 16
        ):
            raise ValueError("Exact live one-use32ff0 wait origin required")
        engine._require_judge_flashable_invocation2026(self, origin.invocation.region)
        self._file_wait_restore_origin2026 = None
        return origin.requested_slot, origin.admission_identity, origin.timing_epoch

    def _apply_judge_parameters_41940_2026(self) -> None:
        """Run41940 only at the active native H source point."""
        invocation = self._judge_invocation2026
        if (
            invocation is None
            or self._engine._require_judge_flashable_invocation2026(
                self, invocation.region
            )
            is not invocation
        ):
            raise ValueError("Actual judge41940 source point required")
        reset = self._judge_reset_point2026
        marker = (
            reset.origin
            if reset is not None
            else self._consumed_judge_commit2026
            if invocation.commit_started
            else self._judge_late_projection_point2026
        )
        if self._frontend_selection_41940_point2026 is not None:
            raise ValueError("41940 source selection is already active")
        point = (
            marker,
            self._engine.native_metadata,
            threading.get_ident(),
        )
        self._frontend_selection_41940_point2026 = point
        try:
            self._validate_frontend_selection_41940_2026(
                self._engine.native_metadata, engine=self._engine
            )
            self._apply_file_parameters_41940_2026()
        finally:
            if self._frontend_selection_41940_point2026 is point:
                self._frontend_selection_41940_point2026 = None

    def _validate_frontend_selection_41940_2026(self, metadata, *, engine) -> None:
        from scripts.cuw_engine_threads import _NativeGetterNextEntryOrigin2026

        point = self._frontend_selection_41940_point2026
        invocation = self._judge_invocation2026
        if (
            point is None
            or engine is not self._engine
            or engine.worker is not self
            or point[1] is not metadata
            or metadata is not engine.native_metadata
            or point[2] != threading.get_ident()
        ):
            raise ValueError("Exact current41940 H selection point required")
        marker = point[0]
        if type(marker) is _NativeGetterNextEntryOrigin2026:
            job = engine.thread_job
            if job is None:
                raise ValueError("Actual G41940 job required")
            job._validate_getter_3d120_origin2026(
                marker, worker=self, source_stage="projection"
            )
            selection = marker.frontend_selection_point2026
            if (
                type(selection) is not tuple
                or len(selection) != 4
                or selection[0] is not self
                or selection[1] is not marker.next_pointer_view
                or selection[2] is not metadata
                or selection[3] != threading.get_ident()
                or marker.projected_metadata is not metadata
                or marker.progress != "flow"
                or marker.wait_restore_point2026 is not None
            ):
                raise ValueError("Exact lexical G41940 projection point required")
            return
        if invocation is None:
            raise ValueError("Actual H41940 invocation required")
        if (
            engine._require_judge_flashable_invocation2026(self, invocation.region)
            is not invocation
        ):
            raise ValueError("41940 point belongs to another H invocation")
        marker = point[0]
        reset = self._judge_reset_point2026
        if reset is not None and marker is reset.origin:
            if (
                reset.stage not in ("first_41940", "second_41940")
                or reset.runtime_metadata is not metadata
            ):
                raise ValueError("Mode1 reset has not reached its actual41940 call")
        elif (
            type(marker) is _NativeJudgeCommitOrigin2026
            and marker is self._consumed_judge_commit2026
        ):
            engine._validate_judge_commit_stage_49010_2026(
                marker, worker=self, candidate=marker.candidate
            )
        elif (
            type(marker) is _NativeJudgeProjectionPoint2026
            and marker is self._judge_late_projection_point2026
        ):
            if (
                marker.invocation is not invocation
                or marker.thread_id != threading.get_ident()
                or marker.ordinal + 1 != self._judge_projection_ordinal2026
                or marker.view.source_container is not metadata.source_container
                or marker.view.source_sha256 != metadata.source_sha256
            ):
                raise ValueError("41940 projection point differs from current FILE")
        else:
            raise ValueError("41940 requires its actual lexical H pointer point")

    def _apply_file_parameters_41940_2026(self) -> None:
        """Keep36's actual selected primitives for subsequent35c60 consumers."""
        (self._general_parameter_41940_2026, self._address_parameter_41940_2026) = (
            self._engine._select_frontend_parameters_41940_2026(
                self._engine.native_metadata
            )
        )

    def _native_flashability_description_35c60_2026(
        self, metadata: Native2026Metadata, view, row: bytes, region: int
    ) -> bytes:
        """Resolve35c60's actual per-row label source and localized value."""
        from scripts.calibration_2026 import (
            native2026_cpu_count,
            native2026_cpu_type,
            native2026_metadata_for_cpu,
            native2026_new_calibration_id,
        )
        from scripts.programming_2026_common import NativeCallbackLookupError

        contact = metadata.vehicle.get("contacttype", "")
        if contact not in ("Ethernet", "P5-Unified", "Phase6"):
            general = self._engine._general_parameters
            if general is None:
                raise NativeCallbackLookupError()
            cpu_index = 0
            current_parameter = self._general_parameter_41940_2026
            selected = (
                current_parameter.parameters("KindOfECUNames", 4)
                if current_parameter is not None
                and self._judge_invocation2026 is not None
                else general._parameter().parameters_with_keys(
                    "KindOfECUNames",
                    metadata.vehicle.get("kindofecu", ""),
                    native2026_cpu_type(metadata, cpu_index),
                    contact,
                    4,
                )
            )
            if selected is None:
                raise NativeCallbackLookupError()
            values, _total = selected
        else:
            old = row[:0x22].split(b"\0", 1)[0]
            new = row[0x22:0x44].split(b"\0", 1)[0]
            label_cid = new if old in (b"", b"-") else old
            sources = self._file_sources
            named = bool(
                sources is not None
                and sources.has_file_vector
                and any(sources.table_file_names)
            )
            index = view.file_index if view is not None else None
            if named and type(index) is not int:
                raise ValueError("35c60 named FILE index is required")
            file_index = 0
            if named:
                assert type(index) is int
                file_index = cast(int, index)
            if not named:
                received = self._engine.received_identifiers
                records = self._engine.identifier_records
            elif (
                sources is not None
                and sources.delta_archive
                and (
                    sources.delta_map_size == 0
                    or sources.group_for_file(file_index) is not None
                )
            ):
                received = self._getter_a48_received_cids2026
                records = (
                    self._engine.identifier_records
                    if sources.delta_map_size == 0
                    else self._getter_flow_query_records2026[file_index]
                )
            else:
                assert type(index) is int
                received = self._getter_flow_received_cids2026[file_index]
                records = self._getter_flow_query_records2026[file_index]

            key = ""
            kind: int | None = None
            found_pair = False
            companion_raw = row[0x44:0x4B].split(b"\0", 1)[0]
            if (
                type(received) is tuple
                and type(records) is tuple
                and len(received) == len(records)
            ):
                for cid, record in zip(received, records, strict=True):
                    if (
                        cid == label_cid
                        and type(record) is bytes
                        and len(record) == 12
                        and b"\0" in record[4:]
                        and record[4:].split(b"\0", 1)[0] == companion_raw
                    ):
                        found_pair = True
                        kind = int.from_bytes(record[:4], "little")
                        key = record[4:].split(b"\0", 1)[0].decode("ascii")
                        break
            if not found_pair:
                for cpu_index in range(native2026_cpu_count(metadata)):
                    context = native2026_metadata_for_cpu(metadata, cpu_index)
                    node = context.node_values
                    diagid = node.get("diagid", "")
                    logical_address = node.get("logicaladdress", "")
                    companion = diagid or logical_address
                    authored = native2026_new_calibration_id(
                        metadata, cpu_index
                    ).encode("latin1")
                    if (
                        authored == label_cid
                        and companion.encode("latin1") == companion_raw
                    ):
                        kind = 1 if contact == "Ethernet" else 0
                        key = logical_address if kind == 1 else diagid
                        break
            if not key:
                return b""
            frontend = self._engine._frontend_parameters
            if frontend is None:
                raise NativeCallbackLookupError()
            frontend.validate_source()
            current_table = self._address_parameter_41940_2026
            current_is_logical = metadata.vehicle.get("contacttype", "") == "Ethernet"
            table = (
                current_table
                if current_table is not None and (kind == 1) == current_is_logical
                else frontend.parameter(
                    "LogicalAddressTable.ini" if kind == 1 else "CanIDTable.ini"
                )
            )
            selected = table.parameters_with_keys("KindOfECUNames", key, "", "", 4)
            values = () if selected is None else selected[0]

        labels = [b"0"] * 4
        for position, value in enumerate(values[:4]):
            encoded = value.encode("latin1")
            if len(encoded) >= 260:
                raise ValueError("Native35c60 label exceeds its bounded buffer")
            labels[position] = encoded
        return labels[region - 1][:0xFF]

    def _judge_flashable_file_5ffc0_2026(self, region: int, view, *, buffers=None):
        """Run the source-backed5ffc0 row matrix for the selected FILE view."""
        from scripts.calibration_2026 import (
            native2026_cpu_count,
            native2026_cpu_targets,
            native2026_cpu_values,
            native2026_match_received_cids,
            native2026_metadata_for_cpu,
            native2026_new_calibration_id,
            native2026_node_index,
        )
        from scripts.cuw_2026 import NativeFlashabilityRow2026
        from scripts.cuw_file_services import (
            NativeFileView2026,
            validate_file_view_2026,
        )

        if buffers is None:
            buffers = _NativeJudgeRows2026()
        if type(buffers) is not _NativeJudgeRows2026:
            raise TypeError("Actual5ffc0 caller output buffers required")
        sources = self._file_sources
        named_table = bool(
            sources is not None
            and sources.has_file_vector
            and any(sources.table_file_names)
        )
        if (
            (view is not None and type(view) is not NativeFileView2026)
            or type(region) is not int
            or not 1 <= region <= 4
        ):
            raise ValueError("Authenticated5ffc0 FILE and region required")
        metadata = self._engine.native_metadata
        if type(metadata) is not Native2026Metadata:
            raise ValueError("5ffc0 requires the already-selected runtime FILE")
        if view is None:
            index = 0
        else:
            if sources is None:
                raise ValueError("FILE view has no issued source set")
            validate_file_view_2026(view, sources)
            index = view.file_index
            if index is None or not 0 <= index < 16:
                raise ValueError("5ffc0 requires an actual named FILE index")
        configuration = self._engine.configuration
        general = self._engine._general_parameters
        if configuration is None or general is None:
            raise ValueError("Actual configured matcher and General required")
        maximum = configuration.cpu_maximum
        configured = self._getter_configured_masks_4f0_2026[index]
        if (
            type(configured) is not tuple
            or len(configured) != maximum
            or any(type(value) is not bool for value in configured)
        ):
            raise ValueError("Actual per-FILE configured mask required")
        cpu_count = native2026_cpu_count(metadata)
        if cpu_count > maximum:
            raise ValueError("Authored FILE exceeds configured CPU capacity")
        if not named_table:
            received = self._engine.received_identifiers
            query_records = self._engine.identifier_records
        elif sources is not None and (
            (sources.delta_archive and sources.delta_map_size == 0)
            or sources.group_for_file(index) is not None
        ):
            received = self._getter_a48_received_cids2026
            query_records = self._getter_flow_query_records2026[index]
        else:
            received = self._getter_flow_received_cids2026[index]
            query_records = self._getter_flow_query_records2026[index]
        if (
            type(received) is not tuple
            or type(query_records) is not tuple
            or len(received) != len(query_records)
            or any(type(value) is not bytes or b"\0" in value for value in received)
            or any(
                type(value) is not bytes or len(value) != 12 for value in query_records
            )
        ):
            raise ValueError("Actual per-FILE CID and query cache required")
        companion_records = (
            self._getter_flow_query_records2026[index]
            if named_table
            and sources is not None
            and not sources.delta_archive
            and sources.group_for_file(index) is None
            else self._engine.identifier_records
        )
        if len(companion_records) < len(received):
            raise ValueError(
                "5ffc0 selected CID vector exceeds its actual query companions"
            )
        observation = self._getter_last_observation2026
        hardware = (
            observation.hardware
            if type(observation) is _NativeGetterObservation2026
            else self._engine.received_hardware
        )
        if type(hardware) is not bytes or b"\0" in hardware:
            raise ValueError("Actual getter hardware bytes required")
        all_configured = cpu_count > 0 and all(configured[:cpu_count])
        is_vbf = cpu_count > 0 and ".vbf" in native2026_cpu_values(metadata, 0).get(
            "cpuimagename", ""
        )
        native_phase = self._engine.native_phase
        error_output = self._engine._native_error_output
        if (
            type(native_phase) is not int
            or type(error_output) is not tuple
            or len(error_output) != 2
            or any(type(value) is not int for value in error_output)
        ):
            raise ValueError("Exact native receiving/error state required")
        if not all_configured and not is_vbf and not self._engine.received_identifiers:
            return 3006, buffers.check_target, buffers.rows
        if (
            not self._engine.native_receiving_cfe2_2026
            and native_phase == 0
            and error_output[0]
        ) or (self._engine.native_receiving_cfe2_2026 and native_phase == 0):
            return 3006, buffers.check_target, buffers.rows
        configured_metadata = None
        if named_table:
            assert sources is not None
            table_metadata = sources.file_view2026(index).metadata
            configured_metadata = self._engine._worker_target_sources.get(
                id(table_metadata.source_container),
                table_metadata,
            )
            if (
                configured_metadata.source_container
                is not table_metadata.source_container
                or configured_metadata.source_sha256 != table_metadata.source_sha256
            ):
                raise ValueError(
                    "4b0f0 indexed runtime FILE differs from its actual table source"
                )
        match_records = (
            self._engine.identifier_records
            if not named_table
            or (
                sources is not None
                and sources.delta_archive
                and sources.delta_map_size == 0
            )
            else self._getter_flow_query_records2026[index]
        )
        match = native2026_match_received_cids(
            metadata,
            received,
            match_records,
            general,
            configuration=configuration,
            shrink_flag=self._engine.shrink_flag,
            received_hardware=hardware,
            configured_cpu_flags=configured,
            configured_metadata=configured_metadata,
            live_received_identifiers=self._engine.received_identifiers,
        )
        buffers.check_target = match.check_target
        selection_cache = _NativeJudgeSelectionCache2026(
            match.authored_target_indices + (-1,) * (maximum - cpu_count),
            match.unmatched_identifiers,
            match.unmatched_companions,
            match.authored_cpu_count,
        )
        self._judge_live_selection2026 = selection_cache
        if (
            sources is not None
            and sources.delta_archive
            and view is not None
            and view.kind in ("whole", "none")
        ):
            self._judge_a48_selection2026 = selection_cache
            self._judge_a48_match2026 = match
            cache_slot = (
                _native_a48_cache_slot2026(sources, index) if sources.files else None
            )
            if cache_slot is not None:
                group_cache = list(self._judge_a48_selection_by_file2026)
                group_cache[cache_slot] = selection_cache
                matches = list(self._judge_a48_matches_by_file2026)
                matches[cache_slot] = match
                self._judge_a48_matches_by_file2026 = tuple(matches)
                self._judge_a48_selection_by_file2026 = tuple(group_cache)
        elif named_table:
            native_cache = list(self._judge_file_selection_cache2026)
            native_cache[index] = replace(
                native_cache[index], targets=selection_cache.targets
            )
            self._judge_file_selection_cache2026 = tuple(native_cache)
            self._judge_file_unmatched_9fc2026 += (selection_cache.unmatched_ids,)
            self._judge_file_companions_a082026 += (
                selection_cache.unmatched_companions,
            )
            self._judge_file_counts_a142026 += (selection_cache.authored_count,)
        if index >= len(self._cid_matches_by_file):
            raise ValueError("Native34e10 match cache has no current FILE slot")
        if named_table and (view is None or view.kind != "whole"):
            matches = list(self._cid_matches_by_file)
            matches[index] = match
            self._cid_matches_by_file = tuple(matches)
            self._authored_cpu_counts_by_file = tuple(
                cpu_count if slot == index else value
                for slot, value in enumerate(self._authored_cpu_counts_by_file)
            )
            self._authored_target_indices_by_file = tuple(
                match.authored_target_indices if slot == index else value
                for slot, value in enumerate(self._authored_target_indices_by_file)
            )
            unmatched_by_file = list(self._unmatched_identifiers_by_file)
            unmatched_by_file[index] = match.unmatched_identifiers
            self._unmatched_identifiers_by_file = tuple(unmatched_by_file)
            unmatched_by_file = list(self._unmatched_companions_by_file)
            unmatched_by_file[index] = match.unmatched_companions
            self._unmatched_companions_by_file = tuple(unmatched_by_file)
        phased = metadata.vehicle.get("contacttype", "") in (
            "P5-Unified",
            "Phase6",
            "Ethernet",
        )
        phase6 = metadata.vehicle.get("contacttype", "") == "Phase6"
        configured_mode = metadata.is_controlled_by_scc or phase6
        unmatched_pairs = set(
            zip(
                match.unmatched_identifiers,
                match.unmatched_companions
                if phased
                else (b"" for _ in match.unmatched_identifiers),
                strict=True,
            )
        )
        unmatched_ids = {value for value, _ in unmatched_pairs}
        capacity = len(received) + cpu_count
        buffers.rows = tuple(
            NativeFlashabilityRow2026(bytes(333)) for _ in range(capacity)
        )
        rows: list[bytes] = []
        emitted_old_pairs: set[tuple[bytes, bytes]] = set()
        emitted_new_pairs: set[tuple[bytes, bytes]] = set()
        new_cids = tuple(
            native2026_new_calibration_id(metadata, cpu).encode("latin1")
            for cpu in range(cpu_count)
        )
        companions = tuple(
            (
                native2026_metadata_for_cpu(metadata, cpu).node_values.get("diagid", "")
                or native2026_metadata_for_cpu(metadata, cpu).node_values.get(
                    "logicaladdress", ""
                )
            ).encode("latin1")
            for cpu in range(cpu_count)
        )
        if configured_mode:
            for cpu in range(cpu_count):
                if configured[native2026_node_index(metadata, cpu)]:
                    rows.append(
                        _native_flashability_row2026(
                            old_cid=b"-",
                            new_cid=new_cids[cpu],
                            companion=companions[cpu],
                            eligible=True,
                            description=b"",
                            terminal=False,
                        )
                    )
                    emitted_old_pairs.add((b"-", companions[cpu]))
                    emitted_new_pairs.add((new_cids[cpu], companions[cpu]))
        skip_received_match = self._engine.shrink_flag or (
            configured_mode and metadata.is_blank_ecu
        )
        if not skip_received_match:
            for received_index, old_cid in enumerate(received):
                query_companion = (
                    companion_records[received_index][4:].split(b"\0", 1)[0]
                    if phased
                    else b""
                )
                for cpu in range(cpu_count):
                    if (
                        configured_mode
                        and configured[native2026_node_index(metadata, cpu)]
                    ):
                        continue
                    if old_cid not in {
                        target.calibration.encode("latin1")
                        for target in native2026_cpu_targets(metadata, cpu)
                    }:
                        continue
                    if phased and query_companion != companions[cpu]:
                        continue
                    new_cid = new_cids[cpu]
                    eligible = new_cid not in unmatched_ids or (
                        phased and (new_cid, query_companion) not in unmatched_pairs
                    )
                    rows.append(
                        _native_flashability_row2026(
                            old_cid=old_cid,
                            new_cid=new_cid,
                            companion=query_companion,
                            eligible=eligible,
                            description=b"",
                            terminal=False,
                        )
                    )
                    emitted_old_pairs.add((old_cid, query_companion))
                    emitted_new_pairs.add((new_cid, query_companion))
        companion_run = 0
        previous_companion = None
        for received_index, old_cid in enumerate(received):
            companion = (
                companion_records[received_index][4:].split(b"\0", 1)[0]
                if phased
                else b""
            )
            if previous_companion is not None and previous_companion != companion:
                companion_run += 1
            previous_companion = companion
            # Native local_c4 counts adjacent companion changes; it is not
            # either the received index or the matching authored CPU index.
            if (
                configured_mode
                and companion_run < maximum
                and configured[companion_run]
            ):
                continue
            old_pair = (old_cid, companion)
            if old_pair in emitted_old_pairs:
                continue
            matching_cpu = next(
                (
                    cpu
                    for cpu in range(cpu_count)
                    if new_cids[cpu] == old_cid and companions[cpu] == companion
                ),
                None,
            )
            if matching_cpu is None:
                new_cid, eligible = b"", False
            else:
                new_cid = new_cids[matching_cpu]
                eligible = new_cid not in unmatched_ids or (
                    phased and (new_cid, companion) not in unmatched_pairs
                )
            rows.append(
                _native_flashability_row2026(
                    old_cid=old_cid,
                    new_cid=new_cid,
                    companion=companion,
                    eligible=eligible,
                    description=b"",
                    terminal=False,
                )
            )
            emitted_old_pairs.add(old_pair)
            if new_cid:
                emitted_new_pairs.add((new_cid, companion))
        live_received = self._engine.received_identifiers
        for cpu in range(cpu_count):
            if configured_mode and configured[native2026_node_index(metadata, cpu)]:
                continue
            pair = (new_cids[cpu], companions[cpu])
            if pair in emitted_new_pairs:
                continue
            vbf_marker = (
                cpu == 0
                and ".vbf" in native2026_cpu_values(metadata, 0).get("cpuimagename", "")
                and not live_received
            )
            rows.append(
                _native_flashability_row2026(
                    old_cid=b"-" if vbf_marker else b"",
                    new_cid=new_cids[cpu],
                    companion=companions[cpu],
                    eligible=False,
                    description=b"",
                    terminal=False,
                )
            )
            emitted_new_pairs.add(pair)
        if len(rows) > capacity:
            raise ValueError("5ffc0 row count exceeds its native temporary allocation")
        raw_buffers = [NativeFlashabilityRow2026(raw) for raw in rows]
        raw_buffers.extend(buffers.rows[len(raw_buffers) :])
        buffers.rows = tuple(raw_buffers)
        labelled = []
        for index_in_rows, raw in enumerate(rows):
            old = raw[:0x22].split(b"\0", 1)[0]
            new = raw[0x22:0x44].split(b"\0", 1)[0]
            description = self._native_flashability_description_35c60_2026(
                metadata, view, raw, region
            )
            packed = bytearray(raw)
            packed[0x4C:0x14C] = bytes(0x100)
            packed[0x4C : 0x4C + len(description)] = description
            packed[0x14C] = int(old == b"-" and bool(new))
            labelled.append(NativeFlashabilityRow2026(bytes(packed)))
            raw_buffers[index_in_rows] = labelled[-1]
            buffers.rows = tuple(raw_buffers)
        buffers.count = len(labelled)
        return 0, buffers.check_target, buffers.rows

    def _judge_flashable_62330_2026(self, region: int):
        """Run the authenticated native62330 FILE/group traversal."""
        from scripts.cuw_2026 import (
            NativeFlashabilityResult2026,
            NativeFlashabilityRow2026,
            _JudgeFlashableInvocation2026,
        )
        from scripts.cuw_file_services import (
            FileSourceSet2026,
            validate_file_sources_2026,
        )

        if type(region) is not int or not 1 <= region <= 4:
            raise ValueError("Native flashability region must be1..4")
        invocation = self._engine._validate_judge_flashable_orchestration2026(
            self, region
        )
        if type(invocation) is not _JudgeFlashableInvocation2026:
            raise TypeError("Native judge invocation marker required")
        self._judge_invocation2026 = invocation
        self._judge_projection_ordinal2026 = 0
        self._judge_projection_point2026 = None
        sources = self._file_sources
        if sources is not None:
            if type(sources) is not FileSourceSet2026:
                raise TypeError("Exact issued FILE source set required")
            validate_file_sources_2026(sources, self._engine)
        rows_buffer: list[bytes] = []
        row_count_buffer = [0]
        boolean_buffer = [False]
        self._judge_rows_buffer2026 = rows_buffer
        self._judge_row_count_buffer2026 = row_count_buffer
        self._judge_boolean_buffer2026 = boolean_buffer

        named = bool(
            sources is not None
            and sources.has_file_vector
            and any(sources.table_file_names)
        )
        direct_delta = (
            sources is not None
            and sources.delta_archive
            and sources.delta_map_size == 0
        )
        projection_plan: list[tuple[str, object]] = []
        if direct_delta:
            assert sources is not None
            group = sources.group_view2026(0) if sources.files else None
            whole = sources.admission_view2026() if group is None else group.whole
            if sources.has_file_vector:
                projection_plan.append(("group_enter", whole))
                projection_plan.extend(
                    ("group_member", member)
                    for member in (
                        group.members
                        if group is not None
                        else tuple(
                            sources.file_view2026(i) for i in range(len(sources.files))
                        )
                    )
                )
                projection_plan.append(("group_whole", whole))
        elif named:
            assert sources is not None
            cursor = 0
            prepass = True
            while cursor < len(sources.files):
                group = sources.group_view2026(cursor)
                if group is None:
                    projection_plan.append(
                        (
                            "outer_initial" if prepass else "outer_initial_next",
                            sources.file_view2026(cursor),
                        )
                    )
                    cursor += 1
                else:
                    projection_plan.append(
                        (
                            "outer_initial" if prepass else "outer_initial_next",
                            group.whole,
                        )
                    )
                    cursor += group.width
                prepass = False
            projection_plan.append(("slot0", sources.file_view2026(0)))
            cursor = 0
            while cursor < len(sources.files):
                group = sources.group_view2026(cursor)
                if cursor > 0:
                    projection_plan.append(
                        (
                            "outer_next",
                            sources.file_view2026(cursor)
                            if group is None
                            else group.whole,
                        )
                    )
                if group is not None:
                    projection_plan.append(("group_enter", group.whole))
                    projection_plan.extend(
                        ("group_member", member) for member in group.members
                    )
                    projection_plan.append(("group_whole", group.whole))
                    cursor += group.width
                else:
                    cursor += 1
        self._judge_projection_plan2026 = tuple(projection_plan)

        status = 0
        check_target = False
        candidate_index = 0
        all_rows: list[bytes] = []
        caller_outputs = _NativeJudgeRows2026()
        try:
            if direct_delta:
                assert sources is not None
                group = sources.group_view2026(0) if sources.files else None
                status, check_target, file_rows, candidate_index, _eligible = (
                    self._judge_flashable_group_61e40_2026(
                        region, group, invocation, buffers=caller_outputs
                    )
                )
                all_rows.extend(
                    self._judge_rows_as_raw2026(file_rows)[: caller_outputs.count]
                )
            elif named:
                assert sources is not None
                cursor = 0
                prepass = True
                while cursor < len(sources.files):
                    group = sources.group_view2026(cursor)
                    if group is None:
                        view = sources.file_view2026(cursor)
                        self._publish_judge_file_projection_32ff0_2026(
                            view,
                            region=region,
                            site="outer_initial" if prepass else "outer_initial_next",
                        )
                        cursor += 1
                    else:
                        self._publish_judge_file_projection_32ff0_2026(
                            group.whole,
                            region=region,
                            site="outer_initial" if prepass else "outer_initial_next",
                        )
                        cursor += group.width
                    prepass = False
                self._publish_judge_file_projection_32ff0_2026(
                    sources.file_view2026(0), region=region, site="slot0"
                )

                cursor = 0
                combined = False
                while cursor < len(sources.files):
                    group = sources.group_view2026(cursor)
                    if cursor > 0:
                        view = (
                            sources.file_view2026(cursor)
                            if group is None
                            else group.whole
                        )
                        self._publish_judge_file_projection_32ff0_2026(
                            view, region=region, site="outer_next"
                        )
                    before = combined
                    if group is None:
                        view = sources.file_view2026(cursor)
                        file_status, file_check, file_rows = (
                            self._judge_flashable_file_5ffc0_2026(
                                region, view, buffers=caller_outputs
                            )
                        )
                        chosen = cursor
                        cursor += 1
                    else:
                        file_status, file_check, file_rows, chosen, _eligible = (
                            self._judge_flashable_group_61e40_2026(
                                region, group, invocation, buffers=caller_outputs
                            )
                        )
                        current_sources = self._file_sources
                        if current_sources is not sources:
                            if current_sources is None:
                                raise ValueError(
                                    "Mode1 lost its source-issued replacement"
                                )
                            sources = current_sources
                            # Native62330 re-reads the compacted pointer and name
                            # tables after61e40. The old group's width no longer
                            # governs traversal once its members became WHOLE.
                            cursor += 1
                            remaining: list[tuple[str, object]] = []
                            future = cursor
                            while future < len(sources.files):
                                following_group = sources.group_view2026(future)
                                following_view = (
                                    sources.file_view2026(future)
                                    if following_group is None
                                    else following_group.whole
                                )
                                remaining.append(("outer_next", following_view))
                                if following_group is not None:
                                    remaining.append(
                                        ("group_enter", following_group.whole)
                                    )
                                    remaining.extend(
                                        ("group_member", member)
                                        for member in following_group.members
                                    )
                                    remaining.append(
                                        ("group_whole", following_group.whole)
                                    )
                                    future += following_group.width
                                else:
                                    future += 1
                            projection_plan = (
                                list(
                                    self._judge_projection_plan2026[
                                        : self._judge_projection_ordinal2026
                                    ]
                                )
                                + remaining
                            )
                            self._judge_projection_plan2026 = tuple(projection_plan)
                        else:
                            cursor += group.width
                    if (
                        type(file_status) is not int
                        or not 0 <= file_status <= 0xFFFFFFFF
                    ):
                        raise ValueError("Native62330 status DWORD required")
                    if not before and file_check:
                        candidate_index = chosen
                    combined = combined or file_check
                    all_rows.extend(
                        self._judge_rows_as_raw2026(file_rows)[: caller_outputs.count]
                    )
                    rows_buffer[:] = all_rows
                    row_count_buffer[0] = len(rows_buffer)
                    boolean_buffer[0] = combined
                    if file_status == 3006:
                        status = file_status
                        break
                check_target = combined
            else:
                file_status, check_target, file_rows = (
                    self._judge_flashable_file_5ffc0_2026(
                        region, None, buffers=caller_outputs
                    )
                )
                status = file_status
                all_rows.extend(row.raw for row in file_rows[: caller_outputs.count])

            stable = (
                tuple(all_rows)
                if status == 3006 or direct_delta
                else _native_flashability_stable_rows62330_2026(tuple(all_rows))
            )
            rows_buffer[:] = stable
            row_count_buffer[0] = len(rows_buffer)
            boolean_buffer[0] = check_target
            if status == 0 and not direct_delta:
                persistence = self._engine._persistence
                if (
                    persistence is not None
                    and self._recovery_ec9b
                    and not self._recovery_ec9c
                ):
                    candidate_index = persistence.state.calibration_file_index
                current_sources = self._file_sources
                candidate = (
                    None
                    if current_sources is None
                    else (
                        current_sources.file_view2026(candidate_index)
                        if current_sources.has_file_vector
                        else current_sources.admission_view2026()
                    )
                )
                if not invocation.commit_started:
                    origin = self._commit_judge_candidate_49010_2026(
                        invocation,
                        region,
                        candidate,
                        status,
                        check_target,
                        stable,
                    )
                    if candidate is not None and candidate.kind != "none":
                        current_sources = self._file_sources
                        requested_slot = candidate.file_index
                        if current_sources is None or type(requested_slot) is not int:
                            raise ValueError(
                                "Final32ff0 requires its actual named FILE argument"
                            )
                        self._engine._accept_judge_committed_file_projection_32ff0_2026(
                            candidate, worker=self, origin=origin
                        )
                        self._apply_judge_parameters_41940_2026()
                        if (
                            current_sources.delta_map_size != 0
                            or not current_sources.delta_archive
                        ):
                            self._engine._received_identifiers = (
                                self._getter_flow_received_cids2026[requested_slot]
                            )
                            self._engine._identifier_records = (
                                self._getter_flow_query_records2026[requested_slot]
                            )
                        self._judge_wait_ready_marker2026 = origin
                        self._restore_judge_file_waits_32ff0_2026(
                            origin, requested_slot
                        )
                        self._restore_judge_file_selection_47e60_2026(origin)
            if status != 3006 and self._judge_projection_ordinal2026 != len(
                projection_plan
            ):
                raise ValueError("Native62330 traversal omitted a literal32ff0 call")

            metadata = self._engine.native_metadata
            pointer = self._capture_pointer_view2026(metadata)
            persistence = self._engine._persistence
            recovery_index = (
                0 if persistence is None else persistence.state.calibration_file_index
            )
            if pointer is None:
                live_kind: Literal["none", "plain", "part", "whole"] = "none"
                live_index = None
                live_digest = None
            else:
                if pointer.kind == "retained":
                    raise ValueError(
                        "Historical cold FILE pointer cannot finish native H"
                    )
                live_kind = pointer.kind
                live_index = pointer.file_index
                live_digest = pointer.source_sha256
            admission_digest = (
                metadata.source_sha256 if sources is None else sources.admission_sha256
            )
            return NativeFlashabilityResult2026(
                status,
                check_target,
                tuple(NativeFlashabilityRow2026(raw) for raw in rows_buffer),
                len(rows_buffer),
                sources,
                admission_digest,
                live_kind,
                live_index,
                live_digest,
                self._flow_file_index2026,
                recovery_index,
            )
        finally:
            self._pending_judge_commit2026 = None
            self._consumed_judge_commit2026 = None
            self._file_wait_restore_origin2026 = None
            self._judge_wait_ready_marker2026 = None
            self._judge_reset_point2026 = None
            self._judge_pointer_publication2026 = None
            self._frontend_selection_41940_point2026 = None
            self._judge_late_projection_point2026 = None
            self._judge_projection_point2026 = None
            self._judge_projection_plan2026 = ()
            self._judge_rows_buffer2026 = None
            self._judge_row_count_buffer2026 = None
            self._judge_boolean_buffer2026 = None
            self._judge_invocation2026 = None

    @staticmethod
    def _judge_rows_as_raw2026(rows) -> tuple[bytes, ...]:
        from scripts.cuw_2026 import NativeFlashabilityRow2026

        if type(rows) is not tuple:
            raise TypeError("Exact native62330 row tuple required")
        raw_rows = []
        for row in rows:
            if type(row) is NativeFlashabilityRow2026:
                raw_rows.append(row.raw)
            elif type(row) is bytes and len(row) == 333:
                raw_rows.append(row)
            else:
                raise TypeError("Native62330 row has an unsupported shape")
        return tuple(raw_rows)

    def _judge_flashable_group_61e40_2026(
        self, region: int, group, invocation, *, buffers=None
    ):
        """Run61e40 member scan, A48 refresh, whole recheck, and native branch."""
        from scripts.cuw_file_services import (
            FileSourceSet2026,
            NativeFileGroupView2026,
            validate_file_group_view_2026,
        )

        if buffers is None:
            buffers = _NativeJudgeRows2026()
        buffers.check_target = False
        member_outputs = _NativeJudgeRows2026()
        sources = self._file_sources
        if type(sources) is not FileSourceSet2026:
            raise ValueError("Actual61e40 source set required")
        direct = sources.delta_archive and sources.delta_map_size == 0
        if group is None:
            if not direct:
                raise ValueError("Mapped61e40 requires its actual group")
            start = 0
            whole = sources.admission_view2026()
            members = tuple(
                sources.file_view2026(index) for index in range(len(sources.files))
            )
            width = len(members)
        else:
            if type(group) is not NativeFileGroupView2026:
                raise ValueError("Actual61e40 source group required")
            validate_file_group_view_2026(group, sources)
            start, width, whole, members = (
                group.start,
                group.width,
                group.whole,
                group.members,
            )
        if start + width > 16:
            raise ValueError("61e40 group width exceeds its fixed source table")
        if sources.has_file_vector:
            self._publish_judge_file_projection_32ff0_2026(
                whole, region=region, site="group_enter"
            )
        cache_start = _native_a48_cache_slot2026(sources, start) if sources.files else 0
        if cache_start is None:
            raise ValueError("61e40 requires its authentic A48 cache mapping")
        a48 = self._getter_a48_received_cids2026
        if type(a48) is not tuple:
            raise ValueError("Actual46d60 A48 whole-CID cache required")
        chosen = 0
        any_eligible = False
        for member in members:
            self._publish_judge_file_projection_32ff0_2026(
                member, region=region, site="group_member"
            )
            member_index = member.file_index
            if member_index is None:
                raise ValueError("61e40 member has no actual FILE slot")
            member_cache_slot = _native_a48_cache_slot2026(sources, member_index)
            if member_cache_slot is None:
                raise ValueError("61e40 member lost its A48 pointer mapping")
            member_cached = self._getter_file_a48_received_cids2026[member_cache_slot]
            if type(member_cached) is tuple:
                a48 = member_cached
            status, check_target, rows = self._judge_flashable_file_5ffc0_2026(
                region, member, buffers=member_outputs
            )
            if type(status) is not int or not 0 <= status <= 0xFFFFFFFF:
                raise ValueError("Actual5ffc0 status DWORD required")
            if not any_eligible and check_target:
                chosen = member_index
            for row in rows:
                raw = row.raw
                old = raw[:0x22].split(b"\0", 1)[0]
                new = raw[0x22:0x44].split(b"\0", 1)[0]
                if raw[0x4B] != 0:
                    any_eligible = True
                    try:
                        position = a48.index(old)
                    except ValueError:
                        continue
                    replacement = list(a48)
                    replacement[position] = new
                    a48 = tuple(replacement)
            selection_cache = list(self._judge_a48_selection_by_file2026)
            selection_cache[member_cache_slot] = self._judge_a48_selection2026
            matches = list(self._judge_a48_matches_by_file2026)
            matches[member_cache_slot] = self._judge_a48_match2026
            self._judge_a48_matches_by_file2026 = tuple(matches)
            self._judge_a48_selection_by_file2026 = tuple(selection_cache)
            cache = list(self._getter_file_a48_received_cids2026)
            cache[member_cache_slot] = a48
            self._getter_a48_received_cids2026 = a48
            self._getter_file_a48_received_cids2026 = tuple(cache)
            if status == 3006:
                return status, buffers.check_target, buffers.rows, chosen, any_eligible

        persistence = self._engine._persistence
        if persistence is None:
            raise ValueError("Actual recovery override source required")
        persistence_state = persistence.state
        if self._recovery_ec9b and not self._recovery_ec9c:
            chosen = persistence_state.calibration_file_index
        # 46d60 replaces only the A48 received-CID vector from the last live member.
        live_received = self._engine.received_identifiers
        refreshed = list(self._getter_file_a48_received_cids2026)
        refreshed[cache_start] = live_received
        self._getter_a48_received_cids2026 = live_received
        selection_cache = list(self._judge_a48_selection_by_file2026)
        selection_cache[cache_start] = self._judge_a48_selection2026
        matches = list(self._judge_a48_matches_by_file2026)
        matches[cache_start] = self._judge_a48_match2026
        self._judge_a48_matches_by_file2026 = tuple(matches)
        self._judge_a48_selection_by_file2026 = tuple(selection_cache)
        self._getter_file_a48_received_cids2026 = tuple(refreshed)
        if sources.has_file_vector:
            self._publish_judge_file_projection_32ff0_2026(
                whole, region=region, site="group_whole"
            )
        buffers.rows = member_outputs.rows
        whole_status, whole_check, whole_rows = self._judge_flashable_file_5ffc0_2026(
            region, whole if sources.has_file_vector else None, buffers=buffers
        )
        if not whole_check:
            self._copy_judge_live_selection_47e60_2026()
            return (
                whole_status,
                whole_check,
                tuple(row.raw for row in whole_rows),
                chosen,
                any_eligible,
            )
        if not any_eligible:
            direct = sources.delta_archive and sources.delta_map_size == 0
            if direct:
                reset_origin = _NativeJudgeDirectResetOrigin2026(
                    self,
                    invocation,
                    sources,
                    whole,
                    region,
                    whole_check,
                    any_eligible,
                    tuple(row.raw for row in whole_rows),
                    threading.get_ident(),
                )
            else:
                assert group is not None
                reset_origin = _NativeJudgeGroupResetOrigin2026(
                    self,
                    invocation,
                    sources,
                    group,
                    region,
                    whole_check,
                    any_eligible,
                    tuple(row.raw for row in whole_rows),
                    threading.get_ident(),
                )
            if self._judge_reset_point2026 is not None:
                raise ValueError("Overlapping native mode1 reset point")
            self._judge_reset_point2026 = _NativeJudgeResetPoint2026(
                reset_origin,
                sources,
                None,
                "direct" if direct else "mapped",
                "factory",
                self._engine.native_metadata,
                whole,
                buffers,
                self._judge_rows_buffer2026,
                self._judge_row_count_buffer2026,
                self._judge_boolean_buffer2026,
                self._engine.configuration,
                self._getter_reset_epoch2026,
            )
            replacement = (
                sources._after_judge_direct_reset_4b900_2026(
                    whole, worker=self, origin=reset_origin
                )
                if direct
                else sources._after_judge_group_reset_4b900_2026(
                    cast(NativeFileGroupView2026, group),
                    worker=self,
                    origin=reset_origin,
                )
            )
            self._judge_reset_point2026.new_sources = replacement
            self._judge_reset_point2026.stage = "flow_pending" if direct else "prepared"
            self._engine._accept_judge_file_reset_4b900_2026(
                sources, replacement, worker=self, origin=reset_origin
            )
            self._copy_judge_live_selection_47e60_2026()
            return (
                whole_status,
                whole_check,
                tuple(row.raw for row in whole_rows),
                chosen,
                False,
            )
        if sources.delta_archive and sources.delta_map_size == 0:
            candidate = sources.file_view2026(chosen)
            origin = self._commit_judge_candidate_49010_2026(
                invocation,
                region,
                candidate,
                whole_status,
                whole_check,
                tuple(row.raw for row in whole_rows),
            )
            self._engine._accept_judge_committed_file_projection_32ff0_2026(
                candidate, worker=self, origin=origin
            )
            self._apply_judge_parameters_41940_2026()
            self._judge_wait_ready_marker2026 = origin
            self._restore_judge_file_waits_32ff0_2026(origin, chosen)
        self._copy_judge_live_selection_47e60_2026()
        return (
            whole_status,
            whole_check,
            tuple(row.raw for row in whole_rows),
            chosen,
            any_eligible,
        )

    def _require_judge_reset_point2026(self, origin):
        point = self._judge_reset_point2026
        if (
            point is None
            or point.origin is not origin
            or type(origin)
            not in (_NativeJudgeGroupResetOrigin2026, _NativeJudgeDirectResetOrigin2026)
            or origin.worker is not self
            or origin.invocation is not self._judge_invocation2026
            or origin.thread_id != threading.get_ident()
            or origin.whole_check is not True
            or origin.any_eligible is not False
            or point.configuration is not self._engine.configuration
            or point.reset_epoch != self._getter_reset_epoch2026
            or point.row_buffer is not self._judge_rows_buffer2026
            or point.count_buffer is not self._judge_row_count_buffer2026
            or point.boolean_buffer is not self._judge_boolean_buffer2026
            or not point.outputs.check_target
            or tuple(row.raw for row in point.outputs.rows) != origin.whole_rows
            or self._pending_judge_commit2026 is not None
            or self._judge_projection_point2026 is not None
        ):
            raise ValueError("Exact live61e40 mode1 reset point required")
        current = self._engine._require_judge_flashable_invocation2026(
            self, origin.region
        )
        if current is not origin.invocation or current.commit_started:
            raise ValueError("Mode1 reset belongs to another judge invocation")
        return point

    def _validate_judge_group_reset_origin2026(self, origin, group) -> None:
        from scripts.cuw_file_services import validate_file_group_view_2026

        point = self._require_judge_reset_point2026(origin)
        if (
            type(origin) is not _NativeJudgeGroupResetOrigin2026
            or point.branch != "mapped"
            or origin.group is not group
            or point.old_sources is not self._file_sources
            or point.stage not in ("factory", "prepared", "pointer_ready")
        ):
            raise ValueError("Exact mapped mode1 factory point required")
        validate_file_group_view_2026(group, point.old_sources)

    def _validate_judge_direct_reset_origin2026(self, origin, current_a48) -> None:
        from scripts.cuw_file_services import validate_file_view_2026

        point = self._require_judge_reset_point2026(origin)
        if (
            type(origin) is not _NativeJudgeDirectResetOrigin2026
            or point.branch != "direct"
            or origin.current_a48 is not current_a48
            or point.current_view is not current_a48
            or point.old_sources is not self._file_sources
            or not point.old_sources.delta_archive
            or point.old_sources.delta_map_size != 0
            or point.stage not in ("factory", "flow_pending", "pointer_ready")
            or self._engine.native_metadata is not point.runtime_metadata
        ):
            raise ValueError("Exact direct mode1 factory point required")
        validate_file_view_2026(current_a48, point.old_sources)

    def _validate_judge_file_reset_stage2026(
        self, origin, old_sources, new_sources
    ) -> str:
        point = self._require_judge_reset_point2026(origin)
        if (
            point.old_sources is not old_sources
            or point.new_sources is not new_sources
            or new_sources is None
            or self._file_sources is not old_sources
            or point.stage not in ("flow_pending", "prepared", "pointer_ready")
        ):
            raise ValueError("Exact factory-issued pending mode1 replacement required")
        return point.stage

    def _validate_judge_file_reset_publication2026(
        self, origin, old_sources, new_sources
    ):
        from scripts.cuw_file_services import validate_file_sources_2026

        point = self._require_judge_reset_point2026(origin)
        if (
            self._validate_judge_file_reset_stage2026(origin, old_sources, new_sources)
            != "pointer_ready"
        ):
            raise ValueError("Mode1 reset has not reached its pointer store")
        validate_file_sources_2026(new_sources, self._engine)
        metadata = point.runtime_metadata
        execution = new_sources.files or (metadata,)
        indices = [
            index
            for index, item in enumerate(execution)
            if item.source_container is metadata.source_container
            and item.source_sha256 == metadata.source_sha256
        ]
        if len(indices) != 1:
            raise ValueError("Mode1 replacement omits its exact current FILE")
        index = indices[0]
        view = (
            new_sources.file_view2026(index)
            if new_sources.has_file_vector
            else new_sources.admission_view2026()
        )
        if (
            view.source_container is not metadata.source_container
            or view.source_sha256 != metadata.source_sha256
        ):
            raise ValueError("Mode1 pointer differs from its retained runtime FILE")
        unresolved = tuple(_unresolved_selection(item) for item in execution)
        orders = tuple(order for _, order in unresolved)
        # Allocate and validate every projection component before the literal
        # pointer store. The publisher below performs assignments only.
        point.publication = {
            "_file_sources": new_sources,
            "_all_loaded_metadata": execution,
            "_online_loaded_metadata": new_sources.files,
            "_current_file_index": index,
            "_current_node": metadata.node,
            "_current_cpu_index": metadata.cpu_index,
            "_current_global_cpu_index": orders[index].index(
                native2026_global_cpu_index(metadata)
            ),
            "_targets_by_file": tuple(targets for targets, _ in unresolved),
            "_cpu_orders_by_file": orders,
            "_authored_cpu_orders_by_file": orders,
            "_unmatched_identifiers_by_file": tuple(() for _ in execution),
            "_unmatched_companions_by_file": tuple(() for _ in execution),
            "_authored_cpu_counts_by_file": (0,) * len(execution),
            "_authored_target_indices_by_file": tuple(
                (-1,) * native2026_cpu_count(item) for item in execution
            ),
            "_selections_by_file": (None,) * len(execution),
            "_cid_matches_by_file": (None,) * len(execution),
            "_cid_selected_files": set(),
            "_progress_base": sum(
                native2026_cpu_count(item) for item in execution[:index]
            ),
            "_delta_archive_active": new_sources.delta_archive,
            "_delta_archive_clone_match": point.branch == "direct",
        }
        return metadata, view

    def _publish_judge_file_reset_projection2026(self, origin) -> None:
        # Called only by36 immediately after the validated pointer_ready seam.
        # No validation, allocation, callbacks, or source work in this tail.
        point = cast(_NativeJudgeResetPoint2026, self._judge_reset_point2026)
        for name, value in cast(dict[str, object], point.publication).items():
            setattr(self, name, value)

    def _apply_judge_file_reset_before_pointer2026(self, origin) -> None:
        point = self._require_judge_reset_point2026(origin)
        expected = "flow_pending" if point.branch == "direct" else "prepared"
        if point.stage != expected or point.new_sources is None:
            raise ValueError("Mode1 prepointer source point was already consumed")
        configuration = self._engine.configuration
        if configuration is None:
            raise ValueError("Configured mode1 reset required")
        maximum = configuration.cpu_maximum
        if point.branch == "direct":
            if self._flow_file_index2026 != 0:
                raise ValueError("Actual46bee numeric store must precede46be0 clears")
            point.stage = "clearing"
            self._getter_authored_cpu_offset_a24_2026 = 0
            self._judge_file_selection_cache2026 = tuple(
                _NativeJudgeSelectionCache2026(targets=(-1,) * maximum)
                for _ in range(16)
            )
            self._judge_file_unmatched_9fc2026 = ()
            self._getter_flow_received_cids2026 = ((),) * 16
            self._getter_flow_query_records2026 = ((),) * 16
        else:
            group = origin.group
            start, width = group.start, group.width
            point.stage = "compacting"
            count = len(point.old_sources.files)

            def compact(values, empty):
                result = list(values)
                for index in range(start + 1, count):
                    previous = index + width - 1
                    result[index] = values[previous] if previous < count else empty
                return tuple(result)

            selection_cache = list(self._judge_file_selection_cache2026)
            cache_slot = _native_a48_cache_slot2026(point.old_sources, start)
            if cache_slot is None:
                raise ValueError("Mode1 reset lost its original A48 cache")
            saved = self._judge_a48_selection_by_file2026[cache_slot]
            point.saved_selection = saved
            point.saved_match = self._judge_a48_matches_by_file2026[cache_slot]
            point.saved_cids = self._getter_a48_received_cids2026
            selection_cache[start] = replace(
                selection_cache[start],
                targets=saved.targets,
                unmatched_ids=saved.unmatched_ids,
            )
            self._judge_file_selection_cache2026 = compact(
                tuple(selection_cache),
                _NativeJudgeSelectionCache2026(targets=(-1,) * maximum),
            )
            unmatched = list(self._judge_file_unmatched_9fc2026)
            unmatched[start] = saved.unmatched_ids
            del unmatched[start + 1 : start + width]
            self._judge_file_unmatched_9fc2026 = tuple(unmatched)
            self._judge_file_companions_a082026 = (
                self._judge_file_companions_a082026[: start + 1]
                + self._judge_file_companions_a082026[start + width :]
            )
            self._judge_file_counts_a142026 = (
                self._judge_file_counts_a142026[: start + 1]
                + self._judge_file_counts_a142026[start + width :]
            )
            # First32ff0(FALSE) sees the compacted WHOLE pointer outside the
            # original PART map and clears A48 before its pointer publication.
            self._judge_a48_selection2026 = _NativeJudgeSelectionCache2026()
            self._getter_flow_received_cids2026 = compact(
                self._getter_flow_received_cids2026, ()
            )
            self._getter_flow_query_records2026 = compact(
                self._getter_flow_query_records2026, ()
            )
            self._getter_configured_masks_4f0_2026 = compact(
                self._getter_configured_masks_4f0_2026, (False,) * maximum
            )
        point.stage = "pointer_ready"

    def _validate_judge_mode1_recovery_23b10_2026(self, origin):
        point = self._require_judge_reset_point2026(origin)
        if (
            point.branch != "mapped"
            or point.stage != "recovery_23b10"
            or point.new_sources is not self._file_sources
            or self._engine.file_sources is not point.new_sources
        ):
            raise ValueError("Exact late mapped mode1 recovery source point required")
        groups = point.old_sources.delta_groups
        group_index = next(
            index
            for index, (start, width, whole) in enumerate(groups)
            if whole.source_container is point.runtime_metadata.source_container
            and width == origin.group.width
        )
        return (
            point.old_sources,
            point.new_sources,
            point.current_view.original_recovery_index,
            point.runtime_metadata,
            point.old_sources.delta_group_names[group_index],
            point.old_sources.delta_group_sources[group_index],
        )

    def _apply_judge_file_reset_after_pointer2026(self, origin) -> None:
        point = self._require_judge_reset_point2026(origin)
        if (
            point.stage != "pointer_ready"
            or self._file_sources is not point.new_sources
            or self._engine.file_sources is not point.new_sources
        ):
            raise ValueError("Actual mode1 pointer publication required")
        point.stage = "first_41940"
        self._apply_judge_parameters_41940_2026()
        if point.branch == "mapped":
            start = origin.group.start
            self._engine._received_identifiers = self._getter_flow_received_cids2026[
                start
            ]
            self._engine._identifier_records = self._getter_flow_query_records2026[
                start
            ]
            point.stage = "first_waits"
            self._judge_wait_ready_marker2026 = origin
            self._restore_judge_file_waits_32ff0_2026(origin, start)
            point.stage = "cache_reload"
            self._judge_a48_selection2026 = cast(
                _NativeJudgeSelectionCache2026, point.saved_selection
            )
            self._getter_a48_received_cids2026 = point.saved_cids
            self._judge_a48_match2026 = point.saved_match
            self._delta_archive_clone_match = True
            start = origin.group.start
            point.stage = "second_41940"
            self._apply_judge_parameters_41940_2026()
            point.stage = "recovery_23b10"
            self._engine._apply_judge_mode1_recovery_23b10_2026(origin, worker=self)
        point.stage = "complete"
        self._judge_reset_point2026 = None

    def _commit_judge_candidate_49010_2026(
        self, invocation, region, candidate, status, flashable, rows
    ) -> _NativeJudgeCommitOrigin2026:
        from scripts.cuw_persistence import CUWPersistence, ReproInfoState

        persistence = self._engine._persistence
        if (
            type(persistence) is not CUWPersistence
            or type(persistence.state) is not ReproInfoState
            or invocation is not self._judge_invocation2026
        ):
            raise ValueError("Exact current49010 persistence and invocation required")
        origin = _NativeJudgeCommitOrigin2026(
            self,
            self._engine,
            invocation,
            region,
            threading.get_ident(),
            self._file_sources,
            candidate,
            self._flow_file_index2026,
            self._engine.native_metadata,
            persistence,
            persistence.state,
            status,
            flashable,
            rows,
        )
        if self._pending_judge_commit2026 is not None:
            raise ValueError("Nested native49010 candidate commit")
        self._pending_judge_commit2026 = origin
        try:
            self._engine._commit_judge_file_49010_2026(
                candidate, worker=self, origin=origin
            )
            return origin
        finally:
            if self._pending_judge_commit2026 is origin:
                self._pending_judge_commit2026 = None

    def _validate_judge_commit_origin_62330_2026(self, origin, candidate) -> None:
        from scripts.cuw_file_services import NativeFileView2026
        from scripts.cuw_persistence import CUWPersistence, ReproInfoState

        if (
            type(origin) is not _NativeJudgeCommitOrigin2026
            or self._pending_judge_commit2026 is not origin
            or origin.worker is not self
            or origin.engine is not self._engine
            or origin.invocation is not self._judge_invocation2026
            or origin.thread_id != threading.get_ident()
            or origin.file_sources is not self._file_sources
            or origin.candidate is not candidate
            or (candidate is not None and type(candidate) is not NativeFileView2026)
            or origin.before_flow != self._flow_file_index2026
            or origin.before_metadata is not self._engine.native_metadata
            or type(origin.persistence) is not CUWPersistence
            or self._engine._persistence is not origin.persistence
            or type(origin.persistence_state) is not ReproInfoState
            or origin.persistence.state is not origin.persistence_state
            or self._consumed_judge_commit2026 is not None
        ):
            raise ValueError("Exact unconsumed source-issued49010 origin required")
        current = self._engine._require_judge_flashable_invocation2026(
            self, origin.region
        )
        if current is not origin.invocation:
            raise ValueError("49010 origin belongs to another public judge call")
        self._consumed_judge_commit2026 = origin
        self._pending_judge_commit2026 = None

    def _complete_getter_3d120_2026(self, decision):
        """Run the authenticated common3d120 body and its actual selected branch."""
        from scripts.cuw_engine_threads import (
            EngineThreadJob2026,
            _CompletionRecord2026,
            _NativeGetterDecision2026,
            _NativeGetterNextEntryOrigin2026,
        )
        from scripts.cuw_file_services import (
            FileSourceSet2026,
            NativeFileGroupView2026,
            NativeFileView2026,
            validate_file_group_view_2026,
            validate_file_sources_2026,
            validate_file_view_2026,
        )
        from scripts.programming_2026_common import NativeControlGetterOutput2026
        from scripts.programming_replay import ProgrammingReplay

        job = self._engine.thread_job
        if (
            type(decision) is not _NativeGetterDecision2026
            or type(job) is not EngineThreadJob2026
            or decision.job is not job
            or decision.worker is not self
            or decision.route != "success_3d120"
        ):
            raise ValueError("Exact successful native getter decision required")
        job._validate_getter_decision_2026(decision, route="success_3d120")
        candidate = decision.candidate
        context = candidate.execute_record.context
        output = self._imported_getter_output2026(context)
        p6_imported = (
            self._imported_phase6_getter_receipt2026(context, job, candidate.sequence)
            is not None
        )
        if not (
            (
                type(output) is NativeControlGetterOutput2026
                and candidate.output is output
            )
            or (output is None and candidate.output is None and p6_imported)
        ):
            raise ValueError("Successful G requires complete imported CanCID output")

        sources = self._file_sources
        if sources is not None:
            if type(sources) is not FileSourceSet2026:
                raise TypeError("Exact issued FILE source set required")
            validate_file_sources_2026(sources, self._engine)
        current_flow = self._flow_file_index2026
        pointer_view = self._capture_pointer_view2026(self._engine.native_metadata)
        named_table = bool(
            sources is not None
            and sources.has_file_vector
            and any(sources.table_file_names)
        )
        if named_table:
            assert sources is not None
            if not 0 <= current_flow < len(sources.files) or current_flow >= 16:
                raise ValueError("Named native getter flow is outside its table")
            if type(pointer_view) is not NativeFileView2026:
                raise ValueError("Actual current native pointer view required")
            validate_file_view_2026(pointer_view, sources)
            current_flow_view = sources.file_view2026(current_flow)
            group = sources.group_view2026(current_flow)
            if group is not None:
                if (
                    type(group) is not NativeFileGroupView2026
                    or group.start != current_flow
                ):
                    raise ValueError(
                        "Current D71C is not the start of its native group"
                    )
                validate_file_group_view_2026(group, sources)
                fanout_count = group.width - 1
            else:
                fanout_count = 0
            after_fanout = current_flow + fanout_count
            names = sources.table_file_names
            following = after_fanout + 1
            has_next_name = (
                following < 15
                and following < len(sources.files)
                and following < len(names)
                and bool(names[following])
            )
            named_next = bool(
                has_next_name
                and (sources.delta_map_size != 0 or not sources.delta_archive)
            )
            if named_next:
                next_flow = following
                next_flow_view = sources.file_view2026(next_flow)
                next_group = sources.group_view2026(next_flow)
                next_pointer_view = (
                    next_group.whole if next_group is not None else next_flow_view
                )
                validate_file_view_2026(next_pointer_view, sources)
                projected_metadata = self._project_getter_file_metadata2026(
                    next_pointer_view
                )
                origin = job._issue_getter_next_entry_3d120_2026(
                    decision,
                    source_set=sources,
                    current_flow_view=current_flow_view,
                    current_pointer_view=pointer_view,
                    fanout_group=group,
                    next_flow_view=next_flow_view,
                    next_pointer_view=next_pointer_view,
                    projected_metadata=projected_metadata,
                )
                branch = "named_next"
            else:
                origin = job._issue_getter_noncontinuing_3d120_2026(
                    decision, worker=self
                )
                branch = "named_terminal"
        else:
            if current_flow != 0:
                raise ValueError("No-table native getter must retain flow zero")
            current_flow_view = None
            group = None
            fanout_count = 0
            next_flow = None
            next_flow_view = None
            next_pointer_view = None
            projected_metadata = None
            origin = job._issue_getter_noncontinuing_3d120_2026(decision, worker=self)
            branch = "no_table"

        if type(origin) is not _NativeGetterNextEntryOrigin2026:
            raise TypeError("Exact source-issued G origin required")
        from scripts.cuw_persistence import CUWPersistence, ReproInfoState

        observation = origin.observation
        persistence = origin.persistence
        persistence_state = origin.persistence_state
        if (
            type(observation) is not _NativeGetterObservation2026
            or type(persistence) is not CUWPersistence
            or type(persistence_state) is not ReproInfoState
            or observation.file_sources is not sources
            or observation.flow_file_index != current_flow
            or persistence is not self._engine._persistence
            or persistence.state is not persistence_state
        ):
            raise ValueError("G origin does not bind the exact observation")
        persistence = cast(CUWPersistence, persistence)
        persistence_state = cast(ReproInfoState, persistence_state)
        observation = cast(_NativeGetterObservation2026, observation)
        reproinfo_values = self._prepare_reproinfo_getter_write_3d120_2026(
            observation, persistence, persistence_state, pointer_view, group
        )
        # The opaque issuer must still prove the exact current origin immediately
        # before the first irreversible source store.
        job._validate_getter_3d120_origin2026(origin, worker=self)
        self._apply_reproinfo_getter_write_3d120_2026(
            persistence, persistence_state, reproinfo_values
        )
        job._advance_getter_3d120_origin2026(origin, worker=self, stage="reproinfo")

        # C179–195: actual per-FILE A28 raw query record cache.
        query_cache = list(self._getter_flow_query_records2026)
        query_cache[current_flow] = observation.query_records
        self._getter_flow_query_records2026 = tuple(query_cache)
        job._advance_getter_3d120_origin2026(origin, worker=self, stage="query_cache")

        self._merge_getter_history_3d120_2026(current_flow, observation)
        self._getter_observation_sequence2026 += 1
        self._getter_last_observation2026 = observation
        job._advance_getter_3d120_origin2026(origin, worker=self, stage="history")

        self._clear_getter_live_auxiliary_43ab0_2026()
        job._advance_getter_3d120_origin2026(origin, worker=self, stage="scratch")

        flow_cids = list(self._getter_flow_received_cids2026)
        flow_cids[current_flow] = observation.received_cids
        self._getter_flow_received_cids2026 = tuple(flow_cids)
        job._advance_getter_3d120_origin2026(origin, worker=self, stage="flow_cache")

        before = current_flow
        if group is not None:
            assert sources is not None
            self._refresh_getter_group_whole_46d60_2026(group, observation)
            fanout_result = self._fanout_getter_group_3d120_2026(group, observation)
            if fanout_result != fanout_count:
                raise ValueError("Native67680 result differs from stored group width")
            if fanout_result:
                self._flow_file_index2026 += fanout_result
                flow_view = sources.file_view2026(self._flow_file_index2026)
                self._engine._record_file_flow_transition2026(
                    worker=self,
                    origin=origin,
                    producer="3d120-fanout",
                    old_sources=sources,
                    new_sources=sources,
                    before_flow=before,
                    after_flow=self._flow_file_index2026,
                    flow_view=flow_view,
                    current_pointer_view=pointer_view,
                )
            job._advance_getter_3d120_origin2026(origin, worker=self, stage="fanout")

        if branch == "named_next":
            assert sources is not None and next_flow is not None
            assert next_pointer_view is not None
            before = self._flow_file_index2026
            self._flow_file_index2026 += 1
            flow_view = sources.file_view2026(self._flow_file_index2026)
            self._engine._record_file_flow_transition2026(
                worker=self,
                origin=origin,
                producer="3d120-next",
                old_sources=sources,
                new_sources=sources,
                before_flow=before,
                after_flow=self._flow_file_index2026,
                flow_view=flow_view,
                current_pointer_view=pointer_view,
            )
            job._advance_getter_3d120_origin2026(origin, worker=self, stage="flow")
            self._engine._accept_getter_file_projection_32ff0_2026(
                next_pointer_view, worker=self, origin=origin
            )
            self._apply_getter_file_projection_tail_32ff0_2026(
                origin, next_pointer_view
            )
            job._advance_getter_3d120_origin2026(
                origin, worker=self, stage="projection"
            )
            self._apply_getter_entry_34cb0_2026(origin=origin)
            job._advance_getter_3d120_origin2026(origin, worker=self, stage="reset")
        elif branch == "named_terminal":
            assert sources is not None
            before = self._flow_file_index2026
            self._flow_file_index2026 = 0
            flow_view = sources.file_view2026(0)
            self._engine._record_file_flow_transition2026(
                worker=self,
                origin=origin,
                producer="3d120-end",
                old_sources=sources,
                new_sources=sources,
                before_flow=before,
                after_flow=0,
                flow_view=flow_view,
                current_pointer_view=pointer_view,
            )
            job._advance_getter_3d120_origin2026(origin, worker=self, stage="flow")
            self._engine._accept_getter_file_projection_32ff0_2026(
                flow_view, worker=self, origin=origin
            )
            self._apply_getter_file_projection_tail_32ff0_2026(origin, flow_view)
            job._advance_getter_3d120_origin2026(
                origin, worker=self, stage="projection"
            )
            if sources.delta_archive and sources.delta_map_size == 0:
                self._refresh_getter_group_whole_46d60_2026(None, observation)
                masks = list(self._getter_configured_masks_4f0_2026)
                for index, name in enumerate(sources.table_file_names):
                    if not name:
                        break
                    masks[index] = observation.configured_bits
                self._getter_configured_masks_4f0_2026 = tuple(masks)
            with persistence._lock:
                persistence_state.can_ids_from_get_cid = tuple(
                    address.request.hex().upper()
                    for address in observation.communication_addresses
                )
            job._advance_getter_3d120_origin2026(origin, worker=self, stage="terminal")
        else:
            job._advance_getter_3d120_origin2026(origin, worker=self, stage="flow")
            job._advance_getter_3d120_origin2026(origin, worker=self, stage="terminal")

        job._advance_getter_3d120_origin2026(origin, worker=self, stage="protocol_tail")
        protocol_tail_value = None
        if not observation.sequence_changed_39c:
            metadata = self._engine.native_metadata
            cpu_type = native2026_cpu_type(
                metadata, native2026_global_cpu_index(metadata)
            )
            should_change_protocol = self._engine.general_parameter_boolean(
                metadata.vehicle.get("kindofecu", ""),
                cpu_type,
                metadata.vehicle.get("contacttype", ""),
                "FlagToChangeProtocolAtSuccessGetCID",
                controller=self._controller,
            )
            if should_change_protocol:
                post_tail_metadata = self._engine._apply_getter_protocol_173d0_2026(
                    origin, worker=self
                )
                protocol_tail_value = self._engine._getter_protocol_4fc_2026
                if (
                    type(protocol_tail_value) is not str
                    or persistence_state.contact_type_at_success_get_cid
                    != protocol_tail_value
                ):
                    raise ValueError("Native173d0 protocol tail was not committed")
            else:
                job._validate_getter_3d120_origin2026(origin, worker=self)
                post_tail_metadata = self._engine.native_metadata
        else:
            job._validate_getter_3d120_origin2026(origin, worker=self)
            post_tail_metadata = self._engine.native_metadata
        if (
            post_tail_metadata.source_container
            is not self._engine.native_metadata.source_container
            or post_tail_metadata.source_sha256
            != self._engine.native_metadata.source_sha256
            or persistence is not self._engine._persistence
            or persistence.state is not persistence_state
        ):
            raise ValueError("Completed getter tail differs from its source aggregate")
        job._advance_getter_3d120_origin2026(origin, worker=self, stage="complete")
        if branch != "named_next":
            return None

        assert sources is not None and next_flow_view is not None
        flow_view = sources.file_view2026(self._flow_file_index2026)
        pointer_view = self._capture_pointer_view2026(self._engine.native_metadata)
        if type(pointer_view) is not NativeFileView2026:
            raise ValueError("Completed getter pointer view is unavailable")
        session = job._session
        completion = job._active_record
        if (
            type(session) is not ProgrammingReplay
            or type(completion) is not _CompletionRecord2026
        ):
            raise ValueError("Completed getter lost its actual old lineage")
        entry = _NativeGetterContinuation2026(
            self,
            job,
            decision.sequence,
            decision.lease,
            session,
            completion,
            sources,
            self._flow_file_index2026,
            flow_view,
            pointer_view,
            self._getter_reset_epoch2026,
            observation,
            decision.decision_sequence,
            context._capture._import_epoch,
            post_tail_metadata,
            protocol_tail_value,
            persistence,
            persistence_state,
        )
        self._issued_getter_continuation2026 = entry
        return entry

    def _validate_file_flow_transition_origin2026(
        self,
        origin: object,
        *,
        producer: str,
        old_sources,
        new_sources,
        before_flow: int,
        after_flow: int,
        flow_view,
        current_pointer_view,
    ) -> None:
        """Validate one D71C writer against the current opaque3d120 stage."""
        from scripts.cuw_engine_threads import EngineThreadJob2026
        from scripts.cuw_file_services import (
            FileSourceSet2026,
            NativeFileView2026,
            validate_file_sources_2026,
            validate_file_view_2026,
        )

        job = self._engine.thread_job
        if type(job) is not EngineThreadJob2026 or job.worker is not self:
            raise ValueError("Current authenticated getter job required")
        if producer == "3d120-next":
            job._validate_getter_next_entry_3d120_2026(origin, worker=self)
        else:
            job._validate_getter_3d120_origin2026(origin, worker=self)
        sources = self._file_sources
        if (
            producer not in ("3d120-fanout", "3d120-next", "3d120-end")
            or type(sources) is not FileSourceSet2026
            or old_sources is not sources
            or new_sources is not sources
            or type(before_flow) is not int
            or type(after_flow) is not int
            or after_flow != self._flow_file_index2026
            or type(flow_view) is not NativeFileView2026
            or type(current_pointer_view) is not NativeFileView2026
        ):
            raise ValueError("Exact current native D71C transition required")
        if producer == "3d120-next":
            next_index = before_flow + 1
            if (
                after_flow != before_flow + 1
                or after_flow != next_index
                or after_flow >= 15
                or after_flow >= len(sources.files)
                or after_flow >= len(sources.table_file_names)
                or not sources.table_file_names[after_flow]
                or (sources.delta_archive and sources.delta_map_size == 0)
            ):
                raise ValueError("Native next D71C transition differs from source")
        elif producer == "3d120-fanout":
            group = sources.group_view2026(before_flow)
            if (
                group is None
                or group.start != before_flow
                or after_flow != before_flow + group.width - 1
            ):
                raise ValueError("Native group transition differs from stored width")
        else:
            following = before_flow + 1
            has_next = (
                following < 15
                and following < len(sources.files)
                and following < len(sources.table_file_names)
                and bool(sources.table_file_names[following])
                and (sources.delta_map_size != 0 or not sources.delta_archive)
            )
            if after_flow != 0 or has_next:
                raise ValueError("Native end D71C transition differs from terminal")
        if producer not in ("3d120-fanout", "3d120-next", "3d120-end") or (
            producer == "3d120-fanout" and after_flow < before_flow
        ):
            raise ValueError("Native D71C transition differs from its source branch")
        validate_file_sources_2026(sources, self._engine)
        if sources.has_file_vector:
            if not 0 <= after_flow < len(sources.files):
                raise ValueError("Native D71C transition exceeds the issued table")
            expected_flow = sources.file_view2026(after_flow)
            if flow_view is not expected_flow:
                raise ValueError("Native D71C flow view is not the current table slot")
        elif after_flow != 0 or flow_view.kind != "none":
            raise ValueError("No-table native flow must remain at zero")
        validate_file_view_2026(flow_view, sources)
        validate_file_view_2026(current_pointer_view, sources)
        current = self._engine.native_metadata
        if (
            current_pointer_view.source_container is not current.source_container
            or current_pointer_view.source_sha256 != current.source_sha256
        ):
            raise ValueError("D71C transition pointer differs from current metadata")

    def _validate_file_projection_origin2026(self, origin, view):
        """Return only the runtime CPU projection bound to a live32ff0 stage."""
        from scripts.calibration_2026 import (
            Native2026Metadata,
            native2026_metadata_for_cpu,
            native2026_validate_runtime_metadata,
        )
        from scripts.cuw_engine_threads import EngineThreadJob2026
        from scripts.cuw_file_services import (
            NativeFileView2026,
            validate_file_sources_2026,
            validate_file_view_2026,
        )

        job = self._engine.thread_job
        sources = self._file_sources
        if (
            type(job) is not EngineThreadJob2026
            or job.worker is not self
            or sources is None
            or type(view) is not NativeFileView2026
        ):
            raise ValueError("Current authenticated FILE projection required")
        if self._flow_file_index2026 == 0 and view.file_index == 0:
            job._validate_getter_3d120_origin2026(origin, worker=self)
            terminal_view = True
        else:
            job._validate_getter_next_entry_3d120_2026(origin, worker=self)
            terminal_view = False
        validate_file_sources_2026(sources, self._engine)
        validate_file_view_2026(view, sources)
        slot = self._flow_file_index2026
        group = sources.group_view2026(slot)
        expected = (
            group.whole
            if not terminal_view and group is not None
            else sources.file_view2026(slot)
        )
        if (
            not sources.has_file_vector
            or view is not expected
            or (terminal_view and slot != 0)
        ):
            raise ValueError(
                "32ff0 projection differs from its literal slot/TRUE branch"
            )
        cached = self._engine._worker_target_sources.get(id(view.source_container))
        base = view.metadata if cached is None else cached
        if (
            type(base) is not Native2026Metadata
            or base.source_container is not view.source_container
            or base.source_sha256 != view.source_sha256
            or base.region != view.metadata.region
            or self._engine._parser_profile(base) != base
        ):
            raise ValueError("Runtime FILE projection is outside its issued source")
        projected = native2026_metadata_for_cpu(base, self._current_global_cpu_index)
        native2026_validate_runtime_metadata(projected)
        if (
            projected.source_container is not view.source_container
            or projected.source_sha256 != view.source_sha256
            or projected.region != view.metadata.region
            or self._engine._parser_profile(projected) != projected
        ):
            raise ValueError("Runtime FILE projection differs from its source view")
        issued_projection = origin.projected_metadata
        if (
            type(issued_projection) is not Native2026Metadata
            or issued_projection != projected
            or issued_projection.source_container is not projected.source_container
        ):
            raise ValueError("32ff0 projection differs from its exact issued origin")
        self._prepare_judge_pointer_mirror_32ff0_2026(origin, issued_projection, view)
        return issued_projection

    def _validate_file_flow_clear_origin2026(self, origin: object) -> None:
        """Validate the already-consumed H origin at the later source clear."""
        if (
            type(origin) is not _NativeJudgeCommitOrigin2026
            or self._consumed_judge_commit2026 is not origin
            or origin.worker is not self
            or origin.engine is not self._engine
            or origin.invocation is not self._judge_invocation2026
            or origin.thread_id != threading.get_ident()
            or origin.file_sources is not self._file_sources
        ):
            raise ValueError("Consumed source-issued H commit required")
        self._engine._validate_judge_commit_stage_49010_2026(
            origin, worker=self, candidate=origin.candidate
        )

    def _prepare_judge_pointer_mirror_32ff0_2026(self, origin, metadata, view) -> None:
        """Precompute the current runtime FILE mirror before the pointer store."""
        sources = self._file_sources
        if sources is None or view.file_index is None:
            raise ValueError("Named judge pointer mirror requires its actual FILE slot")
        execution = list(sources.files)
        index = view.file_index
        execution[index] = metadata
        unresolved = tuple(_unresolved_selection(item) for item in execution)
        count = len(execution)
        targets = (
            list(self._targets_by_file)
            if len(self._targets_by_file) == count
            else [item[0] for item in unresolved]
        )
        orders = (
            list(self._cpu_orders_by_file)
            if len(self._cpu_orders_by_file) == count
            else [item[1] for item in unresolved]
        )
        authored = (
            list(self._authored_cpu_orders_by_file)
            if len(self._authored_cpu_orders_by_file) == count
            else list(orders)
        )
        # 32ff0 doesn't run3e710. Rebuilt FILE order remains in its real cached
        # metadata; another FILE's target/order mirror cannot be reused here.
        targets[index], orders[index] = _unresolved_selection(metadata)
        authored[index] = orders[index]
        extra = {}
        for name, empty in (
            ("_unmatched_identifiers_by_file", ()),
            ("_unmatched_companions_by_file", ()),
            ("_authored_cpu_counts_by_file", 0),
            ("_authored_target_indices_by_file", ()),
            ("_selections_by_file", None),
            ("_cid_matches_by_file", None),
        ):
            values = getattr(self, name)
            extra[name] = (
                values if len(values) == count else tuple(empty for _ in execution)
            )
        self._judge_pointer_publication2026 = (
            origin,
            {
                **extra,
                "_all_loaded_metadata": tuple(execution),
                "_current_file_index": index,
                "_current_node": metadata.node,
                "_current_cpu_index": metadata.cpu_index,
                "_delta_archive_clone_match": bool(
                    sources.delta_archive
                    and view.kind == "whole"
                    and (
                        sources.delta_map_size == 0
                        or _native_a48_cache_slot2026(sources, index) is not None
                    )
                ),
                "_targets_by_file": tuple(targets),
                "_cpu_orders_by_file": tuple(orders),
                "_authored_cpu_orders_by_file": tuple(authored),
                "_progress_base": sum(
                    native2026_cpu_count(item) for item in execution[:index]
                ),
            },
        )

    def _publish_judge_pointer_mirror_32ff0_2026(self, origin) -> None:
        pending = self._judge_pointer_publication2026
        if pending is None or pending[0] is not origin:
            raise ValueError("Exact precomputed judge pointer publication required")
        for name, value in pending[1].items():
            setattr(self, name, value)
        self._judge_pointer_publication2026 = None

    def _validate_judge_commit_projection_origin_2026(
        self, view, *, worker, origin
    ) -> Native2026Metadata:
        """Validate only the final post-49010 pointer projection."""
        from scripts.cuw_file_services import (
            NativeFileView2026,
            validate_file_sources_2026,
            validate_file_view_2026,
        )

        if (
            worker is not self
            or type(origin) is not _NativeJudgeCommitOrigin2026
            or self._consumed_judge_commit2026 is not origin
            or origin.worker is not self
            or origin.engine is not self._engine
            or origin.invocation is not self._judge_invocation2026
            or origin.thread_id != threading.get_ident()
            or origin.file_sources is not self._file_sources
            or origin.candidate is not view
            or type(view) is not NativeFileView2026
        ):
            raise ValueError("Exact committed source FILE projection required")
        self._engine._validate_judge_commit_stage_49010_2026(
            origin, worker=self, candidate=view
        )
        sources = self._file_sources
        if sources is None:
            raise ValueError("Committed FILE projection requires its source set")
        validate_file_sources_2026(sources, self._engine)
        validate_file_view_2026(view, sources)
        if view.file_index != self._flow_file_index2026:
            raise ValueError("Final FILE projection differs from committed D71C")
        projected = self._project_getter_file_metadata2026(view)
        self._prepare_judge_pointer_mirror_32ff0_2026(origin, projected, view)
        return projected

    def _validate_judge_file_projection_origin_2026(
        self, view, *, worker, region: int, invocation
    ):
        """Validate a transient32ff0 view in the active public judge invocation."""
        from scripts.calibration_2026 import Native2026Metadata
        from scripts.cuw_file_services import (
            FileSourceSet2026,
            NativeFileView2026,
            validate_file_sources_2026,
            validate_file_view_2026,
        )

        point = self._judge_projection_point2026
        if (
            worker is not self
            or invocation is not self._judge_invocation2026
            or type(point) is not _NativeJudgeProjectionPoint2026
            or point.invocation is not invocation
            or point.view is not view
            or point.thread_id != threading.get_ident()
            or point.ordinal != self._judge_projection_ordinal2026
            or point.row_buffer is not self._judge_rows_buffer2026
            or point.row_count_buffer is not self._judge_row_count_buffer2026
            or point.boolean_buffer is not self._judge_boolean_buffer2026
            or self._judge_rows_buffer2026 is None
            or self._judge_row_count_buffer2026 is None
            or self._judge_boolean_buffer2026 is None
            or tuple(self._judge_rows_buffer2026) != point.rows_snapshot
            or self._judge_row_count_buffer2026[0] != point.row_count_value
            or self._judge_boolean_buffer2026[0] is not point.boolean_value
            or type(view) is not NativeFileView2026
            or type(region) is not int
            or not 1 <= region <= 4
        ):
            raise ValueError("Exact live H projection identity required")
        current_invocation = self._engine._require_judge_flashable_invocation2026(
            self, region
        )
        if current_invocation is not invocation:
            raise ValueError("H projection belongs to another judge invocation")
        if invocation.commit_started:
            raise ValueError("Intermediate H projection follows final commit")
        sources = self._file_sources
        if type(sources) is not FileSourceSet2026:
            raise ValueError("A named H projection requires the issued FILE table")
        validate_file_sources_2026(sources, self._engine)
        validate_file_view_2026(view, sources)
        plan = self._judge_projection_plan2026
        group = (
            sources.group_view2026(view.file_index)
            if view.file_index is not None
            else None
        )
        canonical = (
            group.whole
            if view.kind == "whole" and group is not None
            else sources.file_view2026(view.file_index)
            if view.file_index is not None
            else None
        )
        if (
            point.ordinal >= len(plan)
            or plan[point.ordinal][0] != point.site
            or plan[point.ordinal][1] is not view
            or view.file_index is None
            or not 0 <= view.file_index < len(sources.files)
            or canonical is not view
        ):
            raise ValueError("H projection differs from the exact source call site")
        projected = self._project_getter_file_metadata2026(view)
        if (
            type(projected) is not Native2026Metadata
            or projected.source_container is not view.source_container
            or projected.source_sha256 != view.source_sha256
        ):
            raise ValueError("H projection differs from its issued source")
        self._prepare_judge_pointer_mirror_32ff0_2026(invocation, projected, view)
        self._judge_late_projection_point2026 = point
        self._judge_projection_point2026 = None
        self._judge_projection_ordinal2026 += 1
        return projected

    def _publish_judge_file_projection_32ff0_2026(
        self, view, *, region: int, site: str
    ) -> None:
        """Publish one literal32ff0 projection at its precomputed scan point."""
        if (
            type(site) is not str
            or self._judge_projection_point2026 is not None
            or self._judge_projection_ordinal2026
            >= len(self._judge_projection_plan2026)
            or self._judge_projection_plan2026[self._judge_projection_ordinal2026][0]
            != site
            or self._judge_projection_plan2026[self._judge_projection_ordinal2026][1]
            is not view
            or self._judge_rows_buffer2026 is None
            or self._judge_row_count_buffer2026 is None
            or self._judge_boolean_buffer2026 is None
        ):
            raise ValueError("Out-of-order native32ff0 scan point")
        invocation = self._judge_invocation2026
        if invocation is None:
            raise ValueError("Active public native judge required")
        point = _NativeJudgeProjectionPoint2026(
            invocation,
            view,
            site,
            self._judge_projection_ordinal2026,
            threading.get_ident(),
            self._judge_rows_buffer2026,
            self._judge_row_count_buffer2026,
            self._judge_boolean_buffer2026,
            tuple(self._judge_rows_buffer2026),
            self._judge_row_count_buffer2026[0],
            self._judge_boolean_buffer2026[0],
        )
        sources = self._file_sources
        if sources is None:
            raise ValueError("Named32ff0 source set required")
        cache_slot = _native_a48_cache_slot2026(sources, view.file_index)
        if cache_slot is not None:
            self._judge_a48_selection2026 = self._judge_a48_selection_by_file2026[
                cache_slot
            ]
            self._judge_a48_match2026 = self._judge_a48_matches_by_file2026[cache_slot]
            cached_cids = self._getter_file_a48_received_cids2026[cache_slot]
            self._getter_a48_received_cids2026 = (
                () if cached_cids is None else cached_cids
            )
        elif sources.delta_archive and sources.delta_map_size != 0:
            self._judge_a48_selection2026 = _NativeJudgeSelectionCache2026()
            self._getter_a48_received_cids2026 = ()
            self._judge_a48_match2026 = None
        self._judge_projection_point2026 = point
        try:
            self._engine._accept_judge_file_projection_32ff0_2026(view, worker=self)
            self._apply_judge_parameters_41940_2026()
            sources = self._file_sources
            if sources is not None and (
                sources.delta_map_size != 0 or not sources.delta_archive
            ):
                index = view.file_index
                self._engine._received_identifiers = (
                    self._getter_flow_received_cids2026[index]
                )
                self._engine._identifier_records = self._getter_flow_query_records2026[
                    index
                ]
            self._judge_wait_ready_marker2026 = point
            self._restore_judge_file_waits_32ff0_2026(point, view.file_index)
        except BaseException:
            if self._judge_projection_point2026 is point:
                self._judge_projection_point2026 = None
            raise

    def _apply_initial_getter_reset_40580_2026(self, origin: object) -> None:
        """Project one cold source-issued reset onto its unpublished worker."""
        from scripts.cuw_2026 import _InitialGetterReset40580_2026

        if type(origin) is not _InitialGetterReset40580_2026:
            raise TypeError("Exact source-issued initial getter reset required")
        with self._lock:
            if (
                self._closed
                or self._getter_reset_epoch2026 != 0
                or self._getter_ordinary_return_sequence2026 != 0
                or self._getter_observation_sequence2026 != 0
                or self._imported_getter_output_ref2026 is not None
                or self._control_file_capture is not None
                or self._control_return_receipt2026 is not None
                or self._sbr_ssm_producer2026 is not None
                or self._control_scratch_reset_pending2026
                or self._pending_continuation is not None
                or self._continuation_sequence != 0
            ):
                raise ValueError("Fresh unpublished worker required for initial reset")
            with _ISSUE_LOCK:
                reference = _ISSUED.get(self._engine)
                if (
                    reference is None
                    or reference() is not self
                    or getattr(self._controller, "worker", None) is not self
                    or self._engine._worker is not None
                ):
                    raise ValueError("Current unpublished worker issuance required")
            self.validate_source(self._engine)
            self._reset_getter_history_and_aux_40580_2026(origin)

    def _cleanup_reset_after_40580(self, cleanup) -> None:
        """Reset worker-owned globals after135 released targets/device/vectors."""
        from scripts.cuw_engine_cleanup import EngineCleanup2026

        if type(cleanup) is not EngineCleanup2026:
            raise TypeError("Actual source-issued engine cleanup required")
        cleanup.validate_owner(self._engine, self)
        if cleanup.state.trace[-3:] != [
            "global-prefix-reset",
            "device-clear",
            "vectors-reset",
        ]:
            raise ValueError("Engine cleanup has not reached worker reset chronology")
        configuration = self._engine.configuration
        if configuration is None:
            raise ValueError("Configured getter capacity required at 40580 reset")
        maximum = configuration.cpu_maximum
        with self._lock:
            self._cid_rebuild_done_3542026 = False
            self._retained_cpu_type = ""
            self._prepare_handshake = 0
            self._battery_voltage = None
            self._complete = self._fatal = self._failed = False
            self._native_fatal_input = False
            self._initial_command_retry = self._ig_off_pending = False
            self._source_mode = 0
            self._recovery_ec9b = self._recovery_ec9c = False
            self._phase_started_ms = None
            self._phase_elapsed_ms[:] = [0] * len(self._phase_elapsed_ms)
            self._pending_continuation = None
            self._continuation_sequence = 0
            self._gateway_startup = None
            self._file_sources = None
            self._all_loaded_metadata = ()
            self._online_loaded_metadata = ()
            self._targets_by_file = ()
            self._cpu_orders_by_file = ()
            self._authored_cpu_orders_by_file = ()
            self._unmatched_identifiers_by_file = ()
            self._unmatched_companions_by_file = ()
            self._authored_cpu_counts_by_file = ()
            self._authored_target_indices_by_file = ()
            self._selections_by_file = ()
            self._cid_matches_by_file = ()
            self._retained_clone_selection = None
            self._selection_rebuild_pending = None
            self._cid_selected_files.clear()
            self._cpu_percentages.clear()
            self._flow_file_index2026 = 0
            self._getter_sequence_changed_39c2026 = False
            self._reset_getter_history_and_aux_40580_2026(cleanup)
            self._configured_bits_4e0_2026 = [False] * maximum
            self._getter_configured_masks_4f0_2026 = tuple(
                (False,) * maximum for _ in range(16)
            )
            self._getter_reset_epoch2026 += 1
            self._vin = b""
            self._current_file_index = self._current_node = 0
            self._current_cpu_index = self._current_global_cpu_index = 0
            self._cpu_offset = self._progress_base = 0
            self._closed = True
            self._lifecycle = "cleaned"
        with _ISSUE_LOCK:
            reference = _ISSUED.get(self._engine)
            if reference is not None and reference() is self:
                del _ISSUED[self._engine]
        if getattr(self._controller, "worker", None) is self:
            delattr(self._controller, "worker")

    def leave_recovery_mode(self) -> None:
        self._engine._require_owned_phase()
        with self._lock:
            self._recovery_ec9c = True

    def mark_cid_reception_complete(self) -> bool:
        """Retain34e10's authored CID match;36800 owns the later3e710."""
        from scripts.calibration_2026 import native2026_unrebuilt_selection

        self._engine._require_owned_phase()
        with self._lock:
            self.validate_source()
            match = self._engine._select_received_worker_cids(worker=self)
            configuration = self._engine.configuration
            assert configuration is not None
            maximum = configuration.cpu_maximum
            self._judge_live_selection2026 = _NativeJudgeSelectionCache2026(
                match.authored_target_indices
                + (-1,) * (maximum - match.authored_cpu_count),
                match.unmatched_identifiers,
                match.unmatched_companions,
                match.authored_cpu_count,
            )
            if not match.check_target:
                return False
            result = native2026_unrebuilt_selection(match)
            metadata = result.rebuilt_metadata
            targets = list(self._targets_by_file)
            targets[self._current_file_index] = result.target_indices
            self._targets_by_file = tuple(targets)
            selectors = list(self._cpu_orders_by_file)
            selectors[self._current_file_index] = tuple(
                range(len(result.ordered_to_authored))
            )
            self._cpu_orders_by_file = tuple(selectors)
            authored = list(self._authored_cpu_orders_by_file)
            authored[self._current_file_index] = result.ordered_to_authored
            self._authored_cpu_orders_by_file = tuple(authored)
            unmatched = list(self._unmatched_identifiers_by_file)
            unmatched[self._current_file_index] = result.unmatched_identifiers
            self._unmatched_identifiers_by_file = tuple(unmatched)
            companions = list(self._unmatched_companions_by_file)
            companions[self._current_file_index] = result.unmatched_companions
            self._unmatched_companions_by_file = tuple(companions)
            counts = list(self._authored_cpu_counts_by_file)
            counts[self._current_file_index] = result.authored_cpu_count
            self._authored_cpu_counts_by_file = tuple(counts)
            authored_targets = list(self._authored_target_indices_by_file)
            authored_targets[self._current_file_index] = result.authored_target_indices
            self._authored_target_indices_by_file = tuple(authored_targets)
            selections = list(self._selections_by_file)
            selections[self._current_file_index] = result
            self._selections_by_file = tuple(selections)
            matches = list(self._cid_matches_by_file)
            matches[self._current_file_index] = match
            self._cid_matches_by_file = tuple(matches)
            if self._delta_archive_active and self._delta_archive_clone_match:
                retained = (
                    None
                    if self._file_sources is None
                    else self._file_sources.auxiliary_metadata
                )
                if (
                    retained is None
                    or metadata.source_container is not retained.source_container
                    or metadata.source_sha256 != retained.source_sha256
                ):
                    raise ValueError("34e10 A48 selection differs from retained clone")
                self._retained_clone_selection = result
                self._selection_rebuild_pending = None
            self._cid_selected_files.add(self._current_file_index)
            return True

    def _clear_retry_cpu_percentages(self, retry) -> None:
        """5e950 clears the CUW c48/c4c vector length, retaining its owner."""
        from scripts.cuw_retry import RetryController2026

        if type(retry) is not RetryController2026:
            raise TypeError("Actual source-issued retry controller required")
        self._engine._validate_retry_controller(retry)
        if not self._engine.active or not retry.query_pending:
            raise ValueError("No active native retry query owns the percentage vector")
        with self._lock:
            self.validate_source()
            self._cpu_percentages.clear()

    @staticmethod
    def _callback_byte(value: int) -> int:
        if type(value) is not int or not 0 <= value <= 0xFF:
            raise ValueError("Actual native callback byte required")
        return value

    def record_callback_24(self, value: int) -> None:
        """58ab0 stores callback24's raw byte in the engine-owned ED0C cache."""
        self._engine._require_owned_phase()
        with self._lock:
            self.validate_source()
            self._engine._publish_callback_24_gateway_cache(worker=self, value=value)

    def publish_callback_25_gateway_node(self) -> None:
        """58b40 callback25 copies cached DAT8ed0c into typData990/BF9."""
        self._engine._require_owned_phase()
        with self._lock:
            self.validate_source()
            self._engine._publish_cached_gateway_kind(worker=self)

    def publish_control_callback_30_2026(self, context) -> int:
        """59000 callback30 zero-extends cached ED8A into shared C08."""
        with self._lock:
            self._validate_control_output_context2026(context)
            value = self._engine.native_dh_type_cache2026
            if type(value) is not int or not 0 <= value <= 0xFF:
                raise ValueError("Persistent ED8A gateway cache must be a byte")
            self._source_mode = value
            self._engine.dh_state._central_gateway_type = value
            return value

    def publish_control_callback_2f2026(self, context) -> int:
        """58f80 publishes actual C08 low byte to persistent ED8A."""
        with self._lock:
            self._validate_control_postexport_cache2026(context)
            raw_value = self._source_mode
            if type(raw_value) is not int or not 0 <= raw_value <= 0xFFFFFFFF:
                raise ValueError("Actual worker C08 DWORD required")
            return raw_value & 0xFF

    def publish_control_callback_28_2026(self, context) -> int:
        """58ca0 copies actual C25 into the shared ED29 byte."""
        with self._lock:
            self._validate_control_postexport_cache2026(context)
            return self._control_ssm_byte2026

    def _validate_control_postexport_cache2026(self, context) -> None:
        """Require the actual 8990 helper's completed primary-return receipt."""
        from scripts import programming_2026_common

        self._validate_control_output_context2026(context)
        entry_lookup = getattr(
            programming_2026_common, "_control_helper_entry2026", None
        )
        returned = getattr(
            programming_2026_common,
            "_control_helper_primary_return_seen2026",
            None,
        )
        if not callable(entry_lookup) or not callable(returned):
            raise TypeError("Source-issued CONTROL post-export receipt is unavailable")
        helper_lease = entry_lookup(context)
        if returned(context, helper_lease, "8990") is not True:
            raise ValueError("Completed CONTROL 8990 primary return is required")

    def read_control_callback_29_2026(self, context) -> int:
        """58d20 reads ED29 and copies that same source byte back into C25."""
        with self._lock:
            self._validate_control_output_context2026(context)
            value = self._engine.native_ssmid_cache2026
            if type(value) is not int or not 0 <= value <= 0xFF:
                raise ValueError("Persistent ED29 SSM cache must be a byte")
            self._control_ssm_byte2026 = value
            return value

    def store_control_ssm_retry2026(self, context) -> int:
        """Named retry seam delegates callback29's ED29-to-C25 source copy."""
        return self.read_control_callback_29_2026(context)

    def _publish_control_gateway_type2026(self, state) -> None:
        """Join an actual DH source setter to the shared native C08 field."""
        from scripts.cuw_2026 import DHControllerState2026

        with self._lock:
            context = self._controller.native_control_context2026(self._engine)
            self._validate_control_output_context2026(context)
            target = self._engine._controller_export_target2026
            if (
                type(state) is not DHControllerState2026
                or state is not self._engine.dh_state
                or target is None
                or target._context is not context
            ):
                raise ValueError("Active source-issued CONTROL DH state required")
            target.validate(self._engine, self._controller)
            operation = target.binding.operation
            if operation == "write":
                from scripts import programming_2026_common

                dispatch = programming_2026_common._control_export_dispatch2026(
                    target, "PrepareRetry"
                )
                if dispatch["module"] not in {
                    "TCUWCanDHFlashWriter.dll",
                    "TCUWCanDHUDSFlashWriter.dll",
                    "TCUWP5CanDHUDSFlashWriter.dll",
                }:
                    raise ValueError("Native DH PrepareRetry export required")
                helper_entry = programming_2026_common._control_helper_entry2026(
                    context
                )
                entries = programming_2026_common._NATIVE_CONTROL_HELPER_ENTRIES_2026
                helper_record = entries.get(id(helper_entry))
                if (
                    helper_record is None
                    or helper_record[0] is not helper_entry
                    or helper_record[1]["engine"] is not self._engine
                    or helper_record[1]["controller"] is not self._controller
                    or helper_record[1]["context"] is not context
                    or helper_record[1]["helper"] not in ("4c10", "5c30")
                ):
                    raise ValueError("Active native CONTROL writer helper required")
            elif operation != "prepare":
                raise ValueError("Active source-issued CONTROL DH state required")
            value = state._central_gateway_type
            if type(value) is not int or value not in (1, 2):
                raise ValueError("Actual DH gateway type must be native DWORD1 or2")
            self._source_mode = value

    def _bind_sbr_ssm_producer2026(self, utility, target) -> None:
        from scripts.programming_2026_common import NativeControlExportTarget2026
        from scripts.programming_2026_vendor import SBRUtils2026, Vendor2026Context

        with self._lock:
            context = self._controller.native_control_context2026(self._engine)
            self._validate_control_output_context2026(context)
            if (
                type(utility) is not SBRUtils2026
                or utility.runtime is not self._runtime
                or type(utility.context) is not Vendor2026Context
                or utility.context.family != "SBR"
                or type(target) is not NativeControlExportTarget2026
                or target._context is not context
                or self._engine._controller_export_target2026 is not target
                or getattr(self._runtime._device_calls, "control_export", None)
                != (self._engine, self._controller, target)
            ):
                raise ValueError("Active source-issued SBR utility and target required")
            target.validate(self._engine, self._controller)
            if (
                target.binding.operation not in ("prepare", "write")
                or utility.context.selection is not target.binding
                or utility.context.stage != target.binding.operation
                or utility.context.identity.module_name
                != target.module_binding.module_name
            ):
                raise ValueError("SBR utility differs from its active CONTROL binding")
            self._sbr_ssm_producer2026 = (utility, target, context, utility.context)

    def publish_sbr_ssm2026(self, utility) -> None:
        from scripts.programming_2026_vendor import SBRUtils2026, Vendor2026Context

        with self._lock:
            context = self._controller.native_control_context2026(self._engine)
            self._validate_control_output_context2026(context)
            producer = self._sbr_ssm_producer2026
            if (
                type(utility) is not SBRUtils2026
                or type(utility.context) is not Vendor2026Context
                or producer is None
                or producer[0] is not utility
                or producer[2] is not context
                or utility.context is not producer[3]
                or utility.context.selection is not producer[1].binding
                or utility.context.family != "SBR"
                or utility.context.stage != producer[1].binding.operation
                or utility.context.identity.module_name
                != producer[1].module_binding.module_name
                or utility.runtime is not self._runtime
                or self._engine._controller_export_target2026 is not producer[1]
                or getattr(self._runtime._device_calls, "control_export", None)
                != (self._engine, self._controller, producer[1])
            ):
                raise ValueError("Exact active source-issued SBR producer required")
            producer[1].validate(self._engine, self._controller)
            if type(utility.ssm) is not int or not 0 <= utility.ssm <= 0xFF:
                raise ValueError("SBR producer must hold an actual native byte")
            self._control_ssm_byte2026 = utility.ssm

    def record_control_return2026(self, context, snapshot, p6_import=None) -> None:
        """Retain only the exact J2534 snapshot registered at raw 4be0 tail."""
        from scripts.j2534_2026 import J2534InterfacePair2026, NativeInterfaceData2026
        from scripts.programming_2026_common import _control_return_snapshot2026

        with self._lock:
            self._validate_control_output_context2026(context)
            pair = self._engine.interface_pair
            if (
                type(pair) is not J2534InterfacePair2026
                or type(snapshot) is not NativeInterfaceData2026
                or _control_return_snapshot2026(context) is not snapshot
            ):
                raise ValueError("Exact ordinary CONTROL raw-tail snapshot required")
            pair.validate_views()
            if self._control_return_receipt2026 is not None:
                raise ValueError("CONTROL raw return snapshot was already recorded")
            if p6_import is not None:
                from scripts.programming_2026_p6 import _P6GetterImportReceipt2026

                if (
                    type(p6_import) is not _P6GetterImportReceipt2026
                    or p6_import.control_context is not context
                    or p6_import.job is not self._engine._thread_job
                ):
                    raise ValueError("Source-issued P6 getter import receipt required")
            self._control_return_receipt2026 = (
                context,
                pair,
                snapshot,
                False,
                p6_import,
            )
            self._getter_ordinary_return_sequence2026 += 1

    def _prepare_getter_import2026(self, context, output, values):
        from scripts.j2534_2026 import NativeCommunicationAddress
        from scripts.programming_2026_common import (
            NativeControlExportTarget2026,
            NativeControlGetterOutput2026,
        )

        if output is None:
            return None
        capture = context._capture
        maximum = capture.configuration.cpu_maximum
        if (
            self._engine.configuration is not capture.configuration
            or any(
                len(vector) != maximum
                for vector in (
                    self._node_strings_4402026,
                    self._node_strings_4682026,
                    self._node_strings_4902026,
                    self._node_strings_4b82026,
                    self._retained_bits_5882026,
                    self._node_dword_bits_1b9c2026,
                    self._configured_bits_4e0_2026,
                )
            )
            or len(self._cell_dword_bits_5542026) != 32 * maximum
            or len(self._cell_strings_5602026) != 32 * maximum
        ):
            raise ValueError("Live native getter scratch differs from configuration")
        if (
            type(output) is not NativeControlGetterOutput2026
            or output.context is not context
            or output.capture is not capture
            or output.configuration is not capture.configuration
            or type(output.getter_mode) is not int
            or output.getter_mode not in (0, 1, 2)
            or type(output.raw_al) is not bool
            or output.identifiers is not values
            or type(output.identifiers) is not tuple
            or len(values) > 34
            or any(
                type(value) is not bytes or len(value) > 33 or b"\0" in value
                for value in values
            )
            or type(output.query_records34) is not tuple
            or len(output.query_records34) != 34
            or any(
                type(record) is not bytes or len(record) != 12
                for record in output.query_records34
            )
            or type(output.hardware) is not bytes
            or b"\0" in output.hardware
            or len(output.hardware) > 4096
            or type(output.getter_targets) is not tuple
            or not output.getter_targets
            or any(
                type(target) is not NativeControlExportTarget2026
                or target._context is not context
                or target.module_binding.module_name != "TCUWCanCIDGetter.dll"
                for target in output.getter_targets
            )
            or type(output.communication_addresses) is not tuple
            or any(
                type(address) is not NativeCommunicationAddress
                for address in output.communication_addresses
            )
        ):
            raise ValueError("Complete source-issued CanCID getter output required")

        widths = (13, 257, 101, 31)
        raw_vectors = (
            output.node_strings_9c8,
            output.node_strings_9cc,
            output.node_strings_9d0,
            output.node_strings_9d4,
        )
        if any(
            type(vector) is not tuple
            or len(vector) != maximum
            or any(type(raw) is not bytes or len(raw) != width for raw in vector)
            for vector, width in zip(raw_vectors, widths)
        ):
            raise ValueError("Native getter string vectors have invalid shapes")
        if (
            type(output.configured_bytes_9d8) is not bytes
            or len(output.configured_bytes_9d8) != maximum
            or any(value not in (0, 1) for value in output.configured_bytes_9d8)
            or type(output.retained_bytes_9dc) is not bytes
            or len(output.retained_bytes_9dc) != maximum
            or any(value not in (0, 1) for value in output.retained_bytes_9dc)
            or type(output.node_cells_9e0) is not tuple
            or len(output.node_cells_9e0) != maximum
            or any(
                type(cells) is not tuple
                or len(cells) != 32
                or any(type(cell) is not bytes or len(cell) != 14 for cell in cells)
                for cells in output.node_cells_9e0
            )
            or type(output.node_dwords_a10) is not tuple
            or len(output.node_dwords_a10) != maximum
            or any(
                type(value) is not int or not 0 <= value <= 0xFFFFFFFF
                for value in output.node_dwords_a10
            )
            or type(output.tail_a14) is not bytes
            or len(output.tail_a14) != 21
            or type(output.tail_a29) is not bytes
            or len(output.tail_a29) != 21
        ):
            raise ValueError("Native getter auxiliary output has invalid shapes")

        strings = [
            list(self._node_strings_4402026),
            list(self._node_strings_4682026),
            list(self._node_strings_4902026),
            list(self._node_strings_4b82026),
        ]
        node_bits = list(self._cell_dword_bits_5542026)
        cell_strings = list(self._cell_strings_5602026)
        retained_bits = list(self._retained_bits_5882026)
        node_dwords = list(self._node_dword_bits_1b9c2026)
        for cpu_index in range(maximum):
            if retained_bits[cpu_index]:
                continue
            for vector_index, (vector, width) in enumerate(zip(raw_vectors, widths)):
                strings[vector_index][cpu_index] = _native_getter_c_string2026(
                    vector[cpu_index], width
                )
            for cell_index, raw_cell in enumerate(output.node_cells_9e0[cpu_index]):
                value_bits, value = _native_getter_cell2026(raw_cell)
                offset = cpu_index * 32 + cell_index
                node_bits[offset] = value_bits
                cell_strings[offset] = value
            retained_bits[cpu_index] = bool(output.retained_bytes_9dc[cpu_index])
            node_dwords[cpu_index] = output.node_dwords_a10[cpu_index]

        configured_bits = list(self._configured_bits_4e0_2026)
        if output.getter_mode == 1:
            configured_bits = [bool(value) for value in output.configured_bytes_9d8]
        return (
            tuple(tuple(vector) for vector in strings),
            node_bits,
            cell_strings,
            configured_bits,
            retained_bits,
            node_dwords,
            _native_getter_c_string2026(output.tail_a14, 21),
            _native_getter_c_string2026(output.tail_a29, 21),
            tuple(output.query_records34),
            output.hardware,
        )

    def import_control_getter_return2026(self, context) -> None:
        """Consume the ordinary raw snapshot once at the actual outer getter join."""
        from scripts.j2534_2026 import J2534InterfacePair2026
        from scripts.programming_2026_common import (
            _control_getter_output2026,
            _control_getter_return_values2026,
            _control_return_snapshot2026,
        )

        with self._lock:
            self._validate_control_output_context2026(context)
            receipt = self._control_return_receipt2026
            if (
                context._capture._phase != 0
                or receipt is None
                or receipt[0] is not context
                or receipt[1] is not self._engine.interface_pair
                or type(receipt[1]) is not J2534InterfacePair2026
                or receipt[2] is not _control_return_snapshot2026(context)
                or receipt[3]
            ):
                raise ValueError("Unconsumed ordinary CONTROL getter return required")
            pair, snapshot = receipt[1], receipt[2]
            p6_import = receipt[4] if len(receipt) == 5 else None
            if p6_import is not None:
                p6_import.validate_consume(self._engine)
            values = _control_getter_return_values2026(context)
            if type(values) is not tuple:
                raise ValueError("Ordinary CONTROL getter result vector is invalid")
            output = _control_getter_output2026(context)
            staged = self._prepare_getter_import2026(context, output, values)
            pair.validate_views()
            pair.import_into(pair.engine, snapshot)
            if staged is not None:
                (
                    strings,
                    node_bits,
                    cell_strings,
                    configured_bits,
                    retained_bits,
                    node_dwords,
                    name_1ba8,
                    name_1bc0,
                    query_records,
                    hardware,
                ) = staged
                self._engine._working_identifier_records = query_records
                self._engine._working_hardware = hardware
            self._engine.commit_received_identifiers(
                values, controller=self._controller
            )
            if p6_import is not None:
                p6_import.consume(self._engine)
                outer_session = p6_import.outer_session
                if outer_session is None:
                    raise ValueError("Consumed P6 receipt lost its root session")
                outer_session._phase6_getter_import2026 = None
            if staged is not None:
                (
                    strings,
                    node_bits,
                    cell_strings,
                    configured_bits,
                    retained_bits,
                    node_dwords,
                    name_1ba8,
                    name_1bc0,
                    _query_records,
                    _hardware,
                ) = staged
                (
                    self._node_strings_4402026,
                    self._node_strings_4682026,
                    self._node_strings_4902026,
                    self._node_strings_4b82026,
                ) = strings
                self._cell_dword_bits_5542026 = node_bits
                self._cell_strings_5602026 = cell_strings
                self._configured_bits_4e0_2026 = configured_bits
                self._retained_bits_5882026 = retained_bits
                self._node_dword_bits_1b9c2026 = node_dwords
                self._name_1ba8_2026 = name_1ba8
                self._name_1bc0_2026 = name_1bc0
            self._imported_getter_output_ref2026 = (
                weakref.ref(output) if output is not None else None
            )
            self._control_return_receipt2026 = (
                context,
                pair,
                snapshot,
                True,
                p6_import,
            )

    def _imported_getter_output2026(self, context):
        """Read only the typed output imported for this active old context."""
        from scripts.programming_2026_common import NativeControlGetterOutput2026

        with self._lock:
            self._validate_control_output_context2026(context)
            receipt = self._control_return_receipt2026
            if receipt is None or receipt[0] is not context or not receipt[3]:
                raise ValueError("Exact imported getter return context required")
            output_ref = self._imported_getter_output_ref2026
            if output_ref is None:
                return None
            output = output_ref()
            if output is None:
                return None
            if (
                type(output) is not NativeControlGetterOutput2026
                or output.context is not context
            ):
                raise ValueError("Imported getter output differs from its context")
            return output

    def _imported_phase6_getter_receipt2026(self, context, job, sequence):
        """Return only a consumed P6 receipt joined to this imported getter."""
        from scripts.programming_2026_p6 import _P6GetterImportReceipt2026

        with self._lock:
            receipt = self._control_return_receipt2026
            if (
                type(receipt) is not tuple
                or len(receipt) != 5
                or receipt[0] is not context
                or receipt[3] is not True
            ):
                return None
            p6_import = receipt[4]
            if (
                type(p6_import) is not _P6GetterImportReceipt2026
                or not p6_import._consumed
                or p6_import.context.identity.module_name != "TCUWP6CanCIDGetter.dll"
                or p6_import.control_context is not context
                or p6_import.job is not job
                or p6_import.sequence != sequence
                or p6_import.identifiers != self._engine.received_identifiers
            ):
                return None
            return p6_import

    def finish_classic_prepare(self) -> None:
        """8990 post-export phase transition; callback BOOL is not success."""
        with self._lock:
            if self._prepare_handshake != 2:
                self._engine.set_comm_phase(3, controller=self._controller)

    def prepare_reentry_handshake(self) -> bool:
        """36800 reruns its prefix, then consumes nonrecovery be8=1 as3."""
        with self._lock:
            self.validate_source()
            if self._prepare_handshake != 1 or self.control_state.recovery_mode:
                return False
            self._retain_first_cpu_type_36800_2026()
            self._runtime.check()
            started = self._runtime.read_local_milliseconds_of_day()
            self._initialize_36800_prefix(started)
            self._prepare_handshake = 3
            return True

    def clear_post_write_state(self) -> None:
        """3b90 post-write clear, with final-CPU notification semantics."""
        with self._lock:
            state = self._engine.dh_state
            state.record_native_error(0, 0, 0)
            state._native_context_964 = False
            self._failed = False
            persistence = getattr(self._engine, "persistence", None) or getattr(
                self._engine, "_persistence", None
            )
            if persistence is not None:
                persistence.last_block_notification.assign(False)
                if self._is_last_cpu():
                    persistence.notification.assign(False)

    def finish_recovery_probe(self, controller: ControlCommPhase2026) -> None:
        """3b90 IsFinish true: clear75c, callback7, then clear968/96c."""
        from scripts.programming_2026_common import ControlCommPhase2026

        if (
            type(controller) is not ControlCommPhase2026
            or controller is not self._controller
        ):
            raise ValueError("Actual worker ControlCommPhase owner required")
        self._engine._require_owned_phase()
        with self._lock:
            self.validate_source()
            self._failed = False
            self._engine.publish_control_failed(controller)
            persistence = getattr(self._engine, "persistence", None) or getattr(
                self._engine, "_persistence", None
            )
            if persistence is not None:
                persistence.notification.assign(False)
                persistence.last_block_notification.assign(False)

    def _is_last_cpu(self) -> bool:
        if not self._all_loaded_metadata:
            return False
        last = self._all_loaded_metadata[-1]
        return self._current_file_index == len(self._all_loaded_metadata) - 1 and (
            self._current_global_cpu_index == native2026_cpu_count(last) - 1
        )

    def _next_position(
        self,
    ) -> tuple[Literal["cpu", "file"], int, int] | None:
        metadata = self._all_loaded_metadata[self._current_file_index]
        next_cpu = self._current_global_cpu_index + 1
        if next_cpu < native2026_cpu_count(metadata):
            return "cpu", self._current_file_index, next_cpu
        next_file = self._current_file_index + 1
        if next_file < len(self._all_loaded_metadata):
            return "file", next_file, 0
        return None

    def _ig_cycle(
        self, current: Native2026Metadata, following: Native2026Metadata
    ) -> bool:
        current_contact = current.vehicle.get("contacttype", "")
        following_contact = following.vehicle.get("contacttype", "")
        if current_contact != following_contact:
            return True
        current_cpu = native2026_cpu_type(current, native2026_global_cpu_index(current))
        following_cpu = native2026_cpu_type(
            following, native2026_global_cpu_index(following)
        )
        if current_cpu == following_cpu:
            return False
        return self._engine.general_parameter_boolean(
            current.vehicle.get("kindofecu", ""),
            following_cpu,
            following_contact,
            "FlagToDoIGOFFONAtCPUTypeChange",
            controller=self._controller,
        )

    def _select_engine_target(self, metadata: Native2026Metadata) -> None:
        current = self._engine.native_metadata
        if current.source_sha256 == metadata.source_sha256:
            self._engine.select_target(
                metadata.node, metadata.cpu_index, controller=self._controller
            )
            return
        selector = getattr(self._engine, "_select_worker_metadata", None)
        if not callable(selector):
            raise TypeError("Engine lacks the source-bound multi-FILE selector")
        selector(metadata, controller=self._controller, worker=self)

    def _persist_position(self) -> None:
        persistence = getattr(self._engine, "persistence", None) or getattr(
            self._engine, "_persistence", None
        )
        if persistence is None:
            return
        state = persistence.state
        state.calibration_file_index = self._recovery_file_index()
        state.offset_of_write_cpu_multi_cal_index = self._cpu_offset
        persistence.update_cpu(self._current_global_cpu_index)

    def _recovery_file_index(self) -> int:
        """Map native FILE-table ownership to RecoveryInfo's original ECIndex."""
        if self._file_sources is None:
            return self._current_file_index
        return self._file_sources.recovery_index_for_metadata(
            self._engine.native_metadata
        )

    def notify_next_cpu(self) -> None:
        """581a0 applies and queues state, then returns without phase recursion."""
        job = self._engine.thread_job
        if job is not None and job.is_child_thread:
            job.dispatch_next_cpu()
            return
        self._engine._require_owned_phase()
        self._engine._begin_continuation_backup(worker=self)
        try:
            self._notify_next_cpu_state()
        finally:
            self._engine._end_continuation_backup(worker=self)

    def _notify_next_cpu_state(self) -> None:
        with self._lock:
            if self._pending_continuation is not None:
                raise ValueError("Previous native continuation has not been consumed")
            current_targets = self._targets_by_file[self._current_file_index]
            if (
                not 0 <= self._current_global_cpu_index < len(current_targets)
                or current_targets[self._current_global_cpu_index] < 0
            ):
                raise ValueError("Native CID completion has not selected current CPU")
            current_target = current_targets[self._current_global_cpu_index]
            current = self._engine.native_metadata
            following_position = self._next_position()
            if following_position is None:
                # 3ec30/3f620 terminal continuation is the DATd34c producer.
                self._continuation_sequence += 1
                self._complete = True
                continuation = WorkerContinuation2026(
                    self._continuation_sequence,
                    "complete",
                    self._current_file_index,
                    self._current_node,
                    self._current_cpu_index,
                    self._current_global_cpu_index,
                    current_target,
                    False,
                )
            else:
                kind, file_index, global_cpu_index = following_position
                base = self._all_loaded_metadata[file_index]
                following_targets = self._targets_by_file[file_index]
                if (
                    not 0 <= global_cpu_index < len(following_targets)
                    or following_targets[global_cpu_index] < 0
                ):
                    raise ValueError(
                        "Native CID completion has not selected following CPU"
                    )
                following_target = following_targets[global_cpu_index]
                self._continuation_sequence += 1
                following = native2026_metadata_for_cpu(
                    base, self._cpu_orders_by_file[file_index][global_cpu_index]
                )
                ig_cycle = self._ig_cycle(current, following)
                if kind == "file":
                    self._control_scratch_reset_pending2026 = True
                    self._progress_base += max(
                        0,
                        native2026_cpu_count(current)
                        - len(self._identifiers_for_file(self._current_file_index)),
                    )
                self._select_engine_target(following)
                self._current_file_index = file_index
                self._current_node = following.node
                self._current_cpu_index = following.cpu_index
                self._current_global_cpu_index = global_cpu_index
                if kind == "file":
                    self._cpu_offset = 0
                    self._cid_rebuild_done_3542026 = False
                if kind == "file":
                    self._persist_position()
                    retry = getattr(self._engine, "_retry_controller", None)
                    if retry is not None:
                        retry._reset_error_counts(self)
                self._ig_off_pending = ig_cycle
                self._engine._publish_worker_cycle(self)
                continuation = WorkerContinuation2026(
                    self._continuation_sequence,
                    kind,
                    file_index,
                    following.node,
                    following.cpu_index,
                    self._current_global_cpu_index,
                    following_target,
                    ig_cycle,
                )
            self._pending_continuation = continuation
            self._lifecycle = "yielded"

    def notify_logical_cpu_boundary(self, next_global_cpu_index: int) -> None:
        """P6 callback1/3f620 same-export CPU transition without an outer yield."""
        if type(next_global_cpu_index) is not int:
            raise TypeError("Native logical-block CPU index required")
        job = self._engine.thread_job
        if job is not None and job.is_child_thread:
            job.dispatch_logical_cpu_boundary(next_global_cpu_index)
            return
        self._engine._require_owned_phase()
        self._engine._begin_continuation_backup(worker=self)
        try:
            self._notify_logical_cpu_boundary_state(next_global_cpu_index)
        finally:
            self._engine._end_continuation_backup(worker=self)

    def _notify_logical_cpu_boundary_state(self, next_global_cpu_index: int) -> None:
        with self._lock:
            if self._engine.worker_phase != 2:
                raise ValueError("Logical CPU boundary requires the writer phase")
            current = self._engine.native_metadata
            if not 0 <= next_global_cpu_index < native2026_cpu_count(current):
                raise ValueError("Logical-block CPU index is outside the current FILE")
            following = native2026_metadata_for_cpu(current, next_global_cpu_index)
            if following.node != current.node:
                raise ValueError("Logical CPU boundary cannot cross a native node")
            if next_global_cpu_index == native2026_global_cpu_index(current):
                raise ValueError("Logical CPU boundary must change the native CPU")
            targets = self._targets_by_file[self._current_file_index]
            if (
                not 0 <= next_global_cpu_index < len(targets)
                or targets[next_global_cpu_index] < 0
            ):
                raise ValueError("Native CID completion has not selected logical CPU")
            if self._phase_started_ms is None:
                raise ValueError("Logical CPU boundary requires active phase timing")
            ended = self._runtime.read_local_milliseconds_of_day()
            elapsed = (ended - self._phase_started_ms) % 86_400_000
            current_index = self._current_global_cpu_index
            if current_index < len(self._phase_elapsed_ms):
                self._phase_elapsed_ms[current_index] += elapsed
            self._phase_started_ms = ended
            self._engine.select_target(
                following.node,
                following.cpu_index,
                controller=self._controller,
            )
            self._target_selected(following)

    def take_continuation(self) -> WorkerContinuation2026 | None:
        """Outer b3e0 consumes this only after the previous phase unwinds."""
        with self._lock:
            continuation = self._pending_continuation
            self._pending_continuation = None
            if continuation is not None:
                self._lifecycle = "ready"
            return continuation

    def _phase_started(self, phase: int, *, _vbf_request=None) -> None:
        if type(phase) is not int or phase not in (0, 1, 2, 3):
            raise ValueError("Native worker phase must be0..3")
        if self._phase_started_ms is not None:
            raise ValueError("Native worker phase was already initialized")
        job = self._engine.thread_job
        if job is not None and job.is_child_thread:
            ordinary = job._prepared_ordinary_entry2026
            if ordinary is not None:
                from scripts.cuw_engine_threads import _PreparedOrdinaryEntry2026

                lease = job._lease
                if (
                    _vbf_request is not None
                    or type(ordinary) is not _PreparedOrdinaryEntry2026
                    or ordinary.worker is not self
                    or ordinary.phase != phase
                    or lease is None
                    or lease.state != "adopted"
                ):
                    raise ValueError("Exact adopted ordinary36800 receipt required")
                receipt = job._consume_ordinary_prepare_entry_36800_2026(lease)
                with self._lock:
                    self._phase_started_ms = receipt.started_ms
                    self._lifecycle = "running"
                return
            if (
                _vbf_request is None
                and phase in (1, 2)
                and job.worker is self
                and job._session is not None
                and job._session.operation in ("prepare", "recovery")
                and (
                    job._is_raw_control_ordinary_root2026(job._session)
                    # A source projection can change the input root's CPU view.
                    # Pending ordinary slots must still fail closed, never
                    # authorize fallback to a second standalone prefix.
                    or job._ordinary_prepare_origin2026 is not None
                    or job._ordinary_prepare_binding2026 is not None
                )
                and job._lease is not None
                and job._lease.phase == phase
                and job._lease.state == "adopted"
            ):
                raise ValueError("Ordinary child has no unconsumed36800 receipt")
        if _vbf_request is not None:
            job = self._engine.thread_job
            if phase != 1 or job is None or not job.is_child_thread:
                raise ValueError("Adopted VBF resume requires the actual child phase1")
            from scripts.cuw_engine_threads import validate_vbf_process_before2026

            lease = job._lease
            if lease is None or lease.state != "adopted":
                raise ValueError("Actual adopted VBF phase-one lease required")
            request = validate_vbf_process_before2026(
                _vbf_request,
                job,
                states=("adopted",),
                lease=lease,
            )
            with self._lock:
                self._phase_started_ms = request.started_ms
                self._lifecycle = "running"
            return
        with self._lock:
            if (
                phase == 1
                and self._prepare_handshake == 1
                and not self.control_state.recovery_mode
            ):
                raise ValueError(
                    "Consume the source prepare-reentry handshake before dispatch"
                )
            if phase == 1:
                self._retain_first_cpu_type_36800_2026()
            self._runtime.check()
            started = self._runtime.read_local_milliseconds_of_day()
            if phase == 1:
                self._initialize_36800(started)
            if (
                phase == 1
                and not self.control_state.recovery_mode
                and native2026_cpu_values(
                    self._engine.native_metadata,
                    0,
                )
                .get("cpuimagename", "")
                .find(".vbf")
                != -1
            ):
                self._prepare_handshake = 1
            self._phase_started_ms = started
            self._lifecycle = "running"

    def _phase_finished(self, phase: int) -> None:
        if type(phase) is not int or phase not in (0, 1, 2, 3):
            raise ValueError("Native worker phase must be0..3")
        with self._lock:
            if self._phase_started_ms is None:
                raise ValueError("Worker phase was not started")
            if self._prepare_handshake != 2 and self._control_scratch_reset_pending2026:
                self._control_count_scratch2026[:] = [0] * len(
                    self._control_count_scratch2026
                )
                self._control_percent_scratch2026[:] = [0] * len(
                    self._control_percent_scratch2026
                )
                self._control_scratch_reset_pending2026 = False
            self._invalidate_control_file_capture2026()
            # Outer unwind records timing after the operation's own cancel point;
            # a fresh runtime check here would replace the primary exception.
            ended = self._runtime.local_milliseconds_of_day()
            if type(ended) is not int or not 0 <= ended < 86_400_000:
                raise ValueError("Native local milliseconds within day required")
            elapsed = (ended - self._phase_started_ms) % 86_400_000
            index = self._current_global_cpu_index
            if index < len(self._phase_elapsed_ms):
                self._phase_elapsed_ms[index] += elapsed
            self._phase_started_ms = None
            self._lifecycle = "ready"

    def _phase_failed(self, error: BaseException) -> None:
        if not isinstance(error, BaseException):
            raise TypeError("Actual phase exception required")
        with self._lock:
            self._invalidate_control_file_capture2026()
            self._phase_started_ms = None
            self._lifecycle = (
                "cancelled" if isinstance(error, InterruptedError) else "faulted"
            )

    def _acknowledge_native_catch_all(self) -> None:
        """41e60 publishes be8=2 and defers its outer wait to145's real job."""
        job = self._engine.thread_job
        if job is not None and not job.native_worker_exists:
            return
        changed = False
        with self._lock:
            if self._prepare_handshake == 1:
                self._prepare_handshake = 2
                changed = True
        if not changed or job is None:
            return
        if job.is_native_thread:
            job.request_prepare_acknowledgement()
            return
        retry = self._engine._retry_controller
        if retry is None:
            raise ValueError(
                "External native catch-all requires the issued retry controller"
            )
        job.request_external_prepare_acknowledgement(retry)

    def check_device_version(self) -> bool:
        """33e50: version plus GET_CONFIG1; native catch-all returns false."""
        from scripts.programming_2026_common import is_native_exception2026

        self._runtime.check()
        device = self._engine.engine_runtime_device()
        try:
            device.read_device_version()
            device.control_io(1, ((1, 0),))
        except (Exception, KeyboardInterrupt) as error:
            if not is_native_exception2026(error):
                raise
            self._acknowledge_native_catch_all()
            return False
        return True

    def read_battery_voltage(self) -> float:
        """33f80→33e50: version, GET_CONFIG key1=0, then READ_VBATT/1000."""
        from scripts.programming_2026_common import is_native_exception2026

        if not self.check_device_version():
            raise NativeWorkerIntegerError2026(0)
        try:
            device = self._engine.engine_runtime_device()
            value = device.control_io(3)
        except (Exception, KeyboardInterrupt) as cause:
            if not is_native_exception2026(cause):
                raise
            self._acknowledge_native_catch_all()
            error = NativeWorkerIntegerError2026(1)
            raise error from cause
        if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
            raise ValueError("READ_VBATT must return a native DWORD")
        voltage = value / 1000.0
        if not math.isfinite(voltage):
            raise ValueError("Finite native battery voltage required")
        with self._lock:
            self._battery_voltage = voltage
        return voltage

    def programming_log_info(self) -> ProgrammingLogInfo | None:
        """65a40 view built from worker/persistence/device state, without snapshots."""
        from scripts.cuw_2026 import EngineStatus2026

        persistence = getattr(self._engine, "persistence", None) or getattr(
            self._engine, "_persistence", None
        )
        if persistence is None:
            return None
        state = persistence.state
        state.validate()
        calibration = state.calibrations[self._recovery_file_index()]
        configuration = self._engine.configuration
        assert configuration is not None
        backup = self._engine.continuation_backup
        battery_cycle = (
            self._engine.native_cycle_output if backup is None else backup.cycle
        )
        phase = self._engine.native_phase
        recovery_status = self._engine.native_recovery_status(previous=True)
        status = EngineStatus2026(
            phase=phase,
            error=self._engine.native_error_output[0],
            fatal=self._engine.native_fatal_output,
            receiving=False,
            complete=self._complete,
            battery_cycle=battery_cycle,
            recovery_status=recovery_status,
            key_handle=(
                self._engine._online_controller is not None
                and not self._engine._online_controller.closed
            ),
            key_state=self._engine.online_modal_state,
            configured_authorization=bool(configuration.flags[2]),
            contact_type=self._engine.native_metadata.vehicle.get("contacttype", ""),
        )
        receiving_status, _requests_41eb0 = self._engine.native_receiving_status2026()
        reprogramming_status = status.reprogramming_status()[0]
        if not calibration.source_path or not (
            receiving_status == 0x138C or reprogramming_status in (0xBBB, 0xBBC)
        ):
            return None
        device = self._engine.engine_runtime_device()
        connected = bool(device.connecting)
        voltage = self.read_battery_voltage() if connected else None
        last = device.last_message
        address_size, exchange = (0, b"") if last is None else last
        return build_programming_log_info(
            calibration_path=calibration.source_path,
            receiving_status=receiving_status,
            reprogramming_status=reprogramming_status,
            current_cpu=self._current_global_cpu_index,
            cpu_offset=self._cpu_offset,
            progress_base=self._progress_base,
            complete=self._complete,
            controller_present=True,
            percentages=tuple(self._cpu_percentages),
            error_code=self._engine.native_error_output[1],
            exchange_data=exchange,
            address_size=address_size,
            connected=connected,
            voltage=voltage,
            alternate_progress_active=backup is not None,
            alternate_current_cpu=None if backup is None else backup.current_cpu,
            alternate_cpu_offset=None if backup is None else backup.cpu_offset,
            alternate_progress_base=None if backup is None else backup.progress_base,
        )

    def write_programming_log(self, previous: bytes) -> bytes | None:
        info = self.programming_log_info()
        return None if info is None else info.to_bytes(previous)

    def show_completion(self, host, config) -> str:
        """48500 uses the existing notice only after source state is complete."""
        from scripts.cuw_2026 import CompletionNotice2026
        from scripts.cuw_services import NoticeConfig

        if not self._complete:
            raise ValueError("Native worker has not reached completion")
        if not isinstance(config, NoticeConfig):
            raise TypeError("Actual completion notice configuration required")
        return CompletionNotice2026(
            host,
            cancelled=self._runtime.cancelled,
            clock=self._runtime.clock,
        ).run(config)

    def close(self) -> None:
        """Invalidate the one issued worker without touching native resources."""
        with self._lock:
            if self._closed:
                return
            if self._engine.active:
                raise ValueError(
                    "Finish the active CUW phase before closing its worker"
                )
            self._pending_continuation = None
            self._invalidate_control_file_capture2026()
            if self._prepare_handshake == 1:
                self._prepare_handshake = 2
            self._closed = True
            self._lifecycle = "closed"
        with _ISSUE_LOCK:
            reference = _ISSUED.get(self._engine)
            if reference is not None and reference() is self:
                del _ISSUED[self._engine]
        if getattr(self._controller, "worker", None) is self:
            delattr(self._controller, "worker")
