"""Concrete CUW2026 outer/child threads and source-owned event lifetime.

The outer thread corresponds to the engine's 3d100/3cb90 loop; each child runs
5ccd0's concrete controller entry. No callable supplied by a host can replace
programming work or publish its result.
"""

from __future__ import annotations

import math
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal, cast

if TYPE_CHECKING:
    from scripts.calibration_2026 import Native2026Metadata
    from scripts.cuw_2026 import CUWEngine2026
    from scripts.cuw_engine_worker import EngineWorker2026, WorkerContinuation2026
    from scripts.cuw_file_services import FileSourceSet2026
    from scripts.programming_2026_common import (
        ControlCommPhase2026,
        NativeControlContext2026,
        NativeControlGetterOutput2026,
    )
    from scripts.programming_replay import ProgrammingReplay

_TOKEN = object()
_ISSUED: dict[int, ThreadPhaseLease2026] = {}
_LOCK = threading.RLock()
_VBF_REQUESTS: dict[int, tuple[VbfProcessBeforeRequest2026, _VbfRequestRecord2026]] = {}
_VBF_LOCK = threading.RLock()


@dataclass(frozen=True, eq=False)
class _VbfCPUSuccessorOrigin2026:
    request: VbfProcessBeforeRequest2026
    record: _VbfRequestRecord2026
    job: EngineThreadJob2026
    engine: CUWEngine2026
    controller: ControlCommPhase2026
    worker: EngineWorker2026
    issuer_thread: int
    previous_sequence: int
    previous_record: _CompletionRecord2026
    previous_lease: ThreadPhaseLease2026
    parked_metadata: Native2026Metadata
    projected_metadata: Native2026Metadata
    source_container: object
    source_digest: str
    source_node: int
    file_sources: FileSourceSet2026 | None
    parked_file_index: int
    received_identifiers: tuple[bytes, ...]
    before_global_cpu: int
    after_global_cpu: int
    before_metadata_cpu_index: int
    after_metadata_cpu_index: int
    before_selection_cpu_index: int
    after_selection_cpu_index: int
    d30c: int
    pending_selection: object | None
    retained_selection: object | None
    persistence: object | None
    persistence_state: object | None
    persisted_cpu: int | None


@dataclass(frozen=True, eq=False)
class _VbfCPUEngineStore2026:
    origin: _VbfCPUSuccessorOrigin2026
    persistence_transition: object | None


@dataclass(frozen=True, eq=False)
class _VbfCPUSuccessor2026:
    engine_store: _VbfCPUEngineStore2026
    worker_node: int
    worker_cpu_index: int
    worker_global_cpu_index: int
    retained_selection: object | None


@dataclass
class _VbfRequestRecord2026:
    fields: dict
    issuer: int
    previous_record: _CompletionRecord2026 | None
    source_descriptor: tuple
    handshake_at_issue: int
    root: ProgrammingReplay | None = None
    lease: ThreadPhaseLease2026 | None = None
    parked_file_index: int | None = None
    parked_global_cpu_index: int | None = None
    cpu_successor_origin: _VbfCPUSuccessorOrigin2026 | None = None
    cpu_engine_store: _VbfCPUEngineStore2026 | None = None
    cpu_successor: _VbfCPUSuccessor2026 | None = None


class VbfProcessBeforeRequest2026:
    """Opaque receipt for one authenticated ProcessBeforeReprogramming call."""

    __slots__ = ()

    def __init__(self, *, _token=None):
        if _token is not _TOKEN:
            raise TypeError("Engine-issued VBF ProcessBefore request required")

    def __getattr__(self, name):
        if name not in {
            "job",
            "engine",
            "controller",
            "worker",
            "runtime",
            "trace",
            "previous_session",
            "previous_sequence",
            "previous_lease",
            "state",
            "wait_required",
            "started_ms",
            "metadata",
            "container",
            "file_sources",
            "source_sha256",
            "node",
            "cpu_index",
            "received_identifiers",
        }:
            raise AttributeError(name)
        record = _vbf_record(self)
        return record.fields[name]

    def __setattr__(self, name, value):
        raise AttributeError("VBF ProcessBefore request fields are read-only")


def _vbf_record(request):
    with _VBF_LOCK:
        entry = _VBF_REQUESTS.get(id(request))
        if entry is None or entry[0] is not request:
            raise ValueError("Exact issued VBF ProcessBefore request required")
        return entry[1]


def _vbf_inflight_raw_root2026(job, session) -> bool:
    """Prove the unused parent is inside its registered raw CONTROL Execute."""
    from scripts.cuw_engine_worker import ControlFileCapture2026
    from scripts.programming_2026_common import (
        _NATIVE_CONTROL_CONTEXTS_2026,
        _NATIVE_CONTROL_RAW_EXECUTIONS_2026,
        ControlCommPhase2026,
        NativeControlContext2026,
    )
    from scripts.programming_replay import ProgrammingReplay

    child = job._child
    lease = job._lease
    engine = job.engine
    controller = job.controller
    worker = job.worker
    if (
        type(session) is not ProgrammingReplay
        or session is not job._session
        or session.used
        or controller._parameter_session is not session
        or session._engine2026 is not engine
        or session._controller2026 is not controller
        or session._runtime2026 is not controller.runtime
        or type(controller) is not ControlCommPhase2026
        or type(child) is not threading.Thread
        or not child.is_alive()
        or type(lease) is not ThreadPhaseLease2026
        or lease.state != "adopted"
        or lease._thread != child.ident
        or engine._active is not True
        or engine._phase_thread != child.ident
        or engine._controller_execution is not controller
        or engine.worker_phase != 1
        or worker._phase_started_ms is None
    ):
        return False
    try:
        validate_thread_phase_lease(lease, engine, controller=controller, phase=1)
    except (TypeError, ValueError):
        return False
    context = controller._native_control_context2026
    token = controller._native_control_raw_execution2026
    if (
        type(context) is not NativeControlContext2026
        or token is None
        or engine._native_control_context2026 is not context
        or _NATIVE_CONTROL_CONTEXTS_2026.get(id(context)) is not context
        or context._expired
        or context._engine is not engine
        or context._controller is not controller
        or context._worker is not worker
        or context._runtime is not controller.runtime
        or _NATIVE_CONTROL_RAW_EXECUTIONS_2026.get(id(token))
        != (token, engine, controller, context)
    ):
        return False
    capture = context._capture
    if (
        type(capture) is not ControlFileCapture2026
        or worker._control_file_capture is not capture
        or capture._worker_ref() is not worker
        or capture._engine is not engine
        or capture._controller is not controller
        or capture._runtime is not controller.runtime
        or capture._thread_job is not job
        or capture._thread_id != child.ident
        or capture._phase != 1
        or capture._import_epoch != engine._identifier_context_epoch
        or capture.metadata.source_container.digest != session.container.digest
        or capture.metadata.source_sha256 != session.container.digest
        or capture.metadata.node != session.node
    ):
        return False
    from scripts.calibration_2026 import native2026_validate_runtime_metadata

    try:
        native2026_validate_runtime_metadata(capture.metadata)
    except (TypeError, ValueError):
        return False
    return True


def _validate_vbf_source(job, record):
    job.worker.validate_source(job.engine)
    metadata = job.engine.native_metadata
    job.engine._validate_persistence_source(metadata)
    sources = job.engine.file_sources
    if sources is not None:
        from scripts.cuw_file_services import validate_file_sources_2026

        validate_file_sources_2026(sources, job.engine)
    from scripts.calibration_2026 import native2026_cpu_values

    cpu = native2026_cpu_values(metadata, 0)
    if ".vbf" not in cpu.get("cpuimagename", ""):
        raise ValueError("Current first CPU is not a case-sensitive VBF source")
    if metadata.source_container is None or not metadata.source_sha256:
        raise ValueError("Authenticated current VBF FILE required")
    if metadata.source_sha256 != metadata.source_container.digest:
        raise ValueError("Current VBF FILE digest is not authenticated")
    if metadata.source_sha256 != job.engine.source_sha256:
        raise ValueError("Current VBF FILE differs from the engine source")
    # An actual141 producer may replace the selected FILE while the captured
    # old root remains the trace/sequence lineage.  worker.validate_source and
    # engine persistence/file-source validation authenticate the live view;
    # source_descriptor remains issue-time provenance, not an equality pin.
    view = {
        "metadata": metadata,
        "container": metadata.source_container,
        "file_sources": sources,
        "source_sha256": metadata.source_sha256,
        "node": metadata.node,
        "cpu_index": job.engine.dh_state.selection_cpu_index,
        "received_identifiers": job.worker._identifiers_for_file(
            job.worker.source_state.current_file_index
        ),
    }
    if any(type(item) is not bytes for item in view["received_identifiers"]):
        raise ValueError("Authenticated native received identifiers required")
    if record is not None and record.fields["container"] is not None:
        if (
            metadata.source_container is not record.fields["container"]
            or metadata.source_sha256 != record.fields["source_sha256"]
            or metadata.node != record.fields["node"]
            or sources is not record.fields["file_sources"]
            or job.worker.source_state.current_file_index != record.parked_file_index
            or view["received_identifiers"] != record.fields["received_identifiers"]
        ):
            raise ValueError("VBF prepared FILE changed after its authenticated view")
        if (
            job.engine.dh_state.selection_cpu_index != record.fields["cpu_index"]
            or job.engine.dh_state.global_cpu_index != record.parked_global_cpu_index
            or job.worker.source_state.current_global_cpu_index
            != record.parked_global_cpu_index
        ):
            job._validate_vbf_cpu_successor2026(record)
    return view


def _validate_vbf_lineage(job, request, record):
    fields = record.fields
    job.validate_owner(fields["engine"], fields["controller"])
    if (
        fields["worker"] is not job.worker
        or fields["runtime"] is not job.controller.runtime
        or fields["runtime"] is not job.worker.runtime
        or fields["trace"] is not fields["previous_session"].trace
        or fields["previous_sequence"] <= 0
        or job._completion_records.get(fields["previous_sequence"])
        is not record.previous_record
    ):
        raise ValueError("Captured VBF generation lineage changed")
    if (
        job._stop
        or job._host_stop
        or job._outer is None
        or not job._outer.is_alive()
        or job._child is None
        or not job._child.is_alive()
    ):
        raise ValueError("Live persistent VBF native threads required")
    _validate_vbf_source(job, record)
    state = fields["state"]
    if state in ("reserved", "adopted"):
        lease = record.lease
        if (
            lease is None
            or lease.vbf_request is not request
            or lease.phase != 1
            or job._sequence != fields["previous_sequence"] + 1
            or job._completion_records.get(job._sequence) is not job._active_record
            or job._session is not record.root
            or job._lease is not lease
        ):
            raise ValueError("Exact promoted VBF generation required")
    else:
        if job._sequence != fields["previous_sequence"]:
            raise ValueError("Unrelated native generation superseded VBF request")
        old_lease = fields["previous_lease"]
        if job._lease is old_lease and job._session is fields["previous_session"]:
            live = (
                old_lease.state == "adopted"
                and not record.previous_record.completed.is_set()
            )
            parked_cleanup = (
                old_lease.state == "released"
                and job._child_parked.is_set()
                and not record.previous_record.completed.is_set()
            )
            if not (live or parked_cleanup):
                raise ValueError("Exact live previous native generation required")
        elif (
            job._lease is not None
            or job._session is not None
            or old_lease.state != "released"
            or not record.previous_record.completed.is_set()
        ):
            raise ValueError("Captured previous generation did not retire normally")


def validate_vbf_process_before2026(
    request, job, *, states: tuple[str, ...], lease=None
) -> VbfProcessBeforeRequest2026:
    """Validate the only issued receipt for a real VBF resume transition."""
    if type(request) is not VbfProcessBeforeRequest2026:
        raise TypeError("Concrete VBF ProcessBefore request required")
    if type(job) is not EngineThreadJob2026:
        raise TypeError("Concrete native engine thread job required")
    if (
        type(states) is not tuple
        or not states
        or any(type(item) is not str for item in states)
    ):
        raise ValueError("Explicit VBF request lifecycle states required")
    record = _vbf_record(request)
    assert record.previous_record is not None
    if record.fields["job"] is not job:
        raise ValueError("VBF request belongs to another native job")
    with job._lock:
        _validate_vbf_lineage(job, request, record)
        if record.fields["state"] not in states:
            raise ValueError("VBF request lifecycle state is not admitted")
        if lease is not None and (
            type(lease) is not ThreadPhaseLease2026
            or record.lease is not lease
            or lease.vbf_request is not request
            or lease.engine is not job.engine
            or lease.controller is not job.controller
            or lease.phase != 1
        ):
            raise ValueError("Exact request-bound phase-one lease required")
    return request


def _queued_vbf_request(job):
    with _VBF_LOCK:
        matches = [
            request
            for request, record in _VBF_REQUESTS.values()
            if record.fields["job"] is job and record.fields["state"] == "queued"
        ]
    if len(matches) > 1:
        raise ValueError("Only one queued VBF source request is admitted")
    return matches[0] if matches else None


def _has_vbf_request2026(job) -> bool:
    """Read-only admission guard for ordinary engine phase entry points."""
    with _VBF_LOCK:
        return any(
            record.fields["job"] is job and record.fields["state"] != "abandoned"
            for _, record in _VBF_REQUESTS.values()
        )


def _discard_unbound_queued_vbf(job, request):
    if threading.current_thread() is not job._outer:
        raise ValueError("Only the actual outer owner may discard queued VBF work")
    with _VBF_LOCK:
        entry = _VBF_REQUESTS.get(id(request))
        if entry is None or entry[0] is not request:
            return
        record = entry[1]
        if (
            record.fields["job"] is job
            and record.fields["state"] == "queued"
            and record.lease is None
        ):
            record.fields["state"] = "abandoned"
            del _VBF_REQUESTS[id(request)]


def _promote_queued_vbf(job, request):
    """Promote a source request only on the outer after captured work retires."""
    validate_vbf_process_before2026(request, job, states=("queued",))
    record = _vbf_record(request)
    assert record.previous_record is not None
    if (
        threading.current_thread() is not job._outer
        or job._lease is not None
        or job._session is not None
        or not record.previous_record.completed.is_set()
        or record.fields["previous_lease"].state != "released"
    ):
        raise ValueError("Retired captured generation required for VBF promotion")
    try:
        next_lease = job.engine.reserve_phase(job.controller, 1, _vbf_request=request)
        next_session = record.root
        if next_session is None:
            job.engine.release_reserved_phase(next_lease)
            raise ValueError("Queued VBF source request lost its root")
    except BaseException:
        _discard_unbound_queued_vbf(job, request)
        raise
    next_sequence = record.fields["previous_sequence"] + 1
    next_record = _CompletionRecord2026(next_sequence)
    job._lease = next_lease
    job._session = next_session
    job._sequence = next_sequence
    job._active_record = next_record
    job._completion_records[next_sequence] = next_record
    job._completed.clear()
    job._child_done.clear()
    job._child_parked.clear()
    job._prepare_pending.clear()
    job._result = job._error = job._continuation = None
    job._child_exit = None
    job._waiting = False


class ThreadPhaseLease2026:
    """One engine lock reservation transferred to the actual child thread."""

    def __init__(self, engine, controller, phase, *, _token=None):
        if _token is not _TOKEN:
            raise TypeError("Engine-issued native thread phase lease required")
        self._engine = engine
        self._controller = controller
        self._phase = phase
        self._state = "reserved"
        self._thread: int | None = None
        self._vbf_request: VbfProcessBeforeRequest2026 | None = None

    @property
    def engine(self):
        return self._engine

    @property
    def controller(self):
        return self._controller

    @property
    def phase(self) -> int:
        return self._phase

    @property
    def vbf_request(self):
        return self._vbf_request

    @property
    def state(self) -> str:
        with _LOCK:
            return self._state

    def _adopt(self) -> None:
        with _LOCK:
            validate_thread_phase_lease(self, self.engine)
            if self._state != "reserved":
                raise ValueError("Native phase lease was already adopted")
            self._thread = threading.get_ident()
            self._state = "adopted"

    def _release(self) -> None:
        with _LOCK:
            validate_thread_phase_lease(self, self.engine)
            if self._state == "adopted" and self._thread != threading.get_ident():
                raise ValueError(
                    "Only the adopting native thread may release its lease"
                )
            self._state = "released"
            del _ISSUED[id(self)]


def _issue_thread_phase_lease(
    engine, controller, phase, *, _vbf_request=None
) -> ThreadPhaseLease2026:
    from scripts.cuw_2026 import CUWEngine2026
    from scripts.programming_2026_common import ControlCommPhase2026

    if (
        type(engine) is not CUWEngine2026
        or type(controller) is not ControlCommPhase2026
    ):
        raise TypeError("Concrete engine and controller required")
    if type(phase) is not int or phase not in (0, 1, 2):
        raise ValueError("Native outer worker phase must be0..2")
    if engine.worker.controller is not controller:
        raise ValueError("Native phase controller belongs to another engine worker")
    lease = ThreadPhaseLease2026(engine, controller, phase, _token=_TOKEN)
    with _LOCK:
        _ISSUED[id(lease)] = lease
    if _vbf_request is not None:
        try:
            job = engine.thread_job
            if job is None:
                raise ValueError("Actual VBF thread job required for lease binding")
            lease._vbf_request = _vbf_request
            job._bind_vbf_phase_lease2026(_vbf_request, lease)
        except BaseException:
            with _LOCK:
                _ISSUED.pop(id(lease), None)
            raise
    return lease


def validate_thread_phase_lease(lease, engine, *, controller=None, phase=None) -> None:
    with _LOCK:
        if (
            type(lease) is not ThreadPhaseLease2026
            or _ISSUED.get(id(lease)) is not lease
            or lease.engine is not engine
            or (controller is not None and lease.controller is not controller)
            or (phase is not None and lease.phase != phase)
        ):
            raise ValueError("Actual issued engine thread phase lease required")


@dataclass(frozen=True)
class ThreadState2026:
    """Readonly native CFD4/CFE0 observations, never scheduling inputs."""

    outer_started: bool
    child_started: bool
    child_alive: bool
    stop_requested: bool
    waiting_for_resume: bool
    prepare_acknowledgement_pending: bool
    sequence: int
    child_exit_code: int | None
    outer_exit_code: int | None


@dataclass
class _CompletionRecord2026:
    sequence: int
    completed: threading.Event = field(default_factory=threading.Event)
    result: dict | None = None
    error: BaseException | None = None
    continuation: WorkerContinuation2026 | None = None
    getter_native: bool = False


@dataclass(frozen=True, eq=False)
class _NativeGetterStopReceipt2026:
    """One source-issued native start+14 write retained for this CStart."""

    job: EngineThreadJob2026
    worker: object
    controller: object
    lease: ThreadPhaseLease2026 | None
    sequence: int
    producer: Literal["5f030", "40580", "31780"]
    origin: object


@dataclass
class _NativeGetterStopStage2026:
    """One source stop transaction, advanced monotonically on its CStart."""

    receipt: _NativeGetterStopReceipt2026
    stage: Literal["child_requested", "outer_requested", "completed"]
    child: threading.Thread | None
    outer: threading.Thread | None = None
    event_published: bool = False
    schedule_published: bool = False


@dataclass(frozen=True, eq=False)
class _NativeGetterEntryOrigin2026:
    """One hidden34cb0 first-entry authority bound to an exact unpublished job."""

    engine: CUWEngine2026
    job: EngineThreadJob2026
    worker: object
    controller: ControlCommPhase2026
    generation: object
    session: ProgrammingReplay
    issuer_thread: int
    previous_phase: int | None
    previous_record: _CompletionRecord2026 | None
    record: _CompletionRecord2026
    sequence: int
    lease: ThreadPhaseLease2026
    source_set: FileSourceSet2026 | None
    source_container: object
    source_sha256: str
    metadata: Native2026Metadata
    configuration: object
    flow_index: int
    flow_view: object | None
    pointer_view: object | None
    cfe0_at_issue: bool


@dataclass(eq=False)
class _GetterEntryStartBinding2026:
    """Lexical start() transaction recognized only while its RLock is held."""

    marker: object
    session: ProgrammingReplay
    record: _CompletionRecord2026
    previous_record: _CompletionRecord2026 | None
    sequence: int
    issuer_thread: int
    generation: object
    source_set: FileSourceSet2026 | None
    source_container: object
    source_sha256: str
    metadata: Native2026Metadata
    configuration: object
    flow_index: int
    flow_view: object | None
    pointer_view: object | None
    cfe0_at_issue: bool
    previous_phase: int | None = None


@dataclass(eq=False)
class _NativeGetterNextEntryOrigin2026:
    """Single live authorization for the selected named-next getter branch."""

    job: EngineThreadJob2026
    engine: CUWEngine2026
    worker: object
    controller: ControlCommPhase2026
    generation: object
    issuer_thread: int
    decision: _NativeGetterDecision2026
    execute_record: _NativeGetterExecuteReturn2026
    context: NativeControlContext2026
    output: NativeControlGetterOutput2026 | None
    observation: object
    lease: ThreadPhaseLease2026
    sequence: int
    record: _CompletionRecord2026
    session: ProgrammingReplay
    source_set: object
    current_flow: int
    current_flow_view: object
    current_pointer_view: object
    fanout_group: object | None
    next_flow_view: object
    next_pointer_view: object
    projected_metadata: Native2026Metadata
    reset_epoch: int
    capture_epoch: int
    persistence: object
    persistence_state: object
    cfe0_at_issue: bool
    be54_at_issue: bool
    variant: Literal["named_next", "named_terminal", "no_table"]
    frontend_selection_point2026: object | None = None
    wait_restore_point2026: object | None = None
    progress: str = "issued"


@dataclass(frozen=True, eq=False)
class _OrdinaryPrepareStartBinding2026:
    """Identity snapshot for one lexical ordinary36800 job.start call."""

    marker: object
    job: EngineThreadJob2026
    engine: CUWEngine2026
    generation: object
    worker: object
    controller: ControlCommPhase2026
    runtime: object
    issuer_thread: int
    sequence: int
    session: ProgrammingReplay
    trace: object
    input_container: object
    input_node: object
    previous_sequence: int
    previous_record: _CompletionRecord2026 | None
    previous_session: ProgrammingReplay | None
    previous_lease: ThreadPhaseLease2026 | None
    source_metadata: Native2026Metadata
    source_container: object
    source_digest: str
    source_set: FileSourceSet2026 | None
    configuration: object
    persistence: object | None
    persistence_state: object | None
    flow_index: int
    flow_view: object | None
    pointer_view: object | None
    reset_epoch: int
    persisted_cpu_index: int | None
    persisted_cpu_offset: int | None
    native_phase: int
    worker_phase: int | None
    prepare_handshake: int
    cfe0: bool
    be54: bool
    cfe2: bool
    stop_requested: bool
    host_stop: bool
    stop_receipt: _NativeGetterStopReceipt2026 | None
    continuation: object | None


@dataclass(eq=False)
class _OrdinaryPrepareOrigin2026:
    """One mutable, exact-slot authority for the literal pre-child 36800 path."""

    binding: _OrdinaryPrepareStartBinding2026
    scope: object
    stage: Literal[
        "issued",
        "retained_type",
        "device",
        "clock",
        "outputs",
        "phase",
        "branch",
        "recovery",
        "nonrecovery",
        "cid",
        "cpu_tail",
        "prepared",
        "reserved",
        "scheduled",
        "early_return",
    ] = "issued"
    started_ms: int | None = None
    phase: int | None = None
    recovery: bool | None = None
    metadata: Native2026Metadata | None = None
    source_container: object | None = None
    source_digest: str | None = None
    source_set: FileSourceSet2026 | None = None
    flow_index: int | None = None
    flow_view: object | None = None
    pointer_view: object | None = None
    reset_epoch: int | None = None
    record: _CompletionRecord2026 | None = None
    lease: ThreadPhaseLease2026 | None = None
    prepared_entry: _PreparedOrdinaryEntry2026 | None = None
    cpu_witness: object | None = None
    source_progress: tuple[int, ...] = ()

    @property
    def progress(self) -> str:
        """Worker-facing spelling for the literal, monotonic source stage."""
        return self.stage


@dataclass(frozen=True, eq=False)
class _PreparedOrdinaryEntry2026:
    """Immutable pre-child36800 result consumed once by its adopted child."""

    origin: _OrdinaryPrepareOrigin2026
    job: EngineThreadJob2026
    engine: CUWEngine2026
    generation: object
    worker: object
    controller: ControlCommPhase2026
    runtime: object
    session: ProgrammingReplay
    record: _CompletionRecord2026
    sequence: int
    lease: ThreadPhaseLease2026
    started_ms: int
    phase: int
    recovery: bool
    metadata: Native2026Metadata
    source_container: object
    source_digest: str
    source_set: FileSourceSet2026 | None
    persistence: object | None
    persistence_state: object | None
    flow_index: int
    flow_view: object | None
    pointer_view: object | None
    reset_epoch: int
    cpu_index: int
    cpu_offset: int
    persisted_cpu_index: int | None
    persisted_cpu_offset: int | None
    cfe0: bool
    be54: bool
    cfe2: bool
    native_phase: int
    worker_phase: int


@dataclass(frozen=True, eq=False)
class _NativeGetterRetirement2026:
    """One actual3cb90 outer retirement probe/reset boundary."""

    job: EngineThreadJob2026
    engine: CUWEngine2026
    worker: object
    controller: ControlCommPhase2026
    generation: object
    sequence: int
    record: _CompletionRecord2026
    session: ProgrammingReplay | None
    lease: ThreadPhaseLease2026 | None
    child: threading.Thread | None
    issuer_thread: int


@dataclass(frozen=True, eq=False)
class _NativeGetterExecuteReturn2026:
    context: NativeControlContext2026
    lease: ThreadPhaseLease2026
    sequence: int
    result: dict
    execute_return: bool


@dataclass(frozen=True, eq=False)
class _NativeGetterCallbackCandidate2026:
    job: EngineThreadJob2026
    worker: object
    lease: ThreadPhaseLease2026
    sequence: int
    output: NativeControlGetterOutput2026 | None
    execute_return: bool
    stop_receipt: _NativeGetterStopReceipt2026 | None
    start_stop_requested_14: bool
    candidate: Literal["success_3d120", "failure_30340", "stop_3dde0"]
    candidate_sequence: int
    execute_record: _NativeGetterExecuteReturn2026


@dataclass(frozen=True, eq=False)
class _NativeGetterDecision2026:
    job: EngineThreadJob2026
    worker: object
    lease: ThreadPhaseLease2026
    sequence: int
    candidate: _NativeGetterCallbackCandidate2026
    prepare_handshake_be8: int
    route: Literal["success_3d120", "failure_30340", "stop_3dde0", "suppressed"]
    decision_sequence: int


def _timeout_deadline(timeout: float) -> float:
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise TypeError("Finite positive host timeout required")
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("Finite positive host timeout required")
    return time.monotonic() + timeout


class EngineThreadJob2026:
    """Issued native worker with real child work, be54 resume and bounded joins."""

    def __init__(self, engine, controller, *, _token=None):
        if _token is not _TOKEN:
            raise TypeError("Engine-issued native thread job required")
        self.engine: CUWEngine2026 = engine
        self.controller: ControlCommPhase2026 = controller
        self.worker = engine.worker
        self._lock = threading.RLock()
        self._resume = threading.Event()
        self._completed = threading.Event()
        self._child_resume = threading.Event()
        self._child_done = threading.Event()
        self._child_parked = threading.Event()
        self._prepare_pending = threading.Event()
        self._activity = threading.Event()
        self._callback_requested = threading.Event()
        self._callback_returned = threading.Event()
        self._callback_error: BaseException | None = None
        self._callback_kind: str | None = None
        self._callback_argument: int | None = None
        self._callback_context = None
        self._outer: threading.Thread | None = None
        self._child: threading.Thread | None = None
        self._lease: ThreadPhaseLease2026 | None = None
        self._session: ProgrammingReplay | None = None
        self._stop = False
        self._host_stop = False
        self._waiting = False
        self._sequence = 0
        self._completion_records: dict[int, _CompletionRecord2026] = {}
        self._active_record: _CompletionRecord2026 | None = None
        self._result: dict | None = None
        self._error: BaseException | None = None
        self._continuation: WorkerContinuation2026 | None = None
        self._child_exit: int | None = None
        self._outer_exit: int | None = None
        self._controller_entry: str | None = None
        self._native_start_generation2026 = object()
        self._getter_stop_receipt2026: _NativeGetterStopReceipt2026 | None = None
        self._getter_stop_stage2026: _NativeGetterStopStage2026 | None = None
        self._getter_entry_origin2026: _NativeGetterEntryOrigin2026 | None = None
        self._getter_entry_binding2026 = None
        self._getter_entry_starting2026 = False
        self._ordinary_prepare_binding2026 = None
        self._ordinary_prepare_origin2026 = None
        self._ordinary_prepare_starting2026 = False
        self._prepared_ordinary_entry2026 = None
        self._getter_retirement2026: _NativeGetterRetirement2026 | None = None
        self._getter_retirement_stage2026: (
            Literal["issued", "probed_false", "probed_true", "reset", "retired"] | None
        ) = None
        self._getter_retirement_pending2026 = None
        self._pending_getter_next_entry_3d120_2026 = None
        self._issued_getter_continuation2026 = None
        self._getter_continuation2026 = None
        self._getter_continuation_stage2026: Literal["pending", "promoting"] | None = (
            None
        )
        self._getter_promotion_root2026 = None
        self._getter_promotion_starting2026 = False
        self._getter_decision_dispatching2026 = None
        self._getter_decision_dispatched_sequence2026 = 0
        self._getter_execute_return2026: _NativeGetterExecuteReturn2026 | None = None
        self._getter_execute_pending2026 = None
        self._getter_callback_candidate2026: (
            _NativeGetterCallbackCandidate2026 | None
        ) = None
        self._getter_callback_decision2026: _NativeGetterDecision2026 | None = None
        self._getter_candidate_sequence2026 = 0
        self._getter_decision_sequence2026 = 0
        self._getter_native_fatal_ack2026: _NativeGetterCallbackCandidate2026 | None = (
            None
        )
        self._getter_control_fatal_ack2026: (
            _NativeGetterCallbackCandidate2026 | None
        ) = None

    def validate_owner(self, engine, controller=None) -> None:
        if (
            self.engine is not engine
            or engine.thread_job is not self
            or engine.worker is not self.worker
        ):
            raise ValueError("Native thread job belongs to another engine worker")
        if self.worker.controller is not self.controller or (
            controller is not None and controller is not self.controller
        ):
            raise ValueError("Native thread job controller identity changed")

    def _record_getter_stop_14_2026(
        self, *, producer: str, origin: object
    ) -> _NativeGetterStopReceipt2026:
        """Record the exact engine-consumed source write on this CStart."""
        if producer not in ("5f030", "40580"):
            raise ValueError("Unsupported native getter-stop producer")
        with self._lock:
            self.validate_owner(self.engine, self.controller)
            if self._getter_stop_receipt2026 is not None:
                raise ValueError(
                    "Native start+14 stop is already issued on this CStart"
                )
            receipt = _NativeGetterStopReceipt2026(
                self,
                self.worker,
                self.controller,
                self._lease,
                self._sequence,
                producer,
                origin,
            )
            self.engine._consume_getter_stop_origin2026(
                origin, job=self, producer=producer
            )
            self._getter_stop_receipt2026 = receipt
            self._getter_stop_stage2026 = _NativeGetterStopStage2026(
                receipt,
                "child_requested",
                self._child,
            )
            return receipt

    def _validate_getter_stop_lease2026(
        self, lease: ThreadPhaseLease2026, sequence: int, producer: str
    ) -> None:
        """Validate only the exact lease still current at a native stop edge."""
        if producer not in ("5f030", "40580"):
            raise ValueError("Unsupported native getter-stop producer")
        with self._lock, _LOCK:
            record = self._completion_records.get(sequence)
            if (
                type(lease) is not ThreadPhaseLease2026
                or self._lease is not lease
                or self._sequence != sequence
                or sequence <= 0
                or lease.engine is not self.engine
                or lease.controller is not self.controller
                or self._active_record is not record
                or record is None
                or record.sequence != sequence
                or record.completed.is_set()
                or self._completed.is_set()
                or (producer == "5f030" and lease.phase != 0)
            ):
                raise ValueError("Native getter stop lost its exact phase lease")
            registered = _ISSUED.get(id(lease)) is lease
            if lease._state in ("reserved", "adopted"):
                if not registered:
                    raise ValueError(
                        "Live native getter-stop lease is not source-issued"
                    )
                if lease._state == "adopted" and (
                    self._child is None or lease._thread != self._child.ident
                ):
                    raise ValueError("Adopted native getter-stop lease lost its child")
                return
            if lease._state == "released":
                if (
                    registered
                    or self.engine.active
                    or self.engine._phase_thread is not None
                    or not self.engine._phase_finished.is_set()
                ):
                    raise ValueError(
                        "Released getter-stop lease is outside source unwind"
                    )
                return
            raise ValueError("Native getter-stop lease is not current")

    def _begin_native_retirement_3cb90_2026(self):
        """Mark the exact live outer record immediately before its 1c58 release."""
        if threading.current_thread() is not self._outer:
            raise ValueError("3cb90 retirement belongs to the actual outer thread")
        with self._lock:
            self.validate_owner(self.engine, self.controller)
            if self._getter_retirement_stage2026 == "retired":
                self._getter_retirement2026 = None
                self._getter_retirement_stage2026 = None
            record, lease, session, child = (
                self._active_record,
                self._lease,
                self._session,
                self._child,
            )
            if (
                record is None
                or record is not self._completion_records.get(self._sequence)
                or record.sequence != self._sequence
                or record.completed.is_set()
                or self._completed.is_set()
                or lease is None
                or lease.state != "released"
                or lease.engine is not self.engine
                or lease.controller is not self.controller
                or session is None
                or child is None
                or not self._child_done.is_set()
                or not self._child_parked.is_set()
                or (
                    child.is_alive()
                    and not (self._child_done.is_set() and self._child_parked.is_set())
                )
                or self._getter_retirement_pending2026 is not None
                or self._getter_retirement2026 is not None
            ):
                raise ValueError("Exact retired getter phase required at 3cb90")
            pending = (record, lease, session, child, threading.current_thread())
            self._getter_retirement_pending2026 = pending
            return pending

    def _issue_native_retirement_3cb90_2026(self, pending):
        """Consume only the marker surrounding the actual 3cb90 release call."""
        issuer_thread = threading.current_thread().ident
        with self._lock:
            if (
                threading.current_thread() is not self._outer
                or self._getter_retirement_pending2026 is not pending
                or type(pending) is not tuple
                or len(pending) != 5
                or pending[0] is not self._active_record
                or pending[0] is not self._completion_records.get(self._sequence)
                or pending[0].sequence != self._sequence
                or pending[0].completed.is_set()
                or pending[1] is None
                or pending[1] is not self._lease
                or pending[2] is not self._session
                or pending[3] is None
                or pending[3] is not self._child
                or not self._child_done.is_set()
                or not self._child_parked.is_set()
                or pending[4] is not threading.current_thread()
                or type(issuer_thread) is not int
                or (
                    pending[3].is_alive()
                    and not (self._child_done.is_set() and self._child_parked.is_set())
                )
            ):
                raise ValueError("Exact source 3cb90 retirement boundary required")
            retirement = _NativeGetterRetirement2026(
                self,
                self.engine,
                self.worker,
                self.controller,
                self._native_start_generation2026,
                self._sequence,
                pending[0],
                pending[2],
                pending[1],
                pending[3],
                issuer_thread,
            )
            self._getter_retirement_pending2026 = None
            self._getter_retirement2026 = retirement
            self._getter_retirement_stage2026 = "issued"
            return retirement

    def _validate_native_retirement_3cb90_2026(self, retirement: object) -> None:
        """Validate one exact source retirement probe/reset transaction."""
        if type(retirement) is not _NativeGetterRetirement2026:
            raise TypeError("Exact native 3cb90 retirement required")
        with self._lock:
            stage = self._getter_retirement_stage2026
            lease = retirement.lease
            child = retirement.child
            before_probe = stage == "issued"
            if (
                self._getter_retirement2026 is not retirement
                or retirement.job is not self
                or retirement.engine is not self.engine
                or retirement.worker is not self.worker
                or retirement.controller is not self.controller
                or retirement.generation is not self._native_start_generation2026
                or retirement.sequence <= 0
                or retirement.record
                is not self._completion_records.get(retirement.sequence)
                or retirement.record.sequence != retirement.sequence
                or (before_probe and retirement.record.completed.is_set())
                or (not before_probe and not retirement.record.completed.is_set())
                or (before_probe and self._active_record is not retirement.record)
                or lease is None
                or lease.state != "released"
                or (before_probe and lease is not self._lease)
                or (before_probe and retirement.session is not self._session)
                or child is None
                or (
                    before_probe
                    and (
                        not self._child_done.is_set() or not self._child_parked.is_set()
                    )
                )
                or threading.current_thread() is not self._outer
                or retirement.issuer_thread != threading.current_thread().ident
                or stage not in ("issued", "probed_true")
            ):
                raise ValueError("Native 3cb90 retirement is stale or out of order")

    def _record_native_retirement_probe2026(self, retirement, signaled: bool) -> None:
        if type(signaled) is not bool:
            raise TypeError("Actual BE54 probe result required")
        with self._lock:
            self._validate_native_retirement_3cb90_2026(retirement)
            if self._getter_retirement_stage2026 != "issued":
                raise ValueError("Native 3cb90 probe was already consumed")
            if signaled is not self.engine._native_be54_pending2026:
                raise ValueError("BE54 changed during its native probe")
            self._getter_retirement_stage2026 = (
                "probed_true" if signaled else "probed_false"
            )

    def _observe_native_retirement_wake2026(self, retirement) -> bool:
        """Classify a host wake by rereading BE54; never synthesize its signal."""
        with self._lock:
            if (
                self._getter_retirement2026 is not retirement
                or self._getter_retirement_stage2026 != "probed_false"
                or threading.current_thread() is not self._outer
            ):
                raise ValueError("Native false-probe wake is out of order")
            signaled = self.engine._native_be54_pending2026
            if signaled:
                self._getter_retirement_stage2026 = "probed_true"
            else:
                self._getter_retirement_stage2026 = "retired"
            return signaled

    def _finish_native_retirement2026(self, retirement) -> None:
        with self._lock:
            if self._getter_retirement2026 is not retirement or (
                self._getter_retirement_stage2026
                not in ("probed_true", "reset", "retired")
            ):
                raise ValueError("Native retirement did not reach an observed terminal")
            self._getter_retirement_stage2026 = "retired"

    def _validate_getter_stop_stage2026(self, receipt: object) -> None:
        """Validate the one monotonic child/outer stop transaction."""
        if type(receipt) is not _NativeGetterStopReceipt2026:
            raise TypeError("Exact retained native getter-stop receipt required")
        with self._lock:
            stage = self._getter_stop_stage2026
            origin = receipt.origin
            if (
                self._getter_stop_receipt2026 is not receipt
                or stage is None
                or stage.receipt is not receipt
                or receipt.job is not self
                or receipt.worker is not self.worker
                or receipt.controller is not self.controller
                or receipt.producer not in ("5f030", "40580")
                or getattr(origin, "job", None) is not self
                or getattr(origin, "worker", None) is not self.worker
                or getattr(origin, "controller", None) is not self.controller
                or getattr(origin, "generation", None)
                is not self._native_start_generation2026
                or getattr(origin, "sequence", None) != receipt.sequence
                or getattr(origin, "lease", None) is not receipt.lease
                or getattr(origin, "producer", None) != receipt.producer
                or receipt.sequence != self._sequence
                or self._completion_records.get(receipt.sequence)
                is not self._active_record
                or self._active_record is None
                or self._active_record.sequence != receipt.sequence
            ):
                raise ValueError("Native getter-stop stage is stale or foreign")
            if stage.child is not self._child or (
                stage.outer is not None and stage.outer is not self._outer
            ):
                raise ValueError("Native getter-stop captured thread changed")

    def _request_getter_child_stop_2026(
        self, receipt: _NativeGetterStopReceipt2026
    ) -> threading.Thread:
        """Publish only child_requested and signal the actual child event."""
        with self._lock:
            self._validate_getter_stop_stage2026(receipt)
            stage = self._getter_stop_stage2026
            assert stage is not None
            if stage.stage == "completed":
                raise ValueError("Native getter stop is already complete")
            if stage.stage == "outer_requested":
                child = stage.child
                if child is None:
                    raise ValueError("Outer stop has no captured child")
                return child
            if stage.child is None:
                stage.stage = "child_requested"
                child = self._ensure_native_child_started2026(receipt)
                stage.child = child
            child = stage.child
            assert child is not None
            stage.stage = "child_requested"
            self._child_resume.set()
            return child

    def _request_getter_outer_stop_2026(
        self, receipt: _NativeGetterStopReceipt2026
    ) -> tuple[threading.Thread, bool]:
        """Advance only after the exact child terminated; return publish-once bit."""
        with self._lock:
            self._validate_getter_stop_stage2026(receipt)
            stage = self._getter_stop_stage2026
            assert stage is not None
            if stage.stage == "completed":
                raise ValueError("Native getter stop is already complete")
            if stage.stage == "outer_requested":
                if stage.outer is None:
                    raise ValueError("Outer stop lost its captured thread")
                return stage.outer, False
            child = stage.child
            if child is None or child.is_alive():
                raise ValueError("Native getter child has not reached terminal state")
            if (
                type(self._child_exit) is not int
                or self._child_exit not in (0, 1)
                or self._outer is None
                or not self._outer.is_alive()
            ):
                raise ValueError("Native getter outer stop lineage is incomplete")
            stage.stage = "outer_requested"
            stage.outer = self._outer
            # This is the native stop-loop latch. Host interruption remains separate.
            self._stop = True
            return stage.outer, True

    def _publish_getter_stop_schedule_2026(
        self,
        receipt: _NativeGetterStopReceipt2026,
        *,
        native_event: bool,
    ) -> None:
        """Wake the captured outer only after the post-child source event point."""
        if type(native_event) is not bool:
            raise TypeError("Native getter stop event decision required")
        with self._lock:
            self._validate_getter_stop_stage2026(receipt)
            stage = self._getter_stop_stage2026
            assert stage is not None
            if stage.stage != "outer_requested":
                raise ValueError("Native getter outer stop request required")
            if stage.schedule_published:
                return
            if native_event is not self.engine._native_outer_cfe0_2026:
                raise ValueError("Native getter stop event differs from CFE0")
            if native_event is not self.engine._native_be54_pending2026:
                raise ValueError("Native getter BE54 store differs from its event")
            stage.event_published = native_event
            stage.schedule_published = True
            self._resume.set()

    def _complete_getter_stop_2026(self, receipt: _NativeGetterStopReceipt2026) -> None:
        """Retire only a fully joined source stop; retain its monotonic receipt."""
        with self._lock:
            self._validate_getter_stop_stage2026(receipt)
            stage = self._getter_stop_stage2026
            assert stage is not None
            if (
                stage.stage != "outer_requested"
                or not stage.schedule_published
                or stage.outer is None
                or stage.outer.is_alive()
                or stage.child is None
                or stage.child.is_alive()
            ):
                raise ValueError("Native getter stop has not joined both threads")
            stage.stage = "completed"
            self._child = self._outer = None

    def _ensure_native_child_started2026(self, authority: object) -> threading.Thread:
        """Create the one real child for an outer iteration or retained14 stop."""
        if threading.current_thread() is not self._outer:
            if (
                type(authority) is not _NativeGetterStopReceipt2026
                or authority is not self._getter_stop_receipt2026
            ):
                raise ValueError("Actual outer record or retained14 authority required")
            self._validate_getter_stop_stage2026(authority)
            stage = self._getter_stop_stage2026
            if stage is None or stage.stage != "child_requested":
                raise ValueError("Only child_requested can create a native child")
        else:
            with self._lock:
                record = self._active_record
                if (
                    authority is not record
                    or record is None
                    or record.sequence != self._sequence
                ):
                    raise ValueError("Actual outer scheduling record required")
                lease = self._lease
                if lease is None or lease.state != "reserved":
                    raise ValueError("Actual reserved native work required")
        with self._lock:
            existing = self._child
            if existing is not None:
                return existing
            child = threading.Thread(
                target=self._run_child, name="CUW2026-5ccd0", daemon=True
            )
            self._child = child
            try:
                child.start()
            except BaseException:
                if self._child is child:
                    self._child = None
                raise
            return child

    def _record_getter_execute_return_2026(self, context, result: dict) -> None:
        """Capture only the exact direct phase-zero Execute return before import."""
        from scripts.programming_2026_common import (
            NativeControlContext2026,
            _control_getter_return_al2026,
            _control_has_ordinary_getter_return2026,
        )

        if threading.current_thread() is not self._child:
            raise ValueError("Direct getter Execute return belongs to the child")
        with self._lock:
            lease, record = self._lease, self._active_record
            pending = self._getter_execute_pending2026
            if type(context) is not NativeControlContext2026:
                raise ValueError("Exact source-issued getter context required")
            context.validate(self.engine, self.controller)
            phase = result.get("native_phase") if type(result) is dict else None
            execute_return = (
                result.get("native_return") if type(result) is dict else None
            )
            if (
                type(context) is not NativeControlContext2026
                or type(result) is not dict
                or type(phase) is not int
                or phase != 0
                or type(execute_return) is not bool
                or lease is None
                or lease.phase != 0
                or self._sequence <= 0
                or record is None
                or record is not self._completion_records.get(self._sequence)
                or record.sequence != self._sequence
                or context._capture._thread_job is not self
                or context._capture.job_sequence != self._sequence
                or context._capture.phase_lease is not lease
                or context._capture.raw_session is not self._session
                or context._capture.completion_record is not record
                or self.engine._controller_execution is not self.controller
                or self.controller.native_control_context2026(self.engine)
                is not context
                or context._capture._phase != 0
                or not _control_has_ordinary_getter_return2026(context)
                or _control_getter_return_al2026(context) is not execute_return
                or type(pending) is not tuple
                or len(pending) != 4
                or pending[0] is not context
                or pending[1] is not result
                or pending[2] is not lease
                or pending[3] != self._sequence
                or self._getter_execute_return2026 is not None
            ):
                raise ValueError("Exact ordinary getter Execute result required")
            self._getter_execute_return2026 = _NativeGetterExecuteReturn2026(
                context, lease, self._sequence, result, execute_return
            )
            record.getter_native = True
            self._getter_execute_pending2026 = None

    def _capture_getter_candidate_2026(self, context):
        """Freeze the source candidate after the real outer 5a050 import."""
        from scripts.programming_2026_common import NativeControlContext2026

        if threading.current_thread() is not self._child:
            raise ValueError("Getter candidate belongs to the actual child")
        with self._lock:
            execute_record = self._getter_execute_return2026
            lease, active = self._lease, self._active_record
            if (
                type(context) is not NativeControlContext2026
                or execute_record is None
                or execute_record.context is not context
                or execute_record.lease is not lease
                or execute_record.sequence != self._sequence
            ):
                raise ValueError("Exact imported getter Execute lineage required")
            context.validate(self.engine, self.controller)
            self.validate_owner(self.engine, self.controller)
            if (
                lease is None
                or lease.phase != 0
                or active is None
                or active is not self._completion_records.get(self._sequence)
                or active.sequence != self._sequence
                or execute_record.context._capture._thread_job is not self
                or execute_record.context._capture.job_sequence != self._sequence
                or execute_record.context._capture.phase_lease is not lease
                or execute_record.context._capture.raw_session is not self._session
                or execute_record.context._capture.completion_record is not active
            ):
                raise ValueError("Current ordinary getter phase required")
            output = self.worker._imported_getter_output2026(context)
            from scripts.programming_2026_common import _control_getter_return_al2026

            if (
                _control_getter_return_al2026(context)
                is not execute_record.execute_return
            ):
                raise ValueError("Imported raw AL differs from direct Execute return")
            if (
                output is not None
                and output.raw_al is not execute_record.execute_return
            ):
                raise ValueError(
                    "Typed getter output differs from direct Execute return"
                )
            stop_receipt = self._getter_stop_receipt2026
            if stop_receipt is not None and (
                stop_receipt.job is not self
                or stop_receipt.worker is not self.worker
                or stop_receipt.controller is not self.controller
            ):
                raise ValueError("Native getter stop receipt belongs to another job")
            if self._getter_callback_candidate2026 is not None:
                raise ValueError("Getter callback candidate was already issued")
            self._getter_candidate_sequence2026 += 1
            candidate = (
                "stop_3dde0"
                if stop_receipt is not None
                else "success_3d120"
                if execute_record.execute_return
                else "failure_30340"
            )
            result = _NativeGetterCallbackCandidate2026(
                self,
                self.worker,
                lease,
                self._sequence,
                output,
                execute_record.execute_return,
                stop_receipt,
                stop_receipt is not None,
                candidate,
                self._getter_candidate_sequence2026,
                execute_record,
            )
            self._getter_callback_candidate2026 = result
            return result

    def _finish_getter_decision_2026(self, candidate):
        """Sample BE8 only after both distinct native fatal-output acknowledgements."""
        if threading.current_thread() is not self._child:
            raise ValueError("Getter decision belongs to the actual child")
        with self._lock:
            record = self._active_record
            capture = (
                candidate.execute_record.context._capture
                if type(candidate) is _NativeGetterCallbackCandidate2026
                else None
            )
            if (
                type(candidate) is not _NativeGetterCallbackCandidate2026
                or self._getter_callback_candidate2026 is not candidate
                or candidate.job is not self
                or candidate.worker is not self.worker
                or candidate.lease is not self._lease
                or candidate.sequence != self._sequence
                or record is None
                or record is not self._completion_records.get(self._sequence)
                or record.sequence != self._sequence
                or capture is None
                or capture._thread_job is not self
                or capture.job_sequence != self._sequence
                or capture.phase_lease is not candidate.lease
                or capture.raw_session is not self._session
                or capture.completion_record is not record
                or self._getter_native_fatal_ack2026 is not candidate
                or self._getter_control_fatal_ack2026 is not candidate
                or self._getter_callback_decision2026 is not None
            ):
                raise ValueError(
                    "Both exact getter fatal-output acknowledgements required"
                )
            handshake = self.worker.native_prepare_handshake
            if type(handshake) is not int or handshake not in (0, 1, 2, 3):
                raise ValueError("Actual native BE8 byte required")
            route = "suppressed" if handshake == 2 else candidate.candidate
            self._getter_decision_sequence2026 += 1
            decision = _NativeGetterDecision2026(
                self,
                self.worker,
                candidate.lease,
                candidate.sequence,
                candidate,
                handshake,
                route,
                self._getter_decision_sequence2026,
            )
            self._getter_callback_decision2026 = decision
            return decision

    def _validate_getter_decision_2026(self, decision, *, route: str) -> None:
        """Validate a still-live decision without consuming or dispatching it."""
        if type(decision) is not _NativeGetterDecision2026 or type(route) is not str:
            raise TypeError("Exact issued getter decision and route required")
        with self._lock:
            self.validate_owner(self.engine, self.controller)
            decision.candidate.execute_record.context.validate(
                self.engine, self.controller
            )
            record = self._completion_records.get(decision.sequence)
            capture = decision.candidate.execute_record.context._capture
            if (
                self._getter_callback_decision2026 is not decision
                or decision.job is not self
                or decision.worker is not self.worker
                or decision.lease is not self._lease
                or decision.sequence != self._sequence
                or decision.candidate is not self._getter_callback_candidate2026
                or decision.route != route
                or decision.candidate.candidate_sequence
                != self._getter_candidate_sequence2026
                or decision.decision_sequence != self._getter_decision_sequence2026
                or record is None
                or record is not self._active_record
                or record.sequence != decision.sequence
                or capture._thread_job is not self
                or capture.job_sequence != decision.sequence
                or capture.phase_lease is not decision.lease
                or capture.raw_session is not self._session
                or capture.completion_record is not record
            ):
                raise ValueError(
                    "Getter decision is stale, foreign, or already retired"
                )

    def _validate_getter_success_handoff2026(self, decision) -> None:
        """Require the actual registered success callback on the outer carrier."""
        if threading.current_thread() is not self._outer:
            raise ValueError("Getter success consumer belongs to the outer carrier")
        with self._lock:
            if (
                self._callback_kind != "getter_success_3d120"
                or not self._callback_requested.is_set()
                or self._callback_context is not decision
                or self._getter_decision_dispatching2026 is not decision
            ):
                raise ValueError("Exact registered getter-success handoff required")
            self.validate_callback_handoff()
            self._validate_getter_decision_2026(decision, route="success_3d120")

    def _issue_getter_next_entry_3d120_2026(
        self,
        decision,
        *,
        source_set,
        current_flow_view,
        current_pointer_view,
        fanout_group,
        next_flow_view,
        next_pointer_view,
        projected_metadata,
    ):
        """Issue only the actual named-next G branch after its source preflight."""
        from scripts.cuw_file_services import (
            FileSourceSet2026,
            NativeFileGroupView2026,
            NativeFileView2026,
            validate_file_group_view_2026,
            validate_file_sources_2026,
            validate_file_view_2026,
        )

        self._validate_getter_success_handoff2026(decision)
        if (
            type(source_set) is not FileSourceSet2026
            or not source_set.has_file_vector
            or self.worker._file_sources is not source_set
            or type(projected_metadata) is not type(self.engine.native_metadata)
        ):
            raise ValueError("Authenticated named FILE source required for G next")
        validate_file_sources_2026(source_set, self.engine)
        if type(current_flow_view) is not NativeFileView2026:
            raise ValueError("Actual current native flow view required")
        validate_file_view_2026(current_flow_view, source_set)
        validate_file_view_2026(current_pointer_view, source_set)
        validate_file_view_2026(next_flow_view, source_set)
        validate_file_view_2026(next_pointer_view, source_set)
        if fanout_group is not None:
            if type(fanout_group) is not NativeFileGroupView2026:
                raise ValueError("Actual native getter group view required")
            validate_file_group_view_2026(fanout_group, source_set)
        current_flow = self.worker._flow_file_index2026
        after_fanout = current_flow + (
            0 if fanout_group is None else fanout_group.width - 1
        )
        next_flow = after_fanout + 1
        next_group = source_set.group_view2026(next_flow)
        expected_next_pointer = (
            next_group.whole
            if next_group is not None
            else source_set.file_view2026(next_flow)
        )
        if (
            current_flow_view is not source_set.file_view2026(current_flow)
            or next_flow_view is not source_set.file_view2026(next_flow)
            or next_pointer_view is not expected_next_pointer
            or fanout_group is not source_set.group_view2026(current_flow)
            or next_flow >= 15
            or next_flow >= len(source_set.files)
            or next_flow >= len(source_set.table_file_names)
            or not source_set.table_file_names[next_flow]
            or (source_set.delta_archive and source_set.delta_map_size == 0)
        ):
            raise ValueError("Supplied views do not prove the named-next branch")
        return self._issue_getter_origin_common2026(
            decision,
            variant="named_next",
            source_set=source_set,
            current_flow_view=current_flow_view,
            current_pointer_view=current_pointer_view,
            fanout_group=fanout_group,
            next_flow_view=next_flow_view,
            next_pointer_view=next_pointer_view,
            projected_metadata=projected_metadata,
        )

    def _issue_getter_noncontinuing_3d120_2026(self, decision, *, worker):
        """Derive terminal/no-table G authority from current source facts only."""
        from scripts.cuw_file_services import (
            FileSourceSet2026,
            NativeFileGroupView2026,
            NativeFileView2026,
            validate_file_sources_2026,
            validate_file_view_2026,
        )

        self._validate_getter_success_handoff2026(decision)
        if worker is not self.worker:
            raise ValueError("Current native getter worker required")
        sources = worker._file_sources
        flow = worker._flow_file_index2026
        current = self.engine.native_metadata
        next_flow_view = None
        next_pointer_view = None
        projected_metadata = current
        if sources is None:
            variant = "no_table"
            flow_view = None
            pointer_view = worker._capture_pointer_view2026(current)
            group = None
        elif type(sources) is FileSourceSet2026:
            validate_file_sources_2026(sources, self.engine)
            named_table = sources.has_file_vector and any(sources.table_file_names)
            if not named_table:
                if flow != 0:
                    raise ValueError("Native no-table getter must retain flow zero")
                variant = "no_table"
                flow_view = None
                pointer_view = worker._capture_pointer_view2026(current)
                group = None
            else:
                if type(flow) is not int or not 0 <= flow < len(sources.files):
                    raise ValueError("Current getter D71C is outside its FILE table")
                flow_view = sources.file_view2026(flow)
                pointer_view = worker._capture_pointer_view2026(current)
                if type(pointer_view) is not NativeFileView2026:
                    raise ValueError("Actual current getter pointer view required")
                validate_file_view_2026(pointer_view, sources)
                group = sources.group_view2026(flow)
                if group is not None and type(group) is not NativeFileGroupView2026:
                    raise ValueError("Current native getter group view is invalid")
                after_fanout = flow + (0 if group is None else group.width - 1)
                following = after_fanout + 1
                has_next = (
                    following < 15
                    and following < len(sources.files)
                    and following < len(sources.table_file_names)
                    and bool(sources.table_file_names[following])
                    and not (sources.delta_archive and sources.delta_map_size == 0)
                )
                if has_next:
                    raise ValueError("Named-next branch must use its strict issuer")
                variant = "named_terminal"
                flow_view = sources.file_view2026(flow)
                next_flow_view = sources.file_view2026(0)
                next_pointer_view = next_flow_view
                projected_metadata = worker._project_getter_file_metadata2026(
                    next_flow_view
                )
        else:
            raise TypeError("Exact authenticated FILE source required")
        return self._issue_getter_origin_common2026(
            decision,
            variant=variant,
            source_set=sources,
            current_flow_view=flow_view,
            current_pointer_view=pointer_view,
            fanout_group=group,
            next_flow_view=next_flow_view,
            next_pointer_view=next_pointer_view,
            projected_metadata=projected_metadata,
        )

    def _issue_getter_origin_common2026(
        self,
        decision,
        *,
        variant,
        source_set,
        current_flow_view,
        current_pointer_view,
        fanout_group,
        next_flow_view,
        next_pointer_view,
        projected_metadata,
    ):
        from scripts.cuw_engine_worker import _NativeGetterObservation2026
        from scripts.programming_2026_common import NativeControlGetterOutput2026

        self._validate_getter_success_handoff2026(decision)
        candidate = decision.candidate
        context = candidate.execute_record.context
        execute_record = candidate.execute_record
        output = candidate.output
        phase6_import = self.worker._imported_phase6_getter_receipt2026(
            context, self, decision.sequence
        )
        phase6_output = output is None and phase6_import is not None
        capture = context._capture
        record = self._active_record
        lease = self._lease
        session = self._session
        persistence = self.engine._persistence
        observation, observed_job, observed_persistence, persistence_state = (
            self.worker._prepare_getter_observation_3d120_2026(decision, output)
        )
        if (
            variant not in ("named_next", "named_terminal", "no_table")
            or not (
                (
                    type(output) is NativeControlGetterOutput2026
                    and output is not None
                    and candidate.output is output
                )
                or phase6_output
            )
            or type(lease) is not ThreadPhaseLease2026
            or lease is not decision.lease
            or lease.state != "adopted"
            or lease.phase != 0
            or type(record) is not _CompletionRecord2026
            or record is not self._completion_records.get(decision.sequence)
            or record.sequence != decision.sequence
            or session is None
            or session is not execute_record.context._capture.raw_session
            or execute_record is not self._getter_execute_return2026
            or execute_record.sequence != decision.sequence
            or (output is not None and output.capture is not capture)
            or capture._thread_job is not self
            or capture.phase_lease is not lease
            or capture.completion_record is not record
            or capture.job_sequence != decision.sequence
            or self._pending_getter_next_entry_3d120_2026 is not None
            or self._getter_decision_dispatched_sequence2026
            >= decision.decision_sequence
            or persistence is None
            or persistence.state is None
            or observed_job is not self
            or observed_persistence is not persistence
            or persistence.state is not persistence_state
            or type(observation) is not _NativeGetterObservation2026
            or observation.file_sources is not source_set
            or observation.flow_file_index != self.worker._flow_file_index2026
            or observation.decision_sequence != decision.decision_sequence
            or observation.phase_sequence != decision.sequence
            or observation.capture_epoch != capture._import_epoch
        ):
            raise ValueError("Exact live G success lineage required")
        if source_set is not self.worker._file_sources:
            raise ValueError("Getter source set changed before G issue")
        origin = _NativeGetterNextEntryOrigin2026(
            self,
            self.engine,
            self.worker,
            self.controller,
            self._native_start_generation2026,
            threading.get_ident(),
            decision,
            execute_record,
            context,
            output,
            observation,
            lease,
            decision.sequence,
            record,
            session,
            source_set,
            self.worker._flow_file_index2026,
            current_flow_view,
            current_pointer_view,
            fanout_group,
            next_flow_view,
            next_pointer_view,
            projected_metadata,
            self.worker._getter_reset_epoch2026,
            capture._import_epoch,
            persistence,
            persistence.state,
            self.engine._native_outer_cfe0_2026,
            self.engine._native_be54_pending2026,
            variant,
        )
        self._pending_getter_next_entry_3d120_2026 = origin
        return origin

    def _validate_getter_3d120_origin2026(
        self, origin, *, worker, source_stage: str | None = None
    ) -> None:
        """Validate common next, terminal or no-table G source progress."""
        from scripts.cuw_engine_worker import _NativeGetterObservation2026
        from scripts.cuw_file_services import NativeFileView2026

        if type(origin) is not _NativeGetterNextEntryOrigin2026:
            raise TypeError("Exact native getter G origin required")
        with self._lock:
            # Before the literal 32ff0 projection, engine.native_metadata still
            # describes the current pointer FILE. The immutable target metadata
            # is only authoritative after that source stage has committed.
            current_view = origin.current_pointer_view
            if type(current_view) is not NativeFileView2026:
                raise ValueError("Native getter G current pointer view is stale")
            expected_metadata = (
                origin.projected_metadata
                if origin.variant != "no_table"
                and (
                    origin.progress
                    in {
                        "projection",
                        "reset",
                        "terminal",
                        "protocol_tail",
                        "complete",
                    }
                    or source_stage == "projection"
                )
                else current_view.metadata
            )
            capture = origin.context._capture
            phase6_import = self.worker._imported_phase6_getter_receipt2026(
                origin.context, self, origin.sequence
            )
            phase6_output = (
                origin.output is None
                and origin.decision.candidate.output is None
                and phase6_import is not None
            )
            self.validate_owner(self.engine, self.controller)
            origin.decision.candidate.execute_record.context.validate(
                self.engine, self.controller
            )
            self._validate_getter_success_handoff2026(origin.decision)
            if (
                self._pending_getter_next_entry_3d120_2026 is not origin
                or origin.job is not self
                or origin.engine is not self.engine
                or origin.worker is not self.worker
                or worker is not self.worker
                or origin.controller is not self.controller
                or origin.generation is not self._native_start_generation2026
                or origin.issuer_thread != threading.get_ident()
                or origin.decision is not self._getter_decision_dispatching2026
                or origin.decision.route != "success_3d120"
                or origin.decision.lease is not origin.lease
                or origin.sequence != self._sequence
                or origin.record is not self._active_record
                or origin.record is not self._completion_records.get(origin.sequence)
                or origin.record.sequence != origin.sequence
                or origin.lease is not self._lease
                or origin.lease.state != "adopted"
                or origin.session is not self._session
                or origin.execute_record is not self._getter_execute_return2026
                or origin.execute_record.context is not origin.context
                or not (
                    (origin.output is not None and origin.output.capture is capture)
                    or phase6_output
                )
                or capture._thread_job is not self
                or capture.phase_lease is not origin.lease
                or capture.completion_record is not origin.record
                or capture.job_sequence != origin.sequence
                or capture._import_epoch != origin.capture_epoch
                or type(origin.observation) is not _NativeGetterObservation2026
                or origin.observation.file_sources is not origin.source_set
                or origin.observation.phase_sequence != origin.sequence
                or origin.observation.decision_sequence
                != origin.decision.decision_sequence
                or origin.observation.capture_epoch != origin.capture_epoch
                or origin.observation.configuration is not capture.configuration
                or origin.variant not in ("named_next", "named_terminal", "no_table")
                or origin.progress
                not in {
                    "issued",
                    "reproinfo",
                    "query_cache",
                    "history",
                    "scratch",
                    "flow_cache",
                    "fanout",
                    "flow",
                    "projection",
                    "reset",
                    "terminal",
                    "protocol_tail",
                    "complete",
                }
                or self.worker._file_sources is not origin.source_set
                or self.engine.configuration is not capture.configuration
                or self.engine._persistence is not origin.persistence
                or getattr(origin.persistence, "state", None)
                is not origin.persistence_state
                or self.engine.native_metadata.source_container
                is not expected_metadata.source_container
                or self.engine.native_metadata.source_sha256
                != expected_metadata.source_sha256
            ):
                raise ValueError("Native getter G origin is stale or foreign")

    def _advance_getter_3d120_origin2026(self, origin, *, worker, stage: str) -> None:
        """Advance the one opaque G permit through literal source positions."""
        if type(origin) is not _NativeGetterNextEntryOrigin2026:
            raise TypeError("Exact native getter G origin required")
        if type(stage) is not str:
            raise TypeError("Native getter G source stage required")
        from scripts.cuw_file_services import NativeFileGroupView2026

        allowed = {
            "issued": "reproinfo",
            "reproinfo": "query_cache",
            "query_cache": "history",
            "history": "scratch",
            "scratch": "flow_cache",
            "flow_cache": "fanout" if origin.fanout_group is not None else "flow",
            "fanout": "flow",
            "flow": (
                "projection"
                if origin.variant in ("named_next", "named_terminal")
                else "terminal"
            ),
            "projection": "reset" if origin.variant == "named_next" else "terminal",
            "reset": "protocol_tail",
            "terminal": "protocol_tail",
            "protocol_tail": "complete",
        }
        with self._lock:
            self._validate_getter_3d120_origin2026(
                origin, worker=worker, source_stage=stage
            )
            if allowed.get(origin.progress) != stage:
                raise ValueError("Native getter G source stage repeated or skipped")
            if stage == "fanout":
                group = origin.fanout_group
                if (
                    type(group) is not NativeFileGroupView2026
                    or worker._flow_file_index2026
                    != origin.current_flow + group.width - 1
                ):
                    raise ValueError("Native G fanout did not commit its stored width")
            elif stage == "flow":
                expected = origin.current_flow
                if origin.variant == "named_next":
                    group = origin.fanout_group
                    if group is not None:
                        if type(group) is not NativeFileGroupView2026:
                            raise ValueError("Native getter group view changed")
                        expected += group.width - 1
                    expected += 1
                elif origin.variant == "named_terminal":
                    expected = 0
                if worker._flow_file_index2026 != expected:
                    raise ValueError("Native G flow differs from its branch")
            elif stage == "projection":
                if self.engine.native_metadata is not origin.projected_metadata:
                    raise ValueError("Native G A48 projection differs from its origin")
            elif stage == "history":
                if worker._getter_last_observation2026 is not origin.observation:
                    raise ValueError("Native G history did not publish its observation")
            elif stage == "terminal":
                expected = (
                    0 if origin.variant == "named_terminal" else origin.current_flow
                )
                if worker._flow_file_index2026 != expected:
                    raise ValueError("Native terminal/no-table D71C differs")
            elif stage == "reset":
                if worker._getter_reset_epoch2026 != origin.reset_epoch + 1:
                    raise ValueError("Native G 34cb0 reset epoch was not committed")
            origin.progress = stage

    def _retire_getter_3d120_origin2026(self, decision, origin) -> None:
        self._retire_pending_getter_origin2026(decision, origin)

    def _validate_getter_next_entry_3d120_2026(self, origin, *, worker) -> None:
        self._validate_getter_3d120_origin2026(origin, worker=worker)
        if origin.variant != "named_next":
            raise ValueError("Named-next G authority required")

    def _validate_getter_protocol_tail_173d0_2026(self, origin, *, worker) -> None:
        self._validate_getter_3d120_origin2026(origin, worker=worker)
        if origin.progress != "protocol_tail":
            raise ValueError("Actual native173d0 common-tail position required")

    def _queue_getter_continuation_2026(self, entry) -> None:
        """Publish only the worker-issued continuation after complete3d120 return."""
        from scripts.cuw_engine_worker import _NativeGetterContinuation2026

        if type(entry) is not _NativeGetterContinuation2026:
            raise TypeError("Exact native getter continuation required")
        with self._lock:
            origin = self._pending_getter_next_entry_3d120_2026
            if type(origin) is not _NativeGetterNextEntryOrigin2026:
                raise ValueError("Completed named-next G origin required")
            self._validate_getter_next_entry_3d120_2026(origin, worker=self.worker)
            sources = entry.source_set
            if (
                origin.progress != "complete"
                or entry is not self.worker._issued_getter_continuation2026
                or entry.job is not self
                or entry.worker is not self.worker
                or entry.old_sequence != origin.sequence
                or entry.old_lease is not origin.lease
                or entry.old_session is not origin.session
                or entry.old_completion is not origin.record
                or sources is not origin.source_set
                or self._getter_continuation2026 is not None
                or self._getter_continuation_stage2026 is not None
                or self.worker._getter_last_observation2026 is not entry.observation
                or entry.decision_sequence != origin.decision.decision_sequence
                or entry.capture_epoch != origin.capture_epoch
                or entry.reset_epoch != self.worker._getter_reset_epoch2026
                or entry.flow_file_index != self.worker._flow_file_index2026
                or entry.flow_view is not sources.file_view2026(entry.flow_file_index)
                or entry.pointer_view
                is not self.worker._capture_pointer_view2026(
                    self.engine.native_metadata
                )
                or entry.post_tail_metadata is not self.engine.native_metadata
                or entry.persistence is not self.engine._persistence
                or entry.persistence_state is not entry.persistence.state
                or self.worker._issued_getter_continuation2026 is not entry
            ):
                raise ValueError("Worker continuation differs from completed G tail")
            self._getter_continuation2026 = entry
            self._getter_continuation_stage2026 = "pending"
            self.worker._issued_getter_continuation2026 = None
            self._pending_getter_next_entry_3d120_2026 = None

    def _validate_promoted_getter_continuation_2026(self, entry) -> None:
        """Validate exact retired G evidence immediately before F clones its root."""
        from scripts.cuw_engine_worker import _NativeGetterContinuation2026

        if type(entry) is not _NativeGetterContinuation2026:
            raise TypeError("Exact native getter continuation required")
        with self._lock:
            retirement = self._getter_retirement2026
            record = entry.old_completion
            lease = entry.old_lease
            if (
                self._getter_continuation2026 is not entry
                or self._getter_continuation_stage2026 != "promoting"
                or not self._getter_promotion_starting2026
                or threading.current_thread() is not self._outer
                or entry.job is not self
                or entry.worker is not self.worker
                or entry.old_session is None
                or record is not self._completion_records.get(entry.old_sequence)
                or record.sequence != entry.old_sequence
                or not record.completed.is_set()
                or lease.engine is not self.engine
                or lease.controller is not self.controller
                or lease.phase != 0
                or lease.state != "released"
                or retirement is None
                or self._getter_retirement_stage2026 != "retired"
                or retirement.sequence != entry.old_sequence
                or retirement.record is not record
                or retirement.lease is not lease
                or retirement.session is not entry.old_session
                or self._getter_stop_receipt2026 is not None
                or self._getter_stop_stage2026 is not None
                or self._stop
                or self._lease is not None
                or self._session is not None
                or self._active_record is not record
                or self._sequence != entry.old_sequence
                or self.engine.active
                or self.engine._phase_thread is not None
                or not self.engine._phase_finished.is_set()
                or self._getter_execute_return2026 is not None
                or self._getter_callback_candidate2026 is not None
                or self._getter_callback_decision2026 is not None
                or self._getter_decision_dispatched_sequence2026
                != entry.decision_sequence
                or self._pending_getter_next_entry_3d120_2026 is not None
                or self.worker._file_sources is not entry.source_set
                or self.worker._flow_file_index2026 != entry.flow_file_index
                or self.worker._getter_reset_epoch2026 != entry.reset_epoch
                or self.worker._getter_last_observation2026 is not entry.observation
                or self.engine.native_metadata is not entry.post_tail_metadata
                or self.engine._persistence is not entry.persistence
                or entry.persistence.state is not entry.persistence_state
                or self.worker._capture_pointer_view2026(self.engine.native_metadata)
                is not entry.pointer_view
                or entry.flow_view
                is not entry.source_set.file_view2026(entry.flow_file_index)
            ):
                raise ValueError("Promoted getter continuation is stale or foreign")

    def _promote_getter_continuation_2026(self) -> int | None:
        """Ask F for one fresh root only after actual old outer retirement."""
        with self._lock:
            entry = self._getter_continuation2026
            if entry is None:
                return None
            if self._getter_stop_receipt2026 is not None:
                # The selected G work completed, but retained14 forbids a new CStart.
                self._getter_continuation2026 = None
                self._getter_continuation_stage2026 = None
                return None
            if self._getter_continuation_stage2026 != "pending":
                raise ValueError(
                    "Only a pending native getter continuation can promote"
                )
            self._getter_continuation_stage2026 = "promoting"
            self._getter_promotion_starting2026 = True
        try:
            self._validate_promoted_getter_continuation_2026(entry)
            root = entry.old_session._next_cid_root_34cb0_2026(entry)
            with self._lock:
                self._getter_promotion_root2026 = root
            sequence = self.start(root, phase=0)
            with self._lock:
                if (
                    type(sequence) is not int
                    or sequence != entry.old_sequence + 1
                    or self._sequence != sequence
                    or self._session is not root
                    or self._lease is None
                    or self._lease.phase != 0
                ):
                    raise ValueError("Fresh F root was not scheduled exactly once")
                self._getter_continuation2026 = None
                self._getter_continuation_stage2026 = None
                self._getter_retirement2026 = None
                self._getter_retirement_stage2026 = None
            return sequence
        finally:
            with self._lock:
                self._getter_promotion_starting2026 = False
                self._getter_promotion_root2026 = None

    def _retire_pending_getter_origin2026(self, decision, origin) -> None:
        with self._lock:
            if self._pending_getter_next_entry_3d120_2026 is origin:
                if origin.decision is not decision or origin.job is not self:
                    raise ValueError("Cannot retire an unrelated getter G origin")
                self._pending_getter_next_entry_3d120_2026 = None

    def _retire_getter_receipts_2026(self, sequence: int) -> None:
        """Drop context-local return/candidate/decision references after teardown."""
        if type(sequence) is not int or sequence <= 0:
            raise ValueError("Issued getter phase sequence required")
        with self._lock:
            execute_record = self._getter_execute_return2026
            candidate = self._getter_callback_candidate2026
            decision = self._getter_callback_decision2026
            if execute_record is not None and execute_record.sequence != sequence:
                raise ValueError("Getter Execute record belongs to another sequence")
            if execute_record is not None and not execute_record.context._expired:
                raise ValueError("Getter context must expire before receipt retirement")
            if candidate is not None and candidate.sequence != sequence:
                raise ValueError("Getter candidate belongs to another sequence")
            if decision is not None and decision.sequence != sequence:
                raise ValueError("Getter decision belongs to another sequence")
            self._getter_execute_return2026 = None
            self._getter_execute_pending2026 = None
            self._getter_callback_candidate2026 = None
            self._getter_callback_decision2026 = None
            self._getter_native_fatal_ack2026 = None
            self._getter_control_fatal_ack2026 = None

    def _begin_vbf_process_before2026(self):
        from scripts.calibration_2026 import native2026_cpu_values
        from scripts.programming_replay import ProgrammingReplay

        caller = threading.current_thread()
        with self._lock:
            self.validate_owner(self.engine, self.controller)
            raw_root_active = _vbf_inflight_raw_root2026(self, self._session)
            if caller in (self._outer, self._child):
                raise ValueError("External VBF ProcessBefore caller required")
            if (
                self._stop
                or self._host_stop
                or self._outer is None
                or not self._outer.is_alive()
                or self._child is None
                or not self._child.is_alive()
                or self._sequence <= 0
                or self._active_record is None
                or self._lease is None
                or (
                    self._lease.state != "adopted"
                    and not (
                        self._lease.state == "released"
                        and self._child_parked.is_set()
                        and not self._active_record.completed.is_set()
                    )
                )
                or self._session is None
                or type(self._session) is not ProgrammingReplay
                or not (self._session.used or raw_root_active)
                or self._active_record
                is not self._completion_records.get(self._sequence)
            ):
                raise ValueError("Actual persistent native generation required")
            if (
                self.worker.native_prepare_handshake != 1
                and not self._child_parked.is_set()
            ):
                raise ValueError("Non-handshake VBF admission requires parked child")
            _validate_vbf_source(self, None)
            metadata = self.engine.native_metadata
            if ".vbf" not in native2026_cpu_values(metadata, 0).get("cpuimagename", ""):
                raise ValueError("First effective CPU is not a case-sensitive VBF")
            if self._session._runtime2026 is not self.controller.runtime:
                raise ValueError("Active raw root belongs to another runtime")
            previous_record = self._completion_records[self._sequence]
            fields = {
                "job": self,
                "engine": self.engine,
                "controller": self.controller,
                "worker": self.worker,
                "runtime": self.controller.runtime,
                "trace": self._session.trace,
                "previous_session": self._session,
                "previous_sequence": self._sequence,
                "previous_lease": self._lease,
                "state": "issued",
                "wait_required": None,
                "started_ms": None,
                "metadata": None,
                "container": None,
                "file_sources": None,
                "source_sha256": None,
                "node": None,
                "cpu_index": None,
                "received_identifiers": None,
            }
            source_descriptor = (
                metadata.source_container,
                metadata.source_sha256,
                self.engine.file_sources,
                self.worker.source_state.current_file_index,
                metadata.node,
                self.engine.dh_state.selection_cpu_index,
            )
            if (
                source_descriptor[0] is not metadata.source_container
                or source_descriptor[1] != metadata.source_sha256
            ):
                raise ValueError("Current authenticated VBF source descriptor changed")
            request = VbfProcessBeforeRequest2026(_token=_TOKEN)
            record = _VbfRequestRecord2026(
                fields,
                threading.get_ident(),
                previous_record,
                source_descriptor,
                self.worker.native_prepare_handshake,
            )
            with _VBF_LOCK:
                if any(
                    item.fields["job"] is self
                    and item.fields["state"]
                    in (
                        "issued",
                        "acknowledged",
                        "parked",
                        "prepared",
                        "queued",
                        "reserved",
                    )
                    for _, item in _VBF_REQUESTS.values()
                ):
                    raise ValueError("VBF ProcessBefore request is already outstanding")
                _VBF_REQUESTS[id(request)] = (request, record)
            return request

    def _record_vbf_acknowledgement2026(self, request, *, wait_required: bool) -> None:
        if type(wait_required) is not bool:
            raise TypeError("Actual native VBF wait decision required")
        validate_vbf_process_before2026(request, self, states=("issued",))
        record = _vbf_record(request)
        assert record.previous_record is not None
        if threading.get_ident() != record.issuer:
            raise ValueError("VBF acknowledgement belongs to its issuing thread")
        if wait_required:
            if (
                record.handshake_at_issue != 1
                or self.worker.native_prepare_handshake != 2
            ):
                raise ValueError("Actual native prepare handshake transition required")
        elif self.worker.native_prepare_handshake == 1:
            raise ValueError("Native handshake was not acknowledged")
        record.fields["wait_required"] = wait_required
        record.fields["state"] = "acknowledged"

    def _validate_vbf_issuer2026(self, request) -> None:
        """Reject foreign callers before lexical engine resume ownership is granted."""
        validate_vbf_process_before2026(
            request, self, states=("issued", "acknowledged", "parked")
        )
        if _vbf_record(request).issuer != threading.get_ident():
            raise ValueError("Captured VBF request issuer required")

    def _wait_vbf_process_before2026(self, request) -> None:
        validate_vbf_process_before2026(request, self, states=("acknowledged",))
        record = _vbf_record(request)
        if threading.get_ident() != record.issuer:
            raise ValueError("VBF parked-child wait belongs to its issuing thread")
        if record.fields["wait_required"]:
            timeout = min(
                self.controller.runtime.check(),
                self.controller.runtime.cleanup_timeout,
            )
            deadline = time.monotonic() + timeout
            while not self._child_parked.wait(
                min(0.5, max(0, deadline - time.monotonic()))
            ):
                self.controller.runtime.check()
                if time.monotonic() >= deadline:
                    raise TimeoutError("VBF parked-child wait exceeded host deadline")
        elif not self._child_parked.is_set():
            raise ValueError(
                "Non-handshake VBF request requires an already parked child"
            )
        with self._lock:
            _validate_vbf_lineage(self, request, record)
            if not self._child_parked.is_set():
                raise ValueError("Actual native child parked event required")
            view = _validate_vbf_source(self, record)
            current_file = self.worker.source_state.current_file_index
            if type(current_file) is not int or current_file < 0:
                raise ValueError("Authenticated parked VBF FILE index required")
            record.parked_file_index = current_file
            record.parked_global_cpu_index = self.engine.dh_state.global_cpu_index
            record.fields.update(view)
            record.fields["state"] = "parked"

    def _issue_vbf_cpu_successor_36800_2026(
        self, request, *, worker
    ) -> _VbfCPUSuccessorOrigin2026 | None:
        """Issue only the measured parked D308=0 to D30C VBF prefix view."""
        from scripts.calibration_2026 import (
            native2026_is_logical_cpu,
            native2026_metadata_for_cpu,
        )

        if not getattr(self._lock, "_is_owned", lambda: False)():
            raise ValueError("VBF CPU successor issue requires the outer job lock")
        if not getattr(worker._lock, "_is_owned", lambda: False)():
            raise ValueError("VBF CPU successor issue requires the worker lock")
        validate_vbf_process_before2026(request, self, states=("parked",))
        record = _vbf_record(request)
        if (
            worker is not self.worker
            or record.issuer != threading.get_ident()
            or record.cpu_successor_origin is not None
            or record.cpu_engine_store is not None
            or record.cpu_successor is not None
            or record.fields["state"] != "parked"
            or record.parked_file_index is None
        ):
            raise ValueError("Exact parked VBF CPU successor issuer required")
        source_state = worker.source_state
        before_global_cpu = source_state.current_global_cpu_index
        d30c = source_state.cpu_offset
        if type(before_global_cpu) is not int or before_global_cpu != 0:
            return None
        if type(d30c) is not int or d30c == 0:
            return None
        metadata = self.engine.native_metadata
        persistence = self.engine._persistence
        persistence_state = None if persistence is None else persistence.state
        persisted_cpu = (
            None if persistence_state is None else persistence_state.write_cpu_index
        )
        current_file = source_state.current_file_index
        current_received = worker._identifiers_for_file(current_file)
        if (
            current_file != record.parked_file_index
            or current_received != record.fields["received_identifiers"]
            or metadata is not record.fields["metadata"]
            or metadata.source_container is not record.fields["container"]
            or metadata.source_sha256 != record.fields["source_sha256"]
            or metadata.node != record.fields["node"]
            or self.engine.file_sources is not record.fields["file_sources"]
            or self.engine.source_sha256 != record.fields["source_sha256"]
            or worker._current_global_cpu_index != 0
            or self.engine.dh_state.metadata is not metadata
            or self.engine.suzuki_state.metadata is not metadata
            or self.engine.dh_state.global_cpu_index != 0
            or self.engine.suzuki_state.global_cpu_index != 0
            or self.engine.dh_state.selection_cpu_index != metadata.cpu_index
            or self.engine.suzuki_state.selection_cpu_index != metadata.cpu_index
            or record.fields["cpu_index"] != metadata.cpu_index
        ):
            raise ValueError("Parked VBF CPU successor source view changed")
        self.engine._validate_persistence_source(metadata)
        projected = native2026_metadata_for_cpu(metadata, d30c)
        if (
            projected.source_container is not metadata.source_container
            or projected.source_sha256 != metadata.source_sha256
            or projected.node != metadata.node
            or projected != native2026_metadata_for_cpu(metadata, d30c)
        ):
            raise ValueError("Canonical VBF CPU projection changed FILE identity")
        if native2026_is_logical_cpu(metadata, d30c) and (
            not metadata.logical_blocks or metadata.logical_blocks[0].cpu_index != d30c
        ):
            raise ValueError(
                "VBF CPU successor cannot authorize a second logical D308 store"
            )
        pending_selection = worker._selection_rebuild_pending
        if pending_selection is not None and (
            pending_selection.rebuilt_metadata is not metadata
            or pending_selection.cpu_offset != d30c
            or current_file != record.parked_file_index
        ):
            raise ValueError("Pending VBF retained selection is stale")
        if self._sequence != request.previous_sequence or (
            self._completion_records.get(request.previous_sequence)
            is not record.previous_record
        ):
            raise ValueError("VBF CPU successor generation changed before issue")
        if (
            record.previous_record is None
            or self._active_record is not record.previous_record
        ):
            raise ValueError("VBF CPU successor lost its parked completion record")
        if (
            request.previous_lease is not self._lease
            or request.previous_lease.state != "released"
            or request.previous_session is not self._session
            or not self._child_done.is_set()
            or not self._child_parked.is_set()
        ):
            raise ValueError("Exact parked VBF child lineage required")
        retained_selection = worker._selections_by_file[current_file]
        origin = _VbfCPUSuccessorOrigin2026(
            request,
            record,
            self,
            self.engine,
            self.controller,
            worker,
            record.issuer,
            request.previous_sequence,
            record.previous_record,
            request.previous_lease,
            metadata,
            projected,
            metadata.source_container,
            metadata.source_sha256,
            metadata.node,
            self.engine.file_sources,
            current_file,
            current_received,
            before_global_cpu,
            d30c,
            metadata.cpu_index,
            projected.cpu_index,
            self.engine.dh_state.selection_cpu_index,
            projected.cpu_index,
            d30c,
            pending_selection,
            retained_selection,
            persistence,
            persistence_state,
            persisted_cpu,
        )
        record.cpu_successor_origin = origin
        return origin

    def _record_vbf_cpu_store_36800_2026(self, origin, *, worker) -> None:
        """Record the exact engine-side D308 publication before worker mirrors."""
        from scripts.cuw_2026 import _PersistenceCPUTransition2026

        if type(origin) is not _VbfCPUSuccessorOrigin2026:
            raise TypeError("Exact VBF CPU successor origin required")
        record = origin.record
        engine = origin.engine
        if (
            origin.job is not self
            or worker is not origin.worker
            or worker is not self.worker
            or _vbf_record(origin.request) is not record
            or record.cpu_successor_origin is not origin
            or record.cpu_engine_store is not None
            or record.cpu_successor is not None
            or record.fields["state"] != "parked"
            or threading.get_ident() != origin.issuer_thread
            or engine is not self.engine
            or self.controller is not origin.controller
            or self._sequence != origin.previous_sequence
            or self._active_record is not origin.previous_record
            or self._completion_records.get(origin.previous_sequence)
            is not origin.previous_record
            or self._lease is not origin.previous_lease
            or self._session is not origin.request.previous_session
            or origin.previous_lease.state != "released"
            or engine._prepare_prefix_owner != (origin.issuer_thread, worker, self)
            or engine._prepare_prefix_vbf_cpu_origin2026 is not origin
        ):
            raise ValueError("Exact live VBF CPU engine-store origin required")
        source_state = worker.source_state
        if (
            source_state.current_file_index != origin.parked_file_index
            or source_state.current_global_cpu_index != origin.before_global_cpu
            or source_state.cpu_offset != origin.d30c
            or worker._current_global_cpu_index != origin.before_global_cpu
            or worker._selection_rebuild_pending is not origin.pending_selection
            or worker._identifiers_for_file(origin.parked_file_index)
            != origin.received_identifiers
            or engine.native_metadata is not origin.projected_metadata
            or engine._worker_target_sources.get(id(origin.source_container))
            is not origin.projected_metadata
        ):
            raise ValueError("VBF CPU engine store differs from its issued projection")
        for state in (engine.dh_state, engine.suzuki_state):
            if (
                state.metadata is not origin.projected_metadata
                or state.source_sha256 != origin.source_digest
                or state.node != origin.source_node
                or state.selection_cpu_index != origin.after_selection_cpu_index
                or state.global_cpu_index != origin.after_global_cpu
                or state.cpu_index != origin.after_global_cpu
            ):
                raise ValueError("VBF CPU native state store is incomplete")
        if (
            engine._persistence is not origin.persistence
            or (
                None
                if origin.persistence is None
                else getattr(origin.persistence, "state", None)
            )
            is not origin.persistence_state
            or (
                None
                if origin.persistence_state is None
                else getattr(origin.persistence_state, "write_cpu_index", None)
            )
            != origin.persisted_cpu
        ):
            raise ValueError("VBF CPU store persistence identity changed")
        transition = engine._persistence_cpu_transition2026
        if (
            origin.persistence is None
            or origin.persisted_cpu == origin.after_global_cpu
        ):
            if transition is not None:
                raise ValueError("Unexpected VBF prefix persistence CPU witness")
        else:
            if type(transition) is not _PersistenceCPUTransition2026 or (
                transition.producer != "vbf-prefix"
                or transition.origin is not origin.request
                or transition.worker is not worker
                or transition.persistence is not origin.persistence
                or transition.state is not origin.persistence_state
                or transition.metadata is not origin.projected_metadata
                or transition.file_sources is not origin.file_sources
                or transition.container is not origin.source_container
                or transition.digest != origin.source_digest
                or transition.node != origin.source_node
                or transition.persisted_cpu != origin.persisted_cpu
                or transition.before_cpu != origin.before_global_cpu
                or transition.after_cpu != origin.after_global_cpu
            ):
                raise ValueError("Exact VBF prefix persistence witness required")
        record.cpu_engine_store = _VbfCPUEngineStore2026(origin, transition)

    def _complete_vbf_cpu_successor_36800_2026(self, origin, *, worker) -> None:
        """Seal the exact worker-side mirrors after the engine CPU store."""
        if type(origin) is not _VbfCPUSuccessorOrigin2026:
            raise TypeError("Exact VBF CPU successor origin required")
        record = origin.record
        engine_store = record.cpu_engine_store
        if (
            origin.job is not self
            or worker is not origin.worker
            or worker is not self.worker
            or record.cpu_successor_origin is not origin
            or type(engine_store) is not _VbfCPUEngineStore2026
            or engine_store.origin is not origin
            or record.cpu_successor is not None
            or record.fields["state"] != "parked"
            or threading.get_ident() != origin.issuer_thread
            or engine_store.persistence_transition
            is not origin.engine._persistence_cpu_transition2026
            or origin.engine._prepare_prefix_vbf_cpu_origin2026 is not origin
        ):
            raise ValueError("Exact VBF worker CPU successor completion required")
        self._validate_vbf_cpu_engine_store2026(origin, worker, engine_store)
        if (
            worker.source_state.current_file_index != origin.parked_file_index
            or worker.source_state.current_global_cpu_index != origin.after_global_cpu
            or worker.source_state.cpu_offset != origin.d30c
            or worker._current_global_cpu_index != origin.after_global_cpu
            or worker._current_cpu_index != origin.after_metadata_cpu_index
            or worker._current_node != origin.source_node
            or engine_store.persistence_transition
            is not origin.engine._persistence_cpu_transition2026
            or worker._selection_rebuild_pending is not None
            or worker._identifiers_for_file(origin.parked_file_index)
            != origin.received_identifiers
        ):
            raise ValueError(
                "VBF worker CPU mirrors did not reach the source successor"
            )
        retained_selection = worker._selections_by_file[origin.parked_file_index]
        if origin.pending_selection is None:
            if retained_selection is not origin.retained_selection:
                raise ValueError("Unissued VBF retained selection changed")
        else:
            from dataclasses import replace

            from scripts.calibration_2026 import NativeCPUSelection2026

            pending_selection = origin.pending_selection
            if type(pending_selection) is not NativeCPUSelection2026:
                raise ValueError("Exact pending VBF retained selection required")

            if (
                retained_selection is pending_selection
                or replace(
                    pending_selection,
                    rebuilt_metadata=origin.projected_metadata,
                )
                != retained_selection
            ):
                raise ValueError("VBF retained selection projection is incomplete")
        record.cpu_successor = _VbfCPUSuccessor2026(
            engine_store,
            worker._current_node,
            worker._current_cpu_index,
            worker._current_global_cpu_index,
            retained_selection,
        )

    def _validate_vbf_cpu_engine_store2026(self, origin, worker, engine_store):
        from scripts.calibration_2026 import native2026_metadata_for_cpu
        from scripts.cuw_2026 import _PersistenceCPUTransition2026

        engine = origin.engine
        transition = engine_store.persistence_transition
        expected_projection = native2026_metadata_for_cpu(
            origin.parked_metadata, origin.d30c
        )
        if (
            engine_store.origin is not origin
            or engine._prepare_prefix_vbf_cpu_origin2026 is not origin
            or engine._prepare_prefix_owner != (origin.issuer_thread, worker, self)
            or expected_projection != origin.projected_metadata
            or expected_projection.source_container is not origin.source_container
            or origin.projected_metadata.source_container is not origin.source_container
            or origin.projected_metadata.source_sha256 != origin.source_digest
            or origin.projected_metadata.node != origin.source_node
            or engine.native_metadata is not origin.projected_metadata
            or engine._worker_target_sources.get(id(origin.source_container))
            is not origin.projected_metadata
        ):
            raise ValueError("VBF engine CPU store receipt is stale")
        for state in (engine.dh_state, engine.suzuki_state):
            if (
                state.metadata is not origin.projected_metadata
                or state.source_sha256 != origin.source_digest
                or state.node != origin.source_node
                or state.selection_cpu_index != origin.after_selection_cpu_index
                or state.global_cpu_index != origin.after_global_cpu
                or state.cpu_index != origin.after_global_cpu
            ):
                raise ValueError(
                    "VBF engine CPU store receipt has partial native state"
                )
        if (
            engine._persistence is not origin.persistence
            or (None if origin.persistence is None else origin.persistence.state)
            is not origin.persistence_state
            or engine._persistence_cpu_transition2026 is not transition
        ):
            raise ValueError("VBF CPU store persistence witness changed")
        if (
            origin.persistence is None
            or origin.persisted_cpu == origin.after_global_cpu
        ):
            if transition is not None:
                raise ValueError("Unexpected VBF persistence CPU transition")
        elif type(transition) is not _PersistenceCPUTransition2026 or (
            transition.producer != "vbf-prefix"
            or transition.origin is not origin.request
            or transition.worker is not worker
            or transition.persistence is not origin.persistence
            or transition.state is not origin.persistence_state
            or transition.metadata is not origin.projected_metadata
            or transition.file_sources is not origin.file_sources
            or transition.container is not origin.source_container
            or transition.digest != origin.source_digest
            or transition.node != origin.source_node
            or transition.persisted_cpu != origin.persisted_cpu
            or transition.before_cpu != origin.before_global_cpu
            or transition.after_cpu != origin.after_global_cpu
        ):
            raise ValueError("VBF CPU store has the wrong persistence witness")

    def _validate_vbf_cpu_successor2026(self, record) -> _VbfCPUSuccessor2026:
        origin = record.cpu_successor_origin
        engine_store = record.cpu_engine_store
        successor = record.cpu_successor
        if (
            type(origin) is not _VbfCPUSuccessorOrigin2026
            or origin.record is not record
            or origin.job is not self
            or _vbf_record(origin.request) is not record
            or record.fields["state"] != "parked"
            or record.fields["job"] is not self
            or threading.get_ident() != origin.issuer_thread
            or self._sequence != origin.previous_sequence
            or self._active_record is not origin.previous_record
            or self._completion_records.get(origin.previous_sequence)
            is not origin.previous_record
            or self._lease is not origin.previous_lease
            or origin.previous_lease.state != "released"
            or self._session is not origin.request.previous_session
            or engine_store is None
            or successor is None
            or type(engine_store) is not _VbfCPUEngineStore2026
            or engine_store.origin is not origin
            or type(successor) is not _VbfCPUSuccessor2026
            or successor.engine_store is not engine_store
            or origin.engine._prepare_prefix_vbf_cpu_origin2026 is not origin
        ):
            raise ValueError("Complete exact VBF CPU successor required")
        if record.parked_file_index != origin.parked_file_index:
            raise ValueError("VBF parked FILE index changed before refresh")
        self._validate_vbf_cpu_engine_store2026(origin, self.worker, engine_store)
        if (
            successor.worker_node != self.worker._current_node
            or successor.worker_cpu_index != self.worker._current_cpu_index
            or successor.worker_global_cpu_index
            != self.worker._current_global_cpu_index
            or successor.retained_selection
            is not self.worker._selections_by_file[origin.parked_file_index]
        ):
            raise ValueError("VBF CPU successor worker projection changed")
        return successor

    def _retire_vbf_cpu_successor_36800_2026(self, origin) -> None:
        """Retire one exact prefix origin without undoing native source stores."""
        if type(origin) is not _VbfCPUSuccessorOrigin2026:
            raise TypeError("Exact VBF CPU successor origin required")
        record = origin.record
        with self._lock:
            if (
                origin.job is not self
                or _vbf_record(origin.request) is not record
                or record.cpu_successor_origin is not origin
                or threading.get_ident() != origin.issuer_thread
                or record.fields["job"] is not self
                or record.fields["state"] not in ("parked", "prepared")
            ):
                raise ValueError("Exact live VBF CPU successor retirement required")
            record.cpu_successor_origin = None
            record.cpu_engine_store = None
            record.cpu_successor = None

    def _record_vbf_prepared2026(self, request, *, started_ms: int):
        if type(started_ms) is not int or not 0 <= started_ms < 86_400_000:
            raise ValueError("Native local milliseconds within day required")
        with self._lock:
            validate_vbf_process_before2026(request, self, states=("parked",))
            record = _vbf_record(request)
            if threading.get_ident() != record.issuer:
                raise ValueError("VBF FULL36800 preparation belongs to its issuer")
            if self.engine._prepare_prefix_owner != (
                record.issuer,
                self.worker,
                self,
            ):
                raise ValueError("Exact lexical FULL36800 preparation owner required")
            if self.worker.native_prepare_handshake != 1:
                raise ValueError("Actual FULL36800 VBF reset state required")
            if record.cpu_successor_origin is None:
                if (
                    record.cpu_engine_store is not None
                    or record.cpu_successor is not None
                ):
                    raise ValueError("Unissued VBF CPU successor cells present")
                view = _validate_vbf_source(self, record)
            else:
                successor = self._validate_vbf_cpu_successor2026(record)
                view = _validate_vbf_source(self, None)
                if (
                    view["metadata"]
                    is not record.cpu_successor_origin.projected_metadata
                    or view["container"] is not record.fields["container"]
                    or view["file_sources"] is not record.fields["file_sources"]
                    or view["source_sha256"] != record.fields["source_sha256"]
                    or view["node"] != record.fields["node"]
                    or view["received_identifiers"]
                    != record.fields["received_identifiers"]
                    or successor.worker_global_cpu_index
                    != record.cpu_successor_origin.after_global_cpu
                ):
                    raise ValueError("Completed VBF CPU successor source view changed")
                record.fields.update(view)
                record.parked_global_cpu_index = successor.worker_global_cpu_index
                record.cpu_engine_store = None
                record.cpu_successor = None
            record.fields["started_ms"] = started_ms
            record.fields["state"] = "prepared"
        return request

    def _queue_vbf_prepare2026(self, request, session) -> int:
        from scripts.programming_replay import ProgrammingReplay

        validate_vbf_process_before2026(request, self, states=("prepared",))
        record = _vbf_record(request)
        if threading.get_ident() != record.issuer:
            raise ValueError("VBF prepared root queue belongs to its issuer")
        if (
            type(session) is not ProgrammingReplay
            or session.operation != "prepare"
            or session.used
            or session.container is not record.fields["container"]
            or session.container.digest != record.fields["source_sha256"]
            or session.node != record.fields["node"]
            or session.trace is not record.fields["trace"]
            or session._runtime2026 is not record.fields["runtime"]
            or session._controller2026 is not record.fields["controller"]
            or session._engine2026 is not record.fields["engine"]
            or session._control_target2026 is not None
            or session._control_export2026 is not None
            or session._retained_export2026 is not None
        ):
            raise ValueError("Fresh authenticated raw VBF prepare root required")
        with self._lock:
            validate_vbf_process_before2026(request, self, states=("prepared",))
            if (
                self._sequence != request.previous_sequence
                or self._completion_records.get(request.previous_sequence)
                is not record.previous_record
            ):
                raise ValueError("VBF source request no longer owns the next sequence")
            next_sequence = self._sequence + 1
            record.root = session
            record.fields["state"] = "queued"
            self._resume.set()
        return next_sequence

    def _bind_vbf_phase_lease2026(self, request, lease) -> None:
        validate_vbf_process_before2026(request, self, states=("queued",))
        record = _vbf_record(request)
        assert record.previous_record is not None
        if (
            threading.current_thread() is not self._outer
            or lease.state != "reserved"
            or lease.phase != 1
            or lease.engine is not self.engine
            or lease.controller is not self.controller
            or self._lease is not None
            or self._session is not None
            or self._sequence != request.previous_sequence
            or self._completion_records.get(request.previous_sequence)
            is not record.previous_record
            or not record.previous_record.completed.is_set()
            or request.previous_lease.state != "released"
        ):
            raise ValueError("Actual outer VBF phase-one reservation required")
        record.lease = lease
        record.fields["state"] = "reserved"

    def _consume_vbf_phase2026(self, request, lease):
        validate_vbf_process_before2026(
            request, self, states=("reserved",), lease=lease
        )
        record = _vbf_record(request)
        if (
            threading.current_thread() is not self._child
            or lease.state != "adopted"
            or lease._thread != threading.get_ident()
            or self.worker.native_prepare_handshake != 1
        ):
            raise ValueError("Actual adopting VBF native child required")
        _validate_vbf_source(self, record)
        record.fields["state"] = "adopted"
        return request

    def _release_vbf_phase2026(self, request, lease) -> None:
        if type(request) is not VbfProcessBeforeRequest2026:
            raise TypeError("Concrete VBF ProcessBefore request required")
        record = _vbf_record(request)
        if (
            record.lease is not lease
            or lease.vbf_request is not request
            or lease.state != "released"
            or (lease._thread is not None and lease._thread != threading.get_ident())
            or (
                lease._thread is None
                and threading.current_thread() not in (self._outer, self._child)
            )
        ):
            raise ValueError("Actual released VBF phase lease required")
        with _VBF_LOCK:
            current = _VBF_REQUESTS.get(id(request))
            if current is None or current[0] is not request or current[1] is not record:
                raise ValueError("VBF request registry identity changed")
            del _VBF_REQUESTS[id(request)]

    def _abandon_vbf_process_before2026(self, request) -> None:
        if type(request) is not VbfProcessBeforeRequest2026:
            raise TypeError("Concrete VBF ProcessBefore request required")
        with _VBF_LOCK:
            entry = _VBF_REQUESTS.get(id(request))
            if entry is None or entry[0] is not request:
                return
            record = entry[1]
        if record.fields["job"] is not self:
            raise ValueError("VBF request belongs to another native job")
        if record.fields["state"] in ("queued", "reserved", "adopted"):
            return
        if threading.get_ident() != record.issuer:
            raise ValueError("Only the VBF issuing thread may abandon its request")
        record.fields["state"] = "abandoned"
        with _VBF_LOCK:
            current = _VBF_REQUESTS.get(id(request))
            if current is not None and current[0] is request:
                del _VBF_REQUESTS[id(request)]

    @property
    def state(self) -> ThreadState2026:
        with self._lock:
            return ThreadState2026(
                self._outer is not None,
                self._child is not None,
                self._child is not None and self._child.is_alive(),
                self._stop,
                self._waiting,
                self._prepare_pending.is_set(),
                self._sequence,
                (
                    0x103
                    if self._child is not None and self._child.is_alive()
                    else self._child_exit
                ),
                (
                    0x103
                    if self._outer is not None and self._outer.is_alive()
                    else self._outer_exit
                ),
            )

    @property
    def continuation(self) -> WorkerContinuation2026 | None:
        with self._lock:
            record = self._completion_records.get(self._sequence)
            if record is None or not record.completed.is_set():
                raise ValueError("Native child has not unwound")
            return record.continuation

    def _is_raw_control_getter_root2026(self, session: ProgrammingReplay) -> bool:
        """Read the actual loader route without consuming a replay or runner."""
        from scripts.calibration_2026 import native2026_cpu_type
        from scripts.native_modules import NativeModuleIdentity
        from scripts.programming_replay import ProgrammingReplay

        if (
            type(session) is not ProgrammingReplay
            or session.operation != "get_cid"
            or session.used
            or session._engine2026 is not self.engine
            or session._controller2026 is not self.controller
            or session._runtime2026 is not self.controller.runtime
            or session.container.digest != self.engine.source_sha256
            or session.node != self.engine.native_metadata.node
            or session.context["observations"]["host"].get("cpu_index", 0)
            != self.engine.dh_state.selection_cpu_index
        ):
            return False
        contact = self.engine.native_metadata.vehicle.get("contacttype", "")
        direct = contact in ("P5-Unified", "Phase6", "Ethernet")
        if not direct:
            kind = self.engine.native_metadata.vehicle.get("kindofecu", "")
            cpu_type = native2026_cpu_type(self.engine.native_metadata, 0)
            filename = (kind + contact + cpu_type + ".ini").casefold()
            if not any(
                name.casefold() == filename for name in session._catalog_sources
            ):
                return False
        module = session.modules.get("TCUWControlCommPhase.dll")
        if module is None:
            return False
        identity = module.native_identity
        if identity is None:
            return False
        return (
            type(identity) is NativeModuleIdentity
            and identity == self.controller.identity
            and {
                "Execute",
                "IsSendingSyncPeriodicMsgToECU",
                "DisconnectJ2534Connection",
                "ChangeToReprogGWModeForDHCentralGW",
            }.issubset(identity.callable_exports)
        )

    def _is_raw_control_ordinary_root2026(self, session: ProgrammingReplay) -> bool:
        """Require the actual CONTROL loader route before ordinary36800 admission."""
        from scripts.calibration_2026 import native2026_cpu_type
        from scripts.native_modules import NativeModuleIdentity
        from scripts.programming_replay import ProgrammingReplay

        if (
            type(session) is not ProgrammingReplay
            or session.operation not in ("prepare", "recovery")
            or session.used
            or session._engine2026 is not self.engine
            or session._controller2026 is not self.controller
            or session._runtime2026 is not self.controller.runtime
            or session.container.digest != self.engine.source_sha256
            or session.node != self.engine.native_metadata.node
            or session.context["observations"]["host"].get("cpu_index", 0)
            != self.engine.dh_state.selection_cpu_index
        ):
            return False
        contact = self.engine.native_metadata.vehicle.get("contacttype", "")
        if contact not in ("P5-Unified", "Phase6", "Ethernet"):
            kind = self.engine.native_metadata.vehicle.get("kindofecu", "")
            cpu_type = native2026_cpu_type(self.engine.native_metadata, 0)
            filename = (kind + contact + cpu_type + ".ini").casefold()
            if not any(
                name.casefold() == filename for name in session._catalog_sources
            ):
                return False
        module = session.modules.get("TCUWControlCommPhase.dll")
        identity = None if module is None else module.native_identity
        return (
            type(identity) is NativeModuleIdentity
            and identity == self.controller.identity
            and {
                "Execute",
                "IsSendingSyncPeriodicMsgToECU",
                "DisconnectJ2534Connection",
                "ChangeToReprogGWModeForDHCentralGW",
            }.issubset(identity.callable_exports)
        )

    def _make_ordinary_prepare_binding2026(
        self, session: ProgrammingReplay
    ) -> _OrdinaryPrepareStartBinding2026:
        """Capture one caller-owned ordinary root before any36800 source write."""
        from scripts.programming_replay import ProgrammingReplay

        with self._lock:
            self.validate_owner(self.engine, self.controller)
            if (
                type(session) is not ProgrammingReplay
                or session.operation not in ("prepare", "recovery")
                or session.used
                or session._engine2026 is not self.engine
                or session._controller2026 is not self.controller
                or session._runtime2026 is not self.controller.runtime
                or self._ordinary_prepare_starting2026
                or self._ordinary_prepare_binding2026 is not None
                or self._ordinary_prepare_origin2026 is not None
                or self._prepared_ordinary_entry2026 is not None
                or self._getter_entry_starting2026
                or self._getter_entry_origin2026 is not None
                or self._getter_stop_receipt2026 is not None
                or self._getter_stop_stage2026 is not None
                or self._getter_continuation2026 is not None
                or self._getter_promotion_starting2026
                or self._pending_getter_next_entry_3d120_2026 is not None
                or self._lease is not None
                or (self._sequence and not self._completed.is_set())
                or self._stop
                or self._host_stop
                or _has_vbf_request2026(self)
            ):
                raise ValueError("Fresh ordinary36800 start authority required")
            previous = self._active_record
            if self._sequence == 0:
                if previous is not None:
                    raise ValueError("Initial ordinary start has a prior record")
            elif (
                previous is None
                or previous.sequence != self._sequence
                or self._completion_records.get(self._sequence) is not previous
                or not previous.completed.is_set()
                or not self._completed.is_set()
            ):
                raise ValueError("Completed prior native generation required")
            self.worker.validate_source(self.engine)
            metadata = self.engine.native_metadata
            source_set = self.worker._file_sources
            source_container = metadata.source_container
            source_digest = metadata.source_sha256
            if (
                source_container is None
                or type(source_digest) is not str
                or source_container.digest != source_digest
                or source_digest != self.engine.source_sha256
                or session.container.digest != source_digest
                or session.node != metadata.node
                or session.context["observations"]["host"].get("cpu_index", 0)
                != self.engine.dh_state.selection_cpu_index
                or not self._is_raw_control_ordinary_root2026(session)
            ):
                raise ValueError(
                    "Raw ordinary root must retain the actual current FILE"
                )
            if source_set is not None:
                from scripts.cuw_file_services import validate_file_sources_2026

                validate_file_sources_2026(source_set, self.engine)
            cfe0 = self.engine._native_outer_cfe0_2026
            be54 = self.engine._native_be54_pending2026
            cfe2 = self.engine._native_receiving_cfe2_2026
            persistence = self.engine.persistence
            persistence_state = None if persistence is None else persistence.state
            persisted_cpu = (
                None if persistence_state is None else persistence_state.write_cpu_index
            )
            persisted_offset = (
                None
                if persistence_state is None
                else persistence_state.offset_of_write_cpu_multi_cal_index
            )
            if any(type(flag) is not bool for flag in (cfe0, be54, cfe2)):
                raise ValueError("Exact native CFE0/BE54/CFE2 source bytes required")
            if cfe2 or (cfe0 and be54):
                raise ValueError("Native receiving event already has pending work")
            binding = _OrdinaryPrepareStartBinding2026(
                object(),
                self,
                self.engine,
                self._native_start_generation2026,
                self.worker,
                self.controller,
                self.controller.runtime,
                threading.get_ident(),
                self._sequence + 1,
                session,
                session.trace,
                session.container,
                session.node,
                self._sequence,
                previous,
                self._session,
                self._lease,
                metadata,
                source_container,
                source_digest,
                source_set,
                self.engine.configuration,
                persistence,
                persistence_state,
                self.worker._flow_file_index2026,
                self.worker._capture_flow_view2026(),
                self.worker._capture_pointer_view2026(metadata),
                self.worker._getter_reset_epoch2026,
                persisted_cpu,
                persisted_offset,
                self.engine.native_phase,
                self.engine.worker_phase,
                self.worker.native_prepare_handshake,
                cfe0,
                be54,
                cfe2,
                self._stop,
                self._host_stop,
                self._getter_stop_receipt2026,
                self._getter_continuation2026,
            )
            self._ordinary_prepare_binding2026 = binding
            self._ordinary_prepare_starting2026 = True
            return binding

    def _start_ordinary_prepare_36800_2026(
        self, session: ProgrammingReplay
    ) -> int | None:
        """Run the exact pre-child36800 source path for a raw CONTROL root."""
        binding = self._make_ordinary_prepare_binding2026(session)
        origin: _OrdinaryPrepareOrigin2026 | None = None
        try:
            with self.engine.ordinary_prepare_execution_36800_2026(
                self, binding
            ) as issued:
                if type(issued) is not _OrdinaryPrepareOrigin2026:
                    raise TypeError("Exact ordinary36800 source origin required")
                source_origin = issued
                origin = source_origin
                self.worker._apply_ordinary_prepare_36800_2026(origin=source_origin)
                if source_origin.stage == "early_return":
                    sequence = None
                else:
                    if source_origin.stage != "prepared":
                        raise ValueError("Complete ordinary36800 prefix required")
                    if source_origin.started_ms is None:
                        raise ValueError("Actual ordinary36800 clock sample required")
                    record = _CompletionRecord2026(binding.sequence)
                    self.engine._reserve_ordinary_prepare_phase_36800_2026(
                        self, source_origin, record
                    )
                    self.engine._publish_ordinary_prepare_tail_36800_2026(source_origin)
                    self._record_ordinary_prepared_36800_2026(
                        source_origin, started_ms=source_origin.started_ms
                    )
                    sequence = self._publish_ordinary_prepare_job2026(source_origin)
            if origin is None:
                raise ValueError("Ordinary36800 source scope returned no origin")
            if origin.stage == "early_return":
                with self._lock:
                    if (
                        self._ordinary_prepare_binding2026 is not binding
                        or self._ordinary_prepare_origin2026 is not origin
                        or self._sequence != binding.previous_sequence
                        or self._active_record is not binding.previous_record
                        or self._lease is not binding.previous_lease
                        or self._prepared_ordinary_entry2026 is not None
                    ):
                        raise ValueError("Exact source early-return lineage changed")
                    self._ordinary_prepare_binding2026 = None
                    self._ordinary_prepare_origin2026 = None
                    self._ordinary_prepare_starting2026 = False
                return None
            assert sequence is not None
            return sequence
        except BaseException as error:
            active_origin = origin or self._ordinary_prepare_origin2026
            try:
                if type(active_origin) is _OrdinaryPrepareOrigin2026:
                    self.engine._abort_ordinary_prepare_36800_2026(active_origin)
                else:
                    self._abandon_ordinary_prepare_binding2026(binding)
            except BaseException as cleanup_error:  # noqa: BLE001 - preserve source error
                if cleanup_error is not error:
                    error.add_note(
                        "Ordinary36800 abort failure: " + type(cleanup_error).__name__
                    )
            raise

    def _issue_ordinary_prepare_origin2026(
        self, binding: _OrdinaryPrepareStartBinding2026, *, scope: object
    ) -> _OrdinaryPrepareOrigin2026:
        """Called by the held36 lexical scope entered directly from job.start."""
        with self._lock:
            if (
                type(binding) is not _OrdinaryPrepareStartBinding2026
                or self._ordinary_prepare_binding2026 is not binding
                or not self._ordinary_prepare_starting2026
                or binding.job is not self
                or binding.engine is not self.engine
                or binding.worker is not self.worker
                or binding.controller is not self.controller
                or binding.generation is not self._native_start_generation2026
                or binding.issuer_thread != threading.get_ident()
                or binding.sequence != self._sequence + 1
                or binding.previous_sequence != self._sequence
                or binding.previous_record is not self._active_record
                or binding.session.used
                or scope is None
                or self._ordinary_prepare_origin2026 is not None
                or self.engine.thread_job is not self
                or self.engine.worker is not self.worker
                or self.worker.controller is not self.controller
            ):
                raise ValueError("Exact ordinary36800 lexical binding required")
            origin = _OrdinaryPrepareOrigin2026(
                binding=binding,
                scope=scope,
                metadata=binding.source_metadata,
                source_container=binding.source_container,
                source_digest=binding.source_digest,
                source_set=binding.source_set,
                flow_index=binding.flow_index,
                flow_view=binding.flow_view,
                pointer_view=binding.pointer_view,
                reset_epoch=binding.reset_epoch,
            )
            self._ordinary_prepare_origin2026 = origin
            return origin

    def _abandon_ordinary_prepare_binding2026(
        self, binding: _OrdinaryPrepareStartBinding2026
    ) -> None:
        """Clear only a pre-origin binding whose lexical engine scope never opened."""
        with self._lock:
            if (
                self._ordinary_prepare_binding2026 is not binding
                or self._ordinary_prepare_origin2026 is not None
                or not self._ordinary_prepare_starting2026
                or binding.job is not self
                or binding.generation is not self._native_start_generation2026
                or binding.issuer_thread != threading.get_ident()
                or binding.sequence != self._sequence + 1
                or self._sequence != binding.previous_sequence
                or self._active_record is not binding.previous_record
                or self._lease is not binding.previous_lease
            ):
                raise ValueError("Exact unpublished ordinary binding required")
            self._ordinary_prepare_binding2026 = None
            self._ordinary_prepare_starting2026 = False

    def _validate_ordinary_prepare_origin_36800_2026(
        self, origin: object, *, _source_point: object | None = None
    ) -> None:
        """Read-only validation of the current exact lexical36800 origin."""
        if type(origin) is not _OrdinaryPrepareOrigin2026:
            raise TypeError("Exact ordinary36800 origin required")
        with self._lock:
            binding = origin.binding
            if (
                self._ordinary_prepare_origin2026 is not origin
                or self._ordinary_prepare_binding2026 is not binding
                or not self._ordinary_prepare_starting2026
                or type(binding) is not _OrdinaryPrepareStartBinding2026
                or binding.job is not self
                or binding.engine is not self.engine
                or binding.worker is not self.worker
                or binding.controller is not self.controller
                or binding.runtime is not self.controller.runtime
                or binding.generation is not self._native_start_generation2026
                or binding.issuer_thread != threading.get_ident()
                or binding.session.container is not binding.input_container
                or binding.session.container.digest != binding.source_digest
                or binding.session.node != binding.input_node
                or binding.input_node != binding.source_metadata.node
                or binding.session.trace is not binding.trace
                or binding.session.used
                or binding.session.context["observations"]["host"].get("cpu_index", 0)
                != binding.source_metadata.cpu_index
                or binding.sequence != self._sequence + 1
                or binding.previous_sequence != self._sequence
                or binding.previous_record is not self._active_record
                or binding.previous_session is not self._session
                or binding.previous_lease is not self._lease
                or self.engine.thread_job is not self
                or self.engine.worker is not self.worker
                or self.worker.controller is not self.controller
                or self.engine.configuration is not binding.configuration
                or self.engine.persistence is not binding.persistence
                or (
                    None
                    if self.engine.persistence is None
                    else self.engine.persistence.state
                )
                is not binding.persistence_state
                or binding.stop_receipt is not None
                or binding.continuation is not None
                or self._getter_stop_receipt2026 is not None
                or self._getter_stop_stage2026 is not None
                or self._getter_promotion_starting2026
                or self._pending_getter_next_entry_3d120_2026 is not None
                or _has_vbf_request2026(self)
                or self._sequence != binding.previous_sequence
                or self._completed.is_set() is not bool(binding.previous_sequence)
            ):
                raise ValueError("Ordinary36800 origin is stale or foreign")
            scope = self.engine._ordinary_prepare_scope2026
            if (
                type(scope) is not tuple
                or len(scope) != 4
                or scope[0] is not self
                or scope[1] is not binding
                or scope[2] is not origin
                or scope[3] is not origin.scope
            ):
                raise ValueError("Exact held native36800 engine scope required")
            if (
                origin.stage
                in (
                    "issued",
                    "retained_type",
                    "device",
                    "clock",
                    "outputs",
                    "phase",
                    "branch",
                    "recovery",
                    "nonrecovery",
                    "cid",
                    "cpu_tail",
                    "prepared",
                )
                and self._lease is not binding.previous_lease
            ):
                raise ValueError("Ordinary prefix must remain pre-reservation")
            if origin.stage in ("reserved", "scheduled") and (
                origin.record is None
                or origin.record.sequence != binding.sequence
                or origin.lease is None
                or origin.lease.state != "reserved"
                or origin.lease.phase != origin.phase
                or not self.engine._active
                or self.engine._phase_thread is not None
                or self.engine.worker_phase != origin.phase
                or self._lease is not binding.previous_lease
            ):
                raise ValueError("Exact ordinary36800 promoted lease required")
            if binding.previous_sequence:
                previous = binding.previous_record
                if (
                    previous is None
                    or previous.sequence != binding.previous_sequence
                    or self._completion_records.get(binding.previous_sequence)
                    is not previous
                    or not previous.completed.is_set()
                ):
                    raise ValueError("Captured completed ordinary generation changed")
            if (
                origin.metadata is None
                or origin.source_container is None
                or origin.source_digest is None
                or origin.metadata.source_container is not origin.source_container
                or origin.metadata.source_sha256 != origin.source_digest
            ):
                raise ValueError("Current authenticated ordinary source view required")
            if _source_point is None:
                if (
                    self.engine.native_metadata is not origin.metadata
                    or self.worker._file_sources is not origin.source_set
                    or self.worker._flow_file_index2026 != origin.flow_index
                    or self.worker._capture_flow_view2026() != origin.flow_view
                    or self.worker._capture_pointer_view2026(origin.metadata)
                    != origin.pointer_view
                    or self.worker._getter_reset_epoch2026 != origin.reset_epoch
                ):
                    raise ValueError(
                        "Ordinary36800 source tuple changed outside a literal source point"
                    )
            else:
                self._validate_ordinary_prepare_source_point2026(origin, _source_point)
            if origin.started_ms is not None and type(origin.started_ms) is not int:
                raise ValueError("Exact ordinary36800 source clock required")

    def _validate_ordinary_prepare_source_point2026(
        self, origin: _OrdinaryPrepareOrigin2026, point: object
    ) -> None:
        """Validate the one live CPU/CID publication while its mirror is committed."""
        from scripts.calibration_2026 import (
            Native2026Metadata,
            NativeCIDRebuildMetadata2026,
            native2026_cpu_count,
        )
        from scripts.cuw_engine_worker import (
            _NativeOrdinaryCIDPoint2026,
            _NativeOrdinaryCPUPoint2026,
        )

        worker = self.worker
        index = worker._current_file_index
        if type(point) is _NativeOrdinaryCPUPoint2026:
            if (
                worker._ordinary_cpu_point2026 is not point
                or point.origin is not origin
                or point.thread_id != threading.get_ident()
                or point.metadata is not origin.metadata
                or worker._current_global_cpu_index != point.after
            ):
                raise ValueError("Exact live ordinary CPU source point required")
            expected = worker._ordinary_file_metadata_for_cursor_3e710_2026(
                point.metadata, point.after
            )
            local_cursor = (
                (expected.node, expected.cpu_index)
                if point.after < native2026_cpu_count(expected)
                else (point.before_node, point.before_cpu_index)
            )
            if (
                self.engine.native_metadata != expected
                or worker._all_loaded_metadata[index] is not self.engine.native_metadata
                or (worker._current_node, worker._current_cpu_index) != local_cursor
            ):
                raise ValueError(
                    "Ordinary CPU source projection is not the published mirror"
                )
            return
        if type(point) is _NativeOrdinaryCIDPoint2026:
            pending = worker._ordinary_cid_point2026
            if (
                pending is not point
                or point.origin is not origin
                or type(point.step) is not NativeCIDRebuildMetadata2026
                or point.metadata is not origin.metadata
                or point.thread_id != threading.get_ident()
                or worker._file_sources is not origin.source_set
                or worker._flow_file_index2026 != origin.flow_index
                or worker._ordinary_cid_publication2026 is not None
            ):
                raise ValueError("Exact live ordinary CID source point required")
            metadata = self.engine.native_metadata
            expected = worker._ordinary_file_metadata_for_cursor_3e710_2026(
                point.step.metadata, worker._current_global_cpu_index
            )
            cursor = worker._current_global_cpu_index
            local_cursor = (
                (expected.node, expected.cpu_index)
                if cursor < native2026_cpu_count(expected)
                else (point.before_node, point.before_cpu_index)
            )
            if (
                type(metadata) is not Native2026Metadata
                or metadata is not worker._all_loaded_metadata[index]
                or metadata != expected
                or metadata.source_container
                is not point.entry_metadata.source_container
                or metadata.source_sha256 != point.entry_metadata.source_sha256
                or (worker._current_node, worker._current_cpu_index) != local_cursor
            ):
                raise ValueError(
                    "Ordinary CID source projection is not the published mirror"
                )
            return
        raise TypeError("Exact live ordinary CPU or CID source point required")

    def _advance_ordinary_prepare_origin2026(self, origin: object, stage: str) -> None:
        """Advance one exact source stage; repeated/skipped stages are rejected."""
        if type(stage) is not str:
            raise TypeError("Literal ordinary36800 source stage required")
        next_stage = {
            "issued": ("retained_type",),
            "retained_type": ("device",),
            "device": ("clock",),
            "clock": ("outputs",),
            "outputs": ("phase",),
            "phase": ("branch", "early_return"),
            "branch": ("recovery", "nonrecovery"),
            "recovery": ("cid",),
            "nonrecovery": ("cid",),
            "cid": ("cpu_tail",),
            "cpu_tail": ("prepared",),
            "prepared": ("reserved",),
            "reserved": ("scheduled",),
            "early_return": (),
            "scheduled": (),
        }
        with self._lock:
            self._validate_ordinary_prepare_origin_36800_2026(origin)
            assert isinstance(origin, _OrdinaryPrepareOrigin2026)
            if stage not in next_stage[origin.stage]:
                raise ValueError("Ordinary36800 source stage is stale or skipped")
            if stage == "clock":
                if (
                    type(origin.started_ms) is not int
                    or not 0 <= origin.started_ms < 86_400_000
                ):
                    raise ValueError("Actual local36800 clock sample required")
            elif stage == "phase":
                phase = self.engine.worker_phase
                if type(phase) is not int or phase not in (1, 2):
                    raise ValueError("Actual ordinary/recovery source phase required")
                origin.phase = phase
            elif stage == "early_return":
                if (
                    self.worker.native_prepare_handshake != 3
                    or origin.phase != 1
                    or self._lease is not None
                    or self._active_record is not origin.binding.previous_record
                ):
                    raise ValueError("Actual 1-to-3 source return required")
            elif stage == "recovery":
                if origin.phase != 1 or not self.worker.control_state.recovery_mode:
                    raise ValueError("Actual recovery branch entry required")
                origin.recovery = True
            elif stage == "nonrecovery":
                if origin.phase != 1:
                    raise ValueError("Source nonrecovery branch requires phase one")
                origin.recovery = False
            elif stage == "prepared":
                if (
                    origin.started_ms is None
                    or origin.phase != (2 if origin.recovery else 1)
                    or type(origin.recovery) is not bool
                ):
                    raise ValueError("Completed ordinary36800 prefix required")
            elif stage in ("reserved", "scheduled") and (
                origin.record is None or origin.lease is None
            ):
                raise ValueError("Exact unpublished ordinary reservation required")
            origin.stage = cast(
                Literal[
                    "issued",
                    "retained_type",
                    "device",
                    "clock",
                    "outputs",
                    "phase",
                    "branch",
                    "recovery",
                    "nonrecovery",
                    "cid",
                    "cpu_tail",
                    "prepared",
                    "reserved",
                    "scheduled",
                    "early_return",
                ],
                stage,
            )

    def _refresh_ordinary_prepare_projection2026(
        self, origin: object, *, point: object
    ) -> None:
        """Refresh only after a live source CPU-store or CID-rebuild point."""
        from scripts.calibration_2026 import (
            Native2026Metadata,
            NativeCIDRebuildMetadata2026,
            native2026_cpu_count,
            native2026_validate_runtime_metadata,
        )
        from scripts.cuw_engine_worker import (
            _NativeOrdinaryCIDPoint2026,
            _NativeOrdinaryCPUPoint2026,
        )

        with self._lock:
            self._validate_ordinary_prepare_origin_36800_2026(
                origin, _source_point=point
            )
            assert isinstance(origin, _OrdinaryPrepareOrigin2026)
            worker = self.worker
            if type(point) is _NativeOrdinaryCPUPoint2026:
                if (
                    worker._ordinary_cpu_point2026 is not point
                    or point.origin is not origin
                    or point.thread_id != threading.get_ident()
                    or point.metadata is not origin.metadata
                    or worker._file_sources is not origin.source_set
                    or worker._flow_file_index2026 != origin.flow_index
                    or worker._current_global_cpu_index != point.after
                ):
                    raise ValueError(
                        "Exact live ordinary CPU projection point required"
                    )
                expected = worker._ordinary_file_metadata_for_cursor_3e710_2026(
                    point.metadata, point.after
                )
                local_cursor = (
                    (expected.node, expected.cpu_index)
                    if point.after < native2026_cpu_count(expected)
                    else (point.before_node, point.before_cpu_index)
                )
                if (
                    self.engine.native_metadata != expected
                    or self.engine.native_metadata.source_container
                    is not expected.source_container
                    or worker._all_loaded_metadata[worker._current_file_index]
                    is not self.engine.native_metadata
                    or (worker._current_node, worker._current_cpu_index) != local_cursor
                    or worker._capture_flow_view2026() != origin.flow_view
                    or worker._getter_reset_epoch2026 != origin.reset_epoch
                ):
                    raise ValueError(
                        "Ordinary CPU projection did not commit atomically"
                    )
            elif type(point) is _NativeOrdinaryCIDPoint2026:
                pending = worker._ordinary_cid_point2026
                if (
                    pending is not point
                    or point.origin is not origin
                    or type(point.step) is not NativeCIDRebuildMetadata2026
                    or point.metadata is not origin.metadata
                    or point.thread_id != threading.get_ident()
                    or worker._file_sources is not origin.source_set
                    or worker._current_file_index != origin.flow_index
                ):
                    raise ValueError("Exact live ordinary3e710 rebuild point required")
                metadata = self.engine.native_metadata
                expected = worker._ordinary_file_metadata_for_cursor_3e710_2026(
                    point.step.metadata, worker._current_global_cpu_index
                )
                cursor = worker._current_global_cpu_index
                local_cursor = (
                    (expected.node, expected.cpu_index)
                    if cursor < native2026_cpu_count(expected)
                    else (point.before_node, point.before_cpu_index)
                )
                if (
                    type(metadata) is not Native2026Metadata
                    or metadata
                    is not worker._all_loaded_metadata[worker._current_file_index]
                    or metadata != expected
                    or metadata.source_container
                    is not point.entry_metadata.source_container
                    or metadata.source_sha256 != point.entry_metadata.source_sha256
                    or (worker._current_node, worker._current_cpu_index) != local_cursor
                ):
                    raise ValueError("Ordinary3e710 changed the authenticated FILE")
                native2026_validate_runtime_metadata(metadata)
            else:
                raise TypeError("Authenticated ordinary CPU or rebuild point required")
            metadata = self.engine.native_metadata
            origin.metadata = metadata
            origin.source_container = metadata.source_container
            origin.source_digest = metadata.source_sha256
            origin.source_set = worker._file_sources
            origin.flow_index = worker._flow_file_index2026
            origin.flow_view = worker._capture_flow_view2026()
            origin.pointer_view = worker._capture_pointer_view2026(metadata)
            origin.reset_epoch = worker._getter_reset_epoch2026
            origin.cpu_witness = self.engine._persistence_cpu_transition2026

    def _bind_ordinary_prepare_reservation2026(
        self,
        origin: object,
        record: _CompletionRecord2026,
        lease: ThreadPhaseLease2026,
    ) -> None:
        """Bind the exact post-prefix reservation before native scheduling."""
        from scripts.cuw_engine_worker import EngineWorker2026

        with self._lock:
            self._validate_ordinary_prepare_origin_36800_2026(origin)
            assert isinstance(origin, _OrdinaryPrepareOrigin2026)
            if (
                origin.stage != "prepared"
                or type(record) is not _CompletionRecord2026
                or record.sequence != origin.binding.sequence
                or record.completed.is_set()
                or record.result is not None
                or record.error is not None
                or record.continuation is not None
                or self._completion_records.get(record.sequence) is not None
                or type(lease) is not ThreadPhaseLease2026
                or lease.engine is not self.engine
                or lease.controller is not self.controller
                or lease.phase != origin.phase
                or lease.state != "reserved"
                or type(self.worker) is not EngineWorker2026
                or self.engine._worker_phase != origin.phase
                or self.engine.native_phase != origin.phase
            ):
                raise ValueError("Exact ordinary36800 phase reservation required")
            validate_thread_phase_lease(
                lease, self.engine, controller=self.controller, phase=origin.phase
            )
            origin.record = record
            origin.lease = lease
            origin.stage = "reserved"

    def _prepare_ordinary_outer_carrier2026(self, origin: object) -> threading.Thread:
        """Start the host carrier before the native CFE0/CreateThread source store."""
        with self._lock:
            self._validate_ordinary_prepare_origin_36800_2026(origin)
            assert isinstance(origin, _OrdinaryPrepareOrigin2026)
            if (
                origin.stage != "reserved"
                or origin.record is None
                or origin.lease is None
                or origin.lease.state != "reserved"
            ):
                raise ValueError("Reserved ordinary36800 carrier authority required")
            outer = self._outer
            if outer is None:
                if self.engine._native_outer_cfe0_2026:
                    raise ValueError("Native CFE0 requires its existing outer carrier")
                outer = threading.Thread(
                    target=self._run_outer, name="CUW2026-3cb90", daemon=True
                )
                self._outer = outer
                try:
                    outer.start()
                except BaseException:
                    if self._outer is outer:
                        self._outer = None
                        self._outer_exit = None
                    raise
            elif not outer.is_alive():
                raise ValueError("Live native outer carrier required")
            if not outer.is_alive():
                raise ValueError("Started native outer carrier did not remain live")
            return outer

    def _publish_ordinary_prepare_job2026(self, origin: object) -> int:
        """Publish host work only after native tail and immutable receipt issuance."""
        with self._lock:
            self._validate_ordinary_prepare_origin_36800_2026(origin)
            assert isinstance(origin, _OrdinaryPrepareOrigin2026)
            binding = origin.binding
            receipt = self._prepared_ordinary_entry2026
            record, lease = origin.record, origin.lease
            if (
                origin.stage != "scheduled"
                or type(receipt) is not _PreparedOrdinaryEntry2026
                or receipt is not origin.prepared_entry
                or receipt.origin is not origin
                or record is None
                or lease is None
                or receipt.record is not record
                or receipt.lease is not lease
                or self._sequence != binding.previous_sequence
                or self._active_record is not binding.previous_record
                or self._session is not binding.previous_session
                or self._lease is not binding.previous_lease
                or self._completion_records.get(binding.sequence) is not None
                or self._outer is None
                or not self._outer.is_alive()
                or lease.state != "reserved"
                or not self.engine._native_receiving_cfe2_2026
            ):
                raise ValueError("Exact scheduled ordinary36800 publication required")
            validate_thread_phase_lease(
                lease, self.engine, controller=self.controller, phase=receipt.phase
            )
            self._sequence = receipt.sequence
            self._completion_records[receipt.sequence] = record
            self._active_record = record
            self._session = receipt.session
            self._lease = lease
            self._completed.clear()
            self._child_done.clear()
            self._child_parked.clear()
            self._prepare_pending.clear()
            self._result = self._error = self._continuation = None
            self._child_exit = None
            self._waiting = False
            self._resume.set()
            return receipt.sequence

    def _record_ordinary_prepared_36800_2026(
        self, origin: object, *, started_ms: int
    ) -> _PreparedOrdinaryEntry2026:
        """Issue the immutable child receipt only after the true native tail."""
        from scripts.cuw_engine_worker import EngineWorker2026
        from scripts.programming_2026_common import ControlCommPhase2026
        from scripts.programming_replay import ProgrammingReplay

        with self._lock:
            self._validate_ordinary_prepare_origin_36800_2026(origin)
            assert isinstance(origin, _OrdinaryPrepareOrigin2026)
            binding = origin.binding
            record, lease = origin.record, origin.lease
            persistence = self.engine.persistence
            state = None if persistence is None else persistence.state
            persisted_cpu = None if state is None else state.write_cpu_index
            persisted_offset = (
                None if state is None else state.offset_of_write_cpu_multi_cal_index
            )
            if (
                origin.stage != "scheduled"
                or self._prepared_ordinary_entry2026 is not None
                or origin.prepared_entry is not None
                or type(self.worker) is not EngineWorker2026
                or type(self.controller) is not ControlCommPhase2026
                or type(binding.session) is not ProgrammingReplay
                or record is None
                or lease is None
                or started_ms != origin.started_ms
                or type(started_ms) is not int
                or not 0 <= started_ms < 86_400_000
                or origin.phase not in (1, 2)
                or origin.recovery is not (origin.phase == 2)
                or record.sequence != binding.sequence
                or record.completed.is_set()
                or lease.phase != origin.phase
                or lease.state != "reserved"
                or self.engine._native_receiving_cfe2_2026 is not True
                or self.engine._worker_phase != origin.phase
                or self.engine.native_phase != origin.phase
                or persistence is not binding.persistence
                or state is not binding.persistence_state
                or (None if state is None else state.write_cpu_index)
                != binding.persisted_cpu_index
                or (
                    None if state is None else state.offset_of_write_cpu_multi_cal_index
                )
                != binding.persisted_cpu_offset
                or type(self.engine._native_outer_cfe0_2026) is not bool
                or type(self.engine._native_be54_pending2026) is not bool
            ):
                raise ValueError("Completed ordinary36800 scheduled source required")
            assert record is not None
            assert lease is not None
            assert origin.phase is not None
            assert type(origin.source_digest) is str
            assert type(origin.flow_index) is int
            assert type(origin.reset_epoch) is int
            assert type(self.engine.worker_phase) is int
            metadata = origin.metadata
            if (
                metadata is None
                or self.engine.native_metadata is not metadata
                or metadata.source_container is not origin.source_container
                or metadata.source_sha256 != origin.source_digest
                or self.worker._file_sources is not origin.source_set
                or self.worker._flow_file_index2026 != origin.flow_index
                or self.worker._capture_flow_view2026() != origin.flow_view
                or self.worker._capture_pointer_view2026(metadata)
                != origin.pointer_view
                or self.worker._getter_reset_epoch2026 != origin.reset_epoch
            ):
                raise ValueError("Final ordinary36800 source projection changed")
            receipt = _PreparedOrdinaryEntry2026(
                origin,
                self,
                self.engine,
                self._native_start_generation2026,
                self.worker,
                self.controller,
                self.controller.runtime,
                binding.session,
                record,
                binding.sequence,
                lease,
                started_ms,
                origin.phase,
                bool(origin.recovery),
                metadata,
                origin.source_container,
                origin.source_digest,
                origin.source_set,
                persistence,
                state,
                origin.flow_index,
                origin.flow_view,
                origin.pointer_view,
                origin.reset_epoch,
                self.engine.dh_state.selection_cpu_index,
                self.worker._cpu_offset,
                persisted_cpu,
                persisted_offset,
                self.engine._native_outer_cfe0_2026,
                self.engine._native_be54_pending2026,
                self.engine._native_receiving_cfe2_2026,
                self.engine.native_phase,
                self.engine.worker_phase,
            )
            self._prepared_ordinary_entry2026 = receipt
            origin.prepared_entry = receipt
            return receipt

    def _consume_ordinary_prepare_entry_36800_2026(
        self, lease: ThreadPhaseLease2026
    ) -> _PreparedOrdinaryEntry2026:
        """Consume the exact prepared receipt at the adopted child's Execute."""
        from scripts.cuw_engine_worker import EngineWorker2026

        with self._lock:
            receipt = self._prepared_ordinary_entry2026
            if type(receipt) is not _PreparedOrdinaryEntry2026:
                raise ValueError("Exact pending ordinary36800 child receipt required")
            record = self._active_record
            origin = receipt.origin
            if (
                threading.current_thread() is not self._child
                or record is None
                or type(self.worker) is not EngineWorker2026
                or self._prepared_ordinary_entry2026 is not receipt
                or self._ordinary_prepare_origin2026 is not origin
                or self._ordinary_prepare_binding2026 is not origin.binding
                or origin.stage != "scheduled"
                or origin.prepared_entry is not receipt
                or self._native_start_generation2026 is not receipt.generation
                or self.engine.thread_job is not self
                or self.engine.worker is not self.worker
                or self.worker.controller is not self.controller
                or self.engine._controller_execution is not self.controller
                or self._sequence != receipt.sequence
                or record is not receipt.record
                or record.sequence != receipt.sequence
                or self._completion_records.get(receipt.sequence) is not record
                or self._session is not receipt.session
                or self._lease is not lease
                or receipt.lease is not lease
                or lease.state != "adopted"
                or lease._thread != threading.get_ident()
                or lease.phase != receipt.phase
                or self.engine.native_metadata is not receipt.metadata
                or receipt.metadata.source_container is not receipt.source_container
                or receipt.metadata.source_sha256 != receipt.source_digest
                or self.worker._file_sources is not receipt.source_set
                or self.worker._flow_file_index2026 != receipt.flow_index
                or self.worker._capture_flow_view2026() != receipt.flow_view
                or self.worker._capture_pointer_view2026(receipt.metadata)
                != receipt.pointer_view
                or self.worker._getter_reset_epoch2026 != receipt.reset_epoch
                or self.engine.persistence is not receipt.persistence
                or (
                    None
                    if self.engine.persistence is None
                    else self.engine.persistence.state
                )
                is not receipt.persistence_state
                or self.engine.native_phase != receipt.native_phase
                or self.engine.worker_phase != receipt.worker_phase
                or self.worker._phase_started_ms is not None
                or self._getter_execute_return2026 is not None
            ):
                raise ValueError("Prepared ordinary36800 receipt is stale or foreign")
            validate_thread_phase_lease(
                lease, self.engine, controller=self.controller, phase=receipt.phase
            )
            persistence = self.engine.persistence
            if persistence is not None and (
                persistence.state.write_cpu_index != receipt.persisted_cpu_index
                or persistence.state.offset_of_write_cpu_multi_cal_index
                != receipt.persisted_cpu_offset
            ):
                raise ValueError("Persisted ordinary CPU lineage changed")
            self._prepared_ordinary_entry2026 = None
            self._ordinary_prepare_origin2026 = None
            self._ordinary_prepare_binding2026 = None
            self._ordinary_prepare_starting2026 = False
            return receipt

    def _validate_ordinary_prepare_dispatch_36800_2026(
        self, worker: object, phase: int, lease: ThreadPhaseLease2026
    ) -> None:
        """Authorize only the initial dispatch carrying this exact receipt."""
        from scripts.cuw_engine_worker import EngineWorker2026

        with self._lock:
            receipt = self._prepared_ordinary_entry2026
            origin = self._ordinary_prepare_origin2026
            record = self._active_record
            if (
                type(receipt) is not _PreparedOrdinaryEntry2026
                or type(origin) is not _OrdinaryPrepareOrigin2026
                or receipt is not origin.prepared_entry
                or receipt.origin is not origin
                or receipt.job is not self
                or receipt.engine is not self.engine
                or receipt.worker is not worker
                or type(worker) is not EngineWorker2026
                or receipt.controller is not self.controller
                or receipt.runtime is not self.controller.runtime
                or self._native_start_generation2026 is not receipt.generation
                or self.engine.thread_job is not self
                or self.engine.worker is not worker
                or worker.controller is not self.controller
                or self.engine._controller_execution is not None
                or self._ordinary_prepare_binding2026 is not origin.binding
                or origin.stage != "scheduled"
                or receipt.phase != phase
                or phase != 1
                or receipt.recovery
                or self._sequence != receipt.sequence
                or record is not receipt.record
                or record is None
                or record.sequence != receipt.sequence
                or self._completion_records.get(receipt.sequence) is not record
                or self._session is not receipt.session
                or self._lease is not receipt.lease
                or lease is not receipt.lease
                or lease.state != "reserved"
                or lease._thread is not None
                or threading.current_thread() is not self._child
                or not self.engine._active
                or self.engine._phase_thread is not None
                or self.engine._worker_phase != phase
                or worker._phase_started_ms is not None
                or self._getter_execute_return2026 is not None
                or self.engine.native_metadata is not receipt.metadata
                or receipt.metadata.source_container is not receipt.source_container
                or receipt.metadata.source_sha256 != receipt.source_digest
                or worker._file_sources is not receipt.source_set
                or worker._flow_file_index2026 != receipt.flow_index
                or worker._capture_flow_view2026() != receipt.flow_view
                or worker._capture_pointer_view2026(receipt.metadata)
                != receipt.pointer_view
                or worker._getter_reset_epoch2026 != receipt.reset_epoch
                or self.engine.persistence is not receipt.persistence
                or (
                    None
                    if self.engine.persistence is None
                    else self.engine.persistence.state
                )
                is not receipt.persistence_state
                or self.engine.native_phase != receipt.native_phase
                or self.engine.worker_phase != receipt.worker_phase
                or worker.native_prepare_handshake != 1
                or worker.control_state.recovery_mode
            ):
                raise ValueError(
                    "Exact initial ordinary36800 dispatch receipt required"
                )
            validate_thread_phase_lease(
                lease, self.engine, controller=self.controller, phase=phase
            )

    def _abort_ordinary_prepare_36800_2026(self, origin: object) -> None:
        """Retire only an exact unpublished ordinary reservation on source fault."""
        if type(origin) is not _OrdinaryPrepareOrigin2026:
            raise TypeError("Exact ordinary36800 origin required")
        with self._lock:
            binding = origin.binding
            scope = self.engine._ordinary_prepare_scope2026
            if (
                type(binding) is not _OrdinaryPrepareStartBinding2026
                or self._ordinary_prepare_origin2026 is not origin
                or self._ordinary_prepare_binding2026 is not binding
                or not self._ordinary_prepare_starting2026
                or binding.job is not self
                or binding.engine is not self.engine
                or binding.generation is not self._native_start_generation2026
                or binding.issuer_thread != threading.get_ident()
                or origin.scope is None
                or type(scope) is not tuple
                or len(scope) != 4
                or scope[0] is not self
                or scope[1] is not binding
                or scope[2] is not origin
                or scope[3] is not origin.scope
            ):
                raise ValueError("Exact unpublished ordinary36800 scope required")
            prefix_abort = (
                origin.stage
                in (
                    "issued",
                    "retained_type",
                    "device",
                    "clock",
                    "outputs",
                    "phase",
                    "branch",
                    "recovery",
                    "nonrecovery",
                    "cid",
                    "cpu_tail",
                    "prepared",
                )
                and origin.record is None
                and origin.lease is None
                and origin.prepared_entry is None
                and self._prepared_ordinary_entry2026 is None
            )
            reserved_abort = (
                origin.stage in ("prepared", "reserved", "scheduled")
                and origin.record is not None
                and origin.lease is not None
                and origin.record.sequence == binding.sequence
                and origin.lease.state == "reserved"
                and (
                    self._prepared_ordinary_entry2026 is None
                    or self._prepared_ordinary_entry2026 is origin.prepared_entry
                )
            )
            if not (
                (prefix_abort or reserved_abort)
                and binding.sequence == binding.previous_sequence + 1
                and self._sequence == binding.previous_sequence
                and self._active_record is binding.previous_record
                and self._lease is binding.previous_lease
                and self._session is binding.previous_session
                and self._completion_records.get(binding.sequence) is None
                and self._completed.is_set() is bool(binding.previous_sequence)
            ):
                raise ValueError("Unpublished ordinary36800 reservation required")
            self._prepared_ordinary_entry2026 = None
            self._ordinary_prepare_binding2026 = None
            self._ordinary_prepare_origin2026 = None
            self._ordinary_prepare_starting2026 = False

    def _validate_getter_entry_reservation2026(
        self, session: ProgrammingReplay, record: _CompletionRecord2026
    ) -> int | None:
        """Authenticate the exact job.start lexical reservation transaction."""
        binding = self._getter_entry_binding2026
        if (
            type(binding) is not _GetterEntryStartBinding2026
            or binding.session is not session
            or binding.record is not record
            or binding.sequence != self._sequence + 1
            or binding.previous_record is not self._active_record
            or binding.issuer_thread != threading.get_ident()
            or binding.generation is not self._native_start_generation2026
            or self._getter_entry_starting2026 is not True
            or self.engine.thread_job is not self
            or self.worker.controller is not self.controller
            or self._lease is not None
            or (self._sequence and not self._completed.is_set())
            or self._getter_entry_origin2026 is not None
            or self._getter_stop_receipt2026 is not None
            or self._getter_continuation2026 is not None
            or not self._is_raw_control_getter_root2026(session)
        ):
            raise ValueError("Exact raw CONTROL getter start transaction required")
        return self.engine._worker_phase

    def _validate_getter_entry_34cb0_2026(self, origin: object) -> None:
        """Validate the current one-use raw getter first-entry origin."""
        if type(origin) is not _NativeGetterEntryOrigin2026:
            raise TypeError("Exact native getter first-entry origin required")
        with self._lock:
            binding = self._getter_entry_binding2026
            if (
                self._getter_entry_origin2026 is not origin
                or type(binding) is not _GetterEntryStartBinding2026
                or binding.session is not origin.session
                or binding.record is not origin.record
                or binding.generation is not origin.generation
                or origin.job is not self
                or origin.engine is not self.engine
                or origin.worker is not self.worker
                or origin.controller is not self.controller
                or origin.generation is not self._native_start_generation2026
                or origin.session is not self._session
                or origin.sequence != self._sequence + 1
                or origin.record is not binding.record
                or origin.record.sequence != origin.sequence
                or origin.previous_record is not self._active_record
                or self._lease is not origin.lease
                or origin.lease.state != "reserved"
                or origin.lease.phase != 0
                or origin.lease.engine is not self.engine
                or origin.lease.controller is not self.controller
                or origin.issuer_thread != binding.issuer_thread
                or origin.issuer_thread != threading.get_ident()
                or self._sequence
                != (
                    0
                    if origin.previous_record is None
                    else origin.previous_record.sequence
                )
                or self._completion_records.get(origin.sequence) is not None
                or self._getter_stop_receipt2026 is not None
                or self._getter_continuation2026 is not None
                or self.engine.thread_job is not self
                or self.engine.native_metadata is not origin.metadata
                or origin.metadata.source_container is not origin.source_container
                or origin.metadata.source_sha256 != origin.source_sha256
                or self.engine.configuration is not origin.configuration
                or self.worker._file_sources is not origin.source_set
                or self.worker._flow_file_index2026 != origin.flow_index
                or self.worker._capture_flow_view2026() != origin.flow_view
                or self.worker._capture_pointer_view2026(origin.metadata)
                != origin.pointer_view
                or self.engine._native_receiving_cfe2_2026
                or self.engine._native_outer_cfe0_2026 is not origin.cfe0_at_issue
                or self.engine._native_be54_pending2026
            ):
                raise ValueError("Getter first-entry origin is stale or foreign")
            self.validate_owner(self.engine, self.controller)
            self.worker.validate_source(self.engine)

    def _issue_getter_entry_origin2026(
        self,
        binding: _GetterEntryStartBinding2026,
        lease: ThreadPhaseLease2026,
    ) -> _NativeGetterEntryOrigin2026:
        """Bind the source prefix to the reserved unpublished record and lease."""
        if (
            self._getter_entry_binding2026 is not binding
            or self._getter_entry_starting2026 is not True
            or binding.issuer_thread != threading.get_ident()
            or binding.generation is not self._native_start_generation2026
            or self._getter_entry_origin2026 is not None
            or self._lease is not lease
            or lease.state != "reserved"
            or lease.phase != 0
        ):
            raise ValueError("Exact getter first-entry reservation required")
        metadata = binding.metadata
        sources = binding.source_set
        if (
            self.engine.native_metadata is not metadata
            or metadata.source_container is not binding.source_container
            or metadata.source_sha256 != binding.source_sha256
            or self.engine.configuration is not binding.configuration
            or self.worker._file_sources is not sources
            or self.worker._flow_file_index2026 != binding.flow_index
            or self.worker._capture_flow_view2026() != binding.flow_view
            or self.worker._capture_pointer_view2026(metadata) != binding.pointer_view
            or self.engine._native_outer_cfe0_2026 is not binding.cfe0_at_issue
            or self.engine._native_be54_pending2026
        ):
            raise ValueError("Getter source snapshot changed during reservation")
        if sources is not None:
            from scripts.cuw_file_services import validate_file_sources_2026

            validate_file_sources_2026(sources, self.engine)
        origin = _NativeGetterEntryOrigin2026(
            self.engine,
            self,
            self.worker,
            self.controller,
            self._native_start_generation2026,
            binding.session,
            binding.issuer_thread,
            binding.previous_phase,
            binding.previous_record,
            binding.record,
            binding.sequence,
            lease,
            sources,
            binding.source_container,
            binding.source_sha256,
            metadata,
            self.engine.configuration,
            binding.flow_index,
            binding.flow_view,
            binding.pointer_view,
            binding.cfe0_at_issue,
        )
        self._session = binding.session
        self._getter_entry_origin2026 = origin
        return origin

    def _publish_getter_entry_schedule_34cb0_2026(self, origin: object) -> None:
        """Publish the first source record only after its complete native prefix."""
        with self._lock:
            if type(origin) is not _NativeGetterEntryOrigin2026:
                raise TypeError("Exact native getter first-entry origin required")
            binding = self._getter_entry_binding2026
            if (
                self._getter_entry_origin2026 is not origin
                or type(binding) is not _GetterEntryStartBinding2026
                or binding.session is not origin.session
                or binding.record is not origin.record
                or binding.generation is not origin.generation
                or origin.job is not self
                or origin.engine is not self.engine
                or origin.worker is not self.worker
                or origin.controller is not self.controller
                or origin.generation is not self._native_start_generation2026
                or origin.session is not self._session
                or origin.sequence != self._sequence + 1
                or origin.record is not binding.record
                or origin.previous_record is not self._active_record
                or origin.lease is not self._lease
                or origin.lease.state != "reserved"
                or origin.issuer_thread != binding.issuer_thread
                or threading.get_ident() != origin.issuer_thread
                or self._getter_entry_starting2026 is not True
                or self._completion_records.get(origin.sequence) is not None
                or self._sequence
                != (
                    0
                    if origin.previous_record is None
                    else origin.previous_record.sequence
                )
                or self.engine.thread_job is not self
                or self.engine.native_metadata is not origin.metadata
                or origin.metadata.source_container is not origin.source_container
                or origin.metadata.source_sha256 != origin.source_sha256
                or self.engine.configuration is not origin.configuration
                or self.worker._file_sources is not origin.source_set
                or self.worker._flow_file_index2026 != origin.flow_index
                or self.worker._capture_flow_view2026() != origin.flow_view
                or self.worker._capture_pointer_view2026(origin.metadata)
                != origin.pointer_view
                or self.engine._native_outer_cfe0_2026 is not origin.cfe0_at_issue
                or self.engine._native_receiving_cfe2_2026
                or self.engine._native_be54_pending2026 is not origin.cfe0_at_issue
            ):
                raise ValueError("First getter scheduling position changed")
            self._sequence = origin.sequence
            self._completion_records[origin.sequence] = origin.record
            self._active_record = origin.record
            self._completed.clear()
            self._child_done.clear()
            self._child_parked.clear()
            self._prepare_pending.clear()
            self._result = self._error = self._continuation = None
            self._child_exit = None
            self._resume.set()

    def _abort_getter_entry_34cb0_2026(self, origin: object) -> None:
        """Revoke an unpublished failed prefix without fabricating completion."""
        if type(origin) is not _NativeGetterEntryOrigin2026:
            raise TypeError("Exact native getter first-entry origin required")
        with self._lock:
            self._validate_getter_entry_34cb0_2026(origin)
            if (
                self._sequence + 1 != origin.sequence
                or self._completion_records.get(origin.sequence) is not None
                or self._active_record is not origin.previous_record
                or origin.lease.state != "reserved"
            ):
                raise ValueError("Published getter entry cannot be rolled back")
            self._lease = None
            self._session = None
            self._getter_entry_origin2026 = None

    def _abort_getter_entry_reservation2026(
        self,
        session: ProgrammingReplay,
        record: _CompletionRecord2026,
        lease: ThreadPhaseLease2026,
    ) -> int | None:
        """Clear only the exact unpublished reservation before origin issuance."""
        with self._lock:
            binding = self._getter_entry_binding2026
            if (
                type(binding) is not _GetterEntryStartBinding2026
                or binding.session is not session
                or binding.record is not record
                or binding.issuer_thread != threading.get_ident()
                or binding.generation is not self._native_start_generation2026
                or not self._getter_entry_starting2026
                or self._lease is not lease
                or self._session is not session
                or lease.state != "reserved"
                or lease.engine is not self.engine
                or lease.controller is not self.controller
                or lease.phase != 0
                or record.sequence != self._sequence + 1
                or self._sequence
                != (
                    0
                    if binding.previous_record is None
                    else binding.previous_record.sequence
                )
                or self._active_record is not binding.previous_record
                or self._completion_records.get(record.sequence) is not None
                or self._getter_entry_origin2026 is not None
            ):
                raise ValueError("Exact unpublished getter reservation required")
            previous_phase = binding.previous_phase
            self._lease = None
            self._session = None
            return previous_phase

    def _start_getter_entry_34cb0_2026(self, session: ProgrammingReplay) -> int:
        """Run the authenticated raw getter prefix before publishing its record."""
        metadata = self.engine.native_metadata
        source_set = self.worker._file_sources
        flow_index = self.worker._flow_file_index2026
        flow_view = self.worker._capture_flow_view2026()
        pointer_view = self.worker._capture_pointer_view2026(metadata)
        if source_set is not None:
            from scripts.cuw_file_services import validate_file_sources_2026

            validate_file_sources_2026(source_set, self.engine)
        if type(flow_index) is not int or flow_index < 0:
            raise ValueError("Current native getter flow index required")

        sequence = self._sequence + 1
        record = _CompletionRecord2026(sequence)
        binding = _GetterEntryStartBinding2026(
            object(),
            session,
            record,
            self._active_record,
            sequence,
            threading.get_ident(),
            self._native_start_generation2026,
            source_set,
            metadata.source_container,
            metadata.source_sha256,
            metadata,
            self.engine.configuration,
            flow_index,
            flow_view,
            pointer_view,
            self.engine._native_outer_cfe0_2026,
        )
        self._getter_entry_binding2026 = binding
        self._getter_entry_starting2026 = True
        lease = None
        origin = None
        try:
            lease = self.engine._reserve_getter_entry_34cb0_2026(self, session, record)
            self._lease = lease
            self._session = session
            origin = self._issue_getter_entry_origin2026(binding, lease)
            if self._outer is None:
                outer = threading.Thread(
                    target=self._run_outer, name="CUW2026-3cb90", daemon=True
                )
                self._outer = outer
                try:
                    outer.start()
                except BaseException:
                    self._outer = None
                    raise

            self.worker._apply_getter_entry_34cb0_2026(origin=origin)
            if (
                self._sequence != sequence
                or self._completion_records.get(sequence) is not record
                or self._active_record is not record
                or not self._resume.is_set()
            ):
                raise ValueError("Native getter prefix did not publish its record")
            self._getter_entry_origin2026 = None
            return sequence
        except BaseException as error:
            if origin is not None and self._sequence < sequence:
                try:
                    self.engine._abort_getter_entry_34cb0_2026(origin)
                except BaseException as rollback_error:  # noqa: BLE001 - retain the exact native/prefix failure
                    error.add_note(
                        "Native getter reservation rollback failed: "
                        + type(rollback_error).__name__
                    )
            elif lease is not None and self._sequence < sequence:
                try:
                    self.engine._abort_getter_entry_reservation_34cb0_2026(
                        self, session, record, lease
                    )
                except BaseException as rollback_error:  # noqa: BLE001 - retain the exact native/prefix failure
                    error.add_note(
                        "Native getter reservation rollback failed: "
                        + type(rollback_error).__name__
                    )
            raise
        finally:
            if (
                self._sequence == sequence
                and self._completion_records.get(sequence) is record
            ):
                self._getter_entry_origin2026 = None
            self._getter_entry_binding2026 = None
            self._getter_entry_starting2026 = False

    def start(
        self, session: ProgrammingReplay, *, phase: int | None = None
    ) -> int | None:
        from scripts.programming_replay import ProgrammingReplay

        if type(session) is not ProgrammingReplay:
            raise TypeError("Concrete programming replay required")
        phases = {"get_cid": 0, "prepare": 1, "write": 2, "recovery": 2}
        expected = phases.get(session.operation)
        if expected is None or (
            phase is not None and (type(phase) is not int or phase != expected)
        ):
            raise ValueError("Native child phase differs from the real export")
        shared_chronology = (
            session._runtime2026 is self.controller.runtime
            and session._controller2026 is self.controller
            and session._engine2026 is self.engine
        )
        if (
            session.used
            or (session.trace.position and not shared_chronology)
            or session.container.digest != self.engine.source_sha256
            or session.node != self.engine.native_metadata.node
            or session.context["observations"]["host"].get("cpu_index", 0)
            != self.engine.dh_state.selection_cpu_index
        ):
            raise ValueError("Fresh replay for the actual engine source required")
        with self._lock:
            self.validate_owner(self.engine)
            if self._stop or (self._outer is not None and not self._outer.is_alive()):
                raise ValueError("Native thread job is stopped")
            promotion = (
                self._getter_promotion_starting2026
                and self._getter_continuation_stage2026 == "promoting"
                and self._getter_promotion_root2026 is session
                and threading.current_thread() is self._outer
            )
            if self._getter_continuation2026 is not None and not promotion:
                raise ValueError("Pending native getter continuation blocks new roots")
            if promotion:
                self._validate_promoted_getter_continuation_2026(
                    self._getter_continuation2026
                )
            with _VBF_LOCK:
                if any(
                    item.fields["job"] is self
                    and item.fields["state"]
                    in (
                        "issued",
                        "acknowledged",
                        "parked",
                        "prepared",
                        "queued",
                        "reserved",
                        "adopted",
                    )
                    for _, item in _VBF_REQUESTS.values()
                ):
                    raise ValueError(
                        "Native start cannot bypass an outstanding VBF request"
                    )
            if (
                expected == 1
                and self.worker.native_prepare_handshake == 1
                and not self.worker.control_state.recovery_mode
                and self.native_worker_exists
            ):
                with self.engine.prepare_reentry_execution(self):
                    if self.worker.prepare_reentry_handshake():
                        return None
            if self._lease is not None or (
                self._sequence and not self._completed.is_set()
            ):
                raise ValueError("Native child is already scheduled")
            if (
                expected == 0
                and not promotion
                and self._is_raw_control_getter_root2026(session)
            ):
                return self._start_getter_entry_34cb0_2026(session)
            if expected in (1, 2) and self._is_raw_control_ordinary_root2026(session):
                return self._start_ordinary_prepare_36800_2026(session)
            self._lease = self.engine.reserve_phase(self.controller, expected)
            self._session = session
            self._completed.clear()
            self._child_done.clear()
            self._child_parked.clear()
            self._prepare_pending.clear()
            self._result = self._error = self._continuation = None
            self._child_exit = None
            sequence = self._sequence + 1
            record = _CompletionRecord2026(sequence)
            if self._outer is None:
                self._outer = threading.Thread(
                    target=self._run_outer, name="CUW2026-3cb90", daemon=True
                )
                try:
                    self._outer.start()
                except BaseException:
                    self.engine.release_reserved_phase(self._lease)
                    self._lease = self._session = None
                    self._outer = None
                    raise
            self._sequence = sequence
            self._completion_records[sequence] = record
            self._active_record = record
            self._resume.set()
            return self._sequence

    def _prepare_controller_entry(self, session: ProgrammingReplay) -> None:
        """5b970 selects the loader;59710/5bf80 retain its actual export identity."""
        from scripts.calibration_2026 import native2026_cpu_type
        from scripts.programming_2026_common import (
            NativeCallbackLookupError,
            NativePassThruException2026,
        )

        self.engine._require_owned_phase()
        metadata = self.engine.native_metadata
        contact = metadata.vehicle.get("contacttype", "")
        legacy = False
        if contact not in ("P5-Unified", "Phase6", "Ethernet"):
            kind = metadata.vehicle.get("kindofecu", "")
            cpu_type = native2026_cpu_type(metadata, 0)
            filename = (kind + contact + cpu_type + ".ini").casefold()
            if not any(
                name.casefold() == filename for name in session._catalog_sources
            ):
                general = self.engine._general_parameters
                if general is None:
                    raise NativeCallbackLookupError()
                if general.boolean_with_keys(
                    kind, cpu_type, contact, "FlagToUseCIDGetterAndFlashWriterDLL"
                ):
                    raise NativePassThruException2026(
                        9999, "CUW2026 native worker loader", 0x16B6
                    )
                legacy = True
        if self._controller_entry is None:
            name = (
                "TCUWLegacyCIDGettersAndFlashWriters.dll"
                if legacy
                else "TCUWControlCommPhase.dll"
            )
            module = session.modules.get(name)
            identity = None if module is None else module.native_identity
            line = 0
            if identity is None:
                line = 0x16DC if legacy else 0x8F2
            elif "Execute" not in identity.callable_exports:
                line = 0x16E3 if legacy else 0x902
            elif not legacy:
                if not {
                    "IsSendingSyncPeriodicMsgToECU",
                    "DisconnectJ2534Connection",
                }.issubset(identity.callable_exports):
                    line = 0x902
                elif (
                    "ChangeToReprogGWModeForDHCentralGW"
                    not in identity.callable_exports
                ):
                    line = 0x90A
                elif identity != self.controller.identity:
                    raise ValueError("Loaded control identity differs from its owner")
            if line:
                raise NativePassThruException2026(
                    9999, "CUW2026 native worker loader", line
                )
            self._controller_entry = name
        if legacy:
            raise ValueError("Consolidated native controller ownership is not bound")

    def _run_child(self) -> None:
        record = None
        try:
            while True:
                self._child_resume.wait()
                self._child_resume.clear()
                with self._lock:
                    lease, session = self._lease, self._session
                    record = self._active_record
                    stop_stage = self._getter_stop_stage2026
                    getter_stop_pending = (
                        self._getter_stop_receipt2026 is not None
                        and stop_stage is not None
                        and stop_stage.receipt is self._getter_stop_receipt2026
                        and stop_stage.stage == "child_requested"
                        and stop_stage.child is threading.current_thread()
                    )
                    if getter_stop_pending and (
                        lease is None or lease.state == "released"
                    ):
                        # Retained14 is consumed at the real post-child wake.
                        # The old released lease can remain in the outer's slot
                        # until its retirement bookkeeping clears that alias.
                        self._child_parked.set()
                        self._child_done.set()
                        self._activity.set()
                        break
                    if self._stop and (lease is None or lease.state != "reserved"):
                        break
                    if lease is None:
                        if getter_stop_pending:
                            # A concrete source-started child may consume +14 with
                            # no queued phase; it performs no invented result/work.
                            self._child_parked.set()
                            self._child_done.set()
                            self._activity.set()
                            break
                        raise ValueError("Native child resume has no reserved work")
                    assert record is not None
                    assert session is not None
                    self._child_parked.clear()
                try:
                    getter_sequence = None
                    with self.controller.runtime.thread_job_host_boundary(self):
                        self.controller.runtime.check()
                        session.bind_controller2026(self.controller)
                        with self.engine.controller_execution(
                            self.controller, lease.phase, lease=lease
                        ):
                            from scripts.j2534_2026 import NativePassThruError2026
                            from scripts.programming_2026_common import (
                                NativePassThruException2026,
                            )

                            self.worker._begin_outer_control_loader()
                            try:
                                self._prepare_controller_entry(session)
                            except (
                                NativePassThruException2026,
                                NativePassThruError2026,
                            ) as error:
                                self.worker._record_outer_control_loader_failure(error)
                            getter_candidate = None
                            if self.worker.native_fatal_input80:
                                result = {
                                    "native_return": None,
                                    "exports": (),
                                    "programming_completed": False,
                                }
                            else:
                                if self._controller_entry == "TCUWControlCommPhase.dll":
                                    # The authenticated raw CONTROL Execute binds its
                                    # held family target after it issues the raw token.
                                    session.bind_controller2026(self.controller)
                                else:
                                    session.bind_engine2026(self.engine)
                                self.controller.bind_startup_session(
                                    self.engine, session
                                )
                                startup = (
                                    self.worker.run_gateway_startup()
                                    if lease.phase == 1
                                    else None
                                )
                                if (
                                    startup is not None
                                    and not startup.returned
                                    and startup.output_flag
                                ):
                                    self._query_native_worker_error()
                                    result = {
                                        "native_return": None,
                                        "startup_return": False,
                                        "exports": (),
                                        "programming_completed": False,
                                    }
                                else:
                                    result = self.controller.execute(
                                        self.engine, session
                                    )
                                    if lease.phase == 0:
                                        from scripts import programming_2026_common

                                        context = (
                                            self.controller.native_control_context2026(
                                                self.engine
                                            )
                                        )
                                        if programming_2026_common._control_has_ordinary_getter_return2026(
                                            context
                                        ):
                                            getter_sequence = self._sequence
                                            with self._lock:
                                                if (
                                                    self._getter_execute_pending2026
                                                    is not None
                                                ):
                                                    raise ValueError(
                                                        "Getter Execute return is already pending"
                                                    )
                                                self._getter_execute_pending2026 = (
                                                    context,
                                                    result,
                                                    lease,
                                                    self._sequence,
                                                )
                                            try:
                                                self._record_getter_execute_return_2026(
                                                    context, result
                                                )
                                            finally:
                                                with self._lock:
                                                    pending = (
                                                        self._getter_execute_pending2026
                                                    )
                                                    if (
                                                        type(pending) is tuple
                                                        and len(pending) == 4
                                                        and pending[1] is result
                                                    ):
                                                        self._getter_execute_pending2026 = None
                                            self.dispatch_control_getter_return()
                                            getter_candidate = (
                                                self._capture_getter_candidate_2026(
                                                    context
                                                )
                                            )
                                            self.dispatch_getter_callback_stage2026(
                                                getter_candidate,
                                                "getter_native_fatal_5b1b0",
                                            )
                                            self.dispatch_getter_callback_stage2026(
                                                getter_candidate,
                                                "getter_control_fatal_5b0e0",
                                            )
                                            self._finish_getter_decision_2026(
                                                getter_candidate
                                            )
                                            decision = (
                                                self._getter_callback_decision2026
                                            )
                                            if decision is None:
                                                raise ValueError(
                                                    "Native getter decision was not issued"
                                                )
                                            self.dispatch_getter_decision2026(decision)
                            if getter_candidate is None:
                                self.dispatch_worker_tail()
                        with self._lock:
                            self._result = result
                            record.result = result
                except BaseException as error:  # noqa: BLE001 - preserve child faults for the joining host
                    with self._lock:
                        self._error = error
                        record.error = error
                finally:
                    if getter_sequence is not None:
                        self._retire_getter_receipts_2026(getter_sequence)
                    if lease.state == "reserved":
                        self.engine.release_reserved_phase(lease)
                    # 5a835 publishes+1c BEFORE be64 and waits for be5c.
                    self._child_parked.set()
                    self._child_done.set()
                    self._activity.set()
            self._child_exit = 0
        except BaseException as error:  # noqa: BLE001 - preserve thread failure for the joining owner
            with self._lock:
                self._error, self._child_exit = error, 1
                if record is not None and not record.completed.is_set():
                    record.error = error
            self._child_done.set()
            self._activity.set()

    def _query_native_worker_error(self) -> None:
        """5b810: source worker query and reconnect on the engine CJ2534IF view."""
        from scripts.j2534_2026 import NativePassThruError2026
        from scripts.programming_2026_common import (
            NativePassThruException2026,
            native_error_fields2026,
        )

        self.engine._require_owned_phase()
        retry = self.engine.bind_retry_controller()
        runtime = self.controller.runtime
        while True:
            runtime.check()
            self.engine.notify_native_error_kind()
            self.engine.notify_native_errors()
            self.worker.begin_control_error_query()
            self.engine.publish_control_failed(self.controller)
            # 5b810 calls the worker+40 CUW function directly;58240 is a separate handoff.
            retry.callback3()
            self.worker.import_control_error_query_decision(retry)
            if not self.worker.control_state.failed:
                return
            try:
                with runtime.engine_device_calls(self.engine):
                    device = self.engine.engine_runtime_device()
                    device.disconnect()
                    for identifier in runtime.owned_identifiers("stop_filter"):
                        runtime.forget_invalidated_resource(
                            "stop_filter", identifier=identifier
                        )
                    if runtime.owns_resource("disconnect"):
                        runtime.forget_invalidated_resource("disconnect")
                    metadata = self.engine.native_metadata
                    contact = metadata.vehicle.get("contacttype", "")
                    protocol = (
                        3
                        if contact == "SIL"
                        else 0x800F
                        if contact == "Ethernet"
                        else 0x8012
                        if contact == "Phase6" and metadata.protocol_at_node == "02"
                        else 6
                    )
                    if protocol == 0x800F and device.version != 1:
                        device.switch_version()
                    device.connect_native(protocol)
                return
            except (NativePassThruException2026, NativePassThruError2026) as error:
                primary, status = native_error_fields2026(error)
                state = self.engine.dh_state
                state.record_native_error(
                    3, primary, state.passthru_error if status is None else status
                )

    def _run_outer(self) -> None:
        record = None
        dispatch_admitted_work = False
        try:
            while True:
                record = None
                if not dispatch_admitted_work:
                    self._resume.wait()
                    self._resume.clear()
                dispatch_admitted_work = False
                with self._lock:
                    lease = self._lease
                    record = self._active_record
                    if lease is None:
                        if self._stop:
                            break
                        queued_request = _queued_vbf_request(self)
                        if queued_request is None:
                            raise ValueError(
                                "Native resume event has no actual child work"
                            )
                        _promote_queued_vbf(self, queued_request)
                        lease = self._lease
                        record = self._active_record
                    assert record is not None
                    self._waiting = False
                    child = self._child
                    if child is None:
                        try:
                            child = self._ensure_native_child_started2026(record)
                        except BaseException:
                            self.engine.release_reserved_phase(lease)
                            self._lease = self._session = None
                            raise
                self._child_resume.set()
                while not self._child_done.is_set():
                    self._activity.wait()
                    self._activity.clear()
                    if self._callback_requested.is_set():
                        try:
                            with self.engine.thread_callback_execution(self):
                                if self._callback_kind == "retry":
                                    self.engine.bind_retry_controller().callback3()
                                elif self._callback_kind == "tail":
                                    self.worker._publish_outer_control_tail()
                                elif self._callback_kind == "getter_native_fatal_5b1b0":
                                    self.engine.publish_native_fatal(worker=self.worker)
                                elif (
                                    self._callback_kind == "getter_control_fatal_5b0e0"
                                ):
                                    self.engine.publish_control_fatal(
                                        worker=self.worker
                                    )
                                elif self._callback_kind in (
                                    "getter_decision_5a835",
                                    "getter_success_3d120",
                                ):
                                    self._dispatch_getter_decision_outer2026(
                                        self._callback_context
                                    )
                                elif self._callback_kind == "next_cpu":
                                    self.worker.notify_next_cpu()
                                elif self._callback_kind == "logical_cpu":
                                    assert self._callback_argument is not None
                                    self.worker.notify_logical_cpu_boundary(
                                        self._callback_argument
                                    )
                                elif self._callback_kind == "control_progress_count":
                                    self.worker.publish_control_count2026(
                                        self._callback_context
                                    )
                                elif self._callback_kind == "control_progress_percent":
                                    self.worker.publish_control_percent2026(
                                        self._callback_context
                                    )
                                elif self._callback_kind == "control_getter_return":
                                    self.worker.import_control_getter_return2026(
                                        self._callback_context
                                    )
                                else:
                                    raise ValueError("Unknown native outer callback")
                        except BaseException as error:  # noqa: BLE001 - restore exact outer callback failure to child
                            self._callback_error = error
                        finally:
                            self._callback_kind = None
                            self._callback_argument = None
                            self._callback_context = None
                            self._callback_requested.clear()
                            self._callback_returned.set()
                if self._prepare_pending.is_set():
                    self.wait_prepare_acknowledgement()
                # 3cb90 deletes1c58 after4b900 has unwound, before waiting be54.
                retirement = None
                signaled = False
                if record.getter_native:
                    retirement_marker = self._begin_native_retirement_3cb90_2026()
                    try:
                        self.engine.bind_cleanup_controller().release_retired_selected(
                            self.worker
                        )
                    except BaseException:
                        with self._lock:
                            if self._getter_retirement_pending2026 is retirement_marker:
                                self._getter_retirement_pending2026 = None
                        raise
                    retirement = self._issue_native_retirement_3cb90_2026(
                        retirement_marker
                    )
                    signaled = self.engine._probe_native_be54_3cb90_2026(retirement)
                    self._record_native_retirement_probe2026(retirement, signaled)
                else:
                    self.engine.bind_cleanup_controller().release_retired_selected(
                        self.worker
                    )
                with self._lock:
                    record.continuation = self.worker.take_continuation()
                    self._continuation = record.continuation
                    self._lease = self._session = None
                    self._completed.set()
                    record.completed.set()
                if retirement is not None:
                    if not signaled:
                        # The old result is now complete. `_resume` is only a host
                        # wake; the source-owned BE54 byte is reread after it wakes.
                        self._resume.wait()
                        self._resume.clear()
                        signaled = self._observe_native_retirement_wake2026(retirement)
                    if signaled:
                        self.engine._reset_native_be54_3cb90_2026(retirement)
                        with self._lock:
                            if self._getter_retirement_stage2026 != "probed_true":
                                raise ValueError(
                                    "Native BE54 reset lost its observed signal"
                                )
                            self._getter_retirement_stage2026 = "reset"
                    self._finish_native_retirement2026(retirement)
                with self._lock:
                    queued_request = _queued_vbf_request(self)
                    if self._stop:
                        if queued_request is not None:
                            _discard_unbound_queued_vbf(self, queued_request)
                        break
                    if self._sequence > record.sequence:
                        # A fresh authenticated root was published while the old
                        # outer was at the real manual-event wait. That wait
                        # consumed this exact host wake; dispatch the already
                        # reserved record directly instead of waiting for a
                        # second SetEvent that the source never performs.
                        if (
                            self._lease is None
                            or self._active_record is None
                            or self._active_record.sequence != self._sequence
                        ):
                            raise ValueError(
                                "Advanced sequence lost its reserved native work"
                            )
                        dispatch_admitted_work = True
                        continue
                    self._waiting = queued_request is None
                    if (
                        queued_request is None
                        and self._lease is None
                        and self.engine._retry_controller is not None
                    ):
                        self.engine._retry_controller.worker_stopped()
                    if queued_request is not None:
                        _promote_queued_vbf(self, queued_request)
                    elif self._getter_continuation2026 is not None:
                        self._promote_getter_continuation_2026()
            self._outer_exit = 0
        except BaseException as error:  # noqa: BLE001 - preserve thread failure for its joining owner
            with self._lock:
                if self._error is None:
                    self._error = error
                elif self._error is not error:
                    self._error.add_note(
                        "Native outer cleanup failure: " + type(error).__name__
                    )
                if record is not None and not record.completed.is_set():
                    record.error = self._error
                self._outer_exit = 1
                self._completed.set()
                if record is not None:
                    record.completed.set()
        finally:
            with self._lock:
                # A failed outer callback must release its actual waiting child
                # before join. Keep the original error object as the child's ACK.
                if (
                    self._callback_requested.is_set()
                    and not self._callback_returned.is_set()
                ):
                    if self._callback_error is None:
                        self._callback_error = self._error
                    self._callback_requested.clear()
                    self._callback_returned.set()
                    self._activity.set()
                self._stop = True
                queued_request = _queued_vbf_request(self)
                if queued_request is not None:
                    _discard_unbound_queued_vbf(self, queued_request)
                self._child_resume.set()
                child = self._child
            if child is not None:
                child.join()
            self._waiting = False

    def result(self, timeout: float = 5.0, *, sequence: int | None = None) -> dict:
        deadline = _timeout_deadline(timeout)
        self._reject_self_join()
        with self._lock:
            if sequence is None and not self._sequence:
                raise ValueError("Native thread job has not been started")
            selected = self._sequence if sequence is None else sequence
            if sequence is not None and (type(sequence) is not int or sequence <= 0):
                raise ValueError("Already-issued positive native sequence required")
            record = self._completion_records.get(selected)
            if record is None:
                raise ValueError("Native thread sequence has not been issued")
        if not record.completed.wait(max(0, deadline - time.monotonic())):
            raise TimeoutError("Native child wait exceeded host deadline")
        if record.error is not None:
            raise record.error
        assert record.result is not None
        return record.result

    @property
    def is_child_thread(self) -> bool:
        return threading.current_thread() is self._child

    @property
    def is_native_thread(self) -> bool:
        return threading.current_thread() in (self._child, self._outer)

    def dispatch_next_cpu(self) -> None:
        """581a0's actual success callback runs on the outer native owner."""
        self._dispatch_outer_callback("next_cpu")

    def dispatch_logical_cpu_boundary(self, index: int) -> None:
        """P6's source-issued logical boundary retains its concrete CPU index."""
        if type(index) is not int:
            raise TypeError("Actual native logical CPU index required")
        self._dispatch_outer_callback("logical_cpu", index)

    def dispatch_retry_callback(self) -> None:
        """58240 publishes the concrete retry callback to be74 and waits be6c."""
        recovering = self.worker.control_state.recovery_mode
        self._dispatch_outer_callback("retry")
        if recovering and not self.worker.control_state.recovery_mode:
            # 3cb90 re-signals this worker after 3ffa0 consumes persisted recovery.
            self._dispatch_outer_callback("retry")

    def dispatch_worker_tail(self) -> None:
        """5b1b0 publishes the source-issued native fatal input on the outer thread."""
        self._dispatch_outer_callback("tail")

    def dispatch_getter_decision2026(self, decision) -> None:
        """Handoff the immutable late-BE8 route to its one actual outer consumer."""
        if threading.current_thread() is not self._child:
            raise ValueError("Getter decision dispatch belongs to the actual child")
        if type(decision) is not _NativeGetterDecision2026:
            raise TypeError("Exact native getter decision required")
        if self._getter_callback_decision2026 is not decision:
            raise ValueError("Current source-issued getter decision required")
        if decision.route == "success_3d120":
            self._validate_getter_decision_2026(decision, route="success_3d120")
        elif decision.route == "failure_30340":
            self._validate_getter_decision_2026(decision, route="failure_30340")
        elif decision.route == "stop_3dde0":
            self._validate_getter_decision_2026(decision, route="stop_3dde0")
        elif decision.route != "suppressed":
            raise ValueError("Unknown native getter decision route")
        callback_kind = (
            "getter_success_3d120"
            if decision.route == "success_3d120"
            else "getter_decision_5a835"
        )
        self._dispatch_outer_callback(callback_kind, context=decision)
        with self._lock:
            if self._getter_callback_decision2026 is not decision:
                raise ValueError("Getter decision retired during its child handoff")
            self._getter_decision_dispatched_sequence2026 = decision.decision_sequence

    def _dispatch_getter_decision_outer2026(self, decision) -> None:
        if type(decision) is not _NativeGetterDecision2026:
            raise TypeError("Exact native getter decision required")
        with self._lock:
            if (
                self._callback_context is not decision
                or self._callback_kind
                != (
                    "getter_success_3d120"
                    if decision.route == "success_3d120"
                    else "getter_decision_5a835"
                )
                or not self._callback_requested.is_set()
                or self._getter_decision_dispatched_sequence2026
                >= decision.decision_sequence
                or self._getter_decision_dispatching2026 is not None
            ):
                raise ValueError("Getter decision callback is stale or replayed")
            self._getter_decision_dispatching2026 = decision
        try:
            if decision.route == "success_3d120":
                self._validate_getter_success_handoff2026(decision)
                continuation = self.worker._complete_getter_3d120_2026(decision)
                origin = self._pending_getter_next_entry_3d120_2026
                if continuation is not None:
                    self._queue_getter_continuation_2026(continuation)
                elif origin is None:
                    raise ValueError("Completed terminal getter lacks its one G origin")
            elif decision.route == "stop_3dde0":
                self._validate_getter_decision_2026(decision, route="stop_3dde0")
                self.engine._set_receiving_prompt_3dde0_2026(decision)
            elif decision.route in ("failure_30340", "suppressed"):
                if decision.route == "failure_30340":
                    self._validate_getter_decision_2026(decision, route="failure_30340")
            else:
                raise ValueError("Unknown native getter decision route")
        finally:
            active_error = sys.exception()
            try:
                with self._lock:
                    origin = self._pending_getter_next_entry_3d120_2026
                if origin is not None and origin.decision is decision:
                    self._retire_getter_3d120_origin2026(decision, origin)
            except BaseException as retirement_error:
                if active_error is None:
                    raise
                active_error.add_note(
                    "Getter G-origin retirement failed: "
                    + type(retirement_error).__name__
                )
            finally:
                with self._lock:
                    self._getter_decision_dispatching2026 = None
                    self._getter_decision_dispatched_sequence2026 = (
                        decision.decision_sequence
                    )

    def dispatch_getter_callback_stage2026(self, candidate, kind: str) -> None:
        """Run one getter fatal-copy callback and wait for its actual outer ACK."""
        if threading.current_thread() is not self._child:
            raise ValueError("Getter fatal-copy handoff belongs to the actual child")
        if (
            type(candidate) is not _NativeGetterCallbackCandidate2026
            or self._getter_callback_candidate2026 is not candidate
            or candidate.job is not self
            or candidate.worker is not self.worker
            or candidate.lease is not self._lease
            or candidate.sequence != self._sequence
        ):
            raise ValueError("Exact current getter candidate required")
        if kind == "getter_native_fatal_5b1b0":
            if self._getter_native_fatal_ack2026 is not None:
                raise ValueError("Native getter fatal output was already acknowledged")
        elif kind == "getter_control_fatal_5b0e0":
            if (
                self._getter_native_fatal_ack2026 is not candidate
                or self._getter_control_fatal_ack2026 is not None
            ):
                raise ValueError(
                    "Native getter fatal output must precede control output"
                )
        else:
            raise ValueError("Exact getter fatal-copy callback kind required")
        self._dispatch_outer_callback(kind)
        with self._lock:
            if kind == "getter_native_fatal_5b1b0":
                self._getter_native_fatal_ack2026 = candidate
            else:
                self._getter_control_fatal_ack2026 = candidate

    def dispatch_control_progress(self, context, kind: str) -> None:
        """Publish the worker-owned CONTROL vector at its real child callback."""
        from scripts.programming_2026_common import NativeControlContext2026

        if type(kind) is not str or kind not in ("count", "percent"):
            raise ValueError("CONTROL progress kind must be count or percent")
        if threading.current_thread() is not self._child:
            raise ValueError("CONTROL progress belongs to the actual child")
        self.engine._require_owned_phase()
        self.validate_owner(self.engine)
        if (
            type(context) is not NativeControlContext2026
            or self.controller.native_control_context2026(self.engine) is not context
        ):
            raise ValueError("Current issued CONTROL context required")
        self.worker._validate_control_output_context2026(context)
        target = self.engine._controller_export_target2026
        if target is None or target._context is not context:
            raise ValueError("Active CONTROL export target required")
        target.validate(self.engine, self.controller)
        self._dispatch_outer_callback(f"control_progress_{kind}", context=context)

    def dispatch_control_getter_return(self) -> None:
        """Import the actual ordinary getter return after raw Execute returns."""
        from scripts.programming_2026_common import NativeControlContext2026

        if threading.current_thread() is not self._child:
            raise ValueError("CONTROL getter return belongs to the actual child")
        self.engine._require_owned_phase()
        self.validate_owner(self.engine)
        context = self.controller.native_control_context2026(self.engine)
        if (
            type(context) is not NativeControlContext2026
            or context._capture._phase != 0
        ):
            raise ValueError("Ordinary CONTROL getter context required")
        self.worker._validate_control_output_context2026(context)
        self._dispatch_outer_callback("control_getter_return", context=context)

    def _dispatch_outer_callback(
        self, kind: str, argument: int | None = None, *, context=None
    ) -> None:
        if threading.current_thread() is not self._child:
            raise ValueError("Native callback publication belongs to the actual child")
        self.engine._require_owned_phase()
        self.controller.runtime.check()
        self._callback_error = None
        self._callback_kind = kind
        self._callback_argument = argument
        self._callback_context = context
        self._callback_returned.clear()
        self._callback_requested.set()
        self._activity.set()
        # Keep phase ownership with the outer callback until its real acknowledgement.
        # The host's result/stop waits are bounded independently of a stalled provider.
        self._callback_returned.wait()
        if self._callback_error is not None:
            raise self._callback_error

    def validate_callback_handoff(self) -> int:
        if (
            threading.current_thread() is not self._outer
            or not self._callback_requested.is_set()
            or self._child is None
            or not self._child.is_alive()
            or self._child.ident is None
            or self._lease is None
            or self._lease.state != "adopted"
        ):
            raise ValueError("Actual parked native child callback handoff required")
        self.validate_owner(self.engine)
        return self._child.ident

    def request_prepare_acknowledgement(self) -> None:
        """Defer41e60's outer barrier until the inline child callback unwinds."""
        if threading.current_thread() not in (self._child, self._outer):
            raise ValueError("Prepare catch-all belongs to an actual native job thread")
        self.engine._require_owned_phase()
        self._prepare_pending.set()

    def request_external_prepare_acknowledgement(self, retry) -> None:
        """External5e950/5d830 native catch waits for the actual child+1c."""
        self.validate_owner(self.engine)
        self.engine._validate_retry_controller(retry)
        if threading.current_thread() in (self._child, self._outer):
            raise ValueError("External native acknowledgement caller required")
        if self.worker.native_prepare_handshake != 2 or not self.native_worker_exists:
            raise ValueError("Actual pending native prepare acknowledgement required")
        self._prepare_pending.set()
        self._wait_child_parked()

    def wait_prepare_acknowledgement(self) -> None:
        """41e60 polls the real child+1c every500ms; hosts cannot set this flag."""
        if threading.current_thread() is not self._outer:
            raise ValueError(
                "Prepare acknowledgement barrier belongs to native outer thread"
            )
        self._wait_child_parked()

    def _wait_child_parked(self) -> None:
        deadline = time.monotonic() + min(
            self.controller.runtime.check(), self.controller.runtime.cleanup_timeout
        )
        try:
            while not self._child_parked.wait(
                min(0.5, max(0, deadline - time.monotonic()))
            ):
                self.controller.runtime.check()
                if time.monotonic() >= deadline:
                    raise TimeoutError(
                        "Native prepare acknowledgement exceeded host deadline"
                    )
        finally:
            self._prepare_pending.clear()

    def _reject_self_join(self) -> None:
        if threading.current_thread() in (self._child, self._outer):
            raise ValueError("Native thread cannot join itself")

    @property
    def native_work_pending(self) -> bool:
        """Actual reserved work through the outer's late CFE2 clear boundary."""
        return self._lease is not None

    @property
    def native_worker_exists(self) -> bool:
        outer = self._outer
        return outer is not None

    @property
    def host_stop_requested(self) -> bool:
        return self._host_stop

    def stop(self, timeout: float = 5.0) -> None:
        """Host interruption, actual native-loop exit, then bounded external join."""
        self._stop_and_join(timeout, host_interruption=True)

    def stop_native(self, timeout: float = 5.0) -> None:
        """Join only after an actual engine native-stop producer set callback12."""
        if not self.engine.native_cancelled():
            raise ValueError("Actual engine native cancellation must precede its join")
        self._stop_and_join(timeout, host_interruption=False)
        with self._lock:
            self._outer = self._child = None

    def _stop_and_join(self, timeout: float, *, host_interruption: bool) -> None:
        deadline = _timeout_deadline(timeout)
        self._reject_self_join()
        if not self._lock.acquire(timeout=max(0, deadline - time.monotonic())):
            raise TimeoutError("Native stop ownership wait exceeded host deadline")
        try:
            self._stop = True
            self._host_stop = self._host_stop or host_interruption
            self._child_resume.set()
            self._resume.set()
            outer = self._outer
        finally:
            self._lock.release()
        if outer is not None:
            outer.join(max(0, deadline - time.monotonic()))
            if outer.is_alive():
                raise TimeoutError("Native outer thread join exceeded host deadline")
        self._resume.clear()
        self._child_resume.clear()
        self._child_done.clear()
        self._child_parked.clear()
        self._prepare_pending.clear()


def _issue_engine_thread_job(engine, controller) -> EngineThreadJob2026:
    from scripts.cuw_2026 import CUWEngine2026
    from scripts.programming_2026_common import ControlCommPhase2026

    if (
        type(engine) is not CUWEngine2026
        or type(controller) is not ControlCommPhase2026
    ):
        raise TypeError("Concrete engine and controller required")
    if engine.worker.controller is not controller:
        raise ValueError("Actual issued worker controller required")
    existing = getattr(engine, "_thread_job", None)
    if existing is not None:
        if type(existing) is not EngineThreadJob2026:
            raise ValueError("Engine has a foreign native thread job")
        existing.validate_owner(engine, controller)
        return existing
    return EngineThreadJob2026(engine, controller, _token=_TOKEN)
