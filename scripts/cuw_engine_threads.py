"""Concrete CUW2026 outer/child threads and source-owned event lifetime.

The outer thread corresponds to the engine's 3d100/3cb90 loop; each child runs
5ccd0's concrete controller entry. No callable supplied by a host can replace
programming work or publish its result.
"""

from __future__ import annotations

import math
import threading
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scripts.cuw_2026 import CUWEngine2026
    from scripts.cuw_engine_worker import WorkerContinuation2026
    from scripts.programming_2026_common import ControlCommPhase2026
    from scripts.programming_replay import ProgrammingReplay

_TOKEN = object()
_ISSUED: dict[int, ThreadPhaseLease2026] = {}
_LOCK = threading.RLock()
_VBF_REQUESTS: dict[int, tuple[VbfProcessBeforeRequest2026, _VbfRequestRecord2026]] = {}
_VBF_LOCK = threading.RLock()


@dataclass
class _VbfRequestRecord2026:
    fields: dict
    issuer: int
    previous_record: _CompletionRecord2026 | None
    source_descriptor: tuple
    handshake_at_issue: int
    root: ProgrammingReplay | None = None
    lease: ThreadPhaseLease2026 | None = None


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


def _validate_vbf_source(job, record, *, freeze=False):
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
    if freeze:
        if record is None:
            raise ValueError("VBF request record required to freeze source view")
        record.fields.update(view)
    elif (
        record is not None
        and record.fields["container"] is not None
        and (
            metadata.source_container is not record.fields["container"]
            or metadata.source_sha256 != record.fields["source_sha256"]
            or metadata.node != record.fields["node"]
            or job.engine.dh_state.selection_cpu_index != record.fields["cpu_index"]
            or sources is not record.fields["file_sources"]
        )
    ):
        raise ValueError("VBF prepared FILE changed after its authenticated view")
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
            _validate_vbf_source(self, record, freeze=True)
            record.fields["state"] = "parked"

    def _record_vbf_prepared2026(self, request, *, started_ms: int):
        if type(started_ms) is not int or not 0 <= started_ms < 86_400_000:
            raise ValueError("Native local milliseconds within day required")
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
        _validate_vbf_source(self, record, freeze=True)
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
            ):
                with self.engine.prepare_reentry_execution(self):
                    if self.worker.prepare_reentry_handshake():
                        return None
            if self._lease is not None or (
                self._sequence and not self._completed.is_set()
            ):
                raise ValueError("Native child is already scheduled")
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
                    if self._stop and (lease is None or lease.state != "reserved"):
                        break
                    if lease is None:
                        raise ValueError("Native child resume has no reserved work")
                    assert record is not None
                    assert session is not None
                    self._child_parked.clear()
                try:
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
                                            self.dispatch_control_getter_return()
                            self.dispatch_worker_tail()
                        with self._lock:
                            self._result = result
                            record.result = result
                except BaseException as error:  # noqa: BLE001 - preserve child faults for the joining host
                    with self._lock:
                        self._error = error
                        record.error = error
                finally:
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
        try:
            while True:
                record = None
                self._resume.wait()
                self._resume.clear()
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
                    needs_start = child is None
                    if child is None:
                        child = threading.Thread(
                            target=self._run_child, name="CUW2026-5ccd0", daemon=True
                        )
                        self._child = child
                if needs_start:
                    try:
                        child.start()
                    except BaseException:
                        with self._lock:
                            self._child = None
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
                self.engine.bind_cleanup_controller().release_retired_selected(
                    self.worker
                )
                with self._lock:
                    record.continuation = self.worker.take_continuation()
                    self._continuation = record.continuation
                    self._lease = self._session = None
                    self._completed.set()
                    record.completed.set()
                    queued_request = _queued_vbf_request(self)
                    self._waiting = queued_request is None
                    if (
                        queued_request is None
                        and self.engine._retry_controller is not None
                    ):
                        self.engine._retry_controller.worker_stopped()
                    if self._stop:
                        if queued_request is not None:
                            _discard_unbound_queued_vbf(self, queued_request)
                        break
                    if queued_request is not None:
                        _promote_queued_vbf(self, queued_request)
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
        self._dispatch_outer_callback("retry")

    def dispatch_worker_tail(self) -> None:
        """5b1b0 publishes the source-issued native fatal input on the outer thread."""
        self._dispatch_outer_callback("tail")

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
