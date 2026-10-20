"""Source-bound CUW2026 multi-file/node/CPU worker state.

The worker is issued once by :class:`CUWEngine2026`.  It owns the native fields
that sit between the engine and ControlCommPhase; transport callbacks never
decide that a phase or a programming operation succeeded.
"""

from __future__ import annotations

import math
import threading
import weakref
from contextlib import nullcontext
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Literal

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
from scripts.cuw_persistence import ProgrammingLogInfo, build_programming_log_info
from scripts.programming_2026_common import NativeException2026

if TYPE_CHECKING:
    from scripts.calibration_2026 import NativeCIDMatch2026, NativeCPUSelection2026
    from scripts.cuw_2026 import CUWEngine2026
    from scripts.programming_2026_common import (
        ControlCommPhase2026,
        NativeRuntime2026,
    )


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
        self._cpu_offset = (
            persistence.state.offset_of_write_cpu_multi_cal_index
            if persistence is not None and loaded
            else 0
        )
        self._progress_base = self._cpu_offset + sum(
            max(0, native2026_cpu_count(item) - len(self._identifiers_for_file(index)))
            for index, item in enumerate(
                self._all_loaded_metadata[: self._current_file_index]
            )
        )
        self._retained_cpu_type = ""
        self._prepare_handshake = 0
        self._callback_24_state = 0
        self._callback_28_state = 0
        self._callback_47_state = 0
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
        self._phase_started_ms: int | None = None
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
            self._cid_selected_files = set(previous._cid_selected_files)
            self._current_node = previous._current_node
            self._current_cpu_index = previous._current_cpu_index
            self._current_global_cpu_index = previous._current_global_cpu_index
            self._cpu_offset = previous._cpu_offset
            self._progress_base = previous._progress_base
            self._retained_cpu_type = previous._retained_cpu_type
            self._callback_24_state = previous._callback_24_state
            self._callback_28_state = previous._callback_28_state
            self._callback_47_state = previous._callback_47_state
            self._battery_voltage = previous._battery_voltage
            self._complete = previous._complete
            self._ig_off_pending = self._engine.native_cycle_output
            self._recovery_ec9b = previous._recovery_ec9b
            self._recovery_ec9c = previous._recovery_ec9c
            self._phase_elapsed_ms = list(previous._phase_elapsed_ms)
            self._delta_archive_active = self._engine.native_delta_active
            self._delta_archive_clone_match = previous._delta_archive_clone_match
            self._gateway_startup = previous._gateway_startup

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

    def _initialize_36800_prefix(self, milliseconds: int) -> None:
        """Run the clock/output prefix that precedes36800's be8 early return."""
        if type(milliseconds) is not int or not 0 <= milliseconds < 86_400_000:
            raise ValueError("Native local milliseconds within day required")
        self._engine._require_native_prepare_prefix(self)
        if not self._retained_cpu_type:
            metadata = self._engine.native_metadata
            self._retained_cpu_type = native2026_cpu_values(metadata, 0).get(
                "cputype", ""
            )
        self._engine._initialize_native_prepare_outputs(worker=self)
        retry = getattr(self._engine, "_retry_controller", None)
        if retry is not None:
            retry._initialize_prepare_state(self, milliseconds)

    def _initialize_36800(self, milliseconds: int) -> None:
        """Run36800 prefix and its later source-gated3e710 continuation."""
        self._initialize_36800_prefix(milliseconds)
        self._apply_pending_cid_match_3e710()
        self._reapply_retained_selection_3e710()

    def _apply_pending_cid_match_3e710(self) -> None:
        """Apply the exact34e10 match only at36800's source-gated3e710 site."""
        from scripts.calibration_2026 import (
            NativeCIDMatch2026,
            native2026_cid_rebuild_allowed,
        )

        index = self._current_file_index
        current_global_cpu_index = self._current_global_cpu_index
        rebuild_allowed = native2026_cid_rebuild_allowed(self._engine.native_metadata)
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
                self._callback_24_state,
                self._callback_28_state,
                self._callback_47_state,
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
                self._engine.repro_gateway_node == 1,
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

    def _reapply_retained_selection_3e710(self) -> None:
        """36800 reapplies the exact cached3e710 result after47e60 restoration."""
        from scripts.calibration_2026 import (
            NativeCPUSelection2026,
            native2026_cid_rebuild_allowed,
        )

        selection = self._selection_rebuild_pending
        if selection is None:
            return
        if type(selection) is not NativeCPUSelection2026:
            raise TypeError("Actual typed34e10 FILE selection required")
        metadata = self._engine.native_metadata
        if metadata is not selection.rebuilt_metadata:
            raise ValueError("36800 current FILE differs from cached FILE projection")
        index = self._current_file_index
        current_global_cpu_index = self._current_global_cpu_index
        if native2026_cid_rebuild_allowed(metadata):
            self._cpu_offset = selection.cpu_offset
        if current_global_cpu_index == 0 and self._cpu_offset != 0:
            self._engine._select_worker_rebuilt_cpu(self._cpu_offset, worker=self)
            current_global_cpu_index = self._cpu_offset
            metadata = self._engine.native_metadata
            selection = replace(selection, rebuilt_metadata=metadata)
            selections = list(self._selections_by_file)
            selections[index] = selection
            self._selections_by_file = tuple(selections)
            if self._delta_archive_active and self._delta_archive_clone_match:
                self._retained_clone_selection = selection
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

    def _file_reset_selected(self, sources) -> None:
        """Install141's exact4b900 FILE-table replacement during engine commit."""
        from scripts.cuw_file_services import (
            FileSourceSet2026,
            validate_file_sources_2026,
        )

        if type(sources) is not FileSourceSet2026:
            raise TypeError("Actual source-issued FILE reset required")
        self._engine._require_owned_phase()
        validate_file_sources_2026(sources, self._engine)
        with self._lock:
            if self._file_sources is None:
                raise ValueError("Worker has no native delta FILE source set")
            current = self._engine.native_metadata
            execution = _loaded_metadata(self._engine)
            matches = [
                index
                for index, item in enumerate(execution)
                if item.source_container is current.source_container
            ]
            if len(matches) != 1:
                raise ValueError("Reset FILE vector must contain the selected source")
            self._file_sources = sources
            self._all_loaded_metadata = execution
            self._online_loaded_metadata = sources.files
            self._current_file_index = matches[0]
            self._current_node = current.node
            self._current_cpu_index = current.cpu_index
            self._targets_by_file, self._cpu_orders_by_file = (
                self._build_selection_vectors()
            )
            self._authored_cpu_orders_by_file = self._cpu_orders_by_file
            self._unmatched_identifiers_by_file = tuple(() for _ in execution)
            self._unmatched_companions_by_file = tuple(() for _ in execution)
            self._authored_cpu_counts_by_file = (0,) * len(execution)
            self._authored_target_indices_by_file = tuple(
                (-1,) * native2026_cpu_count(metadata) for metadata in execution
            )
            self._selections_by_file = (None,) * len(execution)
            self._cid_matches_by_file = (None,) * len(execution)
            self._cid_selected_files.clear()
            actual_cpu_index = native2026_global_cpu_index(current)
            self._current_global_cpu_index = self._cpu_orders_by_file[
                self._current_file_index
            ].index(actual_cpu_index)
            self._cpu_offset = 0
            self._progress_base = sum(
                max(
                    0,
                    native2026_cpu_count(item) - len(self._identifiers_for_file(index)),
                )
                for index, item in enumerate(
                    self._all_loaded_metadata[: self._current_file_index]
                )
            )
            self._phase_elapsed_ms[:] = [0] * len(self._phase_elapsed_ms)
            self._delta_archive_active = self._engine.native_delta_active
            self._delta_archive_clone_match = sources.current_is_retained_clone

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
        with self._lock:
            self._retained_cpu_type = ""
            self._prepare_handshake = 0
            self._callback_24_state = 0
            self._callback_28_state = 0
            self._callback_47_state = 0
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
            if match is None:
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
        """58ab0 stores callback24's raw gateway-classifier byte."""
        self._engine._require_owned_phase()
        with self._lock:
            self._callback_24_state = self._callback_byte(value)

    def publish_callback_25_gateway_node(self) -> None:
        """58b40 callback25 copies cached DAT8ed0c into typData990/BF9."""
        self._engine._require_owned_phase()
        with self._lock:
            self.validate_source()
            self._engine._publish_cached_gateway_kind(worker=self)

    def record_callback_28(self, value: int) -> None:
        """58ca0 stores callback28's raw byte in DAT1008ed29."""
        self._engine._require_owned_phase()
        with self._lock:
            self._callback_28_state = self._callback_byte(value)

    def record_callback_47(self, value: int) -> None:
        """58f80 stores callback47's raw source-mode byte in DAT1008ed8a."""
        self._engine._require_owned_phase()
        with self._lock:
            self._callback_47_state = self._callback_byte(value)

    def publish_callback_48_source_mode(self) -> None:
        """59000 callback48 copies cached DAT8ed8a into typData9c0/C08."""
        self._engine._require_owned_phase()
        with self._lock:
            self.validate_source()
            self._source_mode = self._callback_47_state

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

    def _phase_started(self, phase: int) -> None:
        if type(phase) is not int or phase not in (0, 1, 2, 3):
            raise ValueError("Native worker phase must be0..3")
        with self._lock:
            if (
                phase == 1
                and self._prepare_handshake == 1
                and not self.control_state.recovery_mode
            ):
                raise ValueError(
                    "Consume the source prepare-reentry handshake before dispatch"
                )
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
            receiving=bool(self._engine.active and phase == 0),
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
        receiving_status = status.receiving_status()[0]
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
