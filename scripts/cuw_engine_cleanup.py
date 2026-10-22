"""CUW2026 whole-engine resource disposal, separately from phase completion.

Resources are owned objects; the primitive provider never decides whether a
stage succeeded.  Faults leave the already performed native mutations visible.
"""

from __future__ import annotations

import threading
import weakref
from contextlib import nullcontext
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scripts.calibration_2026 import Native2026Metadata
    from scripts.cuw_2026 import CUWEngine2026
    from scripts.cuw_engine_worker import EngineWorker2026

_TOKEN = object()
_ISSUED: weakref.WeakKeyDictionary = weakref.WeakKeyDictionary()
_LOCK = threading.Lock()


@dataclass
class CleanupResource2026:
    """An actual decoded target owner, with native pointer identity semantics."""

    metadata: Native2026Metadata | None
    deleted: bool = False

    def delete(self) -> None:
        if self.deleted:
            raise ValueError("Native target pointer was deleted more than once")
        self.metadata = None
        self.deleted = True


@dataclass
class CleanupCollectionRecord2026:
    """67a00's borrowed target plus 678b0's retained record containers."""

    resource: CleanupResource2026 | None = None
    strings80: list[bytes] = field(default_factory=list)
    words04: list[int] = field(default_factory=list)
    strings14: list[bytes] = field(default_factory=list)
    strings3c: list[bytes] = field(default_factory=list)
    word60: int = 0
    text64: bytes = b""
    worda4: int = 0
    worda8: int = 0

    def clear(self) -> None:
        self.strings80.clear()
        self.worda4 = self.worda8 = 0
        self.resource = None
        self.words04.clear()
        self.strings14.clear()
        self.strings3c.clear()
        self.word60 = 0
        self.text64 = b""


@dataclass
class CleanupStatistics2026:
    """One of sixteen d9e4 records, with CPU and CPU*32 sized vectors."""

    strings: list[list[bytes]] = field(default_factory=lambda: [[] for _ in range(5)])
    flagsfc: list[bool] = field(default_factory=list)
    wordsc8: list[int] = field(default_factory=list)
    words10c: list[int] = field(default_factory=list)
    text118: bytes = b""
    text130: bytes = b""

    def reset(self, maximum: int) -> None:
        for values in self.strings[:4]:
            values[:] = [b""] * maximum
        self.flagsfc[:] = [False] * maximum
        self.wordsc8[:] = [0] * (maximum * 32)
        self.strings[4][:] = [b""] * (maximum * 32)
        self.words10c[:] = [0] * maximum
        self.text118 = self.text130 = b""


@dataclass
class EngineCleanupState2026:
    """Owned globals, retaining containers rather than replacing their owners."""

    maximum: int
    targets: list[CleanupResource2026 | None]
    names: list[bytes]
    selected: CleanupResource2026 | None
    retired_selected: CleanupResource2026 | None = None
    auxiliary: CleanupCollectionRecord2026 = field(
        default_factory=CleanupCollectionRecord2026
    )
    collection: list[CleanupCollectionRecord2026] = field(default_factory=list)
    collection_index: dict[int, int] = field(default_factory=dict)
    collection_flag: bool = False
    statistics: list[CleanupStatistics2026] = field(default_factory=list)
    slot_cpu_indices: list[list[int]] = field(
        default_factory=lambda: [[] for _ in range(16)]
    )
    # Source addresses identify otherwise anonymous retained native containers.
    scalars: dict[int, int] = field(default_factory=dict)
    strings: dict[int, bytes] = field(default_factory=dict)
    vectors: dict[int, list] = field(default_factory=dict)
    history: bytearray = field(default_factory=lambda: bytearray(0x1028))
    buffers: list[bytearray | None] = field(default_factory=lambda: [None, None])
    completed: bool = False
    trace: list[str] = field(default_factory=list)


def _issue_engine_cleanup(engine, worker):
    from scripts.cuw_2026 import CUWEngine2026
    from scripts.cuw_engine_worker import EngineWorker2026

    if type(engine) is not CUWEngine2026 or type(worker) is not EngineWorker2026:
        raise TypeError("Actual CUW engine and its issued worker required")
    if engine.worker is not worker or worker.engine is not engine:
        raise ValueError("Cleanup worker belongs to another engine")
    with _LOCK:
        previous = _ISSUED.get(engine)
        if previous is not None and previous() is not None:
            cleanup = previous()
            if cleanup.worker is not worker:
                raise ValueError("Cleanup lease belongs to another worker")
            return cleanup
        cleanup = EngineCleanup2026(engine, worker, _token=_TOKEN)
        _ISSUED[engine] = weakref.ref(cleanup)
        return cleanup


def _revoke_engine_cleanup(engine) -> None:
    """The engine closes its ordinary lifetime before issuing a fresh FILE owner."""
    with _LOCK:
        reference = _ISSUED.pop(engine, None)
        cleanup = reference() if reference is not None else None
        if cleanup is not None:
            cleanup._revoked = True


class EngineCleanup2026:
    """40580 chronology for the actual engine-issued resource aggregate."""

    def __init__(self, engine: CUWEngine2026, worker: EngineWorker2026, *, _token=None):
        if _token is not _TOKEN:
            raise TypeError("Cleanup must be issued by its actual engine")
        self.engine, self.worker = engine, worker
        configuration = engine.configuration
        if configuration is None:
            raise ValueError("Configured native engine required")
        maximum = configuration.cpu_maximum
        sources = engine.file_sources
        metadata = sources.files if sources is not None else worker.loaded_metadata
        if len(metadata) > 16:
            raise ValueError("Native engine target table has sixteen slots")
        resources = [CleanupResource2026(item) for item in metadata]
        self._file_resources = {
            id(item): resource
            for item, resource in zip(metadata, resources, strict=True)
        }
        collection = []
        if sources is not None:
            for group, (_start, count, whole) in enumerate(sources.delta_groups):
                resource = self._file_resources.get(id(whole))
                if resource is None:
                    resource = CleanupResource2026(whole)
                    self._file_resources[id(whole)] = resource
                collection.append(
                    CleanupCollectionRecord2026(
                        resource,
                        text64=sources.delta_group_names[group].encode("latin1"),
                        worda4=count,
                        worda8=group,
                    )
                )
        selected = next(
            (
                resource
                for resource in (
                    *resources,
                    *(record.resource for record in collection),
                )
                if resource is not None
                and resource.metadata is not None
                and resource.metadata.source_container
                is engine.native_metadata.source_container
            ),
            None,
        )
        if selected is None:
            raise ValueError("Selected target is absent from the owned native table")
        self.state = EngineCleanupState2026(
            maximum,
            resources + [None] * (16 - len(resources)),
            [item.source_sha256.encode("ascii") for item in metadata]
            + [b""] * (16 - len(resources)),
            selected,
            collection=collection,
            collection_index={
                id(member): group for member, group in sources.delta_map_entries
            }
            if sources is not None
            else {},
            statistics=[CleanupStatistics2026() for _ in range(16)],
        )
        if sources is not None and sources.auxiliary_metadata is not None:
            self.state.auxiliary.resource = self._file_resources[
                id(sources.auxiliary_metadata)
            ]
        self._running = threading.Lock()
        self._revoked = False

    def validate_owner(self, engine, worker) -> None:
        if engine is not self.engine or worker is not self.worker:
            raise ValueError("Cleanup is not the actual issued engine owner")
        with _LOCK:
            reference = _ISSUED.get(engine)
            if (
                type(self) is not EngineCleanup2026
                or self._revoked
                or reference is None
                or reference() is not self
                or engine is not self.engine
                or worker is not self.worker
                or engine._worker is not worker
            ):
                raise ValueError("Cleanup is not the actual issued engine owner")

    def rebind_worker(self, old, new) -> None:
        """59070 replaces the stopped worker without replacing engine globals."""
        from scripts.cuw_engine_worker import EngineWorker2026

        if type(old) is not EngineWorker2026 or type(new) is not EngineWorker2026:
            raise TypeError("Actual previous and replacement engine workers required")
        if not self._running.acquire(blocking=False):
            raise ValueError("Finish native cleanup before replacing its worker")
        try:
            with _LOCK:
                reference = _ISSUED.get(self.engine)
                if (
                    self._revoked
                    or reference is None
                    or reference() is not self
                    or self.worker is not old
                    or old.engine is not self.engine
                    or new.engine is not self.engine
                    or new is not self.engine._worker
                    or old.controller is not new.controller
                    or getattr(new.controller, "worker", None) is not new
                    or not old._closed
                    or new._closed
                    or self.engine.active
                    or self.state.completed
                    or self.state.retired_selected is not None
                ):
                    raise ValueError(
                        "Actual stopped-worker replacement transaction required"
                    )
                job = self.engine.thread_job
                if job is not None:
                    stopped = job.state
                    if (
                        job.engine is not self.engine
                        or (
                            job.worker is not old
                            and not (
                                job.worker is new
                                and self.engine._worker_replacement_thread
                                == threading.get_ident()
                            )
                        )
                        or not stopped.stop_requested
                        or job.native_worker_exists
                        or stopped.child_alive
                    ):
                        raise ValueError(
                            "Join the previous native thread job before reissue"
                        )
                owners = (
                    *self.state.targets,
                    self.state.selected,
                    self.state.auxiliary.resource,
                    *(record.resource for record in self.state.collection),
                )
                if any(
                    not any(
                        resource is not None
                        and not resource.deleted
                        and resource.metadata is not None
                        and resource.metadata.source_container
                        is metadata.source_container
                        for resource in owners
                    )
                    for metadata in new.loaded_metadata
                ):
                    raise ValueError(
                        "Replacement worker has a foreign native FILE owner"
                    )
                new.validate_source(self.engine)
                self.worker = new
        finally:
            self._running.release()

    def target_selected(self, metadata) -> None:
        """Keep the existing FILE owner when node/CPU metadata is reissued."""
        self.validate_owner(self.engine, self.worker)
        if metadata is not self.engine.native_metadata:
            raise ValueError("Selection must be the actual current engine metadata")
        selected = next(
            (
                resource
                for resource in (self.state.selected, *self.state.targets)
                if resource is not None
                and resource.metadata is not None
                and resource.metadata.source_container is metadata.source_container
            ),
            None,
        )
        if selected is None:
            raise ValueError("Selection is absent from actual owned FILE resources")
        self.state.selected = selected

    def accept_file_reset(self, old, new) -> None:
        """Consume141's sealed4b900 replacement without losing the1c58 owner."""
        from scripts.cuw_file_services import validate_file_reset_2026

        self.validate_owner(self.engine, self.worker)
        validate_file_reset_2026(old, new, self.worker)
        if self.engine.file_sources is not new:
            raise ValueError("Native FILE reset is not the actual engine selection")
        state = self.state
        # Runtime CPU projections reissue metadata while retaining the native FILE.
        # The sealed141 lineage authorizes the projection; pointer identity owns it.
        admitted = (*new.files, new.selected_metadata)
        resolved = {}
        for metadata in admitted:
            matches = {
                id(resource): resource
                for resource in self._file_resources.values()
                if not resource.deleted
                and resource.metadata is not None
                and resource.metadata.source_container is metadata.source_container
            }
            if len(matches) != 1:
                raise ValueError("Native FILE reset has no unique existing FILE owner")
            resolved[id(metadata)] = next(iter(matches.values()))
        retained = {id(resolved[id(item)]) for item in new.files}
        for index, metadata in enumerate(old.files):
            resource = state.targets[index]
            if (
                resource is None
                or self._file_resources.get(id(metadata)) is not resource
            ):
                raise ValueError(
                    "Native FILE table differs from its source-issued owner"
                )
            if id(resource) not in retained:
                if resource is state.selected:
                    if state.retired_selected is not None:
                        raise ValueError(
                            "Previous native1c58 owner has not reached post-wait disposal"
                        )
                    state.retired_selected = resource
                else:
                    self._delete_resource(resource)
                state.targets[index] = None
        self._file_resources.update(resolved)
        resources = [resolved[id(item)] for item in new.files]
        selected = resolved[id(new.selected_metadata)]
        state.targets[:] = resources + [None] * (16 - len(resources))
        state.names[:] = [name.encode("utf-8") for name in new.file_names] + [b""] * (
            16 - len(resources)
        )
        state.selected = selected
        state.auxiliary.resource = selected

    def release_retired_selected(self, worker) -> None:
        """3cb90 deletes1c58 after child exit, before be54 processing."""
        self.validate_owner(self.engine, worker)
        resource = self.state.retired_selected
        if resource is not None:
            self._delete_resource(resource)
            self.state.retired_selected = None

    def _delete_resource(self, resource: CleanupResource2026) -> None:
        if resource.deleted:
            raise ValueError("Native target pointer was deleted more than once")
        if resource.metadata is not None:
            self.engine._delete_cleanup_file_source(self, resource.metadata)
        resource.delete()

    def _targets(self) -> None:
        state = self.state
        # 67a00 compares only the first count(nonempty names) target pointers.
        count = sum(bool(name) for name in state.names)
        for record in state.collection:
            resource = record.resource
            if resource is not None:
                if resource is not state.auxiliary.resource and not any(
                    resource is item for item in state.targets[:count]
                ):
                    self._delete_resource(resource)
                record.resource = None
        for record in state.collection:
            record.clear()
        state.collection_flag = False
        state.collection_index.clear()
        state.trace.append("collection-released")
        for index, resource in enumerate(state.targets):
            if resource is not None and resource is not state.selected:
                self._delete_resource(resource)
            state.targets[index] = None
        resource = state.auxiliary.resource
        if resource is not None and resource is not state.selected:
            self._delete_resource(resource)
        state.auxiliary.resource = None
        state.auxiliary.clear()
        if state.selected is not None:
            self._delete_resource(state.selected)
            self.engine._delete_cleanup_target(self)
            state.selected = None
        state.trace.append("targets-released")

    def _globals(self, retry=None) -> None:
        state = self.state
        state.scalars.update(
            {0xCFB8: 4, 0xCFBC: 0, 0xCFC0: 0, 0xCFC4: 0, 0xCFC8: 0, 0xCFCC: 0}
        )
        for address in (
            0xCFD0,
            0xCFD8,
            0xCFDC,
            0xCFE0,
            0xCFE1,
            0xCFE2,
            0xD268,
            0xD2A0,
            0xD2A1,
            0xD300,
            0xD304,
            0xD308,
            0xD30C,
            0xD310,
            0xD314,
            0xD348,
            0xD349,
            0xD34A,
            0xD34B,
            0xD34C,
        ):
            state.scalars[address] = 0
        self.engine._apply_cleanup_globals(self)
        if retry is not None:
            retry._cleanup_prefix_reset(self)
        persistence = self.engine.persistence
        if persistence is not None:
            persistence.assign_cleanup_notifications(self)
        for address in (0xD370, 0xD49C, 0xD374, 0xD378, 0xD3EC):
            state.scalars[address] = 0
        self.engine._apply_cleanup_late_globals(self)
        state.vectors.setdefault(0xD490, [])[:] = [False] * state.maximum
        for address in (0xD37C, 0xD394, 0xD4C4):
            state.strings[address] = b""
        state.trace.append("global-prefix-reset")

    def _vectors(self) -> None:
        state, maximum = self.state, self.state.maximum
        self.engine._apply_cleanup_vectors(self)
        vectors = state.vectors
        for address in (0xD260, 0xD26C, 0xD294, 0xD2B0, 0xD2D8):
            vectors.setdefault(address, []).clear()
        for address in (0xD318, 0xD324, 0xD330, 0xD33C):
            vectors.setdefault(address, [])[:] = [0] * maximum
        vectors.setdefault(0xD9D8, [])[:] = [[] for _ in range(16)]
        state.statistics[:] = [CleanupStatistics2026() for _ in range(16)]
        vectors.setdefault(0xD2A4, [])[:] = [-1] * maximum
        for address in (0xD3B0, 0xD3D8, 0xD3C4):
            vectors.setdefault(address, [])[:] = [0] * 16
        for address in (0xD3AC, 0xD3BC, 0xD3D4, 0xD3E4, 0xD3C0, 0xD3D0):
            state.scalars[address] = 0
        # 23630 recovery aggregate: sixteen file flags with per-CPU contents.
        vectors.setdefault(0xEC48, [])[:] = [b""] * 16
        vectors.setdefault(0xED44, [])[:] = [[False] * maximum for _ in range(16)]
        persistence = self.engine.persistence
        if persistence is not None:
            from scripts.cuw_persistence import ReproInfoState

            # 23630 resets the aggregate in place; unlike38880, no files are deleted.
            with persistence._lock:
                defaults = ReproInfoState(())
                for name, value in vars(defaults).items():
                    setattr(persistence.state, name, value)
        for address in (0xD4E8, 0xD548, 0xD550, 0xD558, 0xD71C, 0xD9D4):
            state.scalars[address] = 0
        for address in (0xD9AC, 0xD9B8, 0xD9C4):
            vectors.setdefault(address, []).clear()
        vectors.setdefault(0xD4A0, [])[:] = [[False] * maximum for _ in range(16)]
        state.scalars[0xDAC0] = state.scalars[0xDB08] = state.scalars[0xDB18] = 0
        for index in range(16):
            state.names[index] = b""
            vectors.setdefault(0xD724 + index * 0x28, []).clear()
            state.slot_cpu_indices[index][:] = [-1] * maximum
        for statistics in state.statistics:
            statistics.reset(maximum)
        for offset in (0x444, 0x46C, 0x494, 0x4BC):
            vectors.setdefault(0xCFB0 + offset, [])[:] = [b""] * maximum
        vectors.setdefault(0xD504, [])[:] = [0] * (maximum * 32)
        vectors.setdefault(0xD514, [])[:] = [b""] * (maximum * 32)
        vectors.setdefault(0xD538, [])[:] = [False] * maximum
        vectors.setdefault(0xEB4C, [])[:] = [0] * maximum
        state.strings[0xEB58] = state.strings[0xEB70] = b""
        state.scalars[0xD544] = 0
        # EB88 virtual+4 resolves to50850, the USB file-copy state clear.
        state.strings[0xEB90] = state.strings[0xEBB4] = b""
        for address in (
            0xEBA8,
            0xEBAC,
            0xEBB0,
            0xEBCC,
            0xEBD0,
            0xEBD4,
            0xEBD8,
            0xEBDC,
            0xEBE0,
            0xEBE4,
            0xEBE8,
        ):
            state.scalars[address] = 0
        state.trace.append("vectors-reset")

    def run(self, retry=None) -> None:
        from scripts.cuw_retry import RetryController2026

        self.validate_owner(self.engine, self.worker)
        if retry is None:
            retry = self.engine._retry_controller
        if retry is not None and (
            type(retry) is not RetryController2026
            or retry.engine is not self.engine
            or retry.worker is not self.worker
            or self.engine._retry_controller is not retry
        ):
            raise ValueError("Actual engine retry controller required")
        if not self._running.acquire(blocking=False):
            raise ValueError("Native engine cleanup is already running")
        try:
            state = self.state
            if state.completed:
                return
            device = self.engine.engine_runtime_device()
            state.trace.append("disconnect")
            device.disconnect()
            if retry is not None:
                retry._cleanup_signal_wait(self)
            self.engine._cleanup_wait_for_worker(self)
            self.release_retired_selected(self.worker)
            state.trace.append("worker-stopped")
            persistence = self.engine.persistence
            with (
                persistence._cleanup_notification_scope(self)
                if persistence is not None
                else nullcontext()
            ):
                self._targets()
                self._globals(retry)
            state.trace.append("device-clear")
            device.clear()
            self._vectors()
            self.worker._cleanup_reset_after_40580(self)
            if retry is not None:
                retry._cleanup_reset(self)
            for address in (0xBE39, 0xBE38, 0xBE48, 0xBE34, 0xBE44, 0xBE30):
                state.scalars[address] = 0
            state.buffers[0] = state.buffers[1] = None
            for address in (0xDAC4, 0xDAC8, 0xDACC, 0xDAD0, 0xDAD4):
                state.scalars[address] = 0
            for address in (0xDAD8, 0xDAE4, 0xDAF0, 0xDAFC):
                state.vectors.setdefault(address, []).clear()
            state.history[:] = bytes(0x1028)
            state.trace.append("complete")
            state.completed = True
        finally:
            self._running.release()
