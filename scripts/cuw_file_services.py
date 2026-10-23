"""CUW2026 public file output composition over authenticated native containers.

OEM code is a static identity input only. No device or OEM executable is opened.
"""

from __future__ import annotations

import configparser
import hashlib
import struct
import threading
import weakref
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from pathlib import PureWindowsPath
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Literal, Protocol, cast, runtime_checkable

from scripts.calibration_2026 import (
    Native2026Metadata,
    native2026_cpu_count,
    native2026_cpu_values,
    native2026_date_presentation,
    native2026_file_cpu,
    native2026_file_header,
    native2026_metadata,
    parse_cuw_2026,
)

if TYPE_CHECKING:
    from scripts.calibration_2026 import NativeUSBSource2026
    from scripts.cuw_2026 import CUWEngine2026
    from scripts.cuw_large import LargeSource2026


@dataclass(frozen=True)
class FileReadResult2026:
    status: int
    header: bytes = field(repr=False)
    cpus: tuple[bytes, ...] = field(repr=False)
    delta_archive: bool = False
    multiple_files: bool = False
    source_sha256: tuple[str, ...] = ()


def compliance_2026(files: tuple[Native2026Metadata, ...]) -> int:
    """4a6f0: first GatewayDiagID0751 per node, or other-contact format10/12."""
    from scripts.calibration_2026 import (
        _number,
        native2026_node_count,
        native2026_node_values,
    )

    for metadata in files:
        if metadata.vehicle.get("contacttype", "") == "P5-Unified":
            for node_index in range(native2026_node_count(metadata)):
                node = native2026_node_values(metadata, node_index)
                if (
                    _number(node, "NumberOfGateway", maximum=99) > 0
                    and node.get("01_gatewaydiagid", "") == "0751"
                ):
                    return 1
        elif metadata.format_version in (10, 12):
            return 1
    return 0


def calibration_family_2026(
    metadata: Native2026Metadata, *, file_count: int = 0
) -> bool:
    """4ad60: only the single-source format10/12 family0790/0791/0792."""
    return (
        file_count == 0
        and metadata.format_version in (10, 12)
        and metadata.vehicle.get("canidtx_phys_usdt", "") in ("0790", "0791", "0792")
    )


@dataclass(frozen=True)
class NativeFileLogger2026:
    """65390/1c4a0 actual callback sink with an explicit captured ACP primitive."""

    engine: Any = field(repr=False, compare=False)
    levels: Mapping[int, int] = field(repr=False)
    sink: Callable[[int, int, int, str, str], None] = field(repr=False, compare=False)
    to_wide: Callable[[bytes], str] = field(repr=False, compare=False)

    def emit(self, context: int, identifier: int, value: bytes) -> None:
        validate_file_logger_2026(self, self.engine)
        if any(
            type(item) is not int or not 0 <= item <= 0xFFFFFFFF
            for item in (context, identifier)
        ):
            raise ValueError("Native log context and identifier DWORDs required")
        if type(value) is not bytes or b"\0" in value:
            raise ValueError("Native ACP log byte string required")
        converted = self.to_wide(value)
        if (
            not isinstance(converted, str)
            or "\0" in converted
            or len(converted.encode("utf-16-le")) > 510
        ):
            raise ValueError("Captured native MultiByteToWideChar output required")
        self.sink(
            context, identifier, self.levels.get(identifier, 0), "CUW.dll", converted
        )


_file_loggers: weakref.WeakValueDictionary[int, NativeFileLogger2026] = (
    weakref.WeakValueDictionary()
)


def validate_file_logger_2026(logger: NativeFileLogger2026, engine) -> None:
    if (
        type(logger) is not NativeFileLogger2026
        or _file_loggers.get(id(logger)) is not logger
        or logger.engine is not engine
    ):
        raise ValueError("Actual source-issued native file logger required")


def file_logger_2026(
    engine: CUWEngine2026,
    engine_bytes: bytes,
    sink: Callable[[int, int, int, str, str], None],
    *,
    to_wide: Callable[[bytes], str],
) -> NativeFileLogger2026:
    """Read1c4a0's actual113 IDs from the authenticated PE; no native execution."""
    from scripts.cuw_2026 import CUWEngine2026, identity_2026

    if (
        type(engine) is not CUWEngine2026
        or identity_2026(engine_bytes, "CUW.dll") != engine.identity
    ):
        raise ValueError("Actual source-identified native engine required for logger")
    if not callable(sink) or not callable(to_wide):
        raise TypeError("Primitive log sink and captured ACP converter required")
    pe = struct.unpack_from("<I", engine_bytes, 0x3C)[0]
    count = struct.unpack_from("<H", engine_bytes, pe + 6)[0]
    table = pe + 24 + struct.unpack_from("<H", engine_bytes, pe + 20)[0]
    first, end = 0x7AC88, 0x7AE4C
    raw = None
    for index in range(count):
        rva, length, offset = struct.unpack_from(
            "<III", engine_bytes, table + index * 40 + 12
        )
        if rva <= first and end <= rva + length:
            raw = engine_bytes[offset + first - rva : offset + end - rva]
            break
    if raw is None or len(raw) != end - first:
        raise ValueError("Native log ID source span unavailable")
    levels = {
        identifier: 2 if first + index * 4 in (0x7ADC8, 0x7ADC4) else 0
        for index, (identifier,) in enumerate(struct.iter_unpack("<I", raw))
    }
    result = NativeFileLogger2026(engine, MappingProxyType(levels), sink, to_wide)
    _file_loggers[id(result)] = result
    return result


@dataclass(frozen=True, eq=False)
class NativeFileView2026:
    """One immutable current-table or current-only FILE descriptor."""

    sources: FileSourceSet2026 = field(repr=False, compare=False)
    file_index: int | None
    kind: Literal["none", "plain", "part", "whole", "retained"]
    metadata: Native2026Metadata = field(repr=False)
    source_container: object = field(repr=False, compare=False)
    source_sha256: str
    original_recovery_index: int
    group_start: int | None


@dataclass(frozen=True, eq=False)
class NativeFileGroupView2026:
    """One source-authenticated contiguous delta group and its whole FILE."""

    sources: FileSourceSet2026 = field(repr=False, compare=False)
    start: int
    width: int
    members: tuple[NativeFileView2026, ...]
    whole: NativeFileView2026


@runtime_checkable
class _JudgeGroupResetOriginValidator2026(Protocol):
    def _validate_judge_group_reset_origin2026(
        self, origin: object, group: NativeFileGroupView2026
    ) -> None: ...


@runtime_checkable
class _JudgeDirectResetOriginValidator2026(Protocol):
    def _validate_judge_direct_reset_origin2026(
        self, origin: object, current_a48: NativeFileView2026
    ) -> None: ...


@dataclass(frozen=True)
class _JudgeGroupTableReplacement2026:
    selected_metadata: Native2026Metadata
    selected_source: Any
    selected_name: str
    files: tuple[Native2026Metadata, ...]
    file_sources: tuple[Any, ...]
    file_names: tuple[str, ...]
    has_file_vector: bool
    auxiliary_metadata: Native2026Metadata


@dataclass(frozen=True)
class _NativeWaitTimingSource2026:
    """One exact raw source/parse pair in the captured43ee0 walk."""

    source_name: str
    source: bytes
    metadata: Native2026Metadata | None


@dataclass(frozen=True)
class _NativeWaitTimingStep2026:
    """A literal native stage; values are source inputs, never computed results."""

    operation: Literal["46010", "32130", "43cd0", "41940", "32ff0"]
    sources: tuple[_NativeWaitTimingSource2026, ...]
    slot: int | None = None
    value: bool | None = None


@dataclass(frozen=True)
class _NativePhase6Reorder67c602026:
    """One source-issued post-4a850 table and optional mapped second select."""

    post_4a850_files: tuple[Native2026Metadata, ...]
    post_4a850_names: tuple[str, ...]
    post_4a850_sources: tuple[Any, ...]
    map_entries: tuple[tuple[Native2026Metadata, int], ...]
    post_67c60_files: tuple[Native2026Metadata, ...]
    post_67c60_names: tuple[str, ...]
    post_67c60_sources: tuple[Any, ...]
    second_select: tuple[int, bool, Native2026Metadata, Any, str]


@dataclass(frozen=True)
class _NativePhase6Transform4a8502026:
    """The exact successful Phase6 merge/reorder producer lineage."""

    raw_files: tuple[Native2026Metadata, ...]
    raw_names: tuple[str, ...]
    raw_sources: tuple[Any, ...]
    edges: tuple[tuple[Any, ...], ...]
    post_4a850_files: tuple[Native2026Metadata, ...]
    post_4a850_names: tuple[str, ...]
    post_4a850_sources: tuple[Any, ...]
    mapped_reorder: _NativePhase6Reorder67c602026 | None


@dataclass(frozen=True, eq=False)
class _NativeColdFileTableStages2026:
    """The exact registered cold FILE tables reachable in one native walk."""

    initial: FileSourceSet2026
    post_4a850: FileSourceSet2026 | None
    post_67c60: FileSourceSet2026 | None
    final: FileSourceSet2026


@dataclass(frozen=True, eq=False)
class FileSourceSet2026:
    """An issued43ee0 file-vector and its concrete46010 whole/delta joins."""

    engine: Any = field(repr=False, compare=False)
    source_name: str = field(repr=False)
    admission_sha256: str
    admission_source: Any = field(repr=False)
    selected_metadata: Native2026Metadata = field(repr=False)
    selected_source: Any = field(repr=False)
    selected_name: str = field(repr=False)
    file_names: tuple[str, ...] = field(repr=False)
    files: tuple[Native2026Metadata, ...] = field(repr=False)
    file_sources: tuple[Any, ...] = field(repr=False)
    output_files: tuple[Native2026Metadata, ...] = field(repr=False)
    delta_groups: tuple[tuple[int, int, Native2026Metadata], ...] = field(repr=False)
    delta_group_sources: tuple[bytes, ...] = field(repr=False)
    delta_group_names: tuple[str, ...] = field(repr=False)
    delta_archive: bool
    has_file_vector: bool
    delta_map_entries: tuple[tuple[Native2026Metadata, int], ...] = field(repr=False)
    selection_role: str
    auxiliary_metadata: Native2026Metadata | None = field(repr=False)
    recovery_file_names: tuple[str, ...] = field(repr=False)
    recovery_file_sources: tuple[Any, ...] = field(repr=False)
    recovery_multi_count: int
    recovery_metadata_indexes: tuple[tuple[Native2026Metadata, int], ...] = field(
        repr=False
    )
    _wait_timing_admission2026: Any = field(default=None, repr=False, compare=False)
    _view_lock: threading.RLock = field(
        default_factory=threading.RLock, init=False, repr=False, compare=False
    )
    _view_cache: dict[tuple[str, int | None, int | None], NativeFileView2026] = field(
        default_factory=dict, init=False, repr=False, compare=False
    )
    _group_view_cache: dict[int, NativeFileGroupView2026] = field(
        default_factory=dict, init=False, repr=False, compare=False
    )
    _admission_view_cache: NativeFileView2026 | None = field(
        default=None, init=False, repr=False, compare=False
    )

    @property
    def table_files(self) -> tuple[Native2026Metadata, ...]:
        """Actual D55C FILE slots; ordinary sources retain only the current FILE."""
        validate_file_sources_2026(self)
        return self.files if self.has_file_vector else ()

    @property
    def table_file_names(self) -> tuple[str, ...]:
        """Actual nonempty D59C names, excluding an ordinary current-only source."""
        validate_file_sources_2026(self)
        return self.file_names if self.has_file_vector else ()

    def recovery_sources(self) -> tuple[tuple[str, ...], tuple[Any, ...], int]:
        """Actual20eb0 original list or direct43ee0 source, before FILE transforms."""
        validate_file_sources_2026(self)
        return (
            self.recovery_file_names,
            self.recovery_file_sources,
            self.recovery_multi_count,
        )

    def recovery_index_for_metadata(self, metadata: Native2026Metadata) -> int:
        """Original FILE+50 ECIndex, retained across native node/LEFT merge producers."""
        from scripts.calibration_2026 import (
            native2026_validate_runtime_metadata,
        )

        validate_file_sources_2026(self)
        native2026_validate_runtime_metadata(metadata)
        for owner, index in self.recovery_metadata_indexes:
            if (
                metadata.source_container is owner.source_container
                and metadata.source_sha256 == owner.source_sha256
            ):
                # This proves FILE ownership only. The engine/worker validates
                # source-issued target/progress mutations before consuming them.
                return index
        raise ValueError(
            "Metadata is outside the issued native recovery FILE index proof"
        )

    @property
    def delta_map(self) -> tuple[tuple[int, int], ...]:
        """Current FILE indices joined to the source-owned native pointer map."""
        validate_file_sources_2026(self)
        return tuple(
            (index, group)
            for index, metadata in enumerate(self.files)
            for member, group in self.delta_map_entries
            if metadata is member
        )

    @property
    def delta_map_size(self) -> int:
        """Native b0c retains map entries even when deleted FILES leave the table."""
        validate_file_sources_2026(self)
        return len(self.delta_map_entries)

    @property
    def current_is_retained_clone(self) -> bool:
        validate_file_sources_2026(self)
        return self.selection_role == "retained_clone"

    @property
    def composite_contact(self) -> bool:
        """DB08 is produced by actual per-node32130 source projections."""
        from scripts.calibration_2026 import (
            NativeCompositeSource2026,
            NativeNodeSource2026,
        )

        validate_file_sources_2026(self)

        def projected(source):
            if type(source) is NativeNodeSource2026:
                return (
                    source.parent.vehicle.get("contacttype", "")
                    == "Ethernet & P5-Unified"
                )
            if type(source) is NativeCompositeSource2026:
                return projected(source.left.source_container) and projected(
                    source.right.source_container
                )
            return False

        return bool(self.file_sources) and all(
            projected(source) for source in self.file_sources
        )

    @property
    def execution_files(self) -> tuple[Native2026Metadata, ...]:
        validate_file_sources_2026(self)
        return (
            (self.selected_metadata,) if self.current_is_retained_clone else self.files
        )

    def file_view2026(self, index: int) -> NativeFileView2026:
        """Return the identity-cached descriptor for an actual table slot."""
        return _file_view_2026(self, index)

    def group_view2026(self, index: int) -> NativeFileGroupView2026 | None:
        """Return the actual source group containing this current table slot."""
        return _group_view_2026(self, index)

    def admission_view2026(self) -> NativeFileView2026:
        """Describe the exact initial current pointer, including no-table sources."""
        return _admission_view_2026(self)

    def group_for_file(
        self, file_index: int
    ) -> tuple[int, int, Native2026Metadata] | None:
        validate_file_sources_2026(self)
        if type(file_index) is not int or not 0 <= file_index < len(self.files):
            raise ValueError("Actual native FILE index required")
        group = next(
            (group for index, group in self.delta_map if index == file_index), None
        )
        if group is None:
            return None
        members = tuple(index for index, other in self.delta_map if other == group)
        return min(members), len(members), self.delta_groups[group][2]

    def after_group_reset(self, file_index: int, *, worker) -> FileSourceSet2026:
        """4b900 mode2's actual FILE-table replacement, issued only for its worker."""
        from scripts.cuw_engine_worker import EngineWorker2026

        validate_file_sources_2026(self)
        if (
            type(worker) is not EngineWorker2026
            or worker.engine is not self.engine
            or worker is not self.engine.worker
        ):
            raise ValueError(
                "Actual bound engine worker required for native FILE reset"
            )
        if self.engine.file_sources is not self:
            raise ValueError("Native reset source is not the engine-owned FILE set")
        worker.validate_source()
        if self.delta_archive and self.delta_map_size == 0:
            # 46be0 clears the complete sixteen-slot table, then selects A48.
            result = replace(
                self,
                files=(),
                file_sources=(),
                file_names=(),
                has_file_vector=False,
                selection_role="retained_clone",
                auxiliary_metadata=self.auxiliary_metadata,
            )
        else:
            group = self.group_for_file(file_index)
            if group is None:
                raise ValueError("Current native FILE is outside the delta pointer map")
            start, count, whole = group
            group_index = next(
                index
                for index, (_, _, item) in enumerate(self.delta_groups)
                if item is whole
            )
            source = self.delta_group_sources[group_index]
            name = self.delta_group_names[group_index]
            result = replace(
                self,
                selected_metadata=whole,
                selected_source=source,
                selected_name=name,
                files=(*self.files[:start], whole, *self.files[start + count :]),
                file_sources=(
                    *self.file_sources[:start],
                    source,
                    *self.file_sources[start + count :],
                ),
                file_names=(
                    *self.file_names[:start],
                    name,
                    *self.file_names[start + count :],
                ),
                selection_role="retained_clone",
                auxiliary_metadata=whole,
            )
        # 34e10 saves the actual A48 runtime selection;47e60 restores it.
        # The worker supplies its registered producer object, never caller flags.
        retained = worker._retained_clone_metadata_for_reset(self)
        if retained is not None:
            from scripts.calibration_2026 import native2026_validate_runtime_metadata

            native2026_validate_runtime_metadata(retained)
            original = result.selected_metadata
            if (
                retained.source_container is not original.source_container
                or retained.source_sha256 != original.source_sha256
            ):
                raise ValueError(
                    "Cached A48 metadata belongs to another native whole FILE"
                )
            result = replace(
                result,
                selected_metadata=retained,
                auxiliary_metadata=retained,
                files=tuple(
                    retained if item is original else item for item in result.files
                ),
                output_files=tuple(
                    retained if item is original else item
                    for item in result.output_files
                ),
                delta_groups=tuple(
                    (start, count, retained if whole is original else whole)
                    for start, count, whole in result.delta_groups
                ),
            )
        _file_sets[id(result)] = result
        key = id(result)
        _reset_lineage[key] = (
            weakref.ref(self),
            weakref.ref(worker),
            weakref.ref(result, lambda _: _reset_lineage.pop(key, None)),
        )
        return result

    def _after_judge_group_reset_4b900_2026(
        self,
        group: NativeFileGroupView2026,
        *,
        worker,
        origin: object,
    ) -> FileSourceSet2026:
        """Issue the distinct mode1 table replacement after authenticated judging."""
        from scripts.cuw_engine_worker import EngineWorker2026

        validate_file_sources_2026(self)
        validate_file_group_view_2026(group, self)
        if (
            type(worker) is not EngineWorker2026
            or worker.engine is not self.engine
            or worker is not self.engine.worker
        ):
            raise ValueError("Actual bound engine worker required for judge FILE reset")
        if self.engine.file_sources is not self:
            raise ValueError("Judge reset source is not the engine-owned FILE set")
        worker.validate_source()
        # This is the sole mode1 origin check. The worker owns its receipt and
        # rejects anything except the actual61e40 whole-true/no-eligible branch.
        if not isinstance(worker, _JudgeGroupResetOriginValidator2026):
            raise TypeError("Native judge-reset origin validator is unavailable")
        cast(
            _JudgeGroupResetOriginValidator2026, worker
        )._validate_judge_group_reset_origin2026(origin, group)

        table = _judge_group_table_replacement2026(self, group)
        runtime_whole = self.engine.native_metadata
        from scripts.calibration_2026 import native2026_validate_runtime_metadata

        native2026_validate_runtime_metadata(runtime_whole)
        authored_whole = group.whole.metadata
        if (
            runtime_whole.source_container is not group.whole.source_container
            or runtime_whole.source_sha256 != group.whole.source_sha256
            or runtime_whole.node != authored_whole.node
            or self.recovery_index_for_metadata(runtime_whole)
            != group.whole.original_recovery_index
        ):
            raise ValueError(
                "Runtime A48 metadata differs from the authenticated WHOLE"
            )
        if runtime_whole is not authored_whole:
            table = replace(
                table,
                selected_metadata=runtime_whole,
                auxiliary_metadata=runtime_whole,
                files=tuple(
                    runtime_whole if item is authored_whole else item
                    for item in table.files
                ),
            )
            replacement_groups = tuple(
                (start, width, runtime_whole if whole is authored_whole else whole)
                for start, width, whole in self.delta_groups
            )
        else:
            replacement_groups = self.delta_groups
        result = replace(
            self,
            selected_metadata=table.selected_metadata,
            selected_source=table.selected_source,
            selected_name=table.selected_name,
            files=table.files,
            file_sources=table.file_sources,
            file_names=table.file_names,
            has_file_vector=table.has_file_vector,
            selection_role="file",
            auxiliary_metadata=table.auxiliary_metadata,
            delta_groups=replacement_groups,
        )
        _file_sets[id(result)] = result
        return result

    def _after_judge_direct_reset_4b900_2026(
        self,
        current_a48: NativeFileView2026,
        *,
        worker,
        origin: object,
    ) -> FileSourceSet2026:
        """Issue the direct zero-map mode1 replacement for its real A48 view."""
        from scripts.cuw_engine_worker import EngineWorker2026

        validate_file_sources_2026(self)
        validate_file_view_2026(current_a48, self)
        if not self.delta_archive or self.delta_map_size != 0:
            raise ValueError("Direct judge reset requires a zero-map delta archive")
        if (
            type(worker) is not EngineWorker2026
            or worker.engine is not self.engine
            or worker is not self.engine.worker
        ):
            raise ValueError(
                "Actual bound engine worker required for direct judge reset"
            )
        if self.engine.file_sources is not self:
            raise ValueError(
                "Direct judge reset source is not the engine-owned FILE set"
            )
        worker.validate_source()
        if not isinstance(worker, _JudgeDirectResetOriginValidator2026):
            raise TypeError("Native direct judge-reset origin validator is unavailable")
        cast(
            _JudgeDirectResetOriginValidator2026, worker
        )._validate_judge_direct_reset_origin2026(origin, current_a48)

        # The engine pointer is the actual current A48 runtime projection. The
        # descriptor authenticates its source association; it is not a fallback
        # metadata source because a prior rebuild may have replaced that object.
        metadata = self.engine.native_metadata
        from scripts.calibration_2026 import native2026_validate_runtime_metadata

        native2026_validate_runtime_metadata(metadata)
        if (
            metadata.source_container is not current_a48.source_container
            or metadata.source_sha256 != current_a48.source_sha256
            or metadata.node != current_a48.metadata.node
        ):
            raise ValueError("Direct current A48 metadata differs from its source view")
        if (
            self.recovery_index_for_metadata(metadata)
            != current_a48.original_recovery_index
        ):
            raise ValueError("Direct current A48 recovery association differs")
        result = replace(
            self,
            selected_metadata=metadata,
            files=(),
            file_sources=(),
            file_names=(),
            has_file_vector=False,
            selection_role="retained_clone",
            auxiliary_metadata=metadata,
        )
        _file_sets[id(result)] = result
        return result


_reset_lineage: dict[
    int, tuple[weakref.ReferenceType, weakref.ReferenceType, weakref.ReferenceType]
] = {}


_file_sets: weakref.WeakValueDictionary[int, FileSourceSet2026] = (
    weakref.WeakValueDictionary()
)


def validate_file_sources_2026(value: FileSourceSet2026, engine=None) -> None:
    from scripts.calibration_2026 import native2026_validate_runtime_metadata

    if type(value) is not FileSourceSet2026 or _file_sets.get(id(value)) is not value:
        raise ValueError("Actual issued native file-source set required")
    if engine is not None and value.engine is not engine:
        raise ValueError("File sources belong to another CUW engine")
    if _file_source_identity(value.admission_source)[1] != value.admission_sha256:
        raise ValueError("Original native admission source identity differs")
    for metadata in (
        value.selected_metadata,
        *value.files,
        *value.output_files,
        *(whole for _, _, whole in value.delta_groups),
    ):
        native2026_validate_runtime_metadata(metadata)
    for metadata, source in zip(value.files, value.file_sources, strict=True):
        if isinstance(source, bytes):
            if metadata.source_sha256 != hashlib.sha256(source).hexdigest():
                raise ValueError("Native file source identity differs")
        else:
            from scripts.calibration_2026 import (
                NativeCompositeSource2026,
                NativeNodeSource2026,
                NativeUSBSource2026,
                _validate_container_2026,
            )
            from scripts.cuw_large import LargeSource2026

            if type(source) in (LargeSource2026, NativeUSBSource2026):
                container = (
                    source.container if type(source) is LargeSource2026 else source
                )
                if (
                    metadata.source_container is not container
                    or metadata.source_sha256 != _file_source_identity(source)[1]
                ):
                    raise ValueError(
                        "Native FILE typed source differs from its actual owner"
                    )
                continue

            if (
                type(source) not in (NativeCompositeSource2026, NativeNodeSource2026)
                or metadata.source_container is not source
                or metadata.source_sha256 != source.digest
            ):
                raise ValueError(
                    "Native FILE composition is outside its actual source proof"
                )
            _validate_container_2026(source)


def _issued_file_view2026(
    sources: FileSourceSet2026,
    *,
    kind: Literal["none", "plain", "part", "whole", "retained"],
    file_index: int | None,
    metadata: Native2026Metadata,
    group_start: int | None,
) -> NativeFileView2026:
    validate_file_sources_2026(sources)
    key = (kind, file_index, group_start)
    source_container = metadata.source_container
    digest = metadata.source_sha256
    recovery_index = sources.recovery_index_for_metadata(metadata)
    with sources._view_lock:
        previous = sources._view_cache.get(key)
        if previous is not None:
            if (
                previous.sources is not sources
                or previous.metadata is not metadata
                or previous.source_container is not source_container
                or previous.source_sha256 != digest
                or previous.original_recovery_index != recovery_index
            ):
                raise ValueError("Native FILE view cache conflicts with source table")
            return previous
        view = NativeFileView2026(
            sources,
            file_index,
            kind,
            metadata,
            source_container,
            digest,
            recovery_index,
            group_start,
        )
        sources._view_cache[key] = view
        return view


def _whole_group_for_metadata2026(sources, metadata):
    matches = [
        (index, start, width, whole)
        for index, (start, width, whole) in enumerate(sources.delta_groups)
        if whole is metadata
    ]
    if len(matches) > 1:
        raise ValueError("Whole FILE is ambiguous across native delta groups")
    return matches[0] if matches else None


def _whole_group_current_start2026(sources, group_index, source_start):
    whole = sources.delta_groups[group_index][2]
    direct_slots = tuple(
        index for index, item in enumerate(sources.files) if item is whole
    )
    if len(direct_slots) == 1:
        return direct_slots[0]
    mapped_slots = tuple(
        index
        for index, item in enumerate(sources.files)
        if any(
            member is item and mapped == group_index
            for member, mapped in sources.delta_map_entries
        )
    )
    if mapped_slots:
        if mapped_slots != tuple(
            range(mapped_slots[0], mapped_slots[0] + len(mapped_slots))
        ):
            raise ValueError("Native FILE group is not contiguous")
        return mapped_slots[0]
    return source_start


def _file_view_2026(sources: FileSourceSet2026, index: int) -> NativeFileView2026:
    validate_file_sources_2026(sources)
    if type(index) is not int or not sources.has_file_vector:
        raise ValueError("Actual native FILE table index required")
    if not 0 <= index < len(sources.files):
        raise ValueError("Native FILE index is outside the issued table")
    metadata = sources.files[index]
    whole_group = _whole_group_for_metadata2026(sources, metadata)
    if whole_group is not None:
        return _issued_file_view2026(
            sources,
            kind="whole",
            file_index=index,
            metadata=metadata,
            group_start=index,
        )

    mapped_group = next(
        (
            group_index
            for member, group_index in sources.delta_map_entries
            if member is metadata
        ),
        None,
    )
    if mapped_group is not None:
        group_indices = tuple(
            current_index
            for current_index, current in enumerate(sources.files)
            if any(
                member is current and group_index == mapped_group
                for member, group_index in sources.delta_map_entries
            )
        )
        if not group_indices or group_indices != tuple(
            range(group_indices[0], group_indices[0] + len(group_indices))
        ):
            raise ValueError("Mapped native FILE group is not contiguous")
        group_start = group_indices[0]
        kind: Literal["plain", "part"] = "part"
    elif sources.delta_archive and sources.delta_map_size == 0:
        direct_group = next(
            (
                (start, width)
                for start, width, _whole in sources.delta_groups
                if start <= index < start + width
            ),
            None,
        )
        if direct_group is None:
            kind, group_start = "plain", None
        else:
            start, width = direct_group
            if start + width > len(sources.files) or any(
                _whole_group_for_metadata2026(sources, item) is not None
                for item in sources.files[start : start + width]
            ):
                raise ValueError("Direct native FILE group differs from current table")
            kind, group_start = "part", start
    else:
        kind, group_start = "plain", None
    return _issued_file_view2026(
        sources,
        kind=kind,
        file_index=index,
        metadata=metadata,
        group_start=group_start,
    )


def _admission_view_2026(sources: FileSourceSet2026) -> NativeFileView2026:
    validate_file_sources_2026(sources)
    with sources._view_lock:
        if sources._admission_view_cache is not None:
            view = sources._admission_view_cache
            if view.kind == "none":
                if (
                    type(view) is not NativeFileView2026
                    or view.sources is not sources
                    or view.file_index is not None
                    or view.metadata is not sources.selected_metadata
                    or sources._view_cache.get(("none", None, None)) is not view
                ):
                    raise ValueError("Cached native no-table admission view is invalid")
            else:
                validate_file_view_2026(view, sources)
            return view
    metadata = sources.selected_metadata
    if not sources.has_file_vector:
        view = _issued_file_view2026(
            sources,
            kind="none",
            file_index=None,
            metadata=metadata,
            group_start=None,
        )
    else:
        current_slots = tuple(
            index for index, item in enumerate(sources.files) if item is metadata
        )
        if len(current_slots) == 1:
            view = _file_view_2026(sources, current_slots[0])
        elif current_slots:
            raise ValueError("Admission FILE is ambiguous in native table")
        else:
            whole_group = _whole_group_for_metadata2026(sources, metadata)
            if whole_group is None:
                capability = sources._wait_timing_admission2026
                stages = (
                    ()
                    if capability is None
                    else tuple(
                        stage
                        for stage in (
                            capability.table_stages.initial,
                            capability.table_stages.post_4a850,
                            capability.table_stages.post_67c60,
                            capability.table_stages.final,
                        )
                        if stage is not None
                    )
                )
                if not any(
                    stage is sources
                    and stage.selected_metadata is metadata
                    and stage.selected_source is sources.selected_source
                    and stage.selected_name == sources.selected_name
                    for stage in stages
                ):
                    raise ValueError(
                        "Admission FILE is outside its issued source table"
                    )
                view = _issued_file_view2026(
                    sources,
                    kind="retained",
                    file_index=None,
                    metadata=metadata,
                    group_start=None,
                )
            else:
                group_index, source_start, width, _whole = whole_group
                map_slots = tuple(
                    index
                    for index, item in enumerate(sources.files)
                    if any(
                        member is item and group == group_index
                        for member, group in sources.delta_map_entries
                    )
                )
                group_start = map_slots[0] if map_slots else source_start
                if map_slots and map_slots != tuple(
                    range(group_start, group_start + width)
                ):
                    raise ValueError("Admission whole FILE group is not contiguous")
                view = _issued_file_view2026(
                    sources,
                    kind="whole",
                    file_index=group_start,
                    metadata=metadata,
                    group_start=group_start,
                )
    with sources._view_lock:
        if sources._admission_view_cache is None:
            object.__setattr__(sources, "_admission_view_cache", view)
        elif sources._admission_view_cache is not view:
            raise ValueError("Concurrent native admission view differs")
        cached = sources._admission_view_cache
        if cached is None:
            raise ValueError("Native admission view cache was not established")
        return cached


def _group_view_2026(
    sources: FileSourceSet2026, index: int
) -> NativeFileGroupView2026 | None:
    validate_file_sources_2026(sources)
    if type(index) is not int or not sources.has_file_vector:
        raise ValueError("Actual native FILE table index required")
    if not 0 <= index < len(sources.files):
        raise ValueError("Native FILE index is outside the issued table")
    metadata = sources.files[index]
    if _whole_group_for_metadata2026(sources, metadata) is not None:
        return None

    mapped_group = next(
        (
            group_index
            for member, group_index in sources.delta_map_entries
            if member is metadata
        ),
        None,
    )
    if mapped_group is not None:
        indices = tuple(
            current_index
            for current_index, current in enumerate(sources.files)
            if any(
                member is current and group_index == mapped_group
                for member, group_index in sources.delta_map_entries
            )
        )
        if not indices or indices != tuple(
            range(indices[0], indices[0] + len(indices))
        ):
            raise ValueError("Mapped native FILE group is not contiguous")
        start = indices[0]
        width = len(indices)
        whole = sources.delta_groups[mapped_group][2]
        if width != sources.delta_groups[mapped_group][1]:
            raise ValueError("Mapped native FILE group width differs from source")
    elif sources.delta_archive and sources.delta_map_size == 0:
        direct = next(
            (
                (start, width, whole)
                for start, width, whole in sources.delta_groups
                if start <= index < start + width
            ),
            None,
        )
        if direct is None:
            return None
        start, width, whole = direct
        if start + width > len(sources.files) or any(
            _whole_group_for_metadata2026(sources, item) is not None
            for item in sources.files[start : start + width]
        ):
            return None
    else:
        return None
    members = tuple(
        _file_view_2026(sources, current) for current in range(start, start + width)
    )
    if any(member.kind != "part" or member.group_start != start for member in members):
        raise ValueError("Native group members differ from actual part views")
    whole_view = _issued_file_view2026(
        sources,
        kind="whole",
        file_index=start,
        metadata=whole,
        group_start=start,
    )
    with sources._view_lock:
        previous = sources._group_view_cache.get(start)
        if previous is not None:
            if (
                previous.sources is not sources
                or previous.width != width
                or previous.members != members
                or previous.whole is not whole_view
            ):
                raise ValueError("Native FILE group view cache conflicts")
            return previous
        result = NativeFileGroupView2026(sources, start, width, members, whole_view)
        sources._group_view_cache[start] = result
        return result


def _judge_group_table_replacement2026(
    sources: FileSourceSet2026, group: NativeFileGroupView2026
) -> _JudgeGroupTableReplacement2026:
    """Compute only the source table writes shared by authenticated mode1."""
    validate_file_group_view_2026(group, sources)
    whole = group.whole.metadata
    group_index = next(
        (
            index
            for index, (_start, _width, candidate) in enumerate(sources.delta_groups)
            if candidate is whole
        ),
        None,
    )
    if group_index is None:
        raise ValueError("Judge FILE group whole is outside the source set")
    source = sources.delta_group_sources[group_index]
    name = sources.delta_group_names[group_index]
    if sources.delta_archive and sources.delta_map_size == 0:
        # 46be0 clears D55C/D59C for direct zero-map delta in either mode.
        files: tuple[Native2026Metadata, ...] = ()
        file_sources: tuple[Any, ...] = ()
        file_names: tuple[str, ...] = ()
        has_file_vector = False
    else:
        files = (
            *sources.files[: group.start],
            whole,
            *sources.files[group.start + group.width :],
        )
        file_sources = (
            *sources.file_sources[: group.start],
            source,
            *sources.file_sources[group.start + group.width :],
        )
        file_names = (
            *sources.file_names[: group.start],
            name,
            *sources.file_names[group.start + group.width :],
        )
        has_file_vector = True
    return _JudgeGroupTableReplacement2026(
        whole,
        source,
        name,
        files,
        file_sources,
        file_names,
        has_file_vector,
        whole,
    )


def validate_file_view_2026(
    view: NativeFileView2026, sources: FileSourceSet2026
) -> None:
    if type(view) is not NativeFileView2026 or type(sources) is not FileSourceSet2026:
        raise TypeError("Concrete native FILE view and source set required")
    validate_file_sources_2026(sources)
    if view.sources is not sources:
        raise ValueError("Native FILE view belongs to another table version")
    if view.kind == "none":
        if (
            sources.has_file_vector
            or view.file_index is not None
            or view.group_start is not None
            or view.metadata is not sources.selected_metadata
            or sources._view_cache.get(("none", None, None)) is not view
            or view is not sources._admission_view_cache
        ):
            raise ValueError("Native no-table view was not issued by this source set")
    elif view.kind == "retained":
        capability = sources._wait_timing_admission2026
        stages = (
            ()
            if capability is None
            else tuple(
                stage
                for stage in (
                    capability.table_stages.initial,
                    capability.table_stages.post_4a850,
                    capability.table_stages.post_67c60,
                    capability.table_stages.final,
                )
                if stage is not None
            )
        )
        if (
            view.file_index is not None
            or view.group_start is not None
            or view.metadata is not sources.selected_metadata
            or not any(
                stage is sources
                and stage.selected_metadata is view.metadata
                and stage.selected_source is sources.selected_source
                and stage.selected_name == sources.selected_name
                for stage in stages
            )
            or sources._view_cache.get(("retained", None, None)) is not view
        ):
            raise ValueError(
                "Historical admission pointer lacks its exact table-stage proof"
            )
    elif type(view.file_index) is int:
        expected = sources._view_cache.get(
            (view.kind, view.file_index, view.group_start)
        )
        if expected is not view:
            raise ValueError("Native FILE view was forged, copied, or is stale")
        if view.kind == "whole":
            if view.group_start != view.file_index:
                raise ValueError("Native whole FILE index differs from its group start")
            group = _whole_group_for_metadata2026(sources, view.metadata)
            if group is None or group[3] is not view.metadata:
                raise ValueError("Native whole FILE is outside this source set")
            if view.file_index != _whole_group_current_start2026(
                sources, group[0], group[1]
            ):
                raise ValueError("Native whole FILE index differs from source group")
        elif view.kind not in ("plain", "part"):
            raise ValueError("Unknown native FILE view kind")
    else:
        raise ValueError("Native FILE view has no actual table position")
    if (
        view.source_container is not view.metadata.source_container
        or view.source_sha256 != view.metadata.source_sha256
        or view.original_recovery_index
        != sources.recovery_index_for_metadata(view.metadata)
    ):
        raise ValueError("Native FILE view source identity changed")


def validate_file_group_view_2026(
    group: NativeFileGroupView2026, sources: FileSourceSet2026
) -> None:
    if (
        type(group) is not NativeFileGroupView2026
        or type(sources) is not FileSourceSet2026
    ):
        raise TypeError("Concrete native FILE group view and source set required")
    validate_file_sources_2026(sources)
    if group.sources is not sources:
        raise ValueError("Native FILE group belongs to another table version")
    if sources._group_view_cache.get(group.start) is not group:
        raise ValueError("Native FILE group was forged, copied, or is stale")
    expected = _group_view_2026(sources, group.start)
    if expected is not group:
        raise ValueError("Native FILE group was forged, copied, or is stale")
    if group.width != len(group.members) or group.width <= 0:
        raise ValueError("Native FILE group width differs from its members")
    for offset, member in enumerate(group.members):
        validate_file_view_2026(member, sources)
        if (
            member.kind != "part"
            or member.file_index != group.start + offset
            or member.group_start != group.start
        ):
            raise ValueError("Native FILE group members are not contiguous parts")
    validate_file_view_2026(group.whole, sources)
    if group.whole.kind != "whole" or group.whole.group_start != group.start:
        raise ValueError("Native whole FILE view differs from its source group")


def _file_source_identity(source) -> tuple[int, str]:
    """Actual original byte identity without serializing typed source views."""
    from scripts.calibration_2026 import NativeUSBSource2026, _validate_container_2026
    from scripts.cuw_large import LargeSource2026, validate_large_container_2026

    if type(source) is bytes:
        return len(source), hashlib.sha256(source).hexdigest()
    if type(source) is LargeSource2026:
        validate_large_container_2026(source.container)
        return len(source), source.container.digest
    if type(source) is NativeUSBSource2026:
        _validate_container_2026(source)
        return source.size, source.digest
    raise TypeError("Original bytes or issued large/USB source required")


def admit_typed_file_source_2026(
    engine: CUWEngine2026, source_name: str, source, *, region: int
) -> FileSourceSet2026:
    """Issue one actual plain-FILE lease, retaining its original pinned source."""
    from scripts.calibration_2026 import NativeUSBSource2026
    from scripts.cuw_2026 import CUWEngine2026
    from scripts.cuw_large import LargeSource2026

    if type(engine) is not CUWEngine2026 or type(source) not in (
        LargeSource2026,
        NativeUSBSource2026,
    ):
        raise TypeError("Actual CUW engine and issued typed file source required")
    if (
        not isinstance(source_name, str)
        or not 0 < len(source_name) <= 4096
        or "\0" in source_name
    ):
        raise ValueError("Bounded native source filename required")
    if type(region) is not int or not 0 <= region <= 3:
        raise ValueError("Native zero-based region required")
    _, digest = _file_source_identity(source)
    container = source.container if type(source) is LargeSource2026 else source
    metadata = engine._parser_profile(native2026_metadata(container, region=region))
    result = FileSourceSet2026(
        engine=engine,
        source_name=source_name,
        admission_sha256=digest,
        admission_source=source,
        selected_metadata=metadata,
        selected_source=source,
        selected_name=source_name,
        file_names=(source_name,),
        files=(metadata,),
        file_sources=(source,),
        output_files=(metadata,),
        delta_groups=(),
        delta_group_sources=(),
        delta_group_names=(),
        delta_archive=False,
        has_file_vector=False,
        delta_map_entries=(),
        selection_role="file",
        auxiliary_metadata=None,
        recovery_file_names=(source_name,),
        recovery_file_sources=(source,),
        recovery_multi_count=0,
        recovery_metadata_indexes=((metadata, 0),),
    )
    _file_sets[id(result)] = result
    return result


def validate_file_reset_2026(
    old: FileSourceSet2026, new: FileSourceSet2026, worker
) -> None:
    """Prove the actual worker's4b900 producer issued this exact replacement."""
    from scripts.cuw_engine_worker import EngineWorker2026

    if type(worker) is not EngineWorker2026:
        raise ValueError("Actual bound native worker required for FILE reset proof")
    validate_file_sources_2026(old, worker.engine)
    validate_file_sources_2026(new, worker.engine)
    proof = _reset_lineage.get(id(new))
    if (
        proof is None
        or proof[0]() is not old
        or proof[1]() is not worker
        or proof[2]() is not new
    ):
        raise ValueError(
            "Native FILE reset was not issued for this exact source/worker"
        )


def _ini(data: bytes) -> dict[str, dict[str, str]]:
    if not data or len(data) > 1024 * 1024 or b"\0" in data:
        raise ValueError("Bounded native attached INI required")
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    parser.read_string(data.decode("latin1"))
    return {section.casefold(): dict(parser[section]) for section in parser.sections()}


def _file_list(data: bytes) -> tuple[str, ...]:
    """46de0/4c650 split at comma, strip first[,last], then every quote."""
    if not data or len(data) > 1024 * 1024 or b"\0" in data:
        raise ValueError("Bounded native file-list bytes required")
    rows = data.decode("latin1").split(",")
    rows[0] = rows[0].replace("[", "", 1)
    at = rows[-1].rfind("]")
    if at >= 0:
        rows[-1] = rows[-1][:at] + rows[-1][at + 1 :]
    return tuple(row.replace('"', "") for row in rows)


def _admission_fault(line: int):
    """Actual CPassThruCtrlr.cpp location at authenticated RVA7c810."""
    from scripts.programming_2026_common import NativePassThruException2026

    return NativePassThruException2026(
        6,
        "C:\\Shimojo\\local\\CUW.dll\\V1.15.0.3(\x83r\x83\x8b\x83h\x97p)\\CUW\\CUW\\CPassThruCtrlr.cpp",
        line,
    )


def _profile_count(value: str) -> int:
    """Bounded decimal host admission; general Win32 profile conversion is open."""
    if value == "":
        return 0
    digits = value[1:] if value[:1] in ("+", "-") else value
    if not digits.isascii() or not digits.isdecimal():
        raise ValueError(
            "Captured GetPrivateProfileIntA conversion required for nondecimal count"
        )
    return int(value, 10)


def admit_file_sources_2026(
    engine: CUWEngine2026,
    source_name: str,
    source: bytes,
    *,
    region: int,
    source_files: Mapping[str, bytes] | None = None,
    cancelled: Callable[[], bool] = lambda: False,
) -> FileSourceSet2026:
    """43ee0 consumes captured file bytes; archive extraction remains in memory.

    The supplied mapping is primitive captured file I/O, not business outcomes.
    All CPU metadata and delta flags are derived from validated original bytes.
    """
    from scripts.cuw_2026 import CUWEngine2026, extract_zip, read_file_header

    if type(engine) is not CUWEngine2026:
        raise TypeError("Concrete source-identified CUW2026 engine required")
    if (
        not isinstance(source_name, str)
        or not 0 < len(source_name) <= 4096
        or "\0" in source_name
    ):
        raise ValueError("Bounded native source filename required")
    if not isinstance(source, bytes) or not 0 < len(source) <= 64 * 1024 * 1024:
        raise ValueError("Bounded immutable native file bytes required")
    if type(region) is not int or not 0 <= region <= 3:
        raise ValueError("Native zero-based region required")
    files = []
    names = []
    sources = []
    output = []
    groups = []
    group_sources = []
    group_names = []
    delta = False
    raw_parse_rows: list[_NativeWaitTimingSource2026] = []
    json_prefix_steps: list[_NativeWaitTimingStep2026] = []
    selected_source = source
    selected_name = source_name
    is_list = PureWindowsPath(source_name).suffix.casefold() == ".json"
    listed_names = _file_list(source) if is_list else ()
    listed_sources = []
    recovery_indexes = []
    active_recovery_index = 0

    def parse(data, *, recovery_index=None):
        if cancelled():
            raise InterruptedError("CUW file admission cancelled")
        metadata = engine._parser_profile(
            native2026_metadata(parse_cuw_2026(data), region=region)
        )
        recovery_indexes.append(
            (
                metadata,
                active_recovery_index if recovery_index is None else recovery_index,
            )
        )
        return metadata

    def append(name, data):
        nonlocal delta, selected_source, selected_name
        suffix = PureWindowsPath(name).suffix.casefold()
        if suffix == ".scuw":
            delta = True
            archive_source = _NativeWaitTimingSource2026(name, data, None)
            members = {
                member.name.casefold(): member.data
                for member in extract_zip(data, name, cancelled=cancelled)
            }
            settings = _ini(members.get("setting.ini", b""))
            settings_delta = settings.get("deltareprocalfile", {})
            count = _profile_count(settings_delta.get("filenum", "0"))
            if count == 0:
                raise _admission_fault(0x3218)
            if not 1 <= count <= 4096:
                raise ValueError(
                    "Native delta FileNum absent or exceeds host bound (0x3218)"
                )
            start = len(files)
            for index in range(1, count + 1):
                # 46010 GetPrivateProfileStringA uses a260-byte output buffer.
                path = settings_delta.get(f"filename{index}", "")[:259]
                if PureWindowsPath(path).as_posix().casefold() not in members:
                    raise _admission_fault(0x3226)
                item = members[PureWindowsPath(path).as_posix().casefold()]
                metadata = parse(item)
                files.append(metadata)
                names.append(path)
                sources.append(item)
                raw_parse_rows.append(_NativeWaitTimingSource2026(path, item, metadata))
            whole_name = settings.get("wholereprocalfile", {}).get("filename", "")[:259]
            if PureWindowsPath(whole_name).as_posix().casefold() not in members:
                raise _admission_fault(0x3233)
            whole_bytes = members[PureWindowsPath(whole_name).as_posix().casefold()]
            whole = parse(whole_bytes)
            whole_source = _NativeWaitTimingSource2026(whole_name, whole_bytes, whole)
            if is_list:
                json_prefix_steps.extend(
                    (
                        _NativeWaitTimingStep2026("46010", (archive_source,)),
                        _NativeWaitTimingStep2026("32130", (whole_source,)),
                    )
                )
            groups.append((start, count, whole))
            group_sources.append(whole_bytes)
            group_names.append(whole_name)
            output.append(whole)
            if not is_list:
                selected_source = whole_bytes
                selected_name = whole_name
        elif suffix == ".cuwc" and not is_list:
            header = read_file_header(data)
            if header.status:
                raise ValueError("Native compressed file header unavailable")
            sections = _ini(data[: header.marker_offset])
            count = _profile_count(
                sections.get("vehicle", {}).get("numberofcalibration", "0")
            )
            if count <= 0:
                raise _admission_fault(0x3399)
            if not 1 <= count <= 4096:
                raise ValueError("Native compressed CPU count unavailable (0x3399)")
            new_ids = tuple(
                sections.get(f"cpu{index:02d}", {}).get("newcid", "")[:259]
                for index in range(1, count + 1)
            )
            if not all(new_ids):
                raise _admission_fault(0x33A8)
            ordered = {}
            for member in extract_zip(data, name, cancelled=cancelled):
                if PureWindowsPath(member.name).suffix.casefold() != ".cuw":
                    continue
                basename = PureWindowsPath(member.name).name
                match = next(
                    (
                        index
                        for index, cid in enumerate(new_ids)
                        if basename.startswith(cid)
                    ),
                    None,
                )
                if match is None:
                    raise _admission_fault(0x3400)
                if match in ordered:
                    raise _admission_fault(0x3409)
                ordered[match] = (member.name, member.data)
            for recovery_index, index in enumerate(sorted(ordered)):
                member_name, item = ordered[index]
                metadata = parse(item, recovery_index=recovery_index)
                files.append(metadata)
                names.append(member_name)
                sources.append(item)
                output.append(metadata)
                raw_parse_rows.append(
                    _NativeWaitTimingSource2026(member_name, item, metadata)
                )
        else:
            metadata = parse(data)
            files.append(metadata)
            names.append(name)
            sources.append(data)
            output.append(metadata)
            raw_parse_rows.append(_NativeWaitTimingSource2026(name, data, metadata))
        if len(files) > 16:
            raise _admission_fault(
                0x308F if is_list else 0x30BE if suffix == ".cuwc" else 0x30D8
            )

    if is_list:
        for active_recovery_index, name in enumerate(listed_names):
            if source_files is None or name not in source_files:
                raise _admission_fault(0x330F)
            captured = source_files[name]
            listed_sources.append(captured)
            append(name, captured)
    else:
        append(source_name, source)
    if not files or not output:
        raise ValueError("Native file admission produced no calibration")
    if is_list:
        recovery_names = listed_names
        recovery_sources = tuple(listed_sources)
        recovery_multi_count = len(listed_names)
    elif PureWindowsPath(source_name).suffix.casefold() == ".cuwc":
        recovery_names = tuple(names)
        recovery_sources = tuple(sources)
        recovery_multi_count = len(names)
    else:
        recovery_names = (source_name,)
        recovery_sources = (source,)
        recovery_multi_count = 0
    has_vector = is_list or PureWindowsPath(source_name).suffix.casefold() in (
        ".cuwc",
        ".scuw",
    )
    if has_vector and any(item.format_version in (10, 12) for item in files):
        raise _admission_fault(0x318C)
    contacts = tuple(item.vehicle.get("contacttype", "") for item in files)
    if "Ethernet & P5-Unified" in contacts:
        if is_list:
            raise _admission_fault(0x3094)
        if len(files) != 1 or groups or has_vector:
            raise ValueError("Native composite admission requires one ordinary source")
        if engine.source_sha256 is not None:
            raise NotImplementedError(
                "Native composite context capture/restore producer is not yet implemented"
            )
        from scripts.calibration_2026 import (
            native2026_node_count,
            native2026_project_node,
        )

        parent = files[0]
        count = native2026_node_count(parent)
        if not 2 <= count <= 16:
            raise _admission_fault(0x313F)
        files = [native2026_project_node(parent, index) for index in range(count)]
        recovery_indexes.extend((item, 0) for item in files)
        sources = [item.source_container for item in files]
        names = [source_name] * count
        recovery_names = tuple(names)
        recovery_sources = (source,) * count
        recovery_multi_count = count
        output = list(files)
        contacts = tuple(item.vehicle.get("contacttype", "") for item in files)
        has_vector = True
    if "Ethernet" in contacts and any(
        contact not in ("Ethernet", "P5-Unified", "Phase6") for contact in contacts
    ):
        raise _admission_fault(0x31A2)
    map_entries = (
        tuple(
            (files[index], group)
            for group, (start, count, _) in enumerate(groups)
            for index in range(start, start + count)
        )
        if is_list
        else ()
    )
    phase6_transform_state = None
    json_initial_record = None
    if (is_list or PureWindowsPath(source_name).suffix.casefold() == ".cuwc") and files:
        initial_metadata = files[0]
        initial_source = sources[0]
        initial_name = names[0]
        initial_group = next(
            (group for member, group in map_entries if member is initial_metadata),
            None,
        )
        if initial_group is not None:
            initial_metadata = groups[initial_group][2]
            initial_source = group_sources[initial_group]
            initial_name = group_names[initial_group]
        initial_candidates = list(raw_parse_rows)
        for step in json_prefix_steps:
            initial_candidates.extend(step.sources)
        json_initial_record = next(
            (
                record
                for record in initial_candidates
                if record.metadata is initial_metadata
                and record.source is initial_source
                and record.source_name == initial_name
            ),
            None,
        )
    if (
        has_vector
        and "Phase6" in contacts
        and (map_entries or not (engine.native_delta_active or delta))
    ):
        from scripts.calibration_2026 import (
            native2026_merge_phase6,
            native2026_node_values,
        )

        def mapped(metadata):
            return next(
                (group for member, group in map_entries if member is metadata), None
            )

        mapped_phase6 = any(
            item.vehicle.get("contacttype", "") == "Phase6" and mapped(item) is not None
            for item in files
        )
        phase6_raw_files = tuple(files)
        phase6_raw_names = tuple(names)
        phase6_raw_sources = tuple(sources)
        phase6_slots = list(range(len(files)))
        phase6_edges = []
        index = 0
        while index < len(files):
            left = files[index]
            if (
                left.vehicle.get("contacttype", "") != "Phase6"
                or mapped(left) is not None
            ):
                index += 1
                continue
            following = index + 1
            while following < len(files):
                right = files[following]
                first = native2026_node_values(left)
                second = native2026_node_values(right)
                if (
                    right.vehicle.get("contacttype", "") == "Phase6"
                    and mapped(right) is None
                    and all(
                        first.get(key, "") == second.get(key, "")
                        for key in ("diagid", "logicaladdress")
                    )
                ):
                    left_recovery_index = next(
                        value for owner, value in recovery_indexes if owner is left
                    )
                    try:
                        left_name = names[index]
                        left_source = sources[index]
                        right_name = names[following]
                        right_source = sources[following]
                        left_slot = phase6_slots[index]
                        right_slot = phase6_slots[following]
                        left = native2026_merge_phase6(left, right)
                    except ValueError as error:
                        if not str(error).startswith("Not combinable:"):
                            raise
                        from scripts.programming_2026_common import NativeException2026

                        raise NativeException2026("Not combinable.") from error
                    phase6_edges.append(
                        (
                            len(phase6_edges),
                            left_slot,
                            right_slot,
                            files[index],
                            files[following],
                            left,
                            left_name,
                            left_source,
                            right_name,
                            right_source,
                        )
                    )
                    files[index] = left
                    recovery_indexes.append((left, left_recovery_index))
                    sources[index] = left.source_container
                    del phase6_slots[following]
                    del files[following], sources[following], names[following]
                else:
                    following += 1
            index += 1
        post_4a850_files = tuple(files)
        post_4a850_names = tuple(names)
        post_4a850_sources = tuple(sources)
        if mapped_phase6:
            # 67a60/67c60 use first DiagID (fallback LogicalAddress), inserting
            # unmapped Phase6 FILES before the first FILE in each key bucket.
            def key(metadata):
                node = native2026_node_values(metadata)
                return node.get("diagid", "") or node.get("logicaladdress", "")

            keys = []
            for item in files:
                value = key(item)
                if item.vehicle.get("contacttype", "") == "Phase6" and value in keys:
                    keys.insert(keys.index(value), value)
                else:
                    keys.append(value)
            ordered = []
            consumed = set()
            for value in keys:
                anchor = None
                for ordinal, item in enumerate(files):
                    if ordinal in consumed or key(item) != value:
                        continue
                    row = (item, sources[ordinal], names[ordinal])
                    if (
                        anchor is not None
                        and item.vehicle.get("contacttype", "") == "Phase6"
                        and mapped(item) is None
                    ):
                        position = next(
                            index
                            for index, other in enumerate(ordered)
                            if other[0] is anchor
                        )
                        ordered.insert(position, row)
                    else:
                        ordered.append(row)
                        if anchor is None:
                            anchor = item
                    consumed.add(ordinal)
            files = [row[0] for row in ordered]
            sources = [row[1] for row in ordered]
            names = [row[2] for row in ordered]
            if engine._metadata is not None or engine._file_sources is not None:
                # Legacy reload remains software-open; preserve its prior
                # preflight rejection without assigning cold C44 timing parity.
                from scripts.calibration_2026 import native2026_validate_phase6_pair

                index = 0
                while index < len(files):
                    first = files[index]
                    if first.vehicle.get("contacttype", "") != "Phase6":
                        index += 1
                        continue
                    first_node = native2026_node_values(first)
                    candidates = []
                    while index < len(files):
                        item = files[index]
                        node = native2026_node_values(item)
                        if any(
                            first_node.get(key, "") != node.get(key, "")
                            for key in ("diagid", "logicaladdress")
                        ):
                            break
                        group = mapped(item)
                        if group is None:
                            candidates.append(item)
                            index += 1
                        else:
                            candidates.append(groups[group][2])
                            index += groups[group][1]
                    for left_index, left in enumerate(candidates):
                        for right in candidates[left_index + 1 :]:
                            try:
                                native2026_validate_phase6_pair(left, right)
                            except ValueError as error:
                                if not str(error).startswith("Not combinable:"):
                                    raise
                                from scripts.programming_2026_common import (
                                    NativeException2026,
                                )

                                raise NativeException2026("Not combinable.") from error
        if mapped_phase6:
            phase6_reorder_state = (
                tuple(files),
                tuple(names),
                tuple(sources),
            )
        else:
            phase6_reorder_state = None
        phase6_transform_state = (
            phase6_raw_files,
            phase6_raw_names,
            phase6_raw_sources,
            tuple(phase6_edges),
            post_4a850_files,
            post_4a850_names,
            post_4a850_sources,
            phase6_reorder_state,
        )
        output = []
        emitted_groups = set()
        for item in files:
            group = mapped(item)
            if group is None:
                output.append(item)
            elif group not in emitted_groups:
                output.append(groups[group][2])
                emitted_groups.add(group)
    # 32ff0(0,true) selects the group's whole FILE whenever table slot0 is mapped.
    selected = output[0]
    first_group = next(
        (group for member, group in map_entries if member is files[0]), None
    )
    if delta and not is_list:
        first_group = 0
    clone_selected = delta and (not is_list or first_group is not None)
    if clone_selected:
        assert first_group is not None
        selected_source = group_sources[first_group]
        selected_name = group_names[first_group]
    else:
        selected_source = sources[0]
        selected_name = names[0]

    trajectory: list[_NativeWaitTimingStep2026] = []
    suffix = PureWindowsPath(source_name).suffix.casefold()

    if is_list:
        trajectory.extend(json_prefix_steps)
        trajectory.append(_NativeWaitTimingStep2026("43cd0", tuple(raw_parse_rows)))
        if json_initial_record is None:
            raise ValueError("Initial JSON native pointer has no raw source record")
        trajectory.append(
            _NativeWaitTimingStep2026(
                "32ff0",
                (json_initial_record,),
                slot=0,
                value=True,
            )
        )
    elif suffix == ".scuw":
        archive = _NativeWaitTimingSource2026(source_name, source, None)
        whole = _NativeWaitTimingSource2026(
            group_names[0], group_sources[0], groups[0][2]
        )
        trajectory.extend(
            (
                _NativeWaitTimingStep2026("46010", (archive,)),
                _NativeWaitTimingStep2026("43cd0", tuple(raw_parse_rows)),
                _NativeWaitTimingStep2026("32130", (whole,)),
                _NativeWaitTimingStep2026("41940", (whole,)),
            )
        )
    elif suffix == ".cuwc":
        if json_initial_record is None:
            raise ValueError("Initial CUWC native pointer has no raw source record")
        trajectory.extend(
            (
                _NativeWaitTimingStep2026("43cd0", tuple(raw_parse_rows)),
                _NativeWaitTimingStep2026(
                    "32ff0",
                    (json_initial_record,),
                    slot=0,
                    value=False,
                ),
            )
        )
    if phase6_transform_state is not None:
        (
            phase6_raw_files,
            phase6_raw_names,
            phase6_raw_sources,
            phase6_edges,
            post_4a850_files,
            post_4a850_names,
            post_4a850_sources,
            phase6_reorder_state,
        ) = phase6_transform_state
        mapped_reorder = None
        if phase6_reorder_state is not None:
            post_67c60_files, post_67c60_names, post_67c60_sources = (
                phase6_reorder_state
            )
            mapped_reorder = _NativePhase6Reorder67c602026(
                post_4a850_files,
                post_4a850_names,
                post_4a850_sources,
                map_entries,
                post_67c60_files,
                post_67c60_names,
                post_67c60_sources,
                (0, True, selected, selected_source, selected_name),
            )
        phase6_transform = _NativePhase6Transform4a8502026(
            phase6_raw_files,
            phase6_raw_names,
            phase6_raw_sources,
            phase6_edges,
            post_4a850_files,
            post_4a850_names,
            post_4a850_sources,
            mapped_reorder,
        )
    else:
        phase6_transform = None
    result = FileSourceSet2026(
        engine,
        source_name,
        hashlib.sha256(source).hexdigest(),
        source,
        selected,
        selected_source,
        selected_name,
        tuple(names),
        tuple(files),
        tuple(sources),
        tuple(output),
        tuple(groups),
        tuple(group_sources),
        tuple(group_names),
        delta,
        has_vector,
        map_entries,
        "retained_clone" if clone_selected else "file",
        selected if clone_selected else None,
        recovery_names,
        recovery_sources,
        recovery_multi_count,
        tuple(recovery_indexes),
    )
    _file_sets[id(result)] = result
    if trajectory and engine._metadata is None and engine._file_sources is None:
        steps = tuple(trajectory)
        issued_stages = False

        def _issue_cold_file_table_stages_2026(
            stage_sources: FileSourceSet2026,
            *,
            steps: tuple[_NativeWaitTimingStep2026, ...],
            phase6_transform: _NativePhase6Transform4a8502026 | None,
        ) -> _NativeColdFileTableStages2026:
            nonlocal issued_stages
            if (
                issued_stages
                or stage_sources is not result
                or steps is not locals_steps
                or phase6_transform is not locals_transform
            ):
                raise ValueError("Cold FILE stage issuer is one-shot and source-bound")
            issued_stages = True

            def output_for(table_files):
                output_files = []
                emitted = set()
                index = 0
                while index < len(table_files):
                    item = table_files[index]
                    group_index = next(
                        (group for member, group in map_entries if member is item),
                        None,
                    )
                    if group_index is None:
                        direct = next(
                            (
                                (start, width, group)
                                for group, (start, width, _whole) in enumerate(groups)
                                if delta and not is_list and start == index
                            ),
                            None,
                        )
                        if direct is None:
                            output_files.append(item)
                        else:
                            _start, width, group = direct
                            output_files.append(groups[group][2])
                            index += width
                            continue
                    elif group_index not in emitted:
                        output_files.append(groups[group_index][2])
                        emitted.add(group_index)
                    index += 1
                return tuple(output_files)

            def stage(
                table_files,
                table_names,
                table_sources,
                pointer,
                pointer_source,
                pointer_name,
            ):
                positions = tuple(
                    index for index, item in enumerate(table_files) if item is pointer
                )
                if len(positions) > 1:
                    raise ValueError("Cold FILE pointer is ambiguous in table")
                retained = not positions
                return replace(
                    result,
                    selected_metadata=pointer,
                    selected_source=pointer_source,
                    selected_name=pointer_name,
                    file_names=tuple(table_names),
                    files=tuple(table_files),
                    file_sources=tuple(table_sources),
                    output_files=output_for(table_files),
                    selection_role="retained_clone" if retained else "file",
                    auxiliary_metadata=pointer if retained else None,
                )

            if locals_transform is None:
                raw_files, raw_names, raw_sources = (
                    result.files,
                    result.file_names,
                    result.file_sources,
                )
            else:
                raw_files = locals_transform.raw_files
                raw_names = locals_transform.raw_names
                raw_sources = locals_transform.raw_sources

            if is_list or suffix == ".cuwc":
                initial_record = json_initial_record
                if initial_record is None:
                    raise ValueError("Cold initial pointer lacks its raw source record")
                initial_pointer = initial_record.metadata
                initial_pointer_source = initial_record.source
                initial_pointer_name = initial_record.source_name
            elif suffix == ".scuw":
                initial_pointer = groups[0][2]
                initial_pointer_source = group_sources[0]
                initial_pointer_name = group_names[0]
            else:
                initial_pointer = result.selected_metadata
                initial_pointer_source = result.selected_source
                initial_pointer_name = result.selected_name

            initial = stage(
                raw_files,
                raw_names,
                raw_sources,
                initial_pointer,
                initial_pointer_source,
                initial_pointer_name,
            )
            if (
                locals_transform is None
                and initial.files == result.files
                and all(
                    a is b for a, b in zip(initial.files, result.files, strict=True)
                )
                and initial.file_names == result.file_names
                and all(
                    a is b
                    for a, b in zip(
                        initial.file_sources, result.file_sources, strict=True
                    )
                )
                and initial.output_files == result.output_files
                and all(
                    a is b
                    for a, b in zip(
                        initial.output_files, result.output_files, strict=True
                    )
                )
                and initial.selected_metadata is result.selected_metadata
                and initial.selected_source is result.selected_source
                and initial.selected_name == result.selected_name
                and initial.selection_role == result.selection_role
                and initial.auxiliary_metadata is result.auxiliary_metadata
            ):
                initial = result

            post_4a850 = None
            post_67c60 = None
            if locals_transform is not None:
                pointer = initial_pointer
                pointer_source = initial_pointer_source
                pointer_name = initial_pointer_name
                for edge in locals_transform.edges:
                    if pointer is edge[3]:
                        pointer = edge[5]
                        pointer_source = edge[5].source_container
                        pointer_name = edge[6]
                post_4a850 = stage(
                    locals_transform.post_4a850_files,
                    locals_transform.post_4a850_names,
                    locals_transform.post_4a850_sources,
                    pointer,
                    pointer_source,
                    pointer_name,
                )
                reorder = locals_transform.mapped_reorder
                if reorder is not None:
                    post_67c60 = stage(
                        reorder.post_67c60_files,
                        reorder.post_67c60_names,
                        reorder.post_67c60_sources,
                        pointer,
                        pointer_source,
                        pointer_name,
                    )
                elif (
                    len(post_4a850.files) == len(result.files)
                    and all(
                        left is right
                        for left, right in zip(
                            post_4a850.files, result.files, strict=True
                        )
                    )
                    and post_4a850.file_names == result.file_names
                    and len(post_4a850.file_sources) == len(result.file_sources)
                    and all(
                        a is b
                        for a, b in zip(
                            post_4a850.file_sources,
                            result.file_sources,
                            strict=True,
                        )
                    )
                    and len(post_4a850.output_files) == len(result.output_files)
                    and all(
                        a is b
                        for a, b in zip(
                            post_4a850.output_files,
                            result.output_files,
                            strict=True,
                        )
                    )
                    and post_4a850.selected_metadata is result.selected_metadata
                    and post_4a850.selected_source is result.selected_source
                    and post_4a850.selected_name == result.selected_name
                    and post_4a850.selection_role == result.selection_role
                    and post_4a850.auxiliary_metadata is result.auxiliary_metadata
                ):
                    post_4a850 = result

            stages = _NativeColdFileTableStages2026(
                initial, post_4a850, post_67c60, result
            )
            for derivative in (initial, post_4a850, post_67c60, result):
                if derivative is not None:
                    _file_sets[id(derivative)] = derivative
            return stages

        locals_steps = steps
        locals_transform = phase6_transform
        table_stages = _issue_cold_file_table_stages_2026(
            result,
            steps=steps,
            phase6_transform=phase6_transform,
        )
        admission = engine._issue_file_wait_timing_admission2026(
            result,
            steps,
            phase6_transform=phase6_transform,
            table_stages=table_stages,
        )
        if any(
            derivative._wait_timing_admission2026 is not admission
            for derivative in (
                table_stages.initial,
                table_stages.post_4a850,
                table_stages.post_67c60,
                table_stages.final,
            )
            if derivative is not None
        ):
            raise ValueError("Cold FILE table derivatives lost their admission")
    return result


def file_calibration_type_2026(
    engine: CUWEngine2026,
    sources: FileSourceSet2026,
    metadata: Native2026Metadata,
    cpu_index: int,
) -> int:
    """34680 selects concrete FILE metadata, then the source-bound profile row."""
    from scripts.calibration_2026 import native2026_node_index, native2026_node_values
    from scripts.programming_2026_common import NativeCallbackLookupError

    validate_file_sources_2026(sources, engine)
    if not any(metadata is item for item in (*sources.files, *sources.output_files)):
        raise ValueError("Calibration type metadata is outside the issued FILE set")
    native2026_cpu_values(metadata, cpu_index)
    contact = metadata.vehicle.get("contacttype", "")
    if contact in ("P5-Unified", "Phase6", "Ethernet"):
        parameters = engine._frontend_parameters
        if parameters is None:
            raise NativeCallbackLookupError()
        parameters.validate_source()
        node = native2026_node_values(
            metadata, native2026_node_index(metadata, cpu_index)
        )
        ethernet = contact == "Ethernet"
        table = parameters.parameter(
            "LogicalAddressTable.ini" if ethernet else "CanIDTable.ini"
        )
        key = node.get("logicaladdress" if ethernet else "diagid", "")
        value = table.long_with_keys("CalibrationType", key, "", "")
        if value is None:
            raise NativeCallbackLookupError()
        return value
    general = engine._general_parameters
    if general is None:
        raise NativeCallbackLookupError()
    return general.long_with_keys(
        metadata.vehicle.get("kindofecu", ""),
        native2026_cpu_values(metadata, 0).get("cputype", ""),
        contact,
        "CalibrationType",
    )


def _outputs(
    engine: CUWEngine2026,
    metadata: Native2026Metadata,
    header: bytes,
    cpu_rows: tuple[bytes, ...],
    *,
    normal: bool,
    sources: FileSourceSet2026 | None = None,
    date_formatter: Callable[[tuple[int, int, int]], bytes] | None,
    cancelled: Callable[[], bool],
) -> tuple[int, bytes, tuple[bytes, ...]]:
    from scripts.calibration_2026 import _file_output_string
    from scripts.programming_2026_common import (
        NativeCallbackLookupError,
        NativeException2026,
        NativePassThruException2026,
    )

    output_files = (metadata,) if sources is None else sources.output_files
    count = sum(native2026_cpu_count(item) for item in output_files)
    if len(cpu_rows) < count:
        raise ValueError("Caller CPU output capacity is smaller than native CPU count")
    output = bytearray(header)
    rows = list(cpu_rows)
    try:
        date = None
        if metadata.date_of_issue_components is not None:
            if date_formatter is None:
                raise ValueError("Captured native OS date formatter required")
            date = native2026_date_presentation(metadata, date_formatter)
        fields = native2026_file_header(metadata, header, date_presentation=date)
        # 5ccf0 writes the five leading strings and count before entering CPU rows.
        output[:0x5F] = fields[:0x5F]
        output[0x64:0x68] = fields[0x64:0x68]
        ordinal = 0
        for item in output_files:
            for cpu in range(native2026_cpu_count(item)):
                if cancelled():
                    raise InterruptedError("CUW file output cancelled")
                row = bytearray(native2026_file_cpu(item, cpu, rows[ordinal]))
                rows[ordinal] = bytes(row)
                if normal:
                    value = (
                        engine.calibration_type(cpu)
                        if sources is None
                        else file_calibration_type_2026(engine, sources, item, cpu)
                    )
                    struct.pack_into("<I", row, 0xBBA8, value & 0xFFFFFFFF)
                    rows[ordinal] = bytes(row)
                ordinal += 1
        struct.pack_into("<I", output, 0x64, count)
        tail = output_files[0]
        _file_output_string(output, 0x68, 0x21, tail.vehicle.get("contacttype", ""))
        output[0x89] = tail.is_controlled_by_scc
        output[0x8A] = tail.is_non_field_fix
        if normal:
            output[0x5F] = engine.file_general_boolean(tail, "EngineTypeFlag")
            output[0x60] = engine.file_general_boolean(
                tail, "FlagToOutputAllAttachedInformation"
            )
            actual_files = (metadata,) if sources is None else sources.files
            struct.pack_into("<I", output, 0x8C, compliance_2026(actual_files))
            output[0x90] = calibration_family_2026(
                tail,
                file_count=len(actual_files)
                if sources is not None and sources.has_file_vector
                else 0,
            )
        else:
            output[0x5F:0x61] = b"\1\1"
            output[0x8C:0x91] = bytes(5)
        struct.pack_into("<I", output, 0x94, tail.format_version)
        engine.emit_file_log(1003, tail.vehicle.get("contacttype", "").encode("latin1"))
        engine.emit_file_log(1002, tail.vehicle.get("kindofecu", "").encode("latin1"))
        for cpu in range(native2026_cpu_count(tail)):
            engine.emit_file_log(
                1001,
                native2026_cpu_values(tail, cpu).get("cputype", "").encode("latin1"),
            )
        engine.emit_file_log(
            2016,
            b"1" if engine.native_delta_active else b"0",
        )
    except (NativeCallbackLookupError, NativeException2026) as error:
        # 5d769..5d7c4 catches native int2 separately and preserves earlier writes.
        status = 1001
        if isinstance(error, NativePassThruException2026):
            status = (
                2001 if error.error == 9999 else 1002 if error.error == 1021 else 1001
            )
        message = (
            b"1(" + str(error.error).encode("ascii") + b")"
            if isinstance(error, NativePassThruException2026)
            else b"3"
        )
        engine.emit_file_log(3002, message)
        return status, bytes(output), tuple(rows)
    return 0, bytes(output), tuple(rows)


def read_reprogramming_data_file_2026(
    engine: CUWEngine2026,
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
    """1005ccf0 byte-input producer and output flow; public region is one based."""
    from scripts.cuw_2026 import CUWEngine2026
    from scripts.programming_2026_common import (
        NativeCallbackLookupError,
        NativeException2026,
        NativePassThruException2026,
    )

    def rejected(error):
        if isinstance(error, NativePassThruException2026):
            engine.emit_file_log(3002, f"1({error.error})".encode("ascii"))
            status = (
                2001 if error.error == 9999 else 1002 if error.error == 1021 else 1001
            )
        else:
            engine.emit_file_log(3002, b"3")
            status = 1001
        return FileReadResult2026(status, caller_header, caller_cpus)

    if type(engine) is not CUWEngine2026:
        raise TypeError("Concrete source-identified CUW2026 engine required")
    if not isinstance(caller_header, bytes) or len(caller_header) != 0x98:
        raise ValueError("Exact immutable native file header output required")
    if type(caller_cpus) is not tuple or any(
        not isinstance(row, bytes) or len(row) != 0xBBAC for row in caller_cpus
    ):
        raise ValueError("Exact immutable native CPU output rows required")
    if type(mode) is not int:
        return FileReadResult2026(1001, caller_header, caller_cpus)
    if type(region) is not int or not 1 <= region <= 4:
        raise ValueError("Public native region must be one-based1..4")
    engine.begin_file_read(region, mode=mode)
    if mode not in (1, 2):
        return FileReadResult2026(1001, caller_header, caller_cpus)
    if cancelled():
        raise InterruptedError("CUW file read cancelled")
    sources = None
    from scripts.calibration_2026 import NativeUSBSource2026, _validate_container_2026
    from scripts.cuw_large import LargeSource2026, validate_large_container_2026

    if type(source) in (LargeSource2026, NativeUSBSource2026):
        if mode == 1:
            try:
                sources = admit_typed_file_source_2026(
                    engine, source_name, source, region=region - 1
                )
                metadata = engine.bind_file_sources(sources)
            except (NativeException2026, NativeCallbackLookupError) as error:
                return rejected(error)
        else:
            if type(source) is LargeSource2026:
                validate_large_container_2026(source.container)
                container = source.container
            else:
                _validate_container_2026(source)
                container = source
            metadata = engine._parser_profile(
                native2026_metadata(container, region=region - 1)
            )
    elif isinstance(source, bytes):
        if mode == 1:
            try:
                sources = admit_file_sources_2026(
                    engine,
                    source_name,
                    source,
                    region=region - 1,
                    source_files=source_files,
                    cancelled=cancelled,
                )
                metadata = engine.bind_file_sources(sources)
            except (NativeException2026, NativeCallbackLookupError) as error:
                return rejected(error)
        else:
            # 331b0 creates an independent parser; recovery output never binds it.
            if PureWindowsPath(source_name).suffix.casefold() == ".scuw":
                from scripts.calibration_2026 import native2026_recovery_header
                from scripts.cuw_2026 import read_file_header

                capture = read_file_header(source)
                if capture.status != 0:
                    raise ValueError("Native recovery compressed header unavailable")
                metadata = native2026_recovery_header(
                    source[: capture.marker_offset],
                    cpu_capacity=engine.common_definitions.num_cpu_maxnum,
                    region=region - 1,
                )
            else:
                try:
                    metadata = engine._parser_profile(
                        native2026_metadata(parse_cuw_2026(source), region=region - 1)
                    )
                except NativeException2026 as error:
                    return rejected(error)
    else:
        raise TypeError("Actual bytes or authenticated native large source required")
    if cancelled():
        raise InterruptedError("CUW file read cancelled")
    status, header, cpus = _outputs(
        engine,
        metadata,
        caller_header,
        caller_cpus,
        normal=mode == 1,
        sources=sources,
        date_formatter=date_formatter,
        cancelled=cancelled,
    )
    if sources is not None:
        if engine.file_sources is not sources:
            raise ValueError("Native FILE source changed during output serialization")
        return FileReadResult2026(
            status,
            header,
            cpus,
            engine.native_delta_active,
            sources.has_file_vector and not sources.composite_contact,
            tuple(item.source_sha256 for item in sources.files),
        )
    return FileReadResult2026(
        status,
        header,
        cpus,
        delta_archive=engine.native_delta_active if mode == 1 else False,
        source_sha256=(
            hashlib.sha256(source).hexdigest()
            if isinstance(source, bytes)
            else metadata.source_sha256,
        ),
    )
