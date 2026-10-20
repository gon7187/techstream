"""CUW2026 public file output composition over authenticated native containers.

OEM code is a static identity input only. No device or OEM executable is opened.
"""

from __future__ import annotations

import configparser
import hashlib
import struct
import weakref
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from pathlib import PureWindowsPath
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

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


@dataclass(frozen=True)
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
                files.append(parse(item))
                names.append(path)
                sources.append(item)
            whole_name = settings.get("wholereprocalfile", {}).get("filename", "")[:259]
            if PureWindowsPath(whole_name).as_posix().casefold() not in members:
                raise _admission_fault(0x3233)
            whole_bytes = members[PureWindowsPath(whole_name).as_posix().casefold()]
            whole = parse(whole_bytes)
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
        else:
            metadata = parse(data)
            files.append(metadata)
            names.append(name)
            sources.append(data)
            output.append(metadata)
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
    if (
        has_vector
        and "Phase6" in contacts
        and (map_entries or not (engine.native_delta_active or delta))
    ):
        from scripts.calibration_2026 import (
            native2026_merge_phase6,
            native2026_node_values,
            native2026_validate_phase6_pair,
        )

        def mapped(metadata):
            return next(
                (group for member, group in map_entries if member is metadata), None
            )

        mapped_phase6 = any(
            item.vehicle.get("contacttype", "") == "Phase6" and mapped(item) is not None
            for item in files
        )
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
                        left = native2026_merge_phase6(left, right)
                    except ValueError as error:
                        if not str(error).startswith("Not combinable:"):
                            raise
                        from scripts.programming_2026_common import NativeException2026

                        raise NativeException2026("Not combinable.") from error
                    files[index] = left
                    recovery_indexes.append((left, left_recovery_index))
                    sources[index] = left.source_container
                    del files[following], sources[following], names[following]
                else:
                    following += 1
            index += 1
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
            # 68190 checks each same-address run using whole-group pointers;
            # it does not merge or rewrite their source-owned map entries.
            index = 0
            while index < len(files):
                item = files[index]
                if item.vehicle.get("contacttype", "") != "Phase6":
                    index += 1
                    continue
                first = native2026_node_values(item)
                candidates = []
                while index < len(files):
                    current = files[index]
                    node = native2026_node_values(current)
                    if any(
                        first.get(name, "") != node.get(name, "")
                        for name in ("diagid", "logicaladdress")
                    ):
                        break
                    group = mapped(current)
                    candidates.append(current if group is None else groups[group][2])
                    index += 1 if group is None else groups[group][1]
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
            except NativeException2026 as error:
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
            except NativeException2026 as error:
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
