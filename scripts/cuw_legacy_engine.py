"""Original CUW executable controller primitives.

These metadata and state primitives implement recovered executable code. They do not authorize
programming, execute a vendor PE, or treat saved recovery as an ECU checkpoint.
"""

from __future__ import annotations

import hashlib
import ntpath
import re
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from types import MappingProxyType
from typing import TYPE_CHECKING, cast

from scripts.calibration_catalog import CalibrationCatalog
from scripts.j2534_2026 import NativeMessage, j2534_indication
from scripts.programming import NativeSavedRecovery, NativeTransportError
from scripts.programming_2026_common import NativeRuntime2026
from scripts.programming_legacy import NativeCPUContext
from scripts.programming_vendor import NativeTransportError as VendorTransportError

if TYPE_CHECKING:
    from scripts.cuw_legacy_recovery import LegacyRecoveryStore
    from scripts.programming import NativeProgrammingChannel

# This reuses host I/O bounds and ownership, not a CUW2026 protocol algorithm.
ExecutableIO = NativeRuntime2026
legacy_indication = j2534_indication
LEGACY_METADATA_VERSIONS = {
    12: (1, 2, 3, 4, 5, 6, 7, 101, 102),
    18: (1, 2, 3, 4, 5, 6, 7, 8, 9, 101, 103, 104, 105, 106, 107, 206),
}


@dataclass
class ExecutableState:
    """Recovered GUI fields; these do not attest ECU state or authorize resume."""

    write_cpu_index: int = 0
    writing: bool = False
    writing_end_block: bool = False
    use_new_software_password: bool = False
    pass_thru_error_code: int = 99
    retry_mode: bool = False
    recovery_retry: bool = False
    retry_input: bool = False
    recovery_persistence_active: bool = False
    native_flag_ed6: bool = False
    native_flag_ed7: bool = False
    native_flag_ed8: bool = False
    native_flag_6e4: bool = False
    native_flag_2c: bool = False
    target_indices: tuple[int, ...] = (0xFFFFFFFF,) * 4
    cpu_type_overrides: dict[int, str] = field(default_factory=dict)
    native_flag_ed5: bool = False
    native_cpu_type_ee0: str = ""
    native_value_e60: int = 0
    native_value_e64: int = 0

    def validate(self) -> None:
        if (
            type(self.write_cpu_index) is not int
            or not 0 <= self.write_cpu_index <= 128
            or type(self.pass_thru_error_code) is not int
            or not 0 <= self.pass_thru_error_code <= 255
            or not isinstance(self.cpu_type_overrides, dict)
            or type(self.target_indices) is not tuple
            or len(self.target_indices) != 4
            or any(
                type(index) is not int or not 0 <= index <= 0xFFFFFFFF
                for index in self.target_indices
            )
            or len(self.cpu_type_overrides) > 128
            or not isinstance(self.native_cpu_type_ee0, str)
            or len(self.native_cpu_type_ee0) > 128
            or not self.native_cpu_type_ee0.isascii()
            or "\x00" in self.native_cpu_type_ee0
            or any(
                type(value) is not int or not 0 <= value <= 0xFFFFFFFF
                for value in (self.native_value_e60, self.native_value_e64)
            )
            or any(
                type(index) is not int
                or not 0 <= index < 128
                or not isinstance(value, str)
                or len(value) > 128
                or not value.isascii()
                or "\x00" in value
                for index, value in self.cpu_type_overrides.items()
            )
            or any(
                type(value) is not bool
                for value in (
                    self.writing,
                    self.writing_end_block,
                    self.use_new_software_password,
                    self.retry_mode,
                    self.recovery_retry,
                    self.retry_input,
                    self.recovery_persistence_active,
                    self.native_flag_ed6,
                    self.native_flag_ed5,
                    self.native_flag_ed7,
                    self.native_flag_ed8,
                    self.native_flag_6e4,
                    self.native_flag_2c,
                )
            )
        ):
            raise ValueError(
                "Native executable recovery fields require CPU index and BOOLs"
            )

    def __post_init__(self) -> None:
        self.validate()


@dataclass(frozen=True)
class ExecutableContext:
    """Source-selected imported CPU data shared by concrete executable families."""

    build: int
    controller: str
    native: NativeCPUContext = field(repr=False)
    cpus: tuple[NativeCPUContext, ...] = field(repr=False)
    container_sha256: str
    state: ExecutableState = field(default_factory=ExecutableState, repr=False)
    recovery: NativeSavedRecovery | None = field(default=None, repr=False)
    attachments: Mapping[str, bytes] = field(default_factory=dict, repr=False)
    observations: Mapping[str, object] = field(default_factory=dict, repr=False)
    cpu_types: tuple[str, ...] = ()
    catalog: CalibrationCatalog | None = field(default=None, repr=False)
    constructor_read_timeout: int | None = None
    source_cpu_indices: tuple[int, ...] = ()
    image_source_cpu_indices: tuple[int, ...] = ()
    recovery_store: LegacyRecoveryStore | None = field(
        default=None, repr=False, compare=False
    )
    kind_of_cal: Mapping[str, str] = field(default_factory=dict, repr=False)
    ram_target_passwords: Mapping[tuple[int, int], int] = field(
        default_factory=dict, repr=False
    )
    constructor_send_timeout: int | None = None

    def __post_init__(self) -> None:
        if (
            type(self.build) is not int
            or self.build not in (12, 18)
            or not isinstance(self.controller, str)
            or not 0 < len(self.controller) <= 96
            or not self.controller.isascii()
            or not self.controller.isidentifier()
            or not isinstance(self.native, NativeCPUContext)
            or self.native.metadata_version not in LEGACY_METADATA_VERSIONS[self.build]
            or not isinstance(self.cpus, tuple)
            or not 0 < len(self.cpus) <= 128
            or any(not isinstance(cpu, NativeCPUContext) for cpu in self.cpus)
            or not any(cpu is self.native for cpu in self.cpus)
            or len({cpu.selected.index for cpu in self.cpus}) != len(self.cpus)
            or not isinstance(self.container_sha256, str)
            or len(self.container_sha256) != 64
            or any(char not in "0123456789abcdef" for char in self.container_sha256)
            or not isinstance(self.state, ExecutableState)
            or (
                self.catalog is not None
                and not isinstance(self.catalog, CalibrationCatalog)
            )
            or (
                self.recovery is not None
                and not isinstance(self.recovery, NativeSavedRecovery)
            )
        ):
            raise ValueError("Bounded source-selected executable context required")
        self.state.validate()
        if (
            not isinstance(self.ram_target_passwords, Mapping)
            or len(self.ram_target_passwords) > 128
            or any(
                type(key) is not tuple
                or len(key) != 2
                or any(type(part) is not int for part in key)
                or not 0 <= key[0] < len(self.native.cpus)
                or not 0 <= key[1] < 32
                or type(value) is not int
                or not 0 <= value <= 0xFFFFFFFF
                for key, value in self.ram_target_passwords.items()
            )
        ):
            raise ValueError(
                "Native appended target DWORDs require actual CPU/target positions"
            )
        object.__setattr__(
            self,
            "ram_target_passwords",
            MappingProxyType(dict(self.ram_target_passwords)),
        )
        if self.recovery_store is not None:
            from scripts.cuw_legacy_recovery import LegacyRecoveryStore

            if (
                not isinstance(self.recovery_store, LegacyRecoveryStore)
                or self.recovery_store.state is not self.state
                or self.recovery_store.build != self.build
                or self.recovery_store.container_sha256 != self.container_sha256
            ):
                raise ValueError(
                    "Concrete recovery store belongs to another native context"
                )
        for indices in (self.source_cpu_indices, self.image_source_cpu_indices):
            if not isinstance(indices, tuple) or (
                indices
                and (
                    len(indices) != len(self.native.cpus)
                    or any(
                        type(index) is not int or not 0 <= index < 128
                        for index in indices
                    )
                )
            ):
                raise ValueError(
                    "Compacted CPU/image source mapping must retain native positions"
                )
        if bool(self.source_cpu_indices) != bool(self.image_source_cpu_indices) or (
            self.source_cpu_indices
            and len(set(self.source_cpu_indices)) != len(self.source_cpu_indices)
        ):
            raise ValueError("Compacted source CPU mapping must be unique and complete")
        if self.constructor_read_timeout is not None and (
            type(self.constructor_read_timeout) is not int
            or not 0 <= self.constructor_read_timeout <= 0xFFFFFFFF
        ):
            raise ValueError("Native controller timeout snapshot must be a DWORD")
        if self.constructor_send_timeout is not None and (
            type(self.constructor_send_timeout) is not int
            or not 0 <= self.constructor_send_timeout <= 0xFFFFFFFF
        ):
            raise ValueError("Native controller send timeout snapshot must be a DWORD")
        if any(
            index >= len(self.native.cpus) for index in self.state.cpu_type_overrides
        ):
            raise ValueError("Native CPU type mutation outside imported CPU table")
        if not isinstance(self.cpu_types, tuple) or (
            self.cpu_types
            and (
                len(self.cpu_types) != len(self.native.cpus)
                or any(
                    not isinstance(value, str) or len(value) > 128 or "\x00" in value
                    for value in self.cpu_types
                )
            )
        ):
            raise ValueError(
                "Normalized CPU types must retain the original CPU index order"
            )
        if self.state.write_cpu_index not in {cpu.selected.index for cpu in self.cpus}:
            raise ValueError(
                "Recovery CPU index absent from imported executable context"
            )
        if (
            self.recovery is not None
            and self.recovery.calibration_sha256 != self.container_sha256
        ):
            raise ValueError("Saved recovery belongs to another imported calibration")
        for name in ("attachments", "observations", "kind_of_cal"):
            values = getattr(self, name)
            if (
                not isinstance(values, Mapping)
                or len(values) > 4096
                or any(
                    not isinstance(key, str) or not 0 < len(key) <= 256 or "\x00" in key
                    for key in values
                )
            ):
                raise ValueError("Bounded named executable inputs required")
            if name == "attachments" and any(
                not isinstance(value, bytes) or len(value) > 64 * 1024 * 1024
                for value in values.values()
            ):
                raise ValueError("Explicit bounded immutable attachment bytes required")
            if name == "kind_of_cal" and any(
                not isinstance(value, str) or len(value) > 1024 or "\x00" in value
                for value in values.values()
            ):
                raise ValueError("Imported bounded KindOfCal strings required")
            object.__setattr__(self, name, MappingProxyType(dict(values)))


@dataclass(frozen=True)
class ExecutableStringContext:
    """Actual Windows ACP/user locale and TStringList CaseSensitive snapshot."""

    code_page: int
    user_default_lcid: int
    case_sensitive: bool

    def __post_init__(self) -> None:
        if (
            type(self.code_page) is not int
            or self.code_page not in (932, 1252)
            or type(self.user_default_lcid) is not int
            or self.user_default_lcid not in (0x409, 0x411)
            or type(self.case_sensitive) is not bool
        ):
            raise ValueError(
                "Explicit supported native ACP, effective user locale and case flag required"
            )

    def equal(self, left: str, right: str) -> bool:
        # CompareStringA(LOCALE_USER_DEFAULT) is bounded to the proven ASCII CID domain.
        for value in (left, right):
            if (
                not isinstance(value, str)
                or len(value) > 128
                or any(
                    not (
                        "A" <= char <= "Z"
                        or "a" <= char <= "z"
                        or "0" <= char <= "9"
                        or char in "-_"
                    )
                    for char in value
                )
            ):
                raise ValueError(
                    "Native CID collation outside bounded ASCII identity domain"
                )
        return left == right if self.case_sensitive else left.upper() == right.upper()


_COMPACTION_ISSUER = object()


@dataclass(frozen=True)
class ExecutableTargets:
    """47c808/44f93c outputs; native_result retains the opaque manager flag."""

    excluded_cids: tuple[str, ...]
    native_result: bool


def _executable_target_rows(native: NativeCPUContext) -> tuple[str, ...]:
    text = native.selected.values.get("numberoftargets", "")
    if not text.isascii() or not text.isdecimal() or not 0 <= int(text) <= 32:
        raise ValueError("Imported target table exceeds native capacity32")
    rows = tuple(
        native.selected.values.get(f"{index + 1:02}_targetcalibration", "")
        for index in range(int(text))
    )
    if any(not isinstance(row, str) or len(row) > 128 or "\x00" in row for row in rows):
        raise ValueError("Bounded native target calibration rows required")
    return rows


def initialize_executable_targets(
    context: ExecutableContext, *, strings: ExecutableStringContext
) -> ExecutableTargets:
    """Produce ordinary native target indices and NewCID exclusions from import.

    The result BOOL deliberately keeps the source WORK+2c/12+28 meaning opaque;
    it is neither a device attestation nor a programming-success result.
    """
    if not isinstance(context, ExecutableContext) or not isinstance(
        strings, ExecutableStringContext
    ):
        raise TypeError("Imported native context and actual string context required")
    context.state.validate()
    observed = context.observations.get("observed_cids")
    if (
        context.recovery is not None
        or context.ram_target_passwords
        or context.source_cpu_indices
        or context.recovery_store is not None
        or context.state.writing
        or context.state.recovery_persistence_active
        or type(observed) is not tuple
        or len(observed) > 4096
        or not 0 < len(context.cpus) <= 4
        or tuple(row.selected.index for row in context.cpus)
        != tuple(range(len(context.native.cpus)))
        or any(
            row.selected != context.native.cpus[index]
            or row.cpus != context.native.cpus
            or row.metadata_version != context.native.metadata_version
            for index, row in enumerate(context.cpus)
        )
        or context.native.base_metadata.get("contact_type")
        not in ("CAN", "P5-CAN", "SIL")
        or context.native.metadata_version not in range(1, 10)
        or any(
            file.values.get("dataformat") in ("03", "04")
            for cpu in context.native.cpus
            for file in cpu.files
        )
    ):
        raise ValueError(
            "Ordinary complete imported target table and actual CID observations required"
        )
    new_cids = tuple(row.selected.values.get("newcid", "") for row in context.cpus)
    rows = tuple(_executable_target_rows(row) for row in context.cpus)
    for cid in (*observed, *new_cids, *(value for row in rows for value in row)):
        strings.equal(cid, cid)
    initial_result = context.state.native_flag_2c
    if (
        ntpath.splitext(context.native.cpus[0].values.get("cpuimagename", ""))[
            1
        ].lower()
        == ".vbf"
    ):
        hardware = context.observations.get("native_hardware_98")
        count = context.native.cpus[0].values.get("numberoftargethardwares", "0")
        if (
            type(hardware) is not str
            or len(hardware) > 128
            or not hardware.isascii()
            or "\x00" in hardware
            or not count.isascii()
            or not count.isdecimal()
            or not 0 <= int(count) <= 99
        ):
            raise ValueError(
                "Actual native hardware field18+98/12+60 and imported hardware rows required"
            )
        targets = tuple(
            context.native.cpus[0].values.get(f"{index:02}_targethardware", "")
            for index in range(1, int(count) + 1)
        )
        if any(
            not target.isascii() or len(target) > 128 or "\x00" in target
            for target in targets
        ):
            raise ValueError("Bounded native ASCII hardware rows required")
        # 47df18/4503cc compares AnsiString exactly, not TStringList IndexOf.
        initial_result = initial_result and hardware in targets
        if not (initial_result and observed):
            context.state.target_indices = (0, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF)
            return ExecutableTargets((), initial_result)

    # CUW18 reads integer1 only; +11 is read only when +10 is true.
    def kind_flag(key: str) -> bool:
        import re

        value = context.kind_of_cal.get(key, "0").strip()
        if (
            re.fullmatch(r"[+-]?[0-9]{1,10}", value) is None
            or not -(2**31) <= int(value) < 2**31
        ):
            raise ValueError("Native KindOfCal requires a bounded decimal integer")
        return int(value) == 1

    controlled = context.build == 18 and kind_flag("iscontrolledbyscc")
    blank = controlled and kind_flag("isblankecu")
    if blank:
        indices = (
            (0,) * len(rows)
            if context.state.native_flag_6e4
            else (0xFFFFFFFF,) * len(rows)
        )
        context.state.target_indices = indices + (0xFFFFFFFF,) * (4 - len(rows))
        return ExecutableTargets((), context.state.native_flag_6e4)
    if controlled and context.state.native_flag_6e4:
        context.state.target_indices = (0xFFFFFFFF,) * 4
        return ExecutableTargets((), False)
    indices = tuple(
        next(
            (
                index
                for index, cid in enumerate(row)
                if any(strings.equal(cid, actual) for actual in observed)
            ),
            0xFFFFFFFF,
        )
        for row in rows
    )
    excluded = [
        cid for cid, index in zip(new_cids, indices, strict=True) if index == 0xFFFFFFFF
    ]
    native_result = initial_result and len(observed) >= len(rows)
    if len(excluded) == len(rows):
        native_result = False
    # Calibration+74 (12+6c) is derived by exact AnsiString comparison on import.
    all_new_cids_are_targets = context.native.metadata_version >= 2 and all(
        cid in row for cid, row in zip(new_cids, rows, strict=True)
    )
    if native_result and not all_new_cids_are_targets:
        for cid in new_cids:
            if any(strings.equal(cid, actual) for actual in observed) and not any(
                strings.equal(cid, item) for item in excluded
            ):
                excluded.append(cid)
        if len(excluded) == len(rows):
            native_result = False
    context.state.target_indices = indices + (0xFFFFFFFF,) * (4 - len(rows))
    return ExecutableTargets(tuple(excluded), native_result)


@dataclass(frozen=True)
class ExecutableCompaction:
    """47d3e4/44fe18 remaining-CID producer bound to one imported RAM snapshot."""

    source_cpu_indices: tuple[int, ...]
    image_source_cpu_indices: tuple[int, ...]
    _context: ExecutableContext = field(repr=False, compare=False)
    _cpu_types: tuple[str, ...] = field(repr=False)
    _overrides: tuple[tuple[int, str], ...] = field(repr=False)
    _target_indices: tuple[int, ...] = field(repr=False)
    _excluded_cids: tuple[str, ...] = field(repr=False)
    _strings: ExecutableStringContext = field(repr=False)
    _issuer: object = field(repr=False, compare=False)


def produce_executable_compaction(
    context: ExecutableContext,
    excluded_cids: tuple[str, ...],
    *,
    strings: ExecutableStringContext,
) -> ExecutableCompaction:
    """Derive ordinary native CPU/image order from imported NewCID and exclusions.

    Exclusions are the actual manager +58 vector (12 +30), not selected CPU IDs.
    The preceding initial-target/error-latch producer remains a separate flow.
    """
    if not isinstance(context, ExecutableContext) or not isinstance(
        strings, ExecutableStringContext
    ):
        raise TypeError(
            "Imported native context and actual string-comparison context required"
        )
    context.state.validate()
    if (
        context.recovery is not None
        or context.ram_target_passwords
        or context.recovery_store is not None
        or context.source_cpu_indices
        or context.state.writing
        or context.state.recovery_persistence_active
        or context.state.retry_mode
    ):
        raise ValueError(
            "Saved or already compacted native state must not be recompacted"
        )
    if any(
        file.values.get("dataformat") in ("03", "04")
        for cpu in context.native.cpus
        for file in cpu.files
    ):
        raise ValueError("Native03/04 file conversion requires its actual producer")
    if context.state.native_flag_6e4 or (
        context.native.metadata_version != 9
        and ntpath.splitext(context.native.cpus[0].values.get("cpuimagename", ""))[
            1
        ].lower()
        == ".vbf"
    ):
        raise ValueError(
            "Native standard factory bypasses CPU compaction in this state"
        )
    if (
        type(excluded_cids) is not tuple
        or len(excluded_cids) > 4096
        or not context.cpu_types
        or not 0 < len(context.cpus) <= 4
        or tuple(row.selected.index for row in context.cpus)
        != tuple(range(len(context.native.cpus)))
        or any(
            row.selected != context.native.cpus[index]
            or row.cpus != context.native.cpus
            or row.metadata_version != context.native.metadata_version
            for index, row in enumerate(context.cpus)
        )
        or context.native.base_metadata.get("contact_type")
        not in ("CAN", "P5-CAN", "SIL")
    ):
        raise ValueError(
            "Ordinary complete native CPU table and exclusion vector required"
        )
    new_cids = tuple(row.selected.values.get("newcid", "") for row in context.cpus)
    for cid in (*new_cids, *excluded_cids):
        strings.equal(cid, cid)
    # 47d3e4 first builds the source-order list, then deletes every excluded match.
    remaining = tuple(
        cid
        for cid in new_cids
        if not any(strings.equal(cid, excluded) for excluded in excluded_cids)
    )
    sources = tuple(
        index
        for index, cid in enumerate(new_cids)
        if any(strings.equal(cid, remaining_cid) for remaining_cid in remaining)
    )
    if not sources:
        raise ValueError("Native compaction leaves no programmable CPU")
    if context.native.metadata_version == 9:
        # 414a14 iterates remaining strings and selects the first exact source CID.
        images = tuple(new_cids.index(cid) for cid in remaining)
    else:
        images = sources
    if len(images) != len(sources):
        raise ValueError("Native CPU/image compaction cardinality differs")
    return ExecutableCompaction(
        sources,
        images,
        context,
        context.cpu_types,
        tuple(sorted(context.state.cpu_type_overrides.items())),
        context.state.target_indices,
        excluded_cids,
        strings,
        _COMPACTION_ISSUER,
    )


def compact_executable_context(
    context: ExecutableContext, plan: ExecutableCompaction
) -> ExecutableContext:
    """40b4e4/4145a0/414a14 +40af00: compact native rows and retain source indices."""
    if isinstance(context, ExecutableContext):
        context.state.validate()
    if (
        not isinstance(context, ExecutableContext)
        or not isinstance(plan, ExecutableCompaction)
        or plan._issuer is not _COMPACTION_ISSUER
        or plan._context is not context
        or plan._cpu_types != context.cpu_types
        or plan._overrides != tuple(sorted(context.state.cpu_type_overrides.items()))
        or plan._target_indices != context.state.target_indices
        or context.recovery is not None
        or context.source_cpu_indices
    ):
        raise ValueError("Fresh source-issued normal native compaction plan required")
    expected = produce_executable_compaction(
        context, plan._excluded_cids, strings=plan._strings
    )
    if (plan.source_cpu_indices, plan.image_source_cpu_indices) != (
        expected.source_cpu_indices,
        expected.image_source_cpu_indices,
    ):
        raise ValueError(
            "Compaction positions differ from the actual imported producer"
        )
    source_rows = context.cpus
    cpus = []
    for index, (source, image_source) in enumerate(
        zip(plan.source_cpu_indices, plan.image_source_cpu_indices, strict=True)
    ):
        metadata = source_rows[source].selected
        image = source_rows[image_source].selected
        if len(metadata.files) != len(image.files):
            raise ValueError(
                "Native compacted file group exceeds associated CPU geometry"
            )
        cpus.append(
            replace(
                metadata,
                index=index,
                image=image.image,
                flash_code=image.flash_code,
                files=image.files,
            )
        )
    native_cpus = tuple(cpus)
    first = source_rows[plan.source_cpu_indices[0]]
    first_image = source_rows[plan.image_source_cpu_indices[0]].image
    cpu_types = tuple(context.cpu_types[source] for source in plan.source_cpu_indices)
    base = dict(first.base_metadata)
    base["cpu_type"] = context.state.cpu_type_overrides.get(
        plan.source_cpu_indices[0], cpu_types[0]
    )
    rows = tuple(
        replace(
            source_rows[source],
            selected=native_cpus[index],
            cpus=native_cpus,
            base_metadata=MappingProxyType(base),
            base_parameters=executable_parameters(context, plan.source_cpu_indices[0]),
            image=source_rows[image_source].image,
            first_image=first_image,
        )
        for index, (source, image_source) in enumerate(
            zip(plan.source_cpu_indices, plan.image_source_cpu_indices, strict=True)
        )
    )
    target_indices = [0xFFFFFFFF] * 4
    for source, row in enumerate(source_rows):
        for index, remaining_source in enumerate(plan.source_cpu_indices):
            if plan._strings.equal(
                row.selected.values.get("newcid", ""),
                source_rows[remaining_source].selected.values.get("newcid", ""),
            ):
                # IndexOf selects the first duplicate; later source CPUs overwrite it.
                target_indices[index] = context.state.target_indices[source]
                break
    state = replace(
        context.state,
        write_cpu_index=0,
        native_cpu_type_ee0=context.state.native_cpu_type_ee0
        or executable_cpu_type(context, 0),
        target_indices=tuple(target_indices),
        cpu_type_overrides={
            index: context.state.cpu_type_overrides[source]
            for index, source in enumerate(plan.source_cpu_indices)
            if source in context.state.cpu_type_overrides
        },
    )
    current_type = state.cpu_type_overrides.get(0, cpu_types[0])
    controller = select_executable_controller(
        base["contact_type"],
        base["kind_of_ecu"],
        current_type,
        current_type,
        native_flag_ed4=cast(bool | None, context.observations.get("native_flag_ed4")),
    )
    return replace(
        context,
        controller=controller,
        native=rows[0],
        cpus=rows,
        state=state,
        cpu_types=cpu_types,
        source_cpu_indices=plan.source_cpu_indices,
        image_source_cpu_indices=plan.image_source_cpu_indices,
    )


def legacy_recovery_password_state(
    writing_end_block: bool, native_mode_78: int, previous: bool
) -> bool:
    """Cuw12 444ecc / Cuw18 46cab0: update UseNewSoftwarePassword through controller field +8c.

    Native +78 is retained as an opaque DWORD until its producer is reconciled.
    This is a boolean state transition, never a transfer offset or block cursor.
    """
    if (
        type(writing_end_block) is not bool
        or type(previous) is not bool
        or type(native_mode_78) is not int
        or not 0 <= native_mode_78 <= 0xFFFFFFFF
    ):
        raise ValueError("Native password state requires two BOOLs and a DWORD")
    return writing_end_block or (native_mode_78 == 7 and not previous)


def legacy_messages(result: object) -> tuple[NativeMessage, ...]:
    """Retain raw PASSTHRU_MSG fields, including RxStatus, at the I/O boundary."""
    if not isinstance(result, (tuple, list)) or len(result) > 4096:
        raise ValueError("Bounded native message array required")
    fields = {
        "protocol_id",
        "data",
        "rx_status",
        "tx_flags",
        "timestamp",
        "extra_data_index",
    }
    messages = []
    for item in result:
        if isinstance(item, NativeMessage):
            messages.append(item)
        elif isinstance(item, Mapping) and set(item) == fields:
            messages.append(NativeMessage(**dict(item)))
        else:
            raise ValueError(
                "Complete native messages required; bytes alone lose RxStatus"
            )
    return tuple(messages)


LEGACY_EXECUTABLE_SHA256 = {
    12: "9a5d508691edb697b7d5fd42dc4495b4ad9e4ffc64eccf518da2e5ff2c47476d",
    18: "97f7b9302a6090e2715ca6c9713aecc73404d6c0f75aede2dd52f09bd201074b",
}
LEGACY_MMC_GETTER_SHA256 = {
    12: "13f95b543361d686d40e17ddbb4e515779c050ac1ff04d90de274e75c575ee93",
    18: "385ab6523512ca0cf4fa97e4cb8f65a81bc4ebbe7042f15efae4ed3e6149cc9f",
}
_MMC_CID_ISSUER = object()


def legacy_executable_bytes(context: ExecutableContext) -> bytes:
    """Admit only explicitly supplied original executable bytes for static reads."""
    if not isinstance(context, ExecutableContext):
        raise TypeError("Source-selected executable context required")
    data = context.attachments.get("legacy_executable")
    if (
        not isinstance(data, bytes)
        or hashlib.sha256(data).hexdigest() != LEGACY_EXECUTABLE_SHA256[context.build]
    ):
        raise ValueError(
            "Explicit original CUW executable matching selected build required"
        )
    return data


class ExecutableImage:
    """File-backed PE virtual-address reads from one admitted immutable executable."""

    def __init__(self, context: ExecutableContext):
        self.data = legacy_executable_bytes(context)
        pe = int.from_bytes(self.data[60:64], "little")
        self.image_base = int.from_bytes(self.data[pe + 52 : pe + 56], "little")
        count = int.from_bytes(self.data[pe + 6 : pe + 8], "little")
        start = pe + 24 + int.from_bytes(self.data[pe + 20 : pe + 22], "little")
        self.sections = tuple(
            (
                int.from_bytes(self.data[row + 12 : row + 16], "little"),
                int.from_bytes(self.data[row + 16 : row + 20], "little"),
                int.from_bytes(self.data[row + 20 : row + 24], "little"),
            )
            for row in range(start, start + 40 * count, 40)
        )

    def read(self, address: int, size: int) -> bytes:
        if (
            type(address) is not int
            or type(size) is not int
            or not 0 <= address <= 0xFFFFFFFF
            or not 0 <= size <= 64 * 1024 * 1024
            or address + size > 2**32
        ):
            raise ValueError("Bounded native virtual address span required")
        rva = address - self.image_base
        offsets = [
            offset + rva - start
            for start, length, offset in self.sections
            if start <= rva and size <= length and rva - start <= length - size
        ]
        if len(offsets) != 1:
            raise ValueError("Native virtual span is not uniquely file-backed")
        return self.data[offsets[0] : offsets[0] + size]


def _executable_getter_uses_dll(context: ExecutableContext) -> bool:
    if not isinstance(context, ExecutableContext):
        raise TypeError("Imported original executable context required")
    switch = context.native.base_parameters.get(
        "FlagToUseCIDGetterAndFlashWriterDLL", ""
    )
    if switch:
        if not re.fullmatch(r"[ \t]*[+-]?[0-9]{1,10}", switch):
            raise ValueError("Unsupported native getter DLL switch spelling")
        value = int(switch, 10)
        if not -0x80000000 <= value <= 0x7FFFFFFF:
            raise ValueError("Native getter DLL switch exceeds bounded LONG")
        return value != 0
    return False


def require_executable_standard_getter(
    context: ExecutableContext, expected_name: str
) -> None:
    """Admit the generic serial getter selected at 18:473900 / 12:44ad8c.

    The catalog DLL switch precedes this factory's local classes. Numeric switch
    text is bounded to complete decimal LONGs; other native strtol spellings are
    an unsupported input boundary, rather than an assumed false switch.
    """
    if expected_name != "CSilCIDGetter":
        raise NotImplementedError("This getter factory branch is not implemented")
    if _executable_getter_uses_dll(context):
        raise ValueError("Actual catalog selects the DLL CID getter")
    base = context.native.base_metadata
    if (
        base["contact_type"] != "SIL"
        or base["kind_of_ecu"] in ("11", "37", "30", "8", "63")
        or executable_cpu_type(context, 0) in ("57", "58", "59", "60")
    ):
        raise ValueError("Actual factory selects a different CID getter")


@dataclass(frozen=True)
class ExecutableMMCCIDs:
    """Issued MMC getter output, retaining hardware/CID prefixes on native error."""

    build: int
    container_sha256: str
    module_sha256: str
    hardware: bytes | None = field(repr=False)
    cids: tuple[bytes, ...] = field(repr=False)
    native_state: str
    native_error_domain: str | None
    native_error_code: int | None
    native_error_text: str | None = field(repr=False)
    diagnostic_response: bytes | None = field(repr=False)
    _context: ExecutableContext = field(repr=False, compare=False)
    _channel: object = field(repr=False, compare=False)
    _issuer: object = field(repr=False, compare=False)
    _issued_payload: tuple = field(repr=False, compare=False)

    def validate(self, context: ExecutableContext) -> None:
        legacy_executable_bytes(context)
        payload = tuple(
            getattr(self, name)
            for name in (
                "build",
                "container_sha256",
                "module_sha256",
                "hardware",
                "cids",
                "native_state",
                "native_error_domain",
                "native_error_code",
                "native_error_text",
                "diagnostic_response",
            )
        )
        if (
            self._issuer is not _MMC_CID_ISSUER
            or self._context is not context
            or self.build != context.build
            or self.container_sha256 != context.container_sha256
            or self.module_sha256 != LEGACY_MMC_GETTER_SHA256[context.build]
            or payload != self._issued_payload
        ):
            raise ValueError(
                "MMC CID result must be issued by this exact source context"
            )


def discover_executable_mmc_cids(
    context: ExecutableContext, channel: NativeProgrammingChannel
) -> ExecutableMMCCIDs:
    """Run the real MMC query on the source-selected lifecycle owned by caller27.

    The caller opens protocol6 and its actual source-derived address/filter;
    this wrapper does not replace those lifecycle operations with a callback.
    """
    from scripts.programming_vendor import VendorP5Channel, vendor_get_cid

    legacy_executable_bytes(context)
    module = context.attachments.get("legacy_mmc_cid_getter")
    if (
        not _executable_getter_uses_dll(context)
        or context.native.base_parameters.get("DLLFileNameForGetCID")
        != "TCUWCanMMCCIDGetter.dll"
        or not isinstance(module, bytes)
        or hashlib.sha256(module).hexdigest() != LEGACY_MMC_GETTER_SHA256[context.build]
        or not isinstance(channel, VendorP5Channel)
        or channel.minimum_response_timeout_ms != 5000
    ):
        raise ValueError("Actual original MMC getter, catalog and P5 channel required")
    native = vendor_get_cid(channel, "MMC", native_build=context.build)
    diagnostic = native.get("diagnostic_response_hex")
    payload = (
        context.build,
        context.container_sha256,
        LEGACY_MMC_GETTER_SHA256[context.build],
        native.get("identifier_f111"),
        tuple(native.get("identifiers", ())),
        native["state"],
        native.get("native_error_domain"),
        native.get("native_error_code"),
        native.get("error"),
        bytes.fromhex(diagnostic) if diagnostic is not None else None,
    )
    return ExecutableMMCCIDs(*payload, context, channel, _MMC_CID_ISSUER, payload)


def publish_executable_mmc_cids(
    context: ExecutableContext, result: ExecutableMMCCIDs
) -> ExecutableContext:
    """Publish the actual MMC hardware string and normal software-CID vector."""
    if not isinstance(result, ExecutableMMCCIDs):
        raise TypeError("Source-issued original MMC getter result required")
    result.validate(context)
    context.state.validate()
    if (
        result.native_state != "read_completed"
        or result.hardware is None
        or context.recovery is not None
        or context.recovery_store is not None
        or context.source_cpu_indices
        or context.ram_target_passwords
        or context.state.target_indices != (0xFFFFFFFF,) * 4
        or context.state.writing
        or context.state.recovery_persistence_active
        or "legacy_mmc_cid_result" in context.observations
    ):
        raise ValueError("Normal MMC getter and fresh native target RAM required")
    observations = dict(context.observations)
    observations.update(
        native_hardware_98=result.hardware.decode("ascii"),
        observed_cids=tuple(cid.decode("ascii") for cid in result.cids),
        legacy_mmc_cid_result=result,
    )
    return replace(context, observations=observations)


def publish_executable_sil_cids(
    context: ExecutableContext, result: object
) -> ExecutableContext:
    """Publish the normal getter's CID list before fresh target selection.

    Native error and termination paths need their separate manager latch port;
    this entrypoint deliberately admits only the zero-status normal branch.
    """
    from scripts.cuw_legacy_sil import SilCIDResult

    require_executable_standard_getter(context, "CSilCIDGetter")
    if not isinstance(result, SilCIDResult):
        raise TypeError("Source-issued original serial CID result required")
    result.validate(context)
    context.state.validate()
    if (
        context.recovery is not None
        or context.recovery_store is not None
        or context.source_cpu_indices
        or context.ram_target_passwords
        or context.state.target_indices != (0xFFFFFFFF,) * 4
        or context.state.writing
        or context.state.recovery_persistence_active
        or context.state.retry_mode
        or "legacy_sil_cid_result" in context.observations
    ):
        raise ValueError("CID publication requires fresh original target RAM")
    if (
        result.terminated
        or result.native_value_d68
        or result.native_value_d70
        or result.native_completion_pair != (0x48, 0x4C)
    ):
        raise ValueError("Native getter error/termination manager branch is not ported")
    observations = dict(context.observations)
    observations["observed_cids"] = result.cids
    observations["legacy_sil_cid_result"] = result
    return replace(context, observations=observations)


def select_executable_controller(
    contact_type: str,
    kind_of_ecu: str,
    first_cpu_type: str,
    selected_cpu_type: str,
    *,
    native_flag_ed4: bool | None = None,
) -> str:
    """Cuw18 VA47623c ordered standard-flow class factory.

    Inputs are native metadata strings, including historical conversions by the
    CUW parser. The separate TechVim flow factory is not selected by these rows.
    """
    if any(
        not isinstance(value, str) or len(value) > 128 or "\x00" in value
        for value in (contact_type, kind_of_ecu, first_cpu_type, selected_cpu_type)
    ) or (native_flag_ed4 is not None and type(native_flag_ed4) is not bool):
        raise ValueError("Bounded literal native metadata and optional BOOL required")
    if contact_type == "SIL":
        if kind_of_ecu in ("8", "11"):
            return "CSilDCMPRLFlashWriter"
        if selected_cpu_type == "17":
            return "CSilM16CFlashWriter"
        if first_cpu_type in ("57", "58", "59", "60"):
            return "CSilEMPS_V850E_PS1_2FlashWriter"
        if kind_of_ecu in ("37", "63"):
            return "CSilOccupantDetectionFlashWriter"
        return "CSilFlashWriter"
    if contact_type == "P5-CAN":
        return "CP5CanFlashWriter"
    if contact_type != "CAN":
        raise ValueError("Native standard-flow factory has no matching contact type")
    if kind_of_ecu == "13" and first_cpu_type == "56":
        return "CCanEMPS_V850E_PS2FlashWriter"
    if kind_of_ecu in ("5", "6"):
        return "CCanFCFlashWriter"
    if kind_of_ecu == "4":
        if native_flag_ed4 is None:
            raise ValueError("KindOfECU4 requires actual native flag +ed4")
        if native_flag_ed4:
            return "CCanOldSpecECBFlashWriter"
    if kind_of_ecu == "7" and first_cpu_type == "27":
        return "CCanEPBFlashWriter"
    if kind_of_ecu in ("4", "14", "15", "20", "21", "7", "49", "52", "50", "13"):
        return "CCanChassisShrinkFlashWriter"
    if kind_of_ecu in ("17", "18", "36", "22"):
        return "CCanDHFlashWriter"
    if kind_of_ecu == "19":
        return "CCanAirbagFlashWriter"
    if kind_of_ecu in (
        "24",
        "27",
        "33",
        "39",
        "40",
        "41",
        "42",
        "43",
        "44",
        "48",
        "53",
        "28",
    ):
        return "CCanBodyFlashWriter"
    if kind_of_ecu == "29":
        return "CCanClearanceSonarFlashWriter"
    if kind_of_ecu in ("31", "32"):
        return "CCanFHIFlashWriter"
    if kind_of_ecu in ("35", "46", "38"):
        return "CCanDSS1FlashWriter"
    if kind_of_ecu in ("8", "11"):
        return "CCanDCMPRLFlashWriter"
    if kind_of_ecu == "45":
        return "CCanElectricPowerControlFlashWriter"
    return "CCanFlashWriter"


def executable_new_password(native: NativeCPUContext | ExecutableContext) -> int:
    """VA4137d8: read four image bytes at PasswordAddress using ByteOrder.

    This executable helper does not substitute the metadata NewPassword field or
    require a TargetCalibration match. Those belong to other native producers.
    """
    import re

    if isinstance(native, ExecutableContext):
        native = replace(native.native, parameters=executable_parameters(native))

    if not isinstance(native, NativeCPUContext) or native.image is None:
        raise ValueError("Materialized imported native CPU image required")
    text = native.parameters.get("PasswordAddress", "")
    if (
        not isinstance(text, str)
        or len(text) > 256
        or len(text) % 2
        or re.fullmatch("[0-9a-fA-F]*", text) is None
    ):
        raise ValueError(
            "PasswordAddress requires a bounded native hexadecimal byte string"
        )
    address = 0
    for index, value in enumerate(reversed(bytes.fromhex(text))):
        address |= value << ((index * 8) & 31)
    order_text = native.parameters.get("ByteOrder", "0")
    if (
        not isinstance(order_text, str)
        or re.fullmatch(r"[+-]?[0-9]{1,10}", order_text) is None
    ):
        raise ValueError("ByteOrder requires a native signed long")
    order = int(order_text)
    if not -(2**31) <= order < 2**31 or address + 4 > len(native.image.data):
        raise ValueError("Native password location or byte order outside bounds")
    return int.from_bytes(
        native.image.data[address : address + 4], "little" if order == 0 else "big"
    )


def _executable_cpu(
    context: ExecutableContext, cpu_index: int | None
) -> NativeCPUContext:
    if not isinstance(context, ExecutableContext):
        raise TypeError("Imported executable context required")
    context.state.validate()
    if cpu_index is None:
        cpu_index = context.native.selected.index
    if type(cpu_index) is not int or not 0 <= cpu_index < 4:
        raise ValueError("Native CPU index outside fixed target array")
    native = next(
        (row for row in context.cpus if row.selected.index == cpu_index), None
    )
    if native is None:
        raise ValueError("Native selected CPU absent from imported runtime table")
    return native


def executable_selected_target_calibration(
    context: ExecutableContext, cpu_index: int | None = None
) -> str:
    """Read the CPU's native selected target row; an unresolved index is an error."""
    native = _executable_cpu(context, cpu_index)
    index = context.state.target_indices[native.selected.index]
    rows = _executable_target_rows(native)
    if index >= len(rows):
        raise LookupError(
            "Actual native selected target index is not bound to a CPU row"
        )
    value = native.selected.values.get(f"{index + 1:02}_targetcalibration")
    if not isinstance(value, str) or not 0 < len(value) <= 128 or "\0" in value:
        raise ValueError("Declared imported target calibration row is missing")
    return value


def executable_selected_password(
    context: ExecutableContext, cpu_index: int | None = None
) -> int:
    """Read native TargetData[index], distinct from image-derived NewPassword."""
    native = _executable_cpu(context, cpu_index)
    executable_selected_target_calibration(context, native.selected.index)
    index = context.state.target_indices[native.selected.index]
    if (native.selected.index, index) in context.ram_target_passwords:
        return context.ram_target_passwords[native.selected.index, index]
    if native.metadata_version in (8, 9):
        return 0
    # INI virtual+70 receives defaultDWORD0 (12:407799 / 18:408c44).
    value = native.selected.values.get(f"{index + 1:02}_targetdata", "0")
    if len(value) > 8 or any(char not in "0123456789abcdefABCDEF" for char in value):
        raise ValueError("Selected imported TargetData must be a hexadecimal DWORD")
    # Native INI hex decoders402278/402380 initialize the empty result to zero.
    return int(value or "0", 16)


def complete_executable_targets(context: ExecutableContext) -> ExecutableContext:
    """47d329/44fdbf: append image-derived NewCID/password for unresolved CPUs.

    Both constructors allocate capacity32. At capacity the native append does
    nothing, but its caller still chooses count-1 after computing the password.
    """
    if not isinstance(context, ExecutableContext):
        raise TypeError("Actual imported executable context required")
    context.state.validate()
    if (
        context.recovery is not None
        or context.recovery_store is not None
        or context.state.writing
        or context.state.recovery_persistence_active
    ):
        raise ValueError("Restored or writing native targets must not be regenerated")
    if (
        tuple(row.selected.index for row in context.cpus)
        != tuple(range(len(context.native.cpus)))
        or any(
            row.selected != context.native.cpus[index]
            or row.cpus != context.native.cpus
            or row.metadata_version != context.native.metadata_version
            for index, row in enumerate(context.cpus)
        )
        or not 0 < len(context.cpus) <= 4
        or context.native.metadata_version not in range(1, 10)
        or context.state.native_flag_6e4
        or ntpath.splitext(context.native.cpus[0].values.get("cpuimagename", ""))[
            1
        ].lower()
        == ".vbf"
        or any(
            file.values.get("dataformat") in ("03", "04")
            for cpu in context.native.cpus
            for file in cpu.files
        )
    ):
        raise ValueError("Complete compact native runtime CPU table required")
    indices = list(context.state.target_indices)
    passwords = dict(context.ram_target_passwords)
    cpus = list(context.native.cpus)
    for row in context.cpus:
        index = row.selected.index
        targets = _executable_target_rows(row)
        if indices[index] != 0xFFFFFFFF:
            if indices[index] >= len(targets):
                raise ValueError("Selected native target index outside its CPU table")
            continue
        password = executable_new_password(replace(context, native=row))
        count = len(targets)
        if count < 32:
            values = dict(row.selected.values)
            values["numberoftargets"] = str(count + 1)
            values[f"{count + 1:02}_targetcalibration"] = values.get("newcid", "")
            values[f"{count + 1:02}_targetdata"] = f"{password:08X}"
            cpus[index] = replace(row.selected, values=MappingProxyType(values))
            passwords[index, count] = password
            count += 1
        indices[index] = count - 1
    native_cpus = tuple(cpus)
    rows = tuple(
        replace(row, selected=native_cpus[row.selected.index], cpus=native_cpus)
        for row in context.cpus
    )
    return replace(
        context,
        native=next(
            row for row in rows if row.selected.index == context.native.selected.index
        ),
        cpus=rows,
        state=replace(context.state, target_indices=tuple(indices)),
        ram_target_passwords=passwords,
    )


def executable_selected_location_id(
    context: ExecutableContext, cpu_index: int | None = None
) -> bytes:
    """Read original 4199f8/40e134 LocationID, including short zero-padded text."""
    from scripts.cuw_legacy_can import original_location_id

    if not isinstance(context, ExecutableContext):
        raise TypeError("Imported executable context required")
    context.state.validate()
    if cpu_index is None:
        cpu_index = context.native.selected.index
    if type(cpu_index) is not int or not 0 <= cpu_index < 128:
        raise ValueError("Native CPU index outside imported table bounds")
    native = next(
        (row for row in context.cpus if row.selected.index == cpu_index), None
    )
    if native is None:
        raise ValueError("Native selected CPU absent from imported runtime table")
    return original_location_id(native.selected.values.get("locationid", ""))


def executable_retry_requested(io: ExecutableIO | ExecutableContext) -> bool:
    """VA42de74: runtime RecoveryInfo+5b && !RecoveryInfo+5c."""
    if isinstance(io, ExecutableContext):
        io.state.validate()
        return io.state.recovery_retry and not io.state.retry_input
    values = io.call("read_recovery_flags")
    if (
        not isinstance(values, Mapping)
        or set(values) != {"native_flag_5b", "native_flag_5c"}
        or any(type(value) is not bool for value in values.values())
    ):
        raise ValueError("Actual native recovery runtime BOOLs required")
    return values["native_flag_5b"] and not values["native_flag_5c"]


def apply_recovery_password_state(
    context: ExecutableContext,
    io: ExecutableIO,
    writing_end_block: bool,
    native_mode_78: int,
    *,
    persist: bool | None = None,
) -> bool:
    """46cab0→42ed0c: mutate password choice, then optionally persist +59."""
    if (
        not isinstance(context, ExecutableContext)
        or (persist is not None and type(persist) is not bool)
        or (context.recovery_store is None and persist is None)
    ):
        raise ValueError(
            "Source-selected context and explicit persistence BOOL required"
        )
    context.state.validate()
    updated = legacy_recovery_password_state(
        writing_end_block, native_mode_78, context.state.use_new_software_password
    )
    context.state.use_new_software_password = updated
    if context.recovery_store is not None:
        context.recovery_store.set_field(io, "UseNewSoftwarePassword", updated)
        return updated
    if (
        persist
        and io.call("write_recovery_bool", key="UseNewSoftwarePassword", value=updated)
        is not None
    ):
        raise ValueError("Native recovery BOOL writer must return None")
    return updated


def executable_sync(io: ExecutableIO, callback: str, **values):
    """Source46ac04..46ac48: one synchronized GUI field-copy callback."""
    expected = {
        "owner_clear": (),
        "flag_68": ("value",),
        "value_70": ("value",),
        "values_78_80": ("value_78", "value_80"),
        "flag_88": ("value",),
        "read_flag_88": (),
        "completion": ("outcome",),
        "error_handler": (),
    }
    if callback not in expected or set(values) != set(expected[callback]):
        raise ValueError("Known controller callback and exact native fields required")
    if callback == "completion":
        if values["outcome"] not in ("success", "failure"):
            raise ValueError(
                "Completion must select native method pair +40/+44 or +48/+4c"
            )
        result = io.call("controller_callback", callback=callback, **values)
        if result is not None:
            raise ValueError("Synchronized completion callback must return None")
        return None
    boolean = callback in ("flag_68", "flag_88")
    if any(
        (type(value) is not bool)
        if boolean
        else (type(value) is not int or not 0 <= value <= 0xFFFFFFFF)
        for value in values.values()
    ):
        raise ValueError(
            "Controller callback fields require native BOOL or DWORD values"
        )
    result = io.call("controller_callback", callback=callback, **values)
    if callback == "read_flag_88":
        if type(result) is not bool:
            raise ValueError("Native GUI flag read must return BOOL")
    elif result is not None:
        raise ValueError("Native GUI field-copy callback must return None")
    return result


class ExecutableNativeError(Exception):
    """Source-translated native exception domain, excluding host/provider faults."""


class ExecutableForeignNativeError(ExecutableNativeError):
    """Native catch-all input with no invented CJ2534 category or driver status."""


class ExecutableJ2534Error(NativeTransportError, ExecutableNativeError):
    """CJ2534Exception: signed native category at +0c and driver DWORD at +1c."""

    def __init__(self, native_code: int, driver_status: int):
        if type(driver_status) is not int or not 0 <= driver_status <= 0xFFFFFFFF:
            raise ValueError("Native J2534 status must be a DWORD")
        self.native_code = native_code
        self.driver_status = driver_status
        super().__init__(driver_status)

    @property
    def native_code(self) -> int:
        return self._native_code

    @native_code.setter
    def native_code(self, value: int) -> None:
        if type(value) is not int or not -128 <= value <= 127:
            raise ValueError("Native exception category must be a signed byte")
        self._native_code = value


def executable_j2534_call(io: ExecutableIO, operation: str, **values):
    """46d090 wrapper for the concrete original PassThru calls below."""
    if operation not in {
        "read_messages",
        "write_messages",
        "start_filter",
        "stop_filter",
        "ioctl",
    }:
        raise ValueError("Source-proven J2534 wrapper operation required")
    try:
        return io.call(operation, **values)
    except ExecutableJ2534Error:
        raise
    except (NativeTransportError, VendorTransportError) as error:
        raise ExecutableJ2534Error(1, error.code) from error


def executable_start_filter(
    io: ExecutableIO, request: bytes, response: bytes, *, padding: bool
) -> int:
    """46f0d8: acquire a flow-control filter from exact CAN headers."""
    if (
        not isinstance(request, bytes)
        or not isinstance(response, bytes)
        or len(request) not in (4, 5)
        or len(response) != len(request)
        or type(padding) is not bool
    ):
        raise ValueError(
            "Equal four/five-byte native CAN headers and padding BOOL required"
        )
    flags = (0x40 if padding else 0) | (0x80 if len(response) == 5 else 0)

    def message(data: bytes) -> NativeMessage:
        return NativeMessage(protocol_id=6, data=data, tx_flags=flags)

    try:
        return io.acquire(
            "start_filter",
            "stop_filter",
            release_key="filter_id",
            filter_type=3,
            mask=message(b"\xff" * len(response)),
            pattern=message(response),
            flow_control=message(request),
        )
    except ExecutableJ2534Error:
        raise
    except (NativeTransportError, VendorTransportError) as error:
        raise ExecutableJ2534Error(1, error.code) from error


def executable_stop_filter(io: ExecutableIO, filter_id: int) -> None:
    """46f3cc with host ownership retained if the native stop faults."""
    if type(filter_id) is not int or not 0 <= filter_id <= 0xFFFFFFFF:
        raise ValueError("Native filter handle must be a DWORD")
    try:
        io.release("stop_filter", filter_id=filter_id)
    except ExecutableJ2534Error:
        raise
    except (NativeTransportError, VendorTransportError) as error:
        raise ExecutableJ2534Error(1, error.code) from error


def set_executable_error_code(
    context: ExecutableContext,
    io: ExecutableIO,
    code: int,
    *,
    persist: bool | None = None,
) -> None:
    """42edc8→RecoveryInfo+74: set PassThruErrorCode and optional INI save."""
    if (
        not isinstance(context, ExecutableContext)
        or type(code) is not int
        or not 0 <= code <= 255
        or (persist is not None and type(persist) is not bool)
        or (context.recovery_store is None and persist is None)
    ):
        raise ValueError(
            "Bounded native recovery error byte and persistence BOOL required"
        )
    context.state.validate()
    context.state.pass_thru_error_code = code
    if context.recovery_store is not None:
        context.recovery_store.set_field(io, "PassThruErrorCode", code)
        return
    if (
        persist
        and io.call("write_recovery_int", key="PassThruErrorCode", value=code)
        is not None
    ):
        raise ValueError("Native recovery integer writer must return None")


def executable_cpu_type(
    context: ExecutableContext, cpu_index: int | None = None
) -> str:
    """Read the parser-produced CPU type; historical names are never guessed."""
    if not isinstance(context, ExecutableContext) or not context.cpu_types:
        raise ValueError("Imported per-CPU normalized native metadata required")
    if cpu_index is None:
        cpu_index = context.native.selected.index
    if type(cpu_index) is not int or not 0 <= cpu_index < len(context.cpu_types):
        raise ValueError("Native CPU index outside original imported order")
    context.state.validate()
    return context.state.cpu_type_overrides.get(cpu_index, context.cpu_types[cpu_index])


def set_executable_cpu_type(
    context: ExecutableContext, cpu_index: int, value: str
) -> None:
    """414d34: retain a controller-detected CPUType in native RAM only."""
    executable_cpu_type(context, cpu_index)
    if (
        not isinstance(value, str)
        or len(value) > 128
        or not value.isascii()
        or "\x00" in value
    ):
        raise ValueError("Bounded native CPU type string required")
    context.state.cpu_type_overrides[cpu_index] = value


def executable_parameters(
    context: ExecutableContext, cpu_index: int | None = None
) -> Mapping[str, str]:
    """43a788 SetKeys: resolve parameters using the current native RAM CPUType."""
    from scripts.programming_legacy import _native_parameter_values

    if cpu_index is None:
        cpu_index = context.native.selected.index
    current_type = executable_cpu_type(context, cpu_index)
    cpu = next(
        (item for item in context.cpus if item.selected.index == cpu_index), None
    )
    if cpu is None:
        raise ValueError("Native CPU parameter request outside selected node")
    if current_type == context.cpu_types[cpu_index]:
        return cpu.parameters
    if context.catalog is None:
        raise ValueError(
            "CPUType mutation requires its original native parameter catalog"
        )
    metadata = dict(cpu.base_metadata)
    metadata["cpu_type"] = current_type
    selected = context.catalog.select_metadata(**metadata, stage="write")
    return _native_parameter_values(selected)


def executable_reconnect(
    context: ExecutableContext, io: ExecutableIO, protocol_id: int
) -> None:
    """Run the original channel lifecycle through its concrete neutral primitives."""
    from scripts.cuw_legacy_channel import reconnect

    if not isinstance(context, ExecutableContext) or (
        type(protocol_id) is not int or not 0 <= protocol_id <= 0xFFFFFFFF
    ):
        raise ValueError(
            "Source-selected executable context and native protocol required"
        )
    reconnect(context, io, protocol_id)


def executable_constructor_timeout(context: ExecutableContext) -> int:
    """Read the channel timeout copied by the native controller constructor."""
    value = context.constructor_read_timeout
    if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
        raise ValueError("Actual channel read timeout at controller creation required")
    return value


def connect_executable_context(context: ExecutableContext, io: ExecutableIO) -> None:
    """Manager12 44bc58 /18 475db4: connect, then set read timeout1000.

    This is the ContactType-selected manager method, not the unported GUI
    transition deciding when to call it. Manager12+d0/d4 correspond to18+e60/e64.
    """
    from scripts.cuw_legacy_channel import channel_state, connect

    legacy_executable_bytes(context)
    context.state.validate()
    contact = context.native.base_metadata["contact_type"]
    if contact not in ("SIL", "CAN", "P5-CAN"):
        raise ValueError("Source-admitted standard executable contact type required")
    try:
        connect(context, io, 3 if contact == "SIL" else 6)
        channel_state(context).read_timeout = 1000
    except ExecutableJ2534Error as error:
        context.state.native_value_e60 = error.native_code & 0xFFFFFFFF
        context.state.native_value_e64 = error.driver_status
        raise


def select_executable_cpu(
    context: ExecutableContext, cpu_index: int
) -> ExecutableContext:
    """Reconstruct the factory from retained WORK/index, not the saved cursor.

    Original12 44e0ec/44e150/44e15c and18 479b20 pass the retained
    WORK pointer and its separate selected index to manager virtual+2c.
    This selects one constructor; it does not advance or execute a CPU loop.
    """
    from scripts.cuw_legacy_channel import channel_state

    legacy_executable_bytes(context)
    context.state.validate()
    if (
        type(cpu_index) is not int
        or not 0 <= cpu_index < len(context.cpus)
        or tuple(row.selected.index for row in context.cpus)
        != tuple(range(len(context.cpus)))
        or any(row.cpus != context.native.cpus for row in context.cpus)
    ):
        raise ValueError("Actual retained runtime CPU position required")
    channel = channel_state(context)
    native = context.cpus[cpu_index]
    controller = select_executable_controller(
        native.base_metadata["contact_type"],
        native.base_metadata["kind_of_ecu"],
        executable_cpu_type(context, 0),
        executable_cpu_type(context, cpu_index),
        native_flag_ed4=cast(bool | None, context.observations.get("native_flag_ed4")),
    )
    if not context.state.native_cpu_type_ee0:
        context.state.native_cpu_type_ee0 = executable_cpu_type(context, 0)
    return replace(
        context,
        native=native,
        controller=controller,
        constructor_read_timeout=channel.read_timeout,
        constructor_send_timeout=channel.send_timeout,
    )


def executable_original_cpu_type(context: ExecutableContext) -> str:
    """Retained factory CPU0 string: manager18+ee0 /12+150."""
    context.state.validate()
    return context.state.native_cpu_type_ee0


def executable_constructor_send_timeout(context: ExecutableContext) -> int:
    """Read the send timeout copied by the source-selected native constructor."""
    value = context.constructor_send_timeout
    if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
        raise ValueError("Actual channel send timeout at controller creation required")
    return value


def execute(
    context: ExecutableContext,
    io: ExecutableIO,
) -> dict:
    """Dispatch implemented original executable Execute bodies on actual context.

    Missing families fail explicitly. Generic SIL obtains its delay predicate
    from the source-selected channel ABI record, never a caller Boolean.
    """
    if not isinstance(context, ExecutableContext) or not isinstance(io, ExecutableIO):
        raise TypeError("Imported executable context and bounded runtime required")
    context.state.validate()
    expected = select_executable_controller(
        context.native.base_metadata["contact_type"],
        context.native.base_metadata["kind_of_ecu"],
        executable_cpu_type(context, 0),
        executable_cpu_type(context),
        native_flag_ed4=cast(bool | None, context.observations.get("native_flag_ed4")),
    )
    if context.controller != expected:
        raise ValueError("Execute class differs from actual native factory selection")
    if not context.state.native_cpu_type_ee0:
        context.state.native_cpu_type_ee0 = executable_cpu_type(context, 0)
    if context.controller in ("CCanFlashWriter", "CP5CanFlashWriter"):
        if context.state.recovery_retry:
            raise NotImplementedError(
                "Original automatic-recovery entry producer is not implemented"
            )
        from scripts.cuw_legacy_can import execute as execute_can

        return execute_can(context, io)
    if context.controller.startswith("CSil"):
        from scripts.cuw_legacy_sil import execute_sil

        return execute_sil(context, io)
    if context.controller in (
        "CCanEPBFlashWriter",
        "CCanElectricPowerControlFlashWriter",
        "CCanChassisShrinkFlashWriter",
        "CCanOldSpecECBFlashWriter",
        "CCanClearanceSonarFlashWriter",
        "CCanFCFlashWriter",
        "CCanBodyFlashWriter",
        "CCanDSS1FlashWriter",
        "CCanAirbagFlashWriter",
    ):
        from scripts.cuw_legacy_body import execute as execute_body

        return execute_body(context, io)
    if context.controller == "CCanEMPS_V850E_PS2FlashWriter":
        from scripts.cuw_legacy_vendor import EMPSController

        return EMPSController(context, io).run()
    if context.controller == "CCanDCMPRLFlashWriter":
        from scripts.cuw_legacy_vendor import DCMController

        return DCMController(context, io).run()
    if context.controller == "CCanDHFlashWriter":
        from scripts.cuw_legacy_vendor import DHController

        return DHController(context, io).run()
    if context.controller == "CCanFHIFlashWriter":
        from scripts.cuw_legacy_vendor import FHIController

        return FHIController(context, io).run()
    raise NotImplementedError(
        f"Original executable Execute is not implemented: {context.controller}"
    )


def bind_context(
    container,
    node: int,
    observed_cids: tuple[str, ...],
    selection,
    *,
    build: int,
    cpu_index: int | None = None,
    recovery: NativeSavedRecovery | None = None,
    attachments: Mapping[str, bytes] | None = None,
    observations: Mapping[str, object] | None = None,
) -> ExecutableContext:
    """Bind original standard-flow class selection to an actual imported CUW.

    Concrete executable families obtain their own source-derived headers and
    preparation address lists; DLL catalog addresses are not evaluated here.
    """
    from scripts.calibration import (
        CalibrationContainer,
        _metadata_parser,
        bind_native_cpu_records,
        native_selection_metadata,
    )
    from scripts.programming_legacy import bind_native_cpu_context

    if (
        not isinstance(container, CalibrationContainer)
        or type(build) is not int
        or build not in (12, 18)
    ):
        raise ValueError("Imported CUW and original executable build required")
    source = (
        attachments.get("legacy_executable")
        if isinstance(attachments, Mapping)
        else None
    )
    if (
        not isinstance(source, bytes)
        or hashlib.sha256(source).hexdigest() != LEGACY_EXECUTABLE_SHA256[build]
    ):
        raise ValueError(
            "Explicit original CUW executable matching selected build required"
        )
    parser, metadata_version = _metadata_parser(container.attached.data)
    if metadata_version not in LEGACY_METADATA_VERSIONS[build]:
        raise ValueError(
            "Metadata version is not admitted by the actual original executable"
        )
    if recovery is not None and not isinstance(recovery, NativeSavedRecovery):
        raise TypeError("Source/device-bound native saved recovery required")
    if cpu_index is None:
        cpu_index = recovery.write_cpu_index if recovery is not None else 0
    if recovery is not None and cpu_index != recovery.write_cpu_index:
        raise ValueError("Selected CPU differs from actual saved recovery CPU")
    cpus = bind_native_cpu_records(container)
    kind_of_cal = next(
        (
            dict(parser[name])
            for name in parser.sections()
            if name.lower() == "kindofcal"
        ),
        {},
    )
    if type(cpu_index) is not int or not 0 <= cpu_index < len(cpus):
        raise ValueError("Selected executable CPU outside imported CUW")
    normalized = tuple(
        native_selection_metadata(container, node=cpu.node or 1, cpu_index=cpu.index)
        for cpu in cpus
    )
    actual = normalized[cpu_index]
    base = normalized[0]
    values = dict(observations or {})
    # The same channel flag resides at +37 in12 and +67 in18.
    if "channel_flag_67" in values:
        if build != 18:
            raise ValueError("Offset67 channel observation belongs to CUW18 only")
        old_padding = values.pop("channel_flag_67")
        if "channel_padding" in values and values["channel_padding"] != old_padding:
            raise ValueError("Conflicting native channel padding observations")
        values["channel_padding"] = old_padding
    if "channel_padding" in values and type(values["channel_padding"]) is not bool:
        raise ValueError("Native channel padding observation must be BOOL")
    if "observed_cids" in values:
        recorded = values["observed_cids"]
        if not isinstance(recorded, (tuple, list)) or tuple(recorded) != observed_cids:
            raise ValueError("Recorded identities differ from native catalog selection")
    values["observed_cids"] = observed_cids
    constructor_timeout = None
    constructor_send_timeout = None
    if "legacy_channel_state" in values:
        from scripts.cuw_legacy_channel import ChannelState

        channel = values["legacy_channel_state"]
        if not isinstance(channel, ChannelState):
            raise TypeError("Actual typed native channel state required")
        channel.validate(build)
        constructor_timeout = channel.read_timeout
        constructor_send_timeout = channel.send_timeout
    controller = select_executable_controller(
        base["contact_type"],
        base["kind_of_ecu"],
        base["cpu_type"],
        actual["cpu_type"],
        native_flag_ed4=cast(bool | None, values.get("native_flag_ed4")),
    )
    contexts = tuple(
        bind_native_cpu_context(
            container,
            node,
            observed_cids,
            selection,
            stage="write",
            cpu_index=cpu.index,
            original_executable_build=build,
        )
        for cpu in cpus
        if cpu.node in (0, node)
    )
    selected = next(
        (item for item in contexts if item.selected.index == cpu_index), None
    )
    if selected is None:
        raise ValueError("Selected executable CPU does not belong to requested node")
    state = ExecutableState(
        write_cpu_index=cpu_index,
        writing=recovery.writing if recovery else False,
        writing_end_block=recovery.writing_end_block if recovery else False,
        use_new_software_password=recovery.use_new_software_password
        if recovery
        else False,
        pass_thru_error_code=cast(int, recovery.fields.get("passthruerrorcode", 99))
        if recovery
        else 99,
    )
    context = ExecutableContext(
        build,
        controller,
        selected,
        contexts,
        container.digest,
        state,
        recovery,
        attachments or {},
        values,
        tuple(row["cpu_type"] for row in normalized),
        selection.catalog,
        constructor_timeout,
        kind_of_cal=kind_of_cal,
        constructor_send_timeout=constructor_send_timeout,
    )
    legacy_executable_bytes(context)
    return context
