"""Concrete source-bound CParameter arrays for native CUW Control helpers."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

from scripts.calibration_2026 import (
    Native2026Metadata,
    native2026_cpu_type,
    native2026_global_cpu_index,
    native2026_node_count,
    native2026_node_cpu_count,
    native2026_node_index,
    native2026_node_logical_block_count,
    native2026_node_values,
    native2026_validate_runtime_metadata,
)
from scripts.programming_2026_common import (
    NativeParameter2026,
    NativeParameterBinding2026,
    NativePassThruException2026,
)

_ISSUE = object()
_POOLS: dict[int, tuple[ControlParameterPool2026, _PoolState]] = {}


@dataclass
class _SlotState:
    parameter: NativeParameter2026 = field(default_factory=NativeParameter2026)
    filename: str | None = None
    source_sha256: str | None = None
    loaded: bool = False
    metadata: Native2026Metadata | None = None
    revision: int = 0


@dataclass
class _PoolState:
    engine: object
    controller: object
    catalog_sources: Mapping[str, bytes]
    encoded: bool
    capacity: int
    slots: list[_SlotState]
    issued_slots: dict[int, ControlParameterSlot2026] = field(default_factory=dict)
    closed: bool = False


def _copy_parameter(value: NativeParameter2026) -> NativeParameter2026:
    result = NativeParameter2026(value.headers, value.rows)
    result.key_column = value.key_column
    result.row_index = value.row_index
    return result


def _source_map(sources: Mapping[str, bytes]) -> Mapping[str, bytes]:
    if not isinstance(sources, Mapping) or len(sources) > 4096:
        raise TypeError("Bounded exact immutable parameter source mapping required")
    copied: dict[str, bytes] = {}
    total = 0
    for name, data in sources.items():
        if (
            not isinstance(name, str)
            or not name
            or len(name) > 259
            or "\0" in name
            or "/" in name
            or "\\" in name
            or not isinstance(data, bytes)
        ):
            raise TypeError("Bounded exact immutable parameter source mapping required")
        total += len(data)
        if total > 64 * 1024 * 1024:
            raise ValueError("Native parameter source catalog exceeds host budget")
        copied[name] = data
    return MappingProxyType(copied)


def _owners(engine, controller) -> None:
    from scripts.cuw_2026 import CUWEngine2026
    from scripts.programming_2026_common import ControlCommPhase2026

    if (
        type(engine) is not CUWEngine2026
        or type(controller) is not ControlCommPhase2026
        or engine.worker.controller is not controller
        or engine.worker.runtime is not controller.runtime
    ):
        raise ValueError("Exact owned CUW engine and Control controller required")


def _retained_owners_for_detach(engine, controller) -> None:
    """Authenticate the retained module owner after its worker has closed."""
    from scripts.cuw_2026 import CUWEngine2026
    from scripts.cuw_engine_worker import EngineWorker2026
    from scripts.programming_2026_common import ControlCommPhase2026

    worker = getattr(engine, "_worker", None)
    if (
        type(engine) is not CUWEngine2026
        or type(controller) is not ControlCommPhase2026
        or type(worker) is not EngineWorker2026
        or worker.engine is not engine
        or worker.controller is not controller
        or worker.runtime is not controller.runtime
    ):
        raise ValueError("Exact retained CUW engine and Control controller required")
    if (
        engine.active
        or engine._controller_export_target2026 is not None
        or controller._native_control_context2026 is not None
        or controller._native_control_raw_execution2026 is not None
        or controller._native_control_helper_entry2026 is not None
        or controller._native_control_export_lease2026 is not None
    ):
        raise ValueError("Active CONTROL module array cannot be detached")


def _native_error(operation: str, line: int) -> NativePassThruException2026:
    source = {
        "get_cid": "TCUWControlCommPhase.dll:RVA6f20",
        "prepare": "TCUWControlCommPhase.dll:RVA8990",
        "write": "TCUWControlCommPhase.dll:RVA4c10",
        "change_gateway": "TCUWControlCommPhase.dll:RVAa250",
    }[operation]
    if line in (0xA22, 0xA33, 0xA42, 0xA49):
        source = "TCUWControlCommPhase.dll:RVA9370"
    elif line in (0xB44, 0xB58, 0xB6A, 0xB73):
        source = "TCUWControlCommPhase.dll:RVA5c30"
    return NativePassThruException2026(9999, source, line)


class ControlParameterPool2026:
    """Issued concrete native array; callers cannot supply rows or capacity."""

    __slots__ = ("__weakref__", "_state")

    def __new__(cls, token=None, state=None):
        if cls is not ControlParameterPool2026 or token is not _ISSUE:
            raise TypeError("Control parameter pools are issued by issue()")
        result = super().__new__(cls)
        result._state = state
        return result

    def __init__(self, token=None, state=None):
        pass

    @classmethod
    def issue(
        cls, engine, controller, catalog_sources: Mapping[str, bytes], *, encoded=True
    ) -> ControlParameterPool2026:
        _owners(engine, controller)
        engine._require_owned_phase()
        if type(encoded) is not bool:
            raise TypeError("Native parameter source encoding Boolean required")
        sources = _source_map(catalog_sources)
        capacity = engine.common_definitions.num_cpu_maxnum
        if type(capacity) is not int or not 0 <= capacity <= 65535:
            raise ValueError(
                "Native CPU capacity exceeds bounded host allocation policy"
            )
        existing = _POOLS.get(id(controller))
        if existing is not None:
            pool, state = existing
            if state.closed:
                _POOLS.pop(id(controller), None)
            elif state.engine is engine and state.controller is controller:
                if (
                    dict(state.catalog_sources) != dict(sources)
                    or state.encoded is not encoded
                    or state.capacity != capacity
                ):
                    raise ValueError(
                        "Exact issued pool catalog/encoding/capacity required"
                    )
                pool.validate(engine, controller)
                return pool
            else:
                raise ValueError("Another engine owns this controller parameter pool")
        state = _PoolState(
            engine,
            controller,
            sources,
            encoded,
            capacity,
            [_SlotState() for _ in range(capacity)],
        )
        pool = cls(_ISSUE, state)
        _POOLS[id(pool)] = (pool, state)
        _POOLS[id(controller)] = (pool, state)
        return pool

    def _require_state(
        self, engine=None, controller=None, *, active=True, check_capacity=True
    ) -> _PoolState:
        registered = _POOLS.get(id(self))
        state = self._state
        if (
            registered is None
            or registered[0] is not self
            or registered[1] is not state
            or state.closed
        ):
            raise ValueError("Current issued control parameter pool required")
        engine = state.engine if engine is None else engine
        controller = state.controller if controller is None else controller
        if engine is not state.engine or controller is not state.controller:
            raise ValueError("Exact issued parameter pool owners required")
        if active:
            _owners(engine, controller)
            engine._require_owned_phase()
        else:
            _retained_owners_for_detach(engine, controller)
        if (
            check_capacity
            and engine.common_definitions.num_cpu_maxnum != state.capacity
        ):
            raise ValueError("Issued control parameter capacity changed")
        return state

    def validate(self, engine, controller) -> None:
        self._require_state(engine, controller)

    @property
    def capacity(self) -> int:
        return self._require_state().capacity

    @property
    def catalog_sources(self) -> Mapping[str, bytes]:
        return self._require_state().catalog_sources

    @property
    def encoded(self) -> bool:
        return self._require_state().encoded

    def slot(self, index: int) -> ControlParameterSlot2026:
        state = self._require_state()
        if type(index) is not int or not 0 <= index < state.capacity:
            raise IndexError("Unsigned bounded native control parameter slot required")
        slot = state.issued_slots.get(index)
        if slot is None:
            slot = object.__new__(ControlParameterSlot2026)
            object.__setattr__(slot, "_pool", self)
            object.__setattr__(slot, "_index", index)
            state.issued_slots[index] = slot
        return slot

    def load_steps_for(self, engine, controller, operation: str) -> Iterator[int]:
        state = self._require_state(engine, controller)
        if operation not in ("get_cid", "prepare", "write", "change_gateway"):
            raise ValueError("Known native Control parameter operation required")
        context = controller.native_control_context2026(engine)
        context.validate(engine, controller)
        cursor = context.cpu_index
        metadata = native2026_validate_runtime_metadata(context.metadata)
        kind = metadata.vehicle.get("kindofecu", "")
        contact = metadata.vehicle.get("contacttype", "")
        modern = contact in ("P5-Unified", "Phase6", "Ethernet")
        count = len(context.target_indices)

        def parameter_metadata(index: int) -> Native2026Metadata:
            return native2026_validate_runtime_metadata(context.metadata_for_cpu(index))

        def cpu_type_for(index: int) -> str:
            selected = parameter_metadata(index)
            return native2026_cpu_type(selected, native2026_global_cpu_index(selected))

        if operation == "get_cid":
            if state.capacity < 1:
                raise ValueError("Control parameter pool has no slot0")
            protocol = ""
            if native2026_node_count(metadata) > 0:
                protocol = native2026_node_values(metadata, 0).get("protocol", "")
            plan = (
                (
                    0,
                    kind + contact + protocol + cpu_type_for(0),
                    kind,
                    cpu_type_for(0),
                    contact + protocol,
                    parameter_metadata(0),
                    0x6AB,
                    0x6B4,
                ),
            )
        elif operation in ("prepare", "write") and not modern:
            if count > state.capacity:
                raise ValueError(
                    "Native CPU image count exceeds issued CParameter array"
                )
            load_line, keys_line = (
                (0x76A, 0x774) if operation == "prepare" else (0x8DC, 0x8E2)
            )
            plan = tuple(
                (
                    i,
                    kind + contact + cpu_type_for(i),
                    kind,
                    cpu_type_for(i),
                    contact,
                    parameter_metadata(i),
                    load_line,
                    keys_line,
                )
                for i in range(count)
            )
        elif operation == "prepare":
            if state.capacity < 1:
                raise ValueError("Control parameter pool has no slot0")
            cpu0 = cpu_type_for(0)
            required = metadata.node_values.get("requiredspecreprover", "")
            protocol = ""
            if required != "02":
                protocol = (
                    metadata.protocol_at_node if contact == "Phase6" else required
                )
            suffix = "" if required == "02" else protocol
            line, keys_line = (0xA42, 0xA49) if required == "02" else (0xA22, 0xA33)
            plan = (
                (
                    0,
                    kind + contact + suffix + cpu0,
                    kind,
                    cpu0,
                    contact + suffix,
                    parameter_metadata(0),
                    line,
                    keys_line,
                ),
            )
        elif operation == "write":
            node = native2026_node_index(
                metadata, native2026_global_cpu_index(metadata)
            )
            logical = native2026_node_logical_block_count(metadata, node) > 0
            start = (
                sum(native2026_node_cpu_count(metadata, prior) for prior in range(node))
                if logical
                else cursor
            )
            end = sum(
                native2026_node_index(
                    parameter_metadata(i),
                    native2026_global_cpu_index(parameter_metadata(i)),
                )
                <= node
                for i in range(count)
            )
            if start > end or end > state.capacity:
                raise ValueError(
                    "Modern native write CPU range exceeds issued CParameter array"
                )
            cpu0 = cpu_type_for(0)
            required = metadata.node_values.get("requiredspecreprover", "")
            protocol = ""
            if required != "02":
                protocol = (
                    metadata.protocol_at_node if contact == "Phase6" else required
                )
            suffix = "" if required == "02" else protocol
            line, keys_line = (0xB6A, 0xB73) if required == "02" else (0xB44, 0xB58)
            plan = tuple(
                (
                    i,
                    kind + contact + suffix + cpu0,
                    kind,
                    cpu0,
                    contact + suffix,
                    parameter_metadata(i),
                    line,
                    keys_line,
                )
                for i in range(start, end)
            )
        else:
            if state.capacity < 1:
                raise ValueError("Control parameter pool has no slot0")
            cpu0 = cpu_type_for(0)
            plan = (
                (
                    0,
                    kind + contact + cpu0,
                    kind,
                    cpu0,
                    contact,
                    parameter_metadata(0),
                    0x812,
                    0x818,
                ),
            )

        for (
            index,
            stem,
            key_kind,
            key_cpu,
            key_contact,
            load_metadata,
            load_line,
            keys_line,
        ) in plan:
            self._require_state(engine, controller)
            context.validate(engine, controller)
            filename = stem + ".ini"
            if (
                len(filename) > 259
                or not filename.isascii()
                or not re.fullmatch(r"[A-Za-z0-9_-]+\.ini", filename)
            ):
                raise ValueError("Bounded native parameter filename required")
            data = state.catalog_sources.get(filename)
            if data is None:
                raise _native_error(operation, load_line)
            parameter = (
                NativeParameter2026.from_encoded(data)
                if state.encoded
                else NativeParameter2026.from_csv(data)
            )
            slot_state = state.slots[index]
            # CCSVFile::Delete leaves +1c, while the new CSV changes +20.
            parameter.row_index = slot_state.parameter.row_index
            slot_state.parameter = parameter
            slot_state.filename = filename
            slot_state.source_sha256 = hashlib.sha256(data).hexdigest()
            slot_state.loaded = True
            slot_state.metadata = load_metadata
            slot_state.revision += 1
            if parameter.key_column < 0:
                raise _native_error(operation, load_line)
            selected = parameter.set_keys(key_kind, key_cpu, key_contact)
            slot_state.revision += 1
            if not selected:
                raise _native_error(operation, keys_line)
            yield index

    def load_for(self, engine, controller, operation: str) -> tuple[int, ...]:
        return tuple(self.load_steps_for(engine, controller, operation))

    def _binding_state2026(
        self, engine, controller, index: int
    ) -> tuple[ControlParameterSlot2026, Native2026Metadata]:
        slot = self.slot(index)
        slot_state = self._slot_state(slot, engine, controller)
        if not slot_state.loaded or slot_state.metadata is None:
            raise ValueError("Loaded native Control parameter slot required")
        metadata = native2026_validate_runtime_metadata(slot_state.metadata)
        context = controller.native_control_context2026(engine)
        context.validate(engine, controller)
        return slot, metadata

    def selected_binding(
        self, engine, controller, index: int, operation: str
    ) -> NativeParameterBinding2026:
        self._binding_state2026(engine, controller, index)
        from scripts.programming_2026_common import _binding_from_control_pool2026

        return _binding_from_control_pool2026(
            engine, controller, self, index, operation
        )

    def _slot_state(self, slot, engine=None, controller=None) -> _SlotState:
        state = self._require_state(engine, controller)
        if (
            type(slot) is not ControlParameterSlot2026
            or slot._pool is not self
            or state.issued_slots.get(slot._index) is not slot
        ):
            raise ValueError("Exact issued native Control parameter slot required")
        return state.slots[slot._index]

    def close(self) -> None:
        registered = _POOLS.get(id(self))
        if registered is None and self._state.closed:
            return
        if registered is None or registered[0] is not self:
            raise ValueError("Current issued control parameter pool required")
        state = self._require_state(active=False, check_capacity=False)
        state.closed = True
        for slot_state in state.slots:
            slot_state.parameter.delete()
            slot_state.filename = None
            slot_state.source_sha256 = None
            slot_state.loaded = False
            slot_state.metadata = None
        _POOLS.pop(id(self), None)
        if _POOLS.get(id(state.controller), (None, None))[0] is self:
            _POOLS.pop(id(state.controller), None)


@dataclass(frozen=True, init=False, eq=False)
class ControlParameterSlot2026:
    _pool: ControlParameterPool2026 = field(repr=False)
    _index: int = field(repr=False)

    def __init__(self, *args, **kwargs):
        raise TypeError("Control parameter slots are issued by their pool")

    def _state(self) -> _SlotState:
        return self._pool._slot_state(
            self, self._pool._state.engine, self._pool._state.controller
        )

    @property
    def index(self) -> int:
        self._state()
        return self._index

    @property
    def filename(self) -> str | None:
        return self._state().filename

    @property
    def source_sha256(self) -> str | None:
        return self._state().source_sha256

    @property
    def row_index(self) -> int:
        return self._state().parameter.row_index

    @property
    def loaded(self) -> bool:
        return self._state().loaded

    @property
    def revision(self) -> int:
        return self._state().revision

    @property
    def parameter(self) -> NativeParameter2026:
        return _copy_parameter(self._state().parameter)

    def value(self, name: str) -> str:
        return self.parameter.string(name) or ""


def _binding_state2026(
    engine, controller, index: int
) -> tuple[ControlParameterSlot2026, Native2026Metadata]:
    """Return a registry-authenticated slot and its strict load-time metadata."""
    registered = _POOLS.get(id(controller))
    if registered is None:
        raise ValueError("No issued native Control parameter pool")
    pool, _state = registered
    return pool._binding_state2026(engine, controller, index)
