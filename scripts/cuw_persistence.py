"""Source-bound CUW2026 recovery persistence over explicit local output only.

No saved pathname is opened. Sources are immutable bytes or pinned issued views;
outputs use an explicitly chosen directory and the native Save/RecoveryInfo.ini
layout. No device, network, vendor executable or authorization calculation.
"""

from __future__ import annotations

import configparser
import hashlib
import math
import ntpath
import os
import secrets
import stat
import struct
import threading
import time
from collections.abc import Callable, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from pathlib import Path
from types import MappingProxyType
from typing import cast

from scripts.calibration_2026 import NativeUSBSource2026, _validate_container_2026
from scripts.cuw_large import MAX_SIZE, LargeSource2026, validate_large_container_2026
from scripts.programming_2026_common import NotificationBool

MAX_BYTES = 64 * 1024 * 1024
MAX_INFO = 1024 * 1024
MAX_ROWS = 4096
STREAM_CHUNK = 1024 * 1024


CalibrationSource = bytes | LargeSource2026 | NativeUSBSource2026


def calibration_source_identity(source: CalibrationSource) -> tuple[int, str]:
    """Bound immutable bytes or the exact parser-issued original backing file."""
    if type(source) is bytes:
        if not 0 < len(source) <= MAX_BYTES:
            raise ValueError("Bounded immutable original calibration bytes required")
        return len(source), hashlib.sha256(source).hexdigest()
    if type(source) is LargeSource2026:
        validate_large_container_2026(source.container)
        return len(source), source.container.digest
    if type(source) is NativeUSBSource2026:
        _validate_container_2026(source)
        if not 0 < source.size <= MAX_SIZE:
            raise ValueError("Bounded original native USB source required")
        return source.size, source.digest
    raise TypeError("Immutable bytes or source-issued original CUW required")


def _source_chunks(source: CalibrationSource):
    size, _ = calibration_source_identity(source)
    for position in range(0, size, STREAM_CHUNK):
        length = min(STREAM_CHUNK, size - position)
        if type(source) is NativeUSBSource2026:
            _validate_container_2026(source)
            if source.raw is not None:
                yield source.raw[position : position + length]
            elif source.backing is not None:
                yield source.backing.read(position, length)
            else:
                raise ValueError("Original native USB backing is absent")
        elif isinstance(source, (bytes, LargeSource2026)):
            yield source[position : position + length]
        else:
            raise TypeError("Issued original source required")


def _text(value: str, maximum: int = 4096) -> str:
    if (
        not isinstance(value, str)
        or len(value) > maximum
        or any(c in value for c in "\x00\r\n")
    ):
        raise ValueError("Bounded native single-line text required")
    value.encode("latin1")
    return value


def _uint(value: int, maximum: int = 0xFFFFFFFF) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError("Native unsigned field outside bounds")
    return value


def _boolean(value: bool) -> bool:
    if type(value) is not bool:
        raise ValueError("Native Boolean required")
    return value


def encode_nibble_text(data: bytes, noise: Callable[[], int] = lambda: 0) -> bytes:
    """21660: hexadecimal nibbles, add8, multiply4 and add rand()&3."""
    if not isinstance(data, bytes) or len(data) > MAX_INFO or b"\x00" in data:
        raise ValueError("Bounded native recovery plaintext required")
    out = bytearray()
    for byte in data:
        for nibble in (byte >> 4, byte & 15):
            out.append((nibble + 8) * 4 + _uint(noise(), 3))
    return bytes(out)


def decode_nibble_text(data: bytes) -> bytes:
    """1c420: discard the two random low bits, reconstruct each original byte."""
    if (
        not isinstance(data, bytes)
        or len(data) > MAX_INFO * 2
        or len(data) % 2
        or any(not 0x20 <= b <= 0x5F for b in data)
    ):
        raise ValueError("Malformed native recovery nibble text")
    return bytes(
        (((data[i] >> 2) - 8) << 4) | ((data[i + 1] >> 2) - 8)
        for i in range(0, len(data), 2)
    )


@dataclass(frozen=True)
class RecoveryDocument:
    sections: Mapping[str, Mapping[str, str]] = field(repr=False)
    original_bytes: bytes = field(repr=False)
    encoded: bool

    def to_bytes(self) -> bytes:
        """Preserve the complete original byte representation, including noise."""
        return self.original_bytes


class _INIParser(configparser.ConfigParser):
    def optionxform(self, optionstr: str) -> str:
        return optionstr


def parse_recovery_info(data: bytes, *, encoded: bool = True) -> RecoveryDocument:
    if not isinstance(data, bytes) or not 0 < len(data) <= MAX_INFO * 2:
        raise ValueError("Bounded RecoveryInfo bytes required")
    _boolean(encoded)
    raw = decode_nibble_text(data) if encoded else data
    if len(raw) > MAX_INFO or b"\x00" in raw:
        raise ValueError("Invalid native recovery plaintext")
    parser = _INIParser(interpolation=None, delimiters=("=",), strict=True)
    try:
        # Native INI fields are byte strings. Shield high bytes from Unicode
        # whitespace classification while using the standard INI parser.
        protected = {
            value: 0xE000 + value for value in (*range(0x1C, 0x20), *range(128, 256))
        }
        parser.read_string(raw.decode("latin1").translate(protected))
    except (ValueError, configparser.Error, UnicodeError) as exc:
        raise ValueError("Malformed native recovery INI") from exc
    if (
        parser.defaults()
        or "RecoveryInfo" not in parser
        or len(parser.sections()) > MAX_ROWS
    ):
        raise ValueError("RecoveryInfo section required without defaults")
    restored = {
        0xE000 + value: value for value in (*range(0x1C, 0x20), *range(128, 256))
    }
    sections = {
        section.translate(restored): {
            key.translate(restored): value.translate(restored)
            for key, value in parser[section].items()
        }
        for section in parser.sections()
    }
    if sum(len(v) for v in sections.values()) > 16384:
        raise ValueError("Recovery field budget exceeded")
    for section, rows in sections.items():
        _text(section, 128)
        for key, value in rows.items():
            _text(key, 128)
            _text(value)
    _validate_sections(sections)
    return RecoveryDocument(
        MappingProxyType({k: MappingProxyType(v) for k, v in sections.items()}),
        data,
        encoded,
    )


def _number(rows, key, default=0, maximum=0xFFFFFFFF):
    try:
        value = int(rows.get(key, str(default)), 10)
    except ValueError as exc:
        raise ValueError("Invalid native recovery integer") from exc
    return _uint(value, maximum)


def _validate_sections(sections):
    root = sections["RecoveryInfo"]
    multi = _number(root, "MultiCalibrationFileNum", maximum=99)
    groups = (
        ["RecoveryInfo"]
        if not multi
        else [f"RecoveryInfo{i}" for i in range(1, multi + 1)]
    )
    for section in groups:
        if section not in sections:
            raise ValueError("Missing native multi-calibration recovery section")
        rows = sections[section]
        for count_key, prefix in (
            ("CIDNum", "CID"),
            ("AssyNoNum", "AssyNo"),
            (
                "VehicleInfoForUpdateAvailableFlagNum",
                "VehicleInfoForUpdateAvailableFlag",
            ),
        ):
            for i in range(1, _number(rows, count_key, maximum=MAX_ROWS) + 1):
                if f"{prefix}{i}" not in rows:
                    raise ValueError("Missing indexed native recovery field")
                if prefix == "VehicleInfoForUpdateAvailableFlag":
                    _number(rows, f"{prefix}{i}", maximum=1)
        if "WholeReproCalibrationFileFlag" in rows:
            _number(rows, "WholeReproCalibrationFileFlag", maximum=1)
        for key, value in rows.items():
            if key.startswith("BlankECUFlag"):
                _uint(int(value), 1)
    for key in (
        "Writing",
        "WritingEndBlock",
        "UseNewSoftwarePassword",
        "IsCentralGWExist",
        "SequenceChangedForGetCID",
    ):
        _number(root, key, maximum=1)
    for key in ("CommPhase", "ReproGWNode", "SSMID", "DHCentralGWType"):
        _number(root, key, maximum=255)
    for key in (
        "WriteCpuIndex",
        "PassThruErrorCode",
        "CalibrationFileIndex",
        "OffsetOfWriteCpuMultiCalIndex",
        "KindOfVehicle",
        "WriteTargetDividedCPUImageIndex",
    ):
        _number(root, key)
    for i in range(
        1, _number(root, "CanIDFromResultOfGetCIDNum", maximum=MAX_ROWS) + 1
    ):
        if f"CanIDFromResultOfGetCID{i}" not in root:
            raise ValueError("Missing indexed native received address")
    for key in ("IsSuzukiReproSecuritySupported", "IsDaihatsuReproSecuritySupported"):
        _number(sections.get("InfoInStorage", {}), key, maximum=1)


@dataclass(frozen=True)
class RequestedAddress:
    value: str
    logical: bool = False

    def __post_init__(self):
        _text(self.value, 6)
        _boolean(self.logical)


@dataclass
class RecoveryCalibration:
    source_path: str = field(repr=False)
    source_bytes: CalibrationSource = field(repr=False)
    cids: tuple[str, ...] = ()
    requested_addresses: tuple[RequestedAddress, ...] = ()
    assembly_numbers: tuple[str, ...] = ()
    update_available: tuple[bool, ...] = ()
    blank_ecu_flags: tuple[bool, ...] = ()
    whole_repro: bool = False
    saved_path: str = field(default="", repr=False)

    def validate(self):
        _text(self.source_path)
        _text(self.saved_path)
        name = ntpath.basename(self.source_path)
        if not name or name in (".", "..") or any(c in name for c in "/\\:"):
            raise ValueError("Safe original calibration basename required")
        calibration_source_identity(self.source_bytes)
        for values in (self.cids, self.assembly_numbers):
            if not isinstance(values, tuple) or len(values) > MAX_ROWS:
                raise ValueError("Bounded native recovery string vector required")
            for value in values:
                _text(value, 256)
        if (
            not isinstance(self.requested_addresses, tuple)
            or len(self.requested_addresses) != len(self.cids)
            or any(
                not isinstance(a, RequestedAddress) for a in self.requested_addresses
            )
        ):
            raise ValueError("One actual requested address per CID required")
        for values in (self.update_available, self.blank_ecu_flags):
            if not isinstance(values, tuple) or len(values) > MAX_ROWS:
                raise ValueError("Bounded native recovery bit vector required")
            for value in values:
                _boolean(value)
        _boolean(self.whole_repro)


@dataclass
class ReproInfoState:
    calibrations: tuple[RecoveryCalibration, ...] = field(repr=False)
    multi_calibration_file_num: int = 0
    selected_j2534_device: str = ""
    vin: str = ""
    is_central_gw_exist: bool = False
    write_cpu_index: int = 0
    writing: bool = False
    use_new_software_password: bool = False
    writing_end_block: bool = False
    loaded: bool = False
    logged: bool = False
    pass_thru_error_code: int = 9999
    comm_phase: int = 2
    repro_gw_node: int = 0
    contact_type_at_success_get_cid: str = ""
    sequence_changed_for_get_cid: bool = False
    ssmid: int = 0
    calibration_file_index: int = 0
    offset_of_write_cpu_multi_cal_index: int = 0
    can_ids_from_get_cid: tuple[str, ...] = ()
    kind_of_vehicle: int = 0
    write_target_divided_cpu_image_index: int = 0
    hardware_id: str = ""
    dh_central_gw_type: int = 0
    is_suzuki_repro_security_supported: bool = False
    is_daihatsu_repro_security_supported: bool = False

    def validate(self):
        if (
            not isinstance(self.calibrations, tuple)
            or not 1 <= len(self.calibrations) <= 99
            or any(not isinstance(c, RecoveryCalibration) for c in self.calibrations)
        ):
            raise ValueError("Bounded actual calibration state tuple required")
        _uint(self.multi_calibration_file_num, 99)
        if len(self.calibrations) != (self.multi_calibration_file_num or 1):
            raise ValueError("Native multi-calibration count/state mismatch")
        if (
            sum(
                calibration_source_identity(c.source_bytes)[0]
                for c in self.calibrations
            )
            > MAX_SIZE
        ):
            raise ValueError("Aggregate original calibration size exceeds UINT32_MAX")
        for calibration in self.calibrations:
            calibration.validate()
        for key in (
            "selected_j2534_device",
            "vin",
            "contact_type_at_success_get_cid",
            "hardware_id",
        ):
            _text(getattr(self, key))
        for key in (
            "is_central_gw_exist",
            "writing",
            "use_new_software_password",
            "writing_end_block",
            "loaded",
            "logged",
            "sequence_changed_for_get_cid",
            "is_suzuki_repro_security_supported",
            "is_daihatsu_repro_security_supported",
        ):
            _boolean(getattr(self, key))
        for key in (
            "write_cpu_index",
            "pass_thru_error_code",
            "calibration_file_index",
            "offset_of_write_cpu_multi_cal_index",
            "kind_of_vehicle",
            "write_target_divided_cpu_image_index",
        ):
            _uint(getattr(self, key))
        for key in ("comm_phase", "repro_gw_node", "ssmid", "dh_central_gw_type"):
            _uint(getattr(self, key), 255)
        if (
            not isinstance(self.can_ids_from_get_cid, tuple)
            or len(self.can_ids_from_get_cid) > MAX_ROWS
        ):
            raise ValueError("Bounded actual CID address vector required")
        for value in self.can_ids_from_get_cid:
            _text(value, 256)


def recovery_sections(state: ReproInfoState) -> dict[str, dict[str, str]]:
    state.validate()
    root = {
        key: str(int(value)) if type(value) in (int, bool) else value
        for key, value in (
            ("SelectedJ2534Device", state.selected_j2534_device),
            ("VIN", state.vin),
            ("IsCentralGWExist", state.is_central_gw_exist),
            ("WriteCpuIndex", state.write_cpu_index),
            ("Writing", state.writing),
            ("UseNewSoftwarePassword", state.use_new_software_password),
            ("WritingEndBlock", state.writing_end_block),
            ("PassThruErrorCode", state.pass_thru_error_code),
            ("CommPhase", state.comm_phase),
            ("ReproGWNode", state.repro_gw_node),
            ("ContactTypeAtSuccessGetCID", state.contact_type_at_success_get_cid),
            ("SequenceChangedForGetCID", state.sequence_changed_for_get_cid),
            ("SSMID", state.ssmid),
            ("MultiCalibrationFileNum", state.multi_calibration_file_num),
            ("CanIDFromResultOfGetCIDNum", len(state.can_ids_from_get_cid)),
            ("KindOfVehicle", state.kind_of_vehicle),
            (
                "WriteTargetDividedCPUImageIndex",
                state.write_target_divided_cpu_image_index,
            ),
            ("HardwareID", state.hardware_id),
            ("DHCentralGWType", state.dh_central_gw_type),
        )
    }
    sections = {
        "RecoveryInfo": root,
        "InfoInStorage": {
            "IsSuzukiReproSecuritySupported": str(
                int(state.is_suzuki_repro_security_supported)
            ),
            "IsDaihatsuReproSecuritySupported": str(
                int(state.is_daihatsu_repro_security_supported)
            ),
        },
    }
    if (
        state.multi_calibration_file_num
        or ntpath.splitext(state.calibrations[0].saved_path)[1].lower() == ".scuw"
    ):
        root.update(
            CalibrationFileIndex=str(state.calibration_file_index),
            OffsetOfWriteCpuMultiCalIndex=str(
                state.offset_of_write_cpu_multi_cal_index
            ),
        )
    root.update(
        {
            f"CanIDFromResultOfGetCID{i}": value
            for i, value in enumerate(state.can_ids_from_get_cid, 1)
        }
    )
    for index, calibration in enumerate(state.calibrations, 1):
        rows = (
            root
            if not state.multi_calibration_file_num
            else sections.setdefault(f"RecoveryInfo{index}", {})
        )
        rows.update(
            SavedCalibrationFilePath=calibration.saved_path,
            CIDNum=str(len(calibration.cids)),
            AssyNoNum=str(len(calibration.assembly_numbers)),
            VehicleInfoForUpdateAvailableFlagNum=str(len(calibration.update_available)),
            WholeReproCalibrationFileFlag=str(int(calibration.whole_repro)),
        )
        rows.update({f"CID{i}": value for i, value in enumerate(calibration.cids, 1)})
        rows.update(
            {
                f"CIDRequested{'LogicalAddress' if address.logical else 'CanID'}{i}": address.value
                for i, address in enumerate(calibration.requested_addresses, 1)
            }
        )
        rows.update(
            {
                f"AssyNo{i}": value
                for i, value in enumerate(calibration.assembly_numbers, 1)
            }
        )
        rows.update(
            {
                f"VehicleInfoForUpdateAvailableFlag{i}": str(int(value))
                for i, value in enumerate(calibration.update_available, 1)
            }
        )
        rows.update(
            {
                f"BlankECUFlag{i}": str(int(value))
                for i, value in enumerate(calibration.blank_ecu_flags, 1)
            }
        )
    return sections


def encode_recovery_info(
    state: ReproInfoState, noise: Callable[[], int] = lambda: 0
) -> bytes:
    sections = recovery_sections(state)
    lines = []
    for name in sorted(sections, key=lambda s: s.encode("latin1")):
        lines.append(f"[{name}]")
        lines.extend(
            f"{key}={sections[name][key]}"
            for key in sorted(sections[name], key=lambda s: s.encode("latin1"))
        )
    return encode_nibble_text("\r\n".join(lines).encode("latin1"), noise)


class CUWPersistence:
    """Actual309d0 notification handler with checked local file operations.

    Native CopyFile/DeleteFile failures were ignored in several paths; this host
    port reports them and never marks logged until atomic RecoveryInfo commit.
    Existing unrelated output entries are preserved. A failed handler leaves the
    NotificationBool value assigned, exactly as CNotificationBool does.
    """

    def __init__(
        self,
        output_root: Path,
        state: ReproInfoState,
        *,
        timeout: float = 30,
        cancelled: Callable[[], bool] = lambda: False,
        clock: Callable[[], float] = time.monotonic,
        fault_hook: Callable[[str, int], None] | None = None,
    ):
        if not isinstance(output_root, Path) or ".." in output_root.parts:
            raise ValueError(
                "Explicit local output root without parent traversal required"
            )
        if not isinstance(state, ReproInfoState):
            raise TypeError("Actual typed ReproInfo state required")
        state.validate()
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or not 0 < timeout <= 86400
        ):
            raise ValueError("Bounded persistence deadline required")
        self.output_root, self.state = output_root.absolute(), state
        self.clock, self.cancelled, self.timeout = clock, cancelled, timeout
        self.deadline = self._time() + timeout
        self.fault_hook = fault_hook
        self.notification = NotificationBool(False)
        self.notification.set_event_handler(
            self, lambda owner, value: cast(CUWPersistence, owner)._notification(value)
        )
        self.last_block_notification = NotificationBool(False)
        self.last_block_notification.set_event_handler(
            self,
            lambda owner, value: cast(CUWPersistence, owner)._last_block_changed(value),
        )
        self.events: list[dict] = []
        self._engine = None
        self._owned: set[str] = set()
        self._owned_hashes: dict[str, bytes] = {}
        self._root_identity = None
        self._save_identity = None
        self._lock = threading.RLock()
        self._cleanup_lease = None
        self._cleanup_assignment = None

    def validate_engine_owner(self, engine):
        """Preflight concrete engine identity without mutating source or owner."""
        from scripts.cuw_2026 import CUWEngine2026

        if type(engine) is not CUWEngine2026:
            raise TypeError("Actual CUW2026 engine source owner required")
        if self._engine is not None and self._engine is not engine:
            raise ValueError("Persistence source engine cannot be replaced")

    def bind_engine_source(self, engine):
        """Bind the actual CUW engine, without replacing either notification."""
        self.validate_engine_owner(engine)
        engine.validate_persistence_binding(self)
        self._engine = engine

    def validate_file_source_association(
        self, sources, metadata, *, state_snapshot=None
    ):
        """Authenticate43ee0's recovery originals against its exact selected FILE."""
        from scripts.cuw_file_services import validate_file_sources_2026

        validate_file_sources_2026(sources, sources.engine)
        self.validate_engine_owner(sources.engine)
        if sources.engine.persistence is not self:
            raise ValueError("FILE source producer does not own this persistence")
        state = self.state if state_snapshot is None else state_snapshot
        if type(state) is not ReproInfoState:
            raise TypeError("Actual recovery state snapshot required")
        state.validate()
        names, originals, count = sources.recovery_sources()
        if state.multi_calibration_file_num != count or len(state.calibrations) != len(
            names
        ):
            raise ValueError(
                "Recovery file count differs from its actual source producer"
            )
        for calibration, name, original in zip(
            state.calibrations, names, originals, strict=True
        ):
            if (
                calibration.source_path != name
                or calibration.source_bytes is not original
            ):
                raise ValueError(
                    "Recovery originals differ from the issued FILE association"
                )
        index = sources.recovery_index_for_metadata(metadata)
        if state.calibration_file_index != index:
            raise ValueError(
                "Recovery file index differs from the actual selected FILE"
            )

    @contextmanager
    def _file_source_binding(self, sources):
        """Apply only32130/20eb0 original file fields around an actual engine commit."""
        from scripts.cuw_file_services import validate_file_sources_2026

        with self._lock:
            engine = sources.engine
            validate_file_sources_2026(sources, engine)
            self.validate_engine_owner(engine)
            if engine.persistence is not self or self._cleanup_lease is not None:
                raise ValueError("Actual idle FILE persistence owner required")
            previous, previous_engine = dict(vars(self.state)), self._engine
            if self.state.calibrations:
                self._guard_engine_source(self._snapshot())
            elif not self._same_cleanup_fields(self.state, ReproInfoState(())):
                raise ValueError("Fresh FILE state must follow actual recovery reset")
            names, originals, count = sources.recovery_sources()
            if not names or len(names) != len(originals) or len(names) != (count or 1):
                raise ValueError("Complete native recovery original vector required")
            calibrations = tuple(
                replace(
                    self.state.calibrations[index],
                    source_path=name,
                    source_bytes=original,
                )
                if index < len(self.state.calibrations)
                else RecoveryCalibration(
                    name,
                    original,
                    blank_ecu_flags=(False,) * engine.configuration.cpu_maximum,
                )
                for index, (name, original) in enumerate(
                    zip(names, originals, strict=True)
                )
            )
            candidate = replace(
                self.state, calibrations=calibrations, multi_calibration_file_num=count
            )
            candidate.validate()
            self.validate_file_source_association(
                sources, sources.selected_metadata, state_snapshot=candidate
            )
            try:
                self.state.calibrations = candidate.calibrations
                self.state.multi_calibration_file_num = (
                    candidate.multi_calibration_file_num
                )
                yield
                if engine.file_sources is not sources:
                    raise ValueError(
                        "Actual engine did not commit the issued FILE sources"
                    )
                self.validate_file_source_association(sources, engine.native_metadata)
            except BaseException:
                for name, value in previous.items():
                    setattr(self.state, name, value)
                self._engine = previous_engine
                raise

    @contextmanager
    def _cleanup_notification_scope(self, cleanup):
        """Seal only40580's two false callbacks before its FILE resources close."""
        with self._lock:
            if self._engine is None or self._cleanup_lease is not None:
                raise ValueError(
                    "Bound engine and fresh cleanup notification scope required"
                )
            self._engine._validate_cleanup_controller(cleanup)
            snapshot = self._snapshot()
            self._guard_engine_source(snapshot)
            last_false = replace(snapshot, writing_end_block=False)
            encoded = encode_recovery_info(last_false) if snapshot.logged else None
            self._cleanup_lease = (
                cleanup,
                threading.get_ident(),
                self.state,
                self.state.calibrations,
                snapshot,
                encoded,
                self.notification,
                self.last_block_notification,
                self._engine.native_metadata,
                tuple(
                    (
                        calibration_source_identity(c.source_bytes),
                        *self._source_lease(c.source_bytes),
                    )
                    for c in snapshot.calibrations
                ),
                (
                    self._engine.native_metadata.source_sha256,
                    self._engine.native_metadata.source_container,
                ),
            )
            try:
                yield
            finally:
                self._cleanup_assignment = None
                self._cleanup_lease = None

    @staticmethod
    def _source_lease(source) -> tuple[object, object, object]:
        if type(source) is LargeSource2026:
            return (
                source.container,
                source.container._source,
                source.container._source.identity,
            )
        if type(source) is NativeUSBSource2026:
            return (
                source,
                source.backing,
                source.backing.identity if source.backing is not None else None,
            )
        return None, None, None

    @staticmethod
    def _same_cleanup_fields(current, expected):
        if type(current) is not type(expected):
            return False
        if isinstance(current, (ReproInfoState, RecoveryCalibration, RequestedAddress)):
            return vars(current).keys() == vars(expected).keys() and all(
                CUWPersistence._same_cleanup_fields(value, vars(expected)[key])
                for key, value in vars(current).items()
            )
        if isinstance(current, tuple):
            return len(current) == len(expected) and all(
                CUWPersistence._same_cleanup_fields(left, right)
                for left, right in zip(current, expected, strict=True)
            )
        return current == expected

    def _validate_cleanup_assignment(self, stage):
        lease = self._cleanup_lease
        if self._engine is None or lease is None or self._cleanup_assignment != stage:
            raise ValueError("Actual scoped cleanup notification assignment required")
        (
            cleanup,
            thread,
            state,
            calibrations,
            snapshot,
            _,
            primary,
            secondary,
            metadata,
            sources,
            metadata_identity,
        ) = lease
        self._engine._validate_cleanup_controller(cleanup)
        if (
            threading.get_ident() != thread
            or self._engine._metadata is not None
            or "targets-released" not in cleanup.state.trace
            or self.state is not state
            or self.state.calibrations is not calibrations
            or self.notification is not primary
            or self.last_block_notification is not secondary
        ):
            raise ValueError("Cleanup source owner or recovery aggregate changed")
        expected = (
            replace(snapshot, writing_end_block=False)
            if stage == "secondary-written"
            else snapshot
        )
        if not self._same_cleanup_fields(self.state, expected) or any(
            current.source_bytes is not original.source_bytes
            for current, original in zip(
                calibrations, snapshot.calibrations, strict=True
            )
        ):
            raise ValueError("Sealed cleanup recovery source or fields changed")
        if (
            metadata.source_sha256 != metadata_identity[0]
            or metadata.source_container is not metadata_identity[1]
        ):
            raise ValueError("Cleanup metadata differs from its sealed FILE identity")
        for calibration, (identity, container, backing, file_identity) in zip(
            calibrations, sources, strict=True
        ):
            source = calibration.source_bytes
            if isinstance(source, (LargeSource2026, NativeUSBSource2026)):
                current_container, current_backing, current_identity = (
                    self._source_lease(source)
                )
                if (
                    current_container is not container
                    or current_backing is not backing
                    or current_identity != file_identity
                    or (
                        source.container.digest
                        if isinstance(source, LargeSource2026)
                        else source.digest
                    )
                    != identity[1]
                    or (
                        source.container._source.size
                        if isinstance(source, LargeSource2026)
                        else source.size
                    )
                    != identity[0]
                ):
                    raise ValueError("Cleanup source lease identity changed")
        return lease

    def assign_cleanup_notifications(self, cleanup):
        """Invoke SAME primary/secondary false objects after actual target deletion."""
        with self._lock:
            lease = self._cleanup_lease
            if (
                lease is None
                or lease[0] is not cleanup
                or self._cleanup_assignment is not None
            ):
                raise ValueError("Actual cleanup scope and owner required")
            try:
                self._check()
                self._cleanup_assignment = "primary"
                self._validate_cleanup_assignment("primary")
                self.notification.assign(False)
                if self._cleanup_assignment != "primary-notified":
                    raise ValueError("Actual primary cleanup callback did not execute")
                self._cleanup_assignment = "secondary"
                self._validate_cleanup_assignment("secondary")
                self.last_block_notification.assign(False)
                if self._cleanup_assignment != "secondary-written":
                    raise ValueError(
                        "Actual secondary cleanup callback did not execute"
                    )
                self._validate_cleanup_assignment("secondary-written")
                self._cleanup_assignment = "complete"
            except BaseException:
                self._cleanup_assignment = "failed"
                raise

    def _snapshot(self):
        snapshot = replace(
            self.state, calibrations=tuple(replace(c) for c in self.state.calibrations)
        )
        snapshot.validate()
        return snapshot

    def _guard_engine_source(self, snapshot=None):
        if self._engine is not None:
            self._engine.validate_persistence_binding(self, state_snapshot=snapshot)

    def _time(self):
        value = self.clock()
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
        ):
            raise ValueError("Finite persistence clock observation required")
        return value

    def _check(self):
        if self.cancelled():
            raise InterruptedError("CUW persistence cancelled")
        if self._time() >= self.deadline:
            raise TimeoutError("CUW persistence deadline expired")

    def _event(self, operation: str):
        self._check()
        index = len(self.events)
        if index >= 65536:
            raise ValueError("Persistence event budget exceeded")
        self.events.append({"operation": operation, "index": index})
        if self.fault_hook is not None:
            self.fault_hook(operation, index)
        self._check()

    @staticmethod
    def _filename(name: str):
        if (
            not isinstance(name, str)
            or not name
            or len(name) > 255
            or name in (".", "..")
            or any(c in name for c in "/\\:\x00")
        ):
            raise ValueError("Safe local output basename required")
        return name

    def _directory(self, *, observe=True):
        if observe:
            self._event("open_output_root")
        parts = self.output_root.parts
        descriptor = os.open(parts[0], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for index, part in enumerate(parts[1:], 1):
                try:
                    child = os.open(
                        part,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                        dir_fd=descriptor,
                    )
                except FileNotFoundError:
                    if not observe or index != len(parts) - 1:
                        raise
                    self._event("mkdir_output_root")
                    os.mkdir(part, 0o700, dir_fd=descriptor)
                    child = os.open(
                        part,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                        dir_fd=descriptor,
                    )
                os.close(descriptor)
                descriptor = child
            info = os.fstat(descriptor)
            identity = info.st_dev, info.st_ino
            if self._root_identity is not None and self._root_identity != identity:
                raise ValueError("Persistence output directory identity changed")
            self._root_identity = identity
            try:
                target = os.open(
                    "Save",
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=descriptor,
                )
            except FileNotFoundError:
                if not observe:
                    raise
                self._event("mkdir_save")
                os.mkdir("Save", 0o700, dir_fd=descriptor)
                target = os.open(
                    "Save",
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=descriptor,
                )
            info = os.fstat(target)
            identity = info.st_dev, info.st_ino
            if self._save_identity is not None and self._save_identity != identity:
                os.close(target)
                raise ValueError("Persistence Save directory identity changed")
            self._save_identity = identity
            return target
        finally:
            os.close(descriptor)

    def _verify_directory(self, directory: int, *, observe=True):
        current = self._directory(observe=observe)
        try:
            actual, expected = os.fstat(directory), os.fstat(current)
            if (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino):
                raise ValueError("Persistence directory was detached from output root")
        finally:
            os.close(current)

    def _existing(self, directory: int, name: str) -> tuple[int, bytes] | None:
        self._filename(name)
        try:
            descriptor = os.open(
                name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory
            )
        except FileNotFoundError:
            return None
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_SIZE:
                raise ValueError(
                    "Existing persistence output must be bounded regular file"
                )
            digest = hashlib.sha256()
            size = 0
            while True:
                self._event("read_existing")
                chunk = os.read(descriptor, STREAM_CHUNK)
                if not chunk:
                    current = os.stat(name, dir_fd=directory, follow_symlinks=False)
                    if (
                        current.st_dev,
                        current.st_ino,
                        current.st_size,
                        current.st_mtime_ns,
                        current.st_ctime_ns,
                    ) != (
                        info.st_dev,
                        info.st_ino,
                        info.st_size,
                        info.st_mtime_ns,
                        info.st_ctime_ns,
                    ):
                        raise FileExistsError(
                            "Persistence target changed while reading"
                        )
                    if size != info.st_size:
                        raise FileExistsError(
                            "Persistence target size changed while reading"
                        )
                    return size, digest.digest()
                digest.update(chunk)
                size += len(chunk)
                if size > MAX_SIZE:
                    raise ValueError("Existing persistence output exceeds budget")
        finally:
            os.close(descriptor)

    @staticmethod
    def _guard_original_target(directory: int, name: str, source: CalibrationSource):
        backing = (
            source.container._source
            if isinstance(source, LargeSource2026)
            else source.backing
            if isinstance(source, NativeUSBSource2026)
            else None
        )
        if backing is None:
            return
        calibration_source_identity(source)
        try:
            target = os.stat(name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            return
        original = os.fstat(backing.fd)
        if (original.st_dev, original.st_ino) == (target.st_dev, target.st_ino):
            raise ValueError(
                "Original calibration backing cannot become an owned output"
            )

    def _preflight(self, planned: Mapping[str, CalibrationSource]):
        directory = self._directory()
        try:
            for name, data in planned.items():
                self._filename(name)
                self._guard_original_target(directory, name, data)
                existing = self._existing(directory, name)
                if name in self._owned:
                    if existing is None or existing[1] != self._owned_hashes[name]:
                        raise FileExistsError(
                            "Owned persistence output changed during preflight"
                        )
                elif existing is not None:
                    size, digest = calibration_source_identity(data)
                    if existing != (size, bytes.fromhex(digest)):
                        raise FileExistsError(
                            "Unrelated persistence output would be replaced"
                        )
                    self._owned.add(name)
                    self._owned_hashes[name] = existing[1]
        finally:
            os.close(directory)

    def _write(self, name: str, data: CalibrationSource):
        self._filename(name)
        cleanup_output = self._cleanup_assignment == "secondary-written"
        if cleanup_output:
            lease = self._validate_cleanup_assignment("secondary-written")
            if name != "RecoveryInfo.ini" or data is not lease[5]:
                raise ValueError("Cleanup permits only its sealed recovery document")
        expected_size, expected_digest = calibration_source_identity(data)
        expected = expected_size, bytes.fromhex(expected_digest)
        directory = self._directory()
        temporary = ".cuw-" + secrets.token_hex(12) + ".tmp"
        descriptor = None
        committed = False
        try:
            self._guard_original_target(directory, name, data)
            existing = self._existing(directory, name)
            if name in self._owned:
                if existing is None or existing[1] != self._owned_hashes[name]:
                    raise FileExistsError(
                        "Owned persistence output was changed externally"
                    )
            elif existing is not None and existing != expected:
                raise FileExistsError("Unrelated persistence output would be replaced")
            self._event("create_temporary")
            self._verify_directory(directory)
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=directory,
            )
            actual = hashlib.sha256()
            size = 0
            for chunk in _source_chunks(data):
                self._event("write_chunk")
                self._verify_directory(directory)
                actual.update(chunk)
                size += len(chunk)
                position = 0
                while position < len(chunk):
                    written = os.write(descriptor, chunk[position:])
                    if written <= 0:
                        raise OSError("Persistence write made no progress")
                    position += written
                    self._check()
            if (size, actual.digest()) != expected:
                raise ValueError("Calibration source digest changed during copy")
            self._event("fsync_file")
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = None
            self._event("atomic_replace")
            self._verify_directory(directory)
            # Recheck the final component immediately before atomic replacement.
            if self._existing(directory, name) != existing:
                raise FileExistsError("Persistence target changed before replacement")
            if calibration_source_identity(data) != (expected_size, expected_digest):
                raise ValueError("Calibration source changed before commit")
            self._guard_original_target(directory, name, data)
            if cleanup_output:
                self._validate_cleanup_assignment("secondary-written")
            # No injected callback occurs between this final validation and rename.
            self._verify_directory(directory, observe=False)
            os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
            committed = True
            self._owned.add(name)
            self._owned_hashes[name] = expected[1]
            self._event("fsync_directory")
            os.fsync(directory)
            self._check()
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if not committed:
                try:
                    os.unlink(temporary, dir_fd=directory)
                except FileNotFoundError:
                    pass
            os.close(directory)

    def _names(self, state=None) -> tuple[str, ...]:
        state = self.state if state is None else state
        names = tuple(
            self._filename(
                (f"{index}_" if state.multi_calibration_file_num else "")
                + ntpath.basename(calibration.source_path)
            )
            for index, calibration in enumerate(state.calibrations, 1)
        )
        if len({name.casefold() for name in names}) != len(names) or any(
            name.casefold() == "recoveryinfo.ini" for name in names
        ):
            raise ValueError("Native output filename collision")
        for calibration, name in zip(state.calibrations, names, strict=True):
            if (
                Path(calibration.source_path).absolute()
                == self.output_root / "Save" / name
            ):
                raise ValueError("Original calibration source cannot be replaced")
        return names

    def _notification(self, value: bool):
        if not value:
            if self._cleanup_assignment == "primary":
                self._validate_cleanup_assignment("primary")
                if bool(self.notification):
                    raise ValueError("Native cleanup primary assignment must be false")
                self._cleanup_assignment = "primary-notified"
            else:
                self._guard_engine_source()
            return
        with self._lock:
            self._event("notification_true")
            snapshot = self._snapshot()
            self._guard_engine_source(snapshot)
            if not snapshot.loaded and not snapshot.logged:
                names = self._names(snapshot)
                for calibration, name in zip(snapshot.calibrations, names, strict=True):
                    calibration.saved_path = str(self.output_root / "Save" / name)
                snapshot.writing = True
                encode_recovery_info(
                    snapshot
                )  # Validate the complete output budget before cache I/O.
                planned = dict(
                    zip(
                        names,
                        (c.source_bytes for c in snapshot.calibrations),
                        strict=True,
                    )
                )
                self._preflight(planned)
                # RecoveryInfo collision must fail before copying any calibration.
                directory = self._directory()
                try:
                    existing = self._existing(directory, "RecoveryInfo.ini")
                    if existing is not None and "RecoveryInfo.ini" not in self._owned:
                        raise FileExistsError(
                            "Existing recovery state requires explicit restore"
                        )
                finally:
                    os.close(directory)
                for calibration, name in zip(
                    self.state.calibrations, names, strict=True
                ):
                    calibration.saved_path = str(self.output_root / "Save" / name)
                for name, data in planned.items():
                    self._write(name, data)
            else:
                if any(
                    not calibration.saved_path
                    for calibration in self.state.calibrations
                ):
                    raise ValueError(
                        "Loaded recovery requires actual adopted cache paths"
                    )
            self.state.writing = True
            self.persist()
            self.state.logged = True

    def _last_block_changed(self, value: bool):
        """30b50: every assignment updatesEC9a and writes iffECDc logged."""
        with self._lock:
            self._event("last_block_notification")
            if self._cleanup_assignment == "secondary":
                lease = self._validate_cleanup_assignment("secondary")
                if bool(self.last_block_notification):
                    raise ValueError(
                        "Native cleanup last-block assignment must be false"
                    )
                self.state.writing_end_block = False
                self._cleanup_assignment = "secondary-written"
                if self.state.logged:
                    self._event("encode_recovery")
                    self._validate_cleanup_assignment("secondary-written")
                    encoded = lease[5]
                    if encoded is None:
                        raise ValueError("Logged cleanup requires its sealed INI")
                    self._write("RecoveryInfo.ini", encoded)
                return
            self._guard_engine_source(self._snapshot())
            self.state.writing_end_block = bool(self.last_block_notification)
            if self.state.logged:
                self.persist()

    def persist(self):
        with self._lock:
            self._event("encode_recovery")
            snapshot = self._snapshot()
            self._guard_engine_source(snapshot)
            encoded = encode_recovery_info(snapshot)
            self._write("RecoveryInfo.ini", encoded)

    def update_cpu(self, cpu_index: int):
        """3f620: updateEC94;21660 only whenECDc logged is already true."""
        self._check()
        old_cpu = self.state.write_cpu_index
        new_cpu = _uint(cpu_index)
        self.state.write_cpu_index = new_cpu
        if old_cpu != new_cpu and self._engine is not None:
            self._engine._persistence_cpu_changed2026(self, old_cpu, new_cpu)
        if self.state.logged:
            self.persist()

    def update_divided_image(self, index: int):
        """58e80 callback45: updateED6c and persist iffECDc is logged."""
        self._check()
        self.state.write_target_divided_cpu_image_index = _uint(index)
        if self.state.logged:
            self.persist()

    def report(self) -> dict:
        return {
            "format": "CUW2026-RecoveryInfo",
            "notification": bool(self.notification),
            "writing": self.state.writing,
            "logged": self.state.logged,
            "loaded": self.state.loaded,
            "calibration_count": len(self.state.calibrations),
            "events": tuple(self.events),
            "resume_authorized": False,
            "physical_status": "PHYSICAL_UNCONFIRMED",
        }

    @classmethod
    def import_recovery(
        cls,
        output_root: Path,
        document: RecoveryDocument,
        source_files: Mapping[str, CalibrationSource],
        *,
        cpu_capacity: int,
        **options,
    ) -> CUWPersistence:
        """Stage explicitly attached cache bytes; never open a saved INI path.

        This imports storage, not ECU recovery approval. The original document
        remains byte-preserving. Native loaded53 is assigned only after the
        complete supplied cache and original INI have been stored successfully.
        """
        state = load_recovery_state(document, source_files, cpu_capacity=cpu_capacity)
        persistence = cls(output_root, state, **options)
        names = tuple(
            persistence._filename(ntpath.basename(c.saved_path))
            for c in state.calibrations
        )
        if len({n.casefold() for n in names}) != len(names) or "recoveryinfo.ini" in {
            n.casefold() for n in names
        }:
            raise ValueError("Imported recovery cache names collide")
        planned = dict(
            zip(names, (c.source_bytes for c in state.calibrations), strict=True)
        )
        planned["RecoveryInfo.ini"] = (
            document.original_bytes
            if document.encoded
            else encode_nibble_text(document.original_bytes)
        )
        persistence._preflight(planned)
        for name, payload in planned.items():
            persistence._write(name, payload)
        for calibration, name in zip(state.calibrations, names, strict=True):
            calibration.saved_path = str(persistence.output_root / "Save" / name)
        state.loaded = True
        return persistence

    def replace_calibration(self, index: int, calibration: RecoveryCalibration):
        """23b10: mark whole-file result and update the cached source association."""
        with self._lock:
            self._check()
            _uint(index, len(self.state.calibrations) - 1)
            calibration.validate()
            old = self.state.calibrations[index]
            calibration = replace(
                old,
                source_path=calibration.source_path,
                source_bytes=calibration.source_bytes,
                whole_repro=True,
            )
            values = list(self.state.calibrations)
            values[index] = calibration
            previous = self.state.calibrations
            self.state.calibrations = tuple(values)
            try:
                self.state.validate()
            except Exception:
                self.state.calibrations = previous
                raise
            if not self.state.logged:
                return
            name = self._filename(
                f"{index + 1}_" + ntpath.basename(calibration.source_path)
            )
            calibration.saved_path = str(self.output_root / "Save" / name)
            candidate = self._snapshot()
            self._guard_engine_source(candidate)
            encode_recovery_info(candidate)
            self._preflight({name: calibration.source_bytes})
            self._write(name, calibration.source_bytes)
            self.persist()
            old_name = ntpath.basename(old.saved_path)
            if old_name != name:
                # Host atomically preserves the old cache until its replacement
                # and recovery document are durable; native deletes it first.
                self._unlink_owned(old_name)

    def _unlink_owned(self, name: str):
        self._filename(name)
        if name not in self._owned:
            raise ValueError("Cannot delete an unowned recovery output")
        directory = self._directory()
        try:
            self._event("unlink_owned")
            existing = self._existing(directory, name)
            if existing is None:
                raise FileNotFoundError("Owned recovery output is absent")
            if existing[1] != self._owned_hashes[name]:
                raise FileExistsError("Owned recovery output changed before deletion")
            self._verify_directory(directory, observe=False)
            os.unlink(name, dir_fd=directory)
            self._owned.remove(name)
            del self._owned_hashes[name]
            self._event("fsync_directory")
            os.fsync(directory)
        finally:
            os.close(directory)

    def delete_recovery(self):
        """38880: attempt all cache files and INI, reset even on native failures.

        Host cancellation/deadline stops immediately and retains the live state;
        ordinary file failures are collected and native reset still takes place.
        """
        with self._lock:
            self._check()
            failures = []
            fresh = (
                not self._owned
                and not self.state.loaded
                and not self.state.logged
                and all(not c.saved_path for c in self.state.calibrations)
            )
            names = (
                ()
                if fresh
                else tuple(
                    ntpath.basename(c.saved_path) for c in self.state.calibrations
                )
                + ("RecoveryInfo.ini",)
            )
            for name in names:
                try:
                    self._unlink_owned(name)
                except (InterruptedError, TimeoutError):
                    raise
                except (OSError, ValueError) as exc:
                    failures.append(type(exc).__name__)
            # 23630 resets in place, retaining engine-owned object identity.
            self.state.calibrations = ()
            defaults = ReproInfoState(())
            for name, value in vars(defaults).items():
                if name != "calibrations":
                    setattr(self.state, name, value)
            if failures:
                raise OSError("Native recovery deletion failed")


def load_recovery_state(
    document: RecoveryDocument,
    source_files: Mapping[str, CalibrationSource],
    *,
    cpu_capacity: int,
) -> ReproInfoState:
    """1f0e0 byte codec and typed fields, with explicit attached saved-file data.

    cpu_capacity is the actual shared CommonDefinitions.num_cpu_maxnum at load,
    not a hardcoded default. Native pads/truncates assembly/update/blank vectors
    to that value. This pure operation does not approve ECU recovery.
    """
    if not isinstance(document, RecoveryDocument) or not isinstance(
        source_files, Mapping
    ):
        raise TypeError(
            "Native document and explicit immutable source attachments required"
        )
    capacity = _uint(cpu_capacity, MAX_ROWS)
    original = parse_recovery_info(document.original_bytes, encoded=document.encoded)
    if original.sections != document.sections:
        raise ValueError("Recovery fields do not match their original source bytes")
    sections = original.sections
    root = sections["RecoveryInfo"]
    multi = _number(root, "MultiCalibrationFileNum", maximum=99)
    calibrations = []
    for index in range(1, (multi or 1) + 1):
        rows = sections["RecoveryInfo" if not multi else f"RecoveryInfo{index}"]
        path = rows.get("SavedCalibrationFilePath", "")
        if path not in source_files:
            raise ValueError(
                "Original saved calibration requires explicit byte attachment"
            )
        cids = tuple(
            rows[f"CID{i}"]
            for i in range(1, _number(rows, "CIDNum", maximum=MAX_ROWS) + 1)
        )
        addresses = []
        for i in range(1, len(cids) + 1):
            logical = rows.get(f"CIDRequestedLogicalAddress{i}", "")
            addresses.append(
                RequestedAddress(
                    (logical or rows.get(f"CIDRequestedCanID{i}", ""))[:6],
                    bool(logical),
                )
            )
        assemblies = tuple(
            rows[f"AssyNo{i}"]
            for i in range(1, _number(rows, "AssyNoNum", maximum=MAX_ROWS) + 1)
        )
        flags = tuple(
            bool(_number(rows, f"VehicleInfoForUpdateAvailableFlag{i}", maximum=1))
            for i in range(
                1,
                _number(rows, "VehicleInfoForUpdateAvailableFlagNum", maximum=MAX_ROWS)
                + 1,
            )
        )
        blank = tuple(
            bool(
                _number(
                    rows,
                    f"BlankECUFlag{i}",
                    _number(rows, "BlankECUFlag", maximum=1),
                    maximum=1,
                )
            )
            for i in range(1, capacity + 1)
        )
        calibration = RecoveryCalibration(
            path,
            source_files[path],
            cids,
            tuple(addresses),
            (assemblies + ("",) * capacity)[:capacity],
            (flags + (False,) * capacity)[:capacity],
            blank,
            bool(_number(rows, "WholeReproCalibrationFileFlag", maximum=1)),
            path,
        )
        calibrations.append(calibration)
    state = ReproInfoState(tuple(calibrations), multi_calibration_file_num=multi)
    fields = {
        "SelectedJ2534Device": "selected_j2534_device",
        "VIN": "vin",
        "ContactTypeAtSuccessGetCID": "contact_type_at_success_get_cid",
        "HardwareID": "hardware_id",
    }
    for key, name in fields.items():
        setattr(state, name, root.get(key, ""))
    fields = {
        "IsCentralGWExist": "is_central_gw_exist",
        "Writing": "writing",
        "UseNewSoftwarePassword": "use_new_software_password",
        "WritingEndBlock": "writing_end_block",
        "SequenceChangedForGetCID": "sequence_changed_for_get_cid",
    }
    for key, name in fields.items():
        setattr(state, name, bool(_number(root, key, maximum=1)))
    fields = {
        "WriteCpuIndex": "write_cpu_index",
        "PassThruErrorCode": "pass_thru_error_code",
        "CommPhase": "comm_phase",
        "ReproGWNode": "repro_gw_node",
        "SSMID": "ssmid",
        "CalibrationFileIndex": "calibration_file_index",
        "OffsetOfWriteCpuMultiCalIndex": "offset_of_write_cpu_multi_cal_index",
        "KindOfVehicle": "kind_of_vehicle",
        "WriteTargetDividedCPUImageIndex": "write_target_divided_cpu_image_index",
        "DHCentralGWType": "dh_central_gw_type",
    }
    for key, name in fields.items():
        setattr(
            state,
            name,
            _number(
                root,
                key,
                9999 if key == "PassThruErrorCode" else 2 if key == "CommPhase" else 0,
            ),
        )
    state.can_ids_from_get_cid = tuple(
        root[f"CanIDFromResultOfGetCID{i}"]
        for i in range(
            1, _number(root, "CanIDFromResultOfGetCIDNum", maximum=MAX_ROWS) + 1
        )
    )
    storage = sections.get("InfoInStorage", {})
    state.is_suzuki_repro_security_supported = bool(
        _number(storage, "IsSuzukiReproSecuritySupported", maximum=1)
    )
    state.is_daihatsu_repro_security_supported = bool(
        _number(storage, "IsDaihatsuReproSecuritySupported", maximum=1)
    )
    state.validate()
    return state


@dataclass(frozen=True)
class ProgrammingLogInfo:
    filename: str
    cpu_progress_index: int
    percent: int
    error_text: str = field(repr=False)
    error_flag: int
    error_code: int
    nrc: str

    def __post_init__(self):
        for value in (self.filename, self.error_text, self.nrc):
            _text(value, MAX_INFO)
        if (
            type(self.cpu_progress_index) is not int
            or not -(2**31) <= self.cpu_progress_index < 2**31
        ):
            raise ValueError("Native signed progress index required")
        _uint(self.percent)
        _uint(self.error_flag, 6)
        _uint(self.error_code)
        if self.nrc and (
            len(self.nrc) != 2 or any(c not in "0123456789ABCDEF" for c in self.nrc)
        ):
            raise ValueError("Native uppercase NRC byte required")

    def to_bytes(self, previous: bytes) -> bytes:
        """65a40 caller-owned0x2160 layout; untouched padding/tails are preserved."""
        if not isinstance(previous, bytes) or len(previous) != 0x2160:
            raise ValueError(
                "Actual caller-owned0x2160 programming-log buffer required"
            )
        out = bytearray(previous)
        for offset, capacity, text in (
            (0, 0x104, self.filename),
            (0x10C, 0x2045, self.error_text),
            (0x215C, 3, self.nrc),
        ):
            raw = text.encode("latin1")[: capacity - 1]
            out[offset : offset + len(raw) + 1] = raw + b"\x00"
        for offset, value in (
            (0x104, self.cpu_progress_index),
            (0x108, self.percent),
            (0x2154, self.error_flag),
            (0x2158, self.error_code),
        ):
            struct.pack_into("<I", out, offset, value & 0xFFFFFFFF)
        return bytes(out)


def build_programming_log_info(
    *,
    calibration_path: str,
    receiving_status: int,
    reprogramming_status: int,
    current_cpu: int,
    cpu_offset: int,
    progress_base: int,
    complete: bool,
    controller_present: bool,
    percentages: tuple[int, ...],
    error_code: int,
    exchange_data: bytes,
    address_size: int,
    connected: bool,
    voltage: float | None,
    alternate_progress_active: bool = False,
    alternate_current_cpu: int | None = None,
    alternate_cpu_offset: int | None = None,
    alternate_progress_base: int | None = None,
) -> ProgrammingLogInfo | None:
    """Actual65a40+4b1e0 data production; None means native return10001/no writes.

    Snapshot fields must come from the engine, its actual status methods and
    captured J2534 observations. This API neither creates a log file nor performs
    an opaque error-formatting callback.
    """
    _text(calibration_path)
    for value in (receiving_status, reprogramming_status, error_code):
        _uint(value)
    for value in (current_cpu, cpu_offset, progress_base):
        if type(value) is not int or not -(2**31) <= value < 2**31:
            raise ValueError("Actual signed native CPU progress fields required")
    for value in (complete, controller_present, connected, alternate_progress_active):
        _boolean(value)
    if not isinstance(percentages, tuple) or len(percentages) > MAX_ROWS:
        raise ValueError("Bounded native per-CPU percentage vector required")
    for percent in percentages:
        _uint(percent)
    if not isinstance(exchange_data, bytes) or len(exchange_data) > 4128:
        raise ValueError("Actual bounded native communication buffer required")
    _uint(address_size, len(exchange_data))
    if connected and (
        isinstance(voltage, bool)
        or not isinstance(voltage, (float, int))
        or not math.isfinite(voltage)
    ):
        raise ValueError("Actual finite native battery-voltage observation required")
    if not calibration_path or not (
        receiving_status == 0x138C or reprogramming_status in (0xBBB, 0xBBC)
    ):
        return None
    text = "-"
    if 0 < address_size < len(exchange_data):
        text = (
            exchange_data[:address_size].hex().upper()
            + " SID"
            + exchange_data[address_size:].hex().upper()
        )
    flag, nrc = 1, ""
    if connected and voltage is not None and voltage <= 1.0:
        flag = 6
    elif error_code == 0:
        flag = 3
        if (
            address_size + 3 <= len(exchange_data)
            and exchange_data[address_size] == 0x7F
        ):
            flag, nrc = (
                4,
                exchange_data[address_size + 2 : address_size + 3].hex().upper(),
            )
    elif error_code == 8:
        flag = 5
    elif error_code in (9, 16):
        flag = 2
    percent = (
        100
        if complete
        else percentages[current_cpu]
        if controller_present and 0 <= current_cpu < len(percentages)
        else 0
    )
    if alternate_progress_active:
        for value in (
            alternate_current_cpu,
            alternate_cpu_offset,
            alternate_progress_base,
        ):
            if type(value) is not int or not -(2**31) <= value < 2**31:
                raise ValueError("Actual alternate native progress fields required")
        assert (
            alternate_current_cpu is not None
            and alternate_cpu_offset is not None
            and alternate_progress_base is not None
        )
        progress = (
            alternate_current_cpu - alternate_cpu_offset + alternate_progress_base
        )
    else:
        progress = current_cpu - cpu_offset + progress_base
    if not -(2**31) <= progress < 2**31:
        raise ValueError("Native CPU progress arithmetic overflows")
    return ProgrammingLogInfo(
        ntpath.basename(calibration_path),
        progress,
        percent,
        text,
        flag,
        error_code,
        nrc,
    )
