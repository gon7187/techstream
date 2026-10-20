"""Original12/18 recovery RAM, ordered INI and nibble-text persistence.

Imported paths are labels only. All host operations use explicit primitives.
"""

from __future__ import annotations

import configparser
import ntpath
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, cast

from scripts.calibration import decode_cuw_text
from scripts.programming import inspect_recovery_info

if TYPE_CHECKING:
    from scripts.cuw_legacy_engine import (
        ExecutableContext,
        ExecutableIO,
        ExecutableState,
    )

_COMMON = (
    "SavedCalibrationFilePath",
    "SelectedJ2534Device",
    "CIDNum",
    "VIN",
    "CIDNodeNum",
    "ReproCheckResult",
    "IsCentralGWExist",
    "WriteCpuIndex",
    "Writing",
    "UseNewSoftwarePassword",
    "WritingEndBlock",
    "PassThruErrorCode",
)
_EXTRA18 = ("AssyNoNum", "VehicleInfoForUpdateAvailableFlagNum")
_VECTORS = {
    "CIDNum": "CID",
    "CIDNodeNum": "CIDNode",
    "AssyNoNum": "AssyNo",
    "VehicleInfoForUpdateAvailableFlagNum": "VehicleInfoForUpdateAvailableFlag",
}
_SHARED = {
    "WriteCpuIndex": "write_cpu_index",
    "Writing": "writing",
    "UseNewSoftwarePassword": "use_new_software_password",
    "WritingEndBlock": "writing_end_block",
    "PassThruErrorCode": "pass_thru_error_code",
}
_BOOL = {"Writing", "UseNewSoftwarePassword", "WritingEndBlock", "IsCentralGWExist"}


def _label(value: str) -> str:
    if (
        not isinstance(value, str)
        or not 0 < len(value) <= 4096
        or any(c in value for c in "\x00\r\n")
    ):
        raise ValueError("Bounded single-line native label required")
    value.encode("cp1252")
    return value


def encode_recovery_text(data: bytes) -> bytes:
    """430a8c/430b18 and418fe4: valid native encoding with noise bits zero."""
    return bytes(
        ((nibble + 8) << 2) for byte in data for nibble in (byte >> 4, byte & 15)
    )


@dataclass
class LegacyRecoveryStore:
    build: int
    container_sha256: str
    state: ExecutableState
    source_path: str
    selected_device: str
    fields: dict[str, str]
    encoded: bool = True
    original_data: bytes | None = field(default=None, repr=False)
    raw_unmapped: str = field(default="", repr=False)
    executable_path: str | None = None
    user_enabled: bool | None = None
    user_name: str | None = None
    recovery_path: str | None = None
    _original_plain: bytes | None = field(default=None, repr=False)
    cpu_indices: tuple[int, ...] = ()
    _owned_output_labels: set[str] = field(default_factory=set, repr=False)
    _reset: bool = False
    _saved_source_path: str | None = None

    @classmethod
    def from_context(
        cls,
        context: ExecutableContext,
        source_path: str,
        selected_device: str,
        original_data: bytes | None = None,
    ) -> LegacyRecoveryStore:
        from scripts.cuw_legacy_engine import ExecutableContext

        if not isinstance(context, ExecutableContext):
            raise TypeError("Actual original executable context required")
        source_path, selected_device = _label(source_path), _label(selected_device)
        fields = {
            key: "0" for key in _COMMON + (_EXTRA18 if context.build == 18 else ())
        }
        fields.update(
            SavedCalibrationFilePath=source_path,
            SelectedJ2534Device=selected_device,
            VIN="",
            PassThruErrorCode="99",
        )
        encoded = True
        plain = None
        unmapped = ""
        if original_data is not None:
            inspected = inspect_recovery_info(original_data)
            encoded = inspected["encoded"]
            plain = decode_cuw_text(original_data) if encoded else original_data
            parser = configparser.ConfigParser(
                interpolation=None, delimiters=("=",), strict=True
            )
            parser.read_string(plain.decode("cp1252"))
            section = next(
                s for s in parser.sections() if s.casefold() == "recoveryinfo"
            )
            raw_fields = dict(parser[section])
            if any(
                any(c in value for c in "\x00\r\n") for value in raw_fields.values()
            ):
                raise ValueError("Single-line recovery field values required")
            values = {k.casefold(): v for k, v in raw_fields.items()}
            if (
                values.get("savedcalibrationfilepath") != source_path
                or values.get("selectedj2534device") != selected_device
            ):
                raise ValueError("Saved recovery source/device association mismatch")
            for key in tuple(fields):
                if key.casefold() in values:
                    fields[key] = values[key.casefold()]
            for count, prefix in _VECTORS.items():
                if count in fields:
                    size = int(fields[count])
                    if {
                        k
                        for k in values
                        if k.startswith(prefix.casefold())
                        and k[len(prefix) :].isdigit()
                    } != {f"{prefix}{i}".casefold() for i in range(1, size + 1)}:
                        raise ValueError("Recovery vector count/index mismatch")
                    for i in range(1, size + 1):
                        fields[f"{prefix}{i}"] = values[f"{prefix}{i}".casefold()]
            known = {k.casefold() for k in fields}
            inside = False
            leftovers = []
            other = []
            for line in plain.decode("cp1252").splitlines(keepends=True):
                stripped = line.strip()
                if stripped.startswith("["):
                    inside = stripped.casefold() == "[recoveryinfo]"
                    if not inside:
                        other.append(line)
                elif inside:
                    if (
                        "=" not in line
                        or line.split("=", 1)[0].strip().casefold() not in known
                    ):
                        leftovers.append(line)
                else:
                    other.append(line)
            unmapped = "".join(leftovers + other)
            index = int(fields["WriteCpuIndex"])
            if index not in {cpu.selected.index for cpu in context.cpus}:
                raise ValueError("Recovery CPU outside actual imported context")
            # Validate the whole import before mutating the shared executable RAM.
            for key, attr in _SHARED.items():
                value = int(fields[key])
                setattr(context.state, attr, bool(value) if key in _BOOL else value)
            context.state.recovery_persistence_active = False
            context.state.validate()
        else:
            for key, attr in _SHARED.items():
                fields[key] = str(int(getattr(context.state, attr)))
        observations = context.observations
        store = cls(
            context.build,
            context.container_sha256,
            context.state,
            source_path,
            selected_device,
            fields,
            encoded,
            original_data,
            unmapped,
            cast(str | None, observations.get("recovery_executable_path")),
            cast(bool | None, observations.get("recovery_user_enabled")),
            cast(str | None, observations.get("recovery_user_name")),
            _original_plain=plain,
            cpu_indices=tuple(cpu.selected.index for cpu in context.cpus),
            _saved_source_path=source_path,
        )
        if (
            original_data is not None
            and store.executable_path is not None
            and type(store.user_enabled) is bool
        ):
            store.recovery_path = store._directory() + "\\RecoveryInfo.ini"
        return store

    def _directory(self) -> str:
        if self.executable_path is None or type(self.user_enabled) is not bool:
            raise ValueError(
                "Actual executable path and native user-profile branch required"
            )
        directory = ntpath.dirname(_label(self.executable_path)) + "\\Save"
        if self.user_enabled:
            directory += "\\" + _label(self.user_name or "")
        return directory

    def _plain(self) -> bytes:
        saved_source = (
            self._saved_source_path
            if self._saved_source_path is not None
            else self.source_path
        )
        if not self._reset and (
            self.fields["SavedCalibrationFilePath"] != saved_source
            or self.fields["SelectedJ2534Device"] != self.selected_device
        ):
            raise ValueError(
                "Recovery source/device association changed outside native path flow"
            )
        self.state.validate()
        for key, attr in _SHARED.items():
            self.fields[key] = str(int(getattr(self.state, attr)))
        keys = _COMMON + (_EXTRA18 if self.build == 18 else ())
        lines = ["[RecoveryInfo]\r\n"]
        for key in keys:
            lines.append(f"{key}={self.fields[key]}\r\n")
            if key in _VECTORS:
                prefix = _VECTORS[key]
                lines.extend(
                    f"{prefix}{i}={self.fields[f'{prefix}{i}']}\r\n"
                    for i in range(1, int(self.fields[key]) + 1)
                )
        result = ("".join(lines) + self.raw_unmapped).encode("cp1252")
        inspect_recovery_info(result)
        return result

    def to_bytes(self) -> bytes:
        plain = self._plain()
        # Retain original lexical form and random nibble bits on an unchanged Save.
        if self.original_data is not None and plain == self._original_plain:
            return self.original_data
        return encode_recovery_text(plain) if self.encoded else plain

    def save(self, io: ExecutableIO) -> None:
        if self.recovery_path is not None:
            self._owned_output_labels.add(self.recovery_path)
        if io.call("write_recovery_bytes", data=self.to_bytes()) is not None:
            raise ValueError("Recovery byte writer must return None")

    def begin_writing(self, io: ExecutableIO) -> None:
        if not self.state.recovery_retry and not self.state.recovery_persistence_active:
            directory = self._directory()
            exists = io.call("recovery_path_exists", path=directory)
            if type(exists) is not bool:
                raise ValueError("Path existence primitive must return BOOL")
            if (
                not exists
                and io.call("create_recovery_directory", path=directory) is not None
            ):
                raise ValueError("Directory primitive must return None")
            copied = directory + "\\" + ntpath.basename(self.source_path)
            if (
                io.call(
                    "copy_recovery_source",
                    source_path=self.source_path,
                    destination_path=copied,
                    fail_if_exists=False,
                )
                is not None
            ):
                raise ValueError("Copy primitive must return None")
            if ntpath.normcase(ntpath.normpath(copied)) != ntpath.normcase(
                ntpath.normpath(self.source_path)
            ):
                self._owned_output_labels.add(copied)
            self._saved_source_path = copied
            self.fields["SavedCalibrationFilePath"] = copied
            self.recovery_path = directory + "\\RecoveryInfo.ini"
        self.state.writing = True
        self.save(io)
        self.state.recovery_persistence_active = True

    def set_field(self, io: ExecutableIO, key: str, value: str | int | bool) -> None:
        if key in ("RetryMode", "RetryInput"):
            if type(value) is not bool:
                raise ValueError("Recovery retry input requires BOOL")
            setattr(
                self.state,
                "recovery_retry" if key == "RetryMode" else "retry_input",
                value,
            )
            return
        if key not in _SHARED:
            raise ValueError("Only recovered native persistence setters are supported")
        if key in _BOOL:
            if type(value) is not bool:
                raise ValueError("Native BOOL setter requires bool")
        elif type(value) is not int or not 0 <= value <= (
            128 if key == "WriteCpuIndex" else 255
        ):
            raise ValueError("Native bounded integer setter required")
        if key == "WriteCpuIndex" and value not in self.cpu_indices:
            terminal = len(self.cpu_indices)
            if value != terminal or self.cpu_indices != tuple(range(terminal)):
                raise ValueError("Recovery CPU outside actual imported context/cursor")
        setattr(self.state, _SHARED[key], value)
        if self.state.recovery_persistence_active:
            self.save(io)

    def finish(self, io: ExecutableIO) -> None:
        """42de54/417ddc: two ordered DeleteFile BOOLs, then native RAM reset.

        Labels and ownership hints never authorize a host unlink. The concrete
        provider must independently verify its own output registry and inodes.
        """
        for path in (self.fields["SavedCalibrationFilePath"], self.recovery_path or ""):
            deleted = io.call(
                "delete_recovery_file",
                path=path,
                owned_output=path in self._owned_output_labels,
            )
            if type(deleted) is not bool:
                raise ValueError("Native DeleteFile primitive must return BOOL")
        self.fields.clear()
        self.fields.update(
            {key: "0" for key in _COMMON + (_EXTRA18 if self.build == 18 else ())}
        )
        self.fields.update(
            SavedCalibrationFilePath="",
            SelectedJ2534Device="",
            VIN="",
            PassThruErrorCode="99",
        )
        for key, attr in _SHARED.items():
            setattr(
                self.state,
                attr,
                False if key in _BOOL else (99 if key == "PassThruErrorCode" else 0),
            )
        self.state.recovery_retry = False
        self.state.retry_input = False
        self.state.recovery_persistence_active = False
        self.original_data = None
        self._original_plain = None
        self.raw_unmapped = ""
        self._owned_output_labels.clear()
        self._reset = True
        self._saved_source_path = ""


def write_recovery_file(path: str | Path, data: bytes) -> None:
    """Atomic host byte primitive, for an explicitly chosen Linux output path.

    Same sibling-temp/fsync/replace contract as workbench._atomic_text; RAM
    mutations and the native activation latch remain the store's responsibility.
    """
    if not isinstance(data, bytes) or not 0 < len(data) <= 2 * 1024 * 1024:
        raise ValueError("Bounded complete recovery byte buffer required")
    path = Path(path)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=path.parent, prefix=f".{path.name}.", delete=False
        ) as target:
            temporary = Path(target.name)
            target.write(data)
            target.flush()
            os.fsync(target.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
