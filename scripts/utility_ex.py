"""Exact-source UtilityEx context and native worker lifecycle.

Business algorithms live in the explicitly selected domain modules. A source
identity never grants an unreviewed operation or substitutes a different build.
"""

from __future__ import annotations

import hashlib
import struct
import threading
from collections.abc import Callable, Collection, Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from scripts.utility_ex_lifecycle import UtilityExSelectedP5Worker

from scripts.j2534_2026 import PrimitiveResult
from scripts.native_memory import NativeMemoryArena
from scripts.utility_ex_comm import UtilityExComm

# Keep the literal identities separate from filenames and ordinal aliases.
SOURCES = {
    "8d9623f028f23876f69cb02baa10e1881c01fa01a4f906013bd36266f7e0fb33": "NK18",
    "980435d6bb2d9c57aab29e8f281d2641e3822b3172728f223c975ec6493d3c1e": "NK12",
    "797833dc0c798984fcb739c21ac6fbd5230871fb67495d3339698df2ee53753f": "NKDS4",
    "36dcdad2e72e29aae813db5576daf0168dd032b08a9cdda3841078dfb0b7b9fd": "NKPlus",
    "79fc495c68eb099a7ebc0d1eefe0eafd80101ac0bc09a58d3f603ed556c84762": "TY18",
    "e85b2456b26d3966ca243c03fa775cf81ad58bf05689bdb87b616eda4c8b6f5f": "TY12",
    "87bc49ada3f9dc8db442e74ebaf62ce868679b37d58fe3fdc4d3f24e31c4ce57": "TYDS4",
    "821bbfd9957679ceef4ac32c239b8840c984e98ac61050ce7348ac2bc88b04ce": "TYPlus",
}


# Exact Ex2SetParaFromBroker primitive read order, separately recovered per image.
_BROKER_KEYS = {
    "79fc495c68eb099a7ebc0d1eefe0eafd80101ac0bc09a58d3f603ed556c84762": (
        116,
        171,
        111,
        112,
        115,
        191,
        251,
        331,
        341,
        351,
        501,
        502,
        503,
        504,
        505,
        506,
        507,
        508,
        509,
        511,
        512,
        513,
        514,
        113,
    ),
    "8d9623f028f23876f69cb02baa10e1881c01fa01a4f906013bd36266f7e0fb33": (
        116,
        171,
        111,
        112,
        115,
        191,
        251,
        331,
        341,
        351,
        501,
        502,
        503,
        504,
        505,
        506,
        507,
        508,
        509,
        511,
        512,
        513,
        514,
        113,
    ),
    "980435d6bb2d9c57aab29e8f281d2641e3822b3172728f223c975ec6493d3c1e": (
        116,
        171,
        111,
        112,
        115,
        191,
        251,
        331,
        341,
        351,
    ),
    "e85b2456b26d3966ca243c03fa775cf81ad58bf05689bdb87b616eda4c8b6f5f": (
        116,
        171,
        111,
        112,
        115,
        191,
        251,
        331,
        341,
        351,
    ),
    "797833dc0c798984fcb739c21ac6fbd5230871fb67495d3339698df2ee53753f": (
        116,
        171,
        111,
        112,
        115,
        191,
        251,
        331,
        341,
        351,
    ),
    "87bc49ada3f9dc8db442e74ebaf62ce868679b37d58fe3fdc4d3f24e31c4ce57": (
        116,
        171,
        111,
        112,
        115,
        191,
        251,
        331,
        341,
        351,
    ),
    "36dcdad2e72e29aae813db5576daf0168dd032b08a9cdda3841078dfb0b7b9fd": (
        116,
        171,
        111,
        112,
        115,
        191,
        251,
        331,
        341,
        351,
        501,
        502,
        503,
        504,
        505,
        506,
        507,
        508,
        509,
        511,
        512,
        513,
        514,
        113,
    ),
    "821bbfd9957679ceef4ac32c239b8840c984e98ac61050ce7348ac2bc88b04ce": (
        116,
        171,
        111,
        112,
        115,
        191,
        251,
        331,
        341,
        351,
        501,
        502,
        503,
        504,
        505,
        506,
        507,
        508,
        509,
        511,
        512,
        513,
        514,
        113,
    ),
}


_BROKER_GLOBAL_BASES = {
    "NK18": 0x101517F0,
    "NK12": 0x100EA978,
    "NKDS4": 0x101B8AD8,
    "NKPlus": 0x101C8008,
    "TY18": 0x1011F700,
    "TY12": 0x100AFE78,
    "TYDS4": 0x1006F308,
    "TYPlus": 0x1013FA38,
}


def uint32(value: object) -> int:
    if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
        raise ValueError("UtilityEx uint32 required")
    return value


class UtilityHost(Protocol):
    """Individual UI/OS primitives; no engine or business completion callback."""

    def get_parameter(self, key: int) -> int: ...
    def get_data_size(self, key: int) -> int: ...
    def get_data(self, key: int) -> bytes: ...
    def set_parameter(self, key: int, value: int) -> int: ...
    def write_parameters(self) -> int: ...
    def ticks(self) -> int: ...
    def sleep(self, milliseconds: int) -> None: ...


@dataclass
class UtilityExContext:
    module_bytes: bytes = field(repr=False)
    host: UtilityHost
    runtime: Any
    device: Any
    state: dict[str, object] = field(default_factory=dict)
    driver_exports: Mapping[str, Callable[..., object]] | None = None
    driver_loaded: bool = True
    sis_driver_exports: Mapping[str, Callable[..., object]] | None = None
    p6_driver_exports: Mapping[str, Callable[..., object]] | None = None
    json_exports: Mapping[str, Callable[..., object]] | None = None
    win32_exports: Mapping[str, Callable[..., object]] | None = None
    native_memory: NativeMemoryArena | None = None
    _drivers: dict[int | tuple[int, int], UtilityDriverBinding] = field(
        default_factory=dict, init=False
    )
    _p6_drivers: dict[tuple[str, int], UtilityP6DriverBinding] = field(
        default_factory=dict, init=False
    )
    module_sha256: str = field(init=False)
    _parameters: dict[int, int] = field(default_factory=dict, init=False)
    _cancel: threading.Event = field(default_factory=threading.Event, init=False)
    _communication: dict[str, UtilityExComm] = field(default_factory=dict, init=False)
    _worker: UtilityWorker | None = field(default=None, init=False, repr=False)
    _sis_driver: UtilitySISDriverBinding | None = field(
        default=None, init=False, repr=False
    )

    def __post_init__(self) -> None:
        if type(self.module_bytes) is not bytes:
            raise TypeError("Immutable original UtilityEx image required")
        self.module_sha256 = hashlib.sha256(self.module_bytes).hexdigest()
        if self.module_sha256 not in SOURCES:
            raise ValueError("Unregistered original UtilityEx source identity")
        self.refresh_parameters()

    @property
    def mode(self) -> int:
        return self.broker(0x6F)

    @property
    def source_sha256(self) -> str:
        return self.module_sha256

    def broker(self, key: int) -> int:
        return self._parameters[uint32(key)]

    def broker_data(self, key: int) -> bytes:
        key = uint32(key)
        size = uint32(self.host.get_data_size(key))
        if size > 16 * 1024 * 1024:
            raise ValueError("Broker data exceeds host resource allocation policy")
        value = self.host.get_data(key)
        if type(value) is not bytes or len(value) != size:
            raise ValueError("Broker data size and immutable native resource differ")
        return value

    def set_parameter(self, key: int, value: int) -> int:
        return uint32(self.host.set_parameter(uint32(key), uint32(value)))

    def write_parameters(self) -> int:
        return uint32(self.host.write_parameters())

    def refresh_parameters(self) -> None:
        keys = _BROKER_KEYS.get(self.module_sha256, (0x6F, 0x70))
        source = SOURCES.get(self.module_sha256, "")
        base = _BROKER_GLOBAL_BASES.get(source)
        for index, key in enumerate(keys):
            self._parameters[key] = uint32(self.host.get_parameter(key))
            if base is not None:
                self.state[f"native_global:{base + index * 4:x}"] = self._parameters[
                    key
                ]
        if source in ("NKPlus", "TYPlus") and self.mode == 22:
            assert base is not None
            for key, prefix in (
                (0x74, 0x18DA00E0),
                (0x15F, 0x18DB00F1),
                (0x155, 0x18DA00F1),
            ):
                value = ((self._parameters[key] << 8) | prefix) & 0xFFFFFFFF
                self._parameters[key] = value
                self.state[f"native_global:{base + keys.index(key) * 4:x}"] = value

    def is_cancelled(self) -> bool:
        return self._cancel.is_set()

    def ticks(self) -> int:
        return uint32(self.host.ticks())

    def tick_count(self) -> int:
        return self.ticks()

    def sleep(self, milliseconds: int) -> None:
        # NK14b10 checks the native cancellation flag between 100ms slices.
        duration, start = uint32(milliseconds), self.ticks()
        while not self.is_cancelled():
            elapsed = (self.ticks() - start) & 0xFFFFFFFF
            if elapsed >= duration:
                return
            self.host.sleep(min(duration - elapsed, 100))

    def native_sleep(self, milliseconds: int) -> None:
        """Preserve direct native Sleep calls independently of cancellation."""
        self.host.sleep(uint32(milliseconds))

    def native_parameter(self, key: int) -> int:
        """Read a direct EbGetPara call without changing the broker snapshot."""
        return uint32(self.host.get_parameter(uint32(key)))

    @property
    def native_memory_owner(self) -> object:
        return self

    def read_module_data(self, va: int, size: int) -> bytes:
        """Read original PE initialized bytes/zero-fill; runtime globals use state."""
        va, size = uint32(va), uint32(size)
        if size > 16 * 1024 * 1024 or va + size > 0x100000000:
            raise ValueError("Bounded native module read required")
        if not size:
            return b""
        data = self.module_bytes
        if len(data) < 0x40 or data[:2] != b"MZ":
            raise ValueError("Original PE image required")
        pe = struct.unpack_from("<I", data, 0x3C)[0]
        if pe + 24 + 64 > len(data) or data[pe : pe + 4] != b"PE\0\0":
            raise ValueError("Invalid PE image header")
        optional = pe + 24
        if struct.unpack_from("<H", data, optional)[0] != 0x10B:
            raise ValueError("Reviewed PE32 image required")
        base = struct.unpack_from("<I", data, optional + 28)[0]
        header_size = struct.unpack_from("<I", data, optional + 60)[0]
        rva = va - base
        if 0 <= rva and rva + size <= min(header_size, len(data)):
            return data[rva : rva + size]
        count = struct.unpack_from("<H", data, pe + 6)[0]
        sections = optional + struct.unpack_from("<H", data, pe + 20)[0]
        if sections + count * 40 > len(data):
            raise ValueError("Invalid PE section table")
        for index in range(count):
            virtual_size, address, raw_size, raw_offset = struct.unpack_from(
                "<IIII", data, sections + index * 40 + 8
            )
            relative = rva - address
            if 0 <= relative and relative + size <= max(virtual_size, raw_size):
                initialized = min(size, max(0, raw_size - relative))
                start = raw_offset + relative
                if initialized and start + initialized > len(data):
                    raise ValueError("Truncated PE section")
                return data[start : start + initialized] + bytes(size - initialized)
        raise ValueError("Native read is outside one supplied PE image section")

    def _win32_export(self, name: str) -> Callable[..., object]:
        allowed = {
            "GetPrivateProfileIntA",
            "GetPrivateProfileStringA",
            "SetTimer",
            "KillTimer",
        }
        if self.win32_exports is None or name not in self.win32_exports:
            raise LookupError("Explicit typed Win32 primitive unavailable")
        if set(self.win32_exports) - allowed:
            raise ValueError("Only source-reviewed individual Win32 exports accepted")
        function = self.win32_exports[name]
        if not callable(function):
            raise TypeError("Typed individual Win32 callable required")
        return function

    def get_private_profile_int_a(
        self, section: bytes, key: bytes, default: int, filename: bytes
    ) -> int:
        for value in (section, key, filename):
            if type(value) is not bytes or b"\0" in value:
                raise ValueError(
                    "Immutable ANSI INI strings without embedded NUL required"
                )
        return uint32(
            self._win32_export("GetPrivateProfileIntA")(
                section, key, uint32(default), filename
            )
        )

    def get_private_profile_string_a(
        self,
        section: bytes,
        key: bytes,
        default: bytes,
        output: bytearray,
        capacity: int,
        filename: bytes,
    ) -> int:
        for value in (section, key, default, filename):
            if type(value) is not bytes or b"\0" in value:
                raise ValueError(
                    "Immutable ANSI INI strings without embedded NUL required"
                )
        capacity = uint32(capacity)
        if (
            type(output) is not bytearray
            or capacity > len(output)
            or capacity > 16 * 1024 * 1024
        ):
            raise ValueError("Bounded mutable native INI output required")
        original_size = len(output)
        result = uint32(
            self._win32_export("GetPrivateProfileStringA")(
                section, key, default, output, capacity, filename
            )
        )
        if (
            len(output) != original_size
            or result > max(0, capacity - 1)
            or (capacity and output[result] != 0)
        ):
            raise ValueError(
                "Win32 INI primitive violated native output bounds/termination"
            )
        return result

    def set_timer(
        self,
        hwnd: int,
        identifier: int,
        interval_ms: int,
        callback: Callable[[int, int, int, int], None],
    ) -> int:
        """Individual native SetTimer; source callback/lifecycle belongs to132."""
        hwnd, identifier, interval_ms = (
            uint32(hwnd),
            uint32(identifier),
            uint32(interval_ms),
        )
        if hwnd != 0 or not callable(callback):
            raise ValueError("Reviewed NULL-window timer and owned TIMERPROC required")
        result = uint32(
            self._win32_export("SetTimer")(hwnd, identifier, interval_ms, callback)
        )
        timers = self.state.setdefault("utility_ex:win32_timers", {})
        if not isinstance(timers, dict):
            raise TypeError("Owned native timer registry required")
        if result:
            timers[result] = callback
        return result

    def kill_timer(self, hwnd: int, identifier: int) -> int:
        """Release callback ownership only when individual KillTimer succeeds."""
        hwnd, identifier = uint32(hwnd), uint32(identifier)
        if hwnd != 0:
            raise ValueError("Only reviewed NULL-window native timers supported")
        observed = self._win32_export("KillTimer")(hwnd, identifier)
        result = int(observed) if type(observed) is bool else uint32(observed)
        timers = self.state.get("utility_ex:win32_timers", {})
        if not isinstance(timers, dict):
            raise TypeError("Owned native timer registry required")
        if result:
            timers.pop(identifier, None)
        return result

    def driver_binding(
        self, protocol: int, *, constructor_parameter: int = 0
    ) -> UtilityDriverBinding:
        protocol = uint32(protocol)
        constructor_parameter = uint32(constructor_parameter)
        key = (protocol, constructor_parameter) if constructor_parameter else protocol
        if self.driver_exports is None:
            raise LookupError("Explicit typed DRIVER export registration unavailable")
        if key not in self._drivers:
            self._drivers[key] = UtilityDriverBinding(
                self,
                protocol,
                dict(self.driver_exports),
                loaded=self.driver_loaded,
                constructor_parameter=constructor_parameter,
            )
        return self._drivers[key]

    def comm(self, selector: str) -> UtilityExComm:
        if selector not in self._communication:
            self._communication[selector] = UtilityExComm(self, selector)
        return self._communication[selector]

    def start_selected_cmn(
        self,
        interval_ms: int,
        skip_response_validation: int = 0,
        request: bytes | bytearray | None = None,
        length: int = 0,
    ) -> int:
        """Native139f0 family: separate retained struct, no cleanup or stop flag."""
        return self._start_selected_cmn(
            interval_ms,
            0,
            0,
            skip_response_validation,
            request,
            length,
            controlled=False,
        )

    def start_selected_cmn_controlled(
        self,
        interval_ms: int,
        finalize_on_exit: int,
        skip_response_validation: int,
        request: bytes | bytearray | None = None,
        length: int = 0,
    ) -> int:
        """Native13970 family has an independent retained struct and stop flag1."""
        return self._start_selected_cmn(
            interval_ms,
            finalize_on_exit,
            1,
            skip_response_validation,
            request,
            length,
            controlled=True,
        )

    def _start_selected_cmn(
        self,
        interval_ms: int,
        finalize_on_exit: int,
        stop_on_error: int,
        skip_response_validation: int,
        request: bytes | bytearray | None,
        length: int,
        *,
        controlled: bool,
    ) -> int:
        from scripts.utility_ex_lifecycle import (
            UtilityExSelectedCMNFields,
            UtilityExSelectedCMNWorker,
        )

        bases = {
            "NK12": 0x100E5DD8,
            "NK18": 0x1014AA40,
            "NKDS4": 0x101B1E70,
            "NKPlus": 0x101BCF70,
        }
        source = SOURCES[self.module_sha256]
        if source not in bases:
            raise LookupError("Selected CMN worker source is not reviewed")
        if controlled:
            bases = {
                "NK12": 0x100E5EF0,
                "NK18": 0x1014AB58,
                "NKDS4": 0x101B1D58,
                "NKPlus": 0x101BCE58,
            }
        base = bases[source]
        finalize_on_exit, stop_on_error = (
            uint32(finalize_on_exit),
            uint32(stop_on_error),
        )
        interval_ms, skip_response_validation = (
            uint32(interval_ms),
            uint32(skip_response_validation),
        )
        count = uint32(length) & 0xFF
        if request is not None and (
            type(request) not in (bytes, bytearray) or len(request) < count
        ):
            raise ValueError(
                "Native CMN request must contain its BYTE-sized copied payload"
            )
        key = "utility_ex:selected_cmn_fields" + (":controlled" if controlled else "")
        fields = self.state.get(key)
        if fields is None:
            fields = UtilityExSelectedCMNFields(0, bytes(256))
            self.state[key] = fields
        if not isinstance(fields, UtilityExSelectedCMNFields):
            raise TypeError("Concrete selected CMN shared fields required")
        backing = bytearray(fields.request)
        if len(backing) != 256:
            raise ValueError("Native CMN shared request backing must retain256 bytes")
        fields.interval_ms = interval_ms
        self.state[f"native_global:{base:x}"] = interval_ms
        fields.finalize_on_exit = finalize_on_exit
        self.state[f"native_global:{base + 4:x}"] = finalize_on_exit
        fields.stop_on_error = stop_on_error
        self.state[f"native_global:{base + 8:x}"] = stop_on_error
        fields.skip_response_validation = skip_response_validation
        self.state[f"native_global:{base + 12:x}"] = skip_response_validation
        # Old writers publish BYTE length beforecopy; modernwriters aftercopy.
        if source in ("NK12", "NK18"):
            fields.request_length = count
            self.state[f"native_global:{base + 0x110:x}"] = count
        if request is not None and count:
            backing[:count] = request[:count]
        fields.request = bytes(backing)
        self.state[f"native_global:{base + 16:x}"] = fields.request
        if source in ("NKDS4", "NKPlus"):
            fields.request_length = count
            self.state[f"native_global:{base + 0x110:x}"] = count
        # Native139f0 copies shared fields even when scheduler149d0 returnsbusy16.
        return UtilityExEngine(self).worker.start(
            lambda: UtilityExSelectedCMNWorker(self, self.comm("selected")).run(fields),
            10000,
        )

    def selected_p5_worker(self) -> UtilityExSelectedP5Worker:
        from scripts.utility_ex_lifecycle import UtilityExSelectedP5Worker

        if SOURCES[self.module_sha256] != "TY18":
            raise LookupError("Selected P5 worker source is not reviewed")
        key = f"utility_ex:selected_p5_worker:{self.module_sha256}"
        worker = self.state.get(key)
        if worker is None:
            worker = UtilityExSelectedP5Worker(self, self.comm("selected"))
            self.state[key] = worker
        if (
            not isinstance(worker, UtilityExSelectedP5Worker)
            or worker.context is not self
        ):
            raise TypeError("Concrete same-context selected P5 worker required")
        return worker

    def sis_driver_binding(self) -> UtilitySISDriverBinding:
        if self.sis_driver_exports is None:
            raise LookupError(
                "Explicit typed SIS DRIVER export registration unavailable"
            )
        if self._sis_driver is None:
            self._sis_driver = UtilitySISDriverBinding(
                self, dict(self.sis_driver_exports), loaded=self.driver_loaded
            )
        return self._sis_driver

    def p6_driver_binding(self, protocol: int) -> UtilityP6DriverBinding:
        protocol = uint32(protocol)
        if protocol not in (6, 0x8012):
            raise ValueError("P6 protocol must be6 or8012")
        if self.p6_driver_exports is None:
            raise LookupError(
                "Explicit typed P6 DRIVER export registration unavailable"
            )
        key = (self.module_sha256, protocol)
        if key not in self._p6_drivers:
            self._p6_drivers[key] = UtilityP6DriverBinding(
                self, protocol, dict(self.p6_driver_exports), loaded=self.driver_loaded
            )
        return self._p6_drivers[key]

    def _json_export(self, name: str) -> Callable[..., object]:
        exports = self.json_exports
        if exports is None:
            raise LookupError("Explicit JSON primitive registration unavailable")
        if set(exports) - {"JsonDGetData", "JsonSGetData"} or any(
            not callable(value) for value in exports.values()
        ):
            raise ValueError("Only literal JSON primitive exports accepted")
        function = exports.get(name)
        if function is None:
            raise LookupError(f"Native {name} primitive unavailable")
        return function

    @staticmethod
    def _json_inputs(kind: int, section: str, key: str) -> tuple[int, str, str]:
        kind = uint32(kind)
        if any(
            type(value) is not str or not value or "\0" in value
            for value in (section, key)
        ):
            raise ValueError("Nonempty literal JSON section and key required")
        return kind, section, key

    def json_d_get_data(self, kind: int, section: str, key: str) -> int:
        args = self._json_inputs(kind, section, key)
        result = self._json_export("JsonDGetData")(*args)
        if type(result) is not int:
            raise TypeError("JSON DWORD EAX integer required")
        return uint32(result)

    def json_s_get_data(self, kind: int, section: str, key: str) -> str:
        args = self._json_inputs(kind, section, key)
        result = self._json_export("JsonSGetData")(*args)
        if type(result) is not str:
            raise TypeError("Native JSON UTF16 string result required")
        if len(result.encode("utf-16-le")) > 16 * 1024 * 1024:
            raise ValueError(
                "JSON UTF16 string exceeds host resource allocation policy"
            )
        return result


_TIMER_STATUS_GLOBALS = {
    "79fc495c68eb099a7ebc0d1eefe0eafd80101ac0bc09a58d3f603ed556c84762": 269617096,
    "8d9623f028f23876f69cb02baa10e1881c01fa01a4f906013bd36266f7e0fb33": 269822132,
    "980435d6bb2d9c57aab29e8f281d2641e3822b3172728f223c975ec6493d3c1e": 269400580,
    "e85b2456b26d3966ca243c03fa775cf81ad58bf05689bdb87b616eda4c8b6f5f": 269160200,
    "797833dc0c798984fcb739c21ac6fbd5230871fb67495d3339698df2ee53753f": 270240636,
    "87bc49ada3f9dc8db442e74ebaf62ce868679b37d58fe3fdc4d3f24e31c4ce57": 268891060,
    "36dcdad2e72e29aae813db5576daf0168dd032b08a9cdda3841078dfb0b7b9fd": 270303404,
    "821bbfd9957679ceef4ac32c239b8840c984e98ac61050ce7348ac2bc88b04ce": 269744868,
}

_WORKER_RESULT_GLOBALS = {
    "NK12": "native_global:100e6270",
    "NK18": "native_global:1014af28",
    "NKDS4": "native_global:101b1f88",
    "NKPlus": "native_global:101bd088",
    "TY12": "native_global:100ab770",
    "TY18": "native_global:10118e38",
    "TYDS4": "native_global:100687b8",
    "TYPlus": "native_global:10134ab8",
}

_NK_CANCEL_GETTERS = {
    "NK12": (0xFAB0, 0xFAC0, 0xFAD0, 0xFAE0, 0xFAF0),
    "NK18": (0x17340, 0x17350, 0x17360, 0x17370, 0x17380),
    "NKDS4": (0x321B0, 0x321A0, 0x321C0, 0x321E0, 0x321F0),
    "NKPlus": (0x330C0, 0x330B0, 0x330D0, 0x330F0, 0x33100),
}


class UtilityWorker:
    """18 TYfe20/NK149d0 start: running15, busy16, no-handle99.

    Python cannot TerminateThread safely. A stop timeout leaves its worker owned
    and raises; it never pretends that native forced termination succeeded.
    """

    def __init__(self, context: UtilityExContext):
        self.context = context
        self.status = 0
        self.timeout_ms = 0
        self._thread: threading.Thread | None = None
        self._failure: BaseException | None = None
        self._lock = threading.RLock()

    def start(self, body: Callable[[], int], timeout_ms: int) -> int:
        timeout_ms = uint32(timeout_ms)
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return 16
            if self._thread is not None:
                self.get_status()
            self.context._cancel.clear()
            self.status, self.timeout_ms, self._failure = 15, timeout_ms, None
            self._publish_status(15)

            def run() -> None:
                try:
                    value = uint32(body())
                except BaseException as error:  # noqa: BLE001 - retain worker exception
                    with self._lock:
                        self._failure = error
                else:
                    with self._lock:
                        self._publish_status(value)
                        self.status = value

            self._thread = threading.Thread(target=run, name="utility-ex", daemon=True)
            self._thread.start()
            return 15

    @property
    def running(self) -> bool:
        """Keep receiver memory leased while the asynchronous callback is alive."""
        with self._lock:
            return self._thread is not None and self._thread.is_alive()

    def _publish_status(self, value: int) -> None:
        field = _WORKER_RESULT_GLOBALS.get(SOURCES.get(self.context.module_sha256, ""))
        if field is not None:
            self.context.state[field] = value

    def get_status(self) -> int:
        thread = self._thread
        if thread is None:
            if self.status == 15:
                self.status = 99
                self._publish_status(99)
            return self.status
        thread.join(0.05)
        if thread.is_alive():
            return self.status
        self._thread = None
        if self._failure is not None:
            error, self._failure = self._failure, None
            raise error
        return self.status

    def stop(self, timeout_ms: int | None = None) -> int:
        thread = self._thread
        if thread is None:
            self.context._cancel.clear()
            return 0
        timeout = self.timeout_ms if timeout_ms is None else uint32(timeout_ms)
        self.context._cancel.set()
        thread.join(timeout / 1000)
        if thread.is_alive():
            raise TimeoutError("UtilityEx worker remains owned after stop deadline")
        try:
            return self.get_status()
        finally:
            self.context._cancel.clear()


class UtilityExEngine:
    """Exact-source domain selection with a persistent native context.

    run_body is the internal worker-body seam. It is deliberately distinct from
    an exported native wrapper's mode check, scheduling and immediate return.
    """

    def __init__(self, context: UtilityExContext):
        self.context = context
        if context._worker is None:
            context._worker = UtilityWorker(context)
        self.worker = context._worker

    def _providers(self) -> list[tuple[Any, Collection[str]]]:
        from scripts import utility_ex_chassis, utility_ex_powertrain, utility_ex_ty

        sha = self.context.module_sha256
        if SOURCES[sha].startswith("NK"):
            providers: list[tuple[Any, Collection[str]]] = [
                (utility_ex_powertrain, utility_ex_powertrain.supported_operations(sha))
            ]
            if sha in (
                utility_ex_chassis.NK18_SHA256,
                utility_ex_chassis.NK12_SHA256,
                utility_ex_chassis.NK_DS4_SHA256,
                utility_ex_chassis.NK_GTS_SHA256,
            ):
                providers.append(
                    (utility_ex_chassis, utility_ex_chassis.supported_exports(sha))
                )
            return providers
        return [(utility_ex_ty, utility_ex_ty.supported_exports(sha))]

    def supported_bodies(self) -> tuple[str, ...]:
        return tuple(sorted({name for _, names in self._providers() for name in names}))

    def _cgw_security_ty18(self) -> int:
        """TY18 worker10150 and helpers10610/10980..10d20, plain selected stack."""
        from scripts.utility_ex_ty_retained_11 import _aes_block

        context = self.context
        comm = context.comm("selected")
        target = comm.read_target()
        old_busy = uint32(comm.read_field("native_rva:121f0"))
        primary: BaseException | None = None

        def configure(rva: int, value: int) -> None:
            comm.configure(f"native_rva:{rva:x}", value)

        def exchange(request: bytes) -> tuple[int, bytes]:
            status, reply = comm.exchange_plain(request)
            if type(reply) is not bytes or len(reply) > 4128:
                raise ValueError("CGW native reply backing exceeded")
            return uint32(status), reply

        def session() -> tuple[int, int]:
            status, reply = exchange(b"\x10\x5f")
            return (status or (3 if len(reply) != 2 else 0)), (
                reply[1] if not status and len(reply) >= 2 else 0 if not status else 255
            )

        def change(value: int) -> int:
            status, reply = exchange(bytes((0x10, value)))
            return status or (3 if len(reply) != 2 else 0)

        def authenticate() -> int:
            attempts = 0
            while attempts < 3:
                status, reply = exchange(b"\x27\x01\x04")
                if status or len(reply) < 3 or reply[1] != 1:
                    attempts += 1
                    continue
                # Source helper copies16 bytes from its zeroed4128-byte buffer.
                seed = reply[2:18].ljust(16, b"\x00")
                material = context.read_module_data(0x100DA1D8, 17)
                if len(material) != 17 or material[16] != 0 or 0 in material[:16]:
                    raise LookupError("Source CGW AES128 key layout is not reviewed")
                encrypted = _aes_block(material[:16], seed)
                for _ in range(2):
                    status, reply = exchange(b"\x27\x02" + encrypted)
                    if status == 0 and len(reply) > 2 and reply[1] == 2:
                        return 0
                attempts += 1
                if attempts < 3:
                    context.native_sleep(10000)
            return 10005

        try:
            configure(0x121D0, 100)
            if context.is_cancelled():
                return 0
            configure(0x11F50, 0x10118D70)
            configure(0x11F60, 0x259)
            comm.select_target(0x786, 0)
            status = comm.initialize(0)
            if status:
                return status
            configure(0x121B0, 200)
            configure(0x121A0, 4)
            status, reply = exchange(b"\x3e\x00")
            status = status or (
                3 if len(reply) > 2 or reply[1:2] not in (b"", b"\x00") else 0
            )
            configure(0x121B0, 1000)
            configure(0x121A0, 3)
            if status:
                return 10001
            status, current = session()
            if status:
                return 10002
            if current != 0x88:
                if current != 1 and change(0x89):
                    return 10004
                if change(0x88):
                    return 10003
            configure(0x121A0, 0)
            status = authenticate()
            configure(0x121A0, 3)
            if status:
                session_status, current = session()
                if session_status:
                    context.native_sleep(5000)
                    return 10006
                if current != 1 and change(0x89):
                    context.native_sleep(5000)
                    return 10007
            return status
        except BaseException as error:
            primary = error
            raise
        finally:
            cleanup_error: BaseException | None = None
            for cleanup in (
                comm.finalize,
                lambda: configure(0x121D0, old_busy),
                lambda: configure(0x11F50, 0),
                lambda: configure(0x11F60, 0),
                lambda: comm.select_target(*target),
            ):
                try:
                    cleanup()
                except BaseException as error:  # noqa: BLE001 - finish every owned cleanup
                    if cleanup_error is None:
                        cleanup_error = error
            if cleanup_error is not None:
                if primary is None:
                    raise cleanup_error
                primary.add_note(
                    "CGW native cleanup also failed; explicit recovery required"
                )

    def invoke_machine(self, export: str, args: tuple[object, ...] = ()) -> int | None:
        """Preserve proven caller-visible EAX even for a declared void wrapper."""
        if type(export) is not str or type(args) is not tuple:
            raise TypeError("Literal UtilityEx export and tuple arguments required")
        if (
            SOURCES[self.context.module_sha256] == "TY18"
            and export == "_Ex2ComSecurityAccessCGW@0"
        ):
            if args:
                raise ValueError("CGW security export takes no arguments")
            # 11670 CALL fe20; ADD ESP,12; RET: scheduler EAX survives unchanged.
            return self.worker.start(self._cgw_security_ty18, 10000)
        return self.invoke(export, args)

    def invoke(self, export: str, args: tuple[object, ...] = ()) -> int | None:
        """Invoke a reviewed exported wrapper, preserving void/direct/worker ABI."""
        if type(export) is not str or type(args) is not tuple:
            raise TypeError("Literal UtilityEx export and tuple arguments required")
        source = SOURCES[self.context.module_sha256]
        if export in (
            "Ex2SetKeepAliveThread",
            "Ex2StartKeepAliveThread",
            "Ex2StopKeepAliveThread",
            "Ex2GetKeepAliveStatus",
        ):
            from scripts.utility_ex_lifecycle import UtilityExSelectedTimerKeepalive

            arity = {"Ex2SetKeepAliveThread": 6, "Ex2StopKeepAliveThread": 1}.get(
                export, 0
            )
            if len(args) != arity:
                raise ValueError(f"{export} requires {arity} arguments")
            if export == "Ex2GetKeepAliveStatus":
                return uint32(
                    self.context.state.get(
                        f"native_global:{_TIMER_STATUS_GLOBALS[self.context.module_sha256]:x}",
                        0,
                    )
                )
            key = f"utility_ex:selected_timer:{self.context.module_sha256}"
            timer = self.context.state.get(key)
            if timer is None:
                timer = UtilityExSelectedTimerKeepalive(
                    self.context, self.context.comm("selected")
                )
                self.context.state[key] = timer
            if (
                not isinstance(timer, UtilityExSelectedTimerKeepalive)
                or timer.context is not self.context
            ):
                raise TypeError("Concrete same-context selected native timer required")
            if export == "Ex2SetKeepAliveThread":
                length = uint32(args[2])
                payload = args[1]
                if length > 0x1020 or (
                    payload is not None and type(payload) not in (bytes, bytearray)
                ):
                    raise ValueError("Bounded native timer request bytes required")
                if payload is None:
                    if length:
                        raise ValueError("Native timer request pointer is null")
                    request = b""
                else:
                    assert isinstance(payload, (bytes, bytearray))
                    if len(payload) < length:
                        raise ValueError(
                            "Native timer request is shorter than its declared length"
                        )
                    request = bytes(payload[:length])
                timer.configure(
                    uint32(args[0]),
                    request,
                    uint32(args[3]),
                    uint32(args[4]),
                    uint32(args[5]),
                )
            elif export == "Ex2StartKeepAliveThread":
                timer.start()
            else:
                timer.stop(uint32(args[0]))
            return None
        if source == "TY18" and export in (
            "Ex2SetKeepAliveThreadP5",
            "Ex2StartKeepAliveThreadP5",
            "Ex2StopKeepAliveThreadP5",
            "Ex2GetKeepAliveStatusP5",
        ):
            arity = {"Ex2SetKeepAliveThreadP5": 5, "Ex2StopKeepAliveThreadP5": 1}.get(
                export, 0
            )
            if len(args) != arity:
                raise ValueError(f"{export} requires {arity} arguments")
            p5 = self.context.selected_p5_worker()
            if export == "Ex2SetKeepAliveThreadP5":
                length = uint32(args[2])
                payload = args[1]
                if length > 0x1020 or (
                    payload is not None and type(payload) not in (bytes, bytearray)
                ):
                    raise ValueError("Bounded native P5 request bytes required")
                if payload is None:
                    if length:
                        raise ValueError("Native P5 request pointer is null")
                    request = b""
                else:
                    assert isinstance(payload, (bytes, bytearray))
                    if len(payload) < length:
                        raise ValueError(
                            "Native P5 request is shorter than its declared length"
                        )
                    request = bytes(payload[:length])
                p5.configure(uint32(args[0]), request, uint32(args[3]), uint32(args[4]))
            elif export == "Ex2StartKeepAliveThreadP5":
                p5.start()
            elif export == "Ex2StopKeepAliveThreadP5":
                p5.stop(uint32(args[0]))
            else:
                return uint32(p5.get_status())
            return None
        if source in ("TY18", "TYPlus") and export in (
            "_Ex2InitializeDoIP@0",
            "Ex2InitializeDoIP",
        ):
            if (source, export) not in (
                ("TY18", "_Ex2InitializeDoIP@0"),
                ("TYPlus", "Ex2InitializeDoIP"),
            ):
                raise LookupError("DoIP export is not reviewed for exact source")
            from scripts.utility_ex_lifecycle import UtilityExSISDriver

            if args:
                raise ValueError(f"{export} takes no arguments")
            reset_global = "1011f684" if source == "TY18" else "10135be4"
            self.context.state[f"native_global:{reset_global}"] = 0
            # Actual manager vslot78(1b600) returnsout22 only for20/20.
            mode, protocol = (
                (self.context.mode, self.context.broker(0x70))
                if source == "TY18"
                else (
                    uint32(self.context.state.get("native_global:1013fa40", 0)),
                    uint32(self.context.state.get("native_global:1013fa44", 0)),
                )
            )
            if mode != 20 or protocol != 20:
                return None
            key = f"utility_ex:sis_driver:{self.context.module_sha256}"
            driver = self.context.state.get(key)
            if driver is None:
                driver = UtilityExSISDriver(
                    self.context, self.context.sis_driver_binding()
                )
                self.context.state[key] = driver
            if (
                not isinstance(driver, UtilityExSISDriver)
                or driver.context is not self.context
            ):
                raise TypeError("Concrete same-context SIS DRIVER required")
            driver.initialize_controller()
            return None
        if source == "TY18" and export in ("Ex2Initialize", "Ex2Finalize"):
            if args:
                raise ValueError(f"{export} takes no arguments")
            if export == "Ex2Finalize" and self.context.mode in (20, 21, 52):
                from scripts.utility_ex_lifecycle import stop_fixed_worker

                self.context.selected_p5_worker().stop(1)
                for address in (
                    0x1011D4F0,
                    0x1011C400,
                    0x1011B310,
                    0x1011A220,
                    0x1011E618,
                ):
                    stop_fixed_worker(self.context, address, 1)
            self.context.state["native_global:1011f768"] = 0
            # Native14520/14540 dispatch directly through the P3standard singleton.
            for protocol in (4, 6, 1):
                self.context.driver_binding(protocol)
            driver = self.context.driver_binding(4)
            return (
                driver.controller_initialize()
                if export == "Ex2Initialize"
                else driver.controller_finalize()
            )
        if source == "NK18" and export in ("Ex2Initialize", "Ex2Finalize"):
            if args:
                raise ValueError(f"{export} takes no arguments")
            if self.context.mode in (20, 21, 52):
                raise LookupError(
                    "Native keepalive/lower lifecycle is unavailable for mode"
                )
            self.context.state["native_global:1015185c"] = 0
            for protocol in (4, 6, 1):
                self.context.driver_binding(protocol)
            driver = self.context.driver_binding(4)
            return (
                driver.controller_initialize()
                if export == "Ex2Initialize"
                else driver.controller_finalize()
            )
        if source == "NK18" and export in (
            "Ex2GetBattVolt",
            "Ex2SetProgrammingVoltage",
            "Ex2CCU_01_ReadVBatt",
            "Ex2CCU_01_SetProgrammingVoltage",
            "Ex2CCU_01_ReProgrammingVoltage",
        ):
            arity = {"Ex2GetBattVolt": 1, "Ex2SetProgrammingVoltage": 2}.get(export, 0)
            if len(args) != arity:
                raise ValueError(f"{export} requires {arity} arguments")
            self.context.state["native_global:1015185c"] = 0
            self.context.state["native_global:10151854"] = 0x1014AEF0
            driver = self.context.driver_binding(4)
            if export == "Ex2GetBattVolt":
                return driver.read_battery_voltage(args[0])
            if export == "Ex2CCU_01_ReadVBatt":
                output = bytearray(4)
                status = driver.read_battery_voltage(output)
                voltage = int.from_bytes(output, "little")
                return 101 if status == 0 and 10000 <= voltage <= 16000 else 102
            pin, voltage = (
                (uint32(args[0]), uint32(args[1]))
                if export == "Ex2SetProgrammingVoltage"
                else (
                    15,
                    0xFFFFFFFE
                    if export.endswith("SetProgrammingVoltage")
                    else 0xFFFFFFFF,
                )
            )
            status = driver.set_programming_voltage(
                pin, voltage, self.context.broker(0xFB)
            )
            return (
                status
                if export == "Ex2SetProgrammingVoltage"
                else 101 + int(status != 0)
            )
        if source == "TY18" and export == "_Ex2ComSecurityAccessCGW@0":
            if args:
                raise ValueError("CGW security export takes no arguments")
            self.worker.start(self._cgw_security_ty18, 10000)
            return None
        contract = _TY_THREAD_WRAPPERS.get(source, {}).get(export)
        if contract is not None:
            arity, timeout = contract
            if len(args) != arity:
                raise ValueError(f"{export} requires {arity} arguments")
            inline = _TY_INLINE_RETURNS.get((source, export, self.context.mode))
            if inline is not None:
                return inline
            if (
                (source, export) not in _TY_ANY_MODE_WRAPPERS
                and self.context.mode
                not in _TY_MODE_OVERRIDES.get((source, export), (20, 21))
            ):
                return _TY_MODE_MISMATCH_RETURNS.get((source, export), 99)
            if export not in self.supported_bodies():
                raise LookupError("UtilityEx worker body unavailable for exact source")
            status = self.worker.start(lambda: self.run_body(export, args), timeout)
            if (source, export) in _TY_VOID_WRAPPERS:
                return None
            return _TY_RETURN_OVERRIDES.get((source, export), status)
        nk_contract = _NK_VARIANT_WRAPPERS.get(source, {}).get(
            export, _NK_WRAPPERS.get(export)
        )
        if source.startswith("NK") and nk_contract is not None:
            if (
                export in _NK_WRAPPER_SOURCE_LIMITS
                and source not in _NK_WRAPPER_SOURCE_LIMITS[export]
            ):
                raise LookupError(
                    "Native wrapper is not reviewed for this exact source"
                )
            mode, dispatch, timeout, arity, void, normalize = nk_contract
            if len(args) != arity:
                raise ValueError(f"{export} requires {arity} arguments")
            for (
                field,
                index,
                condition_index,
                nonzero,
            ) in _NK_PRE_MODE_ARGUMENT_WRITES.get((source, export), ()):
                if condition_index is not None:
                    condition = uint32(args[condition_index])
                    if (condition != 0) != nonzero:
                        continue
                self.context.state[field] = 0 if index == -1 else args[index]
            modes = (mode,) if isinstance(mode, int) else mode
            argument_mode = _NK_ARGUMENT_MODE_WRAPPERS.get((source, export))
            selected_mode = (
                self.context.mode
                if argument_mode is None
                else uint32(args[argument_mode])
            )
            if (
                not _NK_ANY_MODE_WRAPPERS.get((source, export), False)
                and selected_mode not in modes
            ) or any(
                self.context.broker(key) not in values
                for key, values in _NK_BROKER_PREDICATES.get((source, export), ())
            ):
                return None if void else 99
            if export not in self.supported_bodies():
                raise LookupError("UtilityEx worker body unavailable for exact source")
            if dispatch == "direct" or (dispatch == "conditional" and args[1] != 1):
                value = self.run_body(export, args)
                return None if void else value

            def body() -> int:
                value = self.run_body(export, args)
                if normalize and self.context.is_cancelled() and value in (2, 27):
                    counters = self.context.comm("selected").cancellation_counters()
                    (
                        busy_ms,
                        busy_count,
                        busy_limit,
                        no_response_count,
                        no_response_limit,
                    ) = (
                        counters[f"native_rva:{rva:x}"]
                        for rva in _NK_CANCEL_GETTERS[source]
                    )
                    if value == 27:
                        return 29 if busy_ms or busy_count != busy_limit else 28
                    if no_response_count != no_response_limit:
                        return 30
                return value

            assert timeout is not None
            value = self.worker.start(body, timeout)
            return None if void else value
        if export == "Ex2SetParaFromBroker":
            if args:
                raise ValueError("Ex2SetParaFromBroker takes no arguments")
            self.context.refresh_parameters()
            return None
        if export == "Ex2GetThreadStatus":
            if args:
                raise ValueError("Ex2GetThreadStatus takes no arguments")
            return self.worker.get_status()
        if source in ("TY18", "TYPlus") and export in (
            "Ex2FCHV_04_ChangeProtocol",
            "Ex2FCHV_04_CheckCanSendTime",
            "Ex2MS2ABS_01_CheckPressureSensorValue",
            "Ex2ECD_67_CharToInt",
            "Ex2ECD_67_HexToByte",
        ):
            return self.run_body(export, args)
        return self.start_export(export, args)

    def start_export(self, export: str, args: tuple[object, ...] = ()) -> int | None:
        if export in _TY_THREAD_WRAPPERS.get(SOURCES[self.context.module_sha256], {}):
            return self.invoke(export, args)
        source = SOURCES[self.context.module_sha256]
        if source.startswith("NK") and (
            export in _NK_WRAPPERS or export in _NK_VARIANT_WRAPPERS.get(source, {})
        ):
            return self.invoke(export, args)
        # Native wrappers NK18:6dd0, TY18:bd20/bd50. Other wrapper contracts
        # require their own exact branch/argument/timeout proof before enabling.
        contracts = {
            ("NK18", "Ex2ECD_InitialSupplyPump"): ((4,), 10000),
            ("TY18", "Ex2DOOR_01_StartConnectionHistoryClear"): ((20, 21), 10000),
            ("TY18", "Ex2FCHV_16_SendMessage"): ((20, 21), 10000),
            ("TYPlus", "Ex2DOOR_01_StartConnectionHistoryClear"): ((20, 21), 10000),
            ("TYPlus", "Ex2FCHV_16_SendMessage"): ((20, 21), 10000),
        }
        contract = contracts.get((SOURCES[self.context.module_sha256], export))
        if contract is None:
            raise LookupError("UtilityEx export wrapper has not been reviewed")
        modes, timeout = contract
        if self.context.mode not in modes:
            return 99
        if export not in self.supported_bodies():
            raise LookupError("UtilityEx worker body unavailable for exact source")
        return self.worker.start(lambda: self.run_body(export, args), timeout)

    def run_body(self, export: str, args: tuple[object, ...] = ()) -> int:
        if type(export) is not str or type(args) is not tuple:
            raise TypeError("Literal UtilityEx export and tuple arguments required")
        candidates = [
            provider for provider, names in self._providers() if export in names
        ]
        if len(candidates) != 1:
            raise LookupError("No unique reviewed UtilityEx body for exact source")
        value = candidates[0].run_body(export, args, self.context)
        if type(value) is not int or not -(1 << 31) <= value <= 0xFFFFFFFF:
            raise ValueError(
                "UtilityEx body must return an exact native 32-bit integer"
            )
        return value


class UtilityImportBinding:
    """Execute exact IT3 import thunks through authored native UtilityEx bodies.

    This is an IAT binding, not an interpreter for the caller's procedure/UI.
    The supplied caller and selected engine must be the exact proven image pair.
    """

    def __init__(self, caller_bytes: bytes, engine: UtilityExEngine):
        if type(caller_bytes) is not bytes:
            raise TypeError("Immutable original IT3 caller image required")
        if not isinstance(engine, UtilityExEngine):
            raise TypeError("Authored UtilityEx engine required for IT3 imports")
        self.caller_sha256 = hashlib.sha256(caller_bytes).hexdigest()
        if (
            _UTILITY_IMPORT_TARGETS.get(self.caller_sha256)
            != engine.context.module_sha256
        ):
            raise ValueError(
                "Exact source-bound IT3 caller and UtilityEx engine required"
            )
        self.engine = engine

    def invoke_iat(self, iat_rva: int, args: tuple[object, ...] = ()) -> int | None:
        export = _UTILITY_IMPORTS[self.caller_sha256].get(uint32(iat_rva))
        if export is None:
            raise LookupError("IT3 IAT slot has no exact UtilityEx source binding")
        return self.engine.invoke_machine(export, args)


class NativeUtilityExNK2(UtilityExEngine):
    def __init__(self, context: UtilityExContext):
        if not SOURCES[context.module_sha256].startswith("NK"):
            raise ValueError("NativeUtilityExNK2 requires an exact NK source")
        super().__init__(context)


class UtilityEx2TY(UtilityExEngine):
    def __init__(self, context: UtilityExContext):
        if not SOURCES[context.module_sha256].startswith("TY"):
            raise ValueError("UtilityEx2TY requires an exact TY source")
        super().__init__(context)


_DRIVER_SLOTS = {
    0x20: "PassThruConnect",
    0x24: "PassThruOemConnect",
    0x28: "PassThruDisconnect",
    0x2C: "PassThruIoctl",
    0x30: "PassThruGetLastError",
    0x34: "PassThruWriteMsgs",
    0x38: "PassThruReadMsgs",
    0x3C: "PassThruStartPeriodicMsg",
    0x40: "PassThruStopPeriodicMsg",
    0x44: "PassThruStartMsgFilter",
    0x48: "PassThruStopMsgFilter",
    0x4C: "PassThruSetProgrammingVoltage",
    0x50: "PassThruReadVersion",
    0x54: "J2534CtrlInitialize",
    0x58: "J2534CtrlFinalize",
}


_DRIVER_CONSTRUCTORS = {
    "NK18": "10020df0",
    "TY18": "1001bb00",
    "NK12": "10017730",
    "TY12": "10012ca0",
    "NKDS4": "1003a7d0",
    "TYDS4": "1000df90",
    "NKPlus": "1003b7e0",
    "TYPlus": "1001a970",
}


class UtilityDriverBinding:
    """Exact-source standard DRIVER constructor symbol resolution.

    Each supplied callable implements one typed lower export. This models the
    native nullable function table and its all-required flag, without executing
    the original DLL or treating a business callback as an SDK export.
    """

    def __init__(
        self,
        context: UtilityExContext,
        protocol: int,
        exports: dict[str, Callable[..., object]],
        *,
        loaded: bool = True,
        constructor_parameter: int = 0,
    ):
        if SOURCES[context.module_sha256] not in _DRIVER_CONSTRUCTORS:
            raise LookupError("DRIVER constructor not reviewed for exact source")
        if type(loaded) is not bool:
            raise TypeError("Explicit loaded-driver state required")
        self.module_sha256 = context.module_sha256
        self.protocol = uint32(protocol)
        self.constructor_parameter = uint32(constructor_parameter)
        self.oem_protocol = (self.protocol + 0x100) & 0xFFFFFFFF
        if set(exports) - set(_DRIVER_SLOTS.values()) or any(
            not callable(value) for value in exports.values()
        ):
            raise ValueError("Only literal native DRIVER primitive exports accepted")
        self.slots = {
            slot: exports.get(name) if loaded else None
            for slot, name in _DRIVER_SLOTS.items()
        }
        self.ready = all(value is not None for value in self.slots.values())
        self._programming_phase = int(self.ready)
        self._programming_handle = self.oem_protocol
        self._voltage_handles: set[int] = set()

    def resolve(self, offset: int) -> Callable[..., object] | None:
        if type(offset) is not int or offset not in _DRIVER_SLOTS:
            raise LookupError("Unknown native DRIVER function-table offset")
        return self.slots[offset]

    def slot_offset(self, name: str) -> int:
        """Return the reviewed native field offset for one literal SDK name."""
        for offset, symbol in _DRIVER_SLOTS.items():
            if name == symbol:
                return offset
        raise LookupError("Unknown native DRIVER symbol")

    def _raw_status(self, offset: int, *args: object) -> int:
        function = self.resolve(offset)
        if function is None:
            raise LookupError("Required native DRIVER symbol unavailable")
        result = function(*args)
        if not isinstance(result, PrimitiveResult) or result.value is not None:
            raise TypeError("Raw DRIVER status with native positional output required")
        return uint32(result.status)

    def _voltage_connect(self, initial_handle: int = 0) -> tuple[int, int]:
        if SOURCES[self.module_sha256] != "NK18":
            raise LookupError("Voltage DRIVER algorithm not reviewed for exact source")
        output = bytearray(uint32(initial_handle).to_bytes(4, "little"))
        status = self._raw_status(0x20, self.protocol, 0x200, output)
        if len(output) != 4:
            raise ValueError("Native connection output DWORD changed size")
        handle = int.from_bytes(output, "little")
        if status == 0:
            self._voltage_handles.add(handle)
        return status, handle

    def _voltage_disconnect(self, handle: int) -> None:
        # Preserve the native return ABI while retaining failed cleanup ownership.
        if self._raw_status(0x28, handle) == 0:
            self._voltage_handles.discard(handle)

    def read_battery_voltage(self, output: object) -> int:
        # NK18 21ef0 ASM: IOCTL3 and Disconnect statuses are intentionally ignored.
        if type(output) is not bytearray or len(output) < 4:
            raise ValueError("Writable native voltage DWORD required")
        status, handle = self._voltage_connect()
        if status:
            return 90
        try:
            self._raw_status(0x2C, handle, 3, None, output)
        except BaseException as primary:
            try:
                self._voltage_disconnect(handle)
            except BaseException as cleanup:  # noqa: BLE001 - preserve both host failures
                raise BaseExceptionGroup(
                    "Voltage read and disconnect failed", [primary, cleanup]
                ) from None
            raise
        self._voltage_disconnect(handle)
        return 0

    def set_programming_voltage(self, pin: int, voltage: int, control: int) -> int:
        # NK18 21f40 retains the programming connection and releases only on -1.
        if SOURCES[self.module_sha256] != "NK18":
            raise LookupError("Voltage DRIVER algorithm not reviewed for exact source")
        pin, voltage, control = uint32(pin), uint32(voltage), uint32(control)
        if voltage == 0xFFFFFFFE and self._programming_phase < 3:
            status, handle = self._voltage_connect(self._programming_handle)
            self._programming_handle = handle
            if status:
                return 90
            self._programming_phase = 3
        native_voltage = int(voltage != 0xFFFFFFFE) if control == 1 else voltage
        status = self._raw_status(0x4C, pin, native_voltage)
        if voltage == 0xFFFFFFFF:
            self._voltage_disconnect(self._programming_handle)
            self._programming_phase = 1
        return 92 if status else 0

    def controller_initialize(self) -> int:
        if SOURCES[self.module_sha256] in ("NK12", "TY12"):
            raise LookupError("Legacy controller initialize ABI is not reviewed")
        # TY18 1c060 discards the stack output DWORD; EAX is the SDK return.
        function = self.resolve(self.slot_offset("J2534CtrlInitialize"))
        if function is None:
            raise LookupError("Native J2534CtrlInitialize symbol unavailable")
        result = function(1, bytearray(4))
        if not isinstance(result, PrimitiveResult):
            raise TypeError("Typed DRIVER primitive result required")
        return uint32(result.status)

    def controller_finalize(self) -> int:
        function = self.resolve(self.slot_offset("J2534CtrlFinalize"))
        if function is None:
            raise LookupError("Native J2534CtrlFinalize symbol unavailable")
        result = function()
        if not isinstance(result, PrimitiveResult):
            raise TypeError("Typed DRIVER primitive result required")
        return uint32(result.status)


_SIS_DRIVER_SLOTS = {
    0x109C: "PassThruConnect_v0500",
    0x10A0: "PassThruDisconnect_v0500",
    0x10A4: "PassThruIoctl_v0500",
    0x10A8: "PassThruGetLastError",
    0x10AC: "PassThruReadMsgs_v0500",
    0x10B0: "PassThruStartPeriodicMsg_v0500",
    0x10B4: "PassThruStopPeriodicMsg_v0500",
    0x10B8: "PassThruStartMsgFilter_v0500",
    0x10BC: "PassThruStopMsgFilter_v0500",
    0x10C0: "PassThruSetProgrammingVoltage_v0500",
    0x10C4: "PassThruReadVersion_v0500",
    0x10C8: "J2534CtrlInitialize",
    0x10CC: "J2534CtrlFinalize",
    0x10D0: "PassThruLogicalConnect_v0500",
    0x10D4: "PassThruLogicalDisconnect_v0500",
    0x10D8: "PassThruSelect_v0500",
    0x10DC: "PassThruQueueMsgs_v0500",
}


class UtilitySISDriverBinding:
    """TY18/TYPlus SIS tables with source-specific readiness and controller ABI."""

    def __init__(
        self,
        context: UtilityExContext,
        exports: dict[str, Callable[..., object]],
        *,
        loaded: bool = True,
    ):
        if SOURCES[context.module_sha256] not in ("TY18", "TYPlus"):
            raise LookupError("SIS DRIVER constructor not reviewed for exact source")
        if type(loaded) is not bool:
            raise TypeError("Explicit loaded-driver state required")
        names = _DRIVER_SLOTS | _SIS_DRIVER_SLOTS
        if set(exports) - set(names.values()) or any(
            not callable(value) for value in exports.values()
        ):
            raise ValueError(
                "Only literal native SIS DRIVER primitive exports accepted"
            )
        self.context, self.module_sha256 = context, context.module_sha256
        self.profile = SOURCES[context.module_sha256]
        self.protocol, self.oem_protocol, self.constructor_parameter = 0x800F, 0x810F, 0
        self.slots = {
            offset: exports.get(name) if loaded else None
            for offset, name in names.items()
        }
        self.base_ready = all(
            self.slots[offset] is not None for offset in _DRIVER_SLOTS
        )
        self.extended_ready = all(
            self.slots[offset] is not None for offset in _SIS_DRIVER_SLOTS
        )
        # The native +0x74 flag belongs to the extended v0500 table; base15
        # completeness remains a separate readiness fact.
        self.ready = self.extended_ready
        self.controller_initialize_arity = 2 if self.profile == "TY18" else 3

    def resolve(self, offset: int) -> Callable[..., object] | None:
        if type(offset) is not int or offset not in self.slots:
            raise LookupError("Unknown native SIS DRIVER function-table offset")
        return self.slots[offset]

    def slot_offset(self, name: str) -> int:
        for table in (_SIS_DRIVER_SLOTS, _DRIVER_SLOTS):
            for offset, symbol in table.items():
                if name == symbol:
                    return offset
        raise LookupError("Unknown native SIS DRIVER symbol")

    def controller_initialize_arguments(self, output: bytearray) -> tuple[object, ...]:
        if type(output) is not bytearray or len(output) != 4:
            raise ValueError("Mutable native controller DWORD required")
        if self.profile == "TY18":
            return (2, output)
        return (2, output, 0)

    def invoke_raw(self, name: str, *args: object) -> int:
        function = self.resolve(self.slot_offset(name))
        if function is None:
            raise LookupError("Required native SIS DRIVER symbol unavailable")
        result = function(*args)
        if not isinstance(result, PrimitiveResult) or result.value is not None:
            raise TypeError("Raw SIS status with positional output required")
        return uint32(result.status)


_P6_DRIVER_SLOTS = {
    0x24: "PassThruConnect",
    0x28: "PassThruOemConnect",
    0x2C: "PassThruDisconnect",
    0x30: "PassThruIoctl",
    0x34: "PassThruGetLastError",
    0x38: "PassThruWriteMsgs",
    0x3C: "PassThruReadMsgs",
    0x40: "PassThruStartPeriodicMsg",
    0x44: "PassThruStopPeriodicMsg",
    0x48: "PassThruStartMsgFilter",
    0x4C: "PassThruStopMsgFilter",
    0x50: "PassThruSetProgrammingVoltage",
    0x54: "PassThruReadVersion",
    0x58: "J2534CtrlInitialize",
    0x5C: "J2534CtrlFinalize",
}


class UtilityP6DriverBinding:
    """Exact TYPlus/NKPlus P6 table metadata and individual raw exports."""

    slots_by_offset = _P6_DRIVER_SLOTS

    def __init__(
        self,
        context: UtilityExContext,
        protocol: int,
        exports: dict[str, Callable[..., object]],
        *,
        loaded: bool = True,
    ):
        if SOURCES[context.module_sha256] not in ("TYPlus", "NKPlus"):
            raise LookupError("P6 DRIVER constructor not reviewed for exact source")
        if type(loaded) is not bool:
            raise TypeError("Explicit loaded-driver state required")
        if type(protocol) is not int or protocol not in (6, 0x8012):
            raise ValueError("P6 protocol must be6 or8012")
        if set(exports) - set(_P6_DRIVER_SLOTS.values()) or any(
            not callable(value) for value in exports.values()
        ):
            raise ValueError("Only literal native P6 primitive exports accepted")
        self.context, self.module_sha256 = context, context.module_sha256
        self.protocol = protocol
        self.constructor_parameter = 0
        self.oem_protocol = protocol + 0x100
        self.readiness_offset = 0x20
        self.controller_handle_offset = 0x1C
        self.slots = {
            offset: exports.get(name) if loaded else None
            for offset, name in _P6_DRIVER_SLOTS.items()
        }
        self.ready = all(value is not None for value in self.slots.values())

    def resolve(self, offset: int) -> Callable[..., object] | None:
        if type(offset) is not int or offset not in _P6_DRIVER_SLOTS:
            raise LookupError("Unknown native P6 DRIVER function-table offset")
        return self.slots[offset]

    def slot_offset(self, name: str) -> int:
        for offset, symbol in _P6_DRIVER_SLOTS.items():
            if name == symbol:
                return offset
        raise LookupError("Unknown native P6 DRIVER symbol")

    def invoke_raw(self, name: str, *args: object) -> int:
        function = self.resolve(self.slot_offset(name))
        if function is None:
            raise LookupError("Required native P6 DRIVER symbol unavailable")
        result = function(*args)
        if not isinstance(result, PrimitiveResult) or result.value is not None:
            raise TypeError("Raw P6 status with positional output required")
        return uint32(result.status)


# Independently reviewed wrappers on all four exact NK sources.
# Facts: mode, dispatch, timeout, arity, void return, worker normalization.
_NK_WRAPPERS = {
    "Ex2ABS_01_BeginSolenoidDrive": (3, "thread", 10000, 1, False, False),
    "Ex2ABS_BeginAirBleed_Resurrection": (3, "thread", 10000, 1, False, False),
    "Ex2ABS_BeginAirBleed_TRC": (3, "thread", 10000, 1, False, False),
    "Ex2ABS_BeginSolenoidDrive_ABS": (3, "thread", 10000, 1, False, False),
    "Ex2ABS_BeginSolenoidDrive_TRC": (3, "thread", 10000, 1, False, False),
    "Ex2ABS_EndAirBleed_TRC": (3, "conditional", 10000, 2, False, False),
    "Ex2ABS_EndSolenoidDrive_ABS": (3, "conditional", 10000, 2, False, False),
    "Ex2ABS_EndSolenoidDrive_TRC": (3, "conditional", 10000, 2, False, False),
    "Ex2ECD_11_InitCrankTimeValue": (4, "thread", 10000, 0, False, True),
    "Ex2ECD_12_GetSupportInfo": (4, "direct", None, 1, False, False),
    "Ex2ECD_12_InitAFSensorLearn": (4, "thread", 10000, 1, False, True),
    "Ex2ECD_22_ClearZFCLearningValues": (4, "thread", 10000, 1, False, False),
    "Ex2ECD_23_ClearDPFAshValue": (4, "thread", 10000, 0, False, False),
    "Ex2ECD_25_ClearLearningValues": (4, "thread", 10000, 1, False, False),
    "Ex2ECD_26_ReadPresetValue": (4, "direct", None, 1, False, False),
    "Ex2ECD_26_WritePresetValue": (4, "thread", 10000, 1, False, False),
    "Ex2ECD_InitialSupplyPump": (4, "thread", 10000, 0, False, False),
    "Ex2SMRT_03_CompleteCheck": (3, "thread", 10000, 1, False, False),
    "Ex2SMRT_03_GetEntryKey": (3, "direct", None, 2, False, False),
    "Ex2SMRT_03_MasterKeyCheck": (3, "thread", 10000, 0, False, False),
    "Ex2SMRT_03_ModeEnd": (3, "direct", None, 0, False, False),
    "Ex2SMRT_03_ModeEntry": (3, "direct", None, 0, False, False),
    "Ex2SMRT_08_CompleteCheck": (3, "thread", 10000, 2, False, False),
    "Ex2SMRT_08_GetEntryKey": (3, "direct", None, 2, False, False),
    "Ex2SMRT_08_MasterKeyCheck": (3, "thread", 10000, 0, False, False),
    "Ex2SMRT_08_ModeEnd": (3, "direct", None, 0, False, False),
    "Ex2SMRT_08_ModeEntry": (3, "direct", None, 0, False, False),
    "Ex2SMRT_31_GetSupportInfo": (3, "direct", None, 0, False, False),
    "Ex2SMRT_31_GetTheKeyStatus": (3, "thread", 10000, 1, False, False),
    "Ex2SMRT_31_RequestKeyCodeRegistration": (3, "thread", 10000, 1, False, False),
    "Ex2SMRT_31_TerminateKeyCodeRegistration": (3, "thread", 10000, 1, False, False),
    "Ex2SMRT_31_TerminateKeyCodeRegistrationNoChk": (
        3,
        "thread",
        10000,
        0,
        False,
        False,
    ),
    "Ex2SMRT_31_TerminateKeyCodeRegistrationNoChkOnce": (
        3,
        "direct",
        None,
        0,
        False,
        False,
    ),
    "Ex2SMRT_32_EndEraseMode": (3, "direct", None, 1, False, False),
    "Ex2SMRT_32_GetRegKeyNum": (3, "thread", 10000, 0, False, False),
    "Ex2SMRT_32_GetSupportInfo": (3, "direct", None, 0, False, False),
    "Ex2SMRT_32_GetTheKeyStatus_003": (3, "thread", 10000, 0, False, False),
    "Ex2SMRT_32_GetTheKeyStatus_005": (3, "thread", 10000, 0, False, False),
    "Ex2SMRT_32_StartEraseMode": (3, "thread", 10000, 0, False, False),
    "Ex2SMRT_EraseCheck": (3, "direct", None, 0, False, False),
    "Ex2SMRT_EraseGetKey": (3, "direct", None, 2, False, False),
    "Ex2SMRT_EraseKeyStatus": (3, "thread", 20000, 0, False, False),
    "Ex2SMRT_EraseModeEnd": (3, "direct", None, 0, False, False),
    "Ex2SMRT_EraseModeEntry": (3, "direct", None, 0, False, False),
    "Ex2SMRT_EraseModeStatus": (3, "thread", 10000, 0, False, False),
    "Ex2SMRT_SetProgressTimeOutFlg": (3, "direct", None, 0, True, False),
    "Ex2STR_ChangeRegistMode": (3, "thread", 10000, 0, False, False),
    "Ex2STR_ConfMasKey": (3, "direct", None, 0, False, False),
    "Ex2ECD_14_CheckCodeSupportInfo": (4, "direct", None, 1, False, False),
    "Ex2ECD_14_CheckCodeSupportWID20Info": (4, "direct", None, 1, False, False),
    "Ex2ECD_24_GetCodeSupportInfo": (4, "direct", None, 1, False, False),
    "Ex2ECD_31_CheckCodeSupportInfo": (4, "direct", None, 1, False, False),
    "Ex2STR_02_CheckIDCode": (3, "thread", 10000, 0, False, False),
    "Ex2STR_CheckIDCode": (3, "thread", 10000, 0, False, False),
    "Ex2STR_Init": (3, "direct", None, 0, False, False),
    "Ex2STR_RegMasKeyConf": (3, "direct", None, 1, False, False),
    "Ex2STR_GetRegKeyNumAfter": (3, "thread", 10000, 2, False, False),
    "Ex2STR_GetRegKeyNumBefore": (3, "direct", None, 2, False, False),
    "Ex2ECD_31_ReadCode": (4, "thread", 10000, 1, False, True),
    "_Ex2STR_43_CheckOnlineSupport@4": (4, "direct", None, 1, False, False),
    "Ex2ECD_13_ReadCylinderInfo": (4, "direct", None, 1, False, False),
    "Ex2ECD_17_ReadCylinderInfo": (4, "direct", None, 1, False, False),
    "Ex2ECD_22_GetCylinderNum": (4, "direct", None, 1, False, False),
    "Ex2STR_WaitCompEraseKey": (3, "thread", 10000, 0, False, False),
    "Ex2STR_02_WaitCompEraseKey": (3, "thread", 10000, 0, False, False),
    "Ex2STR_GetRegistKey": (3, "thread", 10000, 1, False, False),
    "Ex2STR_WaitCompRegistKey": (3, "thread", 10000, 1, False, False),
    "Ex2STR_ConfRegArea": (3, "thread", 10000, 0, False, False),
    "Ex2STR_ConfRegMode": (3, "thread", 10000, 0, False, False),
    "Ex2STR_CngEraseMode": (3, "thread", 10000, 0, False, False),
    "Ex2STR_InitImbi": (3, "direct", None, 0, False, False),
    "Ex2STR_CngEraseModeImbi": (3, "thread", 10000, 0, False, False),
    "Ex2STR_16_Foced_Termination_Of_FM": (3, "thread", 10000, 0, False, False),
    "Ex2STR_42_ChkIDSupportInfo": (4, "direct", None, 0, False, False),
    "Ex2STR_42_ChkModeCondition": (4, "direct", None, 0, False, False),
    "Ex2STR_42_TransponderIDErasure": (4, "direct", None, 0, False, False),
    "Ex2STR_41_GetRegKeySupportInfo": (4, "direct", None, 3, False, False),
    "Ex2STR_41_EndFactoryMode": (4, "direct", None, 1, False, False),
    "Ex2STR_41_GetRegKeyNum": (4, "direct", None, 0, False, False),
    "Ex2STR_41_GetCurrentMode": (4, "direct", None, 1, False, False),
    "Ex2STR_41_GetCurrentStatus": (4, "direct", None, 0, False, False),
    "Ex2STR_41_GetCurrentModeRepeat": (4, "thread", 50000, 2, False, False),
    "Ex2STR_41_ResultTransponderID": (4, "direct", None, 0, False, False),
    "Ex2STR_41_GetCurrentStatusRepeat": (4, "thread", 50000, 3, False, False),
    "Ex2STR_41_RegTransponderID": (4, "thread", 10000, 3, False, False),
    "Ex2STR_41_RegNewKey": (4, "thread", 10000, 2, False, False),
    "Ex2STR_41_StartCommunication": (4, "thread", 10000, 4, False, False),
    "Ex2STR_41_StartKeepAliveCheck": (4, "thread", 10000, 1, False, False),
    "Ex2ECD_19_CheckCodeSupportInfo": (4, "direct", None, 1, False, False),
    "Ex2ECD_19_CheckCodeSupportWID20Info": (4, "direct", None, 1, False, False),
    "Ex2ECD_15_CheckCodeSupportWID20Info": (4, "direct", None, 2, False, False),
    "Ex2ECD_16_GetCodeSupportWID20": (4, "direct", None, 1, False, False),
    "Ex2ECD_20_CheckCodeSupportWID20Info": (4, "direct", None, 2, False, False),
    "Ex2ECD_09_ChgNormalLearningMode": (4, "direct", None, 1, False, False),
    "Ex2ECD_09_EraseDiagCode": (4, "direct", None, 1, False, False),
    "Ex2ECD_10_ChgDetailLearningMode": (4, "direct", None, 1, False, False),
    "Ex2ECD_10_EraseDiagCode": (4, "direct", None, 1, False, False),
    "Ex2STR_43_CheckRegisteredKeyNum": (4, "direct", None, 0, False, False),
    "Ex2STR_43_StartCommunication": (4, "direct", None, 0, False, False),
    "Ex2STR_43_CheckModeThread": (4, "thread", 20000, 0, False, False),
    "Ex2STR_20_ComfirmSwitchAccOff": (4, "thread", 10000, 0, False, False),
    "Ex2STR_20_ComfirmSwitchAccOffIgOn": (4, "thread", 10000, 0, False, False),
    "Ex2STR_22_ComfirmSwitchAccOffIgOn": (4, "thread", 10000, 0, False, False),
    "Ex2STR_20_GetSupportBitInfo": (4, "direct", None, 0, False, False),
    "Ex2STR_22_GetSupportInfo": (4, "direct", None, 0, False, False),
    "Ex2STR_41_StartKeepAlive": (4, "direct", None, 0, True, False),
    "Ex2STR_42_StartKeepAlive": (4, "direct", None, 0, False, False),
    "Ex2STR_20_StartKeyRegist": (4, "direct", None, 0, False, False),
    "Ex2STR_20_EndKeyRegist": (4, "direct", None, 0, False, False),
    "_Ex2STR_43_StartKeepAliveThread@4": (4, "thread", 10000, 1, True, False),
    "Ex2STR_20_GetTheKeyNumber": (4, "direct", None, 2, False, False),
    "Ex2STR_22_GetKeyNumber": (4, "direct", None, 2, False, False),
    "Ex2STR_20_StartKeepAlive": (4, "direct", None, 0, True, False),
    "Ex2STR_22_StartKeepAlive": (4, "direct", None, 0, True, False),
    "Ex2STR_55_StartKeepAlive": (4, "direct", None, 0, True, False),
    "Ex2STR_56_StartKeepAlive": (4, "direct", None, 0, True, False),
    "Ex2STR_StartKeepAlive": (3, "direct", None, 1, False, False),
    "Ex2STR_20_KeyRegist": (4, "thread", 10000, 1, False, False),
    "Ex2ECD_50_GetSupportInfo": (4, "direct", None, 0, False, False),
    "Ex2ECD_09_StartKeepAlive": ((), "direct", None, 0, False, False),
    "Ex2ECD_10_StartKeepAlive": ((), "direct", None, 0, False, False),
    "Ex2STR_53_GetKeySWStatus_Single": (4, "direct", None, 1, False, False),
    "Ex2STR_53_GetKeyStatus_Single": (4, "direct", None, 3, False, False),
    "Ex2STR_53_GetImmobilizerMode_Single": (4, "direct", None, 3, False, False),
    "Ex2STR_53_GetKeySWStatus": (4, "thread", 10000, 1, False, False),
    "Ex2STR_53_GetKeyStatus": (4, "thread", 10000, 3, False, False),
    "Ex2STR_53_GetImmobilizerMode": (4, "thread", 10000, 3, False, False),
    "Ex2STR_53_GetImmobilizerMode_OnExit": (4, "thread", 10000, 1, False, False),
    "Ex2STR_43_GetSupportInfo": (4, "direct", None, 4, False, False),
    "Ex2STR_43_ReqSecuritySeed": (4, "thread", 10000, 2, False, False),
    "Ex2STR_43_ClearAllKey": (4, "thread", 10000, 3, False, False),
}


# Exact whole-wrapper template: mode20/21, native scheduler, preserved pointer.
_TY_ANY_MODE_WRAPPERS = {("TY18", "Ex2PLG_01_FinalCom"): True}
_TY_VOID_WRAPPERS = {("TY18", "Ex2PLG_01_FinalCom"): True}

_TY_THREAD_WRAPPERS = {
    "TY12": {
        "Ex2ECO_10_TotalNumOfEngineStartsReset": (0, 10000),
        "Ex2IG_01_DisableAutoPowerOffFunc": (0, 10000),
        "Ex2MSW_01_SendMessage": (0, 10000),
        "Ex2DMOT_01_SendMessage": (0, 10000),
        "Ex2EV_02_SendMessage": (0, 10000),
        "Ex2PSAECD_03_RequestResetECU": (1, 10000),
        "Ex2PSAEFI_01_SendMessage": (1, 10000),
        "Ex2PSAECD_01_ReadTempWater": (1, 10000),
        "Ex2PSAECT_01_InitializeECU": (1, 10000),
        "Ex2PSAECT_01_ReadOilUsageCnt": (1, 10000),
        "Ex2PSAECT_01_WriteOilUsageCnt": (1, 10000),
        "Ex2PSADSG_01_ReadWheelIdentifires": (1, 10000),
        "Ex2PSADSG_02_ReadWheelIdentifires": (1, 10000),
        "Ex2PSADSG_01_ClearWheelIdentifires": (0, 10000),
        "Ex2PSADSG_04_ValveProgramCheck": (1, 10000),
        "Ex2PSADSG_02_WriteMainWheelIdentifires": (1, 10000),
        "Ex2PSADSG_02_WriteAdditionalWheelIdentifires": (1, 10000),
        "Ex2PSADSG_03_StartWheelTransmitter": (1, 10000),
        "Ex2ABS_17_SupportCheck": (1, 10000),
        "Ex2ABS_17_GetABSInfo": (1, 10000),
        "Ex2ABS_17_SychronizingABSInfo": (1, 10000),
        "Ex2ABS_18_SupportCheck": (1, 10000),
        "Ex2ABS_18_SetNeutralPos": (1, 10000),
        "Ex2ABS_21_SupportCheck": (1, 10000),
        "Ex2ABS_21_ChangeMode": (1, 10000),
        "Ex2ABS_21_CheckSensorStatus": (1, 10000),
        "Ex2ASG_02_CheckLearnedFlg": (1, 10000),
        "Ex2VGRS_04_StartLockRelease": (1, 10000),
        "Ex2VGRS_04_EndLockRelease": (1, 10000),
        "Ex2VGRS_04_StartNeutralCompMode": (1, 10000),
        "Ex2VGRS_04_EndNeutralCompMode": (1, 10000),
        "Ex2VGRS_04_ClearDTC": (1, 10000),
        "Ex2EMPS_07_ConfirmTheAssistMap": (1, 10000),
        "Ex2EMPS_07_ClearTheAssistMap": (1, 10000),
        "Ex2SMRT_33_ECU_ID_Registration": (1, 10000),
        "Ex2SMRT_33_GetKeyStatus": (1, 10000),
        "Ex2SMRT_35_CommunicationCheck": (1, 10000),
        "Ex2SMRT_35_GetSupportBitInformation": (1, 10000),
        "Ex2SMRT_35_ReGetSupportBitInformation": (1, 10000),
        "Ex2SMRT_35_TerminateCommunicationCheck": (1, 10000),
        "Ex2PSABSI_01_SendMessage": (0, 10000),
        "Ex2PSABSI_02_ExitEconomyMode": (0, 10000),
        "Ex2PSABSI_03_GetMode": (1, 10000),
        "Ex2PSABSI_03_SetMode": (1, 10000),
        "Ex2PSABSI_04_ForcingOfGaugingRequest": (0, 10000),
        "Ex2PSABSI_05_BSIStatusCheck": (1, 10000),
        "Ex2PSABSI_05_ExitCommunication": (0, 10000),
        "Ex2PSABSI_05_KeyRegister": (1, 10000),
        "Ex2PSABSI_05_UnlockRequest": (1, 10000),
        "Ex2PSABSI_06_BSIStatusCheck": (1, 10000),
        "Ex2PSABSI_06_ProgramADCCode": (1, 10000),
        "Ex2PSABSI_07_BSIStatusCheck": (1, 10000),
        "Ex2PSABSI_07_UnlockRequest": (1, 10000),
        "Ex2PSABSI_08_GetVIN": (1, 10000),
        "Ex2PSABSI_08_WriteVIN": (1, 10000),
        "Ex2RWG_01_DTCRead": (1, 10000),
        "Ex2RWG_01_LearnZeroPos": (1, 10000),
        "Ex2RWG_01_SupportCheck": (1, 10000),
        "Ex2OCC_05_ExitCommunication": (0, 10000),
        "Ex2OCC_05_Get30KgLoadRange": (1, 10000),
        "Ex2OCC_05_GetNoLoadRange": (1, 10000),
        "Ex2OCC_05_GetReclineLoadRange": (1, 10000),
        "Ex2OCC_05_GetSensorInfo": (1, 10000),
        "Ex2OCC_05_GetTotalWeightInfo": (1, 10000),
        "Ex2OCC_05_ZeroPointCalibration": (1, 10000),
        "Ex2OCC_06_SupportCheck": (1, 10000),
        "Ex2OCC_06_ZeroPointCalibration": (1, 10000),
        "Ex2ACC_01_LostCommunicationHistoryClear": (1, 10000),
        "Ex2ACC_01_LostCommunicationHistoryRead": (1, 10000),
        "Ex2ACC_01_SupportCheck": (1, 10000),
        "Ex2AHS_01_CameraOpticAxisAdjustmentRequest": (1, 10000),
        "Ex2AHS_01_CameraOpticAxisConfirmation": (1, 10000),
        "Ex2AHS_01_SupportCheck": (1, 10000),
        "Ex2AHS_02_CalibSwivelMarginAngle": (1, 10000),
        "Ex2AHS_02_SupportCheck": (1, 10000),
        "Ex2AHS_03_HeightSensorInitializationAndDTCCheck": (1, 10000),
        "Ex2AHS_03_SupportCheckAndDTCCheck": (1, 10000),
        "Ex2AHS_04_SupportCheckAndDTCCheck": (1, 10000),
        "Ex2AHS_04_SynchronizeInformationAndDTCCheck": (1, 10000),
        "Ex2STB_03_ExecutingSensorCalibration": (1, 10000),
        "Ex2STB_03_PreSensorCalibration": (1, 10000),
        "Ex2STB_03_StartSensorCalibration": (1, 10000),
        "Ex2STB_03_SupportCheck": (1, 10000),
        "Ex2STB_04_DriveActiveStabi": (1, 10000),
        "Ex2STB_04_ExitActiveStabi": (1, 10000),
        "Ex2STB_04_PreparateActiveStabi": (1, 10000),
        "Ex2STB_04_RestartActiveStabi": (1, 10000),
        "Ex2STB_04_SupportCheck": (1, 10000),
        "Ex2PSASRS_01_GetStatus": (1, 10000),
        "Ex2PSASRS_01_SetStatus": (1, 10000),
        "Ex2HNPCS_02_SendMessage": (1, 10000),
        "Ex2HNPCS_02_SupportCheck": (1, 10000),
        "Ex2HNPCS_03_InitializeTheLearningValue": (1, 10000),
        "Ex2HNPCS_03_SupportCheck": (1, 10000),
        "Ex2HNPCS_04_ClearPCSOperationCount": (1, 10000),
        "Ex2HNPCS_04_ReadPCSOperationCount": (1, 10000),
        "Ex2HNPCS_04_SupportCheck": (1, 10000),
        "Ex2PSAALM_01_SendMessage": (0, 10000),
        "Ex2LAMP_01_HeightSensorInitializationRequest": (1, 10000),
        "Ex2LAMP_01_SupportCheck": (1, 10000),
        "Ex2ASG_02_InitialLearning": (1, 10000),
        "Ex2ASG_02_GetLearnedStatus": (1, 10000),
        "Ex2ASG_02_GetLearnedStatusAfterTimeOut": (1, 10000),
        "Ex2ASG_02_GetLearnedStatusAt004": (1, 10000),
        "Ex2FC_04_CheckCanAirBleed": (1, 10000),
        "Ex2FC_04_ConfirmAirBleed": (1, 10000),
        "Ex2FC_04_ExecuteAirBleedHeater": (1, 10000),
        "Ex2FC_04_StartAirBleed": (1, 10000),
        "Ex2FC_04_StartKeepAlive": (1, 10000),
        "Ex2FC_04_SupportCheck": (1, 10000),
        "Ex2FC_05_MonitorAndActivateValve": (1, 10000),
        "Ex2FC_05_SupportCheck": (1, 10000),
        "Ex2HAL_02_HeightSensorInitializationAndDTCCheck": (1, 10000),
        "Ex2HAL_02_SupportCheckAndDTCCheck": (1, 10000),
        "Ex2HAL_03_SupportCheckAndDTCCheck": (1, 10000),
        "Ex2HAL_03_SynchronizeInformationAndDTCCheck": (1, 10000),
        "Ex2IC_01_SendMessage": (1, 10000),
        "Ex2RES_03_InitialRegistrationRequest": (1, 10000),
        "Ex2RES_03_SupportCheck": (1, 10000),
        "Ex2RES_04_RemoteStartRegistration": (1, 10000),
        "Ex2RES_04_SupportCheck": (1, 10000),
        "Ex2GS_01_CheckShutterStatus": (1, 10000),
        "Ex2GS_01_ShiftMode": (1, 10000),
        "Ex2GS_01_SupportCheck": (1, 10000),
        "Ex2GS_02_SendMessage": (1, 10000),
        "Ex2PCM_04_SendMessage": (1, 10000),
        "Ex2FSR_01_02_ActiveTest": (1, 10000),
        "Ex2FSR_01_02_SupportCheck": (1, 10000),
        "Ex2FSR_03_04_ActiveTest": (1, 10000),
        "Ex2FSR_03_04_SupportCheck": (1, 10000),
        "Ex2FSR_05_06_ClearAbnormalHistory": (1, 10000),
        "Ex2FSR_05_06_GetAbnormalHistory": (1, 10000),
        "Ex2FSR_05_06_SupportCheck": (1, 10000),
        "Ex2BCM_01_SendMessage": (1, 10000),
        "Ex2BCM_02_SendMessage": (1, 10000),
        "Ex2HNFCM_02_LearnTarget1": (1, 10000),
        "Ex2HNFCM_02_LearnTarget2": (1, 10000),
        "Ex2HNFCM_02_LearnTarget3": (1, 10000),
        "Ex2HNFCM_02_LearnTargetAll": (1, 10000),
        "Ex2HNFCM_02_ReadCameraData": (1, 10000),
        "Ex2HNFCM_02_SupportCheck": (1, 10000),
        "Ex2ITS_01_SendMessage": (0, 10000),
        "Ex2DR_01_GetDataList": (1, 10000),
        "Ex2AMT_01_GetHistoryData": (1, 10000),
        "Ex2ASG_02_SupportCheck": (1, 10000),
        "Ex2AMT_01_SupportCheck": (1, 10000),
        "Ex2EFI_28_LearningValueReset": (0, 10000),
        "Ex2AMT_01_WriteHistoryDataToECU": (1, 10000),
        "Ex2ASUS_08_EndExtendedSession": (1, 10000),
        "Ex2DP2_11_FrontBeamAxisAdjustment": (1, 10000),
        "Ex2DP2_11_SupportCheck": (1, 10000),
        "Ex2DP2_12_ActiveTest": (1, 10000),
        "Ex2DP2_12_GetSupportBitInformation": (1, 10000),
        "Ex2DP2_13_ActiveTest": (1, 10000),
        "Ex2DP2_13_GetSupportBitInformation": (1, 10000),
        "Ex2DP2_14_SendMessage": (1, 10000),
        "Ex2FRD_01_LearnTarget": (1, 10000),
        "Ex2EVB_02_READYONProhibitionCancel": (0, 10000),
        "Ex2VC_01_GetActuationCnt": (1, 10000),
        "Ex2VC_01_SupportCheck": (1, 10000),
        "Ex2VC_01_WriteActuationCnt": (1, 10000),
        "Ex2VC_02_Learn0Point": (1, 10000),
        "Ex2VC_02_SupportCheck": (1, 10000),
        "Ex2PI_01_GetAbsoTime": (1, 10000),
        "Ex2PI_01_GetCurrentTimeStamp": (1, 10000),
        "Ex2PI_01_GetFuseHistory": (1, 10000),
        "Ex2PI_01_SupportCheck": (1, 10000),
        "Ex2DSC_01_SendMessage": (1, 10000),
        "Ex2DSC_02_SendMessage": (1, 10000),
        "Ex2ASUS_04_ModifyVhight": (1, 10000),
        "Ex2ASUS_06_ConditionCheck": (1, 10000),
        "Ex2ASUS_06_LiftRise": (1, 10000),
        "Ex2ASUS_06_AirPressure": (1, 10000),
        "Ex2ASUS_06_TheHeightAndTank": (1, 10000),
        "Ex2ASUS_07_ConditionCheck": (1, 10000),
        "Ex2ASUS_07_LiftRise": (1, 10000),
        "Ex2ASUS_07_AirPressure": (1, 10000),
        "Ex2ASUS_07_TheHeightAndTank": (1, 10000),
        "Ex2DRS_02_StopActiveTest": (1, 10000),
        "Ex2DRS_03_StopActiveTest": (1, 10000),
        "Ex2BSM_01_02_SupportCheck": (1, 10000),
        "Ex2BSM_01_02_Mov2TestMode": (1, 10000),
        "Ex2BSM_01_02_ChkStilInTestMode": (1, 10000),
        "Ex2BSM_01_02_ExitTestMode": (1, 10000),
        "Ex2BSM_07_08_SupportCheck": (1, 10000),
        "Ex2BSM_07_08_GetAbnormalHistory": (1, 10000),
        "Ex2BSM_07_08_ClearAbnormalHistory": (1, 10000),
        "Ex2VGRS_04_SupportCheck": (1, 10000),
        "Ex2VGRS_04_CheckDTC": (1, 10000),
        "Ex2ASUS_04_SupportCheck": (1, 10000),
        "Ex2ASUS_04_ReturnVhight": (1, 10000),
        "Ex2ASUS_04_LearnKneeldownVheight": (1, 10000),
        "Ex2ASUS_04_CheckReturnedVhight": (1, 10000),
        "Ex2ASUS_05_SupportCheck": (1, 10000),
        "Ex2ASUS_05_ModifyVheightDownStart": (1, 10000),
        "Ex2ASUS_05_ModifyVheightStop": (1, 10000),
        "Ex2ASUS_05_CheckModifiedVheight": (1, 10000),
        "Ex2ASUS_05_ModifyVheightTimeOver": (1, 10000),
        "Ex2ASUS_05_LearnKneelDownVheight": (1, 10000),
        "Ex2ASUS_05_ReturnVheightStart": (1, 10000),
        "Ex2ASUS_05_CheckReturnedVheight": (1, 10000),
        "Ex2HV_15_HiVltFsAccLdHstRst": (0, 10000),
        "Ex2HV_17_BatteryStatusInfoReset": (0, 10000),
        "Ex2ASUS_08_ReadPressureSensor": (1, 10000),
        "Ex2ASUS_08_ModeTransEnterHeightCtrlProhibit": (1, 10000),
        "Ex2ASUS_08_StartCompressRaisingCtrl": (1, 10000),
        "Ex2ASUS_08_StartTankPressLowCtrl": (1, 10000),
        "Ex2ASUS_10_GetStatOfHeightCtrlProhibition": (1, 10000),
        "Ex2ASUS_10_ChgAndGetStatOfHeightCtrlProhibition": (1, 10000),
        "Ex2ARS_01_ReadDTCofVGRS": (1, 10000),
        "Ex2ARS_01_ClearOffSetValue": (1, 10000),
        "Ex2ARS_01_ReadDTCofARS": (1, 10000),
        "Ex2ARS_02_ChkVGRSDtc": (1, 10000),
        "Ex2ARS_02_ClrCompVal": (1, 10000),
        "Ex2ARS_02_ChkARSDtc": (1, 10000),
        "Ex2DRS_02_SupportCheck": (1, 10000),
        "Ex2DRS_02_ReadModeStatus": (1, 10000),
        "Ex2DRS_02_ReadRadarCruiseData": (1, 10000),
        "Ex2DRS_03_SupportCheck": (1, 10000),
        "Ex2DRS_03_ReadRadarCruiseData": (1, 10000),
        "Ex2DRS_03_ReadModeStatus": (1, 10000),
        "Ex2DRS_03_EndProcess": (1, 10000),
        "Ex2DRS_04_SendMessage": (1, 10000),
        "Ex2TPW_03_SendMessage": (1, 10000),
        "Ex2HV_13_READYONProhibitionCancel": (0, 10000),
        "Ex2HV_11_SendMessage": (0, 10000),
        "Ex2BSM_03_04_SupportCheck": (1, 10000),
        "Ex2BSM_03_04_ActiveTest": (1, 10000),
        "Ex2BSM_05_06_SupportCheck": (1, 10000),
        "Ex2BSM_05_06_ActiveTest": (1, 10000),
        "Ex2ARS_01_A8SupportCheck": (1, 10000),
        "Ex2ARS_01_ReturnActuatorCenterPos": (1, 10000),
        "Ex2ARS_02_SupportCheck": (1, 10000),
        "Ex2ARS_02_InitCompVal": (1, 10000),
        "Ex2ARS_03_SupportCheck": (1, 10000),
        "Ex2ARS_03_ActiveTest": (1, 10000),
        "Ex24WD_03_SupportCheck": (1, 10000),
        "Ex24WD_03_ChangePreventionMode": (1, 10000),
        "Ex2ABS4WD_01_SupportCheck": (1, 10000),
        "Ex2ABS4WD_01_ChangePreventionMode": (1, 10000),
        "Ex2PSAABS_01_SendMessage": (0, 10000),
        "Ex2PSAABS_02_SendMessage": (0, 10000),
        "Ex2PSAABS_03_StartActiveTest": (1, 10000),
        "Ex2PSAABS_03_ConfirmStatus": (1, 10000),
        "Ex2HV_12_SupportCheck": (1, 10000),
        "Ex2HV_12_GetDTCAndEEPROMStatus": (1, 10000),
        "Ex2HV_12_UpdateBatteryStatusInfo": (1, 10000),
        "Ex2HV_12_JudgementAfterUpdateInfo": (1, 10000),
        "Ex2HV_10_SupportCheck": (1, 10000),
        "Ex2HV_10_ReadBatteryStatus": (1, 10000),
        "Ex2HV_10_WaitingEEPROMWrite": (1, 10000),
        "Ex2HV_10_JudgementOfStckToReplace": (1, 10000),
        "Ex2EFI_44_SessionTransition": (1, 10000),
        "Ex2HV_14_ReadBatteryBlockVoltage": (1, 10000),
        "Ex2HV_14_ReadBatteryTemperature": (1, 10000),
        "Ex2HV_14_SupportCheck": (1, 10000),
        "Ex2MM_09_GetPIDSupportInfo": (1, 10000),
        "Ex2MM_09_GetSoftErrHistory": (1, 10000),
        "Ex2MM_10_GetDiscErrInfo": (1, 10000),
        "Ex2MM_10_SupportCheck": (1, 10000),
    },
    "TY18": {
        "Ex24WD_07_BackupMemoryClear1st": (1, 10000),
        "Ex24WD_07_BackupMemoryClear2nd": (1, 10000),
        "Ex24WD_07_SupportCheck": (1, 10000),
        "Ex2ABS_29_ShiftDealerMode": (0, 10000),
        "Ex2ABS_29_SupportCheck": (0, 10000),
        "Ex2ABS_31_RoutineStart": (1, 10000),
        "Ex2ABS_31_SupportCheck": (1, 10000),
        "Ex2ABS_32_EPBFullReleaseAndCheck": (0, 10000),
        "Ex2ABS_32_SupportCheck": (0, 10000),
        "Ex2ABS_33_CheckSensorStatus": (1, 10000),
        "Ex2ABS_33_ShiftDealerMode": (1, 10000),
        "Ex2ABS_33_ShiftNormalMode": (1, 10000),
        "Ex2ABS_33_SupportCheck": (1, 10000),
        "Ex2ABS_34_InitAllMemVal": (0, 10000),
        "Ex2ABS_41_DIDSupportCheck": (1, 10000),
        "Ex2ABS_41_DriveMotor": (1, 10000),
        "Ex2ABS_41_DriveSolenoid": (1, 10000),
        "Ex2ABS_41_StopMotor": (1, 10000),
        "Ex2ABS_47_CheckCalibrationStatus": (1, 10000),
        "Ex2ABS_47_DIDRIDSupportCheck": (1, 10000),
        "Ex2ABS_47_EndExtendedSession": (1, 10000),
        "Ex2ABS_47_ErrorEndExtendedSession": (1, 10000),
        "Ex2ABS_47_ExitEndExtendedSession": (1, 10000),
        "Ex2ABS_47_ShiftToDealerMode": (1, 10000),
        "Ex2ABS_48_ChangeToTheDealerMode": (1, 10000),
        "Ex2ABS_48_ChangeToTheNormalMode": (1, 10000),
        "Ex2ABS_48_ConfirmBitInformation": (1, 10000),
        "Ex2ABS_48_RetrunWait": (0, 10000),
        "Ex2ABS_48_StartECBProhibitionControl": (1, 10000),
        "Ex2ABS_48_StartRearAirBleedingDrive": (1, 10000),
        "Ex2ABS_48_StopTheRoutine": (1, 10000),
        "Ex2ABS_48_StopTheRoutineControl": (1, 10000),
        "Ex2ABS_48_StopTheRoutineTimeOver": (1, 10000),
        "Ex2ABS_48_VacuumFillingIncomplete": (1, 10000),
        "Ex2ABS_49_PatternDriveExecutingFlag": (1, 10000),
        "Ex2ABS_49_PatternDriveExecutingFlagError": (1, 10000),
        "Ex2ABS_49_PatternDriveExecutingFlagExit": (1, 10000),
        "Ex2ABS_49_StartSLM2Refresh": (1, 10000),
        "Ex2ABS_52_ReadBrakePadResidualThickness": (1, 10000),
        "Ex2ABS_52_WriteBrakePadResidualThickness": (1, 10000),
        "Ex2AHC_03_EndExtendedSession": (1, 10000),
        "Ex2AHC_03_ReadModeStatus": (1, 10000),
        "Ex2AHC_03_SwitchServiceMode": (1, 10000),
        "Ex2APP_03_StartIRProjectorInspection1st": (1, 10000),
        "Ex2APP_03_StartIRProjectorInspection2nd": (1, 10000),
        "Ex2APP_03_StartIRProjectorInspection3rd": (1, 10000),
        "Ex2APP_03_StartIRProjectorInspection4th": (1, 10000),
        "Ex2ASUS_08_EndExtendedSession": (1, 10000),
        "Ex2ASUS_10_ChgAndGetStatOfHeightCtrlProhibition": (1, 10000),
        "Ex2ASUS_10_GetStatOfHeightCtrlProhibition": (1, 10000),
        "Ex2AWD_04_Overwrite": (1, 10000),
        "Ex2BSM_13_14_23_24_SendMessage": (1, 10000),
        "Ex2BSM_15_16_25_26_SendMessage": (1, 10000),
        "Ex2DCM_30_SendMessage": (1, 10000),
        "Ex2DCM_40_SendMessage": (1, 10000),
        "Ex2DOOR_01_StartConnectionHistoryClear": (0, 10000),
        "Ex2ECD_59_Dummy": (1, 10000),
        "Ex2ECD_60_Dummy": (1, 10000),
        "Ex2ECO_10_TotalNumOfEngineStartsReset": (0, 10000),
        "Ex2EKDSS_02_SendMessage": (0, 10000),
        "Ex2EMPS_12_AutoRackCentering": (1, 10000),
        "Ex2EMPS_12_ReadRoutineStatus": (1, 10000),
        "Ex2EMPS_12_SteeringAngleCheck": (1, 10000),
        "Ex2EMPS_12_SteeringStart": (0, 10000),
        "Ex2FCHV_02_AutoPowerOFFCancel": (1, 10000),
        "Ex2FCHV_02_EndExtendedSession": (1, 10000),
        "Ex2FCHV_02_ReadData": (1, 10000),
        "Ex2FCHV_02_ReadPressure": (1, 10000),
        "Ex2FCHV_02_ReadTankShutValveClose": (1, 10000),
        "Ex2FCHV_02_ReadTankShutValveOpen": (1, 10000),
        "Ex2FCHV_02_ReadTankShutValveRetrun": (1, 10000),
        "Ex2FCHV_02_ReadTankShutValveStart": (1, 10000),
        "Ex2FCHV_02_ReadTemperature": (1, 10000),
        "Ex2FCHV_02_SupportCheck": (1, 10000),
        "Ex2FCHV_02_TankShutValveDrive": (1, 10000),
        "Ex2FCHV_02_TankShutValveStop": (1, 10000),
        "Ex2FCHV_05_SendMessage": (1, 10000),
        "Ex2FCHV_06_SendMessage": (1, 10000),
        "Ex2FCHV_07_Overwrite": (1, 10000),
        "Ex2FCHV_07_ReadValues": (1, 10000),
        "Ex2FCHV_07_SupportCheck": (1, 10000),
        "Ex2FCHV_08_ReadValues": (1, 10000),
        "Ex2FCHV_08_SupportCheck": (1, 10000),
        "Ex2FCHV_08_WriteValues": (1, 10000),
        "Ex2FCHV_09_SendMessage": (1, 10000),
        "Ex2FCHV_10_SendMessage": (1, 10000),
        "Ex2FCHV_13_SendMessage": (1, 10000),
        "Ex2FCHV_14_SendMessage": (1, 10000),
        "Ex2FCHV_16_SendMessage": (1, 10000),
        "Ex2FCM_04_RequestRoutineResult": (1, 10000),
        "Ex2FCM_04_StartFrontRaderSensorMemory": (1, 10000),
        "Ex2FCM_07_CheckNaviInitialization": (1, 10000),
        "Ex2FCM_07_StartNaviInitialization": (1, 10000),
        "Ex2FCM_12_CheckPCSForcedBrakeActivation": (1, 10000),
        "Ex2FCM_12_StartPCSForcedBrakeActivation": (1, 10000),
        "Ex2FCM_12_StopPCSForcedBrakeActivation": (1, 10000),
        "Ex2FCM_13_SendMessage": (1, 10000),
        "Ex2GWY_02_TimeoutInit": (1, 10000),
        "Ex2GWY_03_EndInitErr": (1, 10000),
        "Ex2HF_01_Com_TanksNumberValueClear": (0, 10000),
        "Ex2IG_01_DisableAutoPowerOffFunc": (0, 10000),
        "Ex2IG_02_SendMessage": (0, 10000),
        "Ex2MM_41_TransferToPairingMode": (0, 10000),
        "Ex2PLG_01_RequestDiagnosisResult_Uds": (1, 10000),
        "Ex2PLG_01_RequestRoutineResult_Uds": (1, 10000),
        "Ex2PLG_01_StartDiagnosis_Uds": (1, 10000),
        "Ex2PLG_01_SupportCheck_Uds": (1, 10000),
        "Ex2ROOF_01_ImpactDetectionInfoClear": (0, 10000),
        "Ex2SBW_01_EndExtendedSession": (1, 10000),
        "Ex2STRACT_03_EndExtendedSession": (1, 10000),
        "Ex2MIR_01_SendMessage": (1, 10000),
        "Ex2SAS_02_SendMessage": (0, 10000),
        "Ex2MS2MM_01_SendMessage": (0, 10000),
        "Ex2MSW_01_SendMessage": (0, 10000),
        "Ex2DMOT_01_SendMessage": (0, 10000),
        "Ex2EV_02_SendMessage": (0, 10000),
        "Ex2MS2BSRL_01_SendMessage": (1, 10000),
        "Ex2FCHV_01_SendMessage": (1, 10000),
        "Ex2FCHV_03_SendMessage": (1, 10000),
        "Ex2FCHV_04_SendMessage": (1, 10000),
        "Ex2FCHV_11_SendMessage": (1, 10000),
        "Ex2FCHV_12_SendMessage": (1, 10000),
        "Ex2FCHV_17_SendMessage": (1, 10000),
        "Ex2MS2ABS_01_SendMessage": (1, 10000),
        "Ex2MS2ABS_02_SendMessage": (1, 10000),
        "Ex2MS2ABS_03_SendMessage": (1, 10000),
        "Ex2MS2ABS_05_SendMessage": (0, 10000),
        "Ex2MS2EFI_01_SendMessage": (1, 10000),
        "Ex2MS2EFI_02_SendMessage": (0, 10000),
        "Ex2MS2GWY_01_SendMessage": (1, 10000),
        "Ex2MS2PWD_01_SendMessage": (1, 10000),
        "Ex2MS2PWD_02_SendMessage": (1, 10000),
        "Ex2PSAECD_03_RequestResetECU": (1, 10000),
        "Ex2PSAEFI_01_SendMessage": (1, 10000),
        "Ex2PSAECD_01_ReadTempWater": (1, 10000),
        "Ex2PSAECT_01_InitializeECU": (1, 10000),
        "Ex2PSAECT_01_ReadOilUsageCnt": (1, 10000),
        "Ex2PSAECT_01_WriteOilUsageCnt": (1, 10000),
        "Ex2PSADSG_01_ReadWheelIdentifires": (1, 10000),
        "Ex2PSADSG_02_ReadWheelIdentifires": (1, 10000),
        "Ex2PSADSG_01_ClearWheelIdentifires": (0, 10000),
        "Ex2PSADSG_04_ValveProgramCheck": (1, 10000),
        "Ex2PSADSG_02_WriteMainWheelIdentifires": (1, 10000),
        "Ex2PSADSG_02_WriteAdditionalWheelIdentifires": (1, 10000),
        "Ex2PSADSG_03_StartWheelTransmitter": (1, 10000),
        "Ex2MS2EFI_04_SendMessage": (1, 10000),
        "Ex2EFI_57_ReadDisplayFrequencyMode": (1, 10000),
        "Ex2EFI_57_WriteDisplayFrequencyMode": (1, 10000),
        "Ex2ECD_57_DPFAshValueClear": (0, 10000),
        "Ex2ECD_55_SendMessage": (0, 10000),
        "Ex2ABS_17_SupportCheck": (1, 10000),
        "Ex2ABS_17_GetABSInfo": (1, 10000),
        "Ex2ABS_17_SychronizingABSInfo": (1, 10000),
        "Ex2ABS_18_SupportCheck": (1, 10000),
        "Ex2ABS_18_SetNeutralPos": (1, 10000),
        "Ex2ABS_21_SupportCheck": (1, 10000),
        "Ex2ABS_21_ChangeMode": (1, 10000),
        "Ex2ABS_21_CheckSensorStatus": (1, 10000),
        "Ex2ABS_30_SendMessage": (1, 10000),
        "Ex2ABS_44_SendMessage": (0, 10000),
        "Ex2ABS_46_SendMessage": (1, 10000),
        "Ex2ABS_51_SendMessage": (1, 10000),
        "Ex2ASUS_04_SupportCheck": (1, 10000),
        "Ex2ASUS_04_ModifyVhight": (1, 10000),
        "Ex2ASUS_04_ReturnVhight": (1, 10000),
        "Ex2ASUS_04_LearnKneeldownVheight": (1, 10000),
        "Ex2ASUS_04_CheckReturnedVhight": (1, 10000),
        "Ex2ASUS_05_SupportCheck": (1, 10000),
        "Ex2ASUS_05_ModifyVheightDownStart": (1, 10000),
        "Ex2ASUS_05_ModifyVheightStop": (1, 10000),
        "Ex2ASUS_05_CheckModifiedVheight": (1, 10000),
        "Ex2ASUS_05_ModifyVheightTimeOver": (1, 10000),
        "Ex2ASUS_05_LearnKneelDownVheight": (1, 10000),
        "Ex2ASUS_05_ReturnVheightStart": (1, 10000),
        "Ex2ASUS_05_CheckReturnedVheight": (1, 10000),
        "Ex2ASUS_06_ConditionCheck": (1, 10000),
        "Ex2ASUS_06_LiftRise": (1, 10000),
        "Ex2ASUS_06_AirPressure": (1, 10000),
        "Ex2ASUS_06_TheHeightAndTank": (1, 10000),
        "Ex2ASUS_07_ConditionCheck": (1, 10000),
        "Ex2ASUS_07_LiftRise": (1, 10000),
        "Ex2ASUS_07_AirPressure": (1, 10000),
        "Ex2ASUS_07_TheHeightAndTank": (1, 10000),
        "Ex2ASUS_08_ReadPressureSensor": (1, 10000),
        "Ex2ASUS_08_ModeTransEnterHeightCtrlProhibit": (1, 10000),
        "Ex2ASUS_08_StartCompressRaisingCtrl": (1, 10000),
        "Ex2ASUS_08_StartTankPressLowCtrl": (1, 10000),
        "Ex2ASUS_13_SupportCheck": (1, 10000),
        "Ex2ASUS_13_TestStart": (1, 10000),
        "Ex2ASUS_13_GetHeight": (1, 10000),
        "Ex2ASUS_13_NormalMode": (1, 10000),
        "Ex2ASUS_13_NormalMode005": (1, 10000),
        "Ex2ASUS_13_NormalMode008": (1, 10000),
        "Ex2ASUS_13_HeightOffset": (1, 10000),
        "Ex2ASUS_13_TestStop": (1, 10000),
        "Ex2ASUS_13_GetHeightSec50": (1, 10000),
        "Ex2BSM_01_02_SupportCheck": (1, 10000),
        "Ex2BSM_01_02_Mov2TestMode": (1, 10000),
        "Ex2BSM_01_02_ChkStilInTestMode": (1, 10000),
        "Ex2BSM_01_02_ExitTestMode": (1, 10000),
        "Ex2BSM_07_08_SupportCheck": (1, 10000),
        "Ex2BSM_07_08_GetAbnormalHistory": (1, 10000),
        "Ex2BSM_07_08_ClearAbnormalHistory": (1, 10000),
        "Ex2BSM_03_04_SupportCheck": (1, 10000),
        "Ex2BSM_03_04_ActiveTest": (1, 10000),
        "Ex2BSM_03_04_ActiveTestCon3_5": (1, 10000),
        "Ex2BSM_05_06_SupportCheck": (1, 10000),
        "Ex2BSM_05_06_ActiveTest": (1, 10000),
        "Ex2BSM_27_SendMessage": (1, 10000),
        "Ex2BSM_28_SendMessage": (1, 10000),
        "Ex2ARS_01_A8SupportCheck": (1, 10000),
        "Ex2ARS_01_ReadDTCofVGRS": (1, 10000),
        "Ex2ARS_01_ClearOffSetValue": (1, 10000),
        "Ex2ARS_01_ReadDTCofARS": (1, 10000),
        "Ex2ARS_01_ReturnActuatorCenterPos": (1, 10000),
        "Ex2ARS_02_SupportCheck": (1, 10000),
        "Ex2ARS_02_ChkVGRSDtc": (1, 10000),
        "Ex2ARS_02_ClrCompVal": (1, 10000),
        "Ex2ARS_02_ChkARSDtc": (1, 10000),
        "Ex2ARS_02_InitCompVal": (1, 10000),
        "Ex2ARS_04_SendMessage": (1, 10000),
        "Ex2ARS_05_SendMessage": (1, 10000),
        "Ex2ARS_03_SupportCheck": (1, 10000),
        "Ex2ARS_03_ActiveTest": (1, 10000),
        "Ex2VGRS_04_SupportCheck": (1, 10000),
        "Ex2VGRS_04_StartLockRelease": (1, 10000),
        "Ex2VGRS_04_EndLockRelease": (1, 10000),
        "Ex2VGRS_04_StartNeutralCompMode": (1, 10000),
        "Ex2VGRS_04_EndNeutralCompMode": (1, 10000),
        "Ex2VGRS_04_CheckDTC": (1, 10000),
        "Ex2VGRS_04_ClearDTC": (1, 10000),
        "Ex2DRS_02_SupportCheck": (1, 10000),
        "Ex2DRS_02_ReadModeStatus": (1, 10000),
        "Ex2DRS_02_ReadRadarCruiseData": (1, 10000),
        "Ex2DRS_02_StopActiveTest": (1, 10000),
        "Ex2DRS_03_SupportCheck": (1, 10000),
        "Ex2DRS_03_ReadRadarCruiseData": (1, 10000),
        "Ex2DRS_03_StopActiveTest": (1, 10000),
        "Ex2DRS_03_ReadModeStatus": (1, 10000),
        "Ex2DRS_03_EndProcess": (1, 10000),
        "Ex2DRS_04_SendMessage": (1, 10000),
        "Ex2EMPS_07_ConfirmTheAssistMap": (1, 10000),
        "Ex2EMPS_07_ClearTheAssistMap": (1, 10000),
        "Ex2EMPS_09_SupportCheck": (1, 10000),
        "Ex2EMPS_09_ModeTransition": (1, 10000),
        "Ex2EMPS_11_SendMessage": (1, 10000),
        "Ex2EMPS_13_SendMessage": (1, 10000),
        "Ex24WD_03_SupportCheck": (1, 10000),
        "Ex24WD_03_ChangePreventionMode": (1, 10000),
        "Ex2ABS4WD_01_SupportCheck": (1, 10000),
        "Ex2ABS4WD_01_ChangePreventionMode": (1, 10000),
        "Ex2TPW_07_SupportCheck": (1, 10000),
        "Ex2TPW_07_ReadSystemOperationMode": (1, 10000),
        "Ex2TPW_07_WriteSystemOperationMode": (1, 10000),
        "Ex2EPB_04_SendMessage": (0, 10000),
        "Ex2EPB_05_SendMessage": (1, 10000),
        "Ex2EKDSS_01_SendMessage": (1, 10000),
        "Ex2PSAABS_01_SendMessage": (0, 10000),
        "Ex2PSAABS_02_SendMessage": (0, 10000),
        "Ex2PSAABS_03_StartActiveTest": (1, 10000),
        "Ex2PSAABS_03_ConfirmStatus": (1, 10000),
        "Ex2SMRT_62_DigiKeySupArea": (1, 10000),
        "Ex2SMRT_62_StartDiagMode": (1, 10000),
        "Ex2SMRT_62_TerminateDiagMode": (1, 10000),
        "Ex2MS2SMRT_08_SendMessage": (1, 10000),
        "Ex2MS2SMRT_09_SendMessage": (1, 10000),
        "Ex2MS2BDY_01_SendMessage": (1, 10000),
        "Ex2MS2RAB_01_SendMessage": (1, 10000),
        "Ex2MS2SAS_02_SendMessage": (1, 10000),
        "Ex2ASG_02_CheckLearnedFlg": (1, 10000),
        "Ex2EFI_58_SupportCheck": (1, 10000),
        "Ex2EFI_58_ReadPMDeposition": (1, 10000),
        "Ex2EFI_58_ResultPMRegenerateMode": (1, 10000),
        "Ex2EFI_58_StopPMRegenerateMode": (0, 10000),
        "Ex2EFI_58_StartPMRegenerateMode": (1, 10000),
        "Ex2EFI_58_ReadGPFDealerVehicleStopRegenerateStop": (1, 10000),
        "Ex2TPW_06_SendMessage": (1, 10000),
        "Ex2TPW_08_SendMessage": (1, 10000),
        "Ex2TPW_13_SendMessage": (1, 10000),
        "Ex2MS2SMRT_05_SendMessage": (1, 10000),
        "Ex2MS2SMRT_07_SendMessage": (1, 10000),
        "Ex2MS2DCM_02_SendMessage": (1, 10000),
        "Ex2MS2MET_01_SendMessage": (1, 10000),
        "Ex2MS2TPW_01_SendMessage": (1, 10000),
        "Ex2PSABSI_01_SendMessage": (0, 10000),
        "Ex2PSABSI_02_ExitEconomyMode": (0, 10000),
        "Ex2PSABSI_03_GetMode": (1, 10000),
        "Ex2PSABSI_03_SetMode": (1, 10000),
        "Ex2PSABSI_04_ForcingOfGaugingRequest": (0, 10000),
        "Ex2PSABSI_05_BSIStatusCheck": (1, 10000),
        "Ex2PSABSI_05_ExitCommunication": (0, 10000),
        "Ex2PSABSI_05_KeyRegister": (1, 10000),
        "Ex2PSABSI_05_UnlockRequest": (1, 10000),
        "Ex2PSABSI_06_BSIStatusCheck": (1, 10000),
        "Ex2PSABSI_06_ProgramADCCode": (1, 10000),
        "Ex2PSABSI_07_BSIStatusCheck": (1, 10000),
        "Ex2PSABSI_07_UnlockRequest": (1, 10000),
        "Ex2PSABSI_08_GetVIN": (1, 10000),
        "Ex2PSABSI_08_WriteVIN": (1, 10000),
        "Ex2RWG_01_DTCRead": (1, 10000),
        "Ex2RWG_01_LearnZeroPos": (1, 10000),
        "Ex2RWG_01_SupportCheck": (1, 10000),
        "Ex2EVP_01_InitializeAllMemory": (0, 10000),
        "Ex2OCC_05_ExitCommunication": (0, 10000),
        "Ex2OCC_05_Get30KgLoadRange": (1, 10000),
        "Ex2OCC_05_GetNoLoadRange": (1, 10000),
        "Ex2OCC_05_GetReclineLoadRange": (1, 10000),
        "Ex2OCC_05_GetSensorInfo": (1, 10000),
        "Ex2OCC_05_GetTotalWeightInfo": (1, 10000),
        "Ex2OCC_05_ZeroPointCalibration": (1, 10000),
        "Ex2OCC_06_SupportCheck": (1, 10000),
        "Ex2OCC_06_ZeroPointCalibration": (1, 10000),
        "Ex2OCC_07_SendMessage": (1, 10000),
        "Ex2ACC_01_LostCommunicationHistoryClear": (1, 10000),
        "Ex2ACC_01_LostCommunicationHistoryRead": (1, 10000),
        "Ex2ACC_01_SupportCheck": (1, 10000),
        "Ex2MG_02_SendMessage": (1, 10000),
        "Ex2MG_03_SendMessage": (1, 10000),
        "Ex2MG_04_SendMessage": (1, 10000),
        "Ex2ADX_01_SendMessage": (1, 10000),
        "Ex2AHS_01_CameraOpticAxisAdjustmentRequest": (1, 10000),
        "Ex2AHS_01_CameraOpticAxisConfirmation": (1, 10000),
        "Ex2AHS_01_SupportCheck": (1, 10000),
        "Ex2AHS_02_CalibSwivelMarginAngle": (1, 10000),
        "Ex2AHS_02_SupportCheck": (1, 10000),
        "Ex2AHS_03_HeightSensorInitializationAndDTCCheck": (1, 10000),
        "Ex2AHS_03_SupportCheckAndDTCCheck": (1, 10000),
        "Ex2AHS_04_SupportCheckAndDTCCheck": (1, 10000),
        "Ex2AHS_04_SynchronizeInformationAndDTCCheck": (1, 10000),
        "Ex2PSEAT_01_SendMessage": (1, 10000),
        "Ex2PSEAT_03_SendMessage": (1, 10000),
        "Ex2PSEAT_04_SendMessage": (1, 10000),
        "Ex2IVM_01_SendMessage": (1, 10000),
        "Ex2STB_03_ExecutingSensorCalibration": (1, 10000),
        "Ex2STB_03_PreSensorCalibration": (1, 10000),
        "Ex2STB_03_StartSensorCalibration": (1, 10000),
        "Ex2STB_03_SupportCheck": (1, 10000),
        "Ex2STB_04_DriveActiveStabi": (1, 10000),
        "Ex2STB_04_ExitActiveStabi": (1, 10000),
        "Ex2STB_04_PreparateActiveStabi": (1, 10000),
        "Ex2STB_04_RestartActiveStabi": (1, 10000),
        "Ex2STB_04_SupportCheck": (1, 10000),
        "Ex2RCAM_01_SendMessage": (1, 10000),
        "Ex2RCAM_02_SendMessage": (1, 10000),
        "Ex2RCAM_03_SendMessage": (1, 10000),
        "Ex2PSASRS_01_GetStatus": (1, 10000),
        "Ex2PSASRS_01_SetStatus": (1, 10000),
        "Ex2HNPCS_02_SendMessage": (1, 10000),
        "Ex2HNPCS_02_SupportCheck": (1, 10000),
        "Ex2HNPCS_03_InitializeTheLearningValue": (1, 10000),
        "Ex2HNPCS_03_SupportCheck": (1, 10000),
        "Ex2HNPCS_04_ClearPCSOperationCount": (1, 10000),
        "Ex2HNPCS_04_ReadPCSOperationCount": (1, 10000),
        "Ex2HNPCS_04_SupportCheck": (1, 10000),
        "Ex2DMC_01_SendMessage": (1, 10000),
        "Ex2DMC_02_ReadImageInformationOperation": (1, 10000),
        "Ex2DMC_02_WriteImageInformationOperation": (1, 10000),
        "Ex2HNAHB_01_GetSupport": (1, 10000),
        "Ex2HNAHB_01_HistoryClear": (1, 10000),
        "Ex2SIS_01_SendMessage": (1, 10000),
        "Ex2SIS_02_SendMessage": (1, 10000),
        "Ex2PSAALM_01_SendMessage": (0, 10000),
        "Ex2GWY_02_CheckTheDtc": (1, 10000),
        "Ex2GWY_02_EndInit": (1, 10000),
        "Ex2GWY_02_ErrorInit": (1, 10000),
        "Ex2GWY_02_StartInit": (1, 10000),
        "Ex2GWY_02_StartSession": (1, 10000),
        "Ex2GWY_03_EndInit": (1, 10000),
        "Ex2GWY_03_StartInit": (1, 10000),
        "Ex2GWY_03_StartInitResult": (1, 10000),
        "Ex2STRACT_01_ModeTransition": (1, 10000),
        "Ex2STRACT_01_SupportCheck": (1, 10000),
        "Ex2STRACT_03_ClearZeroPointAdjustment": (1, 10000),
        "Ex2STRACT_03_EndExtendedSessionFinal": (1, 10000),
        "Ex2STRACT_03_StartExtendedSession": (1, 10000),
        "Ex2STRACT_03_StartTestMode": (1, 10000),
        "Ex2STRACT_03_StartZeroPointAdjustment": (1, 10000),
        "Ex2STRACT_04_SendMessage": (1, 10000),
        "Ex2LAMP_01_HeightSensorInitializationRequest": (1, 10000),
        "Ex2LAMP_01_SupportCheck": (1, 10000),
        "Ex2LAMP_04_SendMessage": (1, 10000),
        "Ex2ABG_02_CheckLoadSpecInfo": (1, 10000),
        "Ex2ABG_02_StartLoadSpecInfo": (1, 10000),
        "Ex2EOM_01_ModeTransition": (0, 10000),
        "Ex2ASG_02_InitialLearning": (1, 10000),
        "Ex2ASG_02_GetLearnedStatus": (1, 10000),
        "Ex2ASG_02_GetLearnedStatusAfterTimeOut": (1, 10000),
        "Ex2ASG_02_GetLearnedStatusAt004": (1, 10000),
        "Ex2FC_04_CheckCanAirBleed": (1, 10000),
        "Ex2FC_04_ConfirmAirBleed": (1, 10000),
        "Ex2FC_04_ExecuteAirBleedHeater": (1, 10000),
        "Ex2FC_04_StartAirBleed": (1, 10000),
        "Ex2FC_04_StartKeepAlive": (1, 10000),
        "Ex2FC_04_SupportCheck": (1, 10000),
        "Ex2FC_05_MonitorAndActivateValve": (1, 10000),
        "Ex2FC_05_SupportCheck": (1, 10000),
        "Ex2HAL_02_HeightSensorInitializationAndDTCCheck": (1, 10000),
        "Ex2HAL_02_SupportCheckAndDTCCheck": (1, 10000),
        "Ex2HAL_03_SupportCheckAndDTCCheck": (1, 10000),
        "Ex2HAL_03_SynchronizeInformationAndDTCCheck": (1, 10000),
        "Ex2MGR_01_SendMessage": (1, 10000),
        "Ex2MGR_02_SendMessage": (1, 10000),
        "Ex2MGR_03_SendMessage": (1, 10000),
        "Ex2IC_01_SendMessage": (1, 10000),
        "Ex2RES_03_InitialRegistrationRequest": (1, 10000),
        "Ex2RES_03_SupportCheck": (1, 10000),
        "Ex2RES_04_GetEcuInfo_SIL": (1, 10000),
        "Ex2RES_04_GetSupportFunction_SIL": (1, 10000),
        "Ex2RES_04_KeepAlive_SIL": (1, 10000),
        "Ex2RES_04_RemoteStartRegistration": (1, 10000),
        "Ex2RES_04_SendKey_SIL": (1, 10000),
        "Ex2RES_04_SupportCheck": (1, 10000),
        "Ex2RES_04_SupportCheck_SIL": (1, 10000),
        "Ex2GS_01_CheckShutterStatus": (1, 10000),
        "Ex2GS_01_ShiftMode": (1, 10000),
        "Ex2GS_01_SupportCheck": (1, 10000),
        "Ex2GS_02_SendMessage": (1, 10000),
        "Ex2LDR_09_SendMessage": (1, 10000),
        "Ex2LDR_10_SendMessage": (1, 10000),
        "Ex2LDR_11_SendMessage": (1, 10000),
        "Ex2LDR_12_SendMessage": (1, 10000),
        "Ex2PCM_04_SendMessage": (1, 10000),
        "Ex2FSR_01_02_ActiveTest": (1, 10000),
        "Ex2FSR_01_02_SupportCheck": (1, 10000),
        "Ex2FSR_03_04_ActiveTest": (1, 10000),
        "Ex2FSR_03_04_SupportCheck": (1, 10000),
        "Ex2FSR_05_06_ClearAbnormalHistory": (1, 10000),
        "Ex2FSR_05_06_GetAbnormalHistory": (1, 10000),
        "Ex2FSR_05_06_SupportCheck": (1, 10000),
        "Ex2HNCSN_01_TransitionToNormalMode": (1, 10000),
        "Ex2BCM_01_SendMessage": (1, 10000),
        "Ex2BCM_02_SendMessage": (1, 10000),
        "Ex2AVS_01_SendMessage": (1, 10000),
        "Ex2AVS_02_SendMessage": (1, 10000),
        "Ex2SBW_01_ActPositionLearningResult": (1, 10000),
        "Ex2SBW_01_StartActPositionLearning": (1, 10000),
        "Ex2HNFCM_02_LearnTarget1": (1, 10000),
        "Ex2HNFCM_02_LearnTarget2": (1, 10000),
        "Ex2HNFCM_02_LearnTarget3": (1, 10000),
        "Ex2HNFCM_02_LearnTargetAll": (1, 10000),
        "Ex2HNFCM_02_ReadCameraData": (1, 10000),
        "Ex2HNFCM_02_SupportCheck": (1, 10000),
        "Ex2ADS_04_SendMessage": (1, 10000),
        "Ex2ADS_05_SendMessage": (1, 10000),
        "Ex2ADS_06_SendMessage": (1, 10000),
        "Ex2ADS_07_SendMessage": (1, 10000),
        "Ex2ADS_08_SendMessage": (1, 10000),
        "Ex2ADS_09_SendMessage": (1, 10000),
        "Ex2ADS_10_SendMessage": (1, 10000),
        "Ex2DSEAT_01_SendMessage": (1, 10000),
        "Ex2DSEAT_02_SendMessage": (1, 10000),
        "Ex2DSEAT_03_SendMessage": (1, 10000),
        "Ex2DSEAT_04_SendMessage": (1, 10000),
        "Ex2ITS_01_SendMessage": (0, 10000),
        "Ex2ITS_02_SendMessage": (0, 10000),
        "Ex2DR_01_GetDataList": (1, 10000),
        "Ex2ASECT_01_SendMessage": (1, 10000),
        "Ex2AMT_01_GetHistoryData": (1, 10000),
        "Ex2ASG_02_SupportCheck": (1, 10000),
        "Ex2AMT_01_SupportCheck": (1, 10000),
        "Ex2EFI_28_LearningValueReset": (0, 10000),
        "Ex2AMT_01_WriteHistoryDataToECU": (1, 10000),
        "Ex24WD_06_SendMessage": (1, 10000),
        "Ex24WD_08_SendMessage": (1, 10000),
        "Ex2AC_28_SendMessage": (1, 10000),
        "Ex2DP2_11_BSMFSRRadarFrontBeamAxisAdjustment": (1, 10000),
        "Ex2DP2_11_FrontBeamAxisAdjustment": (1, 10000),
        "Ex2DP2_11_SupportCheck": (1, 10000),
        "Ex2DP2_11_SupportCheck_DID": (1, 10000),
        "Ex2DP2_12_ActiveTest": (1, 10000),
        "Ex2DP2_12_BSMFSRRadarDealershipAxisOffsetAngleOut": (1, 10000),
        "Ex2DP2_12_GetSupportBitInformation": (1, 10000),
        "Ex2DP2_12_SupportCheck_DID": (1, 10000),
        "Ex2DP2_13_ActiveTest": (1, 10000),
        "Ex2DP2_13_GetSupportBitInformation": (1, 10000),
        "Ex2DP2_14_SendMessage": (1, 10000),
        "Ex2FRD_01_LearnTarget": (1, 10000),
        "Ex2FRD_02_SendMessage": (1, 10000),
        "Ex2FRD_03_SendMessage": (1, 10000),
        "Ex2FRD_04_SendMessage": (0, 10000),
        "Ex2FRD_05_SendMessage": (1, 10000),
        "Ex2VCIB_03_SendMessage": (1, 10000),
        "Ex2VCIB_05_SendMessage": (1, 10000),
        "Ex2EVB_02_READYONProhibitionCancel": (0, 10000),
        "Ex2FAS_01_SendMessage": (1, 10000),
        "Ex2VC_01_GetActuationCnt": (1, 10000),
        "Ex2VC_01_SupportCheck": (1, 10000),
        "Ex2VC_01_WriteActuationCnt": (1, 10000),
        "Ex2VC_02_Learn0Point": (1, 10000),
        "Ex2VC_02_SupportCheck": (1, 10000),
        "Ex2VC_03_SendMessage": (1, 10000),
        "Ex2VC_04_SendMessage": (1, 10000),
        "Ex2PI_01_GetAbsoTime": (1, 10000),
        "Ex2PI_01_GetCurrentTimeStamp": (1, 10000),
        "Ex2PI_01_GetFuseHistory": (1, 10000),
        "Ex2PI_01_SupportCheck": (1, 10000),
        "Ex2PI_02_SendMessage": (0, 10000),
        "Ex2DSC_01_SendMessage": (1, 10000),
        "Ex2DSC_02_SendMessage": (1, 10000),
        "Ex2HVB_10_SendMessage": (1, 10000),
        "Ex2HVB_11_SendMessage": (1, 10000),
        "Ex2VIF_02_SendMessage": (1, 10000),
        "Ex2HNSCR_01_SendMessage": (0, 10000),
        "Ex2HNCSN_01_EcuCal": (1, 10000),
        "Ex2HNCSN_01_InitStatusOfSensor": (1, 10000),
        "Ex2HNCSN_01_SupportCheck": (1, 10000),
        "Ex2HNCSN_01_WriteAngleOfSensor": (1, 10000),
        "Ex2HNCSN_01_WriteNeutralPosition": (1, 10000),
        "Ex2HNSCR_02_SendMessage": (1, 10000),
        "Ex24WD_05_SupportCheck": (1, 10000),
        "Ex2AHC_04_SendMessage": (1, 10000),
        "Ex2MS2ABS_04_SendMessage": (1, 10000),
        "Ex2MS2AT_01_SendMessage": (1, 10000),
        "Ex2MS2RAB_02_SendMessage": (1, 10000),
        "Ex2VC_05_SendMessage": (1, 10000),
        "Ex2VIF_01_SendMessage": (1, 10000),
        "Ex2BSM_09_10_19_20_SendMessage": (1, 10000),
        "Ex2BSM_11_12_21_22_SendMessage": (1, 10000),
        "Ex2MS2EFI_03_SendMessage": (1, 10000),
        "Ex2MS2EFI_05_SendMessage": (1, 10000),
        "Ex2MS2EFI_06_SendMessage": (1, 10000),
        "Ex2VCIB_02_SendMessage": (1, 10000),
        "Ex2HV_15_HiVltFsAccLdHstRst": (0, 10000),
        "Ex2HV_17_BatteryStatusInfoReset": (0, 10000),
        "Ex2BDY_21_EndKeyRegistration": (1, 10000),
        "Ex2BDY_21_KeyNumGet": (1, 10000),
        "Ex2BDY_21_KeyRegistration": (1, 10000),
        "Ex2BDY_21_StartKeyRegistration": (1, 10000),
        "Ex2BDY_21_StopKeyRegistration": (1, 10000),
        "Ex2BDY_21_TimeoverKeyRegistration": (1, 10000),
        "Ex2BDY_22_EndKeyCodeErasure": (1, 10000),
        "Ex2BDY_22_KeyCodeErasure": (1, 10000),
        "Ex2BDY_22_KeyNumGet": (1, 10000),
        "Ex2BDY_22_StartKeyCodeErasure": (1, 10000),
        "Ex2BDY_22_StopKeyCodeErasure": (1, 10000),
        "Ex2BDY_22_TimeoverKeyCodeErasure": (1, 10000),
        "Ex2MS2AT_02_SendMessage": (1, 10000),
        "Ex2MS2DCM_01_SendMessage": (1, 10000),
        "Ex2MS2EMPS_01_SendMessage": (1, 10000),
        "Ex2MS2EMPS_02_SendMessage": (1, 10000),
        "Ex2MS2IG_01_SendMessage": (1, 10000),
        "Ex2MS2MET_02_SendMessage": (1, 10000),
        "Ex2MS2SAS_01_SendMessage": (1, 10000),
        "Ex2MS2SAS_03_SendMessage": (1, 10000),
        "Ex2HV_20_SendMessage": (1, 10000),
        "Ex2HV_18_SendMessage": (1, 10000),
        "Ex24WD_05_SendMessage": (1, 10000),
        "Ex24WD_05_WriteHistoryData": (1, 10000),
        "Ex2TPW_03_SendMessage": (1, 10000),
        "Ex2AWD_04_ReadValues": (1, 10000),
        "Ex2MS2EYES_01_SendMessage": (1, 10000),
        "Ex2MS2EYES_02_SendMessage": (1, 10000),
        "Ex2MS2EYES_03_SendMessage": (1, 10000),
        "Ex2MS2EYES_04_SendMessage": (1, 10000),
        "Ex2MS2EYES_05_SendMessage": (1, 10000),
        "Ex2MS2EYES_06_SendMessage": (1, 10000),
        "Ex2MS2EYES_07_SendMessage": (1, 10000),
        "Ex2HV_21_SendMessage": (1, 10000),
        "Ex2HV_22_SendMessage": (1, 10000),
        "Ex2HV_19_SendMessage": (1, 10000),
        "Ex2HV_13_READYONProhibitionCancel": (0, 10000),
        "Ex2HV_11_SendMessage": (0, 10000),
        "Ex2BDY_23_EndExtendedSession": (1, 10000),
        "Ex2BDY_23_SearchOfKey": (1, 10000),
        "Ex2BDY_23_SearchResult": (1, 10000),
        "Ex2BDY_23_SendKeyInfomation": (1, 10000),
        "Ex2BDY_23_TerminateSearch": (1, 10000),
        "Ex2BDY_51_SupportCheck": (1, 10000),
        "Ex2BDY_52_CheckEraseKeys": (1, 10000),
        "Ex2BDY_52_GetRegedNumOfKeys": (1, 10000),
        "Ex2BDY_52_StartEraseKeys": (1, 10000),
        "Ex2BDY_52_SupportCheck": (1, 10000),
        "Ex2HV_12_SupportCheck": (1, 10000),
        "Ex2HV_12_GetDTCAndEEPROMStatus": (1, 10000),
        "Ex2HV_12_UpdateBatteryStatusInfo": (1, 10000),
        "Ex2HV_12_JudgementAfterUpdateInfo": (1, 10000),
        "Ex2HV_10_SupportCheck": (1, 10000),
        "Ex2HV_10_ReadBatteryStatus": (1, 10000),
        "Ex2HV_10_WaitingEEPROMWrite": (1, 10000),
        "Ex2HV_10_JudgementOfStckToReplace": (1, 10000),
        "Ex2BDY_53_CheckRegECUID": (1, 10000),
        "Ex2BDY_53_StartRegECUID": (1, 10000),
        "Ex2BDY_53_SupportCheck": (1, 10000),
        "Ex2EFI_44_SessionTransition": (1, 10000),
        "Ex2EFI_54_ElectricThrottleLearning": (1, 10000),
        "Ex2DCM_45_SendMessage": (1, 10000),
        "Ex2EFI_62_SendMessage": (1, 10000),
        "Ex2DCM_36_SendMessage": (1, 10000),
        "Ex2DCM_43_SendMessage": (1, 10000),
        "Ex2APP_07_SendMessage": (1, 10000),
        "Ex2APP_08_SendMessage": (1, 10000),
        "Ex2ECT_15_SendMessage": (1, 10000),
        "Ex2EFI_59_SendMessage": (1, 10000),
        "Ex2ECT_16_SendMessage": (1, 10000),
        "Ex2EFI_61_SupportCheck": (1, 10000),
        "Ex2EFI_61_WriteTotalShortTripEstimate": (1, 10000),
        "Ex2AC_30_SendMessage": (1, 10000),
        "Ex2PLG_03_SendMessage": (1, 10000),
        "Ex2DCM_22_CancelComPausing": (1, 10000),
        "Ex2DCM_22_SupportCheck": (1, 10000),
        "Ex2EFI_53_SendMessage": (1, 10000),
        "Ex2DCM_15_SendMessage": (1, 10000),
        "Ex2EFI_52_SendMessage": (1, 10000),
        "Ex2DCM_12_ResetBUBMemory": (1, 10000),
        "Ex2DCM_12_SupportCheck": (1, 10000),
        "Ex2DCM_20_ChangeSettings": (1, 10000),
        "Ex2DCM_20_GetTheActivationStatus": (1, 10000),
        "Ex2DCM_20_SupportCheck": (1, 10000),
        "Ex2EFI_55_SendMessage": (1, 10000),
        "Ex2DCM_07_08_09_10_16_ReadRemoteSettingData": (1, 10000),
        "Ex2DCM_07_08_09_10_16_SetRemoteSettingData": (1, 10000),
        "Ex2DCM_07_08_09_10_16_SupportCheck": (1, 10000),
        "Ex2DCM_19_ReadoutFOTAStatus": (1, 10000),
        "Ex2DCM_19_StartFOTA": (1, 10000),
        "Ex2DCM_19_SupportCheck": (1, 10000),
        "Ex2ECT_01_SendMessage": (1, 10000),
        "Ex2ECT_02_SendMessage": (1, 10000),
        "Ex2ECT_03_SendMessage": (1, 10000),
        "Ex2ECT_09_SendMessage": (1, 10000),
        "Ex2ECT_10_SendMessage": (1, 10000),
        "Ex2ECT_12_SendMessage": (1, 10000),
        "Ex2ECT_14_SendMessage": (1, 10000),
        "Ex2ECT_04_SendMessage": (1, 10000),
        "Ex2ECT_05_SendMessage": (1, 10000),
        "Ex2ECT_08_SendMessage": (1, 10000),
        "Ex2ECT_11_SendMessage": (1, 10000),
        "Ex2MM_08_ImageLineCheckRequestAndOperate": (1, 10000),
        "Ex2MM_08_SupportCheck": (1, 10000),
        "Ex2MM_09_GetPIDSupportInfo": (1, 10000),
        "Ex2MM_10_SupportCheck": (1, 10000),
        "Ex2MM_11_13_GetInformation": (1, 10000),
        "Ex2MM_11_13_SupportCheck": (1, 10000),
        "Ex2MM_20_SupportCheck": (1, 10000),
        "Ex2MM_20_ValetModeCancel": (1, 10000),
        "Ex2MM_21_TransferToDiagnosticMode": (0, 10000),
        "Ex2MM_31_SendMessage": (1, 10000),
        "Ex2MM_39_SendMessage": (1, 10000),
        "Ex2ECT_13_SendMessage": (1, 10000),
        "Ex2MM_09_GetSoftErrHistory": (1, 10000),
        "Ex2MM_10_GetDiscErrInfo": (1, 10000),
        "Ex2MM_17_GetSupportInfoAndDataList": (1, 10000),
        "Ex2MM_30_SendMessage": (1, 10000),
        "Ex2MM_40_SendMessage": (1, 10000),
        "Ex2BDY_51_ChkNumberOfKeyRegistered": (1, 10000),
        "Ex2BDY_51_ChkNumberOfTotalKeyRegistered": (1, 10000),
        "Ex2BDY_51_ExitCommunication": (1, 10000),
        "Ex2BDY_51_NewKeyRegistration": (1, 10000),
        "Ex2BDY_51_NewKeyRegistration_Before_Remove_Key": (1, 10000),
        "Ex2BDY_51_OtherKeyRegistration": (1, 10000),
        "Ex2BDY_51_OtherKeyRegistration_Before_Remove_Key": (1, 10000),
        "Ex2BDY_51_OwnerConfirmation": (1, 10000),
        "Ex2BDY_51_OwnerConfirmation_Before_Remove_Key": (1, 10000),
        "Ex2BDY_51_RequestKeyRegistEnd": (1, 10000),
        "Ex2BDY_51_RequestKeyRegistration": (1, 10000),
        "Ex2BDY_51_StatusCheckInterval": (1, 10000),
        "Ex2BDY_51_StatusChkAfterKeyRegist": (1, 10000),
        "Ex2BDY_51_StatusChkAfterOwnerConfirmation": (1, 10000),
        "Ex2BDY_51_StatusChkRegisteredKey": (1, 10000),
        "Ex2DCM_19_ReadoutSoftwareVersion": (1, 10000),
        "Ex2DCM_21_GetTheDCMID": (1, 10000),
        "Ex2DCM_32_SendMessage": (0, 10000),
        "Ex2DCM_37_SendMessage": (0, 10000),
        "Ex2DCM_38_SendMessage": (1, 10000),
        "Ex2DCM_39_SendMessage": (0, 10000),
        "Ex2DCM_41_SendMessage": (0, 10000),
        "Ex2DCM_44_SendMessage": (0, 10000),
        "Ex2AC_08_RefrigerantFillingModeRequest": (1, 10000),
        "Ex2AC_09_RefrigerantHighPressureHistoryClear": (1, 10000),
        "Ex2AC_21_ServomotorForcibleDrive": (0, 10000),
        "Ex2AC_25_BattVoltLowCntClear": (0, 10000),
        "Ex2AC_26_SendMessage": (1, 10000),
        "Ex2AC_27_SendMessage": (1, 10000),
        "Ex2CSN_05_ChangeTireCircumference": (1, 10000),
        "Ex2CSN_05_GetTireCircumference": (1, 10000),
        "Ex2CSN_10_SendMessage": (1, 10000),
        "Ex2SMRT_33_ECU_ID_Registration": (1, 10000),
        "Ex2SMRT_33_GetKeyStatus": (1, 10000),
        "Ex2SMRT_35_CommunicationCheck": (1, 10000),
        "Ex2SMRT_35_GetSupportBitInformation": (1, 10000),
        "Ex2SMRT_35_ReGetSupportBitInformation": (1, 10000),
        "Ex2SMRT_35_TerminateCommunicationCheck": (1, 10000),
        "Ex2PLG_01_QuickChargeRelayDiagnosis": (1, 10000),
        "Ex2PLG_01_ReadChargeLidSW_QuickChargeRelayDiag": (1, 10000),
        "Ex2PLG_01_ReadChargeRelayDiagnosisStatus": (1, 10000),
        "Ex2PLG_01_FinalCom": (1, 10000),
        "Ex2HV_14_ReadBatteryBlockVoltage": (1, 10000),
        "Ex2HV_14_ReadBatteryTemperature": (1, 10000),
        "Ex2HV_14_SupportCheck": (1, 10000),
    },
    "TYPlus": {
        "Ex2ABS_52_ReadBrakePadResidualThickness": (1, 10000),
        "Ex2ABS_52_WriteBrakePadResidualThickness": (1, 10000),
        "Ex2ABS_41_DriveMotor": (1, 10000),
        "Ex2ABS_41_StopMotor": (1, 10000),
        "Ex2ABS_44_SendMessage": (0, 10000),
        "Ex2AHC_03_EndExtendedSession": (1, 10000),
        "Ex2AHC_03_ReadModeStatus": (1, 10000),
        "Ex2AHC_03_SwitchServiceMode": (1, 10000),
        "Ex2ASUS_08_EndExtendedSession": (1, 10000),
        "Ex2AWD_04_Overwrite": (1, 10000),
        "Ex2DOOR_01_StartConnectionHistoryClear": (0, 10000),
        "Ex2ECD_59_Dummy": (1, 10000),
        "Ex2ECD_60_Dummy": (1, 10000),
        "Ex2ECO_10_TotalNumOfEngineStartsReset": (0, 10000),
        "Ex2FCHV_02_AutoPowerOFFCancel": (1, 10000),
        "Ex2FCHV_02_EndExtendedSession": (1, 10000),
        "Ex2FCHV_02_ReadData": (1, 10000),
        "Ex2FCHV_02_ReadPressure": (1, 10000),
        "Ex2FCHV_02_ReadTankShutValveClose": (1, 10000),
        "Ex2FCHV_02_ReadTankShutValveOpen": (1, 10000),
        "Ex2FCHV_02_ReadTankShutValveRetrun": (1, 10000),
        "Ex2FCHV_02_ReadTankShutValveStart": (1, 10000),
        "Ex2FCHV_02_ReadTemperature": (1, 10000),
        "Ex2FCHV_02_SupportCheck": (1, 10000),
        "Ex2FCHV_02_TankShutValveDrive": (1, 10000),
        "Ex2FCHV_02_TankShutValveStop": (1, 10000),
        "Ex2FCHV_05_SendMessage": (1, 10000),
        "Ex2FCHV_06_SendMessage": (1, 10000),
        "Ex2FCHV_07_Overwrite": (1, 10000),
        "Ex2FCHV_07_ReadValues": (1, 10000),
        "Ex2FCHV_07_SupportCheck": (1, 10000),
        "Ex2FCHV_08_ReadValues": (1, 10000),
        "Ex2FCHV_08_SupportCheck": (1, 10000),
        "Ex2FCHV_08_WriteValues": (1, 10000),
        "Ex2FCHV_09_SendMessage": (1, 10000),
        "Ex2FCHV_10_SendMessage": (1, 10000),
        "Ex2FCHV_13_SendMessage": (1, 10000),
        "Ex2FCHV_14_SendMessage": (1, 10000),
        "Ex2FCHV_16_SendMessage": (1, 10000),
        "Ex2FCHV_26_EndExtendedSession": (1, 10000),
        "Ex2FCHV_26_ReadData": (1, 10000),
        "Ex2FCHV_26_ReadPressure": (1, 10000),
        "Ex2FCHV_26_ReadTankShutValveClose": (1, 10000),
        "Ex2FCHV_26_ReadTankShutValveOpen": (1, 10000),
        "Ex2FCHV_26_ReadTankShutValveRetrun": (1, 10000),
        "Ex2FCHV_26_ReadTankShutValveStart": (1, 10000),
        "Ex2FCHV_26_ReadTemperature": (1, 10000),
        "Ex2FCHV_26_SupportCheck": (1, 10000),
        "Ex2FCHV_26_TankShutValveDrive": (1, 10000),
        "Ex2FCHV_26_TankShutValveStop": (1, 10000),
        "Ex2GWY_02_TimeoutInit": (1, 10000),
        "Ex2GWY_03_EndInitErr": (1, 10000),
        "Ex2HF_01_Com_TanksNumberValueClear": (0, 10000),
        "Ex2IG_01_DisableAutoPowerOffFunc": (0, 10000),
        "Ex2IG_02_SendMessage": (0, 10000),
        "Ex2ROOF_01_ImpactDetectionInfoClear": (0, 10000),
        "Ex2SBW_01_EndExtendedSession": (1, 10000),
        "Ex2STRACT_03_EndExtendedSession": (1, 10000),
        "Ex2MIR_01_SendMessage": (1, 10000),
        "Ex2SAS_02_SendMessage": (0, 10000),
        "Ex2MS2MM_01_SendMessage": (0, 10000),
        "Ex2MSW_01_SendMessage": (0, 10000),
        "Ex2DMOT_01_SendMessage": (0, 10000),
        "Ex2EV_02_SendMessage": (0, 10000),
        "Ex2MS2BSRL_01_SendMessage": (1, 10000),
        "Ex2FCHV_01_SendMessage": (1, 10000),
        "Ex2FCHV_03_SendMessage": (1, 10000),
        "Ex2FCHV_04_SendMessage": (1, 10000),
        "Ex2FCHV_11_SendMessage": (1, 10000),
        "Ex2FCHV_12_SendMessage": (1, 10000),
        "Ex2FCHV_17_SendMessage": (1, 10000),
        "Ex2FCHV_24_SendMessage": (1, 10000),
        "Ex2FCHV_25_SendMessage": (1, 10000),
        "Ex2FCHV_27_SendMessage": (1, 10000),
        "Ex2FCHV_28_SendMessage": (1, 10000),
        "Ex2MS2ABS_01_SendMessage": (1, 10000),
        "Ex2MS2ABS_02_SendMessage": (1, 10000),
        "Ex2MS2ABS_03_SendMessage": (1, 10000),
        "Ex2MS2ABS_05_SendMessage": (0, 10000),
        "Ex2MS2EFI_01_SendMessage": (1, 10000),
        "Ex2MS2EFI_02_SendMessage": (0, 10000),
        "Ex2MS2GWY_01_SendMessage": (1, 10000),
        "Ex2MS2PWD_01_SendMessage": (1, 10000),
        "Ex2MS2PWD_02_SendMessage": (1, 10000),
        "Ex2MS2EFI_04_SendMessage": (1, 10000),
        "Ex2EFI_57_ReadDisplayFrequencyMode": (1, 10000),
        "Ex2EFI_57_WriteDisplayFrequencyMode": (1, 10000),
        "Ex2ECD_57_DPFAshValueClear": (0, 10000),
        "Ex2ECD_55_SendMessage": (0, 10000),
        "Ex2ABS_17_SupportCheck": (1, 10000),
        "Ex2ABS_17_GetABSInfo": (1, 10000),
        "Ex2ABS_17_SychronizingABSInfo": (1, 10000),
        "Ex2ABS_18_SupportCheck": (1, 10000),
        "Ex2ABS_18_SetNeutralPos": (1, 10000),
        "Ex2ABS_21_SupportCheck": (1, 10000),
        "Ex2ABS_21_ChangeMode": (1, 10000),
        "Ex2ABS_21_CheckSensorStatus": (1, 10000),
        "Ex2ABS_48_RetrunWait": (0, 10000),
        "Ex2ASUS_13_TestStart": (1, 10000),
        "Ex2ASUS_13_GetHeight": (1, 10000),
        "Ex2ASUS_13_NormalMode": (1, 10000),
        "Ex2ASUS_13_NormalMode005": (1, 10000),
        "Ex2ASUS_13_NormalMode008": (1, 10000),
        "Ex2ASUS_13_HeightOffset": (1, 10000),
        "Ex2ASUS_13_TestStop": (1, 10000),
        "Ex2ASUS_13_GetHeightSec50": (1, 10000),
        "Ex2VGRS_04_StartLockRelease": (1, 10000),
        "Ex2VGRS_04_EndLockRelease": (1, 10000),
        "Ex2VGRS_04_StartNeutralCompMode": (1, 10000),
        "Ex2VGRS_04_EndNeutralCompMode": (1, 10000),
        "Ex2VGRS_04_ClearDTC": (1, 10000),
        "Ex2EMPS_07_ConfirmTheAssistMap": (1, 10000),
        "Ex2EMPS_07_ClearTheAssistMap": (1, 10000),
        "Ex2EPB_04_SendMessage": (0, 10000),
        "Ex2AC_26_SendMessage": (1, 10000),
        "Ex2AC_27_SendMessage": (1, 10000),
        "Ex2MM_41_TransferToPairingMode": (0, 10000),
        "Ex2SMRT_62_DigiKeySupArea": (1, 10000),
        "Ex2SMRT_62_StartDiagMode": (1, 10000),
        "Ex2SMRT_62_TerminateDiagMode": (1, 10000),
        "Ex2APP_03_StartIRProjectorInspection1st": (1, 10000),
        "Ex2APP_03_StartIRProjectorInspection2nd": (1, 10000),
        "Ex2APP_03_StartIRProjectorInspection3rd": (1, 10000),
        "Ex2APP_03_StartIRProjectorInspection4th": (1, 10000),
        "Ex2MS2BDY_01_SendMessage": (1, 10000),
        "Ex2MS2RAB_01_SendMessage": (1, 10000),
        "Ex2MS2SAS_02_SendMessage": (1, 10000),
        "Ex2ASG_02_CheckLearnedFlg": (1, 10000),
        "Ex2EFI_58_SupportCheck": (1, 10000),
        "Ex2EFI_58_ReadPMDeposition": (1, 10000),
        "Ex2EFI_58_ResultPMRegenerateMode": (1, 10000),
        "Ex2EFI_58_StopPMRegenerateMode": (0, 10000),
        "Ex2EFI_58_StartPMRegenerateMode": (1, 10000),
        "Ex2EFI_58_ReadGPFDealerVehicleStopRegenerateStop": (1, 10000),
        "Ex2MS2SMRT_05_SendMessage": (1, 10000),
        "Ex2MS2SMRT_07_SendMessage": (1, 10000),
        "Ex2MS2SMRT_08_SendMessage": (1, 10000),
        "Ex2MS2SMRT_09_SendMessage": (1, 10000),
        "Ex2MS2DCM_02_SendMessage": (1, 10000),
        "Ex2MS2MET_01_SendMessage": (1, 10000),
        "Ex2MS2TPW_01_SendMessage": (1, 10000),
        "Ex2RWG_01_DTCRead": (1, 10000),
        "Ex2RWG_01_LearnZeroPos": (1, 10000),
        "Ex2RWG_01_SupportCheck": (1, 10000),
        "Ex2EVP_01_InitializeAllMemory": (0, 10000),
        "Ex2OCC_05_ExitCommunication": (0, 10000),
        "Ex2OCC_05_Get30KgLoadRange": (1, 10000),
        "Ex2OCC_05_GetNoLoadRange": (1, 10000),
        "Ex2OCC_05_GetReclineLoadRange": (1, 10000),
        "Ex2OCC_05_GetSensorInfo": (1, 10000),
        "Ex2OCC_05_GetTotalWeightInfo": (1, 10000),
        "Ex2OCC_05_ZeroPointCalibration": (1, 10000),
        "Ex2OCC_06_SupportCheck": (1, 10000),
        "Ex2OCC_06_ZeroPointCalibration": (1, 10000),
        "Ex2OCC_07_SendMessage": (1, 10000),
        "Ex2ACC_01_LostCommunicationHistoryClear": (1, 10000),
        "Ex2ACC_01_LostCommunicationHistoryRead": (1, 10000),
        "Ex2ACC_01_SupportCheck": (1, 10000),
        "Ex2MG_02_SendMessage": (1, 10000),
        "Ex2MG_03_SendMessage": (1, 10000),
        "Ex2MG_04_SendMessage": (1, 10000),
        "Ex2ADX_01_SendMessage": (1, 10000),
        "Ex2SZABS_52_SendMessage": (1, 10000),
        "Ex2AHS_01_CameraOpticAxisAdjustmentRequest": (1, 10000),
        "Ex2AHS_01_CameraOpticAxisConfirmation": (1, 10000),
        "Ex2AHS_01_SupportCheck": (1, 10000),
        "Ex2AHS_02_CalibSwivelMarginAngle": (1, 10000),
        "Ex2AHS_02_SupportCheck": (1, 10000),
        "Ex2AHS_03_HeightSensorInitializationAndDTCCheck": (1, 10000),
        "Ex2AHS_03_SupportCheckAndDTCCheck": (1, 10000),
        "Ex2AHS_04_SupportCheckAndDTCCheck": (1, 10000),
        "Ex2AHS_04_SynchronizeInformationAndDTCCheck": (1, 10000),
        "Ex2PSEAT_01_SendMessage": (1, 10000),
        "Ex2PSEAT_03_SendMessage": (1, 10000),
        "Ex2PSEAT_04_SendMessage": (1, 10000),
        "Ex2IVM_01_SendMessage": (1, 10000),
        "Ex2STB_03_ExecutingSensorCalibration": (1, 10000),
        "Ex2STB_03_PreSensorCalibration": (1, 10000),
        "Ex2STB_03_StartSensorCalibration": (1, 10000),
        "Ex2STB_03_SupportCheck": (1, 10000),
        "Ex2STB_04_DriveActiveStabi": (1, 10000),
        "Ex2STB_04_ExitActiveStabi": (1, 10000),
        "Ex2STB_04_PreparateActiveStabi": (1, 10000),
        "Ex2STB_04_RestartActiveStabi": (1, 10000),
        "Ex2STB_04_SupportCheck": (1, 10000),
        "Ex2RCAM_01_SendMessage": (1, 10000),
        "Ex2RCAM_02_SendMessage": (1, 10000),
        "Ex2RCAM_03_SendMessage": (1, 10000),
        "Ex2HNPCS_02_SendMessage": (1, 10000),
        "Ex2HNPCS_02_SupportCheck": (1, 10000),
        "Ex2HNPCS_03_InitializeTheLearningValue": (1, 10000),
        "Ex2HNPCS_03_SupportCheck": (1, 10000),
        "Ex2HNPCS_04_ClearPCSOperationCount": (1, 10000),
        "Ex2HNPCS_04_ReadPCSOperationCount": (1, 10000),
        "Ex2HNPCS_04_SupportCheck": (1, 10000),
        "Ex2DMC_01_SendMessage": (1, 10000),
        "Ex2DMC_02_ReadImageInformationOperation": (1, 10000),
        "Ex2DMC_02_WriteImageInformationOperation": (1, 10000),
        "Ex2HNAHB_01_GetSupport": (1, 10000),
        "Ex2HNAHB_01_HistoryClear": (1, 10000),
        "Ex2SIS_01_SendMessage": (1, 10000),
        "Ex2SIS_02_SendMessage": (1, 10000),
        "Ex2GWY_02_CheckTheDtc": (1, 10000),
        "Ex2GWY_02_EndInit": (1, 10000),
        "Ex2GWY_02_ErrorInit": (1, 10000),
        "Ex2GWY_02_StartInit": (1, 10000),
        "Ex2GWY_02_StartSession": (1, 10000),
        "Ex2GWY_03_EndInit": (1, 10000),
        "Ex2GWY_03_StartInit": (1, 10000),
        "Ex2GWY_03_StartInitResult": (1, 10000),
        "Ex2STRACT_01_ModeTransition": (1, 10000),
        "Ex2STRACT_01_SupportCheck": (1, 10000),
        "Ex2STRACT_03_ClearZeroPointAdjustment": (1, 10000),
        "Ex2STRACT_03_EndExtendedSessionFinal": (1, 10000),
        "Ex2STRACT_03_StartExtendedSession": (1, 10000),
        "Ex2STRACT_03_StartTestMode": (1, 10000),
        "Ex2STRACT_03_StartZeroPointAdjustment": (1, 10000),
        "Ex2STRACT_04_SendMessage": (1, 10000),
        "Ex2LAMP_01_HeightSensorInitializationRequest": (1, 10000),
        "Ex2LAMP_01_SupportCheck": (1, 10000),
        "Ex2LAMP_04_SendMessage": (1, 10000),
        "Ex2ABG_02_CheckLoadSpecInfo": (1, 10000),
        "Ex2ABG_02_StartLoadSpecInfo": (1, 10000),
        "Ex2EOM_01_ModeTransition": (0, 10000),
        "Ex2ASG_02_InitialLearning": (1, 10000),
        "Ex2ASG_02_GetLearnedStatus": (1, 10000),
        "Ex2ASG_02_GetLearnedStatusAfterTimeOut": (1, 10000),
        "Ex2ASG_02_GetLearnedStatusAt004": (1, 10000),
        "Ex2FC_04_CheckCanAirBleed": (1, 10000),
        "Ex2FC_04_ConfirmAirBleed": (1, 10000),
        "Ex2FC_04_ExecuteAirBleedHeater": (1, 10000),
        "Ex2FC_04_StartAirBleed": (1, 10000),
        "Ex2FC_04_StartKeepAlive": (1, 10000),
        "Ex2FC_04_SupportCheck": (1, 10000),
        "Ex2FC_05_MonitorAndActivateValve": (1, 10000),
        "Ex2FC_05_SupportCheck": (1, 10000),
        "Ex2HAL_02_HeightSensorInitializationAndDTCCheck": (1, 10000),
        "Ex2HAL_02_SupportCheckAndDTCCheck": (1, 10000),
        "Ex2HAL_03_SupportCheckAndDTCCheck": (1, 10000),
        "Ex2HAL_03_SynchronizeInformationAndDTCCheck": (1, 10000),
        "Ex2MGR_01_SendMessage": (1, 10000),
        "Ex2MGR_02_SendMessage": (1, 10000),
        "Ex2MGR_03_SendMessage": (1, 10000),
        "Ex2IC_01_SendMessage": (1, 10000),
        "Ex2RES_03_InitialRegistrationRequest": (1, 10000),
        "Ex2RES_03_SupportCheck": (1, 10000),
        "Ex2RES_04_GetEcuInfo_SIL": (1, 10000),
        "Ex2RES_04_GetSupportFunction_SIL": (1, 10000),
        "Ex2RES_04_KeepAlive_SIL": (1, 10000),
        "Ex2RES_04_RemoteStartRegistration": (1, 10000),
        "Ex2RES_04_SendKey_SIL": (1, 10000),
        "Ex2RES_04_SupportCheck": (1, 10000),
        "Ex2RES_04_SupportCheck_SIL": (1, 10000),
        "Ex2GS_01_CheckShutterStatus": (1, 10000),
        "Ex2GS_01_ShiftMode": (1, 10000),
        "Ex2GS_01_SupportCheck": (1, 10000),
        "Ex2GS_02_SendMessage": (1, 10000),
        "Ex2LDR_09_SendMessage": (1, 10000),
        "Ex2LDR_10_SendMessage": (1, 10000),
        "Ex2LDR_11_SendMessage": (1, 10000),
        "Ex2LDR_12_SendMessage": (1, 10000),
        "Ex2PCM_04_SendMessage": (1, 10000),
        "Ex2FSR_01_02_ActiveTest": (1, 10000),
        "Ex2FSR_01_02_SupportCheck": (1, 10000),
        "Ex2FSR_03_04_ActiveTest": (1, 10000),
        "Ex2FSR_03_04_SupportCheck": (1, 10000),
        "Ex2FSR_05_06_ClearAbnormalHistory": (1, 10000),
        "Ex2FSR_05_06_GetAbnormalHistory": (1, 10000),
        "Ex2FSR_05_06_SupportCheck": (1, 10000),
        "Ex2HNCSN_01_TransitionToNormalMode": (1, 10000),
        "Ex2BCM_01_SendMessage": (1, 10000),
        "Ex2BCM_02_SendMessage": (1, 10000),
        "Ex2AVS_01_SendMessage": (1, 10000),
        "Ex2AVS_02_SendMessage": (1, 10000),
        "Ex2SBW_01_ActPositionLearningResult": (1, 10000),
        "Ex2SBW_01_StartActPositionLearning": (1, 10000),
        "Ex2HNFCM_02_LearnTarget1": (1, 10000),
        "Ex2HNFCM_02_LearnTarget2": (1, 10000),
        "Ex2HNFCM_02_LearnTarget3": (1, 10000),
        "Ex2HNFCM_02_LearnTargetAll": (1, 10000),
        "Ex2HNFCM_02_ReadCameraData": (1, 10000),
        "Ex2HNFCM_02_SupportCheck": (1, 10000),
        "Ex2ADS_04_SendMessage": (1, 10000),
        "Ex2ADS_05_SendMessage": (1, 10000),
        "Ex2ADS_06_SendMessage": (1, 10000),
        "Ex2ADS_07_SendMessage": (1, 10000),
        "Ex2ADS_08_SendMessage": (1, 10000),
        "Ex2ADS_09_SendMessage": (1, 10000),
        "Ex2ADS_10_SendMessage": (1, 10000),
        "Ex2DSEAT_01_SendMessage": (1, 10000),
        "Ex2DSEAT_02_SendMessage": (1, 10000),
        "Ex2DSEAT_03_SendMessage": (1, 10000),
        "Ex2DSEAT_04_SendMessage": (1, 10000),
        "Ex2ITS_01_SendMessage": (0, 10000),
        "Ex2ITS_02_SendMessage": (0, 10000),
        "Ex2DR_01_GetDataList": (1, 10000),
        "Ex2ASECT_01_SendMessage": (1, 10000),
        "Ex2EFI_28_LearningValueReset": (0, 10000),
        "Ex2AMT_01_SupportCheck": (1, 10000),
        "Ex2ASG_02_SupportCheck": (1, 10000),
        "Ex2AMT_01_GetHistoryData": (1, 10000),
        "Ex2AMT_01_WriteHistoryDataToECU": (1, 10000),
        "Ex2AC_28_SendMessage": (1, 10000),
        "Ex2DP2_11_BSMFSRRadarFrontBeamAxisAdjustment": (1, 10000),
        "Ex2DP2_11_FrontBeamAxisAdjustment": (1, 10000),
        "Ex2DP2_11_SupportCheck": (1, 10000),
        "Ex2DP2_11_SupportCheck_DID": (1, 10000),
        "Ex2DP2_12_ActiveTest": (1, 10000),
        "Ex2DP2_12_BSMFSRRadarDealershipAxisOffsetAngleOut": (1, 10000),
        "Ex2DP2_12_GetSupportBitInformation": (1, 10000),
        "Ex2DP2_12_SupportCheck_DID": (1, 10000),
        "Ex2DP2_13_ActiveTest": (1, 10000),
        "Ex2DP2_13_GetSupportBitInformation": (1, 10000),
        "Ex2DP2_14_SendMessage": (1, 10000),
        "Ex2FRD_01_LearnTarget": (1, 10000),
        "Ex2FRD_02_SendMessage": (1, 10000),
        "Ex2FRD_03_SendMessage": (1, 10000),
        "Ex2FRD_04_SendMessage": (0, 10000),
        "Ex2FRD_05_SendMessage": (1, 10000),
        "Ex2VCIB_03_SendMessage": (1, 10000),
        "Ex2VCIB_05_SendMessage": (1, 10000),
        "Ex2EVB_02_READYONProhibitionCancel": (0, 10000),
        "Ex2FAS_01_SendMessage": (1, 10000),
        "Ex2VC_01_GetActuationCnt": (1, 10000),
        "Ex2VC_01_SupportCheck": (1, 10000),
        "Ex2VC_01_WriteActuationCnt": (1, 10000),
        "Ex2VC_02_Learn0Point": (1, 10000),
        "Ex2VC_02_SupportCheck": (1, 10000),
        "Ex2VC_03_SendMessage": (1, 10000),
        "Ex2VC_04_SendMessage": (1, 10000),
        "Ex2PI_01_GetAbsoTime": (1, 10000),
        "Ex2PI_01_GetCurrentTimeStamp": (1, 10000),
        "Ex2PI_01_GetFuseHistory": (1, 10000),
        "Ex2PI_01_SupportCheck": (1, 10000),
        "Ex2PI_02_SendMessage": (0, 10000),
        "Ex2DSC_01_SendMessage": (1, 10000),
        "Ex2DSC_02_SendMessage": (1, 10000),
        "Ex2HVB_10_SendMessage": (1, 10000),
        "Ex2HVB_11_SendMessage": (1, 10000),
        "Ex2VIF_02_SendMessage": (1, 10000),
        "Ex2HNSCR_01_SendMessage": (0, 10000),
        "Ex2HNCSN_01_EcuCal": (1, 10000),
        "Ex2HNCSN_01_InitStatusOfSensor": (1, 10000),
        "Ex2HNCSN_01_SupportCheck": (1, 10000),
        "Ex2HNCSN_01_WriteAngleOfSensor": (1, 10000),
        "Ex2HNCSN_01_WriteNeutralPosition": (1, 10000),
        "Ex2HNCSN_01_WriteAngleOfRrSensor": (1, 10000),
        "Ex2HNCSN_01_WriteBumperType": (1, 10000),
        "Ex2SZEIU_01_SendMessage": (1, 10000),
        "Ex2HNSCR_02_SendMessage": (1, 10000),
        "Ex2ABS_33_ShiftNormalMode": (1, 10000),
        "Ex2ABS_47_EndExtendedSession": (1, 10000),
        "Ex2ABS_47_ErrorEndExtendedSession": (1, 10000),
        "Ex2ABS_47_ExitEndExtendedSession": (1, 10000),
        "Ex2MS2ABS_04_SendMessage": (1, 10000),
        "Ex2MS2AT_01_SendMessage": (1, 10000),
        "Ex2MS2RAB_02_SendMessage": (1, 10000),
        "Ex2VC_05_SendMessage": (1, 10000),
        "Ex2VIF_01_SendMessage": (1, 10000),
        "Ex2MS2EFI_03_SendMessage": (1, 10000),
        "Ex2MS2EFI_05_SendMessage": (1, 10000),
        "Ex2MS2EFI_06_SendMessage": (1, 10000),
        "Ex2VCIB_02_SendMessage": (1, 10000),
        "Ex2HV_15_HiVltFsAccLdHstRst": (0, 10000),
        "Ex2HV_17_BatteryStatusInfoReset": (0, 10000),
        "Ex2BDY_21_EndKeyRegistration": (1, 10000),
        "Ex2BDY_21_KeyNumGet": (1, 10000),
        "Ex2BDY_21_KeyRegistration": (1, 10000),
        "Ex2BDY_21_StartKeyRegistration": (1, 10000),
        "Ex2BDY_21_StopKeyRegistration": (1, 10000),
        "Ex2BDY_21_TimeoverKeyRegistration": (1, 10000),
        "Ex2BDY_22_EndKeyCodeErasure": (1, 10000),
        "Ex2BDY_22_KeyCodeErasure": (1, 10000),
        "Ex2BDY_22_KeyNumGet": (1, 10000),
        "Ex2BDY_22_StartKeyCodeErasure": (1, 10000),
        "Ex2BDY_22_StopKeyCodeErasure": (1, 10000),
        "Ex2BDY_22_TimeoverKeyCodeErasure": (1, 10000),
        "Ex2MS2AT_02_SendMessage": (1, 10000),
        "Ex2MS2DCM_01_SendMessage": (1, 10000),
        "Ex2MS2EMPS_01_SendMessage": (1, 10000),
        "Ex2MS2EMPS_02_SendMessage": (1, 10000),
        "Ex2MS2IG_01_SendMessage": (1, 10000),
        "Ex2MS2MET_02_SendMessage": (1, 10000),
        "Ex2MS2SAS_01_SendMessage": (1, 10000),
        "Ex2MS2SAS_03_SendMessage": (1, 10000),
        "Ex2HV_20_SendMessage": (1, 10000),
        "Ex2HV_18_SendMessage": (1, 10000),
        "Ex2MS2EYES_01_SendMessage": (1, 10000),
        "Ex2MS2EYES_02_SendMessage": (1, 10000),
        "Ex2MS2EYES_03_SendMessage": (1, 10000),
        "Ex2MS2EYES_04_SendMessage": (1, 10000),
        "Ex2MS2EYES_05_SendMessage": (1, 10000),
        "Ex2MS2EYES_06_SendMessage": (1, 10000),
        "Ex2MS2EYES_07_SendMessage": (1, 10000),
        "Ex2HV_21_SendMessage": (1, 10000),
        "Ex2HV_22_SendMessage": (1, 10000),
        "Ex2HV_19_SendMessage": (1, 10000),
        "Ex2HV_13_READYONProhibitionCancel": (0, 10000),
        "Ex2HV_11_SendMessage": (0, 10000),
        "Ex2ASUS_04_SupportCheck": (1, 10000),
        "Ex2ASUS_04_ModifyVhight": (1, 10000),
        "Ex2ASUS_04_ReturnVhight": (1, 10000),
        "Ex2ASUS_04_LearnKneeldownVheight": (1, 10000),
        "Ex2ASUS_04_CheckReturnedVhight": (1, 10000),
        "Ex2ASUS_05_ModifyVheightDownStart": (1, 10000),
        "Ex2ASUS_05_ModifyVheightStop": (1, 10000),
        "Ex2ASUS_05_CheckModifiedVheight": (1, 10000),
        "Ex2ASUS_05_ModifyVheightTimeOver": (1, 10000),
        "Ex2ASUS_05_LearnKneelDownVheight": (1, 10000),
        "Ex2ASUS_05_CheckReturnedVheight": (1, 10000),
        "Ex2ASUS_05_ReturnVheightStart": (1, 10000),
        "Ex2ASUS_05_SupportCheck": (1, 10000),
        "Ex2HV_12_SupportCheck": (1, 10000),
        "Ex2HV_12_GetDTCAndEEPROMStatus": (1, 10000),
        "Ex2HV_12_UpdateBatteryStatusInfo": (1, 10000),
        "Ex2HV_12_JudgementAfterUpdateInfo": (1, 10000),
        "Ex2HV_10_SupportCheck": (1, 10000),
        "Ex2HV_10_ReadBatteryStatus": (1, 10000),
        "Ex2HV_10_WaitingEEPROMWrite": (1, 10000),
        "Ex2HV_10_JudgementOfStckToReplace": (1, 10000),
        "Ex2BSM_01_02_SupportCheck": (1, 10000),
        "Ex2BSM_01_02_Mov2TestMode": (1, 10000),
        "Ex2BSM_01_02_ChkStilInTestMode": (1, 10000),
        "Ex2BSM_01_02_ExitTestMode": (1, 10000),
        "Ex2BSM_07_08_SupportCheck": (1, 10000),
        "Ex2BSM_07_08_GetAbnormalHistory": (1, 10000),
        "Ex2BSM_07_08_ClearAbnormalHistory": (1, 10000),
        "Ex2BSM_03_04_SupportCheck": (1, 10000),
        "Ex2BSM_03_04_ActiveTest": (1, 10000),
        "Ex2BSM_03_04_ActiveTestCon3_5": (1, 10000),
        "Ex2BSM_05_06_SupportCheck": (1, 10000),
        "Ex2BSM_05_06_ActiveTest": (1, 10000),
        "Ex2DRS_02_SupportCheck": (1, 10000),
        "Ex2DRS_02_ReadModeStatus": (1, 10000),
        "Ex2DRS_02_ReadRadarCruiseData": (1, 10000),
        "Ex2DRS_02_StopActiveTest": (1, 10000),
        "Ex2DRS_03_SupportCheck": (1, 10000),
        "Ex2DRS_03_ReadRadarCruiseData": (1, 10000),
        "Ex2DRS_03_StopActiveTest": (1, 10000),
        "Ex2DRS_03_ReadModeStatus": (1, 10000),
        "Ex2DRS_03_EndProcess": (1, 10000),
        "Ex2DRS_04_SendMessage": (1, 10000),
        "Ex24WD_03_SupportCheck": (1, 10000),
        "Ex24WD_03_ChangePreventionMode": (1, 10000),
        "Ex2ABS4WD_01_SupportCheck": (1, 10000),
        "Ex2ABS4WD_01_ChangePreventionMode": (1, 10000),
        "Ex2TPW_03_SendMessage": (1, 10000),
        "Ex2EFI_44_SessionTransition": (1, 10000),
        "Ex2EFI_54_ElectricThrottleLearning": (1, 10000),
        "Ex2ARS_01_A8SupportCheck": (1, 10000),
        "Ex2ARS_01_ReadDTCofVGRS": (1, 10000),
        "Ex2ARS_01_ClearOffSetValue": (1, 10000),
        "Ex2ARS_01_ReadDTCofARS": (1, 10000),
        "Ex2ARS_01_ReturnActuatorCenterPos": (1, 10000),
        "Ex2ARS_02_SupportCheck": (1, 10000),
        "Ex2ARS_02_ChkVGRSDtc": (1, 10000),
        "Ex2ARS_02_ClrCompVal": (1, 10000),
        "Ex2ARS_02_ChkARSDtc": (1, 10000),
        "Ex2ARS_02_InitCompVal": (1, 10000),
        "Ex2ARS_03_ActiveTest": (1, 10000),
        "Ex2ARS_03_SupportCheck": (1, 10000),
        "Ex2ASUS_06_ConditionCheck": (1, 10000),
        "Ex2ASUS_06_LiftRise": (1, 10000),
        "Ex2ASUS_06_AirPressure": (1, 10000),
        "Ex2ASUS_06_TheHeightAndTank": (1, 10000),
        "Ex2ASUS_07_LiftRise": (1, 10000),
        "Ex2ASUS_07_AirPressure": (1, 10000),
        "Ex2ASUS_07_TheHeightAndTank": (1, 10000),
        "Ex2ASUS_07_ConditionCheck": (1, 10000),
        "Ex2EFI_62_SendMessage": (1, 10000),
        "Ex2EFI_53_SendMessage": (1, 10000),
        "Ex2EFI_52_SendMessage": (1, 10000),
        "Ex2EFI_59_SendMessage": (1, 10000),
        "Ex2EMPS_12_AutoRackCentering": (1, 10000),
        "Ex2EMPS_12_SteeringStart": (0, 10000),
        "Ex2EMPS_12_SteeringAngleCheck": (1, 10000),
        "Ex2EFI_61_SupportCheck": (1, 10000),
        "Ex2EFI_61_WriteTotalShortTripEstimate": (1, 10000),
        "Ex2EFI_55_SendMessage": (1, 10000),
        "Ex2DCM_30_SendMessage": (1, 10000),
        "Ex2DCM_36_SendMessage": (1, 10000),
        "Ex2DCM_37_SendMessage": (0, 10000),
        "Ex2DCM_39_SendMessage": (0, 10000),
        "Ex2DCM_40_SendMessage": (1, 10000),
        "Ex2DCM_41_SendMessage": (0, 10000),
        "Ex2DCM_43_SendMessage": (1, 10000),
        "Ex2DCM_44_SendMessage": (0, 10000),
        "Ex2DCM_45_SendMessage": (1, 10000),
        "Ex2ECT_01_SendMessage": (1, 10000),
        "Ex2ECT_02_SendMessage": (1, 10000),
        "Ex2ECT_03_SendMessage": (1, 10000),
        "Ex2ECT_09_SendMessage": (1, 10000),
        "Ex2ECT_10_SendMessage": (1, 10000),
        "Ex2ECT_12_SendMessage": (1, 10000),
        "Ex2ECT_14_SendMessage": (1, 10000),
        "Ex2ECT_04_SendMessage": (1, 10000),
        "Ex2ECT_05_SendMessage": (1, 10000),
        "Ex2ECT_08_SendMessage": (1, 10000),
        "Ex2ECT_11_SendMessage": (1, 10000),
        "Ex2ECT_13_SendMessage": (1, 10000),
        "Ex2ECT_15_SendMessage": (1, 10000),
        "Ex2ECT_16_SendMessage": (1, 10000),
        "Ex2HV_14_ReadBatteryBlockVoltage": (1, 10000),
        "Ex2HV_14_ReadBatteryTemperature": (1, 10000),
        "Ex2HV_14_SupportCheck": (1, 10000),
        "Ex2ASUS_10_GetStatOfHeightCtrlProhibition": (1, 10000),
        "Ex2ASUS_10_ChgAndGetStatOfHeightCtrlProhibition": (1, 10000),
        "Ex2MM_09_GetPIDSupportInfo": (1, 10000),
        "Ex2MM_09_GetSoftErrHistory": (1, 10000),
        "Ex2MM_10_GetDiscErrInfo": (1, 10000),
        "Ex2MM_10_SupportCheck": (1, 10000),
    },
}

_NK_WRAPPER_SOURCE_LIMITS = {
    "_Ex2STR_43_StartKeepAliveThread@4": ("NK18", "NKDS4", "NKPlus"),
    "Ex2STR_55_StartKeepAlive": ("NK18", "NKDS4", "NKPlus"),
    "Ex2STR_56_StartKeepAlive": ("NK18", "NKDS4", "NKPlus"),
    "Ex2ABS_36_SupportInfo": ("NK18", "NKDS4", "NKPlus"),
    "Ex2ABS_36_Start_ECBProhibitCtrl": ("NK18", "NKDS4", "NKPlus"),
    "Ex2ABS_36_Stop_ECBProhibitCtrl": ("NK18", "NKDS4", "NKPlus"),
    "Ex2ABS_36_Start_ZeroDownDrive": ("NK18", "NKDS4", "NKPlus"),
    "Ex2ABS_36_Change_DealerMode": ("NK18", "NKDS4", "NKPlus"),
    "Ex2ABS_36_Change_NormalMode": ("NK18", "NKDS4", "NKPlus"),
    "Ex2ABS_36_Motor_Deactivate": ("NK18", "NKDS4", "NKPlus"),
    "Ex2ABS_36_StopRoutine": ("NK18", "NKDS4", "NKPlus"),
    "Ex2ABS_37_ForcedActuatorRefresh": ("NK18", "NKDS4", "NKPlus"),
    "Ex2ABS_37_ForcedActuatorRefreshStop": ("NK18", "NKDS4", "NKPlus"),
    "Ex2ABS_37_ConfirmRoutineResult": ("NK18", "NKDS4", "NKPlus"),
    "Ex2ABS_38_GetSupportInfo": ("NK18", "NKDS4", "NKPlus"),
    "Ex2ABS_38_ECBProhibitionControl": ("NK18", "NKDS4", "NKPlus"),
    "Ex2ABS_38_VacuumFillingFlg": ("NK18", "NKDS4", "NKPlus"),
    "Ex2ABS_38_AccumulatorZeroDown": ("NK18", "NKDS4", "NKPlus"),
    "Ex2ABS_38_StopTheRoutine": ("NK18", "NKDS4", "NKPlus"),
    "Ex2ABS_40_GetSupportInfo": ("NK18", "NKDS4", "NKPlus"),
    "Ex2ABS_40_VSCLine_AirBleeding": ("NK18", "NKDS4", "NKPlus"),
    "Ex2ABS_50_ConfSupportInfo": ("NK18", "NKDS4", "NKPlus"),
    "Ex2ABS_50_RearAirBleeding": ("NK18", "NKDS4", "NKPlus"),
    "Ex2ABS_50_RearAirBleeding_Next_1": ("NK18", "NKDS4", "NKPlus"),
    "Ex2ABS_50_RearAirBleeding_Next_2": ("NK18", "NKDS4", "NKPlus"),
    "Ex2ABS_50_RearAirBleeding_Timeout": ("NK18", "NKDS4", "NKPlus"),
    "Ex2ABS_50_ECBProhibitionControl": ("NK18", "NKDS4", "NKPlus"),
    "Ex2ABS_50_ECBProhibitionControl_Next": ("NK18", "NKDS4", "NKPlus"),
    "Ex2ABS_50_SLM2Refresh": ("NK18", "NKDS4", "NKPlus"),
    "Ex2ABS_50_VacuumFillingIncompleteFlagReset": ("NK18", "NKDS4", "NKPlus"),
    "Ex2ABS_50_EndExtendedSession": ("NK18", "NKDS4", "NKPlus"),
    "Ex2SMRT_45_GetSupportInfo": ("NK18", "NKDS4", "NKPlus"),
    "Ex2SMRT_45_SetSupportInfo": ("NK18", "NKDS4", "NKPlus"),
    "Ex2SMRT_45_StartOwnersKeyReg": ("NK18", "NKDS4", "NKPlus"),
    "Ex2SMRT_45_GetKeyStatus_StatusNormal": ("NK18", "NKDS4", "NKPlus"),
    "Ex2SMRT_45_GetKeyStatus_WaitComp": ("NK18", "NKDS4", "NKPlus"),
    "Ex2SMRT_45_GetKeyStatus_RegNormal": ("NK18", "NKDS4", "NKPlus"),
    "Ex2SMRT_45_StopOwnersKeyReg": ("NK18", "NKDS4", "NKPlus"),
    "Ex2SMRT_46_GetSupportInfo": ("NK18", "NKDS4", "NKPlus"),
    "Ex2SMRT_46_SetSupportInfo": ("NK18", "NKDS4", "NKPlus"),
    "Ex2SMRT_46_KeyCodeChk": ("NK18", "NKDS4", "NKPlus"),
    "Ex2SMRT_46_GetKeyStatus": ("NK18", "NKDS4", "NKPlus"),
    "Ex2SMRT_46_GetKeyStatus_RegistrationChk": ("NK18", "NKDS4", "NKPlus"),
    "Ex2SMRT_46_StopKeyCodeReset": ("NK18", "NKDS4", "NKPlus"),
    "Ex2SMRT_47_GetSupportInfo": ("NK18", "NKDS4", "NKPlus"),
    "Ex2SMRT_47_SetSupportInfo": ("NK18", "NKDS4", "NKPlus"),
    "Ex2SMRT_47_KeyCodeChk": ("NK18", "NKDS4", "NKPlus"),
    "Ex2SMRT_47_GetKeyStatus_NomalChk": ("NK18", "NKDS4", "NKPlus"),
    "Ex2SMRT_47_GetKeyStatus_RegistrationChk": ("NK18", "NKDS4", "NKPlus"),
    "Ex2SMRT_47_StopKeyCodeReset": ("NK18", "NKDS4", "NKPlus"),
    "Ex2ABS_35_ConfDIDBitInfo": ("NK18", "NKDS4", "NKPlus"),
    "Ex2ABS_35_ConfPlumbigStatus": ("NK18", "NKDS4", "NKPlus"),
    "Ex2ABS_35_SolenoidDriving": ("NK18", "NKDS4", "NKPlus"),
    "Ex2SMRT_48_GetSupportInfo": ("NK18", "NKDS4", "NKPlus"),
    "Ex2SMRT_48_ReadVINCode": ("NK18", "NKDS4", "NKPlus"),
    "Ex2SMRT_48_GetTheDigitalKeySerialNo": ("NK18", "NKDS4", "NKPlus"),
    "Ex2SMRT_58_StartIFBOXComIDReg": ("NK18", "NKDS4", "NKPlus"),
    "Ex2SMRT_58_EndExtendedSession": ("NK18", "NKDS4", "NKPlus"),
    "Ex2SMRT_56_ConfirmDIDRIDSupport": ("NK18", "NKDS4", "NKPlus"),
    "Ex2SMRT_56_StartFingerprintMode": ("NK18", "NKDS4", "NKPlus"),
    "Ex2SMRT_56_TerminateFingerprintMode": ("NK18", "NKDS4", "NKPlus"),
    "Ex2SMRT_56_EndExtendedSession": ("NK18", "NKDS4", "NKPlus"),
    "Ex2SMRT_53_Online_Certification": ("NK18", "NKDS4", "NKPlus"),
    "Ex2SMRT_53_Online_Certification_007": ("NK18", "NKDS4", "NKPlus"),
    "Ex2SMRT_53_SendTheKey": ("NK18", "NKDS4", "NKPlus"),
    "Ex2SMRT_55_ConfirmDIDRIDSupport": ("NK18", "NKDS4", "NKPlus"),
    "Ex2SMRT_55_GetKeyDiagInfo": ("NK18", "NKDS4", "NKPlus"),
    "Ex2SMRT_55_CHKSupportStatus": ("NK18", "NKDS4", "NKPlus"),
    "Ex2SMRT_55_SetKeyDiag": ("NK18", "NKDS4", "NKPlus"),
    "Ex2SMRT_55_SetKeyDiag2": ("NK18", "NKDS4", "NKPlus"),
    "Ex2SMRT_55_TermKeyDiag": ("NK18", "NKDS4", "NKPlus"),
    "Ex2SMRT_55_TermKeyDiag2": ("NK18", "NKDS4", "NKPlus"),
    "Ex2STR_52_GetSupportInfo": ("NK18", "NK12", "NKDS4", "NKPlus"),
    "Ex2STR_52_GetDataInfo": ("NK18", "NK12", "NKDS4", "NKPlus"),
    "Ex2STR_52_KeepAlive": ("NK18", "NK12", "NKDS4", "NKPlus"),
    "EX2STR_52_SendTheKey": ("NK18", "NK12", "NKDS4", "NKPlus"),
    "Ex2SMRT_50_GetSupportInfo": ("NK18", "NKDS4", "NKPlus"),
    "Ex2SMRT_50_StartKeyErasure": ("NK18", "NKDS4", "NKPlus"),
    "Ex2SMRT_50_KeyCodeReset": ("NK18", "NKDS4", "NKPlus"),
    "Ex2SMRT_50_EndExtendSession": ("NK18", "NKDS4", "NKPlus"),
    "Ex2SMRT_50_StartKeepAlive": ("NK18", "NKDS4", "NKPlus"),
    "Ex2SMRT_63_EndExtendSession": ("NK18", "NKDS4", "NKPlus"),
    "Ex2SMRT_63_GetKeyStatus": ("NK18", "NKDS4", "NKPlus"),
    "Ex2SMRT_63_GetSupportInfo": ("NK18", "NKDS4", "NKPlus"),
    "Ex2SMRT_63_StartKeepAlive": ("NK18", "NKDS4", "NKPlus"),
    "Ex2SMRT_63_StartKeyErasure": ("NK18", "NKDS4", "NKPlus"),
}

_NK_ANY_MODE_WRAPPERS = {
    ("NK18", "Ex2ECD_09_StartKeepAlive"): True,
    ("NK18", "Ex2ECD_10_StartKeepAlive"): True,
    ("NK12", "Ex2ECD_09_StartKeepAlive"): True,
    ("NK12", "Ex2ECD_10_StartKeepAlive"): True,
    ("NKDS4", "Ex2ECD_09_StartKeepAlive"): True,
    ("NKDS4", "Ex2ECD_10_StartKeepAlive"): True,
    ("NKPlus", "Ex2ECD_09_StartKeepAlive"): True,
    ("NKPlus", "Ex2ECD_10_StartKeepAlive"): True,
    ("NK18", "Ex2SMRT_55_CHKSupportStatus"): True,
    ("NKDS4", "Ex2SMRT_55_CHKSupportStatus"): True,
    ("NKPlus", "Ex2SMRT_55_CHKSupportStatus"): True,
}

_NK_BROKER_PREDICATES = {
    ("NK18", "Ex2STR_41_ResultTransponderID"): ((112, (17,)),),
    ("NK12", "Ex2STR_41_ResultTransponderID"): ((112, (17,)),),
    ("NKDS4", "Ex2STR_41_ResultTransponderID"): ((112, (17,)),),
    ("NKPlus", "Ex2STR_41_ResultTransponderID"): ((112, (17,)),),
    ("NK18", "Ex2STR_41_StartKeepAliveCheck"): ((112, (17,)),),
    ("NK12", "Ex2STR_41_StartKeepAliveCheck"): ((112, (17,)),),
    ("NKDS4", "Ex2STR_41_StartKeepAliveCheck"): ((112, (17,)),),
    ("NKPlus", "Ex2STR_41_StartKeepAliveCheck"): ((112, (17,)),),
    ("NK18", "Ex2STR_41_StartKeepAlive"): ((112, (17,)),),
    ("NK12", "Ex2STR_41_StartKeepAlive"): ((112, (17,)),),
    ("NKDS4", "Ex2STR_41_StartKeepAlive"): ((112, (17,)),),
    ("NKPlus", "Ex2STR_41_StartKeepAlive"): ((112, (17,)),),
    ("NK18", "Ex2ECD_09_StartKeepAlive"): ((112, (17, 33, 81)),),
    ("NK18", "Ex2ECD_10_StartKeepAlive"): ((112, (17, 33, 81)),),
    ("NK12", "Ex2ECD_09_StartKeepAlive"): ((112, (17, 33, 81)),),
    ("NK12", "Ex2ECD_10_StartKeepAlive"): ((112, (17, 33, 81)),),
    ("NKDS4", "Ex2ECD_09_StartKeepAlive"): ((112, (17, 33, 81)),),
    ("NKDS4", "Ex2ECD_10_StartKeepAlive"): ((112, (17, 33, 81)),),
    ("NKPlus", "Ex2ECD_09_StartKeepAlive"): ((112, (17, 33, 81)),),
    ("NKPlus", "Ex2ECD_10_StartKeepAlive"): ((112, (17, 33, 81)),),
}

_NK_ARGUMENT_MODE_WRAPPERS = {
    ("NK18", "Ex2SMRT_48_ReadVINCode"): 0,
    ("NKDS4", "Ex2SMRT_48_ReadVINCode"): 0,
    ("NKPlus", "Ex2SMRT_48_ReadVINCode"): 0,
}

_NK_PRE_MODE_ARGUMENT_WRITES = {
    ("NK18", "Ex2STR_GetRegKeyNumAfter"): (
        ("native_global:1014a720", 0, None, None),
        ("native_global:1014a724", 1, None, None),
    ),
    ("NK12", "Ex2STR_GetRegKeyNumAfter"): (
        ("native_global:100e5cf8", 0, None, None),
        ("native_global:100e5cfc", 1, None, None),
    ),
    ("NKDS4", "Ex2STR_GetRegKeyNumAfter"): (
        ("native_global:101b1ae4", 0, None, None),
        ("native_global:101b1ae8", 1, None, None),
    ),
    ("NKPlus", "Ex2STR_GetRegKeyNumAfter"): (
        ("native_global:101bcbe4", 0, None, None),
        ("native_global:101bcbe8", 1, None, None),
    ),
    ("NK18", "Ex2STR_41_GetCurrentModeRepeat"): (
        ("native_global:1014a790", 0, None, None),
        ("native_global:1014a794", 1, None, None),
    ),
    ("NK12", "Ex2STR_41_GetCurrentModeRepeat"): (
        ("native_global:100e5d48", 0, None, None),
        ("native_global:100e5d4c", 1, None, None),
    ),
    ("NKDS4", "Ex2STR_41_GetCurrentModeRepeat"): (
        ("native_global:101b1aec", 0, None, None),
        ("native_global:101b1af0", 1, None, None),
    ),
    ("NKPlus", "Ex2STR_41_GetCurrentModeRepeat"): (
        ("native_global:101bcbec", 0, None, None),
        ("native_global:101bcbf0", 1, None, None),
    ),
    ("NK18", "Ex2STR_41_GetCurrentStatusRepeat"): (
        ("native_global:1014a738", 0, None, None),
        ("native_global:1014a740", 1, None, None),
        ("native_global:1014a73c", 2, None, None),
    ),
    ("NK12", "Ex2STR_41_GetCurrentStatusRepeat"): (
        ("native_global:100e5d10", 0, None, None),
        ("native_global:100e5d18", 1, None, None),
        ("native_global:100e5d14", 2, None, None),
    ),
    ("NKDS4", "Ex2STR_41_GetCurrentStatusRepeat"): (
        ("native_global:101b1af4", 0, None, None),
        ("native_global:101b1af8", 1, None, None),
        ("native_global:101b1afc", 2, None, None),
    ),
    ("NKPlus", "Ex2STR_41_GetCurrentStatusRepeat"): (
        ("native_global:101bcbf4", 0, None, None),
        ("native_global:101bcbf8", 1, None, None),
        ("native_global:101bcbfc", 2, None, None),
    ),
    ("NK18", "Ex2STR_41_RegTransponderID"): (
        ("native_global:1014a7d8", 0, None, None),
        ("native_global:1014a7e4", 2, None, None),
        ("native_global:1014a7e0", 1, None, None),
        ("native_global:1014a7dc", -1, None, None),
    ),
    ("NK18", "Ex2STR_41_RegNewKey"): (
        ("native_global:1014a7d8", 1, None, None),
        ("native_global:1014a7e0", -1, None, None),
        ("native_global:1014a7e4", -1, None, None),
        ("native_global:1014a7dc", 0, None, None),
    ),
    ("NK18", "Ex2STR_41_StartCommunication"): (
        ("native_global:1014a7e0", 0, None, None),
        ("native_global:1014a7dc", 2, None, None),
        ("native_global:1014a7e4", 1, None, None),
        ("native_global:1014a7d8", 3, None, None),
    ),
    ("NK12", "Ex2STR_41_RegTransponderID"): (
        ("native_global:100e5d70", 0, None, None),
        ("native_global:100e5d7c", 2, None, None),
        ("native_global:100e5d78", 1, None, None),
        ("native_global:100e5d74", -1, None, None),
    ),
    ("NK12", "Ex2STR_41_RegNewKey"): (
        ("native_global:100e5d70", 1, None, None),
        ("native_global:100e5d78", -1, None, None),
        ("native_global:100e5d7c", -1, None, None),
        ("native_global:100e5d74", 0, None, None),
    ),
    ("NK12", "Ex2STR_41_StartCommunication"): (
        ("native_global:100e5d78", 0, None, None),
        ("native_global:100e5d74", 2, None, None),
        ("native_global:100e5d7c", 1, None, None),
        ("native_global:100e5d70", 3, None, None),
    ),
    ("NKDS4", "Ex2STR_41_RegTransponderID"): (
        ("native_global:101b1a80", 0, None, None),
        ("native_global:101b1a88", 1, None, None),
        ("native_global:101b1a8c", 2, None, None),
        ("native_global:101b1a84", -1, None, None),
    ),
    ("NKDS4", "Ex2STR_41_RegNewKey"): (
        ("native_global:101b1a80", 1, None, None),
        ("native_global:101b1a84", 0, None, None),
        ("native_global:101b1a88", -1, None, None),
        ("native_global:101b1a8c", -1, None, None),
    ),
    ("NKDS4", "Ex2STR_41_StartCommunication"): (
        ("native_global:101b1a88", 0, None, None),
        ("native_global:101b1a8c", 1, None, None),
        ("native_global:101b1a84", 2, None, None),
        ("native_global:101b1a80", 3, None, None),
    ),
    ("NKPlus", "Ex2STR_41_RegTransponderID"): (
        ("native_global:101bcb80", 0, None, None),
        ("native_global:101bcb88", 1, None, None),
        ("native_global:101bcb8c", 2, None, None),
        ("native_global:101bcb84", -1, None, None),
    ),
    ("NKPlus", "Ex2STR_41_RegNewKey"): (
        ("native_global:101bcb80", 1, None, None),
        ("native_global:101bcb84", 0, None, None),
        ("native_global:101bcb88", -1, None, None),
        ("native_global:101bcb8c", -1, None, None),
    ),
    ("NKPlus", "Ex2STR_41_StartCommunication"): (
        ("native_global:101bcb88", 0, None, None),
        ("native_global:101bcb8c", 1, None, None),
        ("native_global:101bcb84", 2, None, None),
        ("native_global:101bcb80", 3, None, None),
    ),
    ("NK18", "Ex2STR_53_GetKeyStatus"): (
        ("native_global:1014a7b4", 1, None, None),
        ("native_global:1014a7b0", 0, None, None),
        ("native_global:1014a7b8", 2, None, None),
    ),
    ("NK18", "Ex2STR_53_GetImmobilizerMode"): (
        ("native_global:1014a7b4", 1, None, None),
        ("native_global:1014a7b0", 0, None, None),
        ("native_global:1014a7b8", 2, None, None),
    ),
    ("NK12", "Ex2STR_53_GetKeyStatus"): (
        ("native_global:100e5d5c", 1, None, None),
        ("native_global:100e5d58", 0, None, None),
        ("native_global:100e5d60", 2, None, None),
    ),
    ("NK12", "Ex2STR_53_GetImmobilizerMode"): (
        ("native_global:100e5d5c", 1, None, None),
        ("native_global:100e5d58", 0, None, None),
        ("native_global:100e5d60", 2, None, None),
    ),
    ("NKDS4", "Ex2STR_53_GetKeyStatus"): (
        ("native_global:101b1ad4", 1, None, None),
        ("native_global:101b1ad8", 2, None, None),
        ("native_global:101b1ad0", 0, None, None),
    ),
    ("NKDS4", "Ex2STR_53_GetImmobilizerMode"): (
        ("native_global:101b1ad4", 1, None, None),
        ("native_global:101b1ad8", 2, None, None),
        ("native_global:101b1ad0", 0, None, None),
    ),
    ("NKPlus", "Ex2STR_53_GetKeyStatus"): (
        ("native_global:101bcbd4", 1, None, None),
        ("native_global:101bcbd8", 2, None, None),
        ("native_global:101bcbd0", 0, None, None),
    ),
    ("NKPlus", "Ex2STR_53_GetImmobilizerMode"): (
        ("native_global:101bcbd4", 1, None, None),
        ("native_global:101bcbd8", 2, None, None),
        ("native_global:101bcbd0", 0, None, None),
    ),
    ("NK18", "Ex2STR_43_ReqSecuritySeed"): (
        ("native_global:1014a758", 0, None, None),
        ("native_global:1014a75c", 1, None, None),
    ),
    ("NK18", "Ex2STR_43_ClearAllKey"): (
        ("native_global:1014a728", 0, None, None),
        ("native_global:1014a730", 2, None, None),
        ("native_global:1014a72c", 1, None, None),
    ),
    ("NK12", "Ex2STR_43_ReqSecuritySeed"): (
        ("native_global:100e5d20", 0, None, None),
        ("native_global:100e5d24", 1, None, None),
    ),
    ("NK12", "Ex2STR_43_ClearAllKey"): (
        ("native_global:100e5d00", 0, None, None),
        ("native_global:100e5d08", 2, None, None),
        ("native_global:100e5d04", 1, None, None),
    ),
    ("NKDS4", "Ex2STR_43_ReqSecuritySeed"): (
        ("native_global:101b1a90", 0, None, None),
        ("native_global:101b1a94", 1, None, None),
    ),
    ("NKDS4", "Ex2STR_43_ClearAllKey"): (
        ("native_global:101b1a98", 0, None, None),
        ("native_global:101b1a9c", 1, None, None),
        ("native_global:101b1aa0", 2, None, None),
    ),
    ("NKPlus", "Ex2STR_43_ReqSecuritySeed"): (
        ("native_global:101bcb90", 0, None, None),
        ("native_global:101bcb94", 1, None, None),
    ),
    ("NKPlus", "Ex2STR_43_ClearAllKey"): (
        ("native_global:101bcb98", 0, None, None),
        ("native_global:101bcb9c", 1, None, None),
        ("native_global:101bcba0", 2, None, None),
    ),
    ("NK18", "Ex2SMRT_41_Online_Certification"): (
        ("native_global:1014a5c0", 0, None, None),
        ("native_global:1014a5c8", 2, None, None),
        ("native_global:1014a5d0", 4, None, None),
        ("native_global:1014a5c4", 1, None, None),
        ("native_global:1014a5cc", 3, None, None),
        ("native_global:1014a5d4", 5, 8, True),
        ("native_global:1014a5d8", 6, 8, False),
        ("native_global:1014a5dc", 7, 8, False),
        ("native_global:1014a5e0", 8, None, None),
    ),
    ("NK18", "Ex2SMRT_41_Online_Certification_008"): (
        ("native_global:1014a588", 0, None, None),
        ("native_global:1014a590", 2, None, None),
        ("native_global:1014a58c", 1, None, None),
        ("native_global:1014a594", 3, None, None),
    ),
    ("NK18", "Ex2SMRT_41_KeepAlive"): (
        ("native_global:1014a5b8", 0, None, None),
        ("native_global:1014a5bc", 1, None, None),
    ),
    ("NK18", "Ex2SMRT_41_SendTheKey"): (
        ("native_global:1014a688", 0, None, None),
        ("native_global:1014a690", 2, None, None),
        ("native_global:1014a68c", 1, None, None),
    ),
    ("NK18", "Ex2SMRT_42_GetKeyNum"): (
        ("native_global:1014a640", 0, None, None),
        ("native_global:1014a64c", 1, None, None),
    ),
    ("NK18", "Ex2SMRT_42_KeyCodeErasureChk"): (
        ("native_global:1014a640", 0, None, None),
        ("native_global:1014a648", 2, None, None),
        ("native_global:1014a644", 1, None, None),
        ("native_global:1014a650", 4, None, None),
        ("native_global:1014a64c", 3, None, None),
        ("native_global:1014a658", 6, None, None),
        ("native_global:1014a654", 5, None, None),
        ("native_global:1014a65c", 7, None, None),
    ),
    ("NK18", "Ex2SMRT_42_GetKeyStatus"): (
        ("native_global:1014a644", 1, None, None),
        ("native_global:1014a64c", 0, None, None),
    ),
    ("NK18", "Ex2SMRT_42_KeyCodeErasure"): (("native_global:1014a64c", 0, None, None),),
    ("NK18", "Ex2SMRT_45_GetSupportInfo"): (
        ("native_global:1014a6e0", 0, None, None),
        ("native_global:1014a6e8", 2, None, None),
        ("native_global:1014a6e4", 1, None, None),
        ("native_global:1014a6ec", 3, None, None),
    ),
    ("NK18", "Ex2SMRT_45_StartOwnersKeyReg"): (
        ("native_global:1014a618", 0, None, None),
        ("native_global:1014a620", 2, None, None),
        ("native_global:1014a61c", 1, None, None),
        ("native_global:1014a628", 4, None, None),
        ("native_global:1014a624", 3, None, None),
        ("native_global:1014a62c", 5, None, None),
    ),
    ("NK18", "Ex2SMRT_45_GetKeyStatus_StatusNormal"): (
        ("native_global:1014a628", 0, None, None),
    ),
    ("NK18", "Ex2SMRT_45_GetKeyStatus_WaitComp"): (
        ("native_global:1014a628", 0, None, None),
    ),
    ("NK18", "Ex2SMRT_45_GetKeyStatus_RegNormal"): (
        ("native_global:1014a628", 0, None, None),
    ),
    ("NK18", "Ex2SMRT_46_GetSupportInfo"): (
        ("native_global:1014a530", 0, None, None),
        ("native_global:1014a538", 2, None, None),
        ("native_global:1014a534", 1, None, None),
        ("native_global:1014a53c", 3, None, None),
    ),
    ("NK18", "Ex2SMRT_46_KeyCodeChk"): (
        ("native_global:1014a6b8", 0, None, None),
        ("native_global:1014a6c0", 2, None, None),
        ("native_global:1014a6bc", 1, None, None),
        ("native_global:1014a6c8", 4, None, None),
        ("native_global:1014a6c4", 3, None, None),
        ("native_global:1014a6cc", 5, None, None),
    ),
    ("NK18", "Ex2SMRT_46_GetKeyStatus"): (("native_global:1014a6bc", 0, None, None),),
    ("NK18", "Ex2SMRT_47_GetSupportInfo"): (
        ("native_global:1014a678", 0, None, None),
        ("native_global:1014a680", 2, None, None),
        ("native_global:1014a67c", 1, None, None),
        ("native_global:1014a684", 3, None, None),
    ),
    ("NK18", "Ex2SMRT_47_KeyCodeChk"): (
        ("native_global:1014a598", 0, None, None),
        ("native_global:1014a5a0", 2, None, None),
        ("native_global:1014a59c", 1, None, None),
        ("native_global:1014a5a8", 4, None, None),
        ("native_global:1014a5a4", 3, None, None),
        ("native_global:1014a5ac", 5, None, None),
    ),
    ("NK18", "Ex2SMRT_47_GetKeyStatus_NomalChk"): (
        ("native_global:1014a59c", 0, None, None),
    ),
    ("NK18", "Ex2SMRT_53_Online_Certification"): (
        ("native_global:1014a508", 0, None, None),
        ("native_global:1014a510", 2, None, None),
        ("native_global:1014a518", 4, None, None),
        ("native_global:1014a50c", 1, None, None),
        ("native_global:1014a514", 3, None, None),
    ),
    ("NK18", "Ex2SMRT_53_Online_Certification_007"): (
        ("native_global:1014a6d0", 0, None, None),
        ("native_global:1014a6d8", 2, None, None),
        ("native_global:1014a6d4", 1, None, None),
    ),
    ("NK18", "Ex2SMRT_53_SendTheKey"): (
        ("native_global:1014a520", 0, None, None),
        ("native_global:1014a528", 2, None, None),
        ("native_global:1014a524", 1, None, None),
    ),
    ("NK12", "Ex2SMRT_41_Online_Certification"): (
        ("native_global:100e5c68", 0, None, None),
        ("native_global:100e5c70", 2, None, None),
        ("native_global:100e5c78", 4, None, None),
        ("native_global:100e5c6c", 1, None, None),
        ("native_global:100e5c74", 3, None, None),
        ("native_global:100e5c7c", 5, 8, True),
        ("native_global:100e5c80", 6, 8, False),
        ("native_global:100e5c84", 7, 8, False),
        ("native_global:100e5c88", 8, None, None),
    ),
    ("NK12", "Ex2SMRT_41_Online_Certification_008"): (
        ("native_global:100e5c50", 0, None, None),
        ("native_global:100e5c58", 2, None, None),
        ("native_global:100e5c54", 1, None, None),
        ("native_global:100e5c5c", 3, None, None),
    ),
    ("NK12", "Ex2SMRT_41_KeepAlive"): (
        ("native_global:100e5c60", 0, None, None),
        ("native_global:100e5c64", 1, None, None),
    ),
    ("NK12", "Ex2SMRT_41_SendTheKey"): (
        ("native_global:100e5cb8", 0, None, None),
        ("native_global:100e5cc0", 2, None, None),
        ("native_global:100e5cbc", 1, None, None),
    ),
    ("NK12", "Ex2SMRT_42_GetKeyNum"): (
        ("native_global:100e5c90", 0, None, None),
        ("native_global:100e5c9c", 1, None, None),
    ),
    ("NK12", "Ex2SMRT_42_KeyCodeErasureChk"): (
        ("native_global:100e5c90", 0, None, None),
        ("native_global:100e5c98", 2, None, None),
        ("native_global:100e5c94", 1, None, None),
        ("native_global:100e5ca0", 4, None, None),
        ("native_global:100e5c9c", 3, None, None),
        ("native_global:100e5ca8", 6, None, None),
        ("native_global:100e5ca4", 5, None, None),
        ("native_global:100e5cac", 7, None, None),
    ),
    ("NK12", "Ex2SMRT_42_GetKeyStatus"): (
        ("native_global:100e5c94", 1, None, None),
        ("native_global:100e5c9c", 0, None, None),
    ),
    ("NK12", "Ex2SMRT_42_KeyCodeErasure"): (("native_global:100e5c9c", 0, None, None),),
    ("NKDS4", "Ex2SMRT_41_Online_Certification"): (
        ("native_global:101b19bc", 0, None, None),
        ("native_global:101b19c0", 1, None, None),
        ("native_global:101b19c4", 2, None, None),
        ("native_global:101b19c8", 3, None, None),
        ("native_global:101b19cc", 4, None, None),
        ("native_global:101b19d0", 5, 8, True),
        ("native_global:101b19d4", 6, 8, False),
        ("native_global:101b19d8", 7, 8, False),
        ("native_global:101b19dc", 8, None, None),
    ),
    ("NKDS4", "Ex2SMRT_41_Online_Certification_008"): (
        ("native_global:101b19e0", 0, None, None),
        ("native_global:101b19e4", 1, None, None),
        ("native_global:101b19e8", 2, None, None),
        ("native_global:101b19ec", 3, None, None),
    ),
    ("NKDS4", "Ex2SMRT_41_KeepAlive"): (
        ("native_global:101b19f0", 0, None, None),
        ("native_global:101b19f4", 1, None, None),
    ),
    ("NKDS4", "Ex2SMRT_41_SendTheKey"): (
        ("native_global:101b19f8", 0, None, None),
        ("native_global:101b19fc", 1, None, None),
        ("native_global:101b1a00", 2, None, None),
    ),
    ("NKDS4", "Ex2SMRT_42_GetKeyNum"): (
        ("native_global:101b18c8", 0, None, None),
        ("native_global:101b18d4", 1, None, None),
    ),
    ("NKDS4", "Ex2SMRT_42_GetKeyStatus"): (
        ("native_global:101b18cc", 1, None, None),
        ("native_global:101b18d4", 0, None, None),
    ),
    ("NKDS4", "Ex2SMRT_42_KeyCodeErasure"): (
        ("native_global:101b18d4", 0, None, None),
    ),
    ("NKDS4", "Ex2SMRT_42_KeyCodeErasureChk"): (
        ("native_global:101b18c8", 0, None, None),
        ("native_global:101b18cc", 1, None, None),
        ("native_global:101b18d0", 2, None, None),
        ("native_global:101b18d4", 3, None, None),
        ("native_global:101b18d8", 4, None, None),
        ("native_global:101b18dc", 5, None, None),
        ("native_global:101b18e0", 6, None, None),
        ("native_global:101b18e4", 7, None, None),
    ),
    ("NKDS4", "Ex2SMRT_45_GetKeyStatus_RegNormal"): (
        ("native_global:101b1908", 0, None, None),
    ),
    ("NKDS4", "Ex2SMRT_45_GetKeyStatus_StatusNormal"): (
        ("native_global:101b1908", 0, None, None),
    ),
    ("NKDS4", "Ex2SMRT_45_GetKeyStatus_WaitComp"): (
        ("native_global:101b1908", 0, None, None),
    ),
    ("NKDS4", "Ex2SMRT_45_GetSupportInfo"): (
        ("native_global:101b18e8", 0, None, None),
        ("native_global:101b18ec", 1, None, None),
        ("native_global:101b18f0", 2, None, None),
        ("native_global:101b18f4", 3, None, None),
    ),
    ("NKDS4", "Ex2SMRT_45_StartOwnersKeyReg"): (
        ("native_global:101b18f8", 0, None, None),
        ("native_global:101b18fc", 1, None, None),
        ("native_global:101b1900", 2, None, None),
        ("native_global:101b1904", 3, None, None),
        ("native_global:101b1908", 4, None, None),
        ("native_global:101b190c", 5, None, None),
    ),
    ("NKDS4", "Ex2SMRT_46_GetKeyStatus"): (("native_global:101b1920", 0, None, None),),
    ("NKDS4", "Ex2SMRT_46_GetSupportInfo"): (
        ("native_global:101b1934", 0, None, None),
        ("native_global:101b1938", 1, None, None),
        ("native_global:101b193c", 2, None, None),
        ("native_global:101b1940", 3, None, None),
    ),
    ("NKDS4", "Ex2SMRT_46_KeyCodeChk"): (
        ("native_global:101b191c", 0, None, None),
        ("native_global:101b1920", 1, None, None),
        ("native_global:101b1924", 2, None, None),
        ("native_global:101b1928", 3, None, None),
        ("native_global:101b192c", 4, None, None),
        ("native_global:101b1930", 5, None, None),
    ),
    ("NKDS4", "Ex2SMRT_47_GetKeyStatus_NomalChk"): (
        ("native_global:101b1948", 0, None, None),
    ),
    ("NKDS4", "Ex2SMRT_47_GetSupportInfo"): (
        ("native_global:101b195c", 0, None, None),
        ("native_global:101b1960", 1, None, None),
        ("native_global:101b1964", 2, None, None),
        ("native_global:101b1968", 3, None, None),
    ),
    ("NKDS4", "Ex2SMRT_47_KeyCodeChk"): (
        ("native_global:101b1944", 0, None, None),
        ("native_global:101b1948", 1, None, None),
        ("native_global:101b194c", 2, None, None),
        ("native_global:101b1950", 3, None, None),
        ("native_global:101b1954", 4, None, None),
        ("native_global:101b1958", 5, None, None),
    ),
    ("NKDS4", "Ex2SMRT_53_Online_Certification"): (
        ("native_global:101b1a04", 0, None, None),
        ("native_global:101b1a08", 1, None, None),
        ("native_global:101b1a0c", 2, None, None),
        ("native_global:101b1a10", 3, None, None),
        ("native_global:101b1a14", 4, None, None),
    ),
    ("NKDS4", "Ex2SMRT_53_Online_Certification_007"): (
        ("native_global:101b1a18", 0, None, None),
        ("native_global:101b1a1c", 1, None, None),
        ("native_global:101b1a20", 2, None, None),
    ),
    ("NKDS4", "Ex2SMRT_53_SendTheKey"): (
        ("native_global:101b1a24", 0, None, None),
        ("native_global:101b1a28", 1, None, None),
        ("native_global:101b1a2c", 2, None, None),
    ),
    ("NKPlus", "Ex2SMRT_41_Online_Certification"): (
        ("native_global:101bcabc", 0, None, None),
        ("native_global:101bcac0", 1, None, None),
        ("native_global:101bcac4", 2, None, None),
        ("native_global:101bcac8", 3, None, None),
        ("native_global:101bcacc", 4, None, None),
        ("native_global:101bcad0", 5, 8, True),
        ("native_global:101bcad4", 6, 8, False),
        ("native_global:101bcad8", 7, 8, False),
        ("native_global:101bcadc", 8, None, None),
    ),
    ("NKPlus", "Ex2SMRT_41_Online_Certification_008"): (
        ("native_global:101bcae0", 0, None, None),
        ("native_global:101bcae4", 1, None, None),
        ("native_global:101bcae8", 2, None, None),
        ("native_global:101bcaec", 3, None, None),
    ),
    ("NKPlus", "Ex2SMRT_41_KeepAlive"): (
        ("native_global:101bcaf0", 0, None, None),
        ("native_global:101bcaf4", 1, None, None),
    ),
    ("NKPlus", "Ex2SMRT_41_SendTheKey"): (
        ("native_global:101bcaf8", 0, None, None),
        ("native_global:101bcafc", 1, None, None),
        ("native_global:101bcb00", 2, None, None),
    ),
    ("NKPlus", "Ex2SMRT_42_GetKeyNum"): (
        ("native_global:101bc9c8", 0, None, None),
        ("native_global:101bc9d4", 1, None, None),
    ),
    ("NKPlus", "Ex2SMRT_42_GetKeyStatus"): (
        ("native_global:101bc9cc", 1, None, None),
        ("native_global:101bc9d4", 0, None, None),
    ),
    ("NKPlus", "Ex2SMRT_42_KeyCodeErasure"): (
        ("native_global:101bc9d4", 0, None, None),
    ),
    ("NKPlus", "Ex2SMRT_42_KeyCodeErasureChk"): (
        ("native_global:101bc9c8", 0, None, None),
        ("native_global:101bc9cc", 1, None, None),
        ("native_global:101bc9d0", 2, None, None),
        ("native_global:101bc9d4", 3, None, None),
        ("native_global:101bc9d8", 4, None, None),
        ("native_global:101bc9dc", 5, None, None),
        ("native_global:101bc9e0", 6, None, None),
        ("native_global:101bc9e4", 7, None, None),
    ),
    ("NKPlus", "Ex2SMRT_45_GetKeyStatus_RegNormal"): (
        ("native_global:101bca08", 0, None, None),
    ),
    ("NKPlus", "Ex2SMRT_45_GetKeyStatus_StatusNormal"): (
        ("native_global:101bca08", 0, None, None),
    ),
    ("NKPlus", "Ex2SMRT_45_GetKeyStatus_WaitComp"): (
        ("native_global:101bca08", 0, None, None),
    ),
    ("NKPlus", "Ex2SMRT_45_GetSupportInfo"): (
        ("native_global:101bc9e8", 0, None, None),
        ("native_global:101bc9ec", 1, None, None),
        ("native_global:101bc9f0", 2, None, None),
        ("native_global:101bc9f4", 3, None, None),
    ),
    ("NKPlus", "Ex2SMRT_45_StartOwnersKeyReg"): (
        ("native_global:101bc9f8", 0, None, None),
        ("native_global:101bc9fc", 1, None, None),
        ("native_global:101bca00", 2, None, None),
        ("native_global:101bca04", 3, None, None),
        ("native_global:101bca08", 4, None, None),
        ("native_global:101bca0c", 5, None, None),
    ),
    ("NKPlus", "Ex2SMRT_46_GetKeyStatus"): (("native_global:101bca20", 0, None, None),),
    ("NKPlus", "Ex2SMRT_46_GetSupportInfo"): (
        ("native_global:101bca34", 0, None, None),
        ("native_global:101bca38", 1, None, None),
        ("native_global:101bca3c", 2, None, None),
        ("native_global:101bca40", 3, None, None),
    ),
    ("NKPlus", "Ex2SMRT_46_KeyCodeChk"): (
        ("native_global:101bca1c", 0, None, None),
        ("native_global:101bca20", 1, None, None),
        ("native_global:101bca24", 2, None, None),
        ("native_global:101bca28", 3, None, None),
        ("native_global:101bca2c", 4, None, None),
        ("native_global:101bca30", 5, None, None),
    ),
    ("NKPlus", "Ex2SMRT_47_GetKeyStatus_NomalChk"): (
        ("native_global:101bca48", 0, None, None),
    ),
    ("NKPlus", "Ex2SMRT_47_GetSupportInfo"): (
        ("native_global:101bca5c", 0, None, None),
        ("native_global:101bca60", 1, None, None),
        ("native_global:101bca64", 2, None, None),
        ("native_global:101bca68", 3, None, None),
    ),
    ("NKPlus", "Ex2SMRT_47_KeyCodeChk"): (
        ("native_global:101bca44", 0, None, None),
        ("native_global:101bca48", 1, None, None),
        ("native_global:101bca4c", 2, None, None),
        ("native_global:101bca50", 3, None, None),
        ("native_global:101bca54", 4, None, None),
        ("native_global:101bca58", 5, None, None),
    ),
    ("NKPlus", "Ex2SMRT_53_Online_Certification"): (
        ("native_global:101bcb04", 0, None, None),
        ("native_global:101bcb08", 1, None, None),
        ("native_global:101bcb0c", 2, None, None),
        ("native_global:101bcb10", 3, None, None),
        ("native_global:101bcb14", 4, None, None),
    ),
    ("NKPlus", "Ex2SMRT_53_Online_Certification_007"): (
        ("native_global:101bcb18", 0, None, None),
        ("native_global:101bcb1c", 1, None, None),
        ("native_global:101bcb20", 2, None, None),
    ),
    ("NKPlus", "Ex2SMRT_53_SendTheKey"): (
        ("native_global:101bcb24", 0, None, None),
        ("native_global:101bcb28", 1, None, None),
        ("native_global:101bcb2c", 2, None, None),
    ),
    ("NK18", "Ex2STR_52_GetSupportInfo"): (
        ("native_global:1014a778", 0, None, None),
        ("native_global:1014a780", 2, None, None),
        ("native_global:1014a788", 4, None, None),
        ("native_global:1014a77c", 1, None, None),
        ("native_global:1014a784", 3, None, None),
    ),
    ("NK18", "Ex2STR_52_GetDataInfo"): (
        ("native_global:1014a7e8", 0, None, None),
        ("native_global:1014a7ec", 1, None, None),
    ),
    ("NK18", "EX2STR_52_SendTheKey"): (
        ("native_global:1014a7d0", 0, None, None),
        ("native_global:1014a7d4", 1, None, None),
    ),
    ("NK12", "Ex2STR_52_GetSupportInfo"): (
        ("native_global:100e5d30", 0, None, None),
        ("native_global:100e5d38", 2, None, None),
        ("native_global:100e5d40", 4, None, None),
        ("native_global:100e5d34", 1, None, None),
        ("native_global:100e5d3c", 3, None, None),
    ),
    ("NK12", "Ex2STR_52_GetDataInfo"): (
        ("native_global:100e5d80", 0, None, None),
        ("native_global:100e5d84", 1, None, None),
    ),
    ("NK12", "EX2STR_52_SendTheKey"): (
        ("native_global:100e5d68", 0, None, None),
        ("native_global:100e5d6c", 1, None, None),
    ),
    ("NKDS4", "Ex2STR_52_GetSupportInfo"): (
        ("native_global:101b1aa4", 0, None, None),
        ("native_global:101b1aa8", 1, None, None),
        ("native_global:101b1ab4", 4, None, None),
        ("native_global:101b1aac", 2, None, None),
        ("native_global:101b1ab0", 3, None, None),
    ),
    ("NKDS4", "Ex2STR_52_GetDataInfo"): (
        ("native_global:101b1abc", 1, None, None),
        ("native_global:101b1ab8", 0, None, None),
    ),
    ("NKDS4", "EX2STR_52_SendTheKey"): (
        ("native_global:101b1ac4", 1, None, None),
        ("native_global:101b1ac0", 0, None, None),
    ),
    ("NKPlus", "Ex2STR_52_GetSupportInfo"): (
        ("native_global:101bcba4", 0, None, None),
        ("native_global:101bcba8", 1, None, None),
        ("native_global:101bcbb4", 4, None, None),
        ("native_global:101bcbac", 2, None, None),
        ("native_global:101bcbb0", 3, None, None),
    ),
    ("NKPlus", "Ex2STR_52_GetDataInfo"): (
        ("native_global:101bcbbc", 1, None, None),
        ("native_global:101bcbb8", 0, None, None),
    ),
    ("NKPlus", "EX2STR_52_SendTheKey"): (
        ("native_global:101bcbc4", 1, None, None),
        ("native_global:101bcbc0", 0, None, None),
    ),
    ("NK18", "Ex2SMRT_55_ConfirmDIDRIDSupport"): (
        ("native_global:1014a5b0", 0, None, None),
    ),
    ("NK18", "Ex2SMRT_55_GetKeyDiagInfo"): (
        ("native_global:1014a694", -1, None, None),
        ("native_global:1014a695", -1, None, None),
    ),
    ("NKDS4", "Ex2SMRT_55_ConfirmDIDRIDSupport"): (
        ("native_global:101b19ac", 0, None, None),
    ),
    ("NKDS4", "Ex2SMRT_55_GetKeyDiagInfo"): (
        ("native_global:101b19b0", -1, None, None),
        ("native_global:101b19b1", -1, None, None),
    ),
    ("NKPlus", "Ex2SMRT_55_ConfirmDIDRIDSupport"): (
        ("native_global:101bcaac", 0, None, None),
    ),
    ("NKPlus", "Ex2SMRT_55_GetKeyDiagInfo"): (
        ("native_global:101bcab0", -1, None, None),
        ("native_global:101bcab1", -1, None, None),
    ),
}

_NK_VARIANT_WRAPPERS = {
    "NKDS4": {
        "Ex2SMRT_55_ConfirmDIDRIDSupport": (20, "thread", 10000, 1, False, False),
        "Ex2SMRT_55_GetKeyDiagInfo": (20, "direct", None, 0, False, False),
        "Ex2SMRT_55_CHKSupportStatus": (20, "direct", None, 2, False, False),
        "Ex2SMRT_55_SetKeyDiag": (20, "direct", None, 2, False, False),
        "Ex2SMRT_55_SetKeyDiag2": (20, "direct", None, 3, False, False),
        "Ex2SMRT_55_TermKeyDiag": (20, "direct", None, 0, False, False),
        "Ex2SMRT_55_TermKeyDiag2": (20, "direct", None, 0, False, False),
        "Ex2STR_52_GetSupportInfo": ((4, 20), "thread", 10000, 5, False, False),
        "Ex2STR_52_GetDataInfo": ((4, 20), "thread", 10000, 2, False, False),
        "Ex2STR_52_KeepAlive": ((4, 20), "thread", 10000, 1, False, False),
        "EX2STR_52_SendTheKey": ((4, 20), "thread", 10000, 2, False, False),
        "Ex2STR_RegMasKeyConf": (3, "direct", None, 0, False, False),
        "Ex2SMRT_32_EndEraseMode": (3, "direct", None, 0, False, False),
        "Ex2ABS_36_Change_DealerMode": (20, "thread", 10000, 0, False, False),
        "Ex2ABS_36_Change_NormalMode": (20, "thread", 10000, 0, False, False),
        "Ex2ABS_36_Motor_Deactivate": (20, "thread", 10000, 0, False, False),
        "Ex2ABS_36_Start_ECBProhibitCtrl": (20, "thread", 10000, 0, False, False),
        "Ex2ABS_36_Start_ZeroDownDrive": (20, "thread", 10000, 0, False, False),
        "Ex2ABS_36_StopRoutine": (20, "thread", 10000, 0, False, False),
        "Ex2ABS_36_Stop_ECBProhibitCtrl": (20, "thread", 10000, 0, False, False),
        "Ex2ABS_36_SupportInfo": (20, "thread", 10000, 0, False, False),
        "Ex2ABS_37_ConfirmRoutineResult": (20, "thread", 10000, 0, False, False),
        "Ex2ABS_37_ForcedActuatorRefresh": (20, "thread", 10000, 0, False, False),
        "Ex2ABS_37_ForcedActuatorRefreshStop": (20, "direct", None, 0, False, False),
        "Ex2ABS_38_AccumulatorZeroDown": (20, "thread", 10000, 1, False, False),
        "Ex2ABS_38_ECBProhibitionControl": (20, "thread", 10000, 1, False, False),
        "Ex2ABS_38_GetSupportInfo": (20, "thread", 10000, 1, False, False),
        "Ex2ABS_38_StopTheRoutine": (20, "thread", 10000, 1, False, False),
        "Ex2ABS_38_VacuumFillingFlg": (20, "thread", 10000, 2, False, False),
        "Ex2ABS_40_GetSupportInfo": (4, "thread", 10000, 0, False, False),
        "Ex2ABS_40_VSCLine_AirBleeding": (4, "thread", 10000, 2, False, False),
        "Ex2ABS_50_ConfSupportInfo": (20, "thread", 10000, 0, False, False),
        "Ex2ABS_50_ECBProhibitionControl": (20, "thread", 10000, 0, False, False),
        "Ex2ABS_50_ECBProhibitionControl_Next": (20, "thread", 10000, 0, False, False),
        "Ex2ABS_50_EndExtendedSession": (20, "thread", 10000, 0, False, False),
        "Ex2ABS_50_RearAirBleeding": (20, "thread", 10000, 1, False, False),
        "Ex2ABS_50_RearAirBleeding_Next_1": (20, "thread", 10000, 0, False, False),
        "Ex2ABS_50_RearAirBleeding_Next_2": (20, "thread", 10000, 0, False, False),
        "Ex2ABS_50_RearAirBleeding_Timeout": (20, "thread", 10000, 0, False, False),
        "Ex2ABS_50_SLM2Refresh": (20, "thread", 10000, 0, False, False),
        "Ex2ABS_50_VacuumFillingIncompleteFlagReset": (
            20,
            "thread",
            10000,
            0,
            False,
            False,
        ),
        "Ex2ABS_14_EndAirBleeding": (4, "direct", None, 0, False, False),
        "Ex2ABS_14_GetDIDSupportInfo": (4, "direct", None, 0, False, False),
        "Ex2ABS_14_StartRelayDrive": (4, "direct", None, 0, False, False),
        "Ex2ABS_14_StartSolenoidDrive": (4, "thread", 10000, 1, False, False),
        "Ex2ABS_14_StopRelayDrive": (4, "direct", None, 0, False, False),
        "Ex2ABS_14_StopSolenoidDrive_VSC": (4, "direct", None, 1, False, False),
        "Ex2ABS_03_ADSV2PDecompAirBleed": (4, "thread", 10000, 0, False, False),
        "Ex2ABS_03_ActuatorCheck": ((3, 4), "direct", None, 1, False, False),
        "Ex2ABS_05_GetDIDSupportInfo": (4, "direct", None, 2, False, False),
        "Ex2ABS_15_ChkPatternFlg": (4, "thread", 10000, 0, False, False),
        "Ex2ABS_15_EndActiveTest": (4, "direct", None, 0, False, False),
        "Ex2ABS_15_ExecuteAirBleeding": (4, "thread", 10000, 0, False, False),
        "Ex2ABS_15_GetSupportInfo": (4, "direct", None, 0, False, False),
        "Ex2ABS_15_ShiftNormalMode": (4, "direct", None, 0, False, False),
        "Ex2ABS_15_ShiftTestMode": (4, "direct", None, 0, False, False),
        "Ex2ABS_15_StartAirBleeding": (4, "direct", None, 1, False, False),
        "Ex2ABS_22_AirBleeding": (4, "thread", 10000, 0, False, False),
        "Ex2ABS_22_GetDIDSupport": (4, "direct", None, 0, False, False),
        "Ex2ABS_22_StopActiveTest": (4, "direct", None, 0, False, False),
        "Ex2ABS_25_ConfirmActivatingFlg": (4, "thread", 10000, 0, False, False),
        "Ex2ABS_25_ForcedActuatorRefresh": (4, "thread", 10000, 0, False, False),
        "Ex2ABS_25_GetSupportInfo": (4, "direct", None, 0, False, False),
        "Ex2ABS_25_StopActiveTest": (4, "direct", None, 0, False, False),
        "Ex2ABS_01_Bleed_The_Air": (4, "direct", None, 2, False, False),
        "Ex2ABS_01_Conf_typeof_AirBleeding": (4, "direct", None, 1, False, False),
        "Ex2SMRT_41_Online_Certification": (4, "thread", 10000, 9, False, False),
        "Ex2SMRT_41_Online_Certification_008": (4, "thread", 10000, 4, False, False),
        "Ex2SMRT_41_KeepAlive": (4, "thread", 10000, 2, False, False),
        "Ex2SMRT_41_SendTheKey": (4, "thread", 10000, 3, False, False),
        "Ex2SMRT_42_GetKeyNum": (4, "thread", 10000, 2, False, False),
        "Ex2SMRT_42_GetKeyStatus": (4, "thread", 10000, 2, False, False),
        "Ex2SMRT_42_GetSupportInfo": (4, "direct", None, 4, False, False),
        "Ex2SMRT_42_KeyCodeErasure": (4, "thread", 10000, 1, False, False),
        "Ex2SMRT_42_KeyCodeErasureChk": (4, "thread", 10000, 8, False, False),
        "Ex2SMRT_42_SetSupportInfo": (4, "direct", None, 4, False, False),
        "Ex2SMRT_42_TerminateKeyCodeErasure": (4, "direct", None, 0, False, False),
        "Ex2SMRT_45_GetKeyStatus_RegNormal": (4, "thread", 10000, 1, False, False),
        "Ex2SMRT_45_GetKeyStatus_StatusNormal": (4, "thread", 10000, 1, False, False),
        "Ex2SMRT_45_GetKeyStatus_WaitComp": (4, "thread", 10000, 1, False, False),
        "Ex2SMRT_45_GetSupportInfo": (4, "thread", 10000, 4, False, False),
        "Ex2SMRT_45_SetSupportInfo": (4, "direct", None, 4, False, False),
        "Ex2SMRT_45_StartOwnersKeyReg": (4, "thread", 10000, 6, False, False),
        "Ex2SMRT_45_StopOwnersKeyReg": (4, "thread", 10000, 0, False, False),
        "Ex2SMRT_46_GetKeyStatus": (4, "thread", 10000, 1, False, False),
        "Ex2SMRT_46_GetKeyStatus_RegistrationChk": (
            4,
            "thread",
            10000,
            0,
            False,
            False,
        ),
        "Ex2SMRT_46_GetSupportInfo": (4, "thread", 10000, 4, False, False),
        "Ex2SMRT_46_KeyCodeChk": (4, "thread", 10000, 6, False, False),
        "Ex2SMRT_46_SetSupportInfo": (4, "direct", None, 4, False, False),
        "Ex2SMRT_46_StopKeyCodeReset": (4, "thread", 10000, 0, False, False),
        "Ex2SMRT_47_GetKeyStatus_NomalChk": (4, "thread", 10000, 1, False, False),
        "Ex2SMRT_47_GetKeyStatus_RegistrationChk": (
            4,
            "thread",
            10000,
            0,
            False,
            False,
        ),
        "Ex2SMRT_47_GetSupportInfo": (4, "thread", 10000, 4, False, False),
        "Ex2SMRT_47_KeyCodeChk": (4, "thread", 10000, 6, False, False),
        "Ex2SMRT_47_SetSupportInfo": (4, "direct", None, 4, False, False),
        "Ex2SMRT_47_StopKeyCodeReset": (4, "thread", 10000, 0, False, False),
        "Ex2ABS_35_ConfDIDBitInfo": (20, "thread", 10000, 0, False, False),
        "Ex2ABS_35_ConfPlumbigStatus": (20, "thread", 10000, 0, False, False),
        "Ex2ABS_35_SolenoidDriving": (20, "thread", 10000, 0, False, False),
        "Ex2SMRT_48_GetSupportInfo": (4, "thread", 10000, 0, False, False),
        "Ex2SMRT_48_GetTheDigitalKeySerialNo": (4, "thread", 10000, 1, False, False),
        "Ex2SMRT_48_ReadVINCode": ((4, 20), "thread", 10000, 2, False, False),
        "Ex2SMRT_58_EndExtendedSession": (20, "thread", 10000, 0, False, False),
        "Ex2SMRT_58_StartIFBOXComIDReg": (20, "thread", 10000, 0, False, False),
        "Ex2SMRT_56_ConfirmDIDRIDSupport": (20, "thread", 10000, 0, False, False),
        "Ex2SMRT_56_EndExtendedSession": (20, "thread", 10000, 1, False, False),
        "Ex2SMRT_56_StartFingerprintMode": (20, "thread", 10000, 0, False, False),
        "Ex2SMRT_56_TerminateFingerprintMode": (20, "thread", 10000, 0, False, False),
        "Ex2SMRT_53_Online_Certification": (20, "thread", 10000, 5, False, False),
        "Ex2SMRT_53_Online_Certification_007": (20, "thread", 10000, 3, False, False),
        "Ex2SMRT_53_SendTheKey": (20, "thread", 10000, 3, False, False),
        "Ex2SMRT_50_EndExtendSession": (20, "direct", None, 0, False, False),
        "Ex2SMRT_50_GetSupportInfo": (20, "thread", 10000, 1, False, False),
        "Ex2SMRT_50_KeyCodeReset": (20, "thread", 10000, 0, False, False),
        "Ex2SMRT_50_StartKeepAlive": (20, "direct", None, 0, False, False),
        "Ex2SMRT_50_StartKeyErasure": (20, "thread", 10000, 0, False, False),
        "Ex2SMRT_63_EndExtendSession": (20, "direct", None, 0, False, False),
        "Ex2SMRT_63_GetKeyStatus": (20, "thread", 10000, 1, False, False),
        "Ex2SMRT_63_GetSupportInfo": (20, "thread", 10000, 1, False, False),
        "Ex2SMRT_63_StartKeepAlive": (20, "direct", None, 0, False, False),
        "Ex2SMRT_63_StartKeyErasure": (20, "thread", 10000, 0, False, False),
    },
    "NKPlus": {
        "Ex2SMRT_55_ConfirmDIDRIDSupport": (20, "thread", 10000, 1, False, False),
        "Ex2SMRT_55_GetKeyDiagInfo": (20, "direct", None, 0, False, False),
        "Ex2SMRT_55_CHKSupportStatus": (20, "direct", None, 2, False, False),
        "Ex2SMRT_55_SetKeyDiag": (20, "direct", None, 2, False, False),
        "Ex2SMRT_55_SetKeyDiag2": (20, "direct", None, 3, False, False),
        "Ex2SMRT_55_TermKeyDiag": (20, "direct", None, 0, False, False),
        "Ex2SMRT_55_TermKeyDiag2": (20, "direct", None, 0, False, False),
        "Ex2STR_52_GetSupportInfo": ((4, 20), "thread", 10000, 5, False, False),
        "Ex2STR_52_GetDataInfo": ((4, 20), "thread", 10000, 2, False, False),
        "Ex2STR_52_KeepAlive": ((4, 20), "thread", 10000, 1, False, False),
        "EX2STR_52_SendTheKey": ((4, 20), "thread", 10000, 2, False, False),
        "Ex2STR_RegMasKeyConf": (3, "direct", None, 0, False, False),
        "Ex2SMRT_32_EndEraseMode": (3, "direct", None, 0, False, False),
        "Ex2ABS_36_Change_DealerMode": (20, "thread", 10000, 0, False, False),
        "Ex2ABS_36_Change_NormalMode": (20, "thread", 10000, 0, False, False),
        "Ex2ABS_36_Motor_Deactivate": (20, "thread", 10000, 0, False, False),
        "Ex2ABS_36_Start_ECBProhibitCtrl": (20, "thread", 10000, 0, False, False),
        "Ex2ABS_36_Start_ZeroDownDrive": (20, "thread", 10000, 0, False, False),
        "Ex2ABS_36_StopRoutine": (20, "thread", 10000, 0, False, False),
        "Ex2ABS_36_Stop_ECBProhibitCtrl": (20, "thread", 10000, 0, False, False),
        "Ex2ABS_36_SupportInfo": (20, "thread", 10000, 0, False, False),
        "Ex2ABS_37_ConfirmRoutineResult": (20, "thread", 10000, 0, False, False),
        "Ex2ABS_37_ForcedActuatorRefresh": (20, "thread", 10000, 0, False, False),
        "Ex2ABS_37_ForcedActuatorRefreshStop": (20, "direct", None, 0, False, False),
        "Ex2ABS_38_AccumulatorZeroDown": (20, "thread", 10000, 1, False, False),
        "Ex2ABS_38_ECBProhibitionControl": (20, "thread", 10000, 1, False, False),
        "Ex2ABS_38_GetSupportInfo": (20, "thread", 10000, 1, False, False),
        "Ex2ABS_38_StopTheRoutine": (20, "thread", 10000, 1, False, False),
        "Ex2ABS_38_VacuumFillingFlg": (20, "thread", 10000, 2, False, False),
        "Ex2ABS_40_GetSupportInfo": (4, "thread", 10000, 0, False, False),
        "Ex2ABS_40_VSCLine_AirBleeding": (4, "thread", 10000, 2, False, False),
        "Ex2ABS_50_ConfSupportInfo": (20, "thread", 10000, 0, False, False),
        "Ex2ABS_50_ECBProhibitionControl": ((20, 22), "thread", 10000, 0, False, False),
        "Ex2ABS_50_ECBProhibitionControl_Next": (
            (20, 22),
            "thread",
            10000,
            0,
            False,
            False,
        ),
        "Ex2ABS_50_EndExtendedSession": ((20, 22), "thread", 10000, 0, False, False),
        "Ex2ABS_50_RearAirBleeding": ((20, 22), "thread", 10000, 1, False, False),
        "Ex2ABS_50_RearAirBleeding_Next_1": (
            (20, 22),
            "thread",
            10000,
            0,
            False,
            False,
        ),
        "Ex2ABS_50_RearAirBleeding_Next_2": (
            (20, 22),
            "thread",
            10000,
            0,
            False,
            False,
        ),
        "Ex2ABS_50_RearAirBleeding_Timeout": (
            (20, 22),
            "thread",
            10000,
            0,
            False,
            False,
        ),
        "Ex2ABS_50_SLM2Refresh": ((20, 22), "thread", 10000, 0, False, False),
        "Ex2ABS_50_VacuumFillingIncompleteFlagReset": (
            (20, 22),
            "thread",
            10000,
            0,
            False,
            False,
        ),
        "Ex2ABS_14_EndAirBleeding": (4, "direct", None, 0, False, False),
        "Ex2ABS_14_GetDIDSupportInfo": (4, "direct", None, 0, False, False),
        "Ex2ABS_14_StartRelayDrive": (4, "direct", None, 0, False, False),
        "Ex2ABS_14_StartSolenoidDrive": (4, "thread", 10000, 1, False, False),
        "Ex2ABS_14_StopRelayDrive": (4, "direct", None, 0, False, False),
        "Ex2ABS_14_StopSolenoidDrive_VSC": (4, "direct", None, 1, False, False),
        "Ex2ABS_03_ADSV2PDecompAirBleed": (4, "thread", 10000, 0, False, False),
        "Ex2ABS_03_ActuatorCheck": ((3, 4), "direct", None, 1, False, False),
        "Ex2ABS_05_GetDIDSupportInfo": (4, "direct", None, 2, False, False),
        "Ex2ABS_15_ChkPatternFlg": (4, "thread", 10000, 0, False, False),
        "Ex2ABS_15_EndActiveTest": (4, "direct", None, 0, False, False),
        "Ex2ABS_15_ExecuteAirBleeding": (4, "thread", 10000, 0, False, False),
        "Ex2ABS_15_GetSupportInfo": (4, "direct", None, 0, False, False),
        "Ex2ABS_15_ShiftNormalMode": (4, "direct", None, 0, False, False),
        "Ex2ABS_15_ShiftTestMode": (4, "direct", None, 0, False, False),
        "Ex2ABS_15_StartAirBleeding": (4, "direct", None, 1, False, False),
        "Ex2ABS_22_AirBleeding": (4, "thread", 10000, 0, False, False),
        "Ex2ABS_22_GetDIDSupport": (4, "direct", None, 0, False, False),
        "Ex2ABS_22_StopActiveTest": (4, "direct", None, 0, False, False),
        "Ex2ABS_25_ConfirmActivatingFlg": (4, "thread", 10000, 0, False, False),
        "Ex2ABS_25_ForcedActuatorRefresh": (4, "thread", 10000, 0, False, False),
        "Ex2ABS_25_GetSupportInfo": (4, "direct", None, 0, False, False),
        "Ex2ABS_25_StopActiveTest": (4, "direct", None, 0, False, False),
        "Ex2ABS_01_Bleed_The_Air": (4, "direct", None, 2, False, False),
        "Ex2ABS_01_Conf_typeof_AirBleeding": (4, "direct", None, 1, False, False),
        "Ex2SMRT_41_Online_Certification": (4, "thread", 10000, 9, False, False),
        "Ex2SMRT_41_Online_Certification_008": (4, "thread", 10000, 4, False, False),
        "Ex2SMRT_41_KeepAlive": (4, "thread", 10000, 2, False, False),
        "Ex2SMRT_41_SendTheKey": (4, "thread", 10000, 3, False, False),
        "Ex2SMRT_42_GetKeyNum": (4, "thread", 10000, 2, False, False),
        "Ex2SMRT_42_GetKeyStatus": (4, "thread", 10000, 2, False, False),
        "Ex2SMRT_42_GetSupportInfo": (4, "direct", None, 4, False, False),
        "Ex2SMRT_42_KeyCodeErasure": (4, "thread", 10000, 1, False, False),
        "Ex2SMRT_42_KeyCodeErasureChk": (4, "thread", 10000, 8, False, False),
        "Ex2SMRT_42_SetSupportInfo": (4, "direct", None, 4, False, False),
        "Ex2SMRT_42_TerminateKeyCodeErasure": (4, "direct", None, 0, False, False),
        "Ex2SMRT_45_GetKeyStatus_RegNormal": (4, "thread", 10000, 1, False, False),
        "Ex2SMRT_45_GetKeyStatus_StatusNormal": (4, "thread", 10000, 1, False, False),
        "Ex2SMRT_45_GetKeyStatus_WaitComp": (4, "thread", 10000, 1, False, False),
        "Ex2SMRT_45_GetSupportInfo": (4, "thread", 10000, 4, False, False),
        "Ex2SMRT_45_SetSupportInfo": (4, "direct", None, 4, False, False),
        "Ex2SMRT_45_StartOwnersKeyReg": (4, "thread", 10000, 6, False, False),
        "Ex2SMRT_45_StopOwnersKeyReg": (4, "thread", 10000, 0, False, False),
        "Ex2SMRT_46_GetKeyStatus": (4, "thread", 10000, 1, False, False),
        "Ex2SMRT_46_GetKeyStatus_RegistrationChk": (
            4,
            "thread",
            10000,
            0,
            False,
            False,
        ),
        "Ex2SMRT_46_GetSupportInfo": (4, "thread", 10000, 4, False, False),
        "Ex2SMRT_46_KeyCodeChk": (4, "thread", 10000, 6, False, False),
        "Ex2SMRT_46_SetSupportInfo": (4, "direct", None, 4, False, False),
        "Ex2SMRT_46_StopKeyCodeReset": (4, "thread", 10000, 0, False, False),
        "Ex2SMRT_47_GetKeyStatus_NomalChk": (4, "thread", 10000, 1, False, False),
        "Ex2SMRT_47_GetKeyStatus_RegistrationChk": (
            4,
            "thread",
            10000,
            0,
            False,
            False,
        ),
        "Ex2SMRT_47_GetSupportInfo": (4, "thread", 10000, 4, False, False),
        "Ex2SMRT_47_KeyCodeChk": (4, "thread", 10000, 6, False, False),
        "Ex2SMRT_47_SetSupportInfo": (4, "direct", None, 4, False, False),
        "Ex2SMRT_47_StopKeyCodeReset": (4, "thread", 10000, 0, False, False),
        "Ex2ABS_35_ConfDIDBitInfo": (20, "thread", 10000, 0, False, False),
        "Ex2ABS_35_ConfPlumbigStatus": (20, "thread", 10000, 0, False, False),
        "Ex2ABS_35_SolenoidDriving": (20, "thread", 10000, 0, False, False),
        "Ex2SMRT_48_GetSupportInfo": (4, "thread", 10000, 0, False, False),
        "Ex2SMRT_48_GetTheDigitalKeySerialNo": (4, "thread", 10000, 1, False, False),
        "Ex2SMRT_48_ReadVINCode": ((4, 20), "thread", 10000, 2, False, False),
        "Ex2SMRT_58_EndExtendedSession": (20, "thread", 10000, 0, False, False),
        "Ex2SMRT_58_StartIFBOXComIDReg": (20, "thread", 10000, 0, False, False),
        "Ex2SMRT_56_ConfirmDIDRIDSupport": (20, "thread", 10000, 0, False, False),
        "Ex2SMRT_56_EndExtendedSession": (20, "thread", 10000, 1, False, False),
        "Ex2SMRT_56_StartFingerprintMode": (20, "thread", 10000, 0, False, False),
        "Ex2SMRT_56_TerminateFingerprintMode": (20, "thread", 10000, 0, False, False),
        "Ex2SMRT_53_Online_Certification": (20, "thread", 10000, 5, False, False),
        "Ex2SMRT_53_Online_Certification_007": (20, "thread", 10000, 3, False, False),
        "Ex2SMRT_53_SendTheKey": (20, "thread", 10000, 3, False, False),
        "Ex2SMRT_50_EndExtendSession": (20, "direct", None, 0, False, False),
        "Ex2SMRT_50_GetSupportInfo": (20, "thread", 10000, 1, False, False),
        "Ex2SMRT_50_KeyCodeReset": (20, "thread", 10000, 0, False, False),
        "Ex2SMRT_50_StartKeepAlive": (20, "direct", None, 0, False, False),
        "Ex2SMRT_50_StartKeyErasure": (20, "thread", 10000, 0, False, False),
        "Ex2SMRT_63_EndExtendSession": (20, "direct", None, 0, False, False),
        "Ex2SMRT_63_GetKeyStatus": (20, "thread", 10000, 1, False, False),
        "Ex2SMRT_63_GetSupportInfo": (20, "thread", 10000, 1, False, False),
        "Ex2SMRT_63_StartKeepAlive": (20, "direct", None, 0, False, False),
        "Ex2SMRT_63_StartKeyErasure": (20, "thread", 10000, 0, False, False),
    },
    "NK18": {
        "Ex2SMRT_55_ConfirmDIDRIDSupport": (20, "thread", 10000, 1, False, False),
        "Ex2SMRT_55_GetKeyDiagInfo": (20, "direct", None, 0, False, False),
        "Ex2SMRT_55_CHKSupportStatus": (20, "direct", None, 2, False, False),
        "Ex2SMRT_55_SetKeyDiag": (20, "direct", None, 2, False, False),
        "Ex2SMRT_55_SetKeyDiag2": (20, "direct", None, 3, False, False),
        "Ex2SMRT_55_TermKeyDiag": (20, "direct", None, 0, False, False),
        "Ex2SMRT_55_TermKeyDiag2": (20, "direct", None, 0, False, False),
        "Ex2STR_52_GetSupportInfo": ((4, 20), "thread", 10000, 5, False, False),
        "Ex2STR_52_GetDataInfo": ((4, 20), "thread", 10000, 2, False, False),
        "Ex2STR_52_KeepAlive": ((4, 20), "thread", 10000, 1, False, False),
        "EX2STR_52_SendTheKey": ((4, 20), "thread", 10000, 2, False, False),
        "Ex2ABS_36_SupportInfo": (20, "thread", 10000, 0, False, False),
        "Ex2ABS_36_Start_ECBProhibitCtrl": (20, "thread", 10000, 0, False, False),
        "Ex2ABS_36_Stop_ECBProhibitCtrl": (20, "thread", 10000, 0, False, False),
        "Ex2ABS_36_Start_ZeroDownDrive": (20, "thread", 10000, 0, False, False),
        "Ex2ABS_36_Change_DealerMode": (20, "thread", 10000, 0, False, False),
        "Ex2ABS_36_Change_NormalMode": (20, "thread", 10000, 0, False, False),
        "Ex2ABS_36_Motor_Deactivate": (20, "thread", 10000, 0, False, False),
        "Ex2ABS_36_StopRoutine": (20, "thread", 10000, 0, False, False),
        "Ex2ABS_37_ForcedActuatorRefresh": (20, "thread", 10000, 0, False, False),
        "Ex2ABS_37_ForcedActuatorRefreshStop": (20, "direct", None, 0, False, False),
        "Ex2ABS_37_ConfirmRoutineResult": (20, "thread", 10000, 0, False, False),
        "Ex2ABS_38_GetSupportInfo": (20, "thread", 10000, 1, False, False),
        "Ex2ABS_38_ECBProhibitionControl": (20, "thread", 10000, 1, False, False),
        "Ex2ABS_38_VacuumFillingFlg": (20, "thread", 10000, 2, False, False),
        "Ex2ABS_38_AccumulatorZeroDown": (20, "thread", 10000, 1, False, False),
        "Ex2ABS_38_StopTheRoutine": (20, "thread", 10000, 1, False, False),
        "Ex2ABS_40_GetSupportInfo": (4, "thread", 10000, 0, False, False),
        "Ex2ABS_40_VSCLine_AirBleeding": (4, "thread", 10000, 2, False, False),
        "Ex2ABS_50_ConfSupportInfo": (20, "thread", 10000, 0, False, False),
        "Ex2ABS_50_RearAirBleeding": (20, "thread", 10000, 1, False, False),
        "Ex2ABS_50_RearAirBleeding_Next_1": (20, "thread", 10000, 0, False, False),
        "Ex2ABS_50_RearAirBleeding_Next_2": (20, "thread", 10000, 0, False, False),
        "Ex2ABS_50_RearAirBleeding_Timeout": (20, "thread", 10000, 0, False, False),
        "Ex2ABS_50_ECBProhibitionControl": (20, "thread", 10000, 0, False, False),
        "Ex2ABS_50_ECBProhibitionControl_Next": (20, "thread", 10000, 0, False, False),
        "Ex2ABS_50_SLM2Refresh": (20, "thread", 10000, 0, False, False),
        "Ex2ABS_50_VacuumFillingIncompleteFlagReset": (
            20,
            "thread",
            10000,
            0,
            False,
            False,
        ),
        "Ex2ABS_50_EndExtendedSession": (20, "thread", 10000, 0, False, False),
        "Ex2ABS_14_GetDIDSupportInfo": (4, "direct", None, 0, False, False),
        "Ex2ABS_14_StartSolenoidDrive": (4, "thread", 10000, 1, False, False),
        "Ex2ABS_14_StopSolenoidDrive_VSC": (4, "direct", None, 1, False, False),
        "Ex2ABS_14_StartRelayDrive": (4, "direct", None, 0, False, False),
        "Ex2ABS_14_StopRelayDrive": (4, "direct", None, 0, False, False),
        "Ex2ABS_14_EndAirBleeding": (4, "direct", None, 0, False, False),
        "Ex2ABS_03_ADSV2PDecompAirBleed": (4, "thread", 10000, 0, False, False),
        "Ex2ABS_03_ActuatorCheck": ((3, 4), "direct", None, 1, False, False),
        "Ex2ABS_05_GetDIDSupportInfo": (4, "direct", None, 2, False, False),
        "Ex2ABS_15_GetSupportInfo": (4, "direct", None, 0, False, False),
        "Ex2ABS_15_StartAirBleeding": (4, "direct", None, 1, False, False),
        "Ex2ABS_15_ChkPatternFlg": (4, "thread", 10000, 0, False, False),
        "Ex2ABS_15_ExecuteAirBleeding": (4, "thread", 10000, 0, False, False),
        "Ex2ABS_15_EndActiveTest": (4, "direct", None, 0, False, False),
        "Ex2ABS_15_ShiftTestMode": (4, "direct", None, 0, False, False),
        "Ex2ABS_15_ShiftNormalMode": (4, "direct", None, 0, False, False),
        "Ex2ABS_22_GetDIDSupport": (4, "direct", None, 0, False, False),
        "Ex2ABS_22_AirBleeding": (4, "thread", 10000, 0, False, False),
        "Ex2ABS_22_StopActiveTest": (4, "direct", None, 0, False, False),
        "Ex2ABS_25_GetSupportInfo": (4, "direct", None, 0, False, False),
        "Ex2ABS_25_ForcedActuatorRefresh": (4, "thread", 10000, 0, False, False),
        "Ex2ABS_25_ConfirmActivatingFlg": (4, "thread", 10000, 0, False, False),
        "Ex2ABS_25_StopActiveTest": (4, "direct", None, 0, False, False),
        "Ex2ABS_01_Conf_typeof_AirBleeding": (4, "direct", None, 1, False, False),
        "Ex2ABS_01_Bleed_The_Air": (4, "direct", None, 2, False, False),
        "Ex2SMRT_41_Online_Certification": (4, "thread", 10000, 9, False, False),
        "Ex2SMRT_41_Online_Certification_008": (4, "thread", 10000, 4, False, False),
        "Ex2SMRT_41_KeepAlive": (4, "thread", 10000, 2, False, False),
        "Ex2SMRT_41_SendTheKey": (4, "thread", 10000, 3, False, False),
        "Ex2SMRT_42_GetSupportInfo": (4, "direct", None, 4, False, False),
        "Ex2SMRT_42_GetKeyNum": (4, "thread", 10000, 2, False, False),
        "Ex2SMRT_42_KeyCodeErasureChk": (4, "thread", 10000, 8, False, False),
        "Ex2SMRT_42_GetKeyStatus": (4, "thread", 10000, 2, False, False),
        "Ex2SMRT_42_KeyCodeErasure": (4, "thread", 10000, 1, False, False),
        "Ex2SMRT_42_TerminateKeyCodeErasure": (4, "direct", None, 0, False, False),
        "Ex2SMRT_42_SetSupportInfo": (4, "direct", None, 4, False, False),
        "Ex2SMRT_45_GetSupportInfo": (4, "thread", 10000, 4, False, False),
        "Ex2SMRT_45_SetSupportInfo": (4, "direct", None, 4, False, False),
        "Ex2SMRT_45_StartOwnersKeyReg": (4, "thread", 10000, 6, False, False),
        "Ex2SMRT_45_GetKeyStatus_StatusNormal": (4, "thread", 10000, 1, False, False),
        "Ex2SMRT_45_GetKeyStatus_WaitComp": (4, "thread", 10000, 1, False, False),
        "Ex2SMRT_45_GetKeyStatus_RegNormal": (4, "thread", 10000, 1, False, False),
        "Ex2SMRT_45_StopOwnersKeyReg": (4, "thread", 10000, 0, False, False),
        "Ex2SMRT_46_GetSupportInfo": (4, "thread", 10000, 4, False, False),
        "Ex2SMRT_46_SetSupportInfo": (4, "direct", None, 4, False, False),
        "Ex2SMRT_46_KeyCodeChk": (4, "thread", 10000, 6, False, False),
        "Ex2SMRT_46_GetKeyStatus": (4, "thread", 10000, 1, False, False),
        "Ex2SMRT_46_GetKeyStatus_RegistrationChk": (
            4,
            "thread",
            10000,
            0,
            False,
            False,
        ),
        "Ex2SMRT_46_StopKeyCodeReset": (4, "thread", 10000, 0, False, False),
        "Ex2SMRT_47_GetSupportInfo": (4, "thread", 10000, 4, False, False),
        "Ex2SMRT_47_SetSupportInfo": (4, "direct", None, 4, False, False),
        "Ex2SMRT_47_KeyCodeChk": (4, "thread", 10000, 6, False, False),
        "Ex2SMRT_47_GetKeyStatus_NomalChk": (4, "thread", 10000, 1, False, False),
        "Ex2SMRT_47_GetKeyStatus_RegistrationChk": (
            4,
            "thread",
            10000,
            0,
            False,
            False,
        ),
        "Ex2SMRT_47_StopKeyCodeReset": (4, "thread", 10000, 0, False, False),
        "Ex2ABS_35_ConfDIDBitInfo": (20, "thread", 10000, 0, False, False),
        "Ex2ABS_35_ConfPlumbigStatus": (20, "thread", 10000, 0, False, False),
        "Ex2ABS_35_SolenoidDriving": (20, "thread", 10000, 0, False, False),
        "Ex2SMRT_48_GetSupportInfo": (4, "thread", 10000, 0, False, False),
        "Ex2SMRT_48_ReadVINCode": ((4, 20), "thread", 10000, 2, False, False),
        "Ex2SMRT_48_GetTheDigitalKeySerialNo": (4, "thread", 10000, 1, False, False),
        "Ex2SMRT_58_StartIFBOXComIDReg": (20, "thread", 10000, 0, False, False),
        "Ex2SMRT_58_EndExtendedSession": (20, "thread", 10000, 0, False, False),
        "Ex2SMRT_56_ConfirmDIDRIDSupport": (20, "thread", 10000, 0, False, False),
        "Ex2SMRT_56_StartFingerprintMode": (20, "thread", 10000, 0, False, False),
        "Ex2SMRT_56_TerminateFingerprintMode": (20, "thread", 10000, 0, False, False),
        "Ex2SMRT_56_EndExtendedSession": (20, "thread", 10000, 1, False, False),
        "Ex2SMRT_53_Online_Certification": (20, "thread", 10000, 5, False, False),
        "Ex2SMRT_53_Online_Certification_007": (20, "thread", 10000, 3, False, False),
        "Ex2SMRT_53_SendTheKey": (20, "thread", 10000, 3, False, False),
        "Ex2SMRT_50_GetSupportInfo": (20, "thread", 10000, 1, False, False),
        "Ex2SMRT_50_StartKeyErasure": (20, "thread", 10000, 0, False, False),
        "Ex2SMRT_50_KeyCodeReset": (20, "thread", 10000, 0, False, False),
        "Ex2SMRT_50_EndExtendSession": (20, "direct", None, 0, False, False),
        "Ex2SMRT_50_StartKeepAlive": (20, "direct", None, 0, False, False),
        "Ex2SMRT_63_EndExtendSession": (20, "direct", None, 0, False, False),
        "Ex2SMRT_63_GetKeyStatus": (20, "thread", 10000, 1, False, False),
        "Ex2SMRT_63_GetSupportInfo": (20, "thread", 10000, 1, False, False),
        "Ex2SMRT_63_StartKeepAlive": (20, "direct", None, 0, False, False),
        "Ex2SMRT_63_StartKeyErasure": (20, "thread", 10000, 0, False, False),
    },
    "NK12": {
        "Ex2STR_52_GetSupportInfo": (4, "thread", 10000, 5, False, False),
        "Ex2STR_52_GetDataInfo": (4, "thread", 10000, 2, False, False),
        "Ex2STR_52_KeepAlive": (4, "thread", 10000, 1, False, False),
        "EX2STR_52_SendTheKey": (4, "thread", 10000, 2, False, False),
        "Ex2ABS_14_GetDIDSupportInfo": (4, "direct", None, 0, False, False),
        "Ex2ABS_14_StartSolenoidDrive": (4, "thread", 10000, 1, False, False),
        "Ex2ABS_14_StopSolenoidDrive_VSC": (4, "direct", None, 1, False, False),
        "Ex2ABS_14_StartRelayDrive": (4, "direct", None, 0, False, False),
        "Ex2ABS_14_StopRelayDrive": (4, "direct", None, 0, False, False),
        "Ex2ABS_14_EndAirBleeding": (4, "direct", None, 0, False, False),
        "Ex2ABS_03_ADSV2PDecompAirBleed": (4, "thread", 10000, 0, False, False),
        "Ex2ABS_03_ActuatorCheck": ((3, 4), "direct", None, 1, False, False),
        "Ex2ABS_05_GetDIDSupportInfo": (4, "direct", None, 2, False, False),
        "Ex2ABS_15_GetSupportInfo": (4, "direct", None, 0, False, False),
        "Ex2ABS_15_StartAirBleeding": (4, "direct", None, 1, False, False),
        "Ex2ABS_15_ChkPatternFlg": (4, "thread", 10000, 0, False, False),
        "Ex2ABS_15_ExecuteAirBleeding": (4, "thread", 10000, 0, False, False),
        "Ex2ABS_15_EndActiveTest": (4, "direct", None, 0, False, False),
        "Ex2ABS_15_ShiftTestMode": (4, "direct", None, 0, False, False),
        "Ex2ABS_15_ShiftNormalMode": (4, "direct", None, 0, False, False),
        "Ex2ABS_22_GetDIDSupport": (4, "direct", None, 0, False, False),
        "Ex2ABS_22_AirBleeding": (4, "thread", 10000, 0, False, False),
        "Ex2ABS_22_StopActiveTest": (4, "direct", None, 0, False, False),
        "Ex2ABS_25_GetSupportInfo": (4, "direct", None, 0, False, False),
        "Ex2ABS_25_ForcedActuatorRefresh": (4, "thread", 10000, 0, False, False),
        "Ex2ABS_25_ConfirmActivatingFlg": (4, "thread", 10000, 0, False, False),
        "Ex2ABS_25_StopActiveTest": (4, "direct", None, 0, False, False),
        "Ex2ABS_01_Conf_typeof_AirBleeding": (4, "direct", None, 1, False, False),
        "Ex2ABS_01_Bleed_The_Air": (4, "direct", None, 2, False, False),
        "Ex2SMRT_41_Online_Certification": (4, "thread", 10000, 9, False, False),
        "Ex2SMRT_41_Online_Certification_008": (4, "thread", 10000, 4, False, False),
        "Ex2SMRT_41_KeepAlive": (4, "thread", 10000, 2, False, False),
        "Ex2SMRT_41_SendTheKey": (4, "thread", 10000, 3, False, False),
        "Ex2SMRT_42_GetSupportInfo": (4, "direct", None, 4, False, False),
        "Ex2SMRT_42_GetKeyNum": (4, "thread", 10000, 2, False, False),
        "Ex2SMRT_42_KeyCodeErasureChk": (4, "thread", 10000, 8, False, False),
        "Ex2SMRT_42_GetKeyStatus": (4, "thread", 10000, 2, False, False),
        "Ex2SMRT_42_KeyCodeErasure": (4, "thread", 10000, 1, False, False),
        "Ex2SMRT_42_TerminateKeyCodeErasure": (4, "direct", None, 0, False, False),
        "Ex2SMRT_42_SetSupportInfo": (4, "direct", None, 4, False, False),
    },
}

_TY_MODE_OVERRIDES = {
    ("TY12", "Ex2IG_01_DisableAutoPowerOffFunc"): (4,),
    ("TY18", "Ex2IG_01_DisableAutoPowerOffFunc"): (4,),
    ("TYPlus", "Ex2GWY_02_TimeoutInit"): (20, 21, 22),
    ("TYPlus", "Ex2IG_02_SendMessage"): (20, 21, 22),
    ("TYPlus", "Ex2IG_01_DisableAutoPowerOffFunc"): (4,),
    ("TY12", "Ex2MSW_01_SendMessage"): (4,),
    ("TY12", "Ex2DMOT_01_SendMessage"): (4,),
    ("TY12", "Ex2EV_02_SendMessage"): (4,),
    ("TY18", "Ex2MSW_01_SendMessage"): (4,),
    ("TY18", "Ex2DMOT_01_SendMessage"): (4,),
    ("TY18", "Ex2EV_02_SendMessage"): (4,),
    ("TYPlus", "Ex2MSW_01_SendMessage"): (4,),
    ("TYPlus", "Ex2DMOT_01_SendMessage"): (4,),
    ("TYPlus", "Ex2EV_02_SendMessage"): (4,),
    ("TY18", "Ex2MS2MM_01_SendMessage"): (52,),
    ("TY18", "Ex2MS2BSRL_01_SendMessage"): (52,),
    ("TYPlus", "Ex2MS2MM_01_SendMessage"): (52,),
    ("TYPlus", "Ex2MS2BSRL_01_SendMessage"): (52,),
    ("TY18", "Ex2FCHV_04_SendMessage"): (4, 20, 21),
    ("TYPlus", "Ex2FCHV_04_SendMessage"): (4, 20, 21),
    ("TY18", "Ex2MS2ABS_01_SendMessage"): (52,),
    ("TYPlus", "Ex2MS2ABS_01_SendMessage"): (52,),
    ("TY18", "Ex2MS2ABS_02_SendMessage"): (52,),
    ("TYPlus", "Ex2MS2ABS_02_SendMessage"): (52,),
    ("TY18", "Ex2MS2ABS_03_SendMessage"): (52,),
    ("TYPlus", "Ex2MS2ABS_03_SendMessage"): (52,),
    ("TY18", "Ex2MS2ABS_05_SendMessage"): (52,),
    ("TYPlus", "Ex2MS2ABS_05_SendMessage"): (52,),
    ("TY18", "Ex2MS2EFI_01_SendMessage"): (52,),
    ("TYPlus", "Ex2MS2EFI_01_SendMessage"): (52,),
    ("TY18", "Ex2MS2EFI_02_SendMessage"): (52,),
    ("TYPlus", "Ex2MS2EFI_02_SendMessage"): (52,),
    ("TY18", "Ex2MS2GWY_01_SendMessage"): (52,),
    ("TYPlus", "Ex2MS2GWY_01_SendMessage"): (52,),
    ("TY18", "Ex2MS2PWD_01_SendMessage"): (52,),
    ("TYPlus", "Ex2MS2PWD_01_SendMessage"): (52,),
    ("TY18", "Ex2MS2PWD_02_SendMessage"): (52,),
    ("TYPlus", "Ex2MS2PWD_02_SendMessage"): (52,),
    ("TY12", "Ex2PSAECD_03_RequestResetECU"): (19,),
    ("TY12", "Ex2PSAEFI_01_SendMessage"): (19,),
    ("TY12", "Ex2PSAECD_01_ReadTempWater"): (19,),
    ("TY12", "Ex2PSAECT_01_InitializeECU"): (19,),
    ("TY12", "Ex2PSAECT_01_ReadOilUsageCnt"): (19,),
    ("TY12", "Ex2PSAECT_01_WriteOilUsageCnt"): (19,),
    ("TY12", "Ex2PSADSG_01_ReadWheelIdentifires"): (19,),
    ("TY12", "Ex2PSADSG_02_ReadWheelIdentifires"): (19,),
    ("TY12", "Ex2PSADSG_01_ClearWheelIdentifires"): (19,),
    ("TY12", "Ex2PSADSG_04_ValveProgramCheck"): (19,),
    ("TY12", "Ex2PSADSG_02_WriteMainWheelIdentifires"): (19,),
    ("TY12", "Ex2PSADSG_02_WriteAdditionalWheelIdentifires"): (19,),
    ("TY12", "Ex2PSADSG_03_StartWheelTransmitter"): (19,),
    ("TY18", "Ex2PSAECD_03_RequestResetECU"): (19,),
    ("TY18", "Ex2PSAEFI_01_SendMessage"): (19,),
    ("TY18", "Ex2PSAECD_01_ReadTempWater"): (19,),
    ("TY18", "Ex2PSAECT_01_InitializeECU"): (19,),
    ("TY18", "Ex2PSAECT_01_ReadOilUsageCnt"): (19,),
    ("TY18", "Ex2PSAECT_01_WriteOilUsageCnt"): (19,),
    ("TY18", "Ex2PSADSG_01_ReadWheelIdentifires"): (19,),
    ("TY18", "Ex2PSADSG_02_ReadWheelIdentifires"): (19,),
    ("TY18", "Ex2PSADSG_01_ClearWheelIdentifires"): (19,),
    ("TY18", "Ex2PSADSG_04_ValveProgramCheck"): (19,),
    ("TY18", "Ex2PSADSG_02_WriteMainWheelIdentifires"): (19,),
    ("TY18", "Ex2PSADSG_02_WriteAdditionalWheelIdentifires"): (19,),
    ("TY18", "Ex2PSADSG_03_StartWheelTransmitter"): (19,),
    ("TY18", "Ex2MS2EFI_04_SendMessage"): (52,),
    ("TYPlus", "Ex2MS2EFI_04_SendMessage"): (52,),
    ("TY18", "Ex2ABS_17_SupportCheck"): (4,),
    ("TY12", "Ex2ABS_17_SupportCheck"): (4,),
    ("TYPlus", "Ex2ABS_17_SupportCheck"): (4,),
    ("TY18", "Ex2ABS_17_GetABSInfo"): (4,),
    ("TY12", "Ex2ABS_17_GetABSInfo"): (4,),
    ("TYPlus", "Ex2ABS_17_GetABSInfo"): (4,),
    ("TY18", "Ex2ABS_17_SychronizingABSInfo"): (4,),
    ("TY12", "Ex2ABS_17_SychronizingABSInfo"): (4,),
    ("TYPlus", "Ex2ABS_17_SychronizingABSInfo"): (4,),
    ("TY18", "Ex2ABS_18_SupportCheck"): (4,),
    ("TY12", "Ex2ABS_18_SupportCheck"): (4,),
    ("TYPlus", "Ex2ABS_18_SupportCheck"): (4,),
    ("TY18", "Ex2ABS_18_SetNeutralPos"): (4,),
    ("TY12", "Ex2ABS_18_SetNeutralPos"): (4,),
    ("TYPlus", "Ex2ABS_18_SetNeutralPos"): (4,),
    ("TY18", "Ex2ABS_21_SupportCheck"): (4,),
    ("TY12", "Ex2ABS_21_SupportCheck"): (4,),
    ("TYPlus", "Ex2ABS_21_SupportCheck"): (4,),
    ("TY18", "Ex2ABS_21_ChangeMode"): (4,),
    ("TY12", "Ex2ABS_21_ChangeMode"): (4,),
    ("TYPlus", "Ex2ABS_21_ChangeMode"): (4,),
    ("TY18", "Ex2ABS_21_CheckSensorStatus"): (4,),
    ("TY12", "Ex2ABS_21_CheckSensorStatus"): (4,),
    ("TYPlus", "Ex2ABS_21_CheckSensorStatus"): (4,),
    ("TYPlus", "Ex2ABS_48_RetrunWait"): (20, 21, 22),
    ("TY18", "Ex2ASUS_04_SupportCheck"): (4,),
    ("TY18", "Ex2ASUS_04_ModifyVhight"): (4,),
    ("TY18", "Ex2ASUS_04_ReturnVhight"): (4,),
    ("TY18", "Ex2ASUS_04_LearnKneeldownVheight"): (4,),
    ("TY18", "Ex2ASUS_04_CheckReturnedVhight"): (4,),
    ("TY18", "Ex2ASUS_05_SupportCheck"): (4,),
    ("TY18", "Ex2ASUS_05_ModifyVheightDownStart"): (4,),
    ("TY18", "Ex2ASUS_05_ModifyVheightStop"): (4,),
    ("TY18", "Ex2ASUS_05_CheckModifiedVheight"): (4,),
    ("TY18", "Ex2ASUS_05_ModifyVheightTimeOver"): (4,),
    ("TY18", "Ex2ASUS_05_LearnKneelDownVheight"): (4,),
    ("TY18", "Ex2ASUS_05_ReturnVheightStart"): (4,),
    ("TY18", "Ex2ASUS_05_CheckReturnedVheight"): (4,),
    ("TY18", "Ex2ASUS_13_SupportCheck"): (4,),
    ("TY18", "Ex2ASUS_13_TestStart"): (4,),
    ("TYPlus", "Ex2ASUS_13_TestStart"): (4,),
    ("TY18", "Ex2ASUS_13_GetHeight"): (4,),
    ("TYPlus", "Ex2ASUS_13_GetHeight"): (4,),
    ("TY18", "Ex2ASUS_13_NormalMode"): (4,),
    ("TYPlus", "Ex2ASUS_13_NormalMode"): (4,),
    ("TY18", "Ex2ASUS_13_NormalMode005"): (4,),
    ("TYPlus", "Ex2ASUS_13_NormalMode005"): (4,),
    ("TY18", "Ex2ASUS_13_NormalMode008"): (4,),
    ("TYPlus", "Ex2ASUS_13_NormalMode008"): (4,),
    ("TY18", "Ex2ASUS_13_HeightOffset"): (4,),
    ("TYPlus", "Ex2ASUS_13_HeightOffset"): (4,),
    ("TY18", "Ex2ASUS_13_TestStop"): (4,),
    ("TYPlus", "Ex2ASUS_13_TestStop"): (4,),
    ("TY18", "Ex2ASUS_13_GetHeightSec50"): (4,),
    ("TYPlus", "Ex2ASUS_13_GetHeightSec50"): (4,),
    ("TY18", "Ex2BSM_01_02_SupportCheck"): (4,),
    ("TY18", "Ex2BSM_01_02_Mov2TestMode"): (4,),
    ("TY18", "Ex2BSM_01_02_ChkStilInTestMode"): (4,),
    ("TY18", "Ex2BSM_01_02_ExitTestMode"): (4,),
    ("TY18", "Ex2BSM_07_08_SupportCheck"): (4,),
    ("TY18", "Ex2BSM_07_08_GetAbnormalHistory"): (4,),
    ("TY18", "Ex2BSM_07_08_ClearAbnormalHistory"): (4,),
    ("TY18", "Ex2BSM_03_04_SupportCheck"): (4,),
    ("TY18", "Ex2BSM_03_04_ActiveTest"): (4,),
    ("TY18", "Ex2BSM_03_04_ActiveTestCon3_5"): (4,),
    ("TY18", "Ex2BSM_05_06_SupportCheck"): (4,),
    ("TY18", "Ex2BSM_05_06_ActiveTest"): (4,),
    ("TY18", "Ex2BSM_27_SendMessage"): (4,),
    ("TY18", "Ex2BSM_28_SendMessage"): (4,),
    ("TY18", "Ex2ARS_01_A8SupportCheck"): (4,),
    ("TY18", "Ex2ARS_01_ReadDTCofVGRS"): (4,),
    ("TY18", "Ex2ARS_01_ClearOffSetValue"): (4,),
    ("TY18", "Ex2ARS_01_ReadDTCofARS"): (4,),
    ("TY18", "Ex2ARS_01_ReturnActuatorCenterPos"): (4,),
    ("TY18", "Ex2ARS_02_SupportCheck"): (4,),
    ("TY18", "Ex2ARS_02_ChkVGRSDtc"): (4,),
    ("TY18", "Ex2ARS_02_ClrCompVal"): (4,),
    ("TY18", "Ex2ARS_02_ChkARSDtc"): (4,),
    ("TY18", "Ex2ARS_02_InitCompVal"): (4,),
    ("TY18", "Ex2ARS_03_SupportCheck"): (4,),
    ("TY18", "Ex2ARS_03_ActiveTest"): (4,),
    ("TY18", "Ex2VGRS_04_SupportCheck"): (4,),
    ("TY18", "Ex2VGRS_04_StartLockRelease"): (4,),
    ("TYPlus", "Ex2VGRS_04_StartLockRelease"): (4,),
    ("TY18", "Ex2VGRS_04_EndLockRelease"): (4,),
    ("TYPlus", "Ex2VGRS_04_EndLockRelease"): (4,),
    ("TY18", "Ex2VGRS_04_StartNeutralCompMode"): (4,),
    ("TYPlus", "Ex2VGRS_04_StartNeutralCompMode"): (4,),
    ("TY18", "Ex2VGRS_04_EndNeutralCompMode"): (4,),
    ("TYPlus", "Ex2VGRS_04_EndNeutralCompMode"): (4,),
    ("TY18", "Ex2VGRS_04_CheckDTC"): (4,),
    ("TY18", "Ex2VGRS_04_ClearDTC"): (4,),
    ("TYPlus", "Ex2VGRS_04_ClearDTC"): (4,),
    ("TY18", "Ex2DRS_02_SupportCheck"): (4, 20),
    ("TY18", "Ex2DRS_02_ReadModeStatus"): (4, 20),
    ("TY18", "Ex2DRS_02_ReadRadarCruiseData"): (4, 20),
    ("TY18", "Ex2DRS_02_StopActiveTest"): (4, 20),
    ("TY18", "Ex2DRS_03_SupportCheck"): (4, 20),
    ("TY18", "Ex2DRS_03_ReadRadarCruiseData"): (4, 20),
    ("TY18", "Ex2DRS_03_StopActiveTest"): (4, 20),
    ("TY18", "Ex2DRS_03_ReadModeStatus"): (4, 20),
    ("TY18", "Ex2DRS_03_EndProcess"): (4, 20),
    ("TY18", "Ex2DRS_04_SendMessage"): (4,),
    ("TY18", "Ex2EMPS_07_ConfirmTheAssistMap"): (4,),
    ("TYPlus", "Ex2EMPS_07_ConfirmTheAssistMap"): (4,),
    ("TY18", "Ex2EMPS_07_ClearTheAssistMap"): (4,),
    ("TYPlus", "Ex2EMPS_07_ClearTheAssistMap"): (4,),
    ("TY18", "Ex24WD_03_SupportCheck"): (4,),
    ("TY18", "Ex24WD_03_ChangePreventionMode"): (4,),
    ("TY18", "Ex2ABS4WD_01_SupportCheck"): (4,),
    ("TY18", "Ex2ABS4WD_01_ChangePreventionMode"): (4,),
    ("TY18", "Ex2PSAABS_01_SendMessage"): (19,),
    ("TY18", "Ex2PSAABS_02_SendMessage"): (19,),
    ("TY18", "Ex2PSAABS_03_StartActiveTest"): (19,),
    ("TY18", "Ex2PSAABS_03_ConfirmStatus"): (19,),
    ("TY18", "Ex2MS2SMRT_08_SendMessage"): (52,),
    ("TY18", "Ex2MS2SMRT_09_SendMessage"): (52,),
    ("TY18", "Ex2MS2BDY_01_SendMessage"): (52,),
    ("TYPlus", "Ex2MS2BDY_01_SendMessage"): (52,),
    ("TY18", "Ex2MS2RAB_01_SendMessage"): (52,),
    ("TYPlus", "Ex2MS2RAB_01_SendMessage"): (52,),
    ("TY18", "Ex2MS2SAS_02_SendMessage"): (52,),
    ("TYPlus", "Ex2MS2SAS_02_SendMessage"): (52,),
    ("TY12", "Ex2ASG_02_CheckLearnedFlg"): (4,),
    ("TY18", "Ex2ASG_02_CheckLearnedFlg"): (4,),
    ("TYPlus", "Ex2ASG_02_CheckLearnedFlg"): (4,),
    ("TY12", "Ex2VGRS_04_StartLockRelease"): (4,),
    ("TY12", "Ex2VGRS_04_EndLockRelease"): (4,),
    ("TY12", "Ex2VGRS_04_StartNeutralCompMode"): (4,),
    ("TY12", "Ex2VGRS_04_EndNeutralCompMode"): (4,),
    ("TY12", "Ex2VGRS_04_ClearDTC"): (4,),
    ("TY12", "Ex2EMPS_07_ConfirmTheAssistMap"): (4,),
    ("TY12", "Ex2EMPS_07_ClearTheAssistMap"): (4,),
    ("TY12", "Ex2SMRT_33_ECU_ID_Registration"): (3,),
    ("TY12", "Ex2SMRT_33_GetKeyStatus"): (3,),
    ("TY12", "Ex2SMRT_35_CommunicationCheck"): (3,),
    ("TY12", "Ex2SMRT_35_GetSupportBitInformation"): (3,),
    ("TY12", "Ex2SMRT_35_ReGetSupportBitInformation"): (3,),
    ("TY12", "Ex2SMRT_35_TerminateCommunicationCheck"): (3,),
    ("TY18", "Ex2MS2SMRT_05_SendMessage"): (52,),
    ("TYPlus", "Ex2MS2SMRT_05_SendMessage"): (52,),
    ("TY18", "Ex2MS2SMRT_07_SendMessage"): (52,),
    ("TYPlus", "Ex2MS2SMRT_07_SendMessage"): (52,),
    ("TYPlus", "Ex2MS2SMRT_08_SendMessage"): (52,),
    ("TYPlus", "Ex2MS2SMRT_09_SendMessage"): (52,),
    ("TY18", "Ex2MS2DCM_02_SendMessage"): (52,),
    ("TYPlus", "Ex2MS2DCM_02_SendMessage"): (52,),
    ("TY18", "Ex2MS2MET_01_SendMessage"): (52,),
    ("TYPlus", "Ex2MS2MET_01_SendMessage"): (52,),
    ("TY18", "Ex2MS2TPW_01_SendMessage"): (52,),
    ("TYPlus", "Ex2MS2TPW_01_SendMessage"): (52,),
    ("TY18", "Ex2PSABSI_01_SendMessage"): (19,),
    ("TY12", "Ex2PSABSI_01_SendMessage"): (19,),
    ("TY18", "Ex2PSABSI_02_ExitEconomyMode"): (19,),
    ("TY12", "Ex2PSABSI_02_ExitEconomyMode"): (19,),
    ("TY18", "Ex2PSABSI_03_GetMode"): (19,),
    ("TY12", "Ex2PSABSI_03_GetMode"): (19,),
    ("TY18", "Ex2PSABSI_03_SetMode"): (19,),
    ("TY12", "Ex2PSABSI_03_SetMode"): (19,),
    ("TY18", "Ex2PSABSI_04_ForcingOfGaugingRequest"): (19,),
    ("TY12", "Ex2PSABSI_04_ForcingOfGaugingRequest"): (19,),
    ("TY18", "Ex2PSABSI_05_BSIStatusCheck"): (19,),
    ("TY12", "Ex2PSABSI_05_BSIStatusCheck"): (19,),
    ("TY18", "Ex2PSABSI_05_ExitCommunication"): (19,),
    ("TY12", "Ex2PSABSI_05_ExitCommunication"): (19,),
    ("TY18", "Ex2PSABSI_05_KeyRegister"): (19,),
    ("TY12", "Ex2PSABSI_05_KeyRegister"): (19,),
    ("TY18", "Ex2PSABSI_05_UnlockRequest"): (19,),
    ("TY12", "Ex2PSABSI_05_UnlockRequest"): (19,),
    ("TY18", "Ex2PSABSI_06_BSIStatusCheck"): (19,),
    ("TY12", "Ex2PSABSI_06_BSIStatusCheck"): (19,),
    ("TY18", "Ex2PSABSI_06_ProgramADCCode"): (19,),
    ("TY12", "Ex2PSABSI_06_ProgramADCCode"): (19,),
    ("TY18", "Ex2PSABSI_07_BSIStatusCheck"): (19,),
    ("TY12", "Ex2PSABSI_07_BSIStatusCheck"): (19,),
    ("TY18", "Ex2PSABSI_07_UnlockRequest"): (19,),
    ("TY12", "Ex2PSABSI_07_UnlockRequest"): (19,),
    ("TY18", "Ex2PSABSI_08_GetVIN"): (19,),
    ("TY12", "Ex2PSABSI_08_GetVIN"): (19,),
    ("TY18", "Ex2PSABSI_08_WriteVIN"): (19,),
    ("TY12", "Ex2PSABSI_08_WriteVIN"): (19,),
    ("TY18", "Ex2RWG_01_DTCRead"): (4,),
    ("TY12", "Ex2RWG_01_DTCRead"): (4,),
    ("TYPlus", "Ex2RWG_01_DTCRead"): (4,),
    ("TY18", "Ex2RWG_01_LearnZeroPos"): (4,),
    ("TY12", "Ex2RWG_01_LearnZeroPos"): (4,),
    ("TYPlus", "Ex2RWG_01_LearnZeroPos"): (4,),
    ("TY18", "Ex2RWG_01_SupportCheck"): (4,),
    ("TY12", "Ex2RWG_01_SupportCheck"): (4,),
    ("TYPlus", "Ex2RWG_01_SupportCheck"): (4,),
    ("TY18", "Ex2EVP_01_InitializeAllMemory"): (4,),
    ("TYPlus", "Ex2EVP_01_InitializeAllMemory"): (4,),
    ("TY18", "Ex2OCC_05_ExitCommunication"): (3,),
    ("TY12", "Ex2OCC_05_ExitCommunication"): (3,),
    ("TYPlus", "Ex2OCC_05_ExitCommunication"): (3,),
    ("TY18", "Ex2OCC_05_Get30KgLoadRange"): (3,),
    ("TY12", "Ex2OCC_05_Get30KgLoadRange"): (3,),
    ("TYPlus", "Ex2OCC_05_Get30KgLoadRange"): (3,),
    ("TY18", "Ex2OCC_05_GetNoLoadRange"): (3,),
    ("TY12", "Ex2OCC_05_GetNoLoadRange"): (3,),
    ("TYPlus", "Ex2OCC_05_GetNoLoadRange"): (3,),
    ("TY18", "Ex2OCC_05_GetReclineLoadRange"): (3,),
    ("TY12", "Ex2OCC_05_GetReclineLoadRange"): (3,),
    ("TYPlus", "Ex2OCC_05_GetReclineLoadRange"): (3,),
    ("TY18", "Ex2OCC_05_GetSensorInfo"): (3,),
    ("TY12", "Ex2OCC_05_GetSensorInfo"): (3,),
    ("TYPlus", "Ex2OCC_05_GetSensorInfo"): (3,),
    ("TY18", "Ex2OCC_05_GetTotalWeightInfo"): (3,),
    ("TY12", "Ex2OCC_05_GetTotalWeightInfo"): (3,),
    ("TYPlus", "Ex2OCC_05_GetTotalWeightInfo"): (3,),
    ("TY18", "Ex2OCC_05_ZeroPointCalibration"): (3,),
    ("TY12", "Ex2OCC_05_ZeroPointCalibration"): (3,),
    ("TYPlus", "Ex2OCC_05_ZeroPointCalibration"): (3,),
    ("TY18", "Ex2OCC_06_SupportCheck"): (4,),
    ("TY12", "Ex2OCC_06_SupportCheck"): (4,),
    ("TYPlus", "Ex2OCC_06_SupportCheck"): (4,),
    ("TY18", "Ex2OCC_06_ZeroPointCalibration"): (4,),
    ("TY12", "Ex2OCC_06_ZeroPointCalibration"): (4,),
    ("TYPlus", "Ex2OCC_06_ZeroPointCalibration"): (4,),
    ("TY18", "Ex2ACC_01_LostCommunicationHistoryClear"): (4,),
    ("TY12", "Ex2ACC_01_LostCommunicationHistoryClear"): (4,),
    ("TYPlus", "Ex2ACC_01_LostCommunicationHistoryClear"): (4,),
    ("TY18", "Ex2ACC_01_LostCommunicationHistoryRead"): (4,),
    ("TY12", "Ex2ACC_01_LostCommunicationHistoryRead"): (4,),
    ("TYPlus", "Ex2ACC_01_LostCommunicationHistoryRead"): (4,),
    ("TY18", "Ex2ACC_01_SupportCheck"): (4,),
    ("TY12", "Ex2ACC_01_SupportCheck"): (4,),
    ("TYPlus", "Ex2ACC_01_SupportCheck"): (4,),
    ("TY18", "Ex2ADX_01_SendMessage"): (20,),
    ("TYPlus", "Ex2ADX_01_SendMessage"): (20,),
    ("TYPlus", "Ex2SZABS_52_SendMessage"): (116,),
    ("TY18", "Ex2AHS_01_CameraOpticAxisAdjustmentRequest"): (4,),
    ("TY12", "Ex2AHS_01_CameraOpticAxisAdjustmentRequest"): (4,),
    ("TYPlus", "Ex2AHS_01_CameraOpticAxisAdjustmentRequest"): (4,),
    ("TY18", "Ex2AHS_01_CameraOpticAxisConfirmation"): (4,),
    ("TY12", "Ex2AHS_01_CameraOpticAxisConfirmation"): (4,),
    ("TYPlus", "Ex2AHS_01_CameraOpticAxisConfirmation"): (4,),
    ("TY18", "Ex2AHS_01_SupportCheck"): (4,),
    ("TY12", "Ex2AHS_01_SupportCheck"): (4,),
    ("TYPlus", "Ex2AHS_01_SupportCheck"): (4,),
    ("TY18", "Ex2AHS_02_CalibSwivelMarginAngle"): (4,),
    ("TY12", "Ex2AHS_02_CalibSwivelMarginAngle"): (4,),
    ("TYPlus", "Ex2AHS_02_CalibSwivelMarginAngle"): (4,),
    ("TY18", "Ex2AHS_02_SupportCheck"): (4,),
    ("TY12", "Ex2AHS_02_SupportCheck"): (4,),
    ("TYPlus", "Ex2AHS_02_SupportCheck"): (4,),
    ("TY18", "Ex2AHS_03_HeightSensorInitializationAndDTCCheck"): (4,),
    ("TY12", "Ex2AHS_03_HeightSensorInitializationAndDTCCheck"): (4,),
    ("TYPlus", "Ex2AHS_03_HeightSensorInitializationAndDTCCheck"): (4,),
    ("TY18", "Ex2AHS_03_SupportCheckAndDTCCheck"): (4,),
    ("TY12", "Ex2AHS_03_SupportCheckAndDTCCheck"): (4,),
    ("TYPlus", "Ex2AHS_03_SupportCheckAndDTCCheck"): (4,),
    ("TY18", "Ex2AHS_04_SupportCheckAndDTCCheck"): (4,),
    ("TY12", "Ex2AHS_04_SupportCheckAndDTCCheck"): (4,),
    ("TYPlus", "Ex2AHS_04_SupportCheckAndDTCCheck"): (4,),
    ("TY18", "Ex2AHS_04_SynchronizeInformationAndDTCCheck"): (4,),
    ("TY12", "Ex2AHS_04_SynchronizeInformationAndDTCCheck"): (4,),
    ("TYPlus", "Ex2AHS_04_SynchronizeInformationAndDTCCheck"): (4,),
    ("TY18", "Ex2STB_03_ExecutingSensorCalibration"): (4,),
    ("TY12", "Ex2STB_03_ExecutingSensorCalibration"): (4,),
    ("TYPlus", "Ex2STB_03_ExecutingSensorCalibration"): (4,),
    ("TY18", "Ex2STB_03_PreSensorCalibration"): (4,),
    ("TY12", "Ex2STB_03_PreSensorCalibration"): (4,),
    ("TYPlus", "Ex2STB_03_PreSensorCalibration"): (4,),
    ("TY18", "Ex2STB_03_StartSensorCalibration"): (4,),
    ("TY12", "Ex2STB_03_StartSensorCalibration"): (4,),
    ("TYPlus", "Ex2STB_03_StartSensorCalibration"): (4,),
    ("TY18", "Ex2STB_03_SupportCheck"): (4,),
    ("TY12", "Ex2STB_03_SupportCheck"): (4,),
    ("TYPlus", "Ex2STB_03_SupportCheck"): (4,),
    ("TY18", "Ex2STB_04_DriveActiveStabi"): (4,),
    ("TY12", "Ex2STB_04_DriveActiveStabi"): (4,),
    ("TYPlus", "Ex2STB_04_DriveActiveStabi"): (4,),
    ("TY18", "Ex2STB_04_ExitActiveStabi"): (4,),
    ("TY12", "Ex2STB_04_ExitActiveStabi"): (4,),
    ("TYPlus", "Ex2STB_04_ExitActiveStabi"): (4,),
    ("TY18", "Ex2STB_04_PreparateActiveStabi"): (4,),
    ("TY12", "Ex2STB_04_PreparateActiveStabi"): (4,),
    ("TYPlus", "Ex2STB_04_PreparateActiveStabi"): (4,),
    ("TY18", "Ex2STB_04_RestartActiveStabi"): (4,),
    ("TY12", "Ex2STB_04_RestartActiveStabi"): (4,),
    ("TYPlus", "Ex2STB_04_RestartActiveStabi"): (4,),
    ("TY18", "Ex2STB_04_SupportCheck"): (4,),
    ("TY12", "Ex2STB_04_SupportCheck"): (4,),
    ("TYPlus", "Ex2STB_04_SupportCheck"): (4,),
    ("TY18", "Ex2PSASRS_01_GetStatus"): (19,),
    ("TY12", "Ex2PSASRS_01_GetStatus"): (19,),
    ("TY18", "Ex2PSASRS_01_SetStatus"): (19,),
    ("TY12", "Ex2PSASRS_01_SetStatus"): (19,),
    ("TY18", "Ex2HNPCS_02_SendMessage"): (4,),
    ("TY12", "Ex2HNPCS_02_SendMessage"): (4,),
    ("TYPlus", "Ex2HNPCS_02_SendMessage"): (4,),
    ("TY18", "Ex2HNPCS_02_SupportCheck"): (4,),
    ("TY12", "Ex2HNPCS_02_SupportCheck"): (4,),
    ("TYPlus", "Ex2HNPCS_02_SupportCheck"): (4,),
    ("TY18", "Ex2HNPCS_03_InitializeTheLearningValue"): (4,),
    ("TY12", "Ex2HNPCS_03_InitializeTheLearningValue"): (4,),
    ("TYPlus", "Ex2HNPCS_03_InitializeTheLearningValue"): (4,),
    ("TY18", "Ex2HNPCS_03_SupportCheck"): (4,),
    ("TY12", "Ex2HNPCS_03_SupportCheck"): (4,),
    ("TYPlus", "Ex2HNPCS_03_SupportCheck"): (4,),
    ("TY18", "Ex2HNPCS_04_ClearPCSOperationCount"): (4,),
    ("TY12", "Ex2HNPCS_04_ClearPCSOperationCount"): (4,),
    ("TYPlus", "Ex2HNPCS_04_ClearPCSOperationCount"): (4,),
    ("TY18", "Ex2HNPCS_04_ReadPCSOperationCount"): (4,),
    ("TY12", "Ex2HNPCS_04_ReadPCSOperationCount"): (4,),
    ("TYPlus", "Ex2HNPCS_04_ReadPCSOperationCount"): (4,),
    ("TY18", "Ex2HNPCS_04_SupportCheck"): (4,),
    ("TY12", "Ex2HNPCS_04_SupportCheck"): (4,),
    ("TYPlus", "Ex2HNPCS_04_SupportCheck"): (4,),
    ("TY18", "Ex2HNAHB_01_GetSupport"): (4,),
    ("TYPlus", "Ex2HNAHB_01_GetSupport"): (4,),
    ("TY18", "Ex2HNAHB_01_HistoryClear"): (4,),
    ("TYPlus", "Ex2HNAHB_01_HistoryClear"): (4,),
    ("TY18", "Ex2SIS_01_SendMessage"): (20,),
    ("TYPlus", "Ex2SIS_01_SendMessage"): (20,),
    ("TY18", "Ex2SIS_02_SendMessage"): (20,),
    ("TYPlus", "Ex2SIS_02_SendMessage"): (20,),
    ("TY18", "Ex2PSAALM_01_SendMessage"): (19,),
    ("TY12", "Ex2PSAALM_01_SendMessage"): (19,),
    ("TYPlus", "Ex2GWY_02_CheckTheDtc"): (20, 21, 22),
    ("TYPlus", "Ex2GWY_02_EndInit"): (20, 21, 22),
    ("TYPlus", "Ex2GWY_02_ErrorInit"): (20, 21, 22),
    ("TYPlus", "Ex2GWY_02_StartInit"): (20, 21, 22),
    ("TYPlus", "Ex2GWY_02_StartSession"): (20, 21, 22),
    ("TY18", "Ex2LAMP_01_HeightSensorInitializationRequest"): (4,),
    ("TY12", "Ex2LAMP_01_HeightSensorInitializationRequest"): (4,),
    ("TYPlus", "Ex2LAMP_01_HeightSensorInitializationRequest"): (4,),
    ("TY18", "Ex2LAMP_01_SupportCheck"): (4,),
    ("TY12", "Ex2LAMP_01_SupportCheck"): (4,),
    ("TYPlus", "Ex2LAMP_01_SupportCheck"): (4,),
    ("TY12", "Ex2ASG_02_InitialLearning"): (4,),
    ("TY12", "Ex2ASG_02_GetLearnedStatus"): (4,),
    ("TY12", "Ex2ASG_02_GetLearnedStatusAfterTimeOut"): (4,),
    ("TY12", "Ex2ASG_02_GetLearnedStatusAt004"): (4,),
    ("TY18", "Ex2ASG_02_InitialLearning"): (4,),
    ("TY18", "Ex2ASG_02_GetLearnedStatus"): (4,),
    ("TY18", "Ex2ASG_02_GetLearnedStatusAfterTimeOut"): (4,),
    ("TY18", "Ex2ASG_02_GetLearnedStatusAt004"): (4,),
    ("TYPlus", "Ex2ASG_02_InitialLearning"): (4,),
    ("TYPlus", "Ex2ASG_02_GetLearnedStatus"): (4,),
    ("TYPlus", "Ex2ASG_02_GetLearnedStatusAfterTimeOut"): (4,),
    ("TYPlus", "Ex2ASG_02_GetLearnedStatusAt004"): (4,),
    ("TY18", "Ex2FC_04_CheckCanAirBleed"): (4,),
    ("TY12", "Ex2FC_04_CheckCanAirBleed"): (4,),
    ("TYPlus", "Ex2FC_04_CheckCanAirBleed"): (4,),
    ("TY18", "Ex2FC_04_ConfirmAirBleed"): (4,),
    ("TY12", "Ex2FC_04_ConfirmAirBleed"): (4,),
    ("TYPlus", "Ex2FC_04_ConfirmAirBleed"): (4,),
    ("TY18", "Ex2FC_04_ExecuteAirBleedHeater"): (4,),
    ("TY12", "Ex2FC_04_ExecuteAirBleedHeater"): (4,),
    ("TYPlus", "Ex2FC_04_ExecuteAirBleedHeater"): (4,),
    ("TY18", "Ex2FC_04_StartAirBleed"): (4,),
    ("TY12", "Ex2FC_04_StartAirBleed"): (4,),
    ("TYPlus", "Ex2FC_04_StartAirBleed"): (4,),
    ("TY18", "Ex2FC_04_StartKeepAlive"): (4,),
    ("TY12", "Ex2FC_04_StartKeepAlive"): (4,),
    ("TYPlus", "Ex2FC_04_StartKeepAlive"): (4,),
    ("TY18", "Ex2FC_04_SupportCheck"): (4,),
    ("TY12", "Ex2FC_04_SupportCheck"): (4,),
    ("TYPlus", "Ex2FC_04_SupportCheck"): (4,),
    ("TY18", "Ex2FC_05_MonitorAndActivateValve"): (4,),
    ("TY12", "Ex2FC_05_MonitorAndActivateValve"): (4,),
    ("TYPlus", "Ex2FC_05_MonitorAndActivateValve"): (4,),
    ("TY18", "Ex2FC_05_SupportCheck"): (4,),
    ("TY12", "Ex2FC_05_SupportCheck"): (4,),
    ("TYPlus", "Ex2FC_05_SupportCheck"): (4,),
    ("TY18", "Ex2HAL_02_HeightSensorInitializationAndDTCCheck"): (4,),
    ("TY12", "Ex2HAL_02_HeightSensorInitializationAndDTCCheck"): (4,),
    ("TYPlus", "Ex2HAL_02_HeightSensorInitializationAndDTCCheck"): (4,),
    ("TY18", "Ex2HAL_02_SupportCheckAndDTCCheck"): (4,),
    ("TY12", "Ex2HAL_02_SupportCheckAndDTCCheck"): (4,),
    ("TYPlus", "Ex2HAL_02_SupportCheckAndDTCCheck"): (4,),
    ("TY18", "Ex2HAL_03_SupportCheckAndDTCCheck"): (4,),
    ("TY12", "Ex2HAL_03_SupportCheckAndDTCCheck"): (4,),
    ("TYPlus", "Ex2HAL_03_SupportCheckAndDTCCheck"): (4,),
    ("TY18", "Ex2HAL_03_SynchronizeInformationAndDTCCheck"): (4,),
    ("TY12", "Ex2HAL_03_SynchronizeInformationAndDTCCheck"): (4,),
    ("TYPlus", "Ex2HAL_03_SynchronizeInformationAndDTCCheck"): (4,),
    ("TY18", "Ex2IC_01_SendMessage"): (21,),
    ("TY12", "Ex2IC_01_SendMessage"): (21,),
    ("TYPlus", "Ex2IC_01_SendMessage"): (21,),
    ("TY18", "Ex2RES_03_InitialRegistrationRequest"): (4,),
    ("TY12", "Ex2RES_03_InitialRegistrationRequest"): (4,),
    ("TYPlus", "Ex2RES_03_InitialRegistrationRequest"): (4,),
    ("TY18", "Ex2RES_03_SupportCheck"): (4,),
    ("TY12", "Ex2RES_03_SupportCheck"): (4,),
    ("TYPlus", "Ex2RES_03_SupportCheck"): (4,),
    ("TY18", "Ex2RES_04_GetEcuInfo_SIL"): (4,),
    ("TYPlus", "Ex2RES_04_GetEcuInfo_SIL"): (4,),
    ("TY18", "Ex2RES_04_GetSupportFunction_SIL"): (4,),
    ("TYPlus", "Ex2RES_04_GetSupportFunction_SIL"): (4,),
    ("TY18", "Ex2RES_04_KeepAlive_SIL"): (4,),
    ("TYPlus", "Ex2RES_04_KeepAlive_SIL"): (4,),
    ("TY18", "Ex2RES_04_RemoteStartRegistration"): (4,),
    ("TY12", "Ex2RES_04_RemoteStartRegistration"): (4,),
    ("TYPlus", "Ex2RES_04_RemoteStartRegistration"): (4,),
    ("TY18", "Ex2RES_04_SendKey_SIL"): (4,),
    ("TYPlus", "Ex2RES_04_SendKey_SIL"): (4,),
    ("TY18", "Ex2RES_04_SupportCheck"): (4,),
    ("TY12", "Ex2RES_04_SupportCheck"): (4,),
    ("TYPlus", "Ex2RES_04_SupportCheck"): (4,),
    ("TY18", "Ex2RES_04_SupportCheck_SIL"): (4,),
    ("TYPlus", "Ex2RES_04_SupportCheck_SIL"): (4,),
    ("TY18", "Ex2GS_01_CheckShutterStatus"): (4,),
    ("TY12", "Ex2GS_01_CheckShutterStatus"): (4,),
    ("TYPlus", "Ex2GS_01_CheckShutterStatus"): (4,),
    ("TY18", "Ex2GS_01_ShiftMode"): (4,),
    ("TY12", "Ex2GS_01_ShiftMode"): (4,),
    ("TYPlus", "Ex2GS_01_ShiftMode"): (4,),
    ("TY18", "Ex2GS_01_SupportCheck"): (4,),
    ("TY12", "Ex2GS_01_SupportCheck"): (4,),
    ("TYPlus", "Ex2GS_01_SupportCheck"): (4,),
    ("TY18", "Ex2GS_02_SendMessage"): (4,),
    ("TY12", "Ex2GS_02_SendMessage"): (4,),
    ("TYPlus", "Ex2GS_02_SendMessage"): (4,),
    ("TY18", "Ex2LDR_09_SendMessage"): (20,),
    ("TYPlus", "Ex2LDR_09_SendMessage"): (20,),
    ("TY18", "Ex2LDR_10_SendMessage"): (20,),
    ("TYPlus", "Ex2LDR_10_SendMessage"): (20,),
    ("TY18", "Ex2LDR_11_SendMessage"): (20,),
    ("TYPlus", "Ex2LDR_11_SendMessage"): (20,),
    ("TY18", "Ex2LDR_12_SendMessage"): (20,),
    ("TYPlus", "Ex2LDR_12_SendMessage"): (20,),
    ("TY18", "Ex2PCM_04_SendMessage"): (21,),
    ("TY12", "Ex2PCM_04_SendMessage"): (21,),
    ("TYPlus", "Ex2PCM_04_SendMessage"): (21,),
    ("TY18", "Ex2FSR_01_02_ActiveTest"): (4,),
    ("TY12", "Ex2FSR_01_02_ActiveTest"): (4,),
    ("TYPlus", "Ex2FSR_01_02_ActiveTest"): (4,),
    ("TY18", "Ex2FSR_01_02_SupportCheck"): (4,),
    ("TY12", "Ex2FSR_01_02_SupportCheck"): (4,),
    ("TYPlus", "Ex2FSR_01_02_SupportCheck"): (4,),
    ("TY18", "Ex2FSR_03_04_ActiveTest"): (4,),
    ("TY12", "Ex2FSR_03_04_ActiveTest"): (4,),
    ("TYPlus", "Ex2FSR_03_04_ActiveTest"): (4,),
    ("TY18", "Ex2FSR_03_04_SupportCheck"): (4,),
    ("TY12", "Ex2FSR_03_04_SupportCheck"): (4,),
    ("TYPlus", "Ex2FSR_03_04_SupportCheck"): (4,),
    ("TY18", "Ex2FSR_05_06_ClearAbnormalHistory"): (4,),
    ("TY12", "Ex2FSR_05_06_ClearAbnormalHistory"): (4,),
    ("TYPlus", "Ex2FSR_05_06_ClearAbnormalHistory"): (4,),
    ("TY18", "Ex2FSR_05_06_GetAbnormalHistory"): (4,),
    ("TY12", "Ex2FSR_05_06_GetAbnormalHistory"): (4,),
    ("TYPlus", "Ex2FSR_05_06_GetAbnormalHistory"): (4,),
    ("TY18", "Ex2FSR_05_06_SupportCheck"): (4,),
    ("TY12", "Ex2FSR_05_06_SupportCheck"): (4,),
    ("TYPlus", "Ex2FSR_05_06_SupportCheck"): (4,),
    ("TY18", "Ex2HNCSN_01_TransitionToNormalMode"): (4,),
    ("TYPlus", "Ex2HNCSN_01_TransitionToNormalMode"): (4,),
    ("TY18", "Ex2BCM_01_SendMessage"): (21,),
    ("TY12", "Ex2BCM_01_SendMessage"): (21,),
    ("TYPlus", "Ex2BCM_01_SendMessage"): (21,),
    ("TY18", "Ex2BCM_02_SendMessage"): (21,),
    ("TY12", "Ex2BCM_02_SendMessage"): (21,),
    ("TYPlus", "Ex2BCM_02_SendMessage"): (21,),
    ("TYPlus", "Ex2AVS_02_SendMessage"): (20, 21, 22),
    ("TY18", "Ex2HNFCM_02_LearnTarget1"): (4,),
    ("TY12", "Ex2HNFCM_02_LearnTarget1"): (4,),
    ("TYPlus", "Ex2HNFCM_02_LearnTarget1"): (4,),
    ("TY18", "Ex2HNFCM_02_LearnTarget2"): (4,),
    ("TY12", "Ex2HNFCM_02_LearnTarget2"): (4,),
    ("TYPlus", "Ex2HNFCM_02_LearnTarget2"): (4,),
    ("TY18", "Ex2HNFCM_02_LearnTarget3"): (4,),
    ("TY12", "Ex2HNFCM_02_LearnTarget3"): (4,),
    ("TYPlus", "Ex2HNFCM_02_LearnTarget3"): (4,),
    ("TY18", "Ex2HNFCM_02_LearnTargetAll"): (4,),
    ("TY12", "Ex2HNFCM_02_LearnTargetAll"): (4,),
    ("TYPlus", "Ex2HNFCM_02_LearnTargetAll"): (4,),
    ("TY18", "Ex2HNFCM_02_ReadCameraData"): (4,),
    ("TY12", "Ex2HNFCM_02_ReadCameraData"): (4,),
    ("TYPlus", "Ex2HNFCM_02_ReadCameraData"): (4,),
    ("TY18", "Ex2HNFCM_02_SupportCheck"): (4,),
    ("TY12", "Ex2HNFCM_02_SupportCheck"): (4,),
    ("TYPlus", "Ex2HNFCM_02_SupportCheck"): (4,),
    ("TY18", "Ex2ADS_04_SendMessage"): (20,),
    ("TYPlus", "Ex2ADS_04_SendMessage"): (20,),
    ("TY18", "Ex2ADS_05_SendMessage"): (20,),
    ("TYPlus", "Ex2ADS_05_SendMessage"): (20,),
    ("TY18", "Ex2ADS_06_SendMessage"): (20,),
    ("TYPlus", "Ex2ADS_06_SendMessage"): (20,),
    ("TY18", "Ex2ADS_07_SendMessage"): (20,),
    ("TYPlus", "Ex2ADS_07_SendMessage"): (20,),
    ("TY18", "Ex2ADS_08_SendMessage"): (20,),
    ("TYPlus", "Ex2ADS_08_SendMessage"): (20,),
    ("TY18", "Ex2ADS_09_SendMessage"): (20,),
    ("TYPlus", "Ex2ADS_09_SendMessage"): (20,),
    ("TY18", "Ex2ADS_10_SendMessage"): (20,),
    ("TYPlus", "Ex2ADS_10_SendMessage"): (20,),
    ("TY18", "Ex2ITS_01_SendMessage"): (4,),
    ("TY12", "Ex2ITS_01_SendMessage"): (4,),
    ("TYPlus", "Ex2ITS_01_SendMessage"): (4,),
    ("TY18", "Ex2DR_01_GetDataList"): (4,),
    ("TY12", "Ex2DR_01_GetDataList"): (4,),
    ("TYPlus", "Ex2DR_01_GetDataList"): (4,),
    ("TY12", "Ex2AMT_01_GetHistoryData"): (4,),
    ("TY12", "Ex2ASG_02_SupportCheck"): (4,),
    ("TY12", "Ex2AMT_01_SupportCheck"): (4,),
    ("TY12", "Ex2EFI_28_LearningValueReset"): (4,),
    ("TY12", "Ex2AMT_01_WriteHistoryDataToECU"): (4,),
    ("TY18", "Ex2AMT_01_GetHistoryData"): (4,),
    ("TY18", "Ex2ASG_02_SupportCheck"): (4,),
    ("TY18", "Ex2AMT_01_SupportCheck"): (4,),
    ("TY18", "Ex2EFI_28_LearningValueReset"): (4,),
    ("TY18", "Ex2AMT_01_WriteHistoryDataToECU"): (4,),
    ("TYPlus", "Ex2EFI_28_LearningValueReset"): (4,),
    ("TYPlus", "Ex2AMT_01_SupportCheck"): (4,),
    ("TYPlus", "Ex2ASG_02_SupportCheck"): (4,),
    ("TYPlus", "Ex2AMT_01_GetHistoryData"): (4,),
    ("TYPlus", "Ex2AMT_01_WriteHistoryDataToECU"): (4,),
    ("TY18", "Ex2DP2_11_FrontBeamAxisAdjustment"): (4, 20, 21),
    ("TY12", "Ex2DP2_11_FrontBeamAxisAdjustment"): (4, 20, 21),
    ("TYPlus", "Ex2DP2_11_FrontBeamAxisAdjustment"): (4, 20, 21),
    ("TY18", "Ex2DP2_11_SupportCheck"): (4, 20, 21),
    ("TY12", "Ex2DP2_11_SupportCheck"): (4,),
    ("TYPlus", "Ex2DP2_11_SupportCheck"): (4, 20, 21),
    ("TY18", "Ex2DP2_12_ActiveTest"): (4, 20, 21),
    ("TY12", "Ex2DP2_12_ActiveTest"): (4, 20, 21),
    ("TYPlus", "Ex2DP2_12_ActiveTest"): (4, 20, 21),
    ("TY18", "Ex2DP2_12_GetSupportBitInformation"): (4, 20, 21),
    ("TY12", "Ex2DP2_12_GetSupportBitInformation"): (4,),
    ("TYPlus", "Ex2DP2_12_GetSupportBitInformation"): (4, 20, 21),
    ("TY18", "Ex2DP2_13_ActiveTest"): (4,),
    ("TY12", "Ex2DP2_13_ActiveTest"): (4,),
    ("TYPlus", "Ex2DP2_13_ActiveTest"): (4,),
    ("TY18", "Ex2DP2_13_GetSupportBitInformation"): (4,),
    ("TY12", "Ex2DP2_13_GetSupportBitInformation"): (4,),
    ("TYPlus", "Ex2DP2_13_GetSupportBitInformation"): (4,),
    ("TY18", "Ex2DP2_14_SendMessage"): (4,),
    ("TY12", "Ex2DP2_14_SendMessage"): (4,),
    ("TYPlus", "Ex2DP2_14_SendMessage"): (4,),
    ("TY18", "Ex2VCIB_03_SendMessage"): (20,),
    ("TYPlus", "Ex2VCIB_03_SendMessage"): (20,),
    ("TY18", "Ex2VCIB_05_SendMessage"): (20,),
    ("TYPlus", "Ex2VCIB_05_SendMessage"): (20,),
    ("TY18", "Ex2EVB_02_READYONProhibitionCancel"): (4,),
    ("TY12", "Ex2EVB_02_READYONProhibitionCancel"): (4,),
    ("TYPlus", "Ex2EVB_02_READYONProhibitionCancel"): (4,),
    ("TY18", "Ex2VC_01_GetActuationCnt"): (4,),
    ("TY12", "Ex2VC_01_GetActuationCnt"): (4,),
    ("TYPlus", "Ex2VC_01_GetActuationCnt"): (4,),
    ("TY18", "Ex2VC_01_SupportCheck"): (4,),
    ("TY12", "Ex2VC_01_SupportCheck"): (4,),
    ("TYPlus", "Ex2VC_01_SupportCheck"): (4,),
    ("TY18", "Ex2VC_01_WriteActuationCnt"): (4,),
    ("TY12", "Ex2VC_01_WriteActuationCnt"): (4,),
    ("TYPlus", "Ex2VC_01_WriteActuationCnt"): (4,),
    ("TY18", "Ex2VC_02_Learn0Point"): (4,),
    ("TY12", "Ex2VC_02_Learn0Point"): (4,),
    ("TYPlus", "Ex2VC_02_Learn0Point"): (4,),
    ("TY18", "Ex2VC_02_SupportCheck"): (4,),
    ("TY12", "Ex2VC_02_SupportCheck"): (4,),
    ("TYPlus", "Ex2VC_02_SupportCheck"): (4,),
    ("TY18", "Ex2VC_03_SendMessage"): (4,),
    ("TYPlus", "Ex2VC_03_SendMessage"): (4,),
    ("TY18", "Ex2VC_04_SendMessage"): (4,),
    ("TYPlus", "Ex2VC_04_SendMessage"): (4,),
    ("TY18", "Ex2PI_01_GetAbsoTime"): (4,),
    ("TY12", "Ex2PI_01_GetAbsoTime"): (4,),
    ("TYPlus", "Ex2PI_01_GetAbsoTime"): (4,),
    ("TY18", "Ex2PI_01_GetCurrentTimeStamp"): (4,),
    ("TY12", "Ex2PI_01_GetCurrentTimeStamp"): (4,),
    ("TYPlus", "Ex2PI_01_GetCurrentTimeStamp"): (4,),
    ("TY18", "Ex2PI_01_GetFuseHistory"): (4,),
    ("TY12", "Ex2PI_01_GetFuseHistory"): (4,),
    ("TYPlus", "Ex2PI_01_GetFuseHistory"): (4,),
    ("TY18", "Ex2PI_01_SupportCheck"): (4,),
    ("TY12", "Ex2PI_01_SupportCheck"): (4,),
    ("TYPlus", "Ex2PI_01_SupportCheck"): (4,),
    ("TY18", "Ex2DSC_01_SendMessage"): (21,),
    ("TY12", "Ex2DSC_01_SendMessage"): (21,),
    ("TYPlus", "Ex2DSC_01_SendMessage"): (21,),
    ("TY18", "Ex2DSC_02_SendMessage"): (21,),
    ("TY12", "Ex2DSC_02_SendMessage"): (21,),
    ("TYPlus", "Ex2DSC_02_SendMessage"): (21,),
    ("TYPlus", "Ex2HVB_10_SendMessage"): (20, 21, 22),
    ("TYPlus", "Ex2HVB_11_SendMessage"): (20, 21, 22),
    ("TY18", "Ex2VIF_02_SendMessage"): (4,),
    ("TYPlus", "Ex2VIF_02_SendMessage"): (4,),
    ("TY18", "Ex2HNCSN_01_EcuCal"): (4,),
    ("TYPlus", "Ex2HNCSN_01_EcuCal"): (4,),
    ("TY18", "Ex2HNCSN_01_InitStatusOfSensor"): (4,),
    ("TYPlus", "Ex2HNCSN_01_InitStatusOfSensor"): (4,),
    ("TY18", "Ex2HNCSN_01_SupportCheck"): (4,),
    ("TYPlus", "Ex2HNCSN_01_SupportCheck"): (4,),
    ("TY18", "Ex2HNCSN_01_WriteAngleOfSensor"): (4,),
    ("TYPlus", "Ex2HNCSN_01_WriteAngleOfSensor"): (4,),
    ("TY18", "Ex2HNCSN_01_WriteNeutralPosition"): (4,),
    ("TYPlus", "Ex2HNCSN_01_WriteNeutralPosition"): (4,),
    ("TYPlus", "Ex2HNCSN_01_WriteAngleOfRrSensor"): (4,),
    ("TYPlus", "Ex2HNCSN_01_WriteBumperType"): (4,),
    ("TY12", "Ex2ASUS_04_ModifyVhight"): (4,),
    ("TY12", "Ex2DRS_02_StopActiveTest"): (4, 20),
    ("TY12", "Ex2DRS_03_StopActiveTest"): (4, 20),
    ("TYPlus", "Ex2SZEIU_01_SendMessage"): (116,),
    ("TYPlus", "Ex2ABS_33_ShiftNormalMode"): (20, 21, 22),
    ("TYPlus", "Ex2ABS_47_EndExtendedSession"): (20, 21, 22),
    ("TYPlus", "Ex2ABS_47_ErrorEndExtendedSession"): (20, 21, 22),
    ("TYPlus", "Ex2ABS_47_ExitEndExtendedSession"): (20, 21, 22),
    ("TY18", "Ex2MS2ABS_04_SendMessage"): (52,),
    ("TYPlus", "Ex2MS2ABS_04_SendMessage"): (52,),
    ("TY18", "Ex2MS2AT_01_SendMessage"): (52,),
    ("TYPlus", "Ex2MS2AT_01_SendMessage"): (52,),
    ("TY18", "Ex2MS2RAB_02_SendMessage"): (52,),
    ("TYPlus", "Ex2MS2RAB_02_SendMessage"): (52,),
    ("TY18", "Ex2VC_05_SendMessage"): (4,),
    ("TYPlus", "Ex2VC_05_SendMessage"): (4,),
    ("TY18", "Ex2VIF_01_SendMessage"): (4,),
    ("TYPlus", "Ex2VIF_01_SendMessage"): (4,),
    ("TY12", "Ex2BSM_01_02_SupportCheck"): (4,),
    ("TY12", "Ex2BSM_01_02_Mov2TestMode"): (4,),
    ("TY12", "Ex2BSM_01_02_ChkStilInTestMode"): (4,),
    ("TY12", "Ex2BSM_01_02_ExitTestMode"): (4,),
    ("TY12", "Ex2BSM_07_08_SupportCheck"): (4,),
    ("TY12", "Ex2BSM_07_08_GetAbnormalHistory"): (4,),
    ("TY12", "Ex2BSM_07_08_ClearAbnormalHistory"): (4,),
    ("TY12", "Ex2VGRS_04_SupportCheck"): (4,),
    ("TY12", "Ex2VGRS_04_CheckDTC"): (4,),
    ("TY18", "Ex2MS2EFI_03_SendMessage"): (52,),
    ("TYPlus", "Ex2MS2EFI_03_SendMessage"): (52,),
    ("TY18", "Ex2MS2EFI_05_SendMessage"): (52,),
    ("TYPlus", "Ex2MS2EFI_05_SendMessage"): (52,),
    ("TY18", "Ex2MS2EFI_06_SendMessage"): (52,),
    ("TYPlus", "Ex2MS2EFI_06_SendMessage"): (52,),
    ("TY18", "Ex2VCIB_02_SendMessage"): (20,),
    ("TYPlus", "Ex2VCIB_02_SendMessage"): (20,),
    ("TY12", "Ex2ASUS_04_SupportCheck"): (4,),
    ("TY12", "Ex2ASUS_04_ReturnVhight"): (4,),
    ("TY12", "Ex2ASUS_04_LearnKneeldownVheight"): (4,),
    ("TY12", "Ex2ASUS_04_CheckReturnedVhight"): (4,),
    ("TY12", "Ex2ASUS_05_SupportCheck"): (4,),
    ("TY12", "Ex2ASUS_05_ModifyVheightDownStart"): (4,),
    ("TY12", "Ex2ASUS_05_ModifyVheightStop"): (4,),
    ("TY12", "Ex2ASUS_05_CheckModifiedVheight"): (4,),
    ("TY12", "Ex2ASUS_05_ModifyVheightTimeOver"): (4,),
    ("TY12", "Ex2ASUS_05_LearnKneelDownVheight"): (4,),
    ("TY12", "Ex2ASUS_05_ReturnVheightStart"): (4,),
    ("TY12", "Ex2ASUS_05_CheckReturnedVheight"): (4,),
    ("TY18", "Ex2HV_15_HiVltFsAccLdHstRst"): (4,),
    ("TY12", "Ex2HV_15_HiVltFsAccLdHstRst"): (4,),
    ("TYPlus", "Ex2HV_15_HiVltFsAccLdHstRst"): (4,),
    ("TY18", "Ex2HV_17_BatteryStatusInfoReset"): (4,),
    ("TY12", "Ex2HV_17_BatteryStatusInfoReset"): (4,),
    ("TYPlus", "Ex2HV_17_BatteryStatusInfoReset"): (4,),
    ("TY18", "Ex2MS2AT_02_SendMessage"): (52,),
    ("TYPlus", "Ex2MS2AT_02_SendMessage"): (52,),
    ("TY18", "Ex2MS2DCM_01_SendMessage"): (52,),
    ("TYPlus", "Ex2MS2DCM_01_SendMessage"): (52,),
    ("TY18", "Ex2MS2EMPS_01_SendMessage"): (52,),
    ("TYPlus", "Ex2MS2EMPS_01_SendMessage"): (52,),
    ("TY18", "Ex2MS2EMPS_02_SendMessage"): (52,),
    ("TYPlus", "Ex2MS2EMPS_02_SendMessage"): (52,),
    ("TY18", "Ex2MS2IG_01_SendMessage"): (52,),
    ("TYPlus", "Ex2MS2IG_01_SendMessage"): (52,),
    ("TY18", "Ex2MS2MET_02_SendMessage"): (52,),
    ("TYPlus", "Ex2MS2MET_02_SendMessage"): (52,),
    ("TY18", "Ex2MS2SAS_01_SendMessage"): (52,),
    ("TYPlus", "Ex2MS2SAS_01_SendMessage"): (52,),
    ("TY18", "Ex2MS2SAS_03_SendMessage"): (52,),
    ("TYPlus", "Ex2MS2SAS_03_SendMessage"): (52,),
    ("TY18", "Ex2HV_20_SendMessage"): (4,),
    ("TYPlus", "Ex2HV_20_SendMessage"): (4,),
    ("TY18", "Ex2HV_18_SendMessage"): (4,),
    ("TYPlus", "Ex2HV_18_SendMessage"): (4,),
    ("TY12", "Ex2ARS_01_ReadDTCofVGRS"): (4,),
    ("TY12", "Ex2ARS_01_ClearOffSetValue"): (4,),
    ("TY12", "Ex2ARS_01_ReadDTCofARS"): (4,),
    ("TY12", "Ex2ARS_02_ChkVGRSDtc"): (4,),
    ("TY12", "Ex2ARS_02_ClrCompVal"): (4,),
    ("TY12", "Ex2ARS_02_ChkARSDtc"): (4,),
    ("TY18", "Ex2TPW_03_SendMessage"): (4,),
    ("TY18", "Ex2MS2EYES_01_SendMessage"): (52,),
    ("TYPlus", "Ex2MS2EYES_01_SendMessage"): (52,),
    ("TY18", "Ex2MS2EYES_02_SendMessage"): (52,),
    ("TYPlus", "Ex2MS2EYES_02_SendMessage"): (52,),
    ("TY18", "Ex2MS2EYES_03_SendMessage"): (52,),
    ("TYPlus", "Ex2MS2EYES_03_SendMessage"): (52,),
    ("TY18", "Ex2MS2EYES_04_SendMessage"): (52,),
    ("TYPlus", "Ex2MS2EYES_04_SendMessage"): (52,),
    ("TY18", "Ex2MS2EYES_05_SendMessage"): (52,),
    ("TYPlus", "Ex2MS2EYES_05_SendMessage"): (52,),
    ("TY18", "Ex2MS2EYES_06_SendMessage"): (52,),
    ("TYPlus", "Ex2MS2EYES_06_SendMessage"): (52,),
    ("TY18", "Ex2MS2EYES_07_SendMessage"): (52,),
    ("TYPlus", "Ex2MS2EYES_07_SendMessage"): (52,),
    ("TY18", "Ex2HV_21_SendMessage"): (4,),
    ("TYPlus", "Ex2HV_21_SendMessage"): (4,),
    ("TY18", "Ex2HV_22_SendMessage"): (4,),
    ("TYPlus", "Ex2HV_22_SendMessage"): (4,),
    ("TY12", "Ex2DRS_02_SupportCheck"): (4, 20),
    ("TY12", "Ex2DRS_02_ReadModeStatus"): (4, 20),
    ("TY12", "Ex2DRS_02_ReadRadarCruiseData"): (4, 20),
    ("TY12", "Ex2DRS_03_SupportCheck"): (4, 20),
    ("TY12", "Ex2DRS_03_ReadRadarCruiseData"): (4, 20),
    ("TY12", "Ex2DRS_03_ReadModeStatus"): (4, 20),
    ("TY12", "Ex2DRS_03_EndProcess"): (4, 20),
    ("TY12", "Ex2DRS_04_SendMessage"): (4,),
    ("TY12", "Ex2TPW_03_SendMessage"): (4,),
    ("TY18", "Ex2HV_19_SendMessage"): (4,),
    ("TYPlus", "Ex2HV_19_SendMessage"): (4,),
    ("TY18", "Ex2HV_13_READYONProhibitionCancel"): (4,),
    ("TY12", "Ex2HV_13_READYONProhibitionCancel"): (4,),
    ("TYPlus", "Ex2HV_13_READYONProhibitionCancel"): (4,),
    ("TY18", "Ex2HV_11_SendMessage"): (4,),
    ("TY12", "Ex2HV_11_SendMessage"): (4,),
    ("TYPlus", "Ex2HV_11_SendMessage"): (4,),
    ("TYPlus", "Ex2ASUS_04_SupportCheck"): (4,),
    ("TYPlus", "Ex2ASUS_04_ModifyVhight"): (4,),
    ("TYPlus", "Ex2ASUS_04_ReturnVhight"): (4,),
    ("TYPlus", "Ex2ASUS_04_LearnKneeldownVheight"): (4,),
    ("TYPlus", "Ex2ASUS_04_CheckReturnedVhight"): (4,),
    ("TYPlus", "Ex2ASUS_05_ModifyVheightDownStart"): (4,),
    ("TYPlus", "Ex2ASUS_05_ModifyVheightStop"): (4,),
    ("TYPlus", "Ex2ASUS_05_CheckModifiedVheight"): (4,),
    ("TYPlus", "Ex2ASUS_05_ModifyVheightTimeOver"): (4,),
    ("TYPlus", "Ex2ASUS_05_LearnKneelDownVheight"): (4,),
    ("TYPlus", "Ex2ASUS_05_CheckReturnedVheight"): (4,),
    ("TY12", "Ex2BSM_03_04_SupportCheck"): (4,),
    ("TY12", "Ex2BSM_03_04_ActiveTest"): (4,),
    ("TY12", "Ex2BSM_05_06_SupportCheck"): (4,),
    ("TY12", "Ex2BSM_05_06_ActiveTest"): (4,),
    ("TY12", "Ex2ARS_01_A8SupportCheck"): (4,),
    ("TY12", "Ex2ARS_01_ReturnActuatorCenterPos"): (4,),
    ("TY12", "Ex2ARS_02_SupportCheck"): (4,),
    ("TY12", "Ex2ARS_02_InitCompVal"): (4,),
    ("TY12", "Ex2ARS_03_SupportCheck"): (4,),
    ("TY12", "Ex2ARS_03_ActiveTest"): (4,),
    ("TY12", "Ex24WD_03_SupportCheck"): (4,),
    ("TY12", "Ex24WD_03_ChangePreventionMode"): (4,),
    ("TY12", "Ex2ABS4WD_01_SupportCheck"): (4,),
    ("TY12", "Ex2ABS4WD_01_ChangePreventionMode"): (4,),
    ("TY12", "Ex2PSAABS_01_SendMessage"): (19,),
    ("TY12", "Ex2PSAABS_02_SendMessage"): (19,),
    ("TY12", "Ex2PSAABS_03_StartActiveTest"): (19,),
    ("TY12", "Ex2PSAABS_03_ConfirmStatus"): (19,),
    ("TYPlus", "Ex2ASUS_05_ReturnVheightStart"): (4,),
    ("TYPlus", "Ex2ASUS_05_SupportCheck"): (4,),
    ("TY18", "Ex2BDY_51_SupportCheck"): (4,),
    ("TY18", "Ex2BDY_52_CheckEraseKeys"): (4,),
    ("TY18", "Ex2BDY_52_GetRegedNumOfKeys"): (4,),
    ("TY18", "Ex2BDY_52_StartEraseKeys"): (4,),
    ("TY18", "Ex2BDY_52_SupportCheck"): (4,),
    ("TY18", "Ex2HV_12_SupportCheck"): (4,),
    ("TY12", "Ex2HV_12_SupportCheck"): (4,),
    ("TYPlus", "Ex2HV_12_SupportCheck"): (4,),
    ("TY18", "Ex2HV_12_GetDTCAndEEPROMStatus"): (4,),
    ("TY12", "Ex2HV_12_GetDTCAndEEPROMStatus"): (4,),
    ("TYPlus", "Ex2HV_12_GetDTCAndEEPROMStatus"): (4,),
    ("TY18", "Ex2HV_12_UpdateBatteryStatusInfo"): (4,),
    ("TY12", "Ex2HV_12_UpdateBatteryStatusInfo"): (4,),
    ("TYPlus", "Ex2HV_12_UpdateBatteryStatusInfo"): (4,),
    ("TY18", "Ex2HV_12_JudgementAfterUpdateInfo"): (4,),
    ("TY12", "Ex2HV_12_JudgementAfterUpdateInfo"): (4,),
    ("TYPlus", "Ex2HV_12_JudgementAfterUpdateInfo"): (4,),
    ("TY18", "Ex2HV_10_SupportCheck"): (4,),
    ("TY12", "Ex2HV_10_SupportCheck"): (4,),
    ("TYPlus", "Ex2HV_10_SupportCheck"): (4,),
    ("TY18", "Ex2HV_10_ReadBatteryStatus"): (4,),
    ("TY12", "Ex2HV_10_ReadBatteryStatus"): (4,),
    ("TYPlus", "Ex2HV_10_ReadBatteryStatus"): (4,),
    ("TY18", "Ex2HV_10_WaitingEEPROMWrite"): (4,),
    ("TY12", "Ex2HV_10_WaitingEEPROMWrite"): (4,),
    ("TYPlus", "Ex2HV_10_WaitingEEPROMWrite"): (4,),
    ("TY18", "Ex2HV_10_JudgementOfStckToReplace"): (4,),
    ("TY12", "Ex2HV_10_JudgementOfStckToReplace"): (4,),
    ("TYPlus", "Ex2HV_10_JudgementOfStckToReplace"): (4,),
    ("TYPlus", "Ex2BSM_01_02_SupportCheck"): (4,),
    ("TYPlus", "Ex2BSM_01_02_Mov2TestMode"): (4,),
    ("TYPlus", "Ex2BSM_01_02_ChkStilInTestMode"): (4,),
    ("TYPlus", "Ex2BSM_01_02_ExitTestMode"): (4,),
    ("TYPlus", "Ex2BSM_07_08_SupportCheck"): (4,),
    ("TYPlus", "Ex2BSM_07_08_GetAbnormalHistory"): (4,),
    ("TYPlus", "Ex2BSM_07_08_ClearAbnormalHistory"): (4,),
    ("TYPlus", "Ex2BSM_03_04_SupportCheck"): (4,),
    ("TYPlus", "Ex2BSM_03_04_ActiveTest"): (4,),
    ("TYPlus", "Ex2BSM_03_04_ActiveTestCon3_5"): (4,),
    ("TYPlus", "Ex2BSM_05_06_SupportCheck"): (4,),
    ("TYPlus", "Ex2BSM_05_06_ActiveTest"): (4,),
    ("TYPlus", "Ex2DRS_02_SupportCheck"): (4, 20),
    ("TYPlus", "Ex2DRS_02_ReadModeStatus"): (4, 20),
    ("TYPlus", "Ex2DRS_02_ReadRadarCruiseData"): (4, 20),
    ("TYPlus", "Ex2DRS_02_StopActiveTest"): (4, 20),
    ("TYPlus", "Ex2DRS_03_SupportCheck"): (4, 20),
    ("TYPlus", "Ex2DRS_03_ReadRadarCruiseData"): (4, 20),
    ("TYPlus", "Ex2DRS_03_StopActiveTest"): (4, 20),
    ("TYPlus", "Ex2DRS_03_ReadModeStatus"): (4, 20),
    ("TYPlus", "Ex2DRS_03_EndProcess"): (4, 20),
    ("TYPlus", "Ex2DRS_04_SendMessage"): (4,),
    ("TYPlus", "Ex24WD_03_SupportCheck"): (4,),
    ("TYPlus", "Ex24WD_03_ChangePreventionMode"): (4,),
    ("TYPlus", "Ex2ABS4WD_01_SupportCheck"): (4,),
    ("TYPlus", "Ex2ABS4WD_01_ChangePreventionMode"): (4,),
    ("TYPlus", "Ex2TPW_03_SendMessage"): (4,),
    ("TY18", "Ex2BDY_53_CheckRegECUID"): (4,),
    ("TY18", "Ex2BDY_53_StartRegECUID"): (4,),
    ("TY18", "Ex2BDY_53_SupportCheck"): (4,),
    ("TYPlus", "Ex2EFI_44_SessionTransition"): (20, 21, 22),
    ("TYPlus", "Ex2ARS_01_A8SupportCheck"): (4,),
    ("TYPlus", "Ex2ARS_01_ReadDTCofVGRS"): (4,),
    ("TYPlus", "Ex2ARS_01_ClearOffSetValue"): (4,),
    ("TYPlus", "Ex2ARS_01_ReadDTCofARS"): (4,),
    ("TYPlus", "Ex2ARS_01_ReturnActuatorCenterPos"): (4,),
    ("TYPlus", "Ex2ARS_02_SupportCheck"): (4,),
    ("TYPlus", "Ex2ARS_02_ChkVGRSDtc"): (4,),
    ("TYPlus", "Ex2ARS_02_ClrCompVal"): (4,),
    ("TYPlus", "Ex2ARS_02_ChkARSDtc"): (4,),
    ("TYPlus", "Ex2ARS_02_InitCompVal"): (4,),
    ("TYPlus", "Ex2ARS_03_ActiveTest"): (4,),
    ("TYPlus", "Ex2ARS_03_SupportCheck"): (4,),
    ("TYPlus", "Ex2EFI_62_SendMessage"): (20, 21, 22),
    ("TY18", "Ex2DCM_22_CancelComPausing"): (4,),
    ("TY18", "Ex2DCM_22_SupportCheck"): (4,),
    ("TYPlus", "Ex2EFI_53_SendMessage"): (20, 21, 22),
    ("TY18", "Ex2DCM_15_SendMessage"): (4,),
    ("TYPlus", "Ex2EFI_52_SendMessage"): (20, 21, 22),
    ("TYPlus", "Ex2EMPS_12_AutoRackCentering"): (20, 21, 22),
    ("TYPlus", "Ex2EMPS_12_SteeringStart"): (20, 21, 22),
    ("TYPlus", "Ex2EMPS_12_SteeringAngleCheck"): (20, 21, 22),
    ("TY18", "Ex2DCM_12_ResetBUBMemory"): (4,),
    ("TY18", "Ex2DCM_12_SupportCheck"): (4,),
    ("TY18", "Ex2DCM_20_ChangeSettings"): (4,),
    ("TY18", "Ex2DCM_20_GetTheActivationStatus"): (4,),
    ("TY18", "Ex2DCM_20_SupportCheck"): (4,),
    ("TYPlus", "Ex2EFI_61_SupportCheck"): (20, 21, 22),
    ("TYPlus", "Ex2EFI_61_WriteTotalShortTripEstimate"): (20, 21, 22),
    ("TY18", "Ex2DCM_07_08_09_10_16_ReadRemoteSettingData"): (4,),
    ("TY18", "Ex2DCM_07_08_09_10_16_SetRemoteSettingData"): (4,),
    ("TY18", "Ex2DCM_07_08_09_10_16_SupportCheck"): (4,),
    ("TY18", "Ex2DCM_19_ReadoutFOTAStatus"): (4,),
    ("TY18", "Ex2DCM_19_StartFOTA"): (4,),
    ("TY18", "Ex2DCM_19_SupportCheck"): (4,),
    ("TYPlus", "Ex2ECT_01_SendMessage"): (20, 21, 22),
    ("TYPlus", "Ex2ECT_04_SendMessage"): (20, 21, 22),
    ("TY18", "Ex2MM_08_ImageLineCheckRequestAndOperate"): (4,),
    ("TY18", "Ex2MM_08_SupportCheck"): (4,),
    ("TY18", "Ex2MM_09_GetPIDSupportInfo"): (4,),
    ("TY18", "Ex2MM_10_SupportCheck"): (4,),
    ("TY18", "Ex2MM_11_13_GetInformation"): (4,),
    ("TY18", "Ex2MM_11_13_SupportCheck"): (4,),
    ("TY18", "Ex2MM_20_SupportCheck"): (4,),
    ("TY18", "Ex2MM_20_ValetModeCancel"): (4,),
    ("TY18", "Ex2MM_21_TransferToDiagnosticMode"): (4,),
    ("TYPlus", "Ex2ECT_13_SendMessage"): (20, 21, 22),
    ("TY18", "Ex2MM_09_GetSoftErrHistory"): (4,),
    ("TY18", "Ex2MM_10_GetDiscErrInfo"): (4,),
    ("TY18", "Ex2MM_17_GetSupportInfoAndDataList"): (4,),
    ("TY18", "Ex2BDY_51_ChkNumberOfKeyRegistered"): (4,),
    ("TY18", "Ex2BDY_51_ChkNumberOfTotalKeyRegistered"): (4,),
    ("TY18", "Ex2BDY_51_ExitCommunication"): (4,),
    ("TY18", "Ex2BDY_51_NewKeyRegistration"): (4,),
    ("TY18", "Ex2BDY_51_NewKeyRegistration_Before_Remove_Key"): (4,),
    ("TY18", "Ex2BDY_51_OtherKeyRegistration"): (4,),
    ("TY18", "Ex2BDY_51_OtherKeyRegistration_Before_Remove_Key"): (4,),
    ("TY18", "Ex2BDY_51_OwnerConfirmation"): (4,),
    ("TY18", "Ex2BDY_51_OwnerConfirmation_Before_Remove_Key"): (4,),
    ("TY18", "Ex2BDY_51_RequestKeyRegistEnd"): (4,),
    ("TY18", "Ex2BDY_51_RequestKeyRegistration"): (4,),
    ("TY18", "Ex2BDY_51_StatusCheckInterval"): (4,),
    ("TY18", "Ex2BDY_51_StatusChkAfterKeyRegist"): (4,),
    ("TY18", "Ex2BDY_51_StatusChkAfterOwnerConfirmation"): (4,),
    ("TY18", "Ex2BDY_51_StatusChkRegisteredKey"): (4,),
    ("TY18", "Ex2DCM_19_ReadoutSoftwareVersion"): (4,),
    ("TY18", "Ex2DCM_21_GetTheDCMID"): (4,),
    ("TY18", "Ex2AC_08_RefrigerantFillingModeRequest"): (4,),
    ("TY18", "Ex2AC_09_RefrigerantHighPressureHistoryClear"): (4,),
    ("TY18", "Ex2CSN_05_ChangeTireCircumference"): (4,),
    ("TY18", "Ex2CSN_05_GetTireCircumference"): (4,),
    ("TY18", "Ex2SMRT_33_ECU_ID_Registration"): (3,),
    ("TY18", "Ex2SMRT_33_GetKeyStatus"): (3,),
    ("TY18", "Ex2SMRT_35_CommunicationCheck"): (3,),
    ("TY18", "Ex2SMRT_35_GetSupportBitInformation"): (3,),
    ("TY18", "Ex2SMRT_35_ReGetSupportBitInformation"): (3,),
    ("TY18", "Ex2SMRT_35_TerminateCommunicationCheck"): (3,),
    ("TY18", "Ex2PLG_01_QuickChargeRelayDiagnosis"): (4,),
    ("TY18", "Ex2PLG_01_ReadChargeLidSW_QuickChargeRelayDiag"): (4,),
    ("TY18", "Ex2PLG_01_ReadChargeRelayDiagnosisStatus"): (4,),
    ("TY18", "Ex2HV_14_ReadBatteryBlockVoltage"): (4,),
    ("TY12", "Ex2HV_14_ReadBatteryBlockVoltage"): (4,),
    ("TYPlus", "Ex2HV_14_ReadBatteryBlockVoltage"): (4,),
    ("TY18", "Ex2HV_14_ReadBatteryTemperature"): (4,),
    ("TY12", "Ex2HV_14_ReadBatteryTemperature"): (4,),
    ("TYPlus", "Ex2HV_14_ReadBatteryTemperature"): (4,),
    ("TY18", "Ex2HV_14_SupportCheck"): (4,),
    ("TY12", "Ex2HV_14_SupportCheck"): (4,),
    ("TYPlus", "Ex2HV_14_SupportCheck"): (4,),
    ("TY12", "Ex2MM_09_GetPIDSupportInfo"): (4,),
    ("TY12", "Ex2MM_09_GetSoftErrHistory"): (4,),
    ("TY12", "Ex2MM_10_GetDiscErrInfo"): (4,),
    ("TY12", "Ex2MM_10_SupportCheck"): (4,),
    ("TYPlus", "Ex2MM_09_GetPIDSupportInfo"): (4,),
    ("TYPlus", "Ex2MM_09_GetSoftErrHistory"): (4,),
    ("TYPlus", "Ex2MM_10_GetDiscErrInfo"): (4,),
    ("TYPlus", "Ex2MM_10_SupportCheck"): (4,),
}
_UTILITY_IMPORT_TARGETS = {
    "bc8b64326b53b8ddaa024f6c782528d8bbc20bca8c5038c462681a00451dabcd": "8d9623f028f23876f69cb02baa10e1881c01fa01a4f906013bd36266f7e0fb33",
    "ecba533aeaa2ec2a014fa59a113d025a8efe90338767c2786b8a5a891ca0f599": "79fc495c68eb099a7ebc0d1eefe0eafd80101ac0bc09a58d3f603ed556c84762",
    "d9fc5bb2f9d7bd583a9fbe317c3d45a2ed4eb60b210ea9623a8230f3baec1e8d": "79fc495c68eb099a7ebc0d1eefe0eafd80101ac0bc09a58d3f603ed556c84762",
}

_UTILITY_IMPORTS = {
    "bc8b64326b53b8ddaa024f6c782528d8bbc20bca8c5038c462681a00451dabcd": {
        424024: "Ex2Finalize",
        424028: "Ex2Initialize",
        424032: "Ex2StopKeepAliveThread",
        424036: "Ex2GetThreadStatus",
        424040: "Ex2CmnPortClose",
        424044: "Ex2CCU_01_ReproConnect",
        424048: "Ex2CCU_01_ReProgrammingVoltage",
        424052: "Ex2CCU_01_SetProgrammingVoltage",
        424056: "Ex2CCU_01_SILConnect",
        424060: "Ex2CCU_01_CANConnect",
        424064: "Ex2CCU_01_ReadVBatt",
        424068: "Ex2SetParaFromBroker",
        424072: "Ex2StopCmnThread",
    },
    "ecba533aeaa2ec2a014fa59a113d025a8efe90338767c2786b8a5a891ca0f599": {
        792720: "Ex2FCHV_17_SendMessage",
        792724: "Ex2FCHV_16_SendMessage",
        792728: "Ex2DOOR_01_StartConnectionHistoryClear",
        792732: "Ex2BSM_28_SendMessage",
        792736: "Ex2BSM_27_SendMessage",
        792740: "Ex2AHC_04_SendMessage",
        792744: "Ex2AHC_03_EndExtendedSession",
        792748: "Ex2AHC_03_SwitchServiceMode",
        792752: "Ex2AHC_03_ReadModeStatus",
        792756: "Ex2DCM_45_SendMessage",
        792760: "Ex2DCM_44_SendMessage",
        792764: "Ex2DCM_43_SendMessage",
        792768: "Ex2DCM_41_SendMessage",
        792772: "Ex2DCM_40_SendMessage",
        792776: "Ex2PLG_03_SendMessage",
        792780: "Ex2MM_41_TransferToPairingMode",
        792784: "Ex2AC_31_SendMessage",
        792788: "Ex2AC_30_SendMessage",
        792792: "Ex2ABS_52_WriteBrakePadResidualThickness",
        792796: "Ex2ABS_52_ReadBrakePadResidualThickness",
        792800: "Ex2VIF_02_SendMessage",
        792804: "Ex2VIF_01_SendMessage",
        792808: "Ex2VCIB_05_SendMessage",
        792812: "Ex2FRD_05_SendMessage",
        792816: "Ex2FRD_04_SendMessage",
        792820: "Ex2FCHV_14_SendMessage",
        792824: "Ex2FCHV_13_SendMessage",
        792828: "Ex2FCHV_12_SendMessage",
        792832: "Ex2FCHV_11_SendMessage",
        792836: "Ex2FCHV_10_SendMessage",
        792840: "Ex2EFI_62_SendMessage",
        792844: "Ex2EFI_61_WriteTotalShortTripEstimate",
        792848: "Ex2EFI_61_SupportCheck",
        792852: "Ex2ECT_16_SendMessage",
        792856: "Ex2ECO_14_SendMessage",
        792860: "Ex2EFI_59_SendMessage",
        792864: "Ex2FCM_12_StopPCSForcedBrakeActivation",
        792868: "Ex2FCM_12_CheckPCSForcedBrakeActivation",
        792872: "Ex2FCM_12_StartPCSForcedBrakeActivation",
        792876: "Ex2ECT_15_SendMessage",
        792880: "Ex2ABS_51_SendMessage",
        792884: "Ex2STRACT_04_SendMessage",
        792888: "Ex2STRACT_03_StartZeroPointAdjustment",
        792892: "Ex2STRACT_03_ClearZeroPointAdjustment",
        792896: "Ex2STRACT_03_StartTestMode",
        792900: "Ex2IVM_01_SendMessage",
        792904: "Ex2SetParaFromBroker",
        792908: "Ex2Initialize",
        792912: "Ex2Finalize",
        792916: "Ex2StopKeepAliveThread",
        792920: "Ex2GetThreadStatus",
        792924: "Ex2CmnPortClose",
        792928: "Ex2StopCmnThread",
        792932: "_Ex2ComSecurityAccessCGW@0",
        792936: "_Ex2ComEndDiagSessionCGW@0",
        792940: "Ex2STRACT_03_StartExtendedSession",
        792944: "Ex2APP_08_SendMessage",
        792948: "Ex2APP_07_SendMessage",
        792952: "Ex2VC_05_SendMessage",
        792956: "Ex2STRACT_03_EndExtendedSessionFinal",
        792960: "Ex2STRACT_03_EndExtendedSession",
        792964: "Ex2FCM_13_SendMessage",
        792968: "_Ex2InitializeDoIP@0",
    },
    "d9fc5bb2f9d7bd583a9fbe317c3d45a2ed4eb60b210ea9623a8230f3baec1e8d": {
        2256800: "Ex2TPW_03_SendMessage",
        2258500: "Ex24WD_05_WriteHistoryData",
        2258508: "Ex24WD_05_SendMessage",
        2258516: "Ex2AWD_04_ReadValues",
    },
}

_TY_INLINE_RETURNS = {
    ("TY18", "Ex2HV_12_SupportCheck", 20): 180000,
    ("TY18", "Ex2HV_12_SupportCheck", 21): 180000,
    ("TY12", "Ex2HV_12_SupportCheck", 20): 180000,
    ("TY12", "Ex2HV_12_SupportCheck", 21): 180000,
    ("TYPlus", "Ex2HV_12_SupportCheck", 20): 180000,
    ("TYPlus", "Ex2HV_12_SupportCheck", 21): 180000,
    ("TYPlus", "Ex2HV_12_SupportCheck", 22): 180000,
    ("TY18", "Ex2EFI_44_SessionTransition", 4): 4404,
    ("TY12", "Ex2EFI_44_SessionTransition", 4): 4404,
    ("TYPlus", "Ex2EFI_44_SessionTransition", 4): 4404,
    ("TY12", "Ex2DP2_11_SupportCheck", 20): 0,
    ("TY12", "Ex2DP2_11_SupportCheck", 21): 0,
    ("TY12", "Ex2DP2_12_GetSupportBitInformation", 20): 0,
    ("TY12", "Ex2DP2_12_GetSupportBitInformation", 21): 0,
}
_TY_RETURN_OVERRIDES = {
    ("TY18", "Ex2PI_01_GetAbsoTime"): 0,
    ("TY12", "Ex2PI_01_GetAbsoTime"): 0,
    ("TYPlus", "Ex2PI_01_GetAbsoTime"): 0,
}
_TY_MODE_MISMATCH_RETURNS = {
    ("TY18", "Ex2PI_01_GetAbsoTime"): 0,
    ("TY12", "Ex2PI_01_GetAbsoTime"): 0,
    ("TYPlus", "Ex2PI_01_GetAbsoTime"): 0,
}
