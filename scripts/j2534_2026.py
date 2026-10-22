"""Recovered CUW2026 J2534 host algorithms over typed, injected primitives.

No vendor library, adapter, socket or vehicle is opened by this module.
"""

import math
import sys
import threading
import time
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass, replace
from typing import Protocol

from scripts.programming import NativeTransportError

J2534_SHA256 = "d29da8dbdb7f08c6ff301e9f5859a9f407e3c9af68a6496410e8580ceae8bb08"
ADDRESS_SHA256 = "fd18f710af60ba9a1be979831ac2e878739ea577f3a1ba0d6edf0d7ce9b1e12d"


def _is_native_fault(error: BaseException) -> bool:
    # Lazy import keeps the compatibility re-export dependency acyclic.
    from scripts.programming_2026_common import is_native_exception2026

    return is_native_exception2026(error)


def unsigned(value: object) -> int:
    if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
        raise ValueError("Native unsigned 32-bit value required")
    return value


@dataclass(frozen=True)
class NativeMessage:
    protocol_id: int
    data: bytes
    rx_status: int = 0
    tx_flags: int = 0
    timestamp: int = 0
    extra_data_index: int = 0

    def __post_init__(self):
        for value in (
            self.protocol_id,
            self.rx_status,
            self.tx_flags,
            self.timestamp,
            self.extra_data_index,
        ):
            unsigned(value)
        if not isinstance(self.data, bytes) or len(self.data) > 4128:
            raise ValueError("Immutable bounded PASSTHRU_MSG Data required")
        if self.extra_data_index > len(self.data):
            raise ValueError("ExtraDataIndex exceeds DataSize")


@dataclass(frozen=True)
class NativeReadBatch2026:
    """Observed PASSTHRU_MSG backing records and independent reported count."""

    messages: tuple[NativeMessage, ...]
    count: int

    def __post_init__(self):
        if (
            not isinstance(self.messages, tuple)
            or len(self.messages) > 256
            or any(not isinstance(message, NativeMessage) for message in self.messages)
            or unsigned(self.count) > len(self.messages)
        ):
            raise ValueError("Bounded typed read backing and reported count required")


@dataclass(frozen=True)
class SpecifiedRead2026:
    """Native requested/output count is independent of first message backing."""

    message: NativeMessage
    count: int

    def __post_init__(self):
        if not isinstance(self.message, NativeMessage) or unsigned(self.count) > 1:
            raise ValueError("Typed single-message read result required")


@dataclass(frozen=True)
class PrimitiveResult:
    status: int = 0
    value: object = None

    def __post_init__(self):
        unsigned(self.status)


class PrimitiveProvider(Protocol):
    def __call__(self, operation: dict, remaining: float, /) -> PrimitiveResult: ...


def j2534_indication(rx_status: int, padding: bool = False) -> int:
    """RVA2b80: indication is determined by the low five status bits."""
    unsigned(rx_status)
    if type(padding) is not bool:
        raise TypeError("Boolean padding flag required")
    return {0: 3, 2: 1, 9: 0, 16: 2 if padding else 3}.get(rx_status & 31, 4)


class J2534Device2026:
    """Native CJ2534IF state; the provider only implements PassThru/OS calls.

    Provider return values are PrimitiveResult(status, value); successful void
    calls have value None, reads a tuple[NativeMessage,...], writes an int count.
    """

    def __init__(
        self,
        provider: PrimitiveProvider,
        *,
        timeout: float = 30,
        clock: Callable[[], float] = time.monotonic,
        cancelled: Callable[[], bool] = lambda: False,
        background_workers: bool = True,
        max_calls: int = 65536,
        max_cleanup_calls: int = 1024,
    ):
        if not callable(provider) or not callable(clock) or not callable(cancelled):
            raise TypeError("Callable provider, clock and cancellation required")
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            raise ValueError("Finite positive timeout required")
        if type(background_workers) is not bool:
            raise TypeError("Background worker selection must be boolean")
        if unsigned(max_calls) == 0 or unsigned(max_cleanup_calls) == 0:
            raise ValueError("Positive bounded host call budgets required")
        self.max_calls, self.max_cleanup_calls = max_calls, max_cleanup_calls
        self.routine_release_calls = 0
        self.background_workers = background_workers
        self._state_lock = threading.RLock()
        self._execution_context = threading.local()
        self._interface_pair: J2534InterfacePair2026 | None = None
        self.sync_worker: threading.Thread | None = None
        self.sync_stop = threading.Event()
        self.sync_error: BaseException | None = None
        self.ownership_thread: threading.Thread | None = None
        self._ownership_slot: threading.Thread | None = None
        self.ownership_ready: ManualResetEvent2026 | None = None
        self.ownership_release: ManualResetEvent2026 | None = None
        self.ownership_done = threading.Event()
        self.ownership_error: BaseException | None = None
        self.provider, self.clock, self.cancelled = provider, clock, cancelled
        self.deadline = clock() + timeout
        self.calls = 0
        self.cleanup_calls = 0
        self.protocol_id = 0
        self.device_id: int | None = None
        self.opened = False
        self.channel_id: int | None = None
        self._last_channel_id = 0
        self.connecting = False
        self.version = 0
        self.timeout = 0
        self.send_timeout = 1000
        self.padding = True
        self.voltage_enabled = False
        self.last_enabled = True
        self.history_sink: MessageHistory2026 | None = None
        self.filters: list[int] = []
        self.sil_filter_count = 2
        self.sil_filter_ids = [0, 0]
        self.sil_filter_active = [False, False]
        self.periodics: list[int] = []
        self.logical: dict[int, int] = {}
        self.sync: SyncPeriodic2026 | None = None
        self.previous_send_time = 0
        self.driver: DriverMetadata2026 | None = None
        self.driver_versions: list[DriverMetadata2026] = [
            DriverMetadata2026(),
            DriverMetadata2026(),
        ]
        self.shim_handle: int | None = None
        self.wrapper_handle: int | None = None
        self.driver_loaded = False
        self.symbols: dict[str, int] = {}
        self.function_slots = dict.fromkeys(range(0x60, 0xC4, 4), 0)
        self.temporary_libraries: list[int] = []
        self.ownership_mutex: int | None = None
        self.ownership_acquired = False

    @property
    def interface_pair(self) -> "J2534InterfacePair2026 | None":
        return self._interface_pair

    def _check(self):
        if (
            self.sync_error is not None
            and threading.current_thread() is not self.sync_worker
        ):
            raise self.sync_error
        if self.cancelled():
            raise InterruptedError("J2534 operation cancelled")
        deadline = (
            min(view.deadline for view in self._interface_pair._views)
            if self._interface_pair is not None
            else self.deadline
        )
        remaining = deadline - self.clock()
        if not math.isfinite(remaining) or remaining <= 0:
            raise TimeoutError("J2534 operation deadline expired")
        return remaining

    def _cleanup_remaining(self) -> float:
        deadline = getattr(self._execution_context, "cleanup_deadline", None)
        remaining = 5.0 if deadline is None else min(5.0, deadline - self.clock())
        if not math.isfinite(remaining) or remaining <= 0:
            raise TimeoutError("J2534 cleanup allowance expired")
        return remaining

    def _call(
        self,
        operation: str,
        *,
        cleanup=False,
        acquired=None,
        accepted=None,
        observed=None,
        ignore_status=False,
        **values,
    ):
        cleanup = cleanup or getattr(self._execution_context, "cleanup", False)
        remaining = self._cleanup_remaining() if cleanup else self._check()
        allowances = getattr(self._execution_context, "release_allowances", None)
        mutex = values.get("mutex")
        paired_release = bool(
            operation == "unlock" and allowances and allowances.get(mutex, 0)
        )
        if self._interface_pair is not None:
            self._interface_pair.validate_views()
        views = (
            self._interface_pair._views if self._interface_pair is not None else (self,)
        )
        with self._state_lock:
            if paired_release:
                # One attempt reserved by each successful Lock, even after cancellation.
                assert allowances is not None
                if allowances[mutex] == 1:
                    del allowances[mutex]
                else:
                    allowances[mutex] -= 1
                self.routine_release_calls += 1
            elif cleanup:
                self.cleanup_calls += 1
                if sum(view.cleanup_calls for view in views) > self.max_cleanup_calls:
                    raise ValueError("Host cleanup call budget exceeded")
            else:
                self.calls += 1
                if sum(view.calls for view in views) > self.max_calls:
                    raise ValueError("Host primitive call budget exceeded")
        started = self.clock()
        request = {"operation": operation, **values}
        result = (
            self._interface_pair._invoke(self, request, remaining)
            if self._interface_pair is not None
            else self.provider(request, remaining)
        )
        if not isinstance(result, PrimitiveResult):
            raise TypeError("Typed J2534 primitive result required")
        if observed is not None:
            observed(result)
        if result.status and not ignore_status:
            raise NativeJ2534Error2026(result.status)
        if operation == "lock":
            if allowances is None:
                allowances = {}
                self._execution_context.release_allowances = allowances
            allowances[mutex] = allowances.get(mutex, 0) + 1
        # Retain successful handles before a provider-triggered cancel/timeout.
        if acquired is not None:
            acquired(unsigned(result.value))
        if accepted is not None:
            accepted(result.value)
        if cleanup:
            if self.clock() - started >= remaining:
                raise TimeoutError("J2534 cleanup deadline expired")
        else:
            self._check()
        return result.value

    def _channel(self) -> int:
        if not self.connecting:
            raise ValueError("J2534 channel is not connected")
        return self.channel_id if self.channel_id is not None else 0

    def _acquired_device(self, handle: int):
        self.device_id, self.opened = handle, True

    def _acquired_channel(self, handle: int, protocol: int):
        self.channel_id, self.connecting, self.protocol_id = handle, True, protocol
        self._last_channel_id = handle

    def _closed_device(self):
        self.device_id, self.opened = None, False

    @property
    def last_message(self) -> tuple[int, bytes] | None:
        return self.history_sink.value if self.history_sink is not None else None

    @last_message.setter
    def last_message(self, value: tuple[int, bytes] | None):
        if self.history_sink is not None:
            self.history_sink.value = value

    def set_history_sink(self, sink: "MessageHistory2026 | None"):
        if sink is not None and not isinstance(sink, MessageHistory2026):
            raise TypeError("Typed optional native last-message sink required")
        if sink is not None:
            sink.__post_init__()
        self.history_sink = sink

    def _history(self, message: NativeMessage):
        # RVA5670 records before write mutation and only after a matching read.
        if self.last_enabled and self.protocol_id != 3:
            self.last_message = (
                5 if (message.rx_status | message.tx_flags) & 0x80 else 4,
                message.data,
            )

    def __copy__(self):
        raise TypeError("Native CJ2534IF copy construction is private")

    def __deepcopy__(self, _memo):
        raise TypeError("Native CJ2534IF copy construction is private")

    def get_dll_name(self, version: int | None = None) -> str:
        if version is None:
            driver = self.driver
        else:
            if type(version) is not int or version not in (0, 1):
                raise ValueError("Native J2534 version must be 0 or 1")
            driver = self.driver_versions[version]
        return driver.dll_name if driver is not None else ""

    def set_history_enabled(self, enabled: bool):
        if type(enabled) is not bool:
            raise TypeError("Native history-enable flag must be boolean")
        self.last_enabled = enabled

    def set_version(self, version: int):
        if type(version) is not int or version not in (0, 1):
            raise ValueError("Native J2534 version must be 0 or 1")
        self.version = version

    def set_opened(self, opened: bool):
        if type(opened) is not bool:
            raise TypeError("Native opened flag must be boolean")
        self.opened = opened
        if opened and self.device_id is None:
            self.device_id = 0

    def set_padding(self, padding: bool):
        if type(padding) is not bool:
            raise TypeError("Native padding flag must be boolean")
        self.padding = padding

    def set_current_driver(self, driver: "DriverMetadata2026"):
        """Native55a0 copies current strings without changing the two version records."""
        if not isinstance(driver, DriverMetadata2026):
            raise TypeError("Typed J2534 driver metadata required")
        driver.__post_init__()
        self.driver = replace(driver)

    def set_driver(self, driver: "DriverMetadata2026"):
        """Host selection convenience: supply current and selected-version metadata."""
        self.set_current_driver(driver)
        self.driver_versions[self.version] = replace(driver)

    def _symbol(self, handle: int, name: str) -> int:
        return unsigned(self._call("get_symbol", handle=handle, name=name))

    def load_driver(self):
        if self.driver is None:
            raise ValueError("J2534 driver metadata is not selected")
        if self.shim_handle is None:
            self._call(
                "load_library",
                name="ptshim32_0500.dll" if self.version == 1 else "ptshim32.dll",
                acquired=lambda handle: setattr(self, "shim_handle", handle),
            )
            if self.shim_handle == 0:
                self.shim_handle = None
                raise NativePassThruError2026(2)
        names = (
            "PassThruOpen",
            "PassThruClose",
            "PassThruConnect",
            "PassThruDisconnect",
        )
        if self.version == 1:
            names = (
                ("PassThruGetNextDevice", "PassThruScanForDevices")
                + names
                + (
                    "PassThruLogicalConnect",
                    "PassThruLogicalDisconnect",
                    "PassThruReadMsgs",
                    "PassThruQueueMsgs",
                    "PassThruIoctl",
                    "PassThruReadVersion",
                )
            )
        else:
            names += (
                "PassThruReadMsgs",
                "PassThruWriteMsgs",
                "PassThruStartMsgFilter",
                "PassThruStopMsgFilter",
                "PassThruSetProgrammingVoltage",
                "PassThruIoctl",
                "PassThruReadVersion",
                "PassThruStartPeriodicMsg",
                "PassThruStopPeriodicMsg",
            )
        names += ("PassThruLoadLibrary", "PassThruUnloadLibrary", "PassThruSaveLog")
        for name in names:
            symbol = self._symbol(unsigned(self.shim_handle), name)
            self.symbols[name] = symbol
            slots = (
                {
                    "PassThruGetNextDevice": 0xA0,
                    "PassThruScanForDevices": 0xA4,
                    "PassThruOpen": 0xA8,
                    "PassThruClose": 0x64,
                    "PassThruConnect": 0xAC,
                    "PassThruDisconnect": 0x6C,
                    "PassThruLogicalConnect": 0xB0,
                    "PassThruLogicalDisconnect": 0xB4,
                    "PassThruReadMsgs": 0xB8,
                    "PassThruQueueMsgs": 0xBC,
                    "PassThruIoctl": 0x84,
                    "PassThruReadVersion": 0x88,
                    "PassThruLoadLibrary": 0x94,
                    "PassThruUnloadLibrary": 0x98,
                    "PassThruSaveLog": 0x9C,
                }
                if self.version == 1
                else dict(zip(names, range(0x60, 0xA0, 4), strict=True))
            )
            self.function_slots[slots[name]] = symbol
            if not symbol:
                raise NativePassThruError2026(2)
        if self.wrapper_handle is None:
            self._call(
                "load_library",
                name="MsgDatCommWrapper.dll",
                acquired=lambda handle: setattr(self, "wrapper_handle", handle),
            )
            if not self.wrapper_handle:
                self.wrapper_handle = None
                raise NativePassThruError2026(2)
            symbol = self._symbol(self.wrapper_handle, "ER_SetCommunicationLogModeCS")
            self.function_slots[0xC0] = symbol
            if not symbol:
                raise NativePassThruError2026(2)
        try:
            self._call(
                "passthru_load_library",
                name=self.driver.dll_name,
                accepted=lambda _: setattr(self, "driver_loaded", True),
            )
        except NativeTransportError as exc:
            raise NativePassThruError2026(2) from exc
        self.driver_loaded = True

    def unload_driver(self):
        if self.shim_handle is not None:
            self._call(
                "passthru_unload_library",
                cleanup=True,
                ignore_status=True,
                accepted=lambda _: setattr(self, "driver_loaded", False),
            )

    def unload_shim(self):
        if self.shim_handle is not None:
            self._call(
                "free_library",
                handle=self.shim_handle,
                cleanup=True,
                accepted=lambda _: setattr(self, "shim_handle", None),
            )

    def close(self):
        if self.opened:
            self._call(
                "passthru_close",
                device=self.device_id,
                cleanup=True,
                ignore_status=True,
                accepted=lambda _: self._closed_device(),
            )

    def read_device_version(self) -> tuple[str, str, str]:
        if not self.opened:
            raise ValueError("Open J2534 device required")
        versions = [("", "", "")]

        def observed(result: PrimitiveResult):
            value = result.value
            if value is None and result.status:
                value = (
                    "",
                    "",
                    "",
                )  # Native43c0 initializes all three buffers to zero.
            if (
                not isinstance(value, tuple)
                or len(value) != 3
                or any(
                    not isinstance(text, str) or len(text) >= 80 or "\0" in text
                    for text in value
                )
            ):
                raise ValueError("Three bounded native version strings required")
            versions[0] = value

        try:
            self._call(
                "passthru_read_version", device=self.device_id, observed=observed
            )
        except NativePassThruError2026 as error:
            error.versions = versions[0]
            raise
        return versions[0]

    @staticmethod
    def _cleanup_steps(*steps: Callable[[], object]):
        """Attempt remaining host cleanup without replacing an unwinding failure."""
        primary = sys.exception()
        first = None
        for step in steps:
            try:
                step()
            except BaseException as error:  # noqa: BLE001 - preserve primary while attempting cleanup
                retained = primary if primary is not None else first
                if retained is None:
                    first = error
                else:
                    retained.add_note("J2534 cleanup failed: " + str(error))
        if primary is None and first is not None:
            raise first

    def get_device_info(self, previous: tuple[str, str, str, str] | None = None):
        if self.driver is None:
            raise ValueError("J2534 driver metadata is not selected")
        if previous is not None and (
            not isinstance(previous, tuple)
            or len(previous) != 4
            or any(
                not isinstance(text, str) or len(text) > 32767 or "\0" in text
                for text in previous
            )
        ):
            raise ValueError("Four bounded preceding device-info strings required")
        versions = previous[1:] if previous is not None else ("", "", "")
        temporary_open = not self.opened
        temporary_load = not self.driver_loaded
        loaded_here = False
        try:
            if temporary_open:
                if temporary_load:
                    self.load_driver()
                    loaded_here = True
                self.open()
            try:
                versions = self.read_device_version()
            except NativePassThruError2026 as error:
                if error.versions is not None:
                    versions = error.versions
                raise
        except Exception as error:
            if not _is_native_fault(error):
                raise
            # Native29e0 catch-all2ac5 continues to cleanup2ad7 and returns.
        finally:
            self._cleanup_steps(
                lambda: self.close() if temporary_open and self.opened else None,
                lambda: (
                    self.unload_driver()
                    if temporary_load and (loaded_here or self.driver_loaded)
                    else None
                ),
            )
        return (self.driver.device_name,) + versions

    def output_shim_log(self, path: str):
        if not isinstance(path, str) or not path or len(path) > 32767 or "\0" in path:
            raise ValueError("Bounded nonempty native log path required")
        self._call("passthru_save_log", path=path)

    def set_communication_log_mode(self, mode: int) -> int:
        if type(mode) is not int or not -0x80000000 <= mode <= 0x7FFFFFFF:
            raise ValueError("Native signed communication log mode required")
        result = self._call("set_communication_log_mode", mode=mode)
        if type(result) is not int or not -0x80000000 <= result <= 0x7FFFFFFF:
            raise ValueError("Native signed communication log result required")
        return result

    def query_device_info(self, parameter: int) -> "DeviceInfo2026":
        unsigned(parameter)
        if not self.opened:
            raise ValueError("Open J2534 device required")
        info = [DeviceInfo2026(parameter, 0, 0)]

        def observed(result: PrimitiveResult):
            value = result.value
            if value is None and result.status:
                value = info[0]
            if not isinstance(value, DeviceInfo2026) or value.parameter != parameter:
                raise ValueError("Typed correlated native device-info result required")
            info[0] = value

        try:
            self._call(
                "passthru_ioctl",
                channel=self.device_id,
                ioctl=0x800C,
                parameters=(parameter,),
                count=1,
                observed=observed,
            )
        except NativePassThruError2026 as error:
            error.device_info = info[0]
            raise
        return info[0]

    def supports_can_fd(self) -> bool:
        if self.opened:
            return False
        temporary_load = not self.driver_loaded
        loaded_here = False
        try:
            if temporary_load:
                self.load_driver()
                loaded_here = True
            try:
                self.open(2)
            except Exception as error:
                if not _is_native_fault(error):
                    raise
                # Native3417 retries Open(1); a successful fallback still returns false.
                self.open(1)
                return False
            try:
                return self.query_device_info(0x4D).supported == 1
            except Exception as error:
                if not _is_native_fault(error):
                    raise
                return False  # Native333fd catches the capability-query native fault.
        finally:
            self._cleanup_steps(
                lambda: self.close() if self.opened else None,
                lambda: (
                    self.unload_driver()
                    if temporary_load and (loaded_here or self.driver_loaded)
                    else None
                ),
            )

    def _temporary_library(self) -> int:
        if self.driver is None:
            raise ValueError("J2534 driver metadata is not selected")
        return unsigned(
            self._call(
                "load_library",
                name=self.driver.dll_name,
                acquired=self.temporary_libraries.append,
            )
        )

    def _free_temporary_library(self, handle: int):
        if handle:
            self._call(
                "free_library",
                handle=handle,
                cleanup=True,
                accepted=lambda _: self.temporary_libraries.remove(handle),
            )
        else:
            self.temporary_libraries.remove(handle)

    def wireless_device_kind(self) -> int:
        handle = self._temporary_library()
        try:
            if handle and self._symbol(handle, "_GtsNewVimFixInterface@8"):
                return 1
        finally:
            self._cleanup_steps(lambda: self._free_temporary_library(handle))
        temporary_open = not self.opened
        try:
            if temporary_open:
                try:
                    self.open()
                except Exception as error:
                    if not _is_native_fault(error):
                        raise
                    # Native2d26 continues into GetDeviceInfo after the first Open fault.
            return 2 if "MongoosePro" in self.get_device_info()[1] else 0
        finally:
            self._cleanup_steps(
                lambda: self.close() if temporary_open and self.opened else None
            )

    def dsti_fix_interface(self, mode: int):
        unsigned(mode)
        handle = self._temporary_library()
        try:
            if handle:
                symbol = self._symbol(handle, "_GtsNewVimFixInterface@8")
                if symbol:
                    self._call("call_symbol", symbol=symbol, arguments=(0, 0))
                    self._call("call_symbol", symbol=symbol, arguments=(mode, 0))
        finally:
            self._cleanup_steps(lambda: self._free_temporary_library(handle))

    def is_wireless_connecting(self, kind: int = 0):
        if kind not in (0, 1, 2):
            raise ValueError("Native wireless device enum required")
        temporary_load = not self.driver_loaded
        loaded_here = False
        try:
            if temporary_load:
                try:
                    self.load_driver()
                    loaded_here = True
                except Exception as error:
                    if not _is_native_fault(error):
                        raise
                    # Native3510 catch3575 continues into the selected probe.
            if kind == 0:
                kind = self.wireless_device_kind()
            if kind == 2:
                temporary_open = not self.opened
                info = DeviceInfo2026(0x100, 0, 0)
                try:
                    try:
                        if temporary_open:
                            self.open()
                        info = self.query_device_info(0x100)
                    except Exception as error:
                        if not _is_native_fault(error):
                            raise
                        observed_info = getattr(error, "device_info", None)
                        if observed_info is not None:
                            info = observed_info
                    return bool(info.supported) and info.value == 3
                finally:
                    self._cleanup_steps(
                        lambda: self.close() if temporary_open else None
                    )
            if kind == 1:
                handle = self._temporary_library()
                symbol = 0
                try:
                    if not handle:
                        return False
                    symbol = self._symbol(handle, "_GtsNewVimFixInterface@8")
                    if not symbol:
                        return False
                    self.close()
                    self._call("call_symbol", symbol=symbol, arguments=(0, 0))
                    self._call("call_symbol", symbol=symbol, arguments=(4, 0))
                    try:
                        self.open()
                    except Exception as error:
                        if not _is_native_fault(error):
                            raise
                        return False  # Native35f0 catch3697 still resets/frees the DLL.
                    return True
                finally:
                    self._cleanup_steps(
                        lambda: self.close() if symbol else None,
                        lambda: (
                            self._call(
                                "call_symbol",
                                symbol=symbol,
                                arguments=(0, 0),
                                cleanup=True,
                            )
                            if symbol
                            else None
                        ),
                        lambda: self._free_temporary_library(handle),
                    )
            return False
        finally:
            self._cleanup_steps(
                lambda: (
                    self.unload_driver()
                    if temporary_load and (loaded_here or self.driver_loaded)
                    else None
                )
            )

    def clear(self):
        self.disconnect()
        self.unload_shim()
        if self.wrapper_handle is not None:
            self._call(
                "free_library",
                handle=self.wrapper_handle,
                cleanup=True,
                accepted=lambda _: setattr(self, "wrapper_handle", None),
            )
        for handle in tuple(reversed(self.temporary_libraries)):
            self._free_temporary_library(handle)
        self.driver = None
        self.driver_versions = [DriverMetadata2026(), DriverMetadata2026()]
        self.version = 0
        self.timeout, self.send_timeout = 0, 1000
        self.padding, self.voltage_enabled = True, False
        self.logical.clear()
        self.sil_filter_count = 2
        self.sil_filter_ids, self.sil_filter_active = [0, 0], [False, False]
        self.previous_send_time = 0
        self._last_channel_id = 0
        self.symbols.clear()
        self.function_slots = dict.fromkeys(range(0x60, 0xC4, 4), 0)
        for event in (self.ownership_ready, self.ownership_release):
            if event is not None:
                event.close()
        self.ownership_ready, self.ownership_release = None, None

    def _acquire_ownership_mutex(self):
        if self.ownership_acquired:
            return
        if self.ownership_mutex is None:
            self._call(
                "create_mutex",
                name="TECHSTREAM_MUTEX_J2534",
                acquired=lambda handle: setattr(self, "ownership_mutex", handle),
            )
        if not self.ownership_mutex:
            self.ownership_mutex = None
            raise NativePassThruError2026(2)
        for milliseconds in (0, 500):
            status = unsigned(
                self._call(
                    "wait_handle",
                    handle=self.ownership_mutex,
                    milliseconds=milliseconds,
                    accepted=lambda result: setattr(
                        self, "ownership_acquired", unsigned(result) == 0
                    ),
                )
            )
            if status == 0:
                self.ownership_acquired = True
                return
        self._call(
            "close_handle",
            handle=self.ownership_mutex,
            cleanup=True,
            accepted=lambda _: setattr(self, "ownership_mutex", None),
        )
        raise NativePassThruError2026(2)

    def _release_ownership_mutex(self):
        if self.ownership_mutex is not None:
            if self.ownership_acquired:
                self._call(
                    "release_mutex",
                    handle=self.ownership_mutex,
                    cleanup=True,
                    accepted=lambda _: setattr(self, "ownership_acquired", False),
                )
            self._call(
                "close_handle",
                handle=self.ownership_mutex,
                cleanup=True,
                accepted=lambda _: setattr(self, "ownership_mutex", None),
            )

    def _ownership_worker(self, cleanup_deadline: float | None = None):
        try:
            try:
                if cleanup_deadline is not None:
                    self._execution_context.cleanup = True
                    self._execution_context.cleanup_deadline = cleanup_deadline
                self._acquire_ownership_mutex()
            finally:
                # The worker can own the mutex beyond the caller's acquisition allowance.
                self._execution_context.cleanup = False
                self._execution_context.cleanup_deadline = None
            assert (
                self.ownership_ready is not None and self.ownership_release is not None
            )
            self.ownership_ready.set()
            self.ownership_release.wait()
            self.ownership_release.clear()
        except BaseException as exc:  # noqa: BLE001 - transfer worker failure to its owner
            self.ownership_error = exc
        finally:
            try:
                self._release_ownership_mutex()
            except BaseException as exc:  # noqa: BLE001 - transfer worker failure to its owner
                if self.ownership_error is None:
                    self.ownership_error = exc
                else:
                    self.ownership_error.add_note(
                        "J2534 ownership cleanup failed: " + str(exc)
                    )
            if self.ownership_release is not None:
                self.ownership_release.worker_error = self.ownership_error
            self.ownership_done.set()

    def have_ownership(self):
        if not self.background_workers:
            return self._acquire_ownership_mutex()
        if self.ownership_thread is not None and self.ownership_thread.is_alive():
            return
        if self.ownership_ready is None:
            self.ownership_ready = ManualResetEvent2026()
        if self.ownership_release is None:
            self.ownership_release = ManualResetEvent2026()
        self.ownership_ready.clear()
        self.ownership_release.clear()
        self.ownership_done.clear()
        self.ownership_error = None
        self.ownership_release.worker_error = None
        self.ownership_thread = threading.Thread(
            target=self._ownership_worker,
            args=(getattr(self._execution_context, "cleanup_deadline", None),),
            name="CUW2026-J2534-ownership",
            daemon=True,
        )
        self._ownership_slot = self.ownership_thread
        self.ownership_thread.start()
        while not self.ownership_ready.wait(0.005):
            self._check()
            if self.ownership_done.is_set():
                if self.ownership_error is not None:
                    self.ownership_release.worker_error = None
                    raise self.ownership_error
                raise NativePassThruError2026(2)
        self.ownership_ready.clear()
        self._check()
        if not self.ownership_thread.is_alive():
            raise NativePassThruError2026(2)

    def release_ownership(self):
        worker = self.ownership_thread
        if worker is None:
            return self._release_ownership_mutex()
        was_alive = worker.is_alive()
        if was_alive:
            if self.ownership_release is None:
                raise ValueError("Imported ownership worker lacks release event")
            self.ownership_release.set()
            worker.join(timeout=self._cleanup_remaining())
            if worker.is_alive():
                raise TimeoutError(
                    "Native ownership worker did not release within cleanup allowance"
                )
        self.ownership_thread = None
        if was_alive:
            self._ownership_slot = None
        error = (
            self.ownership_release.worker_error
            if self.ownership_release is not None
            else self.ownership_error
        )
        if error is not None:
            if self.ownership_release is not None:
                self.ownership_release.worker_error = None
            self.ownership_error = None
            raise error

    def connect_native(self, protocol_id: int):
        self._connect_native_core(protocol_id)
        if self.protocol_id == 0x8012:
            self._configure_connected_can_fd()

    def _connect_native_core(self, protocol_id: int):
        """Source2550/1f50 driver-selection path over explicitly typed metadata."""
        unsigned(protocol_id)
        self.have_ownership()
        self.last_enabled, self.last_message = True, None
        self._open_and_connect_native(protocol_id)

    def connect_0500(self, protocol_id: int):
        """Native1f50 core entry: no ownership acquisition or history reset."""
        if self.version != 1:
            raise ValueError("Native Connect0500 requires version0500")
        unsigned(protocol_id)
        self._open_and_connect_native(protocol_id)

    def _open_and_connect_native(self, protocol_id: int):
        self.load_driver()
        kind = self.wireless_device_kind()
        if kind == 1:
            self.dsti_fix_interface(1)
        self.open(2 if protocol_id == 0x8012 else 0)
        if kind == 2 and self.is_wireless_connecting(2):
            self.close()
            raise NativeJ2534Error2026(0)
        self._connect_channel(protocol_id)

    def export_data(
        self, previous: "NativeInterfaceData2026 | None" = None
    ) -> "NativeInterfaceData2026":
        """RVA27c0: logical channels, sync state, loaded/history-enable flags are absent."""
        if previous is not None and not isinstance(previous, NativeInterfaceData2026):
            raise TypeError("Typed preceding native interface data required")
        driver = (
            self.driver
            if self.driver is not None
            else previous.driver
            if previous is not None
            else None
        )
        sil_ids = list(previous.sil_ids) if previous is not None else [0, 0]
        sil_active = (
            list(previous.sil_active) if previous is not None else [False, False]
        )
        sil_ids[: self.sil_filter_count] = self.sil_filter_ids[: self.sil_filter_count]
        sil_active[: self.sil_filter_count] = self.sil_filter_active[
            : self.sil_filter_count
        ]
        return NativeInterfaceData2026(
            self.provider,
            self.device_id or 0,
            self.opened,
            self.protocol_id,
            self.channel_id if self.channel_id is not None else self._last_channel_id,
            self.version,
            self.shim_handle,
            self.connecting,
            self.timeout,
            self.send_timeout,
            driver,
            tuple(self.driver_versions),
            self.sil_filter_count,
            tuple(sil_ids),
            tuple(sil_active),
            self.voltage_enabled,
            self.padding,
            self.ownership_thread or self._ownership_slot,
            self.ownership_ready,
            self.ownership_release,
            self.wrapper_handle,
            self.history_sink,
            tuple(self.function_slots[offset] for offset in range(0x60, 0xC4, 4)),
        )

    def import_data(self, data: "NativeInterfaceData2026"):
        """RVA3020 typed transfer; unrelated active ownership cannot be discarded."""
        return self._import_data(data)

    def _import_data(self, data: "NativeInterfaceData2026", *, _issuer=None):
        """Only the bound source-issued pair may replace active transferred state."""
        if not isinstance(data, NativeInterfaceData2026):
            raise TypeError("Typed native interface data required")
        data.__post_init__()
        if data.driver is None:
            raise ValueError(
                "Native imported current-driver string pointers are missing"
            )
        if _issuer is not None and (
            _issuer is not self._interface_pair
            or not _issuer._accepts_import(self, data)
        ):
            raise ValueError("Foreign native interface transfer issuer")
        if _issuer is None and (
            self.opened
            or self.connecting
            or self.shim_handle is not None
            or self.wrapper_handle is not None
            or self.sync is not None
            or self.ownership_mutex is not None
            or (self.ownership_thread is not None and self.ownership_thread.is_alive())
        ):
            current = self.export_data(data)
            if data == current and all(
                getattr(data, name) is getattr(current, name)
                for name in (
                    "provider",
                    "ownership_thread",
                    "ownership_ready",
                    "ownership_release",
                    "history_sink",
                )
            ):
                # Equivalent re-import must preserve unexported local resource owners.
                return
            raise ValueError("Import receiver must not discard owned native resources")
        self.provider = data.provider
        self.device_id, self.opened = data.device_id, data.opened
        self.protocol_id, self.channel_id = data.protocol_id, data.channel_id
        self._last_channel_id = data.channel_id
        self.version, self.shim_handle = data.version, data.shim_handle
        self.connecting, self.timeout, self.send_timeout = (
            data.connecting,
            data.timeout,
            data.send_timeout,
        )
        self.driver = replace(data.driver)
        self.driver_versions = [replace(driver) for driver in data.drivers]
        preceding_sil = {
            identifier
            for identifier, active in zip(
                self.sil_filter_ids[: self.sil_filter_count],
                self.sil_filter_active[: self.sil_filter_count],
                strict=True,
            )
            if active
        }
        retained_filters = (
            [
                identifier
                for identifier in self.filters
                if identifier not in preceding_sil
            ]
            if _issuer is not None
            else []
        )
        self.sil_filter_count = data.sil_filter_count
        self.sil_filter_ids[: data.sil_filter_count] = data.sil_ids[
            : data.sil_filter_count
        ]
        self.sil_filter_active[: data.sil_filter_count] = data.sil_active[
            : data.sil_filter_count
        ]
        self.filters = retained_filters + [
            identifier
            for identifier, active in zip(
                self.sil_filter_ids[: self.sil_filter_count],
                self.sil_filter_active[: self.sil_filter_count],
                strict=True,
            )
            if active
        ]
        self.voltage_enabled, self.padding = data.voltage_enabled, data.padding
        self.ownership_thread = data.ownership_thread
        self._ownership_slot = data.ownership_thread
        self.ownership_ready, self.ownership_release = (
            data.ownership_ready,
            data.ownership_release,
        )
        self.wrapper_handle, self.history_sink = data.wrapper_handle, data.history_sink
        self.function_slots = dict(
            zip(range(0x60, 0xC4, 4), data.function_slots, strict=True)
        )

    def open(self, spec_version: int = 0):
        unsigned(spec_version)
        if self.version not in (0, 1):
            raise ValueError("Native J2534 version must be 0 or 1")
        if self.opened:
            raise ValueError("J2534 device already open")
        name = "J2534-2:" if spec_version == 2 else None
        if self.version == 1:
            count = unsigned(self._call("passthru_scan_devices"))
            if count == 0:
                raise NativeJ2534Error2026(0)
            discovered = self._call("passthru_next_device")
            if (
                not isinstance(discovered, str)
                or not discovered
                or len(discovered) > 103
                or "\0" in discovered
            ):
                raise ValueError("Bounded native 0500 device name required")
            name = "J2534-2:" + discovered
        self._call(
            "passthru_open",
            name=name,
            version=self.version,
            acquired=self._acquired_device,
        )

    def open_0500(self):
        if self.version != 1:
            raise ValueError("Native Open0500 requires version0500")
        self.open()

    def connect(self, protocol_id: int):
        self.last_enabled, self.last_message = True, None
        self._connect_channel(protocol_id)
        if self.protocol_id == 0x8012:
            self._configure_connected_can_fd()

    def _configure_connected_can_fd(self):
        try:
            self.configure_can_fd(True)
        except Exception as error:
            if not _is_native_fault(error):
                raise
            # Native2242/63a4: full Disconnect, core reconnect, then configure(FALSE).
            self.disconnect()
            if self.driver is not None:
                self._connect_native_core(0x8012)
            else:
                self.open(2)
                self._connect_channel(0x8012)
            self.configure_can_fd(False)

    def _connect_channel(self, protocol_id: int, *, classic: bool = False):
        unsigned(protocol_id)
        if self.version not in (0, 1):
            raise ValueError("Native J2534 version must be 0 or 1")
        if protocol_id == 0x800F and self.version != 1:
            raise ValueError("Ethernet requires native J2534 version 0500")
        if self.connecting or not self.opened:
            raise ValueError("Open device and unconnected channel required")
        if self.version == 1 and not classic:
            self._call(
                "passthru_ioctl", channel=self.device_id, ioctl=3, resource=(1, 1, (8,))
            )
            self._call(
                "passthru_ioctl", channel=self.device_id, ioctl=0x8022, resource=0x1FE
            )
            self._call(
                "passthru_connect_0500",
                device=self.device_id,
                protocol=protocol_id,
                flags=0,
                baud=100000000,
                resources=(1, 4, (3, 11, 12, 13)),
                acquired=lambda handle: self._acquired_channel(handle, protocol_id),
            )
            self.protocol_id = protocol_id
            return
        flags = (
            0x1200 if protocol_id == 3 else 0x900 if protocol_id in (6, 0x8012) else 0
        )
        baud = (
            10400
            if protocol_id == 3
            else 500000
            if protocol_id in (5, 6, 0x8012)
            else 0
        )
        self._call(
            "passthru_connect",
            device=self.device_id,
            protocol=protocol_id,
            flags=flags,
            baud=baud,
            acquired=lambda handle: self._acquired_channel(handle, protocol_id),
        )
        self.protocol_id = protocol_id
        if protocol_id == 3:
            self.start_sil_filters()

    def control_io(self, ioctl: int, parameters=()):
        return self._control_io(ioctl, parameters, resource=16)

    def control_io_0500(self, ioctl: int, parameters=(), resource: int = 16):
        """Native2280 direct entry retains its explicit resource argument."""
        if self.version != 1:
            raise ValueError("Native ControlIO0500 requires version0500")
        return self._control_io(ioctl, parameters, resource=unsigned(resource))

    def _control_io(self, ioctl: int, parameters, *, resource: int):
        unsigned(ioctl)
        if not isinstance(parameters, tuple) or any(
            not isinstance(pair, tuple) or len(pair) != 2 for pair in parameters
        ):
            raise ValueError("Typed configuration parameter pairs required")
        for key, value in parameters:
            unsigned(key)
            unsigned(value)
        if self.version == 1:
            if ioctl not in (1, 2, 3, 8, 0x8022, 0x800C):
                return None
            handle = (
                (self.device_id or 0)
                if ioctl in (3, 0x8022, 0x800C)
                else self.logical.get(0x8208, 0)
                if ioctl == 8
                else self._channel()
            )
            if ioctl == 3:
                return self._call(
                    "passthru_ioctl",
                    channel=handle,
                    ioctl=3,
                    resource=(1, 1, (resource,)),
                )
        else:
            handle = (
                (self.device_id or 0) if ioctl in (3, 14, 0x800C) else self._channel()
            )
        return self._call(
            "passthru_ioctl",
            channel=handle,
            ioctl=ioctl,
            parameters=parameters,
            protocol=self.protocol_id if ioctl == 5 else None,
        )

    def configure_can_fd(self, extended: bool):
        if type(extended) is not bool:
            raise TypeError("Boolean CAN FD configuration flag required")
        parameters = ((0x805C, 2000000), (0x8001, 0x60E), (0x805D, 0x20))
        if extended:
            parameters += ((0x805E, 3),)
        self.control_io(2, parameters + ((0x805F, 1000), (0x8060, 0xCC)))

    def five_baud_init(self, data: bytes) -> bytes:
        if not isinstance(data, bytes) or len(data) != 1:
            raise ValueError(
                "One-byte native five-baud initialization address required"
            )
        result = self._call(
            "passthru_ioctl", channel=self._channel(), ioctl=4, data=data, capacity=256
        )
        if not isinstance(result, bytes) or len(result) > 256:
            raise ValueError("Bounded native five-baud initialization output required")
        return result

    def fast_init(self, data: bytes, tx_flags: int = 0) -> NativeMessage:
        message = NativeMessage(self.protocol_id, data, tx_flags=unsigned(tx_flags))
        result = self._call(
            "passthru_ioctl", channel=self._channel(), ioctl=5, message=message
        )
        if not isinstance(result, NativeMessage):
            raise TypeError("FAST_INIT must return typed native message")
        return result

    def read_messages(self, count: int = 1, protocol_id: int | None = None):
        result = self.read_messages_result(count, protocol_id)
        return result.messages[: result.count]

    def read_messages_result(self, count: int = 1, protocol_id: int | None = None):
        unsigned(count)
        if count > 256:
            raise ValueError("Host read count must be 0..256")
        protocol = self.protocol_id if protocol_id is None else unsigned(protocol_id)
        channel = self.logical.get(protocol, self._channel())
        result = self._call(
            "passthru_read",
            channel=channel,
            protocol=protocol,
            count=count,
            timeout=self.timeout,
            version=self.version,
        )
        if isinstance(result, tuple):
            result = NativeReadBatch2026(result, len(result))
        if (
            not isinstance(result, NativeReadBatch2026)
            or result.count > count
            or len(result.messages) > max(1, count)
        ):
            raise ValueError("Bounded typed J2534 read messages required")
        return result

    def logical_connect(
        self, protocol: int, descriptor: bytes = b"", *, discovery=False
    ):
        if self.version != 1:
            raise ValueError("Logical channels require J2534 version 0500")
        unsigned(protocol)
        if (
            type(discovery) is not bool
            or not isinstance(descriptor, bytes)
            or len(descriptor) > 260
        ):
            raise ValueError("Bounded typed logical channel descriptor required")
        if protocol == 0x8203:
            parent, native_descriptor, slot = self._channel(), (1, 10000, 0, 0), 0x8203
        elif protocol == 0x8205:
            parent = self.logical.get(0x8203)
            native_descriptor = (0x3458 if discovery else 0xC000,)
            slot = 0x8207 if discovery else 0x8205
        elif protocol == 0x8206 and not discovery:
            parent = self.logical.get(0x8203)
            if len(descriptor) < 4:
                raise ValueError("TCP client descriptor requires four-byte prefix")
            native_descriptor, slot = b"\x01\xc0\x58\x34" + descriptor[4:], 0x8208
        else:
            raise ValueError("Unsupported native logical channel protocol")
        if parent is None or slot in self.logical:
            raise ValueError("Logical parent required and slot must be unconnected")
        handle = self._call(
            "passthru_logical_connect",
            channel=parent,
            protocol=protocol,
            flags=0,
            descriptor=native_descriptor,
            acquired=lambda handle: self.logical.__setitem__(slot, handle),
        )
        if discovery:
            self._call("passthru_ioctl", channel=handle, ioctl=8, parameters=())
        return unsigned(handle)

    def logical_disconnect(self, protocol: int, *, discovery=False):
        unsigned(protocol)
        slot = 0x8207 if discovery else 0x8208 if protocol == 0x8206 else protocol
        if not discovery and protocol not in (0x8203, 0x8205, 0x8206):
            raise ValueError("Native logical-disconnect protocol required")
        self._call(
            "passthru_logical_disconnect",
            channel=self.logical.get(slot, 0),
            cleanup=True,
            accepted=lambda _: self.logical.pop(slot, None),
        )

    def read_buffer(self, protocol: int, requested: int):
        unsigned(protocol)
        unsigned(requested)
        if requested > 4128:
            raise ValueError("Bounded native 0500 read capacity required")
        if self.version != 1:
            raise ValueError("Byte-buffer reads require J2534 0500")
        channel = self.logical.get(protocol, self._channel())
        result = self._call(
            "passthru_read_buffer",
            channel=channel,
            protocol=protocol,
            count=requested,
            timeout=0 if protocol == 0x8207 else self.timeout,
        )
        if not isinstance(result, BufferRead2026) or result.count > requested:
            raise ValueError("Typed bounded native 0500 buffer result required")
        return result

    def read_tcp(self):
        header = self.read_buffer(0x8208, 8)
        if len(header.message.data) < 8:
            raise ValueError("TCP native header backing is truncated")
        length = int.from_bytes(header.message.data[4:8], "big")
        return self.read_buffer(0x8208, length)

    def queue_message(self, message: NativeMessage, count: int = 1):
        if not isinstance(message, NativeMessage) or self.version != 1:
            raise ValueError("Typed native 0500 message required")
        unsigned(count)
        if count > 1:
            raise ValueError("One typed queue message cannot supply a larger count")
        channel = self.logical.get(message.protocol_id, self._channel())
        accepted = unsigned(
            self._call("passthru_queue", channel=channel, message=message, count=count)
        )
        if accepted > count:
            raise ValueError("Queue count exceeds supplied messages")
        return accepted

    def write_tcp(self, message: NativeMessage, count: int = 1):
        if not isinstance(message, NativeMessage) or len(message.data) < 12:
            raise ValueError("TCP native request header is truncated")
        written = self.queue_message(message, count)
        expected = message.data[10:12] + message.data[8:10]
        while True:
            response = self.read_tcp()
            if (
                response.count
                and len(response.message.data) >= 4
                and response.message.data[:4] == expected
            ):
                return written

    def read_indication(self, address: bytes | None = None):
        if address is None:
            messages = self.read_messages_result().messages
            return j2534_indication(
                messages[0].rx_status if messages else 0, self.padding
            )
        self._address(address)
        while True:
            for message in self.read_messages_result().messages:
                if address is None or message.data.startswith(address):
                    indication = j2534_indication(message.rx_status, self.padding)
                    if address is None or indication != 4:
                        return indication

    def read_after_indication(self, count: int = 1):
        result = self.read_after_indication_result(count)
        return result.messages[: result.count]

    def read_after_indication_result(self, count: int = 1):
        try:
            self.read_indication()
        except Exception as error:
            if not _is_native_fault(error):
                raise
            # Native4840 catch-all487e continues at the second read4887.
        return self.read_messages_result(count)

    @staticmethod
    def _address(address):
        if not isinstance(address, bytes) or len(address) not in (4, 5):
            raise ValueError("Four/five-byte CAN address required")

    def read_specified(self, address: bytes, frame: int = 2):
        return self.read_specified_result(address, frame).message

    def read_specified_result(self, address: bytes, frame: int = 2, count: int = 1):
        self._address(address)
        if frame not in (0, 1, 2) or unsigned(count) > 1:
            raise ValueError("Native CAN frame enum and bounded input count required")
        try:
            if frame == 1 and self.read_indication(address) != 1:
                raise NativeJ2534Error2026(999)
            while True:
                batch = self.read_messages_result(count)
                messages = batch.messages
                if not messages and address == bytes(len(address)):
                    # Native48c0 zeroes backing, then66e0 prewrites ProtocolID only
                    # for requested slots. Unlike44e0,48c0 never checks DataSize.
                    message = NativeMessage(self.protocol_id if count else 0, b"")
                    self._history(message)
                    return SpecifiedRead2026(message, 0)
                for message in messages:
                    if message.data[: len(address)].ljust(
                        len(address), b"\0"
                    ) == address and (
                        frame != 2
                        or j2534_indication(message.rx_status, self.padding) == 3
                    ):
                        self._history(message)
                        return SpecifiedRead2026(message, batch.count)
        except NativeTransportError as error:
            raise NativeReadError2026(
                error.code,
                (),
                native_error_code=getattr(error, "native_error_code", 1),
                passthru_status=getattr(error, "passthru_status", error.code),
            ) from error

    def wrap_write_messages(
        self, messages: tuple[NativeMessage, ...], count: int | None = None
    ):
        """Native6770: mutate protocol/flags, clear RX, write; no history/indication."""
        if (
            not isinstance(messages, tuple)
            or len(messages) > 256
            or any(not isinstance(message, NativeMessage) for message in messages)
        ):
            raise ValueError("Bounded typed messages required")
        requested = len(messages) if count is None else unsigned(count)
        if requested > len(messages):
            raise ValueError("Write count exceeds supplied message capacity")
        prepared = (
            tuple(
                replace(
                    message,
                    protocol_id=self.protocol_id,
                    tx_flags=(message.tx_flags | (0x40 if self.padding else 0))
                    if self.protocol_id in (6, 0x8012)
                    else 0,
                )
                for message in messages[:requested]
            )
            + messages[requested:]
        )
        self.control_io(8)
        value = self._call(
            "passthru_write",
            channel=self._channel(),
            messages=prepared,
            count=requested,
            timeout=self.send_timeout,
        )
        count = unsigned(value)
        if count > requested:
            raise ValueError("Write count exceeds supplied messages")
        return count

    def write_messages(
        self,
        messages: tuple[NativeMessage, ...],
        *,
        indication=True,
        count: int | None = None,
    ):
        if (
            not isinstance(messages, tuple)
            or not 0 < len(messages) <= 256
            or any(not isinstance(message, NativeMessage) for message in messages)
        ):
            raise ValueError("Bounded typed messages required")
        if self.protocol_id in (6, 0x8012) and len(messages[0].data) < 4:
            raise ValueError("CAN write address is truncated")
        self._history(messages[0])
        count = self.wrap_write_messages(messages, count)
        if indication and self.protocol_id in (6, 0x8012):
            if len(messages[0].data) < 4:
                raise ValueError("CAN write address is truncated")
            try:
                self.read_indication(messages[0].data[:4])
            except Exception as error:
                if not _is_native_fault(error):
                    raise
                # Native6950 catch69f6 discards indication faults after a completed write.
        return count

    @contextmanager
    def _sync_guard(self, *, cleanup=False):
        state = self.sync
        locked = [False]
        primary = None
        try:
            if state is not None:
                self._call(
                    "lock",
                    mutex=state.mutex,
                    cleanup=cleanup,
                    accepted=lambda _: locked.__setitem__(0, True),
                )
            yield
        except BaseException as error:
            primary = error
            raise
        finally:
            if state is not None and locked[0]:
                try:
                    self._call("unlock", mutex=state.mutex, cleanup=True)
                except BaseException as error:
                    if primary is None:
                        raise
                    primary.add_note("J2534 mutex release failed: " + str(error))

    def start_flow_control_filter(self, request: bytes, response: bytes):
        self._address(request)
        self._address(response)
        if len(request) != len(response):
            raise ValueError("CAN addresses must have matching widths")
        flags = (0x40 if self.padding else 0) | (
            0x100 if request[0] and request[1] else 0
        )
        if len(response) == 5:
            flags |= 0x80
        messages = tuple(
            NativeMessage(self.protocol_id, data, tx_flags=flags)
            for data in (b"\xff" * len(response), response, request)
        )
        with self._sync_guard():
            identifier = unsigned(
                self._call(
                    "passthru_start_filter",
                    channel=self._channel(),
                    filter_type=3,
                    mask=messages[0],
                    pattern=messages[1],
                    flow_control=messages[2],
                    acquired=self.filters.append,
                )
            )
        return identifier

    def start_sil_filters(self):
        if self.protocol_id != 3:
            raise ValueError("SIL protocol required")
        for index, pattern in enumerate((b"\x00", b"\x80")[: self.sil_filter_count]):
            self._call(
                "passthru_start_filter",
                channel=self._channel(),
                filter_type=1,
                mask=NativeMessage(3, b"\x80"),
                pattern=NativeMessage(3, pattern),
                flow_control=None,
                acquired=lambda handle, index=index: self._acquired_sil_filter(
                    index, handle
                ),
            )

    def _acquired_sil_filter(self, index: int, handle: int):
        self.sil_filter_ids[index], self.sil_filter_active[index] = handle, True
        self.filters.append(handle)

    def stop_sil_filters(self):
        for index, active in enumerate(
            tuple(self.sil_filter_active)[: self.sil_filter_count]
        ):
            if active:
                identifier = self.sil_filter_ids[index]

                def released(_value, index=index, identifier=identifier):
                    self.sil_filter_ids[index], self.sil_filter_active[index] = 0, False
                    if identifier in self.filters:
                        self.filters.remove(identifier)

                with self._sync_guard(cleanup=True):
                    self._call(
                        "passthru_stop_filter",
                        channel=self._channel(),
                        identifier=identifier,
                        cleanup=True,
                        accepted=released,
                    )

    def start_can_filter(self, kind: int, mask: bytes, pattern: bytes):
        if kind not in (0, 1):
            raise ValueError("Native pass/block filter enum required")
        if (
            not isinstance(mask, bytes)
            or not isinstance(pattern, bytes)
            or min(len(mask), len(pattern)) < 4
        ):
            raise ValueError("Four-byte CAN filter data required")
        identifier = unsigned(
            self._call(
                "passthru_start_filter",
                channel=self._channel(),
                filter_type=kind + 1,
                mask=NativeMessage(6, mask[:4]),
                pattern=NativeMessage(6, pattern[:4]),
                flow_control=None,
                acquired=self.filters.append,
            )
        )
        return identifier

    def read_specified_many(self, addresses: tuple[bytes, ...]):
        if not isinstance(addresses, tuple) or not 0 < len(addresses) <= 256:
            raise ValueError("Bounded address tuple required")
        for address in addresses:
            self._address(address)
        outstanding = list(addresses)
        result = []
        try:
            while outstanding:
                for message in self.read_messages(len(outstanding)):
                    if j2534_indication(message.rx_status, self.padding) != 3:
                        continue
                    for index, address in enumerate(outstanding):
                        if message.data.startswith(address):
                            result.append(message)
                            outstanding.pop(index)
                            break
        except NativeTransportError as exc:
            raise NativeReadError2026(
                exc.code,
                tuple(result),
                native_error_code=getattr(exc, "native_error_code", 1),
                passthru_status=getattr(exc, "passthru_status", exc.code),
            ) from exc
        except (InterruptedError, TimeoutError, TypeError, ValueError):
            raise
        except Exception as exc:
            if not _is_native_fault(exc):
                raise
            raise NativeReadError2026(
                9999, tuple(result), native_error_code=9999, passthru_status=None
            ) from exc
        self._history(result[-1])
        return tuple(result)

    def start_periodic(self, message: NativeMessage, interval: int):
        if not isinstance(message, NativeMessage):
            raise TypeError("Typed periodic message required")
        unsigned(interval)
        # RVA5be0 always sets CAN padding, independently of the instance flag.
        prepared = replace(
            message,
            protocol_id=self.protocol_id,
            tx_flags=message.tx_flags | 0x40 if self.protocol_id == 6 else 0,
        )
        return unsigned(
            self._call(
                "passthru_start_periodic",
                channel=self._channel(),
                message=prepared,
                interval=interval,
                acquired=self.periodics.append,
            )
        )

    def stop_periodic(self, identifier: int):
        unsigned(identifier)
        self._call(
            "passthru_stop_periodic",
            channel=self._channel(),
            identifier=identifier,
            cleanup=True,
            accepted=lambda _: (
                self.periodics.remove(identifier)
                if identifier in self.periodics
                else None
            ),
        )

    def start_sync_periodic(
        self,
        messages: tuple[NativeMessage, ...],
        interval: int,
        poll_interval: int,
        post_delay: int = 0,
        *,
        tcp=False,
    ):
        if self.sync is not None:
            raise ValueError("Synchronous periodic worker already active")
        if (
            not isinstance(messages, tuple)
            or not 0 < len(messages) <= 256
            or any(not isinstance(message, NativeMessage) for message in messages)
            or type(tcp) is not bool
        ):
            raise ValueError("Bounded typed synchronous periodic messages required")
        for value in (interval, poll_interval, post_delay):
            unsigned(value)
        prepared = (
            messages
            if self.version == 1
            else tuple(
                replace(
                    message,
                    protocol_id=self.protocol_id,
                    tx_flags=message.tx_flags | 0x40
                    if self.protocol_id in (6, 0x8012) and self.padding
                    else message.tx_flags,
                )
                for message in messages
            )
        )
        self.sync = SyncPeriodic2026(
            prepared,
            interval,
            poll_interval,
            post_delay,
            tcp,
            previous=self.previous_send_time,
        )
        self._call(
            "create_mutex",
            name="EXCLUSIVE_OF_J2534API_ON_CUW",
            acquired=lambda handle: setattr(self.sync, "mutex", handle),
        )

        self.sync_stop.clear()
        self.sync_error = None
        if self.background_workers:
            self.sync_worker = threading.Thread(
                target=self._sync_worker_main,
                name="CUW2026-J2534-periodic",
                daemon=True,
            )
            self.sync_worker.start()

    def _sync_worker_main(self):
        try:
            while not self.sync_stop.is_set():
                self.sync_step()
        except BaseException as exc:  # noqa: BLE001 - transfer worker failure to its owner
            self.sync_error = exc

    def sync_step(self) -> bool:
        """One cooperative iteration of native5320/50c0; caller pumps the worker."""
        state = self.sync
        if state is None:
            raise ValueError("Synchronous periodic worker is not active")
        now = self._local_time_ms()
        adjusted = now + (86400000 if now // 3600000 < state.previous // 3600000 else 0)
        elapsed = (adjusted - state.previous) & 0xFFFFFFFF
        if elapsed < state.interval:
            self._call("wait", milliseconds=state.poll_interval)
            return False
        with self._sync_guard():
            for message in state.messages:
                if self.version == 0:
                    # RVA5320 ignores PassThruWriteMsgs status, unlike wrapped sends.
                    self._call(
                        "passthru_write",
                        channel=self._channel(),
                        messages=(message,),
                        count=1,
                        timeout=self.send_timeout,
                        ignore_status=True,
                    )
                else:
                    try:
                        if state.tcp:
                            self.write_tcp(message)
                        else:
                            self.queue_message(message)
                    except Exception as error:
                        if not _is_native_fault(error):
                            raise
                        # Native50c0 catch526f advances to the next periodic frame.
            if state.post_delay:
                state.previous = self._local_time_ms()
                self.previous_send_time = state.previous
                self._call("wait", milliseconds=state.post_delay)
        if not state.post_delay:
            state.previous = self._local_time_ms()
            self.previous_send_time = state.previous
        return True

    def _local_time_ms(self) -> int:
        result = unsigned(self._call("local_time_ms"))
        if result >= 86400000:
            raise ValueError("Native local time must be milliseconds within one day")
        return result

    def set_previous_send_time(self):
        self.previous_send_time = self._local_time_ms()
        if self.sync is not None:
            self.sync.previous = self.previous_send_time

    def stop_sync_periodic(self):
        state = self.sync
        worker = self.sync_worker
        self.sync_stop.set()
        if worker is not None:
            if state is not None:
                self._call("wait", milliseconds=state.poll_interval, cleanup=True)
            worker.join(timeout=self._cleanup_remaining())
            if worker.is_alive():
                raise TimeoutError(
                    "Native periodic worker did not stop within cleanup allowance"
                )
            self.sync_worker = None
        if state is not None:
            if state.mutex is not None:
                self._call(
                    "close_handle",
                    handle=state.mutex,
                    cleanup=True,
                    accepted=lambda _: setattr(state, "mutex", None),
                )
            self.sync = None
        if self.sync_error is not None:
            error, self.sync_error = self.sync_error, None
            if not (isinstance(error, InterruptedError) and self.cancelled()):
                raise error

    def switch_connection(self, protocol_id: int):
        unsigned(protocol_id)
        if self.connecting:
            if self.protocol_id == 3:
                self.stop_sil_filters()
            self._call(
                "passthru_disconnect",
                channel=self.channel_id,
                ignore_status=True,
                accepted=lambda _: self._forget_switched_channel(),
            )
        self._connect_channel(protocol_id, classic=True)
        if protocol_id == 0x8012:
            self._configure_connected_can_fd()

    def switch_version(self):
        self.unload_shim()
        self.version = int(self.version == 0)
        selected = self.driver_versions[self.version]
        self.set_current_driver(
            selected if selected is not None else DriverMetadata2026()
        )

    def switch_connection_with_version(self, protocol_id: int):
        unsigned(protocol_id)
        if protocol_id == self.protocol_id:
            return
        previous = self.protocol_id
        self.disconnect()
        if 0x800F in (previous, protocol_id):
            self.switch_version()
        if self.driver is not None:
            self.connect_native(protocol_id)
        else:
            self.open(2 if protocol_id == 0x8012 else 0)
            self.connect(protocol_id)

    def stop_filter(self, identifier: int):
        unsigned(identifier)
        with self._sync_guard(cleanup=True):
            self._call(
                "passthru_stop_filter",
                channel=self._channel(),
                identifier=identifier,
                cleanup=True,
                accepted=lambda _: (
                    self.filters.remove(identifier)
                    if identifier in self.filters
                    else None
                ),
            )

    def set_programming_voltage(self, pin: int, voltage: int):
        unsigned(pin)
        unsigned(voltage)
        if voltage not in (0xFFFFFFFE, 0xFFFFFFFF):
            return
        enabled = voltage == 0xFFFFFFFE
        if enabled == self.voltage_enabled:
            return
        self._call(
            "passthru_voltage",
            device=self.device_id or 0,
            pin=pin,
            voltage=voltage,
            accepted=lambda _: setattr(self, "voltage_enabled", enabled),
        )

    def _forget_switched_channel(self):
        if self.channel_id is not None:
            self._last_channel_id = self.channel_id
        self.channel_id = None
        self.connecting = False
        self.protocol_id = 0

    def _forget_channel(self):
        self._forget_switched_channel()
        self.voltage_enabled = False
        self.filters.clear()
        self.periodics.clear()
        self.logical.clear()

    def disconnect(self):
        self._cleanup_steps(
            self.stop_sync_periodic,
            lambda: (
                self.stop_sil_filters()
                if self.connecting and self.protocol_id == 3
                else None
            ),
            lambda: (
                self._call(
                    "passthru_disconnect",
                    channel=self.channel_id,
                    cleanup=True,
                    ignore_status=True,
                    accepted=lambda _: self._forget_channel(),
                )
                if self.connecting
                else None
            ),
            self.close,
            self.unload_driver,
            self.release_ownership,
        )

    def cleanup_primitive(self, operation: dict, remaining: float):
        """Explicit bounded release/restore capability, without changing wire dictionaries."""
        if operation.get("operation") not in (
            "control_io",
            "set_timeout",
            "set_send_timeout",
            "set_history_enabled",
            "unlock",
            "wait",
            "stop_filter",
            "stop_periodic",
            "stop_sync_periodic",
            "stop_sync_periodic_message",
            "disconnect",
            "logical_disconnect",
            "logical_disconnect_udp_discovery",
            "switch_connection",
        ):
            raise ValueError(
                "Operation is not a J2534 cleanup or restoration primitive"
            )
        previous = getattr(self._execution_context, "cleanup", False)
        previous_deadline = getattr(self._execution_context, "cleanup_deadline", None)
        if (
            isinstance(remaining, bool)
            or not isinstance(remaining, (int, float))
            or not math.isfinite(remaining)
            or remaining <= 0
        ):
            raise ValueError("Finite positive cleanup allowance required")
        deadline = self.clock() + remaining
        self._execution_context.cleanup_deadline = (
            min(deadline, previous_deadline)
            if previous_deadline is not None
            else deadline
        )
        self._execution_context.cleanup = True
        try:
            return self.primitive(operation, remaining)
        finally:
            self._execution_context.cleanup = previous
            self._execution_context.cleanup_deadline = previous_deadline

    def primitive(self, operation: dict, remaining: float):
        """Adapter for existing NativeRuntime2026/CanDiag2026 raw contracts."""
        if (
            isinstance(remaining, bool)
            or not isinstance(remaining, (int, float))
            or not math.isfinite(remaining)
            or remaining <= 0
        ):
            raise ValueError("Finite positive caller deadline required")
        if not getattr(self._execution_context, "cleanup", False):
            self.deadline = min(self.deadline, self.clock() + remaining)
        name = operation["operation"]
        if name == "switch_connection":
            return self.switch_connection(unsigned(operation["protocol"]))
        if name == "switch_connection_with_version":
            return self.switch_connection_with_version(unsigned(operation["protocol"]))
        if name == "connect":
            protocol = unsigned(operation["protocol"])
            if self.driver is not None:
                return self.connect_native(protocol)
            if not self.opened:
                self.open(2 if protocol == 0x8012 else 0)
            return self.connect(protocol)
        if name == "start_sync_periodic":
            self._channel()
            frames = operation["frames"]
            if not isinstance(frames, tuple) or operation.get("count") != len(frames):
                raise ValueError("Native periodic frame/count mismatch")
            if not 0 < len(frames) <= 256 or any(
                not isinstance(frame, tuple) or len(frame) != 2 for frame in frames
            ):
                raise ValueError("Bounded native periodic frame tuples required")
            messages = tuple(
                NativeMessage(self.protocol_id, data, tx_flags=flags)
                for data, flags in frames
            )
            return self.start_sync_periodic(
                messages,
                operation["interval_ms"],
                operation["retry_ms"],
                operation["delay_ms"],
            )
        if name == "set_local_time_to_previous_send_time":
            return self.set_previous_send_time()
        if name == "is_sending_sync_periodic":
            return self.sync is not None
        if name == "disconnect":
            return self.disconnect()
        if name in ("stop_sync_periodic", "stop_sync_periodic_message"):
            return self.stop_sync_periodic()
        if name == "get_can_frame_padding":
            return self.padding
        if name == "get_protocol_id":
            self._channel()
            return unsigned(self.protocol_id)
        if name == "get_send_timeout":
            return unsigned(self.send_timeout)
        if name == "set_send_timeout":
            self.send_timeout = unsigned(operation["milliseconds"])
            return None
        if name == "set_history_enabled":
            return self.set_history_enabled(operation["enabled"])
        if name == "get_system_time":
            value = self._call("get_system_time")
            if (
                not isinstance(value, tuple)
                or len(value) != 8
                or any(
                    type(field) is not int or not 0 <= field <= 0xFFFF
                    for field in value
                )
            ):
                raise ValueError("Eight native SYSTEMTIME uint16 fields required")
            return value
        if name == "local_time_ms":
            return self._local_time_ms()
        if name == "get_timeout":
            return self.timeout
        if name == "set_timeout":
            self.timeout = unsigned(operation["milliseconds"])
            return None
        if name == "write_messages":
            if "messages" in operation or isinstance(operation.get("data"), tuple):
                data = operation.get("messages", operation.get("data"))
                if (
                    not isinstance(data, tuple)
                    or type(operation.get("count")) is not int
                    or operation["count"] != len(data)
                ):
                    raise ValueError("Native batch write frame/count mismatch")
                return self.write_messages(
                    tuple(
                        NativeMessage(
                            self.protocol_id,
                            frame,
                            tx_flags=operation.get("tx_flags", 0),
                        )
                        for frame in data
                    )
                )
            if type(operation.get("count")) is not int or operation["count"] != 1:
                raise ValueError("CanDiag bridge writes exactly one message")
            return self.write_messages(
                (
                    NativeMessage(
                        operation["protocol"],
                        operation["data"],
                        tx_flags=operation["tx_flags"],
                    ),
                )
            )
        if name == "read_specified_can_messages":
            addresses = operation["addresses"]
            if (
                not isinstance(addresses, tuple)
                or type(operation.get("count")) is not int
                or operation["count"] != len(addresses)
            ):
                raise ValueError("Native batch read address/count mismatch")
            return tuple(
                message.data for message in self.read_specified_many(addresses)
            )
        if name in ("read_messages_result", "read_after_indication_result"):
            return (
                self.read_after_indication_result(operation.get("count", 1))
                if name == "read_after_indication_result"
                else self.read_messages_result(
                    operation.get("count", 1), operation.get("protocol")
                )
            )
        if name in ("read_messages", "read_after_indication"):
            if type(operation.get("count")) is not int or operation["count"] != 1:
                raise ValueError("Raw diagnostic bridge reads exactly one message")
            if name == "read_after_indication":
                messages = self.read_after_indication_result().messages
                return messages[0].data if messages else b""
            if self.version == 1:
                result = self.read_buffer(
                    operation.get("protocol", self.protocol_id), 1
                )
                return result.message.data
            messages = self.read_messages_result().messages
            return messages[0].data if messages else b""
        if name in ("queue_messages", "write_tcp"):
            if type(operation.get("count")) is not int or operation["count"] != 1:
                raise ValueError("Native 0500 bridge accepts one message")
            message = NativeMessage(
                operation["protocol"], operation["data"], tx_flags=operation["tx_flags"]
            )
            return (
                self.queue_message(message)
                if name == "queue_messages"
                else self.write_tcp(message)
            )
        if name == "read_tcp":
            if type(operation.get("count")) is not int or operation["count"] != 1:
                raise ValueError("Native TCP bridge reads one message")
            return self.read_tcp().message.data
        if name == "logical_connect":
            self.logical_connect(
                operation["protocol"], operation.get("descriptor", b"")
            )
            return None
        if name == "logical_disconnect":
            return self.logical_disconnect(operation["protocol"])
        if name == "logical_connect_udp_discovery":
            self.logical_connect(0x8205, discovery=True)
            return None
        if name == "logical_disconnect_udp_discovery":
            return self.logical_disconnect(0x8205, discovery=True)
        if name == "start_sync_periodic_0500":
            if (
                operation.get("count") != 1
                or type(operation.get("enabled")) is not bool
            ):
                raise ValueError("Native 0500 periodic count/flag required")
            message = NativeMessage(
                operation["protocol"], operation["data"], tx_flags=operation["tx_flags"]
            )
            return self.start_sync_periodic(
                (message,),
                operation["interval_ms"],
                operation["poll_ms"],
                operation["delay_ms"],
                tcp=operation["enabled"],
            )
        if name == "five_baud_init":
            return self.five_baud_init(operation["data"])
        if name == "fast_init":
            return self.fast_init(operation["data"], operation.get("tx_flags", 0))
        if name == "read_specified_can_message":
            if operation.get("count") != 1:
                raise ValueError("CanDiag bridge reads exactly one message")
            return self.read_specified(operation["address"], operation["frame"]).data
        if name == "start_periodic":
            preceding = tuple(self.periodics)
            try:
                return self.start_periodic(operation["message"], operation["interval"])
            except (Exception, KeyboardInterrupt) as error:
                # Runtime.acquire cannot own an ID hidden by our post-call check.
                fresh = tuple(self.periodics[len(preceding) :])
                for identifier in reversed(fresh):
                    try:
                        self.cleanup_primitive(
                            {"operation": "stop_periodic", "identifier": identifier},
                            5.0,
                        )
                    except (Exception, KeyboardInterrupt) as cleanup_error:  # noqa: BLE001 - retain original fault and device ownership
                        error.add_note(
                            "Fresh periodic remains device-owned after rollback failure: "
                            + type(cleanup_error).__name__
                        )
                        break
                else:
                    self.periodics[:] = preceding
                raise
        if name == "stop_periodic":
            return self.stop_periodic(operation["identifier"])
        if name == "start_flow_control_filter":
            preceding = tuple(self.filters)
            try:
                return self.start_flow_control_filter(
                    operation["request_address"], operation["response_address"]
                )
            except (Exception, KeyboardInterrupt) as error:
                # Runtime.acquire cannot own a handle hidden by our post-call check.
                fresh = tuple(self.filters[len(preceding) :])
                for identifier in reversed(fresh):
                    try:
                        self.cleanup_primitive(
                            {"operation": "stop_filter", "identifier": identifier},
                            5.0,
                        )
                    except (Exception, KeyboardInterrupt) as cleanup_error:  # noqa: BLE001 - retain original fault and device ownership
                        error.add_note(
                            "Fresh filter remains device-owned after rollback failure: "
                            + type(cleanup_error).__name__
                        )
                        break
                else:
                    self.filters[:] = preceding
                raise
        if name == "stop_filter":
            return self.stop_filter(operation["identifier"])
        if name == "control_io":
            return self.control_io(operation["ioctl"], operation.get("parameters", ()))
        if name in ("lock", "unlock") and self.sync is None:
            return None
        if name in ("wait", "lock", "unlock"):
            values = {
                key: value for key, value in operation.items() if key != "operation"
            }
            if name in ("lock", "unlock") and self.sync is not None:
                values["mutex"] = self.sync.mutex
            return self._call(name, cleanup=name == "unlock", **values)
        raise ValueError(f"Unsupported J2534 host primitive: {name}")


@dataclass(frozen=True)
class NativeCommunicationAddress:
    """Native seven-byte record: two padded three-byte IDs and extension flag."""

    request: bytes
    response: bytes
    extended: bool = False

    def __post_init__(self):
        if type(self.extended) is not bool:
            raise TypeError("Native address extension flag must be boolean")
        width = 3 if self.extended else 2
        if any(
            not isinstance(value, bytes) or len(value) != width
            for value in (self.request, self.response)
        ):
            raise ValueError("Native address width must match extension flag")

    def record(self) -> bytes:
        return (
            self.request.ljust(3, b"\0")
            + self.response.ljust(3, b"\0")
            + bytes((self.extended,))
        )

    def headers(self) -> tuple[bytes, bytes]:
        # Metadata uses 16-bit CAN IDs and optional fifth address-extension byte.
        return b"\0\0" + self.request, b"\0\0" + self.response


def _metadata_text(value: object) -> str:
    if not isinstance(value, str) or len(value) > 260 or "\0" in value:
        raise ValueError("Bounded native metadata text required")
    try:
        value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("Native address metadata must be ASCII") from exc
    return value


def _hex_metadata(value: str) -> bytes:
    _metadata_text(value)
    if (
        not value
        or len(value) % 2
        or any(character not in "0123456789abcdefABCDEF" for character in value)
    ):
        raise ValueError("Even-length native hexadecimal metadata required")
    return bytes.fromhex(value)


def separate_can_id(value: str) -> NativeCommunicationAddress:
    """RVA2f50: request text length selects width; CBytes.SetNum aligns right."""
    _metadata_text(value)
    parts = value.split("/")
    if len(parts) != 2 or len(value) >= 20:
        raise ValueError("Native address pair must fit its 20-byte buffer")
    request, response = (_hex_metadata(part) for part in parts)
    width = 3 if len(parts[0]) == 6 else 2
    return NativeCommunicationAddress(
        request[-width:].rjust(width, b"\0"),
        response[-width:].rjust(width, b"\0"),
        width == 3,
    )


def _raw_can_ids(request: str, response: str, *, suzuki=False):
    width = 3 if not suzuki and len(request) == 6 else 2
    return NativeCommunicationAddress(
        _hex_metadata(request)[:width].ljust(width, b"\0"),
        _hex_metadata(response)[:width].ljust(width, b"\0"),
        width == 3,
    )


class CommunicationAddress2026:
    """RVA2c10 strategy chain over actual typed parameter/calibration fields.

    Parameters and callback lookup results are raw metadata, never a callback
    claiming that address selection succeeded. History is explicitly shared by
    callers belonging to one native context; duplicates are preserved.
    """

    def __init__(
        self,
        parameters,
        *,
        node_diag_ids: tuple[str, ...] = (),
        response_canids=None,
        suzuki_ids: tuple[str, str] | None = None,
        history: list[NativeCommunicationAddress] | None = None,
    ):
        from collections.abc import Mapping
        from types import MappingProxyType

        if not isinstance(parameters, Mapping) or len(parameters) > 256:
            raise ValueError("Bounded native parameter mapping required")
        copied = {}
        for key, values in parameters.items():
            _metadata_text(key)
            if not isinstance(values, tuple) or len(values) > 10:
                raise ValueError("Native address parameter count exceeds ten")
            copied[key] = tuple(_metadata_text(value) for value in values)
        if not isinstance(node_diag_ids, tuple) or len(node_diag_ids) > 256:
            raise ValueError("Bounded native calibration nodes required")
        for value in node_diag_ids:
            _metadata_text(value)
        response_canids = {} if response_canids is None else response_canids
        if not isinstance(response_canids, Mapping) or len(response_canids) > 256:
            raise ValueError("Bounded ResponseCANID lookup required")
        for key, value in response_canids.items():
            _metadata_text(key)
            _metadata_text(value)
        if suzuki_ids is not None:
            if not isinstance(suzuki_ids, tuple) or len(suzuki_ids) != 2:
                raise ValueError("Suzuki request/response metadata pair required")
            for value in suzuki_ids:
                _metadata_text(value)
        if history is not None and (
            not isinstance(history, list)
            or len(history) > 4096
            or any(not isinstance(item, NativeCommunicationAddress) for item in history)
        ):
            raise ValueError("Bounded native address history required")
        self.parameters = MappingProxyType(copied)
        self.node_diag_ids = node_diag_ids
        self.response_canids = MappingProxyType(dict(response_canids))
        self.suzuki_ids = suzuki_ids
        self.history = [] if history is None else history
        self.addresses: tuple[NativeCommunicationAddress, ...] = ()

    def __copy__(self):
        result = CommunicationAddress2026(
            self.parameters,
            node_diag_ids=self.node_diag_ids,
            response_canids=self.response_canids,
            suzuki_ids=self.suzuki_ids,
            history=self.history,
        )
        result.addresses = self.addresses
        return result

    def move(self):
        result = self.__copy__()
        self.addresses = ()
        return result

    def remember(self, address: NativeCommunicationAddress):
        if (
            not isinstance(address, NativeCommunicationAddress)
            or len(self.history) >= 4096
        ):
            raise ValueError("Typed address and bounded native history required")
        self.history.append(address)

    def history_request_ids(self) -> tuple[str, ...]:
        return tuple(address.request.hex().upper() for address in self.history)

    def _parameter(self, name: str):
        values = self.parameters.get(name)
        return (
            (False, ())
            if values is None
            else (True, tuple(separate_can_id(value) for value in values))
        )

    def resolve(
        self,
        functions: tuple[str, ...],
        *,
        cids: tuple[str, ...] = (),
        location_id: str | None = None,
    ) -> tuple[bool, tuple[NativeCommunicationAddress, ...]]:
        if (
            not isinstance(functions, tuple)
            or len(functions) > 256
            or not isinstance(cids, tuple)
            or len(cids) > 256
        ):
            raise ValueError("Bounded native function and CID tuples required")
        for value in functions + cids:
            _metadata_text(value)
        self.addresses = ()
        success = False
        result = []
        parameter_names = {
            "GetCanIDsFromParamForGetCID": "CanIDForGetCID",
            "GetCanIDsFromParamForPrepareWrite": "CanIDForPrepareWrite",
            "GetCanIDsFromParamForReprogGateway": "CanIDForReprogGateway",
        }
        for function in functions:
            addresses = ()
            if function in parameter_names:
                success, addresses = self._parameter(parameter_names[function])
            elif function == "GetCanIDsFromParamMatchedPartOfCIDForPrepareWrite":
                prefixes = self.parameters.get("CIDForCalcCpuNum")
                success = prefixes is not None
                if prefixes is not None:
                    matched = (
                        len(cids)
                        if prefixes and prefixes[0] == "*"
                        else sum(
                            any(cid.startswith(prefix) for prefix in prefixes)
                            for cid in cids
                        )
                    )
                    if matched > 1:
                        success, addresses = self._parameter("CanIDMatchedPartOfCID")
            elif function == "GetCanIDsFromParamRespondCID":
                success, addresses = self._parameter("CanIDForPrepareWrite")
                if success:
                    # RVA2810 repeats the whole accumulated vector, not only the new IDs.
                    original = tuple(result) + addresses
                    copies = max(1, len(cids)) - 1
                    if len(result) + len(addresses) + len(original) * copies > 4096:
                        raise ValueError("Host resolved address budget exceeded")
                    addresses += original * copies
            elif function == "GetCanIDsFromResultOfGetCID":
                success, candidates = self._parameter("CanIDForGetCID")
                addresses = tuple(
                    candidate
                    for candidate in candidates
                    if any(
                        candidate.extended == previous.extended
                        and candidate.request == previous.request
                        for previous in self.history
                    )
                )
            elif function == "GetCanIDsFromCANIDTable":
                success = bool(self.node_diag_ids)
                selected = []
                for diag_id in self.node_diag_ids:
                    response = self.response_canids.get(diag_id, "")
                    if not response:
                        success = False
                        break
                    selected.append(_raw_can_ids(diag_id, response))
                addresses = tuple(selected)
            elif function == "GetCanIDsFromCalibrationFileForSUZUKI":
                success = self.suzuki_ids is not None and all(self.suzuki_ids)
                if success and self.suzuki_ids is not None:
                    # RVA2180 takes the first two bytes and forces extension off.
                    addresses = (_raw_can_ids(*self.suzuki_ids, suzuki=True),)
            elif function == "GetCanIDsFromLocationIDForWrite":
                if location_id is None:
                    raise ValueError("LocationID metadata required")
                _metadata_text(location_id)
                if (
                    len(location_id) < 16
                    or len(location_id) % 2
                    or any(
                        value not in "0123456789abcdefABCDEF" for value in location_id
                    )
                ):
                    raise ValueError(
                        "LocationID requires at least eight hexadecimal bytes"
                    )
                raw = bytes.fromhex(location_id)
                gateway = b"\x07\x20" if raw[6:8] == b"\x07\x20" else b"\x07\x40\xfe"
                addresses = (
                    NativeCommunicationAddress(raw[2:4], raw[:2]),
                    NativeCommunicationAddress(
                        gateway, b"\0" * len(gateway), len(gateway) == 3
                    ),
                )
                success = True
            result.extend(addresses)
            if len(result) > 4096:
                raise ValueError("Host resolved address budget exceeded")
            self.addresses = tuple(result)
            if not success:
                break
        return success, self.addresses


@dataclass(frozen=True)
class NativeModuleIdentity2026:
    name: str
    sha256: str

    def __post_init__(self):
        expected = {
            "TCUWJ2534DeviceIF.dll": J2534_SHA256,
            "TCUWCommunicationAddress.dll": ADDRESS_SHA256,
        }
        if self.name not in expected or self.sha256 != expected[self.name]:
            raise ValueError("Exact CUW2026 native module identity required")


@dataclass(frozen=True)
class BufferRead2026:
    message: NativeMessage
    count: int

    def __post_init__(self):
        unsigned(self.count)
        if not isinstance(self.message, NativeMessage) or self.count > len(
            self.message.data
        ):
            raise ValueError("Native 0500 byte count exceeds returned buffer")


@dataclass
class SyncPeriodic2026:
    messages: tuple[NativeMessage, ...]
    interval: int
    poll_interval: int
    post_delay: int
    tcp: bool
    previous: int = 0
    mutex: int | None = None


@dataclass
class DriverMetadata2026:
    device_name: str = ""
    dll_name: str = ""

    def __post_init__(self):
        for value in (self.device_name, self.dll_name):
            if not isinstance(value, str) or len(value) > 32767 or "\0" in value:
                raise ValueError("Bounded native J2534 driver text required")

    def clear(self):
        self.device_name, self.dll_name = "", ""

    def set_device_name(self, name: str):
        candidate = replace(self, device_name=name)
        self.device_name = candidate.device_name

    def set_dll_name(self, name: str):
        candidate = replace(self, dll_name=name)
        self.dll_name = candidate.dll_name

    def assign(self, other: "DriverMetadata2026"):
        if not isinstance(other, DriverMetadata2026):
            raise TypeError("Typed native driver descriptor required")
        other.__post_init__()
        self.device_name, self.dll_name = other.device_name, other.dll_name
        return self

    def __copy__(self):
        raise TypeError("Native CJ2534Device copy construction is private")

    def __deepcopy__(self, _memo):
        raise TypeError("Native CJ2534Device copy construction is private")


@dataclass(frozen=True)
class DeviceInfo2026:
    parameter: int
    value: int
    supported: int

    def __post_init__(self):
        for value in (self.parameter, self.value, self.supported):
            unsigned(value)


class NativePassThruError2026(NativeTransportError):
    """TCUWException2430: native primary enum, without a J2534 status member."""

    def __init__(self, code: int):
        super().__init__(unsigned(code))
        self.native_error_code = code
        self.passthru_status: int | None = None
        self.versions: tuple[str, str, str] | None = None
        self.device_info: DeviceInfo2026 | None = None


class NativeJ2534Error2026(NativePassThruError2026):
    """TCUWException2180: primary enum1 plus distinct raw J2534 status."""

    def __init__(self, status: int):
        super().__init__(status)
        self.native_error_code = 1
        self.passthru_status = status


class NativeReadError2026(NativeJ2534Error2026):
    def __init__(
        self,
        code: int,
        messages: tuple[NativeMessage, ...],
        *,
        native_error_code: int = 1,
        passthru_status: int | None = None,
    ):
        super().__init__(code)
        self.native_error_code = unsigned(native_error_code)
        self.passthru_status = passthru_status
        # 4fe9 clears the native count and first DataSize before rethrowing.
        # Retained frames are authored observations, not successful native output.
        self.returned_count = 0
        self.first_data_size = 0
        self.messages = messages


def communication_addresses_from_calibration(
    container,
    parameters,
    *,
    response_canids=None,
    history: list[NativeCommunicationAddress] | None = None,
) -> CommunicationAddress2026:
    """Bind actual validated2026 calibration fields to native address strategies."""
    from scripts.calibration_2026 import native2026_metadata

    metadata = native2026_metadata(container)
    if metadata.format_version >= 101:
        text = metadata.vehicle.get("numberofnode", "0")
        if not text.isascii() or not text.isdecimal() or not 1 <= int(text) <= 9:
            raise ValueError("Bounded native node count required")
        diag_ids = tuple(
            metadata.sections.get(f"node{index:02}", {}).get("diagid", "")
            for index in range(1, int(text) + 1)
        )
        if any(not value for value in diag_ids):
            raise ValueError("Every native calibration node requires DiagID")
    else:
        diag_ids = ()
    suzuki_ids = None
    if metadata.format_version in (10, 12):
        suzuki_ids = (
            metadata.vehicle.get("canidtx_phys_usdt", ""),
            metadata.vehicle.get("canidrx_phys_usdt", ""),
        )
    return CommunicationAddress2026(
        parameters,
        node_diag_ids=diag_ids,
        response_canids=response_canids,
        suzuki_ids=suzuki_ids,
        history=history,
    )


@dataclass
class MessageHistory2026:
    value: tuple[int, bytes] | None = None

    def __post_init__(self):
        if self.value is not None and (
            not isinstance(self.value, tuple)
            or len(self.value) != 2
            or type(self.value[0]) is not int
            or self.value[0] not in (4, 5)
            or not isinstance(self.value[1], bytes)
            or len(self.value[1]) > 4128
        ):
            raise ValueError("Bounded native last-message record required")


@dataclass(frozen=True)
class MessageBuffer0500:
    header: tuple[int, ...]
    data: bytes

    def __post_init__(self):
        if not isinstance(self.header, tuple) or len(self.header) != 7:
            raise ValueError("Native 0500 message has seven scalar header fields")
        for value in self.header:
            unsigned(value)
        if not isinstance(self.data, bytes) or len(self.data) > 4128:
            raise ValueError("Bounded immutable native 0500 buffer required")


def init_passthru_message_0500(
    previous: MessageBuffer0500, data: bytes | None = None, capacity: int = 0
) -> MessageBuffer0500:
    """RVA3280 clears seven fields and retained/replaced backing buffer."""
    if not isinstance(previous, MessageBuffer0500):
        raise TypeError("Typed preceding native 0500 message required")
    unsigned(capacity)
    backing = previous.data if data is None else data
    if not isinstance(backing, bytes) or len(backing) > 4128:
        raise ValueError("Bounded native backing buffer required")
    size = len(previous.data) if capacity == 0 else capacity
    if size > len(backing):
        raise ValueError("Native initializer capacity exceeds backing buffer")
    return MessageBuffer0500((0,) * 7, bytes(size))


def communication_addresses_from_parameter(
    container,
    parameter,
    *,
    response_canids=None,
    history: list[NativeCommunicationAddress] | None = None,
) -> CommunicationAddress2026:
    """Use the selected actual CParameter row, with no legacy catalog fallback."""
    from scripts.programming_2026_common import NativeParameter2026

    if not isinstance(parameter, NativeParameter2026):
        raise TypeError("Bound actual2026 CParameter context required")
    names = (
        "CanIDForGetCID",
        "CanIDForPrepareWrite",
        "CanIDForReprogGateway",
        "CanIDMatchedPartOfCID",
        "CIDForCalcCpuNum",
    )
    parameters = {}
    for name in names:
        values = parameter.values(name)
        if values is not None:
            parameters[name] = values
    if container is None:
        return CommunicationAddress2026(
            parameters, response_canids=response_canids, history=history
        )
    return communication_addresses_from_calibration(
        container, parameters, response_canids=response_canids, history=history
    )


@dataclass(frozen=True, eq=False)
class NativeChannelLease2026:
    """Physical channel observation; only exact pair-issued identity has authority."""

    channel_id: int
    generation: int

    def __post_init__(self):
        unsigned(self.channel_id)
        if type(self.generation) is not int or self.generation <= 0:
            raise ValueError("Positive host channel generation required")


class J2534InterfacePair2026:
    """Two source-bound native views with issued transfers and host release accounting."""

    def __init__(self, engine: J2534Device2026, control: J2534Device2026):
        if (
            type(engine) is not J2534Device2026
            or type(control) is not J2534Device2026
            or engine is control
            or engine._interface_pair is not None
            or control._interface_pair is not None
        ):
            raise ValueError("Two distinct unpaired native interface views required")
        self.engine, self.control = engine, control
        self._views = (engine, control)
        self._capabilities = self._capability(engine)
        if not self._matches_capability(control):
            raise ValueError(
                "Native views must share provider, clock and execution policy"
            )
        if (
            engine.driver != control.driver
            or engine.driver_versions != control.driver_versions
        ):
            raise ValueError("Native views must start with the same driver metadata")
        if all(
            view.opened
            or view.connecting
            or view.shim_handle is not None
            or view.wrapper_handle is not None
            or view.driver_loaded
            or view.sync is not None
            or view.ownership_mutex is not None
            or view.ownership_ready is not None
            or view.ownership_release is not None
            or bool(view.filters or view.periodics or view.logical)
            for view in self._views
        ):
            raise ValueError("Pair issuance requires an initially unowned peer")
        if (
            sum(view.calls for view in self._views) > engine.max_calls
            or sum(view.cleanup_calls for view in self._views)
            > engine.max_cleanup_calls
        ):
            raise ValueError("Existing native view calls exceed the shared pair budget")
        self._condition = threading.Condition(threading.RLock())
        self._serial = 0
        self._tokens: dict[J2534Device2026, dict[tuple[str, int], int]] = {
            engine: {},
            control: {},
        }
        self._channel_leases: dict[tuple[int, int], NativeChannelLease2026] = {}
        self._channel_parents: dict[tuple[int, int], tuple[int, int]] = {}
        self._released: set[tuple[str, int, int]] = set()
        self._pending: set[tuple[str, int, int]] = set()
        self._importing: tuple[J2534Device2026, object] | None = None
        self._issued: dict[
            J2534Device2026, tuple[object, tuple, dict[tuple[str, int], int]]
        ] = {}
        for view in self._views:
            for key in self._exported_keys(view):
                self._serial += 1
                self._tokens[view][key] = self._serial
            if view.opened and view.connecting:
                device = view.device_id if view.device_id is not None else 0
                channel = view.channel_id if view.channel_id is not None else 0
                self._channel_parents[
                    (channel, self._tokens[view][("channel", channel)])
                ] = (device, self._tokens[view][("device", device)])
            view._interface_pair = self
        # The two native views enter through the same thread-local host capability.
        control._state_lock = engine._state_lock
        control._execution_context = engine._execution_context
        self._state_lock = engine._state_lock
        self._execution_context = engine._execution_context

    @staticmethod
    def _capability(view: J2534Device2026) -> tuple:
        return (
            view.provider,
            view.clock,
            view.cancelled,
            view.background_workers,
            view.max_calls,
            view.max_cleanup_calls,
        )

    def _matches_capability(self, view: J2534Device2026) -> bool:
        current = self._capability(view)
        return (
            all(
                left is right
                for left, right in zip(current[:3], self._capabilities[:3], strict=True)
            )
            and current[3:] == self._capabilities[3:]
        )

    def validate_views(self):
        if (self.engine, self.control) != self._views:
            raise ValueError("Native interface pair roles changed")
        for view in self._views:
            if (
                view._interface_pair is not self
                or not self._matches_capability(view)
                or view._state_lock is not self._state_lock
                or view._execution_context is not self._execution_context
            ):
                raise ValueError("Native interface pair capability changed")

    def _issued_channel_lease(self, lease: object) -> NativeChannelLease2026:
        self.validate_views()
        if (
            not isinstance(lease, NativeChannelLease2026)
            or self._channel_leases.get((lease.channel_id, lease.generation))
            is not lease
        ):
            raise ValueError("Exact pair-issued physical channel lease required")
        return lease

    def _channel_generation_retired(self, channel: int, generation: int) -> bool:
        parent = self._channel_parents.get((channel, generation))
        return ("channel", channel, generation) in self._released or (
            parent is not None and ("device", *parent) in self._released
        )

    def channel_lease(self, view: J2534Device2026) -> NativeChannelLease2026:
        self.validate_views()
        if view not in self._views:
            raise ValueError("Foreign native channel view")
        with self._condition:
            channel = view._channel()
            generation = self._tokens[view].get(("channel", channel))
            if generation is None or self._channel_generation_retired(
                channel, generation
            ):
                raise ValueError(
                    "Current physical channel generation is unproven or retired"
                )
            key = (channel, generation)
            if key not in self._channel_leases:
                self._channel_leases[key] = NativeChannelLease2026(*key)
            return self._channel_leases[key]

    def channel_lease_retired(self, lease: object) -> bool:
        with self._condition:
            issued = self._issued_channel_lease(lease)
            return self._channel_generation_retired(
                issued.channel_id, issued.generation
            )

    def validate_channel_lease(self, view: J2534Device2026, lease: object):
        with self._condition:
            issued = self._issued_channel_lease(lease)
            if self.channel_lease(view) is not issued:
                raise ValueError(
                    "Child resource belongs to another physical channel generation"
                )

    @staticmethod
    def _exported_keys(view: J2534Device2026) -> tuple[tuple[str, int], ...]:
        keys = []
        if view.opened:
            keys.append(("device", view.device_id if view.device_id is not None else 0))
        if view.connecting:
            keys.append(
                ("channel", view.channel_id if view.channel_id is not None else 0)
            )
        for handle in (view.shim_handle, view.wrapper_handle):
            if handle is not None:
                keys.append(("library", handle))
        if view.shim_handle is not None:
            keys.append(("driver", view.shim_handle))
        return tuple(keys)

    @staticmethod
    def _signature(data: "NativeInterfaceData2026") -> tuple:
        pointers = {
            "provider",
            "ownership_thread",
            "ownership_ready",
            "ownership_release",
            "history_sink",
        }
        values = []
        for name, value in vars(data).items():
            if name in pointers:
                values.append((name, id(value)))
            elif name == "driver":
                values.append(
                    (
                        name,
                        None if value is None else (value.device_name, value.dll_name),
                    )
                )
            elif name == "drivers":
                values.append(
                    (name, tuple((item.device_name, item.dll_name) for item in value))
                )
            else:
                values.append((name, value))
        return tuple(values)

    def export_from(
        self, view: J2534Device2026, previous=None
    ) -> "NativeInterfaceData2026":
        self.validate_views()
        if view not in self._views:
            raise ValueError("Foreign native export view")
        data = view.export_data(previous)
        with self._condition:
            keys = self._exported_keys(view)
            tokens = {
                key: value for key, value in self._tokens[view].items() if key in keys
            }
            self._issued[view] = (data, self._signature(data), tokens)
        return data

    def import_into(self, view: J2534Device2026, data: "NativeInterfaceData2026"):
        self.validate_views()
        if view not in self._views:
            raise ValueError("Foreign native import view")
        peer = self.control if view is self.engine else self.engine
        with self._condition:
            issued = self._issued.get(peer)
            if (
                issued is None
                or data is not issued[0]
                or self._signature(data) != issued[1]
                or self._signature(peer.export_data(data)) != issued[1]
            ):
                raise ValueError("Latest exact source-issued peer snapshot required")
            preceding = self._exported_keys(view)
            self._importing = (view, data)
            try:
                view._import_data(data, _issuer=self)
            finally:
                self._importing = None
            for key in preceding:
                self._tokens[view].pop(key, None)
            self._tokens[view].update(issued[2])
            self._issued.pop(view, None)

    def _accepts_import(self, view: J2534Device2026, data: object) -> bool:
        return (
            self._importing is not None
            and self._importing[0] is view
            and self._importing[1] is data
        )

    def _invoke(
        self, view: J2534Device2026, operation: dict, remaining: float
    ) -> PrimitiveResult:
        self.validate_views()
        with self._condition:
            self._issued.pop(view, None)
        name = operation["operation"]
        parent = None
        if name in ("passthru_connect", "passthru_connect_0500"):
            with self._condition:
                device = operation["device"]
                generation = self._tokens[view].get(("device", device))
                if generation is not None:
                    parent = (device, generation)
        releases = {
            "passthru_disconnect": ("channel", operation.get("channel")),
            "passthru_close": ("device", operation.get("device")),
            "free_library": ("library", operation.get("handle")),
            "passthru_unload_library": ("driver", view.shim_handle),
        }
        key = releases.get(name)
        token = None
        if key is not None:
            with self._condition:
                generation = self._tokens[view].get(key)
                if generation is not None:
                    token = (*key, generation)
                    while token in self._pending:
                        if not self._condition.wait(remaining):
                            raise TimeoutError(
                                "Paired native release is still in progress"
                            )
                    if token in self._released or (
                        key[0] == "channel"
                        and self._channel_generation_retired(key[1], generation)
                    ):
                        return PrimitiveResult()
                    self._pending.add(token)
        try:
            result = view.provider(operation, remaining)
            if isinstance(result, PrimitiveResult) and result.status == 0:
                with self._condition:
                    if token is not None:
                        self._released.add(token)
                    acquired_kind = {
                        "passthru_open": "device",
                        "passthru_connect": "channel",
                        "passthru_connect_0500": "channel",
                        "load_library": "library",
                    }.get(name)
                    if (
                        acquired_kind is not None
                        and type(result.value) is int
                        and 0 <= result.value <= 0xFFFFFFFF
                        and (acquired_kind != "library" or result.value != 0)
                    ):
                        self._serial += 1
                        self._tokens[view][(acquired_kind, result.value)] = self._serial
                        if acquired_kind == "channel" and parent is not None:
                            self._channel_parents[(result.value, self._serial)] = parent
                    if name == "passthru_load_library" and view.shim_handle is not None:
                        self._serial += 1
                        self._tokens[view][("driver", view.shim_handle)] = self._serial
            return result
        finally:
            if token is not None:
                with self._condition:
                    self._pending.discard(token)
                    self._condition.notify_all()


@dataclass(frozen=True)
class NativeInterfaceData2026:
    provider: PrimitiveProvider
    device_id: int
    opened: bool
    protocol_id: int
    channel_id: int
    version: int
    shim_handle: int | None
    connecting: bool
    timeout: int
    send_timeout: int
    driver: DriverMetadata2026 | None
    drivers: tuple[DriverMetadata2026, ...]
    sil_filter_count: int
    sil_ids: tuple[int, ...]
    sil_active: tuple[bool, ...]
    voltage_enabled: bool
    padding: bool
    ownership_thread: threading.Thread | None
    ownership_ready: "ManualResetEvent2026 | None"
    ownership_release: "ManualResetEvent2026 | None"
    wrapper_handle: int | None
    history_sink: MessageHistory2026 | None
    function_slots: tuple[int, ...]

    def __post_init__(self):
        if not callable(self.provider):
            raise TypeError("Native primitive capability table required")
        for value in (
            self.device_id,
            self.protocol_id,
            self.channel_id,
            self.version,
            self.timeout,
            self.send_timeout,
        ):
            unsigned(value)
        if self.version not in (0, 1):
            raise ValueError("Native interface version must be 0 or 1")
        for value in (self.shim_handle, self.wrapper_handle):
            if value is not None:
                unsigned(value)
        if any(
            type(value) is not bool
            for value in (
                self.opened,
                self.connecting,
                self.voltage_enabled,
                self.padding,
            )
        ):
            raise ValueError("Literal native state flags required")
        if self.driver is not None and not isinstance(self.driver, DriverMetadata2026):
            raise TypeError("Typed native current driver required")
        if (
            not isinstance(self.drivers, tuple)
            or len(self.drivers) != 2
            or any(
                not isinstance(driver, DriverMetadata2026) for driver in self.drivers
            )
        ):
            raise ValueError("Two typed native driver-version records required")
        for driver in (self.driver, *self.drivers):
            if driver is not None:
                driver.__post_init__()
        if (
            not isinstance(self.sil_ids, tuple)
            or len(self.sil_ids) != 2
            or not isinstance(self.sil_active, tuple)
            or len(self.sil_active) != 2
        ):
            raise ValueError("Native interface has exactly two SIL filter slots")
        if (
            type(self.sil_filter_count) is not int
            or not 0 <= self.sil_filter_count <= 2
        ):
            raise ValueError("Native SIL filter count must fit its two physical slots")
        for value in self.sil_ids:
            unsigned(value)
        if any(type(value) is not bool for value in self.sil_active):
            raise ValueError("Literal SIL filter flags required")
        if self.ownership_thread is not None and not isinstance(
            self.ownership_thread, threading.Thread
        ):
            raise TypeError("Native ownership thread reference required")
        for value in (self.ownership_ready, self.ownership_release):
            if value is not None and not isinstance(value, ManualResetEvent2026):
                raise TypeError("Native manual-reset event reference required")
        if self.history_sink is not None:
            if not isinstance(self.history_sink, MessageHistory2026):
                raise TypeError("Shared typed native history reference required")
            self.history_sink.__post_init__()
        if not isinstance(self.function_slots, tuple) or len(self.function_slots) != 25:
            raise ValueError("Native transfer has 25 function-pointer slots")
        for value in self.function_slots:
            unsigned(value)


class ManualResetEvent2026:
    """Actual manual-reset OS event with shared-handle invalidation on Close."""

    def __init__(self):
        self._event = threading.Event()
        self.closed = False
        # Diagnostic only: native typJ2534IF exports the event, not a status field.
        self.worker_error: BaseException | None = None

    def _check(self):
        if self.closed:
            raise ValueError("Native event handle is closed")

    def set(self):
        self._check()
        self._event.set()

    def clear(self):
        self._check()
        self._event.clear()

    def wait(self, timeout: float | None = None):
        self._check()
        return self._event.wait(timeout)

    def is_set(self):
        self._check()
        return self._event.is_set()

    def close(self):
        self.closed = True
