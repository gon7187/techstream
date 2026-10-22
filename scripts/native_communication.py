"""Selected Common communication over typed native frame operations; no implicit I/O."""

from __future__ import annotations

import math
import struct
import sys
import threading
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from scripts.database_resources import DdrPacketLog
    from scripts.drive_recorder import NativeVehicleSelection, NativeVehicleSession

from scripts.frame_transport import (
    DriverProperties,
    FrameTransportError,
    J2534Backend,
    NativeFrameOperations,
    NativeFrameReceive,
)
from scripts.frame_transport_variants import EthernetOperations, create_lower_transport
from scripts.monitor_support import (
    MonitorSupportCache,
    SupportQuery,
    SupportReceive,
    SupportSend,
)
from scripts.profiles import ProtocolProfile, SelectedFrame, VehicleProfile
from scripts.support import (
    ConnectionCacheEntry,
    ProtocolCandidate,
    ProtocolSelection,
    lookup_connection_cache,
    word,
)
from scripts.support import (
    check_protocol_cache as select_protocol_from_cache,
)
from scripts.toyota import ToyotaCodecError
from scripts.toyota_session import Cancelled, Limits, NativeFrameSend, SessionError

TIMEOUT = 0x91010009
NO_RESPONSE = 0x90020323
PARTIAL_RESPONSE = 0x90020321


class CommunicationError(ToyotaCodecError):
    def __init__(self, result: CommunicationResult):
        super().__init__("Native selected transaction failed", result.status)
        self.response = result.response


class FrameReceive(Protocol):
    @property
    def code(self) -> int: ...
    @property
    def data(self) -> bytes: ...


class FrameOperations(Protocol):
    def send(
        self,
        request: bytes | None,
        *,
        timeout: int,
        initialization_mode: int,
        clear_rx: int,
        no_session: bool = False,
        deadline: float,
    ) -> int: ...
    def receive(
        self,
        *,
        maximum: int,
        timeout: int,
        argument_5: int = 0,
        flags: int = 100,
        deadline: float,
    ) -> FrameReceive: ...
    def close(self) -> int | None: ...


@dataclass(frozen=True)
class CommunicationResult:
    status: int
    response: bytes
    attempts: int
    selected: SelectedFrame


@dataclass(frozen=True)
class ConnectionResult:
    status: int
    connected: bool
    selected: SelectedFrame | None
    response: bytes = b""
    cache_hit: bool = False


@dataclass(frozen=True)
class NativeConnectionEntry(ConnectionCacheEntry):
    """CShareData slot8 observation, including the native protocol BYTE."""

    protocol: int = 0

    def __post_init__(self) -> None:
        for value, lower, upper in (
            (self.category, 0, 0xFFFFFFFF),
            (self.variant, 0, 0xFFFF),
            (self.supported, -(1 << 31), (1 << 31) - 1),
            (self.protocol, 0, 255),
        ):
            if type(value) is not int or not lower <= value <= upper:
                raise ValueError("Native connection-cache scalar exceeds its ABI")
        if type(self.request) is not bytes or type(self.reply) is not bytes:
            raise TypeError("Native connection-cache frames must be immutable bytes")


@dataclass(frozen=True)
class BehaviorResult:
    status: int
    supported: bool
    ignored_failure: bool
    identifiers: tuple[int, ...] = ()


@dataclass
class OperationUsage:
    primitive_calls: int = 0
    cache_calls: int = 0

    @property
    def used(self) -> int:
        return max(self.primitive_calls, self.cache_calls)


def receive_timeout(
    profile: ProtocolProfile,
    request: bytes,
    bus_id: int,
    timeout: int,
    source_build: int,
) -> int:
    """18 Common6bbe0 is advisory: absent optional joins leave timeout intact."""
    if source_build == 12 or not request or not 1 <= request[0] <= 10:
        return timeout
    try:
        prot = profile.protocol_info(bus_id)
        if prot is None or len(prot) <= 26 or prot[26] != 1:
            return timeout
        rows = profile.comm_info_can_records(word(prot, 2))
        return word(rows[0], 14) if rows else timeout
    except ToyotaCodecError as error:
        if error.code in (0xA0030107, 0x90020104):
            return timeout
        raise


def wwh_request_state(request: bytes | None) -> int:
    """Native18 EE50 classification used by the WWH virtual160 method."""
    if not request:
        return 1
    sid, size = request[0], len(request)
    if (
        sid == 0x14
        and size >= 4
        and request[1:3] == b"\xff\xff"
        and request[3] in (0x33, 0xFF)
    ):
        return 4
    if sid == 0x19:
        if size >= 2 and request[1] == 0x42:
            return 3
        if size >= 6 and (
            (request[1] == 4 and request[5] == 0)
            or (request[1] == 6 and (0x90 <= request[5] <= 0xEF or request[5] == 0xFE))
        ):
            return 3
    if sid == 0x22 and size >= 3 and 0xF4 <= request[1] <= 0xF8:
        return 4
    if sid == 0x31 and size >= 4 and request[2] in (0xE0, 0xE1):
        return 3
    return 1


class NativeFrameController:
    """CCommFrameCtrl outer lifecycle over the concrete retained native lower."""

    def __init__(self, operations: NativeFrameOperations):
        self.operations = operations
        self.profile = operations.profile
        self.current_category = 0
        self._interface_word = word(operations.diagnostic_mode, 0)
        self._context_failed = False
        self._reconstruct_after_failed_open = False
        self.current_bus = 0
        self.session_state = 0
        self.current_service = 0
        self.events: list[tuple[str, int]] = []
        self.communication_mode = 0
        self.session_wait_ms = 0
        self.legacy_initialized = False
        self.legacy_service = 10000
        self._session_parameters: tuple[int, int, int] | None = None
        self._tester_thread: threading.Thread | None = None
        self._tester_stop = threading.Event()
        self._tester_request = b""
        self._tester_category = 0
        self._tester_mode = 1
        self._tester_tick = 0.0
        self._tester_enabled = False
        self.tester_error: Exception | None = None
        self._idle_thread: threading.Thread | None = None
        self._idle_stop = threading.Event()
        self.idle_error: Exception | None = None
        self._connection_entries: list[NativeConnectionEntry] = []

    def _event(self, name: str, value: int) -> None:
        self.events.append((name, value))
        del self.events[:-256]

    @property
    def native_build(self) -> int:
        return self.operations.native_build

    def set_packet_log(
        self,
        writer: Callable[[bytes], int] | None,
        failure: Callable[[], None] | None = None,
    ) -> None:
        """The outer logger survives native lower-class reconstruction."""
        self.operations.set_packet_log(writer, failure)

    def stop_tester(self) -> int:
        """15890 stop/ack before touching the retained communication channel."""
        self._tester_stop.set()
        thread = self._tester_thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=5.0)
            if thread.is_alive():
                return 0x90020402
        self._tester_thread = None
        self._event("tester_stop", 0)
        return 0

    def start_tester(self) -> int:
        """155f0 selects function DD, not the lower startup/tester frame 7F."""
        if self.current_bus == 0x1C or self.current_bus & 15 == 10:
            return 0
        if self._tester_thread is not None and self._tester_thread.is_alive():
            return 0
        if self._tester_category != self.current_category:
            try:
                request = self.profile.function_frame(0xDD).frame.request
            except ToyotaCodecError as error:
                return error.code
            if not request:
                return 0x90020401
            self._tester_request = request
            self._tester_category = self.current_category
            self._tester_mode = 1
        self._tester_tick = self.operations.clock()
        self._tester_stop.clear()
        self.tester_error = None
        self._tester_thread = threading.Thread(target=self._tester_worker, daemon=True)
        self._tester_thread.start()
        self._event("tester_start", self.current_category)
        return 0

    def _tester_cycle(self) -> None:
        """15d30 invokes the base send/read directly, preserving the outer SID."""
        request = self._tester_request[: len(self._tester_request) & 255]
        deadline = self.operations.clock() + 5.0
        code = self.operations.send(
            request,
            timeout=1000,
            initialization_mode=self._tester_mode,
            clear_rx=1,
            no_session=False,
            deadline=deadline,
        )
        self._tester_mode = 1
        if code:
            self.session_state = 0
            return
        received = self.operations.receive(
            maximum=0x78,
            timeout=1000,
            argument_5=0,
            flags=100,
            deadline=deadline,
        )
        reply = received.data
        if received.code == 0 and request:
            if self.operations.native_build == 18 and request[0] == 0x10:
                if reply and reply[0] == 0x50:
                    self.session_state = 3
                    return
            elif (
                len(reply) >= 4
                and len(request) >= 3
                and reply[0] == request[0] + 0x40
                and reply[1:3] == request[1:3]
            ):
                self.session_state = reply[3]
                return
        self._tester_mode = self.session_state = 0

    def stop_idle(self) -> int:
        self._idle_stop.set()
        thread = self._idle_thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=5.0)
            if thread.is_alive():
                return 0x90020404
        self._idle_thread = None
        return 0

    def start_idle(self, *, deadline: float | None = None) -> int:
        """16380 / 12-11b60: wake the lowA inactivity watcher."""
        if self._idle_thread is not None and self._idle_thread.is_alive():
            return 0
        if not self.operations.last_activity:
            until = self.operations.clock() + 30.0 if deadline is None else deadline
            self.operations._wait_ms(5000, until)
            return 0x90020403
        self._idle_stop.clear()
        self.idle_error = None
        self._idle_thread = threading.Thread(target=self._idle_worker, daemon=True)
        self._idle_thread.start()
        return 0

    def _idle_cycle(self) -> float:
        if self.current_bus & 15 != 10 or not self.operations.last_activity:
            return 0.0
        elapsed = (
            (int(self.operations.clock() * 1000) & 0xFFFFFFFF)
            - self.operations.last_activity
        ) & 0xFFFFFFFF
        if elapsed < 3000:
            return (3000 - elapsed) / 1000
        self.operations.pre_initialize(deadline=self.operations.clock() + 5.0)
        self.operations.clear_runtime_context()
        self.current_category = 0
        self._event("idle", 0)
        return 0.0

    def _idle_worker(self) -> None:
        try:
            delay = 3.0
            while not self._idle_stop.wait(delay):
                delay = self._idle_cycle()
                if not delay:
                    break
        except Exception as error:  # noqa: BLE001 -- retain host worker failure
            self.idle_error = error
            self._idle_stop.set()

    def _tester_worker(self) -> None:
        try:
            delay = 2.0
            while not self._tester_stop.wait(delay):
                delay = max(0.0, 2.0 - (self.operations.clock() - self._tester_tick))
                if delay:
                    continue
                self._tester_cycle()
                delay = 2.0
        except Exception as error:  # noqa: BLE001 -- worker boundary records host errors
            # Retain provider/policy failure for the owner; never retry uncertain I/O.
            self.tester_error = error
            self._tester_stop.set()

    @staticmethod
    def _service_family(service: int) -> int:
        return 1 if 1 <= service <= 15 else 2 if service >= 16 else 0

    def _parameters(self) -> tuple[int, int, int] | None:
        prot = self.profile.protocol_info(self.operations.bus_id)
        return None if prot is None else (word(prot, 8), word(prot, 10), word(prot, 20))

    def _setup(self, deadline: float) -> int:
        code = self.operations.setup(deadline=deadline)
        if code == 0:
            self._session_parameters = self._parameters()
        return code

    def _session_command(self, function: int, mode: int, deadline: float) -> int:
        """PSA cc40/12-93f0 ignores packet statuses, retaining host policy failures."""
        if isinstance(self.operations, EthernetOperations):
            return self.operations.send_function(
                function, initialization_mode=mode, no_session=True, deadline=deadline
            )
        try:
            selected = self.profile.function_frame(function)
            prot = self.profile.protocol_info(self.operations.bus_id)
            if prot is None:
                return 0x90020104
            records = self.profile.comm_info_can_records(word(prot, 2))
            if not records:
                return 0x90020104
        except ToyotaCodecError as error:
            return error.code
        request = selected.frame.request[: len(selected.frame.request) & 255]
        self.operations.send(
            request or None,
            timeout=1000,
            initialization_mode=mode,
            clear_rx=1,
            no_session=True,
            deadline=deadline,
        )
        self.operations.receive(
            maximum=0x78,
            timeout=word(records[0], 12),
            argument_5=0,
            flags=100,
            deadline=deadline,
        )
        self._event("session_command", function)
        return 0

    def _enter_session(self, mode: int, deadline: float) -> None:
        self._session_command(0xD1, mode, deadline)
        self._session_command(0xD2, mode, deadline)
        self.session_state = 3
        if self.session_wait_ms:
            self.operations._wait_ms(self.session_wait_ms, deadline)
            self.session_wait_ms = 0

    def change_context(
        self,
        profile: ProtocolProfile,
        *,
        bus_id: int,
        first_request: bytes,
        request: bytes | None,
        deadline: float,
        diagnostic_mode: bytes | None = None,
        interface_word: int | None = None,
    ) -> int:
        """14510/12-ffa0 retain or replace the actual selected lower class."""
        stopped = self.stop_idle()
        if stopped:
            return stopped
        old = self.operations
        mode = old.diagnostic_mode if diagnostic_mode is None else diagnostic_mode
        if interface_word is None:
            interface_word = word(mode, 0)
        flags = profile.category_record[72]
        psa = bus_id & 15 == 2 and flags & 31 in (0x14, 0x15)
        variant = (
            ("psa_wwh" if old.native_build == 18 and profile.mode_wwh() else "psa")
            if psa
            else "normal"
        )
        old_bus = self.current_bus or old.bus_id
        special = (
            (0x12, 0x22, 0x62, 0x14) if old.native_build == 18 else (0x12, 0x22, 0x62)
        )
        rebuild = self._reconstruct_after_failed_open or (
            old_bus in special
            and bus_id in special
            and old_bus != bus_id
            or old_bus == 0x32
            and bus_id in special
            or old_bus & 15 != bus_id & 15
        )
        if old.device_kind in (2, 8) and old_bus & 15 == bus_id & 15 == 8:
            rebuild |= self._interface_word != interface_word
        old_flags = self.profile.category_record[72]
        if bus_id & 15 == 2:
            rebuild |= old_flags != flags or old.native_variant != variant
        parameters = profile.protocol_info(bus_id) if psa else None
        matches = parameters is not None and self._session_parameters == (
            word(parameters, 8),
            word(parameters, 10),
            word(parameters, 20),
        )
        if (
            (not rebuild and not (psa and matches))
            or rebuild
            and old_flags & 31 in (0x14, 0x15)
        ):
            code = self.stop_communication_check(
                profile.category, request, deadline=deadline
            )
            if code:
                return code
        if (
            not rebuild
            and profile is self.profile
            and bus_id == old.bus_id
            and bus_id & 15 not in (2, 4)
        ):
            return (
                0  # Native same-class fast path only performs StopCommunicationCheck.
            )
        reopen_ethernet, retained_status = False, 0
        if not rebuild and bus_id & 15 == 4 and isinstance(old, EthernetOperations):
            retained_status, state = old.session_state(deadline=deadline)
            if state != 2:
                code = self.stop_tester()
                if code:
                    return code
                code = old.release_channels(deadline=deadline)
                if code:
                    self._context_failed = True
                    return code
                reopen_ethernet = True
        if rebuild:
            code = self.close()
            self._context_failed = True
            self._reconstruct_after_failed_open = False
            if code:
                return code
        # Constructor is pure; native setup remains in the subsequent SendProc.
        try:
            candidate = create_lower_transport(
                profile,
                first_request,
                old.backend,
                native_build=old.native_build,
                bus_id=bus_id,
                driver=old.driver,
                device_kind=old.device_kind,
                interface_word=interface_word,
                diagnostic_mode=mode,
                native_variant=variant,
                open_baud=old.open_baud,
                communication_interval=old.communication_interval,
                clock=old.clock,
                cancelled=old.cancelled,
                wait=old.wait,
                shared_state=old.shared_state,
                ethernet_settings=(
                    old.ethernet_settings
                    if isinstance(old, EthernetOperations)
                    else None
                ),
            )
        except FrameTransportError as error:
            return error.status
        except ToyotaCodecError as error:
            return error.code
        if rebuild:
            candidate.set_packet_log(*old.packet_log_hooks)
            self.operations = candidate
            self.profile = profile
            code = candidate.open(deadline=deadline, setup=False)
            if code:
                return self._failed_open(code)
            self._session_parameters = None
        else:
            old.rebind(profile, candidate.plan, bus_id=bus_id, diagnostic_mode=mode)
            if reopen_ethernet:
                self._context_failed = True
                code = old.open(deadline=deadline)
                if code:
                    return self._failed_open(code)
                retained_status = 0
        self.profile = profile
        self._context_failed = False
        self._interface_word = interface_word
        self._event("context", profile.category)
        return retained_status

    def _failed_open(self, status: int) -> int:
        """Native ChangeCommIF discards the lower after a completed open failure."""
        self._context_failed = True
        self._reconstruct_after_failed_open = False
        if self.close() == 0 and not self.operations.poisoned:
            self._context_failed = False
            self._reconstruct_after_failed_open = True
        return status

    def stop_communication_check(
        self, category: int, request: bytes | None, *, deadline: float
    ) -> int:
        """14f10 / 12-10780 stop old sessions without disconnecting the channel."""
        if not self.current_category or self.operations.channel is None:
            return 0
        if self.current_category == category:
            if self.current_bus != 0x1C or not (
                request is None
                or (
                    self.legacy_service != 10000
                    and request
                    and self.legacy_service != request[0]
                )
            ):
                return 0
            code = self.operations.finish_bus_session(deadline=deadline)
            if code:
                return code
        else:
            if self.profile.category_record[72] & 31 in (0x14, 0x15):
                code = self.stop_tester()
                if code:
                    return code
                diagnostic = (
                    self.operations.request_state in (1, 2)
                    if self.operations.native_variant == "psa_wwh"
                    else self._service_family(self.operations.current_service) == 2
                )
                if not diagnostic:
                    self.operations.set_service_context(0x10)
                    self._tester_enabled = True
                    code = self._setup(deadline)
                    if code:
                        self.close()
                        return code
            code = self.operations.pre_initialize(deadline=deadline)
            if code:
                return code
            code = self.operations.finish_bus_session(deadline=deadline)
            if code:
                return code
            self.session_state = 0
        self.operations.clear_runtime_context()
        self.current_category = 0
        self.legacy_service = 10000
        self.legacy_initialized = False
        return 0

    def _prepare_psa(
        self, request: bytes | None, mode: int, no_session: bool, deadline: float
    ) -> int:
        stopped = self.stop_tester()
        if stopped:
            return stopped
        if request is None:
            self._tester_enabled = True
            self.operations.set_service_context(0)
            return 0
        wwh = self.operations.native_variant == "psa_wwh"
        next_state = wwh_request_state(request) if wwh else 0
        family = (
            (1 if next_state in (3, 4) else 2)
            if wwh
            else self._service_family(request[0])
            if request
            else 0
        )
        if not no_session:
            previous = (
                (
                    1
                    if self.operations.request_state in (3, 4)
                    else 2
                    if self.operations.request_state in (1, 2)
                    else 0
                )
                if wwh
                else self._service_family(self.operations.current_service)
            )
            same = (
                self._session_parameters == self._parameters()
                and self._session_parameters is not None
            )
            if same and family == previous and family != 0:
                if family == 2 and self.session_state != 3:
                    self._enter_session(mode, deadline)
            else:
                self._tester_enabled = True
                self.operations.set_service_context(0x10)
                code = self._setup(deadline)
                if code:
                    return code
                if family == 2:
                    self._enter_session(mode, deadline)
                elif family == 1:
                    self._session_command(0xD1, mode, deadline)
                    self.session_state = 0
        if self.communication_mode == 0x11 and self.session_state != 0:
            self.operations.set_service_context(0x10)
            code = self._setup(deadline)
            if code:
                return code
            self._session_command(0xD1, mode, deadline)
            self.session_state = 0
        self.operations.set_service_context(request[0] if request else 0)
        if wwh:
            self.operations.set_request_state(next_state)
        return 0

    def send(
        self,
        request: bytes | None,
        *,
        timeout: int,
        initialization_mode: int,
        clear_rx: int,
        no_session: bool = False,
        deadline: float,
        profile: ProtocolProfile | None = None,
        bus_id: int | None = None,
        first_request: bytes | None = None,
    ) -> int:
        if self._context_failed:
            return 0x90020701
        first = (
            request
            if request
            else (
                first_request
                if first_request is not None
                else self.operations.plan.startup_request
            )
        )
        code = self.change_context(
            self.profile if profile is None else profile,
            bus_id=self.operations.bus_id if bus_id is None else bus_id,
            first_request=first,
            request=request,
            deadline=deadline,
        )
        if code:
            return code
        if self.communication_mode == 0x11:
            initialization_mode, no_session = 2, True
        if self.operations.bus_id == 0x1C:
            initialization_mode = 2
        if self.operations.channel is None:
            code = self.operations.open(deadline=deadline, setup=False)
            if code:
                return self._failed_open(code)
        if isinstance(self.operations, EthernetOperations):
            self.operations.set_service_context(request[0] if request else 0)
        if self.profile.category_record[72] & 0x1F in (0x14, 0x15):
            if self.operations.native_variant in ("psa", "psa_wwh"):
                code = self._prepare_psa(
                    request, initialization_mode, no_session, deadline
                )
                if code:
                    self.close()
                    return code
            else:
                # Normal protocol classes have constant-zero PSA virtual predicates.
                self.operations.set_service_context(request[0] if request else 0)
        code = self._setup(deadline)
        if code:
            self.close()
            return code
        self.current_category = self.profile.category
        self.current_bus = self.operations.bus_id
        self.current_service = request[0] if request else 0
        self._event("service", self.current_service)
        if self.current_bus == 0x1C:
            if request is None or (
                not self.legacy_initialized
                and self.legacy_service != self.current_service
            ):
                code = self.operations.prepare_bus_session(deadline=deadline)
                if code:
                    self.legacy_initialized = False
                    self.legacy_service = 10000
                    return code
            if request is None:
                self.legacy_initialized = True
                self.legacy_service = 10000
                return 0
            self.legacy_initialized = False
            self.legacy_service = self.current_service
        else:
            self.legacy_initialized = False
            self.legacy_service = 10000
        self.operations.idle = False
        status = self.operations.send(
            request,
            timeout=timeout,
            initialization_mode=initialization_mode,
            clear_rx=clear_rx,
            no_session=no_session,
            deadline=deadline,
        )
        if self.current_bus & 15 == 10 and (status == 0 or self.operations.idle):
            self.start_idle(
                deadline=deadline
            )  # Native SendProc preserves its send status.
            self.operations.idle = False
        return status

    def receive(
        self,
        *,
        maximum: int,
        timeout: int,
        argument_5: int = 0,
        flags: int = 100,
        deadline: float,
    ) -> NativeFrameReceive:
        if self._context_failed:
            return NativeFrameReceive(code=0x90020701)
        received = self.operations.receive(
            maximum=maximum,
            timeout=timeout,
            argument_5=argument_5,
            flags=flags,
            deadline=deadline,
        )
        if (
            self.current_category == 0x1B5
            and len(received.data) > 2
            and received.data[:2] == b"\x61\x80"
        ):
            received = replace(
                received,
                data=received.data[:2]
                + bytes((received.data[2] & 0xF7,))
                + received.data[3:],
            )
        if received.code in (0, PARTIAL_RESPONSE, NO_RESPONSE):
            self._tester_tick = self.operations.clock()
        if self.profile.category_record[72] & 31 in (0x14, 0x15):
            enabled = (
                self.operations.request_state in (1, 2)
                if self.operations.native_variant == "psa_wwh"
                else self.current_service > 15
                if self.operations.native_build == 12
                else self._tester_enabled
            )
            if enabled:
                self.start_tester()  # Native Receive ignores TestPresentStart status.
        return received

    def close(self) -> int:
        return self.disconnect(0)

    def disconnect(self, flag: int = 0, *, deadline: float | None = None) -> int:
        """15ba0 / 12-11400: flag1 retains the PSA pre-init D1 setting."""
        if type(flag) is not int or not -(1 << 31) <= flag < 1 << 31:
            raise ValueError("Native Disconnect flag must be a signed DWORD")
        first = self.stop_tester() or self.stop_idle()
        if first:
            return first
        try:
            if (
                self.operations.channel is not None
                and not self.operations.poisoned
                and self.current_category != 0
                and self.operations.native_variant in ("psa", "psa_wwh")
                and not self.operations.cancelled()
            ):
                if flag != 1:
                    self.operations.set_preinit_d1_suppressed(1)
                diagnostic = (
                    self.operations.request_state in (1, 2)
                    if self.operations.native_variant == "psa_wwh"
                    else self._service_family(self.operations.current_service) == 2
                )
                if not diagnostic:
                    self.operations.set_service_context(0x10)
                    self._tester_enabled = True
                    first = self.operations.setup(deadline=deadline)
        finally:
            try:
                closed = self.operations.close(deadline=deadline)
            finally:
                self.current_category = self.current_bus = 0
                self.session_state = self.current_service = 0
                self._session_parameters = None
        return first or closed


class NativeCommunication:
    """Common5d190/71790 with one retained lower channel and shared Ever/TEMP cache.

    Operations must be an explicitly supplied NativeFrameOperations instance.
    Import/construction never opens an adapter or executes a vendor binary.
    """

    def __init__(
        self,
        profile: ProtocolProfile,
        operations: FrameOperations,
        ecu: str,
        *,
        bus_id: int,
        source_build: int = 18,
        limits: Limits | None = None,
        cancelled: Callable[[], bool] = lambda: False,
        clock: Callable[[], float] = time.monotonic,
    ):
        if source_build not in (12, 18) or type(source_build) is not int:
            raise ValueError("Native source build must be 12 or 18")
        if type(bus_id) is not int or not 0 <= bus_id <= 65535:
            raise ValueError("Observed bus identity must be ushort")
        self.profile, self.operations, self.ecu = profile, operations, ecu
        self.bus_id, self.source_build = bus_id, source_build
        self.limits, self.cancelled, self.clock = limits or Limits(), cancelled, clock
        self.deadline, self.calls = clock() + self.limits.seconds, 0
        self.no_init = self.no_session = False
        self.closed = False
        self.cache = MonitorSupportCache(
            profile,
            self,
            ecu,
            source_build=source_build,
            stream=self,
            bus_id=bus_id,
            limits=self.limits,
            cancelled=cancelled,
            clock=clock,
        )
        self.cleanup_status = 0
        self._cleanup_pending = False
        self.last_result: CommunicationResult | None = None
        self._comm_log: DdrPacketLog | None = None
        self._shared_controller = False
        self._context_first_request: bytes | None = None
        self._selected_vehicle_binding: tuple[object, ...] | None = None
        self._selected_vehicle_context: NativeCommunication | None = None
        self._native_backend = (
            operations.operations.backend
            if isinstance(operations, NativeFrameController)
            else None
        )
        self._native_driver = (
            operations.operations.driver
            if isinstance(operations, NativeFrameController)
            else None
        )
        self._native_device_kind = (
            operations.operations.device_kind
            if isinstance(operations, NativeFrameController)
            else None
        )

    def bind_comm_log(self, logger: DdrPacketLog) -> None:
        """Bind the concrete native file owner to this retained controller."""
        from scripts.database_resources import DdrPacketLog

        if (
            type(logger) is not DdrPacketLog
            or logger.operations is not self.operations
            or not isinstance(self.operations, NativeFrameController)
            or self.source_build != self.operations.native_build
        ):
            raise ValueError("Communication log must bind this native controller/build")
        if self._comm_log is not None and self._comm_log is not logger:
            raise ValueError("Communication log owner is already bound")
        self._comm_log = logger

    def start_comm_log(self, kind: int) -> int:
        self._check()
        if self._comm_log is None:
            raise ValueError("Concrete native communication-log file owner is required")
        return self._comm_log.start(kind)

    def stop_comm_log(self) -> int:
        # Stop remains available after Disconnect or parent cancellation.
        if self._comm_log is None:
            raise ValueError("Concrete native communication-log file owner is required")
        return self._comm_log.stop()

    def share_context(
        self,
        profile: ProtocolProfile,
        ecu: str,
        *,
        bus_id: int,
        first_request: bytes,
    ) -> NativeCommunication:
        """Pin another Common cache to the same native outer controller."""
        self._check()
        if not isinstance(self.operations, NativeFrameController):
            raise TypeError("Shared contexts require the concrete native controller")
        if not isinstance(first_request, bytes) or len(first_request) > 65535:
            raise ValueError("Shared context requires a selected constructor request")
        if self._context_first_request is None:
            raise ValueError("Shared owner requires its concrete constructor request")
        sibling = NativeCommunication(
            profile,
            self.operations,
            ecu,
            bus_id=bus_id,
            source_build=self.source_build,
            limits=self.limits,
            cancelled=self.cancelled,
            clock=self.clock,
        )
        sibling.cache.share_ever_cache(self.cache)
        sibling.cache.share_discovery_cache(self.cache)
        self._shared_controller = sibling._shared_controller = True
        sibling._context_first_request = first_request
        return sibling

    def bind_selected_vehicle(
        self,
        session: NativeVehicleSession,
        selection: NativeVehicleSelection,
        profile: VehicleProfile,
        ecu: str,
        *,
        bus_id: int,
        first_request: bytes,
    ) -> NativeCommunication:
        """Bind a selector-proved terminal model to this retained outer controller."""
        from scripts.drive_recorder import NativeVehicleSelection, NativeVehicleSession
        from scripts.frame_transport import runtime_frame_plan

        self._check()
        if type(self.operations) is not NativeFrameController:
            raise TypeError("Selected vehicle binding requires its concrete controller")
        if (
            type(session) is not NativeVehicleSession
            or session.communication is not self
        ):
            raise ValueError("Selected vehicle binding requires its original session")
        session._check()
        lower = self.operations.operations
        if (
            type(selection) is not NativeVehicleSelection
            or type(profile) is not VehicleProfile
            or type(ecu) is not str
            or not ecu
            or "\0" in ecu
            or type(bus_id) is not int
            or not 0 <= bus_id <= 65535
            or type(first_request) is not bytes
            or len(first_request) > 65535
        ):
            raise ValueError("Invalid selected vehicle binding inputs")
        if (
            type(selection.trailing_words) is not tuple
            or len(selection.trailing_words) != 2
            or any(type(value) is not int for value in selection.trailing_words)
        ):
            raise ValueError("Native vehicle selection has malformed terminal words")
        model = selection.trailing_words[1]
        if (
            selection.trailing_words[0] != 0
            or type(model) is not int
            or not 1 <= model <= 0xFFFE
            or session.current_model != model
            or not session.model_list
            or session.model_list[0] != model
        ):
            raise ValueError("A matching terminal native vehicle selection is required")
        if (
            self.closed
            or lower.poisoned
            or self.operations._context_failed
            or self._context_first_request is None
            or self.source_build != lower.native_build
            or lower.backend is not self._native_backend
            or lower.driver is not self._native_driver
            or lower.device_kind != self._native_device_kind
            or self.operations.profile is not lower.profile
            or lower.profile.catalog is not self.profile.catalog
            or lower.profile.catalog.management.sha256
            != self.profile.catalog.management.sha256
            or tuple(lower.profile.exception_ids) != tuple(self.profile.exception_ids)
            or profile.catalog is not self.profile.catalog
            or profile.catalog.management.sha256
            != self.profile.catalog.management.sha256
            or tuple(profile.exception_ids) != tuple(self.profile.exception_ids)
            or profile.vehicle_name_key != model
            or ecu != self.ecu
        ):
            raise ValueError("Selected vehicle source or retained controller changed")
        systems = profile.catalog.vehicle_systems(model, tuple(profile.exception_ids))
        if not any(
            item["category"] == profile.category and item["file"] == profile.filename
            for item in systems
        ):
            raise ValueError("Selected ECU is not associated with the terminal vehicle")
        if type(self.operations.operations.driver) is not DriverProperties:
            raise ValueError("Selected native driver properties are not validated")
        target_variant = (
            ("psa_wwh" if self.source_build == 18 and profile.mode_wwh() else "psa")
            if bus_id & 15 == 2 and profile.category_record[72] & 0x1F in (0x14, 0x15)
            else "normal"
        )
        runtime_frame_plan(
            profile,
            first_request,
            native_build=self.source_build,
            native_variant=target_variant,
            bus_id=bus_id,
            driver=lower.driver,
            diagnostic_mode=lower.diagnostic_mode,
        )
        binding = (session, model, profile, ecu, bus_id, first_request)
        if self._selected_vehicle_binding is not None:
            if (
                self._selected_vehicle_binding == binding
                and self._selected_vehicle_context is not None
            ):
                return self._selected_vehicle_context
            raise ValueError("This retained owner is already bound to another vehicle")

        sibling = NativeCommunication(
            profile,
            self.operations,
            ecu,
            bus_id=bus_id,
            source_build=self.source_build,
            limits=self.limits,
            cancelled=self.cancelled,
            clock=self.clock,
        )
        protocol_profile = profile.catalog.build_protocol_profile(
            profile.category, exception_ids=tuple(profile.exception_ids)
        )
        sibling.cache._bind_selected_vehicle_storage(
            self.cache, protocol_profile=protocol_profile
        )
        self._shared_controller = sibling._shared_controller = True
        sibling._context_first_request = first_request
        self._selected_vehicle_binding = binding
        self._selected_vehicle_context = sibling
        return sibling

    def _active_context(self) -> bool:
        return not isinstance(self.operations, NativeFrameController) or (
            self.operations.profile is self.profile
            and self.operations.operations.bus_id == self.bus_id
        )

    def protocol_context(
        self,
        profile: ProtocolProfile,
        *,
        bus_id: int,
    ) -> NativeCommunication:
        """Bind a protocol candidate using its canonical native default frame."""
        frame, _ = profile._communication_frame(0)
        request = frame.request[: len(frame.request) & 255]
        return self.share_context(
            profile,
            f"{self.ecu}:{profile.category}:{bus_id}",
            bus_id=bus_id,
            first_request=request,
        )

    @classmethod
    def from_backend(
        cls,
        profile: ProtocolProfile,
        backend: J2534Backend,
        ecu: str,
        *,
        first_request: bytes,
        driver: DriverProperties,
        device_kind: int,
        bus_id: int,
        source_build: int,
        limits: Limits | None = None,
        diagnostic_mode: bytes = bytes(16),
        interface_word: int | None = None,
        cancelled: Callable[[], bool] = lambda: False,
        clock: Callable[[], float] = time.monotonic,
    ) -> NativeCommunication:
        """Bind authored selected metadata to concrete J2534 operations without I/O."""
        if source_build not in (12, 18):
            raise ValueError("Explicit native build 12 or 18 required")
        if interface_word is None:
            interface_word = word(diagnostic_mode, 0)
        variant = (
            ("psa_wwh" if source_build == 18 and profile.mode_wwh() else "psa")
            if (bus_id & 15 == 2 and profile.category_record[72] & 0x1F in (0x14, 0x15))
            else "normal"
        )
        lower = create_lower_transport(
            profile,
            first_request,
            backend,
            native_build=source_build,
            bus_id=bus_id,
            driver=driver,
            device_kind=device_kind,
            diagnostic_mode=diagnostic_mode,
            interface_word=interface_word,
            native_variant=variant,
            cancelled=cancelled,
            clock=clock,
        )
        controller = NativeFrameController(lower)
        controller._interface_word = interface_word
        runtime = cls(
            profile,
            controller,
            ecu,
            bus_id=bus_id,
            source_build=source_build,
            limits=limits,
            cancelled=cancelled,
            clock=clock,
        )
        runtime._context_first_request = first_request
        return runtime

    def _check(self, *, timeout_error: BaseException | None = None) -> None:
        if self.closed:
            raise SessionError("Native communication is closed")
        if self.cancelled():
            raise Cancelled("Native communication cancelled")
        now = self.clock()
        if not math.isfinite(now) or now >= self.deadline:
            if isinstance(timeout_error, TimeoutError):
                raise timeout_error
            raise SessionError("Native communication deadline exhausted")
        if self.source_build != self.cache.source_build:
            raise SessionError("Selected native source build changed")
        self.cache.check_context()
        if (
            isinstance(self.operations, NativeFrameController)
            and self.operations.native_build != self.source_build
        ):
            raise SessionError("Retained controller native source build changed")
        if not self._shared_controller and not self._active_context():
            raise SessionError("Retained controller selected context changed")

    def begin_operation(self, *, limits: Limits | None = None) -> None:
        if limits is not None:
            self.limits = limits
        self.cache.begin_operation(limits=self.limits)
        self.deadline, self.calls = self.clock() + self.limits.seconds, 0
        self._check()

    @contextmanager
    def communication_flags(self, *, no_init: bool, no_session: bool) -> Iterator[None]:
        """Scope native CCommCachePlus flags independently of retained storage."""
        if type(no_init) is not bool or type(no_session) is not bool:
            raise ValueError("Native communication flags must be bool")
        saved = self.no_init, self.no_session
        self.no_init, self.no_session = no_init, no_session
        try:
            yield
        finally:
            self.no_init, self.no_session = saved

    @contextmanager
    def constrain_operation(
        self,
        *,
        deadline: float,
        exchanges: int,
        cancelled: Callable[[], bool] = lambda: False,
    ) -> Iterator[OperationUsage]:
        """Narrow one synchronous parent operation without resetting native caches."""
        if not math.isfinite(deadline) or type(exchanges) is not int or exchanges < 1:
            raise ValueError(
                "Parent operation needs a finite deadline and positive allowance"
            )
        saved = (
            self.deadline,
            self.limits,
            self.cancelled,
            self.cache.deadline,
            self.cache.limits,
            self.cache.cancelled,
        )
        initial_calls, initial_cache = self.calls, self.cache.calls
        original_cancelled, cache_cancelled = self.cancelled, self.cache.cancelled
        lower = (
            self.operations.operations
            if isinstance(self.operations, NativeFrameController)
            else self.operations
            if isinstance(self.operations, NativeFrameOperations)
            else None
        )
        lower_cancelled = lower.cancelled if lower is not None else None
        if lower is not None and lower_cancelled is not None:
            lower.cancelled = lambda: lower_cancelled() or cancelled()
        usage = OperationUsage()
        self.deadline = min(self.deadline, deadline)
        self.cache.deadline = min(self.cache.deadline, deadline)
        self.limits = replace(
            self.limits, exchanges=min(self.limits.exchanges, self.calls + exchanges)
        )
        self.cache.limits = replace(
            self.cache.limits,
            exchanges=min(self.cache.limits.exchanges, self.cache.calls + exchanges),
        )
        self.cancelled = lambda: original_cancelled() or cancelled()
        self.cache.cancelled = lambda: cache_cancelled() or cancelled()
        try:
            self._check()
            yield usage
        finally:
            if lower is not None and lower_cancelled is not None:
                lower.cancelled = lower_cancelled
            usage.primitive_calls = self.calls - initial_calls
            usage.cache_calls = self.cache.calls - initial_cache
            (
                self.deadline,
                self.limits,
                self.cancelled,
                self.cache.deadline,
                self.cache.limits,
                self.cache.cancelled,
            ) = saved

    def _primitive(self) -> None:
        self._check()
        if self.calls >= self.limits.exchanges:
            raise SessionError("Native communication primitive budget exhausted")
        self.calls += 1

    def send_native(self, send: NativeFrameSend) -> int:
        self._primitive()
        if send.command_id != self.profile.category or send.parameter5 != self.bus_id:
            raise ValueError(
                "Native send selected category/bus differs from retained channel"
            )
        if (
            self.source_build == 12
            and send.operation == "SendIntNoInitNoSession"
            and send.request is not None
            and len(send.request) > 255
        ):
            raise ValueError("Version12 no-session request length is BYTE")
        mode = (
            2
            if send.operation
            in (
                "SendIntNoInit",
                "SendIntNoInitExt",
                "SendIntNoInitNoSession",
                "SendIntExtDualMon",
            )
            else 0
            if send.parameter6 == 1
            else 1
        )
        if (
            mode != 0
            and not send.request
            and not (
                send.request is None
                and self.bus_id == 0x1C
                and isinstance(self.operations, NativeFrameController)
            )
        ):
            return 0x90020701
        try:
            if isinstance(self.operations, NativeFrameController):
                status = self.operations.send(
                    send.request,
                    timeout=send.parameter4,
                    initialization_mode=mode,
                    clear_rx=send.parameter7,
                    no_session=send.operation == "SendIntNoInitNoSession",
                    deadline=self.deadline,
                    profile=self.profile,
                    bus_id=self.bus_id,
                    first_request=self._context_first_request,
                )
            else:
                status = self.operations.send(
                    send.request,
                    timeout=send.parameter4,
                    initialization_mode=mode,
                    clear_rx=send.parameter7,
                    no_session=send.operation == "SendIntNoInitNoSession",
                    deadline=self.deadline,
                )
        finally:
            self._check(timeout_error=sys.exception())
        if type(status) is not int or not 0 <= status <= 0xFFFFFFFF:
            raise ValueError("Native send returned malformed status")
        return status

    def send(self, send: SupportSend, /) -> int:
        operation = (
            "SendIntNoInitNoSession"
            if self.no_session
            else "SendIntNoInit"
            if self.no_init
            else "SendInt"
        )
        if send.query.extended and (
            self.source_build == 12 or operation != "SendIntNoInitNoSession"
        ):
            operation = "SendIntNoInitExt" if self.no_init else "SendIntExt"
        return self.send_native(
            NativeFrameSend(
                operation,
                self.profile.category,
                send.request,
                send.parameter4,
                send.parameter5,
                send.parameter6,
                send.parameter7,
            )
        )

    def receive(self, receive: SupportReceive, /) -> tuple[int, bytes]:
        self._primitive()
        if not self._active_context():
            raise SessionError("Cannot receive through an inactive shared context")
        try:
            result = self.operations.receive(
                maximum=receive.capacity,
                timeout=receive.parameter4,
                argument_5=receive.parameter5,
                flags=receive.wait_ms,
                deadline=self.deadline,
            )
        finally:
            self._check(timeout_error=sys.exception())
        if type(result.code) is not int or not 0 <= result.code <= 0xFFFFFFFF:
            raise ValueError("Native receive returned malformed status")
        if not isinstance(result.data, bytes) or len(result.data) > receive.capacity:
            raise ToyotaCodecError(
                "Native receive exceeds supplied capacity", 0xA0040202
            )
        return result.code, result.data

    def receive_native(
        self, *, maximum: int, timeout: int, argument_5: int = 0, flags: int = 100
    ) -> NativeFrameReceive:
        """Retain the actual ReceiveExt source/timestamp for event consumers."""
        if not isinstance(self.operations, NativeFrameController):
            raise TypeError("Native source identity requires concrete frame controller")
        self._primitive()
        if not self._active_context():
            raise SessionError("Cannot receive through an inactive shared context")
        try:
            result = self.operations.receive(
                maximum=maximum,
                timeout=timeout,
                argument_5=argument_5,
                flags=flags,
                deadline=self.deadline,
            )
        finally:
            self._check(timeout_error=sys.exception())
        if type(result) is not NativeFrameReceive or len(result.data) > maximum:
            raise ValueError("Malformed concrete native receive result")
        return result

    def execute(
        self,
        selected: SelectedFrame,
        request: bytes | None = None,
        *,
        bus_id: int | None = None,
        extended: bool = False,
        capacity: int | None = None,
        initialization_control: int = 0,
    ) -> CommunicationResult:
        self._check()
        if (
            not isinstance(selected, SelectedFrame)
            or len(selected.settings_record) != 16
        ):
            raise ToyotaCodecError(
                "Malformed selected communication settings", 0xC0040001
            )
        self.profile.validate_frame(selected)
        request = selected.frame.request if request is None else request
        if not isinstance(request, bytes) or len(request) > (
            65535 if extended else 255
        ):
            raise ToyotaCodecError("Ordinary Common request length is BYTE", 0xC0040001)
        maximum = (0x1000 if extended else 255) if capacity is None else capacity
        if type(maximum) is not int or not 0 < maximum <= (65535 if extended else 255):
            raise ValueError("Receive capacity exceeds selected native ABI")
        bus = self.bus_id if bus_id in (None, 0) else bus_id
        if bus != self.bus_id:
            raise ValueError("Transaction bus differs from retained native channel")
        send_timeout, timeout = struct.unpack_from("<II", selected.settings_record)
        retries = selected.settings_record[14]
        query = SupportQuery(
            self.ecu, request, selected, self.cache.identity, bus, extended
        )
        status, reply, attempts = 0, b"", 0
        for attempts in range(1, retries + 2):
            status = self.send(
                SupportSend(query, send_timeout, bus, initialization_control, 1)
            )
            if status == 0 and not request:
                break
            if status == 0:
                timeout = receive_timeout(
                    self.profile, request, bus, timeout, self.source_build
                )
                status, reply = self.receive(SupportReceive(query, maximum, timeout))
                if status == NO_RESPONSE:
                    break
                if status == 0:
                    if reply and reply[0] == request[0] | 0x40:
                        break
                    status = 0xA0040201
        response = reply if status in (0, PARTIAL_RESPONSE) else b""
        result = CommunicationResult(status, response, attempts, selected)
        self.last_result = result
        return result

    def __call__(self, query: SupportQuery, /) -> bytes:
        if query.ecu != self.ecu or query.source_identity != self.cache.identity:
            raise ValueError("Support query belongs to another selected context")
        result = self.execute(
            query.selected,
            query.request,
            bus_id=query.native_parameter,
            extended=query.extended,
            capacity=query.capacity,
        )
        if result.status:
            raise CommunicationError(result)
        return result.response

    def execute_raw(
        self,
        selected: SelectedFrame,
        request: bytes | None = None,
        *,
        capacity: int = 255,
        initialization_control: int = 0,
    ) -> CommunicationResult:
        """Common18:5c450/12:3bc60 BYTE exchange without positive SID validation."""
        self._check()
        self.profile.validate_frame(selected)
        if len(selected.settings_record) != 16:
            raise ToyotaCodecError("Malformed raw communication settings", 0xC0040001)
        request = selected.frame.request if request is None else request
        if not isinstance(request, bytes) or len(request) > 255:
            raise ValueError("Raw Common request length is BYTE")
        if type(capacity) is not int or not 1 <= capacity <= 255:
            raise ValueError("Raw Common receive capacity is BYTE")
        send_timeout, timeout = struct.unpack_from("<II", selected.settings_record)
        query = SupportQuery(
            self.ecu, request, selected, self.cache.identity, self.bus_id
        )
        status, reply, attempts = 0, b"", 0
        for attempts in range(1, selected.settings_record[14] + 2):
            status = self.send_native(
                NativeFrameSend(
                    "SendInt",
                    self.profile.category,
                    request,
                    send_timeout,
                    self.bus_id,
                    initialization_control,
                    1,
                )
            )
            if status == 0:
                if not request:
                    break
                status, reply = self.receive(SupportReceive(query, capacity, timeout))
                if status == 0:
                    if reply:
                        break
                    status = 0xA0040201
        result = CommunicationResult(
            status, reply if status == 0 else b"", attempts, selected
        )
        self.last_result = result
        return result

    @property
    def connection_entries(self) -> tuple[NativeConnectionEntry, ...]:
        """Retained slot8 values; reading does not create connection observations."""
        if not isinstance(self.operations, NativeFrameController):
            raise TypeError("Connection observations require the concrete controller")
        return tuple(self.operations._connection_entries)

    def connect_set(
        self,
        category: int,
        supported: int,
        bus_id: int,
        protocol: int,
        *,
        overwrite: bool = False,
    ) -> int:
        """721d0 append-if-absent / 72360 category-only overwrite, retaining frames."""
        self._check()
        entry = NativeConnectionEntry(category, bus_id, supported, protocol=protocol)
        entries = self.connection_entries
        assert isinstance(self.operations, NativeFrameController)
        for index, previous in enumerate(entries):
            if previous.category == category and (
                overwrite or previous.variant == bus_id
            ):
                if overwrite:
                    self.operations._connection_entries[index] = replace(
                        entry,
                        request=previous.request,
                        reply=previous.reply,
                    )
                return 0
        self.operations._connection_entries.append(entry)
        return 0

    def clear_connection_buffer(self) -> int:
        self._check()
        _ = self.connection_entries
        assert isinstance(self.operations, NativeFrameController)
        self.operations._connection_entries.clear()
        return 0

    def check_connection_buffer(self, frame_id: int = 0) -> tuple[int, int]:
        """71010 checks canonical DB111 bytes against actual persistent observations."""
        self._check()
        frame, _ = self.profile._communication_frame(frame_id)
        return lookup_connection_cache(
            self.connection_entries,
            self.profile.category,
            self.bus_id,
            frame,
        )

    def comm_connection(
        self,
        frame_id: int = 0,
        settings_id: int = 1,
        *,
        protocol: int | None = None,
    ) -> ConnectionResult:
        """713d0 standard connection and AddBuffer, without NoBuffer's drain.

        The OEM reads an uninitialized receive-count local after an empty send
        or failed exchange. Those branches stop explicitly before fabricating a
        cache entry or the AddBuffer return status which overwrites the failure.
        """
        self._check()
        _ = self.connection_entries
        protocol = self.profile.category_record[72] if protocol is None else protocol
        NativeConnectionEntry(self.profile.category, self.bus_id, 0, protocol=protocol)
        selected = None
        try:
            selected = self.profile.direct_frame(frame_id, settings_id)
            wire = selected.frame.request
            request = selected.frame.request[: len(selected.frame.request) & 255]
            with self.communication_flags(no_init=False, no_session=False):
                result = self.execute(
                    selected,
                    request,
                    initialization_control=0 if request else 1,
                )
            if result.status or not request:
                raise SessionError(
                    "Native CommConnection receive count is source-undefined "
                    f"after status 0x{result.status:08x} / empty request"
                )
            response = result.response
            if len(response) > 128:
                raise SessionError(
                    "Native CommConnection response exceeds its 128-byte stack buffer"
                )
            mask, check = selected.frame.receive_mask, selected.frame.receive_check
            if not mask or not check:
                return ConnectionResult(0, False, selected, response)
            if len(response) < len(mask) or len(check) > len(mask):
                raise ToyotaCodecError(
                    "Connection mask/check exceeds response", 0xA0040202
                )
            connected = all(
                response[index] & mask[index] == expected
                for index, expected in enumerate(check)
            )
            entry = NativeConnectionEntry(
                self.profile.category,
                self.bus_id,
                int(connected),
                wire[: len(wire) & 255],
                response[: len(response) & 255],
                protocol,
            )
            assert isinstance(self.operations, NativeFrameController)
            self.operations._connection_entries.append(
                entry
            )  # AddBuffer never deduplicates.
            return ConnectionResult(0, connected, selected, response)
        except ToyotaCodecError as error:
            return ConnectionResult(error.code, False, selected)
        except ValueError as error:
            if str(error).startswith(
                "Expected one communication settings record; found "
            ):
                return ConnectionResult(0xC0040102, False, selected)
            raise

    def connection_check(
        self,
        frame_id: int = 0,
        settings_id: int = 1,
        *,
        protocol: int | None = None,
    ) -> ConnectionResult:
        """70f00 normal ConnectCheck -> CheckBuffer -> standard CommConnection."""
        self._check()
        protocol = self.profile.category_record[72] if protocol is None else protocol
        if (
            type(protocol) is not int
            or not 0 <= protocol <= 255
            or protocol & 31 not in (1, 2, 3, 4, 5, 6, 7, 10, 18, 19, 20, 21)
            or not self.bus_id
        ):
            return ConnectionResult(0xC0040001, False, None)
        try:
            supported, found = self.check_connection_buffer(frame_id)
        except ToyotaCodecError as error:
            return ConnectionResult(error.code, False, None)
        if found:
            return ConnectionResult(0, supported == 1, None, cache_hit=True)
        return self.comm_connection(frame_id, settings_id, protocol=protocol)

    def check_protocol(
        self,
        candidates: Sequence[ProtocolCandidate],
        *,
        contexts: Mapping[tuple[int, int], NativeCommunication] | None = None,
        start: int = 0,
    ) -> ProtocolSelection | None:
        """72a60 bound to actual initialization probes and the one slot8 list."""
        self._check()
        contexts = (
            contexts
            if contexts is not None
            else {(self.profile.category, self.bus_id): self}
        )

        def target(category: int, bus: int) -> NativeCommunication:
            selected = contexts.get((category, bus))
            if (
                type(selected) is not NativeCommunication
                or selected.operations is not self.operations
                or selected.profile.category != category
                or selected.bus_id != bus
            ):
                raise ValueError(
                    "Protocol candidate requires its actual shared selected context"
                )
            return selected

        def lookup(category: int, bus: int) -> tuple[int, int]:
            return target(category, bus).check_connection_buffer()

        def probe(
            category: int, bus: int, timeout: int, control: int, clear: int
        ) -> None:
            status = target(category, bus).send_native(
                NativeFrameSend("SendInt", category, None, timeout, bus, control, clear)
            )
            if status:
                raise ToyotaCodecError("Native empty protocol probe failed", status)

        def remember_failure(
            category: int, supported: int, bus: int, protocol: int
        ) -> None:
            self.connect_set(category, supported, bus, protocol)

        return select_protocol_from_cache(
            candidates,
            lookup=lookup,
            probe=probe,
            start=start,
            remember_failure=remember_failure,
        )

    def connection_no_buffer(
        self,
        frame_id: int = 0,
        settings_id: int = 1,
        *,
        temporary: bool = False,
        force: bool = False,
    ) -> ConnectionResult:
        self._check()
        try:
            selected = self.profile.direct_frame(frame_id, settings_id)
        except ToyotaCodecError as error:
            return ConnectionResult(error.code, False, None)
        except ValueError as error:
            if str(error) == "No selected communication frame":
                return ConnectionResult(0xC0040101, False, None)
            if str(error).startswith(
                "Expected one communication settings record; found "
            ):
                return ConnectionResult(0xC0040102, False, None)
            raise
        request = selected.frame.request[: len(selected.frame.request) & 255]
        hit, response, connected = False, b"", False
        try:
            if not request:
                with self.communication_flags(no_init=False, no_session=False):
                    result = self.execute(selected, b"", initialization_control=1)
                status, response = result.status, result.response
                connected = status == 0
            else:
                if force and not temporary:
                    self.cache.invalidate_response(request)
                with self.communication_flags(
                    no_init=self.no_init if temporary else False,
                    no_session=self.no_session if temporary else False,
                ):
                    response = self.cache.transaction(
                        selected,
                        request,
                        native_parameter=self.bus_id,
                        cached=not temporary,
                        temporary=temporary,
                    )
                hit = self.cache.cache_hit
                status = 0
                mask, check = selected.frame.receive_mask, selected.frame.receive_check
                if len(response) < len(mask) or len(check) > len(mask):
                    raise ToyotaCodecError(
                        "Connection response mask/check exceeds buffer", 0xA0040202
                    )
                connected = all(
                    (response[index] & mask[index]) == expected
                    for index, expected in enumerate(check)
                )
                # Native requires non-null receive-mask/check pointers to set true.
                connected = connected and bool(mask) and bool(check)
            mask_present = bool(selected.frame.receive_mask) and bool(
                selected.frame.receive_check
            )
            if (
                status == 0
                and not hit
                and (not request or mask_present)
                and self._needs_drain(request)
            ):
                query = SupportQuery(
                    self.ecu, b"", selected, self.cache.identity, self.bus_id
                )
                while True:
                    status, _ = self.receive(SupportReceive(query, 0xFFF, 0))
                    if status == TIMEOUT:
                        status = 0
                        break
                    if status:
                        connected = False
                        break
            return ConnectionResult(status, connected, selected, response, hit)
        except ToyotaCodecError as error:
            return ConnectionResult(
                error.code,
                False,
                selected,
                response,
                self.cache.cache_hit if request else False,
            )

    def is_behavior_code(self, frame_id: int, settings_id: int) -> BehaviorResult:
        """CCmdCheckSupport14050 segmented WORD identifier predicate."""
        self._check()
        try:
            selected = self.profile.behavior_frame(frame_id, settings_id)
        except ToyotaCodecError as error:
            return BehaviorResult(error.code, False, True)
        settings, frame = selected.settings_record, selected.frame
        request = frame.request[: len(frame.request) & 255]
        if not request:
            return BehaviorResult(0x90020701, False, True)
        send_timeout, timeout = struct.unpack_from("<II", settings)
        retries = settings[14]
        query = SupportQuery(
            self.ecu, request, selected, self.cache.identity, self.bus_id
        )
        identifiers: list[int] = []
        expected = consumed = packets = 0
        started = False
        status = 0
        try:
            for _ in range(retries + 1):
                if not started:
                    identifiers.clear()
                    status = self.send_native(
                        NativeFrameSend(
                            "SendInt",
                            self.profile.category,
                            request,
                            send_timeout,
                            self.bus_id,
                            0,
                            1,
                        )
                    )
                    if status:
                        continue
                expected = consumed = packets = 0
                timeout = receive_timeout(
                    self.profile, request, self.bus_id, timeout, self.source_build
                )
                while True:
                    status, reply = self.receive(SupportReceive(query, 255, timeout))
                    if status == TIMEOUT and packets:
                        status = 0
                        break
                    if status:
                        if status in (NO_RESPONSE, 0xA0040201, 0xA0040202):
                            return BehaviorResult(status, False, True)
                        started = False
                        break
                    if not reply or reply[0] != request[0] | 0x40:
                        return BehaviorResult(0xA0040201, False, True)
                    if len(reply) <= 2:
                        return BehaviorResult(0xA0040202, False, True)
                    if not started:
                        expected = reply[2]
                        if expected == 0:
                            break
                    started = True
                    count = min((len(reply) - 3) // 2, expected - consumed)
                    identifiers.extend(
                        int.from_bytes(reply[index : index + 2], "big")
                        for index in range(3, 3 + count * 2, 2)
                    )
                    consumed = (consumed + count) & 255
                    packets += 1
                    if consumed >= expected:
                        break
                if status == 0:
                    break
            if status:
                return BehaviorResult(status, False, True)
            if len(frame.receive_check) < 2:
                return BehaviorResult(0xC0040102, False, False, tuple(identifiers))
            target = int.from_bytes(frame.receive_check[:2], "big")
            return BehaviorResult(0, target in identifiers, False, tuple(identifiers))
        except ToyotaCodecError as error:
            return BehaviorResult(error.code, False, True)

    def _needs_drain(self, request: bytes) -> bool:
        if self.source_build == 12:
            return True
        kind = self.profile.category_record[72]
        if kind in (0x14, 0x34):
            return False
        if kind != 4:
            return True
        if not request:
            return False
        allowed = {
            1,
            2,
            3,
            4,
            5,
            6,
            7,
            8,
            10,
            0x10,
            0x12,
            0x14,
            0x1A,
            0x21,
            0x27,
            0x30,
            0x3B,
            0x3E,
            0x81,
            0x82,
            0xA0,
            0xA4,
            0xA6,
            0xA9,
            0xAA,
        }
        return request[0] not in allowed and not (
            request[0] == 9 and self.bus_id & 15 == 2
        )

    def disconnect(self, flag: int = 0, *, deadline: float | None = None) -> int:
        """Native Disconnect with retryable host cleanup after a failed release."""
        if not isinstance(self.operations, NativeFrameController):
            raise TypeError("Native Disconnect requires the concrete outer controller")
        if self.closed and not self._cleanup_pending:
            return self.cleanup_status
        self.closed, self._cleanup_pending = True, True
        status = self.operations.disconnect(flag, deadline=deadline)
        self.cleanup_status = status
        self._cleanup_pending = bool(status)
        return status

    def close(self) -> int:
        if self.closed and not self._cleanup_pending:
            return self.cleanup_status
        self.closed, self._cleanup_pending = True, True
        status = self.operations.close()
        if status is None:
            status = 0
        if type(status) is not int or not 0 <= status <= 0xFFFFFFFF:
            raise ValueError("Native close returned malformed status")
        self.cleanup_status = status
        self._cleanup_pending = bool(status)
        return status
