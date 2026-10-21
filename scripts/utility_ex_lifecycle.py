"""Source-bound UtilityEx fixed manager and owned keepalive worker.

Fixed managers retain source-specific selectors; lower source support is
provided by the concrete communication module, never an initialization callback.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Protocol

from scripts.j2534_2026 import (
    J2534Device2026,
    NativeJ2534Error2026,
    NativeMessage,
    PrimitiveResult,
    unsigned,
)
from scripts.utility_ex_comm import (
    _ADDITIONAL_FIXED_OBJECTS,
    _FIXED_OBJECTS,
    _MANAGER_OBJECTS,
    _TARGET_GLOBAL_BASES,
    NATIVE_NRC,
    SHA_12_NK,
    SHA_12_TY,
    SHA_18_NK,
    SHA_18_TY,
    SHA_DS4_NK,
    SHA_DS4_TY,
    SHA_PLUS_NK,
    SHA_PLUS_TY,
    CommContext,
    DriverReceive,
    UDSFields,
    UtilityExBroadcastCANLower,
    UtilityExCANLower,
    UtilityExDirectDriver,
    UtilityExP3Lower,
    UtilityExP6Fields,
    UtilityExP6Lower,
    UtilityExP6Pool,
    UtilityExP6UDSScheduler,
    UtilityExPassThruPool,
    UtilityExSourceError,
    UtilityExUDSScheduler,
    elapsed,
    unpack_uds_response,
)


def _paced_native_sleep(context: CommContext, stop: threading.Event) -> None:
    """Keep the literal 120 ms worker cadence even with a virtual host clock."""
    started = time.monotonic()
    context.native_sleep(120)
    remaining = 0.120 - (time.monotonic() - started)
    if remaining > 0:
        stop.wait(remaining)


@dataclass
class UtilityExAlternateUDSFields:
    """The separate native vslot18 budgets used by keepalive workers."""

    no_response_seen: int = 0
    no_response_limit: int = 1
    busy_seen: int = 0
    busy_limit: int = 1
    busy_ms: int = 0
    pending_ms: int = 0
    pending_limit: int = 1


ALTERNATE_UDS_OFFSETS = {
    0x10B4: "no_response_seen",
    0x10B8: "no_response_limit",
    0x10BC: "busy_seen",
    0x10C0: "busy_limit",
    0x10C4: "busy_ms",
    0x10C8: "pending_ms",
    0x10CC: "pending_limit",
}


P6_ALTERNATE_UDS_OFFSETS = {
    offset + 4: name for offset, name in ALTERNATE_UDS_OFFSETS.items()
}
SIS_ALTERNATE_UDS_OFFSETS = {
    offset - 4: name for offset, name in ALTERNATE_UDS_OFFSETS.items()
}


def alternate_uds_fields(
    context: CommContext, address: int
) -> UtilityExAlternateUDSFields:
    key = f"utility_ex:alternate_uds_fields:{context.module_sha256}:{address:x}"
    result = context.state.setdefault(key, UtilityExAlternateUDSFields())
    if not isinstance(result, UtilityExAlternateUDSFields):
        raise TypeError("Concrete independent alternate UDS fields required")
    return result


class UtilityExAlternateUDSScheduler:
    """Concrete fixed/P6/SIS vslot18; never the ordinary exchange scheduler."""

    def __init__(
        self,
        context: CommContext,
        lower: UtilityExCANLower | UtilityExSISLower,
        fields: UDSFields | UtilityExSISFields,
        alternate: UtilityExAlternateUDSFields,
    ):
        if (
            not isinstance(lower, (UtilityExCANLower, UtilityExSISLower))
            or lower.context is not context
        ):
            raise TypeError("Concrete same-context alternate UDS lower required")
        if not isinstance(fields, (UDSFields, UtilityExSISFields)) or not isinstance(
            alternate, UtilityExAlternateUDSFields
        ):
            raise TypeError("Concrete source manager and alternate fields required")
        self.context, self.lower, self.fields, self.alternate = (
            context,
            lower,
            fields,
            alternate,
        )
        self.calls = 0

    def _check(self) -> None:
        self.calls += 1
        if self.calls > 65536:
            raise TimeoutError("Alternate UDS exceeds host primitive budget")

    def _cancelled(self) -> int:
        return (
            self.fields.receive_cancel
            if isinstance(self.fields, UtilityExSISFields)
            else self.fields.receive_cancelled
        )

    def _clear_cancel(self) -> None:
        if isinstance(self.fields, UtilityExSISFields):
            self.fields.receive_cancel = 0
        else:
            self.fields.receive_cancelled = 0

    def _abort(self, response: bytes) -> DriverReceive:
        ignore = (
            self.fields.ignore_receive_abort
            if isinstance(self.fields, UtilityExSISFields)
            else self.fields.response_pending_seen
        )
        cancelled = self._cancelled()
        if ignore:
            self._clear_cancel()
            return DriverReceive(0, response)
        self.lower.interrupt(100)
        self._clear_cancel()
        return DriverReceive(20 if cancelled else 5, response)

    def _sis_packet(self, previous: bytes) -> DriverReceive:
        assert isinstance(self.lower, UtilityExSISLower)
        self._check()
        status, header = self.lower.receive_bytes(8)
        if status:
            return DriverReceive(status, previous)
        total = int.from_bytes(header[4:], "big")
        # Alternate20110/1b260 reads exactly one bounded payload, not the
        # primary receiver's multi-chunk loop and extra zero-length read.
        if header[:4] != b"\x02\xfd\x80\x01" or not 4 <= total <= 0x1020:
            return DriverReceive(99, previous)
        status, payload = self.lower.receive_bytes(total)
        if status:
            return DriverReceive(status, previous)
        response = payload[4:]
        status = 0
        if len(response) == 3 and response[0] == 0x7F:
            status = {0x12: 22, 0x21: 27, 0x78: 5}.get(response[2], 7)
        return DriverReceive(status, response)

    def _receive(self) -> DriverReceive:
        f, a = self.fields, self.alternate
        start, count, previous = self.context.ticks(), 0, b""
        if isinstance(self.lower, UtilityExSISLower):
            assert isinstance(f, UtilityExSISFields)
            self.lower.timeout_ms = f.first_receive_ms
        while True:
            self._check()
            reply = (
                self._sis_packet(previous)
                if isinstance(self.lower, UtilityExSISLower)
                else self.lower.receive()
            )
            previous = reply.data
            if len(reply.data) == 3 and reply.data[0] == 0x7F:
                f.native_error = NATIVE_NRC.get(reply.data[2], 999)
            if reply.status == 7:
                if f.native_error == 100 and f.suppress_error == 1:
                    f.native_error = 0x3E6
                return reply
            if reply.status != 5:
                if reply.status == 27:
                    f.pending_count = 0
                return reply
            f.suppress_error, f.suppress_positive = 1, 0
            if isinstance(self.lower, UtilityExSISLower):
                assert isinstance(f, UtilityExSISFields)
                self.lower.timeout_ms = f.pending_receive_ms
            if a.pending_ms:
                exhausted = elapsed(self.context.ticks(), start) >= a.pending_ms
            else:
                count += 1
                f.pending_count = count
                exhausted = count >= a.pending_limit
            if self._cancelled() or (exhausted and not f.continue_pending):
                return self._abort(reply.data)

    def _wait_busy(self, received: int) -> None:
        deadline = (received + self.fields.busy_interval_ms) & 0xFFFFFFFF
        for _ in range(65536):
            if self.context.is_cancelled():
                return
            now = self.context.ticks()
            if (now + 100) & 0xFFFFFFFF < deadline:
                self.context.native_sleep(100)
                continue
            remaining = (deadline - self.context.ticks()) & 0xFFFFFFFF
            if remaining <= 100:
                self.context.native_sleep(remaining)
            return
        raise TimeoutError("Alternate UDS busy wait exceeds host budget")

    def exchange(self, request: bytes) -> tuple[int, bytes]:
        if type(request) is not bytes or not 1 <= len(request) <= 0x101F:
            raise ValueError("Bounded nonempty alternate UDS request required")
        f, a = self.fields, self.alternate
        self.calls = 0
        a.busy_seen = a.no_response_seen = 0
        self._clear_cancel()
        f.suppress_positive = int(
            len(request) >= 2
            and request[0] in (0x10, 0x11, 0x19, 0x27, 0x2C, 0x31, 0x3E, 0x85)
            and bool(request[1] & 0x80)
        )
        start = self.context.ticks()
        try:
            while True:
                self._check()
                status = self.lower.send(request)
                if status:
                    return status, b""
                if isinstance(self.lower, UtilityExSISLower):
                    self.lower.timeout_ms = self.lower.driver._global(0x1011F73C)
                    status, ack = self.lower.receive_bytes(13)
                    if status:
                        return status, b""
                    if ack[:4] != b"\x02\xfd\x80\x02":
                        return (12 if ack[:4] == b"\x02\xfd\x80\x03" else 3), b""
                reply = self._receive()
                received_tick = self.context.ticks()
                if self.context.is_cancelled():
                    return reply.status, reply.data
                if reply.status == 27:
                    if a.busy_ms:
                        exhausted = elapsed(self.context.ticks(), start) >= a.busy_ms
                    else:
                        a.busy_seen += 1
                        a.no_response_seen = 0
                        exhausted = a.busy_seen >= a.busy_limit
                    if exhausted:
                        return 28, reply.data
                    self._wait_busy(received_tick)
                    continue
                if reply.status == 2:
                    if f.suppress_positive == 1:
                        return 0, reply.data
                    a.no_response_seen += 1
                    if a.no_response_seen < a.no_response_limit:
                        continue
                if reply.status == 0 and (
                    not reply.data or reply.data[0] != request[0] + 0x40
                ):
                    return 3, reply.data
                return reply.status, reply.data
        finally:
            f.suppress_error = 0


class UtilityExFixedLifecycle:
    """Eight source fixed manager state machines, with concrete owned lower I/O."""

    def __init__(
        self,
        context: CommContext,
        pool: UtilityExPassThruPool,
        fields: UDSFields,
        native_address: int,
    ):
        if context.module_sha256 not in _FIXED_OBJECTS:
            raise UtilityExSourceError("Fixed manager lifecycle source is not reviewed")
        if not isinstance(pool, UtilityExPassThruPool) or pool.context is not context:
            raise TypeError("Concrete same-context native pool required")
        if not isinstance(fields, UDSFields):
            raise TypeError("Concrete shared native manager fields required")
        objects = (
            _FIXED_OBJECTS[context.module_sha256],
            *_ADDITIONAL_FIXED_OBJECTS.get(context.module_sha256, ()),
        )
        if type(native_address) is not int or native_address not in objects:
            raise UtilityExSourceError("Fixed manager object identity is not reviewed")
        self.context, self.pool, self.fields = context, pool, fields
        self.native_address = native_address
        self.alternate_fields = alternate_uds_fields(context, native_address)
        self.lower: UtilityExCANLower | None = None
        self.broadcast_lower: UtilityExBroadcastCANLower | None = None
        self._lower_parameters: tuple[tuple[int, int], ...] = ()
        self.scheduler: UtilityExUDSScheduler | None = None
        self._initialize_worker_state()

    def _initialize_worker_state(self) -> None:
        """Shared native worker constructor; P6 uses the same ThreadMain body."""
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.worker_error: BaseException | None = None
        self.worker_status = 15
        self._worker_exit_status = 0
        self.worker_active = False
        self.worker_paused = False
        self.worker_interval_ms = 2000
        self.worker_request = b"\x3e\x00"
        self.worker_response_length = 2
        self.worker_recovery = 0xF0
        self.worker_rate_mode = 1
        self.worker_last_tick = 0
        self.native_10cc, self.native_10c0 = 1, 1
        self.native_10c4, self.native_10c8 = 0, 0

    def _defaults(self) -> None:
        f = self.fields
        f.receive_count, f.receive_ms = 150, 180000
        f.busy_count = 255
        # Native initialization deliberately preserves retry1064/pending1098.

    def _native_defaults(self) -> None:
        self.native_10cc, self.native_10c0 = 1, 1
        self.native_10c4, self.native_10c8 = 0, 0
        a = self.alternate_fields
        a.pending_limit, a.busy_limit, a.busy_ms, a.pending_ms = 1, 1, 0, 0

    def _create_lower(self, kind: int) -> UtilityExCANLower:
        if self.fields.diagnostic_enabled == 3:
            if self.broadcast_lower is None:
                raise UtilityExSourceError("Native broadcast child is not selected")
            return self.broadcast_lower
        return UtilityExCANLower(self.context, self.pool, kind)

    def _create_scheduler(self, lower: UtilityExCANLower) -> UtilityExUDSScheduler:
        return UtilityExUDSScheduler(self.context, lower, fields=self.fields)

    def _global(self, offset: int, broker_key: int) -> int:
        base = _TARGET_GLOBAL_BASES[self.context.module_sha256]
        value = self.context.state.get(f"native_global:{base + offset:x}")
        if value is None:
            value = self.context.broker(broker_key)
        if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
            raise ValueError("Native selected module global must be uint32")
        return value

    def _target_defaults(self) -> None:
        f = self.fields
        if not f.target_configured:
            f.primary_address = self._global(0, 0x74)
            f.extension = self._global(4, 0xAB)
            f.alternate_extension = self._global(0x24, 0x15F)
            f.oem_parameter = self.context.native_parameter(0x71)
            f.alternate_address = self._global(0x20, 0x155)
            f.target_configured = True

    def _kind(self) -> int:
        if self.fields.lower_kind:
            return self.fields.lower_kind
        mode, protocol = self._global(8, 0x6F), self._global(12, 0x70)
        source = self.context.module_sha256
        modes = (0x14, 0x15) if source in (SHA_12_NK, SHA_12_TY) else (0x14, 0x15, 0x34)
        if source in (SHA_PLUS_NK, SHA_PLUS_TY):
            modes += (0x74,)
        if mode in modes:
            if protocol == 0x12:
                return 0x13 if mode in (0x15, 0x74) else 0x10
            if protocol == 0x22:
                return 0x14 if mode in (0x15, 0x74) else 0x11
            if protocol == 0x62 and mode == 0x15:
                return 0x15
        return 0

    def select_diagnostic_mode(self, mode: int) -> int:
        """Native23460: byte selection precedes initialization, not live swap."""
        selected = unsigned(mode) & 0xFF
        if selected == self.fields.diagnostic_enabled:
            return 0
        if self.lower is not None:
            return 13
        if selected == 3:
            kind = self._kind()
            if kind not in (0x10, 0x13, 0x15):
                return 99
            self.broadcast_lower = UtilityExBroadcastCANLower(
                self.context, self.pool, kind
            )
            self.fields.diagnostic_enabled = 3
            return 0
        if self.fields.diagnostic_enabled == 3:
            # 23460 calls17ec0 to replace the retained broadcast child before
            # publishing ordinary/alternate diagnostic mode.
            self.broadcast_lower = None
        self.fields.diagnostic_enabled = 2 if selected == 2 else 1
        return 0

    def initialize(self, mode: int = 0) -> int:
        if type(mode) is not int or not 0 <= mode <= 0xFFFFFFFF:
            raise ValueError("Native initialization mode must be uint32")
        with self._lock:
            if self.fields.diagnostic_enabled == 3 and self.broadcast_lower is None:
                raise UtilityExSourceError(
                    "Native broadcast child must be selected before initialization"
                )
            self.fields.suppress_error = 0
            self._native_defaults()
            self._target_defaults()
            self._defaults()
            f = self.fields
            f.busy_ms = 0
            previous_tick = 0
            if mode == 1 and self.lower is not None:
                previous_tick = self.lower.last_receive_tick
                status = self.lower.finalize()
                if status:
                    return status
                self.lower = None
                self.scheduler = None
            setup_child = self.lower is None
            if setup_child:
                kind = (
                    self.broadcast_lower.kind
                    if self.broadcast_lower is not None
                    else self._kind()
                )
                if not kind:
                    return 99
                self.lower = self._create_lower(kind)
                assert self.lower is not None
                self._lower_parameters = f.parameters
                self.scheduler = self._create_scheduler(self.lower)
            # Keep ownership attached before calling lower/host validation.
            lower = self.lower
            assert lower is not None
            address = (
                f.alternate_address
                if f.diagnostic_enabled in (2, 3)
                else f.primary_address
            )
            try:
                override = bool(f.parameters) or (
                    setup_child and f.diagnostic_enabled == 3
                )
                status = lower.initialize(
                    address,
                    extra=f.extension,
                    alternate_extra=f.alternate_extension,
                    override=override,
                    supplied=(self._lower_parameters or None) if override else None,
                    oem_parameter=f.oem_parameter,
                )
                if status:
                    self.finalize()
                    return status
                if mode == 1:
                    lower.last_receive_tick = previous_tick
                self.fields.native_error = 0
                self.worker_error = None
                self.configure_worker(2000, b"\x3e\x00", 2, 0xF0)
                return 0
            except BaseException as error:
                try:
                    self.finalize()
                except BaseException as cleanup_error:  # noqa: BLE001 - preserve primary SDK failure
                    error.add_note(
                        "Native manager cleanup: " + type(cleanup_error).__name__
                    )
                raise

    def configure_worker(
        self, interval_ms: int, request: bytes, response_length: int, recovery: int
    ) -> None:
        for value in (interval_ms, response_length, recovery):
            if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
                raise ValueError("Native worker fields must be uint32")
        if not isinstance(request, bytes) or len(request) > 0x1020:
            raise ValueError("Bounded immutable native worker request required")
        with self._lock:
            self.worker_interval_ms = interval_ms
            self.worker_request = request
            self.worker_response_length = response_length
            self.worker_recovery = recovery

    def configure_keepalive(
        self, interval_ms: int, request: bytes, response_size: int, flags: int
    ) -> None:
        self.configure_worker(interval_ms, request, response_size, flags)

    def exchange(self, request: bytes) -> tuple[int, bytes]:
        with self._lock:
            self.worker_paused = True
            try:
                if self.worker_error is not None:
                    raise self.worker_error
                if self.scheduler is None:
                    return 99, b""
                return self.scheduler.exchange(request)
            finally:
                self.worker_paused = False

    def cleanup_exchange(self, request: bytes) -> tuple[int, bytes]:
        with self._lock:
            if self.lower is None or self.scheduler is None:
                return 99, b""
            self.worker_paused = True
            try:
                with utility_ex_cleanup_scope(self.lower):
                    return self.scheduler.exchange(request)
            finally:
                self.worker_paused = False

    def cleanup_session(
        self,
        mode: int,
        keepalive: int = 1,
        *,
        normal_first: bool = False,
        stop_on_error: bool = False,
    ) -> int:
        with self._lock:
            if self.lower is None:
                return self.session(
                    mode,
                    keepalive,
                    normal_first=normal_first,
                    stop_on_error=stop_on_error,
                )
            with utility_ex_cleanup_scope(self.lower):
                return self.session(
                    mode,
                    keepalive,
                    normal_first=normal_first,
                    stop_on_error=stop_on_error,
                )

    def session(
        self,
        mode: int,
        keepalive: int = 1,
        *,
        normal_first: bool = False,
        stop_on_error: bool = False,
    ) -> int:
        if type(mode) is not int or not 0 <= mode <= 255:
            raise ValueError("Session mode must be uint8")
        if type(keepalive) is not int or keepalive not in (0, 1):
            raise ValueError("Native keepalive selector must be 0 or 1")
        if normal_first and mode != 3:
            raise ValueError("Native extended helper selects session3")
        normal_session = (mode & 0x7F) == 1 and not normal_first
        try:
            with self._lock:
                if self.scheduler is None:
                    return 99
                status = self.scheduler.session(mode, 0, normal_first=normal_first)
            if status == 0 and keepalive:
                self.keepalive(not normal_session)
            return status
        finally:
            # 23110 stops on positive, native failure and foreign exception.
            if stop_on_error and keepalive:
                self.keepalive(False)

    def worker_step(self) -> bool:
        """One literal 23f60 iteration; exposed for deterministic offline clocks."""
        if not self.worker_active or self._stop.is_set():
            return False
        now = self.context.ticks()
        if (
            self.worker_rate_mode == 1
            and elapsed(now, self.worker_last_tick) <= self.worker_interval_ms
        ):
            return False
        lower = self.lower
        if lower is None:
            return False
        if (
            elapsed(self.context.ticks(), lower.last_receive_tick)
            <= self.worker_interval_ms
        ):
            return False
        if not self._lock.acquire(blocking=False):
            return False
        try:
            if self.worker_paused or self._stop.is_set():
                return False
            self.worker_last_tick = self.context.ticks()
            status, response = UtilityExAlternateUDSScheduler(
                self.context, lower, self.fields, self.alternate_fields
            ).exchange(self.worker_request)
            if (
                status == 0
                and self.worker_response_length
                and len(response) != self.worker_response_length
            ):
                status = 3
            self.worker_status = status
            self._worker_exit_status = status
            if status and self.worker_rate_mode == 0 and self.worker_recovery != 0xF0:
                self._worker_exit_status = self._reopen(self.worker_recovery)
            return True
        finally:
            self._lock.release()

    def _reopen(self, address: int) -> int:
        # Worker calls manager vslot0c(address,1), rebuilding its source-selected
        # child while retaining the outer worker/session/budget state.
        previous = self.lower
        if previous is None:
            return 99
        last_tick = previous.last_receive_tick
        status = previous.finalize()
        if status:
            return status
        self.lower = None
        self.scheduler = None
        kind = (
            self.broadcast_lower.kind
            if self.broadcast_lower is not None
            else self._kind()
        )
        if not kind:
            return 99
        lower = self._create_lower(kind)
        self.lower = lower
        self._lower_parameters = self.fields.parameters
        self.scheduler = self._create_scheduler(lower)
        try:
            status = lower.initialize(
                address,
                extra=self.fields.extension,
                alternate_extra=self.fields.alternate_extension,
                override=bool(self._lower_parameters)
                or self.fields.diagnostic_enabled == 3,
                supplied=self._lower_parameters or None,
                oem_parameter=self.fields.oem_parameter,
            )
            if not status:
                lower.last_receive_tick = last_tick
            elif lower.finalize() == 0:
                self.lower = None
                self.scheduler = None
            return status
        except BaseException as error:
            try:
                if lower.finalize() == 0:
                    self.lower = None
                    self.scheduler = None
            except BaseException as cleanup_error:  # noqa: BLE001 - preserve original SDK fault
                error.add_note(
                    "Native recovery cleanup: " + type(cleanup_error).__name__
                )
            raise

    def _run(self) -> None:
        try:
            while not self._stop.is_set():
                _paced_native_sleep(self.context, self._stop)
                self.worker_step()
        except BaseException as error:  # noqa: BLE001 - expose worker failure to its owner
            self.worker_error = error
            self._worker_exit_status = 99
        finally:
            self.worker_status = self._worker_exit_status
            self.worker_active = False

    def keepalive(self, enabled: bool, wait: bool = False) -> int:
        if type(enabled) is not bool or type(wait) is not bool:
            raise TypeError("Native worker controls must be bool")
        if enabled:
            if self.worker_error is not None:
                raise self.worker_error
            if not self.worker_request:
                return 99
            if self.worker_active:
                return 0
            self._stop.clear()
            self.worker_active = True
            self.worker_error = None
            self.worker_status = 15
            self._worker_exit_status = 0
            self.worker_last_tick = self.context.ticks()
            self._thread = threading.Thread(
                target=self._run, name="utility-ex-keepalive", daemon=True
            )
            try:
                self._thread.start()
            except BaseException:
                self.worker_active = False
                self._thread = None
                raise
            return 0
        self._stop.set()
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=2)
            if thread.is_alive():
                raise TimeoutError(
                    "Native keepalive still owns the communication lower"
                )
            self._thread = None
        self.worker_active = False
        if wait:
            self.finalize()
        return 0

    def finalize(self) -> int:
        self.keepalive(False)
        with self._lock:
            self._defaults()
            # Native close preserves10c4; initialize clears it separately.
            preserved = self.alternate_fields.busy_ms
            self._native_defaults()
            self.native_10c4 = preserved
            self.alternate_fields.busy_ms = preserved
            if self.lower is None:
                self.fields.current_session = 0
                return 99
            status = self.lower.finalize()
            if status == 0:
                self.lower = None
                self.scheduler = None
                self.fields.current_session = 0
            return status


_P6_MANAGER_OBJECTS = {SHA_PLUS_NK: 0x101C6DA0, SHA_PLUS_TY: 0x1013E7D0}


class UtilityExP6Lifecycle(UtilityExFixedLifecycle):
    """Plus1e5f0/3ee30 outer manager with separate P6 lower and native schema."""

    def __init__(
        self,
        context: CommContext,
        pool: UtilityExP6Pool,
        fields: UtilityExP6Fields,
        native_address: int,
    ):
        if _P6_MANAGER_OBJECTS.get(context.module_sha256) != native_address:
            raise UtilityExSourceError("P6 manager source identity is not reviewed")
        if not isinstance(pool, UtilityExP6Pool) or pool.context is not context:
            raise TypeError("Concrete same-context P6 pool required")
        if not isinstance(fields, UtilityExP6Fields):
            raise TypeError("Separate concrete P6 fields required")
        self.context, self.pool, self.fields = context, pool, fields
        self.native_address = native_address
        self.alternate_fields = alternate_uds_fields(context, native_address)
        self.lower = None
        self.broadcast_lower = None
        self.scheduler = None
        self._lower_parameters = ()
        self._initialize_worker_state()
        self._native_defaults()

    def _kind(self) -> int:
        if self._global(8, 0x6F) != 0x16:
            return 0
        return {0x18: 0x17, 0x78: 0x18}.get(self._global(12, 0x70), 0)

    def select_diagnostic_mode(self, mode: int) -> int:
        selected = unsigned(mode) & 0xFF
        if selected == self.fields.diagnostic_enabled:
            return 0
        if self.lower is not None:
            return 13
        if selected == 3:
            if self._kind() not in (0x17, 0x18):
                return 99
            # Plus25e70 allocates its separate CComCanP6_Broadcast child.
            raise UtilityExSourceError("P6 broadcast lower source is not ported")
        return super().select_diagnostic_mode(selected)

    def _create_lower(self, kind: int) -> UtilityExP6Lower:
        if not isinstance(self.pool, UtilityExP6Pool):
            raise TypeError("Concrete P6 pool required")
        return UtilityExP6Lower(self.context, self.pool, kind)

    def _create_scheduler(self, lower: UtilityExCANLower) -> UtilityExP6UDSScheduler:
        if not isinstance(lower, UtilityExP6Lower) or not isinstance(
            self.fields, UtilityExP6Fields
        ):
            raise TypeError("Separate concrete P6 lower and fields required")
        return UtilityExP6UDSScheduler(self.context, lower, fields=self.fields)

    def _native_defaults(self) -> None:
        a = self.alternate_fields
        a.pending_limit, a.busy_limit, a.busy_ms, a.pending_ms = 1, 1, 0, 0
        self.native_10d0, self.native_10c4 = 1, 1
        self.native_10c8, self.native_10cc = 0, 0

    def finalize(self) -> int:
        self.keepalive(False)
        with self._lock:
            self._defaults()
            preserved = self.alternate_fields.busy_ms
            self._native_defaults()
            self.native_10c8 = preserved
            self.alternate_fields.busy_ms = preserved
            if self.lower is None:
                self.fields.current_session = 0
                return 99
            status = self.lower.finalize()
            if status == 0:
                self.lower = None
                self.scheduler = None
                self.fields.current_session = 0
            return status


class UtilityExClassicCANLower:
    """Eight exact classic CAN/SIL identities, distinct from the logical pool."""

    def __init__(
        self, context: CommContext, driver: UtilityExDirectDriver, native_address: int
    ):
        if context.module_sha256 not in _MANAGER_OBJECTS:
            raise UtilityExSourceError("Selected classic CAN source is not reviewed")
        if (
            not isinstance(driver, UtilityExDirectDriver)
            or driver.context is not context
            or driver.protocol != 6
        ):
            raise TypeError("Concrete same-context direct protocol6 driver required")
        objects = tuple(
            _MANAGER_OBJECTS[context.module_sha256][index]
            for index in (8, 9, 6, 5, 7, 10, 11)
        )
        if type(native_address) is not int or native_address not in objects:
            raise UtilityExSourceError("Selected classic CAN object is not reviewed")
        self.context, self.driver, self.native_address = context, driver, native_address
        index = objects.index(native_address)
        self.sil_offset = {2: 0x100, 3: 0x20, 4: 0xC0}.get(index, 0)
        if (
            self.sil_offset
            and getattr(driver.adapter.binding, "constructor_parameter", 0) != 0xD
        ):
            raise UtilityExSourceError(
                "Distinct native SIL constructorD DRIVER required"
            )
        self._sil_session_active = False
        self.p5 = index in (1, 6)
        self.extended = index in (5, 6)
        self.attached = False
        self.profile, self.delay_ms, self.last_receive_tick = 0, 0, 0
        self.timeout_ms = 1000
        self.native_timeout_10 = 1000
        self.filter_ids = [0xFFFFFFFF, 0xFFFFFFFF]

    def _extra_parameters(self, parameters: tuple[tuple[int, int], ...]) -> int:
        if not any(key == 0x23 for key, _ in parameters):
            value = self.context.native_parameter(0xD3)
            if value not in (0xFFFFFFFF, 0xFFFF):
                status = self.driver.ioctl(2, ((0x23, value),))
                if status:
                    return status
        if not any(key == 0x2A for key, _ in parameters):
            value = self.context.native_parameter(0xDD)
            if value != 0xFFFFFFFF:
                # Native deliberately ignores this final optional IOCTL status.
                self.driver.ioctl(2, ((0x2A, value),))
        return 0

    def _configure(self, override: bool) -> int:
        if override:
            self.delay_ms = 0
            # 12 has only DC/15D (standard) and D0/180 (extended) profile
            # branches; later images add the other presets below.
            profile = self.profile
            if self.context.module_sha256 in (SHA_12_NK, SHA_12_TY):
                allowed = (0xD0, 0x180) if self.extended else (0xDC, 0x15D)
                if profile not in allowed:
                    profile = 0
            if self.p5:
                parameters = (
                    (1, 500000),
                    (0x10100, 8),
                    (0x10206, 0),
                    (0x10103, 0x300000),
                    (0x10105, 0),
                    (0x10106, 50),
                )
            elif self.extended:
                padding = 0x300064 if profile == 0x7B else 0x300100
                base = (
                    (1, 500000),
                    (0x10103, padding),
                    (0x10105, 0),
                    (0x10106, 0x3FC),
                    (0x2A, 3),
                    (0x1010A, 0),
                )
                if profile == 0xD0:
                    parameters = (base[0], base[1], base[3], base[4], base[5])
                elif profile in (0x7B, 0xE9):
                    parameters = base
                else:
                    parameters = (
                        (1, 500000),
                        (0x10100, 8),
                        (0x10206, 0),
                        (0x10103, 0x300100 if profile == 0x180 else 0x300000),
                        (0x10105, 0),
                        (0x10106, 0x3FC if profile == 0x180 else 1000),
                    )
            else:
                base = (
                    (1, 500000),
                    (0x10103, 0x300004),
                    (0x10105, 0),
                    (0x10106, 0x3FC),
                    (0x2A, 3),
                    (0x1010A, 0),
                )
                if profile == 0xDC:
                    parameters = (
                        (1, 500000),
                        (0x10103, 0x300000),
                        (0x10106, 0x3FC),
                        (0x2A, 3),
                        (0x1010A, 0),
                    )
                elif profile == 0xEA:
                    parameters = (base[3], base[5], base[2], base[1], base[0], base[4])
                elif profile in (0x69, 0xEC, 0x147, 0x17B, 0x1A9, 0x1D0):
                    parameters = base
                else:
                    parameters = (
                        (1, 500000),
                        (0x10100, 8),
                        (0x10206, 0),
                        (0x10103, 0x300004 if profile == 0x15D else 0x300000),
                        (0x10105, 0),
                        (0x10106, 0x3FC if profile == 0x15D else 50),
                    )
            status = self.driver.ioctl(2, parameters)
            return status or self._extra_parameters(parameters)
        self.delay_ms = self.context.broker(0x14B)
        blob = self.context.broker_data(500)
        if type(blob) is not bytes or len(blob) > 65536 * 8:
            raise ValueError("Bounded immutable native SCONFIG backing required")
        parameters = tuple(
            (
                int.from_bytes(blob[index : index + 4], "little"),
                int.from_bytes(blob[index + 4 : index + 8], "little"),
            )
            for index in range(0, len(blob) & ~7, 8)
        )
        status = self.driver.ioctl(2, parameters)
        if status and any(key == 0x2A for key, _ in parameters):
            status = self.driver.ioctl(
                2, tuple(pair for pair in parameters if pair[0] != 0x2A)
            )
        return status

    def _filter_message(self, address: int, extra: int = 0) -> NativeMessage:
        return NativeMessage(
            6, address.to_bytes(4, "big") + (bytes((extra,)) if extra else b"")
        )

    def _start_filter(
        self,
        index: int,
        kind: int,
        mask: NativeMessage,
        pattern: NativeMessage,
        flow: NativeMessage | None,
    ) -> int:
        def retain(handle: int) -> None:
            self.filter_ids[index] = handle

        try:
            self.driver._call(
                "PassThruStartMsgFilter",
                acquired=retain,
                channel_id=self.driver.handle,
                filter_type=kind,
                mask=mask,
                pattern=pattern,
                flow_control=flow,
            )
        except NativeJ2534Error2026:
            # 21ca0 deliberately discards the raw SDK filter status.
            return 0
        return 0

    def _sil_filters(self) -> int:
        expected = (self.driver.address - self.sil_offset) & 0xFFFFFFFF
        # Native ignores the first filter's raw status and returns the second.
        self._start_filter(
            0, 1, self._filter_message(0x7FF), self._filter_message(expected), None
        )
        return self._start_filter(
            1,
            3,
            self._filter_message(0xFFFFFFFF),
            self._filter_message(expected),
            self._filter_message(self.driver.address),
        )

    def _sil_session(self, entering: bool) -> int:
        if self.sil_offset == 0x20:
            request, expected = (
                (b"\x81", b"\xc1\xd0\x8f") if entering else (b"\x82", b"\xc2")
            )
        else:
            request, expected = (
                (b"\x10\xc0", b"\x50\xc0") if entering else (b"\x10\x81", b"\xc1\x81")
            )
        status = self.send(request)
        if status:
            return status
        for _ in range(65536):
            reply = self.receive()
            if reply.status == 5:
                continue
            if reply.status:
                return reply.status
            return 0 if reply.data == expected else 3
        raise TimeoutError("Native SIL session exceeds host receive budget")

    def _sil_finalize(self) -> int:
        native_status = 0
        primary: BaseException | None = None
        if self.driver.handle is not None:
            if self._sil_session_active:
                try:
                    with utility_ex_cleanup_scope(self):
                        native_status = self._sil_session(False)
                except BaseException as error:  # noqa: BLE001 - still close filters and channel
                    primary = error
            try:
                result = self.driver._call(
                    "PassThruStopMsgFilter",
                    channel_id=self.driver.handle,
                    filter_id=self.filter_ids[0],
                    cleanup=True,
                )
                if result.status == 0:
                    self.filter_ids[0] = 0xFFFFFFFF
            except BaseException as error:  # noqa: BLE001 - preserve session failure
                if primary is None:
                    primary = error
            try:
                disconnected = self.driver.finalize()
                if disconnected:
                    native_status = disconnected
                else:
                    self.attached = False
                    self._sil_session_active = False
                    self.filter_ids[1] = 0xFFFFFFFF
            except BaseException as error:  # noqa: BLE001 - retain failed channel ownership
                if primary is None:
                    primary = error
        else:
            self.attached = False
        if primary is not None:
            raise primary
        return native_status

    def initialize(
        self, address: int, *, override: bool = False, reuse: bool = False
    ) -> int:
        if type(address) is not int or not 0 <= address <= 0xFFFFFFF7:
            raise ValueError("Native CAN target must permit response+8")
        if type(override) is not bool or type(reuse) is not bool:
            raise TypeError("Native classic initialization flags must be bool")
        if type(self.profile) is not int or not 0 <= self.profile <= 0xFFFFFFFF:
            raise ValueError("Native selected profile must be uint32")
        self.attached = True
        try:
            # Native ignores Connect return and examines the resulting phase3.
            self.driver.connect(address, 0x80 if self.extended else 0)
            if self.driver.handle is None:
                self.finalize()
                return 99
            status = self._configure(override or reuse)
            if self.sil_offset:
                if status == 0:
                    status = self._sil_filters()
                if status == 0:
                    status = self._sil_session(True)
                    self._sil_session_active = status == 0
                if status:
                    self.finalize()
                return status
            if status == 0:
                broad = self._filter_message(0x700)
                status = self._start_filter(0, 1, broad, broad, broad)
            if status == 0:
                base = _TARGET_GLOBAL_BASES[self.context.module_sha256]
                extra = self.context.state.get(
                    f"native_global:{base + 4:x}", self.context.broker(0xAB)
                )
                target = self.context.state.get(
                    f"native_global:{base:x}", self.context.broker(0x74)
                )
                if (
                    type(extra) is not int
                    or not 0 <= extra <= 0xFFFFFFFF
                    or type(target) is not int
                    or not 0 <= target <= 0xFFFFFFFF
                ):
                    raise ValueError(
                        "Native selected filter target globals must be uint32"
                    )
                extra &= 255
                status = self._start_filter(
                    1,
                    3,
                    self._filter_message(0xFFFFFFFF, 255 if extra else 0),
                    self._filter_message((target + 8) & 0x7FF, extra),
                    self._filter_message(target & 0x7FF, extra),
                )
            if status:
                self.finalize()
            return status
        except BaseException as error:
            try:
                self.finalize()
            except BaseException as cleanup:  # noqa: BLE001 - retain the first SDK failure
                error.add_note("Selected CAN cleanup: " + type(cleanup).__name__)
            raise

    def finalize(self) -> int:
        if not self.attached:
            return 0
        if self.sil_offset:
            return self._sil_finalize()
        primary: BaseException | None = None
        if self.driver.handle is not None:
            for index, handle in enumerate(self.filter_ids):
                try:
                    result = self.driver._call(
                        "PassThruStopMsgFilter",
                        channel_id=self.driver.handle,
                        filter_id=handle,
                        cleanup=True,
                    )
                    if result.status == 0:
                        self.filter_ids[index] = 0xFFFFFFFF
                except BaseException as error:  # noqa: BLE001 - release every acquired resource
                    if primary is None:
                        primary = error
            try:
                status = self.driver.finalize()
            except BaseException as error:  # noqa: BLE001 - preserve a prior filter fault
                if primary is None:
                    primary = error
                status = 99
        else:
            status = 0
        if status == 0:
            self.attached = False
        if primary is not None:
            raise primary
        return status

    def _extension(self) -> int:
        base = _TARGET_GLOBAL_BASES[self.context.module_sha256]
        value = self.context.state.get(
            f"native_global:{base + 4:x}", self.context.broker(0xAB)
        )
        if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
            raise ValueError("Native selected extension global must be uint32")
        return value & 255

    def send(self, request: bytes) -> int:
        if not self.attached:
            return 99
        if type(request) is not bytes or len(request) > (
            0x101B if self.extended else 0x101C
        ):
            raise ValueError("Bounded immutable selected CAN request required")
        self.timeout_ms = 0x3FC if self.p5 else self._normal_timeout()
        return self.driver.write(
            NativeMessage(
                6,
                self.driver.address.to_bytes(4, "big")
                + (bytes((self._extension(),)) if self.extended else b"")
                + request,
            ),
            self.timeout_ms,
        )

    def receive(self) -> DriverReceive:
        if not self.attached:
            return DriverReceive(99)
        status, message = self.driver.read(self.timeout_ms)
        self.last_receive_tick = self.context.ticks()
        if status:
            return DriverReceive(status)
        assert message is not None
        if self.sil_offset:
            expected = (self.driver.address - self.sil_offset) & 0xFFFFFFFF
            if len(message.data) < 4 or message.data[:4] != expected.to_bytes(4, "big"):
                return DriverReceive(3)
            response = message.data[4:]
            status, native_error = 0, 0
            if response[:1] == b"\x7f":
                if len(response) != 3:
                    status = 3
                else:
                    status = {0x12: 0x16, 0x21: 0x1B, 0x78: 5}.get(response[2], 7)
                    native_error = NATIVE_NRC.get(response[2], 999)
            reply = DriverReceive(status, response, native_error)
        else:
            if len(message.data) < 4 or message.data[:4] != (
                self.driver.address + 8
            ).to_bytes(4, "big"):
                return DriverReceive(3)
            if self.extended:
                if len(message.data) < 5 or message.data[4] != self._extension():
                    return DriverReceive(3)
                message = NativeMessage(6, message.data[:4] + message.data[5:])
            reply = unpack_uds_response(message, self.driver.address)
        if reply.status == 5:
            self.timeout_ms = 5530 if self.p5 and not self.extended else 5000
        else:
            if not self.p5:
                self.timeout_ms = self._normal_timeout()
            if reply.status in (7, 0x16, 0x1B):
                self.context.native_sleep(self.delay_ms)
        return reply

    def _normal_timeout(self) -> int:
        if (
            self.extended
            or self.sil_offset
            or self.context.module_sha256 in (SHA_12_NK, SHA_12_TY)
        ):
            return 1000
        return self.native_timeout_10

    def interrupt(self, timeout_ms: int) -> int:
        if type(timeout_ms) is not int or not 0 <= timeout_ms <= 65536:
            raise ValueError("Bounded native interrupt receive count required")
        if self.p5:
            return 0
        if self.send(b"\x3e"):
            return 99
        status = 0
        for _ in range(timeout_ms):
            status = self.receive().status
            if status != 5:
                return 0 if status == 0 else 99
        return status


@contextmanager
def utility_ex_cleanup_scope(
    lower: UtilityExCANLower
    | UtilityExP3Lower
    | UtilityExClassicCANLower
    | UtilityExSISLower,
):
    """Bounded explicit wire release, borrowing the guard's thread-local scope."""
    if isinstance(lower, UtilityExCANLower):
        device = lower.pool.device
    elif isinstance(
        lower, (UtilityExP3Lower, UtilityExClassicCANLower, UtilityExSISLower)
    ):
        device = lower.driver.device
    else:
        raise TypeError("Concrete owned UtilityEx lower required for cleanup")
    execution = device._execution_context
    previous = getattr(execution, "cleanup", False)
    previous_deadline = getattr(execution, "cleanup_deadline", None)
    deadline = device.clock() + 5.0
    execution.cleanup_deadline = (
        min(deadline, previous_deadline) if previous_deadline is not None else deadline
    )
    execution.cleanup = True
    try:
        yield
    finally:
        execution.cleanup = previous
        execution.cleanup_deadline = previous_deadline


@dataclass
class UtilityExByteArray:
    """Mutable native SBYTE_ARRAY count/backing for FIVE_BAUD_INIT."""

    count: int
    data: bytearray

    def validate(self) -> None:
        if (
            type(self.count) is not int
            or type(self.data) is not bytearray
            or not 0 <= self.count <= len(self.data) <= 65536
        ):
            raise ValueError("Bounded mutable native SBYTE_ARRAY required")


def legacy_p4_parameters(profile: int) -> tuple[tuple[int, int], ...]:
    if type(profile) is not int or not 0 <= profile <= 0xFFFFFFFF:
        raise ValueError("Native legacy P4 profile must be uint32")
    if profile in (1, 0x1EB):
        return (
            (1, 10400),
            (20, 25),
            (14, 105),
            (15, 20),
            (16, 20),
            (17, 50),
            (18, 330),
            (6, 0),
            (7, 40),
            (8, 50),
            (9, 100),
            (10, 110),
            (11, 10000),
            (12, 10),
            (13, 40),
        )
    return (
        (1, 10400),
        (20, 25),
        (14, 300),
        (15, 20),
        (16, 20),
        (17, 30),
        (18, 350),
        (9, 100),
        (10, 100),
    )


class UtilityExLegacyP4Lower(UtilityExP3Lower):
    """Eight source selected P4/ISO9141 lifecycles and checksummed frames."""

    def initialize(
        self,
        address: int,
        *,
        override: bool = False,
        supplied: tuple[tuple[int, int], ...] | None = None,
        reuse: bool = False,
    ) -> int:
        if self.context.module_sha256 not in _MANAGER_OBJECTS:
            raise UtilityExSourceError("Legacy P4 lower source is not reviewed")
        if type(override) is not bool:
            raise TypeError("Native initialization override must be bool")
        parameters = (
            legacy_p4_parameters(self.profile) if override or reuse else supplied
        )
        return super().initialize(
            address, override=False, supplied=parameters, reuse=reuse
        )

    def fast_init(self) -> int:
        if not self.attached or self.driver.handle is None:
            return 99
        for _ in range(3):
            fast = self.context.native_parameter(0x73) == 0x5C
            if fast:
                from scripts.utility_ex_comm import pack_p3_request

                request = pack_p3_request(self.driver.address, b"\x81", 4)
                output = [NativeMessage(4, bytes(7))]
                status = self.driver.ioctl(5, request, output)
                if status == 2:
                    continue
                if status:
                    return 4
                if len(output) != 1 or not isinstance(output[0], NativeMessage):
                    raise ValueError(
                        "One bounded native legacy FAST_INIT output required"
                    )
                data = output[0].data
                backing = data.ljust(4, b"\0")
                if (
                    backing[1] != 0xF0
                    or backing[2] != self.driver.address
                    or not data
                    or data[-1] != sum(data[:-1]) & 255
                ):
                    return 3
                return 0
            delay = (self.last_receive_tick + 5000 - self.context.ticks()) & 0xFFFFFFFF
            if delay < 5000:
                self.context.native_sleep(delay)
            request_bytes = UtilityExByteArray(1, bytearray(b"\x33"))
            keyword_bytes = UtilityExByteArray(2, bytearray(2))
            status = self.driver.ioctl(4, request_bytes, keyword_bytes)
            request_bytes.validate()
            keyword_bytes.validate()
            if status == 2:
                continue
            self.last_receive_tick = self.context.ticks()
            return status
        if fast:
            return 4
        self.last_receive_tick = self.context.ticks()
        return 2

    def send(self, request: bytes) -> int:
        if not self.attached:
            return 99
        if type(request) is not bytes or len(request) > 0x101C:
            raise ValueError("Bounded immutable legacy P4 request required")
        data = b"\x68\x6a\xf0" + request
        self.timeout_ms = 1000
        return self.driver.write(
            NativeMessage(4, data + bytes((sum(data) & 255,))), self.timeout_ms
        )

    @staticmethod
    def _decode(data: bytes, previous: bytes = b"") -> DriverReceive:
        if len(data) < 4 or data[:2] != b"\x48\x6b" or data[-1] != sum(data[:-1]) & 255:
            return DriverReceive(3, previous)
        response = data[3:-1]
        status = 0
        if len(response) >= 3 and response[0] == 0x7F:
            status = {0x78: 5, 0x21: 0x1B}.get(response[2], 0)
        return DriverReceive(status, response)

    def receive_once(self) -> DriverReceive:
        """Distinct native vslot18/1a820, not aggregate vslot14/1a760."""
        if not self.attached:
            return DriverReceive(99)
        for _ in range(65536):
            status, message = self.driver.read(self.timeout_ms)
            self.last_receive_tick = self.context.ticks()
            if status:
                return DriverReceive(status)
            assert message is not None
            self.timeout_ms = 100
            if len(message.data) >= 3 and message.data[2] == self.driver.address:
                return self._decode(message.data)
        raise TimeoutError(
            "Native legacy P4 single receive exceeds host primitive budget"
        )

    def receive(self) -> DriverReceive:
        if not self.attached:
            return DriverReceive(99)
        last = DriverReceive(2)
        backing = bytes(0x1020)
        for _ in range(65536):
            status, message = self.driver.read(self.timeout_ms)
            self.last_receive_tick = self.context.ticks()
            if status == 2:
                return last
            if message is not None:
                backing = message.data
            data = backing
            if len(data) >= 3 and data[2] == self.driver.address:
                last = self._decode(data, last.data)
                if last.status == 5:
                    return last
            self.timeout_ms = 100
        raise TimeoutError("Native legacy P4 receive exceeds host primitive budget")


def p3_strict_parameters(profile: int, source: str) -> tuple[tuple[int, int], ...]:
    """Selected index2 19b50/387e0, distinct from base P3's 9600 table."""
    unsigned(profile)
    if source not in _MANAGER_OBJECTS:
        raise UtilityExSourceError("Selected strict P3 source is not reviewed")
    profiles = (2, 0x104) if source in (SHA_12_NK, SHA_12_TY) else (2, 0x104, 0x156)
    if profile not in profiles:
        return ((1, 10400), (20, 25), (9, 100), (10, 100))
    return (
        (1, 10400),
        (20, 25),
        (14, 300 if profile == 0x156 else 105),
        (15, 20),
        (16, 20),
        (17, 50),
        (18, 300),
        (6, 0),
        (7, 40),
        (8, 40 if profile == 2 else 50),
        (9, 110 if profile == 2 else 100),
        (10, 0 if profile == 2 else 110),
        (11, 10000),
        (12, 10),
        (13, 40),
    )


class UtilityExP3StrictLower(UtilityExP3Lower):
    """Selected index2: F0 frames with exact three-byte NRC decoding."""

    tester_address = 0xF0

    def initialize(
        self,
        address: int,
        *,
        override: bool = False,
        supplied: tuple[tuple[int, int], ...] | None = None,
        reuse: bool = False,
    ) -> int:
        parameters = (
            p3_strict_parameters(self.profile, self.context.module_sha256)
            if override or reuse
            else supplied
        )
        return super().initialize(
            address, override=False, supplied=parameters, reuse=reuse
        )

    def receive(self) -> DriverReceive:
        if not self.attached:
            return DriverReceive(99)
        status, message = self.driver.read(self.timeout_ms)
        self.last_receive_tick = self.context.ticks()
        if status:
            return DriverReceive(status)
        assert message is not None
        data = message.data
        if (
            len(data) < 4
            or data[1] != self.tester_address
            or data[2] != self.driver.address
            or data[-1] != sum(data[:-1]) & 255
        ):
            return DriverReceive(3)
        response = data[3:-1]
        status = 0
        if response[:1] == b"\x7f":
            status = (
                3
                if len(response) != 3
                else {0x12: 0x16, 0x21: 0x1B, 0x78: 5}.get(response[2], 7)
            )
        return DriverReceive(status, response)


class UtilityExP3F1Lower(UtilityExP3StrictLower):
    """Selected index1: tester F1 and its own sixteen-entry timing table."""

    tester_address = 0xF1

    def initialize(
        self,
        address: int,
        *,
        override: bool = False,
        supplied: tuple[tuple[int, int], ...] | None = None,
        reuse: bool = False,
    ) -> int:
        parameters = (
            (
                (1, 10400),
                (20, 25),
                (21, 50),
                (14, 250),
                (15, 20),
                (16, 20),
                (17, 50),
                (18, 300),
                (6, 0),
                (7, 20),
                (8, 2),
                (9, 500),
                (10, 2),
                (11, 10000),
                (12, 40),
                (13, 50),
            )
            if override or reuse
            else supplied
        )
        return UtilityExP3Lower.initialize(
            self, address, override=False, supplied=parameters, reuse=reuse
        )

    def _message(self, request: bytes) -> NativeMessage:
        if type(request) is not bytes or len(request) > 0x101C:
            raise ValueError("Bounded immutable F1 request required")
        data = (
            bytes(((len(request) + 0x80) & 255, self.driver.address & 255, 0xF1))
            + request
        )
        return NativeMessage(4, data + bytes((sum(data) & 255,)))

    def send(self, request: bytes) -> int:
        return (
            99
            if not self.attached
            else self.driver.write(self._message(request), self.timeout_ms)
        )

    def fast_init(self) -> int:
        if not self.attached:
            return 0
        for _ in range(3):
            output = [NativeMessage(4, bytes(7))]
            status = self.driver.ioctl(5, self._message(b"\x81"), output)
            if status == 2:
                continue
            if status:
                return 4
            if len(output) != 1 or not isinstance(output[0], NativeMessage):
                raise ValueError("One bounded native F1 FAST_INIT output required")
            data = output[0].data
            if (
                len(data) < 4
                or data[1] != 0xF1
                or data[2] != self.driver.address
                or data[-1] != sum(data[:-1]) & 255
            ):
                return 3
            return 0
        return 4


class UtilityExP3SlowLower(UtilityExP3Lower):
    """Selected index4: F0 P3 codec, slow/fast init and fixed nine timings."""

    fast_init = UtilityExLegacyP4Lower.fast_init

    def initialize(
        self,
        address: int,
        *,
        override: bool = False,
        supplied: tuple[tuple[int, int], ...] | None = None,
        reuse: bool = False,
    ) -> int:
        parameters = (
            (
                (1, 10400),
                (20, 35),
                (14, 300),
                (15, 20),
                (16, 20),
                (17, 30),
                (18, 350),
                (9, 100),
                (10, 100),
            )
            if override or reuse
            else supplied
        )
        return super().initialize(
            address, override=False, supplied=parameters, reuse=reuse
        )


@dataclass
class UtilityExSISMessage:
    """Native v0500 nine-DWORD descriptor, separate from PASSTHRU_MSG.

    Pointer field1c is represented by its owned byte backing. The source sets
    fields14/18 and length20 independently; a read can change length20 without
    changing the backing capacity. Reserved fields remain explicit DWORDs.
    """

    protocol_id: int
    data: bytearray
    length: int
    rx_status: int = 0
    tx_flags: int = 0
    timestamp: int = 0
    native_10: int = 0
    native_14: int = 0
    native_18: int = 0

    def validate(self) -> None:
        for value in (
            self.protocol_id,
            self.length,
            self.rx_status,
            self.tx_flags,
            self.timestamp,
            self.native_10,
            self.native_14,
            self.native_18,
        ):
            unsigned(value)
        if (
            not isinstance(self.data, bytearray)
            or len(self.data) > 0x1020
            or self.length > len(self.data)
        ):
            raise ValueError("Bounded mutable native v0500 message required")


@dataclass(frozen=True)
class UtilityExSISPins:
    """SCONFIG-style native Connect structure passed inline, not a pointer."""

    kind: int
    pins: tuple[int, ...]

    def __post_init__(self) -> None:
        unsigned(self.kind)
        if not isinstance(self.pins, tuple) or len(self.pins) > 16:
            raise ValueError("Bounded native pin backing required")
        for pin in self.pins:
            unsigned(pin)


class _SISPrimitives:
    def __init__(self, context: CommContext, binding: object):
        from scripts.utility_ex import UtilitySISDriverBinding

        if (
            not isinstance(binding, UtilitySISDriverBinding)
            or binding.context is not context
            or not binding.ready
        ):
            raise TypeError("Ready same-context concrete SIS DRIVER required")
        self.binding = binding

    def __call__(self, operation: dict, remaining: float) -> PrimitiveResult:
        function = self.binding.resolve(
            self.binding.slot_offset(operation["operation"])
        )
        if function is None:
            raise UtilityExSourceError("Native SIS primitive unavailable")
        result = function(*operation["arguments"])
        if not isinstance(result, PrimitiveResult) or result.value is not None:
            raise TypeError("Raw SIS SDK status with positional outputs required")
        output = operation.get("handle_output")
        if output is not None:
            if not isinstance(output, bytearray) or len(output) != 4:
                raise ValueError("Native SIS output DWORD must retain four bytes")
            return PrimitiveResult(result.status, int.from_bytes(output, "little"))
        return result


_SIS_PLUS_GLOBALS = {
    0x1011F700: 0x1013FA38,
    0x1011F708: 0x1013FA40,
    0x1011F70C: 0x1013FA44,
    0x1011F728: 0x1013FA60,
    0x1011F72C: 0x1013FA64,
    0x1011F730: 0x1013FA68,
    0x1011F734: 0x1013FA6C,
    0x1011F738: 0x1013FA70,
    0x1011F73C: 0x1013FA74,
    0x1011F740: 0x1013FA78,
    0x1011F748: 0x1013FA80,
    0x1011F750: 0x1013FA88,
    0x1011F754: 0x1013FA8C,
    0x1011F758: 0x1013FA90,
    0x1011F75C: 0x1013FA94,
}


class UtilityExSISDriver:
    """TY18 1f4c0..1fcf0 owned v0500 physical/logical DRIVER singleton.

    Handles60/64/68/6c and controller78 are independent. This does not use the
    ordinary CAN pool or standard DRIVER's symbol offsets/message layout.
    """

    def __init__(self, context: CommContext, binding: object):
        if context.module_sha256 not in (SHA_18_TY, SHA_PLUS_TY):
            raise UtilityExSourceError("SIS DRIVER source is not reviewed")
        adapter = _SISPrimitives(context, binding)
        self.context, self.adapter = context, adapter
        self.device = J2534Device2026(
            adapter, cancelled=context.is_cancelled, background_workers=False
        )
        self.controller: int | None = None
        self.physical: int | None = None
        self.logical: dict[int, int] = {}
        self.address = 0x103
        self.phase = 1

    def _call(
        self, name: str, arguments: tuple, *, output=None, retain=None, cleanup=False
    ) -> PrimitiveResult:
        observed: list[PrimitiveResult] = []
        self.device._call(
            name,
            arguments=arguments,
            handle_output=output,
            acquired=retain,
            cleanup=cleanup,
            ignore_status=retain is None,
            observed=observed.append,
        )
        return observed[0]

    def initialize_controller(self) -> int:
        output = bytearray(4)
        # f4c0 ignores the native status but stores the output before returning.
        # accepted() retains even a nonzero-status output before host postcheck.
        self.device._call(
            "J2534CtrlInitialize",
            arguments=(2, output, 0)
            if self.context.module_sha256 == SHA_PLUS_TY
            else (2, output),
            handle_output=output,
            ignore_status=True,
            accepted=lambda value: setattr(self, "controller", unsigned(value)),
        )
        return 0

    def connect(
        self, address: int, flags: int, oem_parameter: int, pins: UtilityExSISPins
    ) -> int:
        for value in (address, flags, oem_parameter):
            unsigned(value)
        if not isinstance(pins, UtilityExSISPins):
            raise TypeError("Concrete SIS native pin configuration required")
        if self.physical is not None:
            return 13 if address == self.address else 14
        if self.controller is None:
            raise ValueError("SIS controller is not initialized")
        output = bytearray(4)

        def retain(handle: int) -> None:
            self.physical, self.address, self.phase = handle, address, 3

        try:
            self._call(
                "PassThruConnect_v0500",
                (
                    self.controller,
                    0x800F,
                    flags,
                    oem_parameter,
                    pins.kind,
                    len(pins.pins),
                    pins.pins,
                    output,
                ),
                output=output,
                retain=retain,
            )
        except NativeJ2534Error2026:
            return 99
        return 0

    def ioctl(self, kind: int, payload=None, output=None, *, cleanup=False) -> int:
        unsigned(kind)
        handle = (
            self.physical
            if kind == 2
            else self.logical.get(0x8206)
            if kind == 8
            else self.controller
        )
        if handle is None:
            return 99
        result = self._call(
            "PassThruIoctl_v0500",
            (handle, kind, payload, output),
            cleanup=cleanup,
        )
        return 0 if result.status == 0 else 2 if result.status == 9 else 99

    def logical_connect(self, protocol: int, configuration: bytes) -> int:
        if protocol not in (0x8203, 0x8205, 0x8206):
            raise ValueError("Unreviewed SIS logical protocol")
        if not isinstance(configuration, bytes) or len(configuration) > 32:
            raise ValueError("Bounded immutable native logical config required")
        parent = self.physical if protocol == 0x8203 else self.logical.get(0x8203)
        if parent is None:
            return 3
        if protocol in self.logical:
            raise ValueError("SIS logical channel already owned")
        output = bytearray(4)

        def retain(handle: int) -> None:
            self.logical[protocol] = handle
            # UDP phase8 is set only after its CLEAR_RX_BUFFER succeeds.
            if protocol != 0x8205:
                self.phase |= {0x8203: 4, 0x8206: 0x10}[protocol]

        try:
            self._call(
                "PassThruLogicalConnect_v0500",
                (parent, protocol, 0, configuration, output),
                output=output,
                retain=retain,
            )
        except NativeJ2534Error2026:
            return 3
        return 0

    def _global(self, address: int) -> int:
        if self.context.module_sha256 == SHA_PLUS_TY:
            if address not in _SIS_PLUS_GLOBALS:
                raise UtilityExSourceError("Plus SIS native global is not reviewed")
            address = _SIS_PLUS_GLOBALS[address]
        value = self.context.state.get(f"native_global:{address:x}")
        if value is None:
            reader = getattr(self.context, "read_module_data", None)
            if reader is None:
                raise UtilityExSourceError(f"SIS native global {address:x} unavailable")
            value = int.from_bytes(reader(address, 4), "little")
        return unsigned(value)

    def initialize_logical(
        self, udp_port: int | None = None, tcp_port: int | None = None
    ) -> int:
        """Native f760 discovery/routing; ports are individual INI outputs."""
        if udp_port is not None:
            unsigned(udp_port)
        if tcp_port is not None:
            unsigned(tcp_port)
        if self.phase < 3:
            return 3
        ip = self._global(0x1011F730)
        status = self.logical_connect(
            0x8203, b"\x01" + ip.to_bytes(4, "little") + bytes(16)
        )
        if status:
            return status
        if udp_port is None:
            udp_port = self._source_port("UDP")
        status = self.logical_connect(
            0x8205, ((udp_port or 0xC000) & 0xFFFF).to_bytes(2, "little")
        )
        if status:
            return status
        raw = self._call(
            "PassThruIoctl_v0500", (self.logical[0x8205], 8, None, None)
        ).status
        if raw:
            return 2 if raw == 9 else 99
        self.phase |= 8
        backing = bytearray(0x1020)
        backing[:14] = bytes.fromhex("ffffffff3458ff00000100000000")
        message = UtilityExSISMessage(0x8205, backing, 14, native_14=14, native_18=14)
        status = self.queue(message, tcp=False)
        if status:
            return 99  # f760 remaps helper's native3, not the raw SDK status.
        reply = UtilityExSISMessage(0x8205, backing, 0x1020)
        status = self.read(0x8205, 1, reply, self._global(0x1011F734))
        if status:
            return 99
        remote_port = int.from_bytes(backing[4:6], "big")
        if tcp_port is None:
            tcp_port = self._source_port("TCP")
        tcp_config = (
            ((tcp_port or 0xC000) & 0xFFFF).to_bytes(2, "little")
            + remote_port.to_bytes(2, "little")
            + backing[:4]
            + bytes(12)
        )
        status = self.logical_connect(0x8206, tcp_config)
        if status:
            return status
        status = self.ioctl(8)
        if status:
            return status
        backing[2:4] = b"\x00\x05"
        backing[10:15] = bytes(5)
        message = UtilityExSISMessage(0x8208, backing, 15, native_14=15, native_18=14)
        status = self.queue(message, tcp=True)
        if status:
            return 99
        reply.protocol_id, reply.native_14 = 0x8208, 0x1020
        status = self.read(0x8208, 0x11, reply, self._global(0x1011F738))
        return 0 if status == 0 else 99

    def _source_port(self, transport: str) -> int:
        if self.context.module_sha256 == SHA_PLUS_TY:
            getter = getattr(self.context, "json_d_get_data", None)
            if not callable(getter):
                raise UtilityExSourceError(
                    "Individual Plus JsonDGetData primitive required"
                )
            return unsigned(getter(1, "ethernet", "sourcePortNumber" + transport))
        return self.context.get_private_profile_int_a(  # type: ignore[attr-defined]
            b"Ethernet",
            ("SourcePortNumber" + transport).encode("ascii"),
            0,
            b".\\EtherTimeParam.ini",
        )

    def read(
        self, protocol: int, count: int, message: UtilityExSISMessage, timeout_ms: int
    ) -> int:
        for value in (protocol, count, timeout_ms):
            unsigned(value)
        if not isinstance(message, UtilityExSISMessage):
            raise TypeError("Concrete v0500 message required")
        message.validate()
        handle = (
            self.physical
            if protocol == 0x800F
            else self.logical.get(protocol if protocol in (0x8203, 0x8205) else 0x8206)
        )
        if handle is None or self.phase < 3:
            return 3
        reported = bytearray(count.to_bytes(4, "little"))
        result = self._call(
            "PassThruReadMsgs_v0500", (handle, message, reported, timeout_ms)
        )
        if len(reported) != 4 or int.from_bytes(reported, "little") > count:
            raise ValueError("Native SIS read count exceeds supplied bound")
        message.validate()
        return 0 if result.status == 0 else 2 if result.status in (9, 0x10) else 3

    def queue(self, message: UtilityExSISMessage, *, tcp: bool) -> int:
        if not isinstance(message, UtilityExSISMessage) or type(tcp) is not bool:
            raise TypeError("Concrete SIS message and boolean transport required")
        message.validate()
        protocol = 0x8206 if tcp else 0x8205
        if self.phase < (0x1F if tcp else 0xF) or protocol not in self.logical:
            return 3
        if tcp:
            if message.length < 10:
                raise ValueError("SIS TCP envelope requires at least ten bytes")
            message.data[:2] = b"\x02\xfd"
            message.data[4:8] = (message.length - 8).to_bytes(4, "big")
            value = self._global(0x1011F758)
            message.data[8:10] = (unsigned(value) & 0xFFFF).to_bytes(2, "big")
        count = bytearray((1).to_bytes(4, "little"))
        result = self._call(
            "PassThruQueueMsgs_v0500", (self.logical[protocol], message, count)
        )
        if len(count) != 4 or int.from_bytes(count, "little") > 1:
            raise ValueError("Native SIS queue count exceeds one descriptor")
        return 0 if result.status == 0 else 3

    def finalize_logical(self) -> int:
        result = 0
        for protocol, bit in ((0x8206, 0x10), (0x8205, 8), (0x8203, 4)):
            if protocol not in self.logical:
                continue
            status = self._call(
                "PassThruLogicalDisconnect_v0500",
                (self.logical[protocol],),
                cleanup=True,
            ).status
            if status:
                result = 3
            else:
                del self.logical[protocol]
                self.phase &= ~bit
        return result

    def finalize(self) -> int:
        logical_status = self.finalize_logical()
        if self.logical:
            return logical_status
        if self.physical is None:
            return logical_status
        result = self._call("PassThruDisconnect_v0500", (self.physical,), cleanup=True)
        if result.status:
            return 3
        self.physical, self.phase = None, 1
        return logical_status


class SISContext(CommContext, Protocol):
    def read_module_data(self, address: int, size: int) -> bytes: ...
    def get_private_profile_int_a(
        self, section: bytes, key: bytes, default: int, filename: bytes
    ) -> int: ...
    def get_private_profile_string_a(
        self,
        section: bytes,
        key: bytes,
        default: bytes,
        output: bytearray,
        capacity: int,
        filename: bytes,
    ) -> int: ...


class UtilityExSISLower:
    """TY18/Plus measured physical init and source-specific DoIP stream I/O."""

    def __init__(self, context: SISContext, driver: UtilityExSISDriver):
        if (
            context.module_sha256 not in (SHA_18_TY, SHA_PLUS_TY)
            or not isinstance(driver, UtilityExSISDriver)
            or driver.context is not context
        ):
            raise TypeError("Concrete same-context source SIS DRIVER required")
        self.context, self.driver = context, driver
        self.address = 0
        self.timeout_ms = 0
        self.last_receive_tick = 0
        self.attached = False
        self.parameters: tuple[tuple[int, int], ...] = ()

    def _cstring(self, address: int) -> bytes:
        data = self.context.read_module_data(address, 256)
        end = data.find(b"\x00")
        if end < 0:
            raise ValueError("Bounded NUL-terminated SIS source string required")
        return data[:end]

    def interrupt(self, timeout_ms: int) -> int:
        if type(timeout_ms) is not int or timeout_ms != 100:
            raise ValueError("Native SIS interrupt uses count100")
        # TY18 vslot0c=1e9a0 / Plus16680 are actual no-op methods.
        return 0

    def _measure(self, pin: int) -> tuple[int, int]:
        output = bytearray(4)
        status = self.driver.ioctl(3, UtilityExSISPins(1, (pin,)), output)
        if len(output) != 4:
            raise ValueError("Native SIS measurement DWORD must retain four bytes")
        return status, int.from_bytes(output, "little")

    def _fallback_valid(self) -> bool:
        if self.context.module_sha256 == SHA_PLUS_TY:
            getter = getattr(self.context, "json_s_get_data", None)
            if not callable(getter):
                raise UtilityExSourceError(
                    "Individual Plus JsonSGetData primitive required"
                )
            value = getter(3, "vim", "name")
            if type(value) is not str or len(value) > 4096 or "\0" in value:
                raise ValueError("Bounded native JSON UTF16 string required")
            backing = self.context.read_module_data(0x100DF360, 256)
            for end in range(0, len(backing) - 1, 2):
                if backing[end : end + 2] == b"\0\0":
                    expected = backing[:end].decode("utf-16-le")
                    return value == expected
            raise ValueError("Bounded NUL-terminated SIS source UTF16 string required")
        output = bytearray(17)
        default = self.context.state.get("native_bytes:101207e4")
        if default is None:
            default = self._cstring(0x101207E4)
        if type(default) is not bytes or b"\x00" in default:
            raise ValueError("Native SIS default profile value must be ANSI bytes")
        count = self.context.get_private_profile_string_a(
            self._cstring(0x100F81C0),
            self._cstring(0x100F81CC),
            default,
            output,
            17,
            self._cstring(0x100F81D4),
        )
        expected = self._cstring(0x100F81AC) + b"\x00"
        return count == 16 and len(expected) == 17 and output == expected

    def _configure(self, override: bool) -> int:
        if override:
            parameters = self.parameters or ((0x805F, 1),)
        else:
            blob = self.context.broker_data(500)
            if type(blob) is not bytes or len(blob) > 0x10000 * 8:
                raise ValueError("Bounded immutable native broker500 required")
            parameters = tuple(
                (
                    int.from_bytes(blob[i : i + 4], "little"),
                    int.from_bytes(blob[i + 4 : i + 8], "little"),
                )
                for i in range(0, len(blob) & ~7, 8)
            )
        return self.driver.ioctl(2, parameters)

    def initialize(
        self, address: int, *, override: bool = True, reuse: bool = False
    ) -> int:
        unsigned(address)
        if type(override) is not bool or type(reuse) is not bool:
            raise TypeError("Native SIS init controls must be bool")
        self.address, self.attached = address, True
        if self.driver.controller is None:
            raise UtilityExSourceError("SIS controller2 initialization is required")
        try:
            status = self._initialize(override, reuse)
            if status and status != 13:
                self.finalize()
            return status
        except BaseException as error:
            try:
                self.finalize()
            except BaseException as cleanup_error:  # noqa: BLE001 - preserve primary failure
                error.add_note("SIS lower cleanup: " + type(cleanup_error).__name__)
            raise

    def _initialize(self, override: bool, reuse: bool) -> int:
        driver = self.driver
        word = lambda value: bytearray(value.to_bytes(4, "little"))
        if driver.ioctl(0x8022, word(0xFFFFFFFF)) == 0:
            self.context.native_sleep(driver._global(0x1011F750))
        status, first = self._measure(8)
        if status:
            return status
        if first >= 2000:
            return 99
        status = driver.ioctl(0x8022, word(0x125C))
        if status:
            if not self._fallback_valid():
                return status
        else:
            self.context.native_sleep(driver._global(0x1011F754))
            status, first = self._measure(8)
            if status:
                return status
            status, supply = self._measure(16)
            if status:
                return status
            if (
                supply >= 16000
                or first > (83 * supply) // 100
                or first <= (53 * supply) // 100
            ):
                return 99
        # Both reset/status calls deliberately ignore native SDK failure.
        driver.ioctl(0x8022, word(0xFFFFFFFF))
        driver.ioctl(0x8022, word(0x1FE))
        self.context.native_sleep(driver._global(0x1011F728))
        status = driver.connect(
            self.address,
            0,
            driver._global(0x1011F75C),
            UtilityExSISPins(1, (3, 11, 12, 13)),
        )
        if status and not (reuse and status == 13):
            return status
        status = self._configure(override)
        if status:
            return status
        message = UtilityExSISMessage(0x800F, bytearray(0x1020), 0x1020)
        status = driver.read(0x800F, 1, message, driver._global(0x1011F72C))
        if status:
            return status
        return driver.initialize_logical()

    def send(self, request: bytes) -> int:
        if type(request) is not bytes or len(request) > 0x1014:
            raise ValueError("Bounded immutable SIS diagnostic payload required")
        if not self.attached:
            return 99
        if self.driver.phase < 0x1F:
            return 3
        state = bytearray(4)
        raw = self.driver._call(
            "PassThruIoctl_v0500", (self.driver.logical[0x8206], 0x8023, None, state)
        ).status
        if len(state) != 4:
            raise ValueError("Native SIS socket state DWORD must retain four bytes")
        if int.from_bytes(state, "little") != 2:
            status = 2 if raw == 9 else 99
            if status == 99:
                status = self.finalize()
                if status == 0:
                    status = self.initialize(self.address, override=True)
            if status:
                return status
        status = self.driver.ioctl(8)
        if status:
            return status
        backing = bytearray(len(request) + 12)
        backing[2:4] = b"\x80\x01"
        backing[10:12] = (self.address & 0xFFFF).to_bytes(2, "big")
        backing[12:] = request
        message = UtilityExSISMessage(
            0x8208, backing, len(backing), native_14=len(backing)
        )
        return self.driver.queue(message, tcp=True)

    def receive_bytes(self, count: int) -> tuple[int, bytes]:
        unsigned(count)
        if count > 0x1020:
            raise ValueError("SIS native stream read exceeds backing")
        if not self.attached:
            return 99, b""
        message = UtilityExSISMessage(0x8208, bytearray(0x1020), 0x1020)
        status = self.driver.read(0x8208, count, message, self.timeout_ms)
        self.last_receive_tick = self.context.ticks()
        if status:
            return status, b""
        if message.native_14 != count:
            return 3, b""
        return 0, bytes(message.data[:count])

    def finalize(self) -> int:
        status = self.driver.finalize()
        if not self.driver.logical and self.driver.physical is None:
            self.attached = False
        return status


@dataclass
class UtilityExSelectedCMNFields:
    """Live native139f0 structure; busy calls can overwrite it during136d0."""

    interval_ms: int
    request: bytes = b""
    request_length: int = 0
    finalize_on_exit: int = 0
    stop_on_error: int = 0
    skip_response_validation: int = 0

    def validate(self) -> None:
        for value in (
            self.interval_ms,
            self.finalize_on_exit,
            self.stop_on_error,
            self.skip_response_validation,
        ):
            unsigned(value)
        if (
            type(self.request) is not bytes
            or len(self.request) > 256
            or type(self.request_length) is not int
            or not 0 <= self.request_length <= min(255, len(self.request))
        ):
            raise ValueError("Bounded native CMN BYTE length/backing required")


class UtilityExSelectedCMNWorker:
    """Four NK scheduled CMN bodies over the concrete selected facade.

    The source engine owns its shared UtilityWorker/thread and cancel flag. This
    object executes actual selected exchanges, recovery and exit counter resets;
    it does not implement the separate SetTimer-based keepalive18c90 family.
    """

    def __init__(self, context: CommContext, communication: object):
        from scripts.utility_ex_comm import UtilityExComm

        sources = {
            SHA_12_NK: (0x100EBA04, 0x100E6270, 0xFA90, 0xFA80),
            SHA_18_NK: (0x101528B4, 0x1014AF28, 0x17320, 0x172F0),
            SHA_DS4_NK: (0x101B8B7C, 0x101B1F88, 0x32450, 0x32480),
            SHA_PLUS_NK: (0x101C80AC, 0x101BD088, 0x33360, 0x33390),
        }
        if context.module_sha256 not in sources:
            raise UtilityExSourceError("Selected CMN worker source is not reviewed")
        if (
            not isinstance(communication, UtilityExComm)
            or communication.context is not context
            or communication.selector != "selected"
        ):
            raise TypeError("Concrete same-context selected communication required")
        self.context, self.communication = context, communication
        (
            self.native_status,
            self.native_result,
            self.busy_setter,
            self.no_response_setter,
        ) = sources[context.module_sha256]
        self.status = 0
        self.error: BaseException | None = None
        self.iterations = 0

    def _wait(self, duration: int) -> None:
        start = self.context.ticks()
        for _ in range(65536):
            if self.context.is_cancelled():
                return
            passed = elapsed(self.context.ticks(), start)
            if passed >= duration:
                return
            self.context.native_sleep(min(100, duration - passed))
        raise TimeoutError("Selected CMN wait exceeds host iteration budget")

    def run(
        self,
        interval_ms: int | UtilityExSelectedCMNFields,
        request: bytes = b"",
        *,
        skip_response_validation: bool = False,
        stop_on_error: bool = False,
        finalize_on_exit: bool = False,
    ) -> int:
        fields = (
            interval_ms if isinstance(interval_ms, UtilityExSelectedCMNFields) else None
        )
        if type(request) is not bytes or len(request) > 255:
            raise ValueError("Native CMN request is bounded by its BYTE length")
        if any(
            type(value) is not bool
            for value in (skip_response_validation, stop_on_error, finalize_on_exit)
        ):
            raise TypeError("Native CMN controls must be bool")
        if fields is None:
            interval_value = unsigned(interval_ms)
            fields = UtilityExSelectedCMNFields(
                interval_value,
                request,
                len(request),
                int(finalize_on_exit),
                int(stop_on_error),
                int(skip_response_validation),
            )
        fields.validate()
        plain = fields.request_length == 0
        interval = fields.interval_ms
        stop_plain = fields.stop_on_error == 1
        # Native136d0 copies the initial payload once, then keeps reading the
        # live BYTE length/flags/interval from its shared structure.
        request = fields.request[: fields.request_length]
        if plain:
            request = b"\x21\x00"
        if len(request) < 2 and not fields.skip_response_validation:
            raise UtilityExSourceError(
                "Native CMN compares an undefined second request byte"
            )
        comm = self.communication
        self.status, self.error, self.iterations = 0, None, 0
        previous = self.context.state.get(f"native_global:{self.native_status:x}", 0)
        unsigned(previous)
        global_status = previous
        try:
            self._wait(interval)
            while not self.context.is_cancelled():
                self.iterations += 1
                if self.iterations > 65536:
                    raise TimeoutError(
                        "Selected CMN worker exceeds host iteration budget"
                    )
                start = self.context.ticks()
                fields.validate()
                length = 2 if plain else fields.request_length
                if length > len(request):
                    raise UtilityExSourceError(
                        "Live CMN length reaches uninitialized native stack payload"
                    )
                self.status, response = comm.exchange(request[:length])
                # 134f0 always validates.136d0 fieldC skips both validation and
                # error recovery, while still retaining the actual result.
                if plain or fields.skip_response_validation == 0:
                    if len(request) < 2:
                        raise UtilityExSourceError(
                            "Live CMN validation reaches undefined second request byte"
                        )
                    if self.status == 0 and (
                        len(response) < 2 or response[1] != request[1]
                    ):
                        self.status = 3
                    if self.status:
                        if stop_plain if plain else fields.stop_on_error == 1:
                            global_status = self.status
                            break
                        if self.context.is_cancelled():
                            break
                        self.status = comm.initialize(1)
                if not plain and self.context.is_cancelled():
                    break
                now = self.context.ticks()
                end = (start + (interval if plain else fields.interval_ms)) & 0xFFFFFFFF
                # Source uses this absolute DWORD comparison, including its
                # wraparound behavior, rather than elapsed(now,start)<interval.
                if now < end:
                    duration = interval if plain else fields.interval_ms
                    self._wait((start - now + duration) & 0xFFFFFFFF)
            status_key = f"native_global:{self.native_status:x}"
            current = self.context.state.get(status_key)
            # A cancelled worker has no new result to publish. Restore the entry
            # snapshot only when no other owner (for example the timer callback)
            # has published a newer shared status in the meantime.
            if global_status != previous or current is None or current == previous:
                self.context.state[status_key] = global_status
            comm.configure(f"native_rva:{self.busy_setter:x}", 100)
            comm.configure(f"native_rva:{self.no_response_setter:x}", 3)
            self.context.state[f"native_global:{self.native_result:x}"] = self.status
            if self.status != 0 and fields.finalize_on_exit:
                comm.finalize()
            return self.status
        except BaseException as error:
            self.error = error
            if fields.finalize_on_exit:
                try:
                    comm.finalize()
                except BaseException as cleanup_error:  # noqa: BLE001 - preserve primary
                    error.add_note(
                        "Selected CMN cleanup: " + type(cleanup_error).__name__
                    )
            raise


@dataclass
class UtilityExSISFields:
    """Independent TY18 SIS state: these are not normal fixed UDS offsets."""

    retry_count: int = 3  # 1060
    suppress_positive: int = 0  # 1064
    suppress_error: int = 0  # 1068
    receive_count: int = 150  # 1074
    receive_ms: int = 180000  # 1078
    receive_cancel: int = 0  # 107c
    ignore_receive_abort: int = 0  # 1080
    continue_pending: int = 0  # 1084
    no_response_seen: int = 0  # 1088
    no_response_limit: int = 3  # 108c
    busy_seen: int = 0  # 1090
    busy_limit: int = 255  # 1094
    busy_ms: int = 0  # 1098
    pending_count: int = 0  # 10a0
    native_error: int = 0  # 10a4
    first_receive_ms: int = 5000  # 10a8
    pending_receive_ms: int = 0x26DE  # 10ac
    current_session: int = 0  # 105c
    busy_interval_ms: int = 0  # 109c, alternate retry delay


SIS_FIELD_OFFSETS = {
    0x105C: "current_session",
    0x1060: "retry_count",
    0x1064: "suppress_positive",
    0x1068: "suppress_error",
    0x1074: "receive_count",
    0x1078: "receive_ms",
    0x107C: "receive_cancel",
    0x1080: "ignore_receive_abort",
    0x1084: "continue_pending",
    0x1088: "no_response_seen",
    0x108C: "no_response_limit",
    0x1090: "busy_seen",
    0x1094: "busy_limit",
    0x1098: "busy_ms",
    0x109C: "busy_interval_ms",
    0x10A0: "pending_count",
    0x10A4: "native_error",
    0x10A8: "first_receive_ms",
    0x10AC: "pending_receive_ms",
}


class UtilityExSISUDSScheduler:
    """TY18 1ff60/1b510/1aee0, including separate DoIP ACK retry state."""

    def __init__(
        self, context: SISContext, lower: UtilityExSISLower, fields: UtilityExSISFields
    ):
        if (
            not isinstance(lower, UtilityExSISLower)
            or lower.context is not context
            or not isinstance(fields, UtilityExSISFields)
        ):
            raise TypeError("Concrete SIS lower and independent native fields required")
        self.context, self.lower, self.fields = context, lower, fields
        self.calls = 0

    def _check(self) -> None:
        self.calls += 1
        if self.calls > 65536:
            raise TimeoutError("SIS exchange exceeds host primitive budget")

    def _ack(self) -> int:
        self.lower.timeout_ms = self.lower.driver._global(0x1011F73C)
        status, data = self.lower.receive_bytes(13)
        if status:
            return status
        if data[:4] == b"\x02\xfd\x80\x02":
            return 0
        return 12 if data[:4] == b"\x02\xfd\x80\x03" else 3

    def _packet(self) -> tuple[int, bytes]:
        self._check()
        status, header = self.lower.receive_bytes(8)
        if status:
            return status, b""
        if header[:4] != b"\x02\xfd\x80\x01":
            return 99, b""
        total = int.from_bytes(header[4:], "big")
        if total < 4:
            return 99, b""
        if total > 16 * 1024 * 1024:
            raise ValueError("SIS payload exceeds host allocation policy")
        data = bytearray()
        remaining = total
        # Source uses floor(total/1020)+1; exact multiples perform an extra
        # zero-byte read. It is not a conventional ceiling division.
        for index in range(total // 0x1020 + 1):
            self._check()
            count = min(remaining, 0x1020)
            status, chunk = self.lower.receive_bytes(count)
            if status:
                return 99, bytes(data)
            data += chunk[4:] if index == 0 else chunk
            remaining -= count
        return 0, bytes(data)

    def _receive(self) -> tuple[int, bytes]:
        f = self.fields
        start, count = self.context.ticks(), 0
        previous = b""
        self.lower.timeout_ms = f.first_receive_ms
        while True:
            status, response = self._packet()
            if status:
                return status, response or previous
            previous = response
            if len(response) != 3 or response[0] != 0x7F:
                return 0, response
            nrc = response[2]
            f.native_error = NATIVE_NRC.get(nrc, 999)
            if nrc == 0x12:
                return 22, response
            if nrc == 0x21:
                f.pending_count = 0
                return 27, response
            if nrc != 0x78:
                if f.native_error == 100 and f.suppress_error == 1:
                    f.native_error = 0x3E6
                return 7, response
            self.lower.timeout_ms = f.pending_receive_ms
            f.suppress_error, f.suppress_positive = 1, 0
            if f.receive_ms:
                exhausted = elapsed(self.context.ticks(), start) >= f.receive_ms
            else:
                count += 1
                f.pending_count = count
                exhausted = count >= f.receive_count
            if f.receive_cancel or (exhausted and not f.continue_pending):
                if f.ignore_receive_abort:
                    f.receive_cancel = 0
                    return 0, response
                status = 20 if f.receive_cancel else 5
                f.receive_cancel = 0
                return status, response

    def exchange(self, request: bytes) -> tuple[int, bytes]:
        if type(request) is not bytes or not 1 <= len(request) <= 0x1014:
            raise ValueError("Bounded nonempty SIS diagnostic request required")
        f = self.fields
        self.calls = 0
        start = self.context.ticks()
        f.busy_seen = f.no_response_seen = f.receive_cancel = 0
        f.suppress_positive = int(
            len(request) >= 2
            and request[0] in (0x10, 0x11, 0x19, 0x27, 0x2C, 0x31, 0x3E, 0x85)
            and bool(request[1] & 0x80)
        )
        ack_timeouts = ack_errors = receive_errors = 0
        try:
            while True:
                self._check()
                f.native_error = 0
                status = self.lower.send(request)
                if status:
                    return status, b""
                status = self._ack()
                if status == 2:
                    ack_timeouts += 1
                    if ack_timeouts >= f.no_response_limit:
                        return status, b""
                    continue
                if status:
                    ack_errors += 1
                    if ack_errors >= f.retry_count:
                        return status, b""
                    continue
                status, response = self._receive()
                if self.context.is_cancelled():
                    return status, response
                if status == 27:
                    if f.busy_ms:
                        exhausted = elapsed(self.context.ticks(), start) >= f.busy_ms
                    else:
                        f.busy_seen += 1
                        f.no_response_seen = 0
                        exhausted = f.busy_seen >= f.busy_limit
                    if exhausted:
                        return 28, response
                    continue
                if status == 2:
                    if f.suppress_positive == 1:
                        return 0, response
                    f.no_response_seen += 1
                    if f.no_response_seen >= f.no_response_limit:
                        return status, response
                    continue
                if status == 5:
                    return status, response
                if status == 7 and f.native_error == 0x3E6 and f.suppress_error == 1:
                    return 5, response
                if status == 0:
                    return (
                        0 if response and response[0] == request[0] + 0x40 else 3
                    ), response
                receive_errors += 1
                if receive_errors >= f.retry_count:
                    return status, response
        finally:
            f.suppress_error = 0


class UtilityExSISLifecycle:
    """TY18 native1011e618 SIS manager and its no-recovery20830 worker."""

    def __init__(
        self,
        context: SISContext,
        driver: UtilityExSISDriver,
        fields: UtilityExSISFields,
        native_address: int,
    ):
        addresses = {SHA_18_TY: 0x1011E618, SHA_PLUS_TY: 0x10134B78}
        if native_address != addresses.get(context.module_sha256):
            raise UtilityExSourceError("Exact source SIS manager identity required")
        if (
            not isinstance(driver, UtilityExSISDriver)
            or driver.context is not context
            or not isinstance(fields, UtilityExSISFields)
        ):
            raise TypeError("Concrete SIS driver and independent fields required")
        self.context, self.driver, self.fields, self.native_address = (
            context,
            driver,
            fields,
            native_address,
        )
        self.alternate_fields = alternate_uds_fields(context, native_address)
        self.lower: UtilityExSISLower | None = None
        self.scheduler: UtilityExSISUDSScheduler | None = None
        self._lock, self._stop = threading.RLock(), threading.Event()
        self._thread: threading.Thread | None = None
        self.worker_error: BaseException | None = None
        self.worker_active = self.worker_paused = False
        self.worker_status, self._worker_exit_status = 15, 0
        self.worker_interval_ms, self.worker_request = 2000, b""
        self.worker_response_length, self.worker_last_tick = 0, 0
        self.worker_rate_mode = 1
        self.native_10c8, self.native_10bc = 1, 1
        self.native_10c0, self.native_10c4 = 0, 0

    def _defaults(self) -> None:
        self.fields.receive_count, self.fields.receive_ms = 150, 180000
        self.fields.busy_limit = 255
        self.native_10c8, self.native_10bc, self.native_10c4 = 1, 1, 0
        a = self.alternate_fields
        a.pending_limit, a.busy_limit, a.pending_ms = 1, 1, 0

    def initialize(self, mode: int = 0) -> int:
        unsigned(mode)
        with self._lock:
            self.fields.suppress_error = 0
            self._defaults()
            self.fields.busy_ms = 0
            self.native_10c0 = 0
            self.alternate_fields.busy_ms = 0
            if (
                self.driver._global(0x1011F708) != 0x14
                or self.driver._global(0x1011F70C) != 0x14
            ):
                return 99
            self.fields.first_receive_ms = self.driver._global(0x1011F740)
            self.fields.pending_receive_ms = self.driver._global(0x1011F748)
            if self.lower is None:
                self.lower = UtilityExSISLower(self.context, self.driver)
                self.scheduler = UtilityExSISUDSScheduler(
                    self.context, self.lower, self.fields
                )
            status = self.lower.initialize(
                self.driver._global(0x1011F700), override=True, reuse=bool(mode)
            )
            if status == 0:
                self.fields.native_error = 0
                self.worker_error = None
                self.configure_keepalive(2000, b"\x3e\x00", 2, 0)
            return status

    def exchange(self, request: bytes) -> tuple[int, bytes]:
        with self._lock:
            if (
                self.worker_error is not None
                and threading.current_thread() is not self._thread
            ):
                raise self.worker_error
            if self.scheduler is None:
                return 99, b""
            self.worker_paused = True
            try:
                return self.scheduler.exchange(request)
            finally:
                self.worker_paused = False

    def configure_keepalive(
        self, interval_ms: int, request: bytes, response_size: int, flags: int
    ) -> None:
        unsigned(interval_ms)
        unsigned(response_size)
        unsigned(flags)
        if type(request) is not bytes or len(request) > 0x1020:
            raise ValueError("Bounded native SIS keepalive request required")
        # SIS1b5c0 takes four stack arguments (interval,request,len,replysize).
        # The ordinary manager's fifth recovery argument is not consumed here.
        with self._lock:
            self.worker_interval_ms, self.worker_request = interval_ms, request
            self.worker_response_length = response_size

    def worker_step(self) -> bool:
        if not self.worker_active or self._stop.is_set() or self.lower is None:
            return False
        if (
            self.worker_rate_mode == 1
            and elapsed(self.context.ticks(), self.worker_last_tick)
            <= self.worker_interval_ms
        ):
            return False
        if (
            elapsed(self.context.ticks(), self.lower.last_receive_tick)
            <= self.worker_interval_ms
        ):
            return False
        if not self._lock.acquire(blocking=False):
            return False
        try:
            if self.worker_paused or self._stop.is_set():
                return False
            self.worker_last_tick = self.context.ticks()
            status, response = UtilityExAlternateUDSScheduler(
                self.context, self.lower, self.fields, self.alternate_fields
            ).exchange(self.worker_request)
            if (
                status == 0
                and self.worker_response_length
                and len(response) != self.worker_response_length
            ):
                status = 3
            self._worker_exit_status = status
            return True
        finally:
            self._lock.release()

    def _run(self) -> None:
        try:
            while not self._stop.is_set():
                _paced_native_sleep(self.context, self._stop)
                self.worker_step()
        except BaseException as error:  # noqa: BLE001 - expose owned worker failure
            self.worker_error, self._worker_exit_status = error, 99
        finally:
            self.worker_status, self.worker_active = self._worker_exit_status, False

    def keepalive(self, enabled: bool, wait: bool = False) -> int:
        if type(enabled) is not bool or type(wait) is not bool:
            raise TypeError("Native SIS worker controls must be bool")
        if enabled:
            if self.worker_error is not None:
                raise self.worker_error
            if not self.worker_request:
                return 99
            if self.worker_active:
                return 0
            self._stop.clear()
            self.worker_active, self.worker_error = True, None
            self.worker_status, self._worker_exit_status = 15, 0
            self.worker_last_tick = self.context.ticks()
            self._thread = threading.Thread(
                target=self._run, name="utility-ex-sis-keepalive", daemon=True
            )
            try:
                self._thread.start()
            except BaseException:
                self.worker_active, self._thread = False, None
                raise
            return 0
        self._stop.set()
        if self._thread is not None and self._thread is not threading.current_thread():
            self._thread.join(timeout=2)
            if self._thread.is_alive():
                raise TimeoutError("SIS keepalive still owns its native lower")
            self._thread = None
        self.worker_active = False
        if wait:
            self.finalize()
        return 0

    def session(
        self,
        mode: int,
        keepalive: int = 1,
        *,
        normal_first: bool = False,
        stop_on_error: bool = False,
    ) -> int:
        if (
            type(mode) is not int
            or not 0 <= mode <= 255
            or type(keepalive) is not int
            or keepalive not in (0, 1)
        ):
            raise ValueError("Native SIS session byte/keepalive selector required")
        if normal_first and mode != 3:
            raise ValueError("Native extended helper selects session3")
        try:
            with self._lock:
                if self.scheduler is None:
                    return 99
                for selected in (1, 3) if normal_first else (mode,):
                    status, response = self.scheduler.exchange(bytes((0x10, selected)))
                    if status:
                        return status
                    if not selected & 0x80:
                        if len(response) < 2:
                            return 3
                        if response[1] != (selected & 0x7F):
                            return 7
                self.fields.current_session = mode & 0x7F
            if keepalive:
                self.keepalive((mode & 0x7F) != 1)
            return 0
        finally:
            if stop_on_error and keepalive:
                self.keepalive(False)

    def cleanup_session(
        self,
        mode: int,
        keepalive: int = 1,
        *,
        normal_first: bool = False,
        stop_on_error: bool = False,
    ) -> int:
        with self._lock:
            if self.lower is None:
                return self.session(
                    mode,
                    keepalive,
                    normal_first=normal_first,
                    stop_on_error=stop_on_error,
                )
            with utility_ex_cleanup_scope(self.lower):
                return self.session(
                    mode,
                    keepalive,
                    normal_first=normal_first,
                    stop_on_error=stop_on_error,
                )

    def cleanup_exchange(self, request: bytes) -> tuple[int, bytes]:
        with self._lock:
            if self.lower is None or self.scheduler is None:
                return 99, b""
            with utility_ex_cleanup_scope(self.lower):
                return self.scheduler.exchange(request)

    def finalize(self) -> int:
        self.keepalive(False)
        with self._lock:
            self._defaults()
            self.fields.current_session = 0
            # 1ae40 retains its lower pointer even after successful close.
            return 99 if self.lower is None else self.lower.finalize()


def stop_fixed_worker(
    context: CommContext, native_address: int, close: int = 0
) -> None:
    """Native TY18 1a580/1df40, including an untouched BSS manager.

    A common finalizer must not load a DRIVER or allocate a CAN pool merely to
    stop a worker that never started. Existing owners still perform real close.
    """
    from scripts.utility_ex_comm import _SIS_OBJECTS, _uds_fields

    unsigned(close)
    objects = (
        _FIXED_OBJECTS.get(context.module_sha256),
        *_ADDITIONAL_FIXED_OBJECTS.get(context.module_sha256, ()),
        *_SIS_OBJECTS.get(context.module_sha256, ()),
        _P6_MANAGER_OBJECTS.get(context.module_sha256),
    )
    if type(native_address) is not int or native_address not in objects:
        raise UtilityExSourceError("Fixed worker object identity is not reviewed")
    key = f"utility_ex:fixed_lifecycle:{context.module_sha256}:{native_address:x}"
    lifecycle = context.state.get(key)
    if lifecycle is not None:
        if (
            not isinstance(lifecycle, (UtilityExFixedLifecycle, UtilityExSISLifecycle))
            or lifecycle.context is not context
        ):
            raise TypeError("Concrete same-context fixed worker required")
        # Native self-stop only signals; it does not close from inside the worker.
        if threading.current_thread() is lifecycle._thread:
            lifecycle._stop.set()
            return
        lifecycle.keepalive(False, bool(close))
        return
    if not close:
        return
    if native_address in _SIS_OBJECTS.get(context.module_sha256, ()):
        fields_key = f"utility_ex:sis_fields:{context.module_sha256}:{native_address:x}"
        fields = context.state.setdefault(fields_key, UtilityExSISFields())
        if not isinstance(fields, UtilityExSISFields):
            raise TypeError("Concrete independent SIS fields required")
        fields.receive_count, fields.receive_ms, fields.busy_limit = 150, 180000, 255
    elif native_address == _P6_MANAGER_OBJECTS.get(context.module_sha256):
        fields_key = f"utility_ex:p6_fields:{context.module_sha256}:{native_address:x}"
        fields = context.state.setdefault(fields_key, UtilityExP6Fields())
        if not isinstance(fields, UtilityExP6Fields):
            raise TypeError("Separate concrete P6 fields required")
        fields.receive_count, fields.receive_ms, fields.busy_count = 150, 180000, 255
    else:
        fields = _uds_fields(context, native_address)
        fields.receive_count, fields.receive_ms, fields.busy_count = 150, 180000, 255
    alternate = alternate_uds_fields(context, native_address)
    alternate.pending_limit, alternate.busy_limit, alternate.pending_ms = 1, 1, 0
    fields.current_session = 0


class UtilityExSelectedP5Worker:
    """Eight selected P5 workers, distinct from CMN and timer workers."""

    def __init__(self, context: CommContext, communication: object):
        from scripts.utility_ex_comm import UtilityExComm

        if context.module_sha256 not in _MANAGER_OBJECTS:
            raise UtilityExSourceError("Selected P5 worker source is not reviewed")
        if (
            not isinstance(communication, UtilityExComm)
            or communication.context is not context
            or communication.selector != "selected"
        ):
            raise TypeError("Concrete same-context selected communication required")
        self.context, self.communication = context, communication
        self.interval_ms, self.request, self.response_size, self.recovery = (
            2000,
            b"",
            0,
            0xF0,
        )
        self.request_length = 0
        self.request_backing = bytearray(0x1020)
        self.active, self.running, self.status = False, False, 0
        self.error: BaseException | None = None
        self._last_result = 0
        self._lock, self._stop = threading.RLock(), threading.Event()
        self._thread: threading.Thread | None = None

    def configure(
        self, interval_ms: int, request: bytes, response_size: int, recovery: int
    ) -> None:
        for value in (interval_ms, response_size, recovery):
            unsigned(value)
        if type(request) is not bytes or len(request) > 0x1020:
            raise ValueError("Bounded immutable native P5 request required")
        # 11330 does not pause the worker around these individual stores.
        self.interval_ms = interval_ms
        self.request_length = len(request)
        self.request_backing[: len(request)] = request
        self.request = request
        self.response_size, self.recovery = response_size, recovery

    @contextmanager
    def pause(self):
        """1d520/1d560: selected P5 business calls borrow the worker mutex."""
        with self._lock:
            yield

    def worker_step(self) -> int:
        from scripts.utility_ex_comm import (
            UtilityExClassicScheduler,
            UtilityExSelectedPending,
        )

        lower = self.communication._selected_lower()
        if elapsed(self.context.ticks(), lower.last_receive_tick) <= self.interval_ms:
            return self._last_result
        if not self._lock.acquire(blocking=False):
            return self._last_result
        try:
            # 11740 uses the plain selected stack class; the public selected
            # facade uses its derived pending class and cannot substitute here.
            scheduler = UtilityExClassicScheduler(
                self.context, UtilityExSelectedPending(self.context, lower)
            )
            status, response = scheduler.exchange(
                bytes(self.request_backing[: self.request_length])
            )
            if (
                status == 0
                and self.response_size
                and len(response) != self.response_size
            ):
                status = 3
            if status and self.recovery != 0xF0:
                status = self.communication.initialize_at(self.recovery, 1)
            self._last_result = status
            return status
        finally:
            self._lock.release()

    def _run(self) -> None:
        self.status, self.running, self._last_result = 15, True, 0
        try:
            while not self._stop.is_set():
                _paced_native_sleep(self.context, self._stop)
                self.worker_step()
        except BaseException as error:  # noqa: BLE001 - expose worker failure to its owner
            self.error, self._last_result = error, 99
        finally:
            self.status, self.running = self._last_result, False

    def start(self) -> None:
        if threading.current_thread() is self._thread:
            return
        if self.error is not None:
            raise self.error
        self.active = True
        self.stop()
        self.active = True
        self.error = None
        self._stop.clear()
        thread = threading.Thread(
            target=self._run, name="utility-ex-selected-p5", daemon=True
        )
        self._thread = thread
        try:
            thread.start()
        except BaseException:
            # A failed Thread.start leaves no live worker. Do not retain an
            # active owner or an unstarted thread that a later stop cannot join.
            self._thread = None
            self.active = False
            self._stop.set()
            raise

    def stop(self, close: int = 0) -> None:
        unsigned(close)
        self._stop.set()
        if threading.current_thread() is self._thread:
            return
        if self._thread is not None:
            self._thread.join(timeout=2)
            if self._thread.is_alive():
                raise TimeoutError("Selected P5 worker still owns its native lower")
            self._thread = None
        self.active = False
        if close:
            self.communication.finalize()

    def get_status(self) -> int:
        if self.error is not None:
            raise self.error
        return self.status


class TimerContext(CommContext, Protocol):
    def set_timer(
        self,
        hwnd: int,
        identifier: int,
        interval_ms: int,
        callback: Callable[[int, int, int, int], None],
    ) -> int: ...
    def kill_timer(self, hwnd: int, identifier: int) -> int: ...


_TIMER_GLOBAL_NAMES = (
    "status",
    "timer_id",
    "interval",
    "active",
    "busy",
    "callback",
    "buffer",
    "length",
    "response",
    "recovery",
    "action",
)
_TIMER_GLOBALS = {
    SHA_12_NK: (
        0x100EBA04,
        0x100EBA0C,
        0x100EBA10,
        0x100EA9E0,
        0x100EBA08,
        0x100EA9D4,
        0x100EA9E4,
        0x100EA9DC,
        0x100EA9D8,
        0x100E50E8,
        0x100E50EC,
    ),
    SHA_18_NK: (
        0x101528B4,
        0x101528BC,
        0x101528C0,
        0x10151890,
        0x101528B8,
        0x10151884,
        0x10151894,
        0x1015188C,
        0x10151888,
        0x101490E8,
        0x101490EC,
    ),
    SHA_DS4_NK: (
        0x101B8B7C,
        0x101B9BA8,
        0x101B9BAC,
        0x101B8B70,
        0x101B8B74,
        0x101B8B78,
        0x101B8B80,
        0x101B9BA0,
        0x101B9BA4,
        0x101B00A4,
        0x101B00A8,
    ),
    SHA_PLUS_NK: (
        0x101C80AC,
        0x101C90D8,
        0x101C90DC,
        0x101C80A0,
        0x101C80A4,
        0x101C80A8,
        0x101C80B0,
        0x101C90D0,
        0x101C90D4,
        0x101BB0A4,
        0x101BB0A8,
    ),
    SHA_12_TY: (
        0x100B0F08,
        0x100B0F10,
        0x100B0F14,
        0x100AFEE4,
        0x100B0F0C,
        0x100AFED8,
        0x100AFEE8,
        0x100AFEE0,
        0x100AFEDC,
        0x1008B104,
        0x1008B108,
    ),
    SHA_18_TY: (
        0x101207C8,
        0x101207D0,
        0x101207D4,
        0x1011F7A4,
        0x101207CC,
        0x1011F798,
        0x1011F7A8,
        0x1011F7A0,
        0x1011F79C,
        0x100F81A4,
        0x100F81A8,
    ),
    SHA_DS4_TY: (
        0x1006F3B4,
        0x100703E0,
        0x100703E4,
        0x1006F3A8,
        0x1006F3AC,
        0x1006F3B0,
        0x1006F3B8,
        0x100703D8,
        0x100703DC,
        0x10028018,
        0x1002801C,
    ),
    SHA_PLUS_TY: (
        0x1013FAE4,
        0x10140B10,
        0x10140B14,
        0x1013FAD8,
        0x1013FADC,
        0x1013FAE0,
        0x1013FAE8,
        0x10140B08,
        0x10140B0C,
        0x100F4018,
        0x100F401C,
    ),
}


class UtilityExSelectedTimerKeepalive:
    """Eight source USER32 timer keepalive state machines and owned callbacks."""

    def __init__(self, context: TimerContext, communication: object):
        from scripts.utility_ex_comm import UtilityExComm

        if context.module_sha256 not in _TIMER_GLOBALS:
            raise UtilityExSourceError(
                "Selected timer keepalive source is not reviewed"
            )
        if (
            not isinstance(communication, UtilityExComm)
            or communication.context is not context
            or communication.selector != "selected"
        ):
            raise TypeError("Concrete same-context selected communication required")
        self.context, self.communication = context, communication
        self.layout: dict[str, int] = dict(
            zip(_TIMER_GLOBAL_NAMES, _TIMER_GLOBALS[context.module_sha256], strict=True)
        )
        self.interval_ms = 0
        self.request = b""
        self._request_backing, self.request_length = bytes(0x1020), 0
        self.response_size, self.recovery_byte, self.action_mode = 0, 0, 0
        self.timer_id, self.active, self.busy, self.in_callback = 0, 0, False, False
        self.last_exchange_status: int | None = None
        self.error: BaseException | None = None

    def _state(self, name: str, value: object) -> None:
        address = self.layout[name]
        self.context.state[f"native_global:{address:x}"] = value

    @property
    def native_status(self) -> int:
        return unsigned(
            self.context.state.get(f"native_global:{self.layout['status']:x}", 0)
        )

    @native_status.setter
    def native_status(self, value: int) -> None:
        self._state("status", unsigned(value))

    def configure(
        self,
        interval_ms: int,
        request: bytes,
        response_size: int,
        recovery: int,
        action_mode: int,
    ) -> None:
        for value in (interval_ms, response_size, recovery, action_mode):
            unsigned(value)
        if type(request) is not bytes or len(request) > 0x1020:
            raise ValueError("Bounded immutable native timer request required")
        self.interval_ms = interval_ms
        self._state("interval", interval_ms)
        self.request, self._request_backing = b"", bytes(0x1020)
        self.context.state[f"native_bytes:{self.layout['buffer']:x}"] = (
            self._request_backing
        )
        self.request, self._request_backing = request, request.ljust(0x1020, b"\x00")
        self.context.state[f"native_bytes:{self.layout['buffer']:x}"] = (
            self._request_backing
        )
        legacy = self.context.module_sha256 in (
            SHA_12_NK,
            SHA_18_NK,
            SHA_12_TY,
            SHA_18_TY,
        )
        if legacy:
            self.request_length = len(request)
            self._state("length", self.request_length)
        self.response_size = response_size
        self._state("response", response_size)
        self.action_mode = action_mode
        self._state("action", action_mode)
        if not legacy:
            self.request_length = len(request)
            self._state("length", self.request_length)
        self.recovery_byte = recovery & 0xFF
        self._state("recovery", self.recovery_byte)

    def start(self) -> None:
        self.native_status = 15
        self.stop(0)
        self.active = 1
        self._state("active", 1)
        self.timer_id = self.context.set_timer(
            0, self.timer_id, self.interval_ms, self.timer_callback
        )
        unsigned(self.timer_id)
        self._state("timer_id", self.timer_id)

    def stop(self, close: int = 0) -> None:
        unsigned(close)
        started = self.context.ticks()
        for _ in range(65536):
            if not self.busy:
                break
            if elapsed(self.context.ticks(), started) >= 2000:
                raise TimeoutError("Native timer callback still owns its lower")
            self.context.native_sleep(100)
        else:
            raise TimeoutError("Native timer callback remains busy")
        self.context.kill_timer(0, self.timer_id)
        if close:
            self.communication.finalize()

    def timer_callback(self, hwnd: int, message: int, timer_id: int, tick: int) -> None:
        for value in (hwnd, message, timer_id, tick):
            unsigned(value)
        self.in_callback = True
        self._state("callback", 1)
        try:
            if self.active != 1:
                return
            self.busy = True
            self._state("busy", 1)
            status, response = self.communication.exchange(
                self._request_backing[: self.request_length]
            )
            if (
                status == 0
                and self.response_size
                and len(response) != self.response_size
            ):
                status = 3
            self.last_exchange_status = status
            if self.action_mode == 1 and status:
                if self.recovery_byte != 0xF0:
                    self.communication.initialize_at(self.recovery_byte, 1)
                else:
                    self.context.kill_timer(0, timer_id)
                    self.native_status = status
                    self.communication.finalize()
        except BaseException as error:
            self.error = error
            raise
        finally:
            # Host exception protection releases the callback ownership flags as
            # well; native normal completion clears them at18ea4/18ebf.
            self.busy, self.in_callback = False, False
            self._state("busy", 0)
            self._state("callback", 0)
