"""CUW2026 callback3 query and captured InformResultOfQueryRetry chronology.

Native user input is a signed int and byte, never a stage-success Boolean.
The engine issues this controller for its existing concrete worker/runtime.
"""

from __future__ import annotations

import re
import threading
import time
import weakref
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scripts.cuw_2026 import CUWEngine2026
    from scripts.cuw_engine_worker import EngineWorker2026

_TOKEN = object()
_ISSUED: weakref.WeakKeyDictionary = weakref.WeakKeyDictionary()
_ISSUE_LOCK = threading.Lock()


@dataclass(frozen=True)
class RetryQuery2026:
    sequence: int
    error_kind: int
    primary_error: int
    passthru_error: int
    recovery_status: int
    file_index: int
    cpu_index: int


@dataclass(frozen=True)
class RetryInput2026:
    sequence: int
    native_result: int
    native_option: int

    def __post_init__(self):
        if type(self.sequence) is not int or self.sequence < 1:
            raise ValueError("Positive captured query sequence required")
        if (
            type(self.native_result) is not int
            or not -(2**31) <= self.native_result < 2**31
        ):
            raise ValueError("Captured native signed int required")
        if type(self.native_option) is not int or not 0 <= self.native_option <= 255:
            raise ValueError("Captured native byte required")


@dataclass(frozen=True)
class RetryNotification2026:
    """Copied a44 primitive UI output; it cannot certify a phase result."""

    kind: int
    color1: int
    color2: int
    blink_cycle: int
    message1: bytes
    message2: bytes


def _notification_configuration(encoded: bytes) -> tuple[RetryNotification2026, ...]:
    from scripts.cuw_persistence import _INIParser, decode_nibble_text

    if type(encoded) is not bytes or not 0 < len(encoded) <= 1024 * 1024:
        raise ValueError("Bounded captured encoded RCN.ini bytes required")
    raw = decode_nibble_text(encoded)
    if b"\0" in raw:
        raise ValueError("Embedded RCN.ini terminator")
    parser = _INIParser(interpolation=None, delimiters=("=",), strict=True)
    protected = {
        value: 0xE000 + value for value in (*range(0x1C, 0x20), *range(128, 256))
    }
    restored = {target: source for source, target in protected.items()}
    parser.read_string(raw.decode("latin1").translate(protected))
    if parser.defaults():
        raise ValueError("Inherited RCN.ini defaults are not native source values")

    def integer(section, name):
        match = re.match(r"[ \t\r\n\v\f]*([+-]?[0-9]+)", section[name])
        if match is None:
            raise ValueError("Native RCN.ini stol value has no digits")
        value = int(match[1])
        if not -(2**31) <= value < 2**31:
            raise ValueError("Native RCN.ini stol value exceeds signed long")
        return value

    records = []
    for kind, name in enumerate(("Success", "Error")):
        section = parser[name]
        colors = tuple(
            (integer(section, "Blue" + suffix) & 255) << 16
            | (integer(section, "Green" + suffix) & 255) << 8
            | integer(section, "Red" + suffix) & 255
            for suffix in ("1", "2")
        )
        records.append(
            RetryNotification2026(
                kind,
                colors[0],
                colors[1],
                integer(section, "BlinkCycle") & 0xFFFFFFFF,
                section["Message1"].translate(restored).encode("latin1"),
                section["Message2"].translate(restored).encode("latin1"),
            )
        )
    return tuple(records)


@dataclass(frozen=True)
class RetryState2026:
    """Readonly source fields; no caller can set native retry flags."""

    result14: int
    decision399: bool
    query_pending39a: bool
    native_option_eb48: int
    battery_query5a8: bool
    battery_above_threshold598: bool
    battery_voltage5a0: float
    log_flag398: bool
    resume_milliseconds_d314: int
    error_counts38c: tuple[int, ...]


def _issue_retry_controller(engine, worker):
    from scripts.cuw_2026 import CUWEngine2026
    from scripts.cuw_engine_worker import EngineWorker2026

    if type(engine) is not CUWEngine2026 or type(worker) is not EngineWorker2026:
        raise TypeError("Actual CUW2026 engine and issued worker required")
    if worker.engine is not engine or engine.worker is not worker:
        raise ValueError("Retry worker differs from actual engine owner")
    with _ISSUE_LOCK:
        previous = _ISSUED.get(engine)
        if previous is not None:
            controller = previous()
            if controller is not None:
                if controller.worker is not worker:
                    raise ValueError("Retry controller belongs to another worker")
                return controller
        controller = RetryController2026(engine, worker, _token=_TOKEN)
        _ISSUED[engine] = weakref.ref(controller)
        return controller


def check_j2534_connection_2026(engine: CUWEngine2026) -> int:
    """5d830 also runs before59070; CFE4/selected driver are its source guards."""
    from scripts.calibration_2026 import (
        native2026_node_count,
        native2026_node_values,
    )
    from scripts.cuw_2026 import CUWEngine2026, connect_j2534
    from scripts.cuw_engine_worker import NativeWorkerIntegerError2026, _loaded_metadata
    from scripts.j2534_2026 import NativePassThruError2026
    from scripts.programming_2026_common import (
        NativePassThruException2026,
        is_native_exception2026,
    )

    if type(engine) is not CUWEngine2026:
        raise TypeError("Actual CUW2026 engine required for native connection check")
    if engine._metadata is None or engine.interface_pair is None:
        return 0xFA3
    device = engine.engine_runtime_device()
    if device.driver is None:
        return 0xFA3
    device._check()
    worker = engine._worker
    metadata = engine.native_metadata
    if engine.file_sources is not None:
        from scripts.cuw_file_services import validate_file_sources_2026

        validate_file_sources_2026(engine.file_sources, engine)
        sources = engine.file_sources.files
    else:
        sources = _loaded_metadata(engine)

    def check_version() -> bool:
        if worker is not None:
            return worker.check_device_version()
        try:
            device.read_device_version()
            device.control_io(1, ((1, 0),))
        except Exception as error:
            if not is_native_exception2026(error):
                raise
            # 33e50→41e60 has no worker to acknowledge before59070.
            return False
        return True

    def read_voltage() -> float:
        if worker is not None:
            return worker.read_battery_voltage()
        if not check_version():
            raise NativeWorkerIntegerError2026(0)
        try:
            value = device.control_io(3)
        except Exception as cause:
            if not is_native_exception2026(cause):
                raise
            raise NativeWorkerIntegerError2026(1) from cause
        if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
            raise ValueError("READ_VBATT must return a native DWORD")
        return value / 1000.0

    try:
        can_fd = any(
            source.vehicle.get("contacttype", "") == "Phase6"
            and any(
                native2026_node_values(source, node).get("protocol", "") == "02"
                for node in range(native2026_node_count(source))
            )
            for source in sources
        )
        if can_fd and not device.supports_can_fd():
            raise NativePassThruError2026(0x402)
        version_ok = False
        if device.connecting:
            try:
                low_battery = read_voltage() <= 1.0
            except Exception as error:
                if not is_native_exception2026(error):
                    raise
                low_battery = False  # 48fea native catch-all resumes false.
            if low_battery:
                raise NativePassThruError2026(0x3F0)
            version_ok = check_version()
        if not device.connecting or not version_ok:
            try:
                device.disconnect()
            except Exception as error:
                if not is_native_exception2026(error):
                    raise
            contact = metadata.vehicle.get("contacttype", "")
            # 33b40 first runs49b50: Ethernet uses0500; modern CAN uses0404.
            if (contact == "Ethernet" and device.version != 1) or (
                contact in ("P5-Unified", "Phase6") and device.version != 0
            ):
                device.switch_version()
            connect_j2534(device, contact, metadata.protocol_at_node)
            device.disconnect()
        return (
            0xFA5 if engine.native_recovery_status() == 3 and device.connecting else 0
        )
    except NativeWorkerIntegerError2026:
        return 0xFA5 + int(device.is_wireless_connecting(0))
    except (NativePassThruError2026, NativePassThruException2026) as error:
        return {2: 0xFA4, 0x3F0: 0xFAC, 0x402: 0xFAD}.get(
            error.native_error_code, 0xFA5
        )


class RetryController2026:
    """3ffa0/40070 and 5e950 share one real wait/resume event."""

    def __init__(self, engine: CUWEngine2026, worker: EngineWorker2026, *, _token=None):
        if _token is not _TOKEN:
            raise TypeError("Retry controller must be issued by its native engine")
        self.engine, self.worker = engine, worker
        self._lock = threading.RLock()
        self._resume = threading.Event()
        self._changed = threading.Event()
        self._stopped = threading.Event()
        self._checkpoint_byte = 0
        self._pending = False
        self._sequence = 0
        self._option = 0
        self._result = 0
        self._battery_query = False
        self._battery_above_threshold = False
        self._battery_voltage = 0.0
        if (
            type(engine._native_prepare_d314_2026) is not int
            or not 0 <= engine._native_prepare_d314_2026 < 86400000
        ):
            raise ValueError("Actual native D314 clock state required")
        self._queries: list[RetryQuery2026] = []
        self._inputs: list[RetryInput2026] = []
        configuration = engine.configuration
        assert configuration is not None
        shared = engine.bind_cleanup_controller().state
        self._error_counts: list[int] = shared.vectors.setdefault(
            0xD33C, [0] * configuration.cpu_maximum
        )
        self._history = shared.history
        self._notification_records = tuple(
            RetryNotification2026(kind, 0, 0, 0, b"", b"") for kind in (0, 1)
        )
        self._notifications: list[RetryNotification2026] = []
        self._closed = False
        self._host_deadline = time.monotonic() + worker.runtime.check()
        self._periodic_identifier = 0
        self._periodic_mode = 0

    @property
    def query_pending(self) -> bool:
        with self._lock:
            return self._pending

    @property
    def decision(self) -> bool:
        return self.engine.write_complete_output

    @property
    def native_option(self) -> int:
        with self._lock:
            return self._option

    @property
    def result(self) -> int:
        return self._result

    @property
    def queries(self) -> tuple[RetryQuery2026, ...]:
        with self._lock:
            return tuple(self._queries)

    @property
    def inputs(self) -> tuple[RetryInput2026, ...]:
        with self._lock:
            return tuple(self._inputs)

    @property
    def source_state(self) -> RetryState2026:
        with self._lock:
            return RetryState2026(
                self._result,
                self.engine.write_complete_output,
                self._pending,
                self._option,
                self._battery_query,
                self._battery_above_threshold,
                self._battery_voltage,
                self.engine.native_cycle_output,
                self.engine._native_prepare_d314_2026,
                tuple(self._error_counts),
            )

    @property
    def notifications(self) -> tuple[RetryNotification2026, ...]:
        with self._lock:
            return tuple(self._notifications)

    def load_notification_configuration(self, encoded_rcn: bytes) -> None:
        """483e0/4f4d0 receives actual captured RCN.ini bytes, never fallback text."""
        self.engine._require_owned_phase()
        records = _notification_configuration(encoded_rcn)
        with self._lock:
            self._notification_records = records

    def record_callback30(self, value: int) -> None:
        """588d0 retains the actual callback30 raw byte in worker+c24."""
        if type(value) is not int or not 0 <= value <= 255:
            raise ValueError("Actual callback30 native byte required")
        self.engine._require_owned_phase()
        with self._lock:
            self._checkpoint_byte = value
            self._changed.set()

    def _record_postwait_file_reset(self, worker) -> None:
        """3ffa0 sets398 only after the concrete4b900 file reset completed."""
        if worker is not self.worker or worker.engine is not self.engine:
            raise ValueError("Actual source-issued retry worker required")
        self.engine._require_owned_phase()
        with self._lock:
            self.engine._publish_retry_cycle(self)

    def _reset_error_counts(self, worker) -> None:
        """3ec30/3f813 zero the complete native38c vector at the file boundary."""
        if worker is not self.worker or worker.engine is not self.engine:
            raise ValueError("Actual source-issued retry worker required")
        self.engine._require_owned_phase()
        with self._lock:
            self._error_counts[:] = [0] * len(self._error_counts)

    def _initialize_prepare_state(self, worker, milliseconds: int) -> None:
        """36800 prefix clears its query fields using the actual worker clock read."""
        if worker is not self.worker or worker.engine is not self.engine:
            raise ValueError("Actual issued retry worker required")
        self.engine._require_native_prepare_prefix(worker)
        if type(milliseconds) is not int or not 0 <= milliseconds < 86400000:
            raise ValueError("Native local milliseconds within day required")
        if self.engine._native_prepare_d314_2026 != milliseconds:
            raise ValueError("Prepare clock must already be published at D314")
        with self._lock:
            self._battery_above_threshold = False
            self._battery_voltage = 0.0
            self._battery_query = False
            self._checkpoint_byte = 0

    def worker_started(self) -> None:
        remaining = self.worker.runtime.check()
        with self._lock:
            self._host_deadline = time.monotonic() + remaining
            self._stopped.clear()

    def worker_stopped(self) -> None:
        with self._lock:
            self._stopped.set()
            self._changed.set()

    def _check(self) -> float:
        if self._closed:
            raise ValueError("Native retry controller is closed")
        remaining = self.worker.runtime.check()
        remaining = min(remaining, self._host_deadline - time.monotonic())
        if remaining <= 0:
            raise TimeoutError("CUW2026 host query wait deadline expired")
        return remaining

    def _wait(self, event: threading.Event) -> None:
        while True:
            remaining = self._check()
            if event.wait(min(0.05, remaining)):
                self._check()
                return

    def wait_for_query(self, after_sequence: int = 0) -> RetryQuery2026:
        """Host input pump observes a published query; it does not create one."""
        if type(after_sequence) is not int or after_sequence < 0:
            raise ValueError("Nonnegative observed query sequence required")
        while True:
            remaining = self._check()
            with self._lock:
                self._changed.clear()
                if self._pending and self._sequence > after_sequence:
                    return self._queries[-1]
                job = self.engine.thread_job
                if self._stopped.is_set() and (
                    job is None or not job.native_work_pending
                ):
                    raise RuntimeError(
                        "Native worker stopped before another retry query"
                    )
            # A failed native thread start can release its real reservation
            # without entering the child scope or publishing another query.
            self._changed.wait(min(0.05, remaining))

    def accept_gateway_startup(self, producer) -> None:
        """Join actual1ad30 BE48 and acquired1bc90/1be60 BE34, even on faults."""
        from scripts.cuw_gateway_startup import GatewayStartup2026

        if type(producer) is not GatewayStartup2026:
            raise TypeError("Actual source-issued gateway startup required")
        producer.validate_owner(self.engine, self.worker)
        self.engine._require_owned_phase()
        observed = producer.source_state
        with self._lock:
            self._periodic_mode = observed.classification
            if observed.periodic_identifier is not None:
                self._periodic_identifier = observed.periodic_identifier

    def callback3(self) -> None:
        """Source3ffa0: modal/recovery bypass, optional battery, then real query."""
        self.engine._require_owned_phase()
        self._check()
        if self.engine.online_modal_state in (1, 4, 5, 6, 7, 8, 10):
            self._result = 1
            self.engine._publish_retry_decision(self, False)
            return
        status = self.engine.native_recovery_status()
        if status == 2:
            from scripts.programming_2026_common import is_native_exception2026

            try:
                voltage = self.worker.read_battery_voltage()
            except Exception as error:
                if not is_native_exception2026(error):
                    raise
                # 4005e/40064 resumes at40070 after native battery faults.
            else:
                self._battery_voltage = voltage
                configuration = self.engine.configuration
                assert configuration is not None
                if voltage > configuration.scalar_b:
                    self._battery_above_threshold = True
            self._battery_query = True
        if self.worker.control_state.recovery_mode:
            self.worker.leave_recovery_mode()
            self.engine._publish_retry_decision(self, True)
            if (
                self.engine.native_metadata.vehicle.get("kindofecu", "").lstrip("0")
                == "9"
            ):
                self.engine.dh_state.mark_native_retry()
            return
        self._query()

    def _query(self) -> None:
        # 3a120 stops the existing sync periodic message through the real device.
        if self._periodic_mode == 1:
            from scripts.programming_2026_common import is_native_exception2026

            try:
                self.engine.engine_runtime_device().stop_periodic(
                    self._periodic_identifier
                )
            except Exception as error:
                if not is_native_exception2026(error):
                    raise
                # 3a182 resumes3a170 after the native StopPeriodicMsg fault.
            else:
                runtime = self.worker.runtime
                if runtime.owns_resource(
                    "stop_periodic", identifier=self._periodic_identifier
                ):
                    runtime.forget_invalidated_resource(
                        "stop_periodic", identifier=self._periodic_identifier
                    )
        status = self.engine.native_recovery_status()
        kind = self.engine.native_error_kind_output
        primary, passthru = self.engine.native_error_output
        source = self.worker.source_state
        with self._lock:
            if self._pending:
                raise ValueError("A native retry query is already pending")
            self._result = status
            if kind not in (3, 1, 5) and primary != 7:
                index = source.current_global_cpu_index
                if not 0 <= index < len(self._error_counts):
                    raise ValueError(
                        "Native error counter CPU exceeds configured capacity"
                    )
                self._error_counts[index] = (self._error_counts[index] + 1) & 0xFFFFFFFF
            if kind in (1, 2, 4, 5):
                self._notifications.append(self._notification_records[1])
                if kind not in (4, 5):
                    self.engine._publish_retry_cycle(self)
            self._sequence += 1
            self._queries.append(
                RetryQuery2026(
                    self._sequence,
                    kind,
                    primary,
                    passthru,
                    status,
                    source.current_file_index,
                    source.current_global_cpu_index,
                )
            )
            self._resume.clear()
            self._stopped.clear()
            self.engine._retain_native_error_kind(worker=self.worker)
            self._pending = True
            self._changed.set()
        try:
            self._wait(self._resume)
            self._resume.clear()
            # 3ffa0 clears39a before either concrete postwait recovery branch.
            with self._lock:
                self._pending = False
            self.worker._retry_query_resume(self)
        finally:
            with self._lock:
                self._pending = False
                self._changed.set()

    def inform_result(self, native_result: int, native_option: int) -> int:
        """5e950 accepts only actual captured native int/byte arguments."""
        with self._lock:
            captured = RetryInput2026(self._sequence or 1, native_result, native_option)
            if not self._pending:
                return 0xBBD
            self._check()
            self.engine._accept_retry_decision(self, native_result, native_option)
            self.worker._clear_retry_cpu_percentages(self)
            self._option = native_option
            self._battery_above_threshold = False
            self._battery_query = False
            self._battery_voltage = 0.0
            self._history[:] = bytes(0x1028)
            self._inputs.append(captured)
            self._pending = False
            self._resume.set()
            self._changed.set()
        self._wait_worker_resume()
        if native_result != 1:
            self._cleanup_40580()
        if not self.query_pending:
            return 0
        status = self.engine.native_recovery_status()
        if status == 3:
            if self.engine.native_error_output[0] == 0x3F0:
                return 0xFAC
            return self.check_j2534_connection() or 0xFA5
        return 0 if status == 2 else 9999

    def check_j2534_connection(self) -> int:
        """Check the actual engine interface on this retry runtime's deadline."""
        self._check()
        return check_j2534_connection_2026(self.engine)

    def _wait_worker_resume(self) -> None:
        """3c720 returns at next query, worker resume checkpoint, or worker exit."""
        while True:
            with self._lock:
                if self._pending or self._stopped.is_set():
                    return
                if self._checkpoint_byte:
                    self.engine._native_prepare_d314_2026 = (
                        self.worker.runtime.read_local_milliseconds_of_day()
                    )
                    self._checkpoint_byte = 0
                    return
                self._changed.clear()
            self._wait(self._changed)

    def _cleanup_40580(self) -> None:
        self.engine.bind_cleanup_controller().run(self)

    def _cleanup_signal_wait(self, cleanup) -> None:
        """405c3 clears399 and signalsbe50 only while39a is still set."""
        from scripts.cuw_engine_cleanup import EngineCleanup2026

        if type(cleanup) is not EngineCleanup2026:
            raise TypeError("Actual engine cleanup controller required")
        cleanup.validate_owner(self.engine, self.worker)
        with self._lock:
            if self._pending:
                self.engine._apply_cleanup_retry_decision(cleanup)
                self._resume.set()
                self._changed.set()

    def _cleanup_prefix_reset(self, cleanup) -> None:
        """40580 clearsCFC4/D314/D34A before native False notifications."""
        from scripts.cuw_engine_cleanup import EngineCleanup2026

        if type(cleanup) is not EngineCleanup2026:
            raise TypeError("Actual engine cleanup controller required")
        cleanup.validate_owner(self.engine, self.worker)
        with self._lock:
            self._pending = False
            self._result = self.engine._native_prepare_d314_2026 = 0
            self._changed.set()

    def _cleanup_reset(self, cleanup) -> None:
        """40580 resets native query globals after resources have been released."""
        from scripts.cuw_engine_cleanup import EngineCleanup2026

        if type(cleanup) is not EngineCleanup2026:
            raise TypeError("Actual engine cleanup controller required")
        cleanup.validate_owner(self.engine, self.worker)
        with self._lock:
            self._pending = self._battery_query = False
            self._battery_above_threshold = False
            self._battery_voltage = 0.0
            self._result = self.engine._native_prepare_d314_2026 = (
                self._checkpoint_byte
            ) = 0
            self._periodic_mode = self._periodic_identifier = 0
            self._error_counts[:] = [0] * len(self._error_counts)
            self._changed.set()

    def rebind_worker(self, old, new) -> None:
        """59070 replaces the stopped worker while CUW retry globals survive."""
        from scripts.cuw_engine_worker import EngineWorker2026

        if type(old) is not EngineWorker2026 or type(new) is not EngineWorker2026:
            raise TypeError("Actual previous and replacement engine workers required")
        with _ISSUE_LOCK, self._lock:
            reference = _ISSUED.get(self.engine)
            if (
                self._closed
                or reference is None
                or reference() is not self
                or self.worker is not old
                or old.engine is not self.engine
                or new.engine is not self.engine
                or new is not self.engine._worker
                or old.controller is not new.controller
                or getattr(new.controller, "worker", None) is not new
                or not old._closed
                or new._closed
                or self.engine.active
                or self._pending
            ):
                raise ValueError("Actual stopped-worker retry lease required")
            new.validate_source(self.engine)
            self.worker = new
            # 59070 initializes the new worker's c24 word; CUW globals survive.
            self._checkpoint_byte = 0

    def close(self) -> None:
        if self.query_pending:
            raise ValueError("Finish the native retry query before closing")
        self._closed = True
        self.worker_stopped()
        with _ISSUE_LOCK:
            lease = _ISSUED.get(self.engine)
            if lease is not None and lease() is self:
                del _ISSUED[self.engine]
