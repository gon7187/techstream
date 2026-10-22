"""Concrete CUW2026 outer/child threads and source-owned event lifetime.

The outer thread corresponds to the engine's 3d100/3cb90 loop; each child runs
5ccd0's concrete controller entry. No callable supplied by a host can replace
programming work or publish its result.
"""

from __future__ import annotations

import math
import threading
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scripts.cuw_2026 import CUWEngine2026
    from scripts.cuw_engine_worker import WorkerContinuation2026
    from scripts.programming_2026_common import ControlCommPhase2026
    from scripts.programming_replay import ProgrammingReplay

_TOKEN = object()
_ISSUED: dict[int, ThreadPhaseLease2026] = {}
_LOCK = threading.RLock()


class ThreadPhaseLease2026:
    """One engine lock reservation transferred to the actual child thread."""

    def __init__(self, engine, controller, phase, *, _token=None):
        if _token is not _TOKEN:
            raise TypeError("Engine-issued native thread phase lease required")
        self._engine = engine
        self._controller = controller
        self._phase = phase
        self._state = "reserved"
        self._thread: int | None = None

    @property
    def engine(self):
        return self._engine

    @property
    def controller(self):
        return self._controller

    @property
    def phase(self) -> int:
        return self._phase

    @property
    def state(self) -> str:
        with _LOCK:
            return self._state

    def _adopt(self) -> None:
        with _LOCK:
            validate_thread_phase_lease(self, self.engine)
            if self._state != "reserved":
                raise ValueError("Native phase lease was already adopted")
            self._thread = threading.get_ident()
            self._state = "adopted"

    def _release(self) -> None:
        with _LOCK:
            validate_thread_phase_lease(self, self.engine)
            if self._state == "adopted" and self._thread != threading.get_ident():
                raise ValueError(
                    "Only the adopting native thread may release its lease"
                )
            self._state = "released"
            del _ISSUED[id(self)]


def _issue_thread_phase_lease(engine, controller, phase) -> ThreadPhaseLease2026:
    from scripts.cuw_2026 import CUWEngine2026
    from scripts.programming_2026_common import ControlCommPhase2026

    if (
        type(engine) is not CUWEngine2026
        or type(controller) is not ControlCommPhase2026
    ):
        raise TypeError("Concrete engine and controller required")
    if type(phase) is not int or phase not in (0, 1, 2):
        raise ValueError("Native outer worker phase must be0..2")
    if engine.worker.controller is not controller:
        raise ValueError("Native phase controller belongs to another engine worker")
    lease = ThreadPhaseLease2026(engine, controller, phase, _token=_TOKEN)
    with _LOCK:
        _ISSUED[id(lease)] = lease
    return lease


def validate_thread_phase_lease(lease, engine, *, controller=None, phase=None) -> None:
    with _LOCK:
        if (
            type(lease) is not ThreadPhaseLease2026
            or _ISSUED.get(id(lease)) is not lease
            or lease.engine is not engine
            or (controller is not None and lease.controller is not controller)
            or (phase is not None and lease.phase != phase)
        ):
            raise ValueError("Actual issued engine thread phase lease required")


@dataclass(frozen=True)
class ThreadState2026:
    """Readonly native CFD4/CFE0 observations, never scheduling inputs."""

    outer_started: bool
    child_started: bool
    child_alive: bool
    stop_requested: bool
    waiting_for_resume: bool
    prepare_acknowledgement_pending: bool
    sequence: int
    child_exit_code: int | None
    outer_exit_code: int | None


def _timeout_deadline(timeout: float) -> float:
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise TypeError("Finite positive host timeout required")
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("Finite positive host timeout required")
    return time.monotonic() + timeout


class EngineThreadJob2026:
    """Issued native worker with real child work, be54 resume and bounded joins."""

    def __init__(self, engine, controller, *, _token=None):
        if _token is not _TOKEN:
            raise TypeError("Engine-issued native thread job required")
        self.engine: CUWEngine2026 = engine
        self.controller: ControlCommPhase2026 = controller
        self.worker = engine.worker
        self._lock = threading.RLock()
        self._resume = threading.Event()
        self._completed = threading.Event()
        self._child_resume = threading.Event()
        self._child_done = threading.Event()
        self._child_parked = threading.Event()
        self._prepare_pending = threading.Event()
        self._activity = threading.Event()
        self._callback_requested = threading.Event()
        self._callback_returned = threading.Event()
        self._callback_error: BaseException | None = None
        self._callback_kind: str | None = None
        self._callback_argument: int | None = None
        self._callback_context = None
        self._outer: threading.Thread | None = None
        self._child: threading.Thread | None = None
        self._lease: ThreadPhaseLease2026 | None = None
        self._session: ProgrammingReplay | None = None
        self._stop = False
        self._host_stop = False
        self._waiting = False
        self._sequence = 0
        self._result: dict | None = None
        self._error: BaseException | None = None
        self._continuation: WorkerContinuation2026 | None = None
        self._child_exit: int | None = None
        self._outer_exit: int | None = None
        self._controller_entry: str | None = None

    def validate_owner(self, engine, controller=None) -> None:
        if (
            self.engine is not engine
            or engine.thread_job is not self
            or engine.worker is not self.worker
        ):
            raise ValueError("Native thread job belongs to another engine worker")
        if self.worker.controller is not self.controller or (
            controller is not None and controller is not self.controller
        ):
            raise ValueError("Native thread job controller identity changed")

    @property
    def state(self) -> ThreadState2026:
        with self._lock:
            return ThreadState2026(
                self._outer is not None,
                self._child is not None,
                self._child is not None and self._child.is_alive(),
                self._stop,
                self._waiting,
                self._prepare_pending.is_set(),
                self._sequence,
                (
                    0x103
                    if self._child is not None and self._child.is_alive()
                    else self._child_exit
                ),
                (
                    0x103
                    if self._outer is not None and self._outer.is_alive()
                    else self._outer_exit
                ),
            )

    @property
    def continuation(self) -> WorkerContinuation2026 | None:
        with self._lock:
            if not self._completed.is_set():
                raise ValueError("Native child has not unwound")
            return self._continuation

    def start(
        self, session: ProgrammingReplay, *, phase: int | None = None
    ) -> int | None:
        from scripts.programming_replay import ProgrammingReplay

        if type(session) is not ProgrammingReplay:
            raise TypeError("Concrete programming replay required")
        phases = {"get_cid": 0, "prepare": 1, "write": 2, "recovery": 2}
        expected = phases.get(session.operation)
        if expected is None or (
            phase is not None and (type(phase) is not int or phase != expected)
        ):
            raise ValueError("Native child phase differs from the real export")
        shared_chronology = (
            session._runtime2026 is self.controller.runtime
            and session._controller2026 is self.controller
            and session._engine2026 is self.engine
        )
        if (
            session.used
            or (session.trace.position and not shared_chronology)
            or session.container.digest != self.engine.source_sha256
            or session.node != self.engine.native_metadata.node
            or session.context["observations"]["host"].get("cpu_index", 0)
            != self.engine.dh_state.selection_cpu_index
        ):
            raise ValueError("Fresh replay for the actual engine source required")
        with self._lock:
            self.validate_owner(self.engine)
            if self._stop or (self._outer is not None and not self._outer.is_alive()):
                raise ValueError("Native thread job is stopped")
            if (
                expected == 1
                and self.worker.native_prepare_handshake == 1
                and not self.worker.control_state.recovery_mode
            ):
                with self.engine.prepare_reentry_execution(self):
                    if self.worker.prepare_reentry_handshake():
                        return None
            if self._lease is not None or (
                self._sequence and not self._completed.is_set()
            ):
                raise ValueError("Native child is already scheduled")
            self._lease = self.engine.reserve_phase(self.controller, expected)
            self._session = session
            self._completed.clear()
            self._child_done.clear()
            self._child_parked.clear()
            self._prepare_pending.clear()
            self._result = self._error = self._continuation = None
            self._child_exit = None
            self._sequence += 1
            if self._outer is None:
                self._outer = threading.Thread(
                    target=self._run_outer, name="CUW2026-3cb90", daemon=True
                )
                try:
                    self._outer.start()
                except BaseException:
                    self.engine.release_reserved_phase(self._lease)
                    self._lease = self._session = None
                    self._outer = None
                    self._sequence -= 1
                    raise
            self._resume.set()
            return self._sequence

    def _prepare_controller_entry(self, session: ProgrammingReplay) -> None:
        """5b970 selects the loader;59710/5bf80 retain its actual export identity."""
        from scripts.calibration_2026 import native2026_cpu_type
        from scripts.programming_2026_common import (
            NativeCallbackLookupError,
            NativePassThruException2026,
        )

        self.engine._require_owned_phase()
        metadata = self.engine.native_metadata
        contact = metadata.vehicle.get("contacttype", "")
        legacy = False
        if contact not in ("P5-Unified", "Phase6", "Ethernet"):
            kind = metadata.vehicle.get("kindofecu", "")
            cpu_type = native2026_cpu_type(metadata, 0)
            filename = (kind + contact + cpu_type + ".ini").casefold()
            if not any(
                name.casefold() == filename for name in session._catalog_sources
            ):
                general = self.engine._general_parameters
                if general is None:
                    raise NativeCallbackLookupError()
                if general.boolean_with_keys(
                    kind, cpu_type, contact, "FlagToUseCIDGetterAndFlashWriterDLL"
                ):
                    raise NativePassThruException2026(
                        9999, "CUW2026 native worker loader", 0x16B6
                    )
                legacy = True
        if self._controller_entry is None:
            name = (
                "TCUWLegacyCIDGettersAndFlashWriters.dll"
                if legacy
                else "TCUWControlCommPhase.dll"
            )
            module = session.modules.get(name)
            identity = None if module is None else module.native_identity
            line = 0
            if identity is None:
                line = 0x16DC if legacy else 0x8F2
            elif "Execute" not in identity.callable_exports:
                line = 0x16E3 if legacy else 0x902
            elif not legacy:
                if not {
                    "IsSendingSyncPeriodicMsgToECU",
                    "DisconnectJ2534Connection",
                }.issubset(identity.callable_exports):
                    line = 0x902
                elif (
                    "ChangeToReprogGWModeForDHCentralGW"
                    not in identity.callable_exports
                ):
                    line = 0x90A
                elif identity != self.controller.identity:
                    raise ValueError("Loaded control identity differs from its owner")
            if line:
                raise NativePassThruException2026(
                    9999, "CUW2026 native worker loader", line
                )
            self._controller_entry = name
        if legacy:
            raise ValueError("Consolidated native controller ownership is not bound")

    def _run_child(self) -> None:
        try:
            while True:
                self._child_resume.wait()
                self._child_resume.clear()
                with self._lock:
                    lease, session = self._lease, self._session
                    if self._stop and (lease is None or lease.state != "reserved"):
                        break
                    if lease is None:
                        raise ValueError("Native child resume has no reserved work")
                    assert session is not None
                    self._child_parked.clear()
                try:
                    with self.controller.runtime.thread_job_host_boundary(self):
                        self.controller.runtime.check()
                        session.bind_controller2026(self.controller)
                        with self.engine.controller_execution(
                            self.controller, lease.phase, lease=lease
                        ):
                            from scripts.j2534_2026 import NativePassThruError2026
                            from scripts.programming_2026_common import (
                                NativePassThruException2026,
                            )

                            self.worker._begin_outer_control_loader()
                            try:
                                self._prepare_controller_entry(session)
                            except (
                                NativePassThruException2026,
                                NativePassThruError2026,
                            ) as error:
                                self.worker._record_outer_control_loader_failure(error)
                            if self.worker.native_fatal_input80:
                                result = {
                                    "native_return": None,
                                    "exports": (),
                                    "programming_completed": False,
                                }
                            else:
                                if self._controller_entry == "TCUWControlCommPhase.dll":
                                    # The authenticated raw CONTROL Execute binds its
                                    # held family target after it issues the raw token.
                                    session.bind_controller2026(self.controller)
                                else:
                                    session.bind_engine2026(self.engine)
                                self.controller.bind_startup_session(
                                    self.engine, session
                                )
                                startup = (
                                    self.worker.run_gateway_startup()
                                    if lease.phase == 1
                                    else None
                                )
                                if (
                                    startup is not None
                                    and not startup.returned
                                    and startup.output_flag
                                ):
                                    self._query_native_worker_error()
                                    result = {
                                        "native_return": None,
                                        "startup_return": False,
                                        "exports": (),
                                        "programming_completed": False,
                                    }
                                else:
                                    result = self.controller.execute(
                                        self.engine, session
                                    )
                                    if lease.phase == 0:
                                        from scripts import programming_2026_common

                                        context = (
                                            self.controller.native_control_context2026(
                                                self.engine
                                            )
                                        )
                                        if programming_2026_common._control_has_ordinary_getter_return2026(
                                            context
                                        ):
                                            self.dispatch_control_getter_return()
                            self.dispatch_worker_tail()
                        with self._lock:
                            self._result = result
                except BaseException as error:  # noqa: BLE001 - preserve child faults for the joining host
                    with self._lock:
                        self._error = error
                finally:
                    if lease.state == "reserved":
                        self.engine.release_reserved_phase(lease)
                    # 5a835 publishes+1c BEFORE be64 and waits for be5c.
                    self._child_parked.set()
                    self._child_done.set()
                    self._activity.set()
            self._child_exit = 0
        except BaseException as error:  # noqa: BLE001 - preserve thread failure for the joining owner
            with self._lock:
                self._error, self._child_exit = error, 1
            self._child_done.set()
            self._activity.set()

    def _query_native_worker_error(self) -> None:
        """5b810: source worker query and reconnect on the engine CJ2534IF view."""
        from scripts.j2534_2026 import NativePassThruError2026
        from scripts.programming_2026_common import (
            NativePassThruException2026,
            native_error_fields2026,
        )

        self.engine._require_owned_phase()
        retry = self.engine.bind_retry_controller()
        runtime = self.controller.runtime
        while True:
            runtime.check()
            self.engine.notify_native_error_kind()
            self.engine.notify_native_errors()
            self.worker.begin_control_error_query()
            self.engine.publish_control_failed(self.controller)
            # 5b810 calls the worker+40 CUW function directly;58240 is a separate handoff.
            retry.callback3()
            self.worker.import_control_error_query_decision(retry)
            if not self.worker.control_state.failed:
                return
            try:
                with runtime.engine_device_calls(self.engine):
                    device = self.engine.engine_runtime_device()
                    device.disconnect()
                    for identifier in runtime.owned_identifiers("stop_filter"):
                        runtime.forget_invalidated_resource(
                            "stop_filter", identifier=identifier
                        )
                    if runtime.owns_resource("disconnect"):
                        runtime.forget_invalidated_resource("disconnect")
                    metadata = self.engine.native_metadata
                    contact = metadata.vehicle.get("contacttype", "")
                    protocol = (
                        3
                        if contact == "SIL"
                        else 0x800F
                        if contact == "Ethernet"
                        else 0x8012
                        if contact == "Phase6" and metadata.protocol_at_node == "02"
                        else 6
                    )
                    if protocol == 0x800F and device.version != 1:
                        device.switch_version()
                    device.connect_native(protocol)
                return
            except (NativePassThruException2026, NativePassThruError2026) as error:
                primary, status = native_error_fields2026(error)
                state = self.engine.dh_state
                state.record_native_error(
                    3, primary, state.passthru_error if status is None else status
                )

    def _run_outer(self) -> None:
        try:
            while True:
                self._resume.wait()
                self._resume.clear()
                with self._lock:
                    lease = self._lease
                    if lease is None:
                        if self._stop:
                            break
                        raise ValueError("Native resume event has no actual child work")
                    self._waiting = False
                    child = self._child
                    needs_start = child is None
                    if child is None:
                        child = threading.Thread(
                            target=self._run_child, name="CUW2026-5ccd0", daemon=True
                        )
                        self._child = child
                if needs_start:
                    try:
                        child.start()
                    except BaseException:
                        with self._lock:
                            self._child = None
                            self.engine.release_reserved_phase(lease)
                            self._lease = self._session = None
                        raise
                self._child_resume.set()
                while not self._child_done.is_set():
                    self._activity.wait()
                    self._activity.clear()
                    if self._callback_requested.is_set():
                        try:
                            with self.engine.thread_callback_execution(self):
                                if self._callback_kind == "retry":
                                    self.engine.bind_retry_controller().callback3()
                                elif self._callback_kind == "tail":
                                    self.worker._publish_outer_control_tail()
                                elif self._callback_kind == "next_cpu":
                                    self.worker.notify_next_cpu()
                                elif self._callback_kind == "logical_cpu":
                                    assert self._callback_argument is not None
                                    self.worker.notify_logical_cpu_boundary(
                                        self._callback_argument
                                    )
                                elif self._callback_kind == "control_progress_count":
                                    self.worker.publish_control_count2026(
                                        self._callback_context
                                    )
                                elif self._callback_kind == "control_progress_percent":
                                    self.worker.publish_control_percent2026(
                                        self._callback_context
                                    )
                                elif self._callback_kind == "control_getter_return":
                                    self.worker.import_control_getter_return2026(
                                        self._callback_context
                                    )
                                else:
                                    raise ValueError("Unknown native outer callback")
                        except BaseException as error:  # noqa: BLE001 - restore exact outer callback failure to child
                            self._callback_error = error
                        finally:
                            self._callback_kind = None
                            self._callback_argument = None
                            self._callback_context = None
                            self._callback_requested.clear()
                            self._callback_returned.set()
                if self._prepare_pending.is_set():
                    self.wait_prepare_acknowledgement()
                # 3cb90 deletes1c58 after4b900 has unwound, before waiting be54.
                self.engine.bind_cleanup_controller().release_retired_selected(
                    self.worker
                )
                with self._lock:
                    self._continuation = self.worker.take_continuation()
                    self._lease = self._session = None
                    self._waiting = True
                    if self.engine._retry_controller is not None:
                        self.engine._retry_controller.worker_stopped()
                    self._completed.set()
                    if self._stop:
                        break
            self._outer_exit = 0
        except BaseException as error:  # noqa: BLE001 - preserve thread failure for its joining owner
            with self._lock:
                if self._error is None:
                    self._error = error
                elif self._error is not error:
                    self._error.add_note(
                        "Native outer cleanup failure: " + type(error).__name__
                    )
                self._outer_exit = 1
                self._completed.set()
        finally:
            with self._lock:
                self._stop = True
                self._child_resume.set()
                child = self._child
            if child is not None:
                child.join()
            self._waiting = False

    def result(self, timeout: float = 5.0) -> dict:
        deadline = _timeout_deadline(timeout)
        self._reject_self_join()
        if not self._sequence:
            raise ValueError("Native thread job has not been started")
        if not self._completed.wait(max(0, deadline - time.monotonic())):
            raise TimeoutError("Native child wait exceeded host deadline")
        with self._lock:
            if self._error is not None:
                raise self._error
            assert self._result is not None
            return self._result

    @property
    def is_child_thread(self) -> bool:
        return threading.current_thread() is self._child

    @property
    def is_native_thread(self) -> bool:
        return threading.current_thread() in (self._child, self._outer)

    def dispatch_next_cpu(self) -> None:
        """581a0's actual success callback runs on the outer native owner."""
        self._dispatch_outer_callback("next_cpu")

    def dispatch_logical_cpu_boundary(self, index: int) -> None:
        """P6's source-issued logical boundary retains its concrete CPU index."""
        if type(index) is not int:
            raise TypeError("Actual native logical CPU index required")
        self._dispatch_outer_callback("logical_cpu", index)

    def dispatch_retry_callback(self) -> None:
        """58240 publishes the concrete retry callback to be74 and waits be6c."""
        self._dispatch_outer_callback("retry")

    def dispatch_worker_tail(self) -> None:
        """5b1b0 publishes the source-issued native fatal input on the outer thread."""
        self._dispatch_outer_callback("tail")

    def dispatch_control_progress(self, context, kind: str) -> None:
        """Publish the worker-owned CONTROL vector at its real child callback."""
        from scripts.programming_2026_common import NativeControlContext2026

        if type(kind) is not str or kind not in ("count", "percent"):
            raise ValueError("CONTROL progress kind must be count or percent")
        if threading.current_thread() is not self._child:
            raise ValueError("CONTROL progress belongs to the actual child")
        self.engine._require_owned_phase()
        self.validate_owner(self.engine)
        if (
            type(context) is not NativeControlContext2026
            or self.controller.native_control_context2026(self.engine) is not context
        ):
            raise ValueError("Current issued CONTROL context required")
        self.worker._validate_control_output_context2026(context)
        target = self.engine._controller_export_target2026
        if target is None or target._context is not context:
            raise ValueError("Active CONTROL export target required")
        target.validate(self.engine, self.controller)
        self._dispatch_outer_callback(f"control_progress_{kind}", context=context)

    def dispatch_control_getter_return(self) -> None:
        """Import the actual ordinary getter return after raw Execute returns."""
        from scripts.programming_2026_common import NativeControlContext2026

        if threading.current_thread() is not self._child:
            raise ValueError("CONTROL getter return belongs to the actual child")
        self.engine._require_owned_phase()
        self.validate_owner(self.engine)
        context = self.controller.native_control_context2026(self.engine)
        if (
            type(context) is not NativeControlContext2026
            or context._capture._phase != 0
        ):
            raise ValueError("Ordinary CONTROL getter context required")
        self.worker._validate_control_output_context2026(context)
        self._dispatch_outer_callback("control_getter_return", context=context)

    def _dispatch_outer_callback(
        self, kind: str, argument: int | None = None, *, context=None
    ) -> None:
        if threading.current_thread() is not self._child:
            raise ValueError("Native callback publication belongs to the actual child")
        self.engine._require_owned_phase()
        self.controller.runtime.check()
        self._callback_error = None
        self._callback_kind = kind
        self._callback_argument = argument
        self._callback_context = context
        self._callback_returned.clear()
        self._callback_requested.set()
        self._activity.set()
        # Keep phase ownership with the outer callback until its real acknowledgement.
        # The host's result/stop waits are bounded independently of a stalled provider.
        self._callback_returned.wait()
        if self._callback_error is not None:
            raise self._callback_error

    def validate_callback_handoff(self) -> int:
        if (
            threading.current_thread() is not self._outer
            or not self._callback_requested.is_set()
            or self._child is None
            or not self._child.is_alive()
            or self._child.ident is None
            or self._lease is None
            or self._lease.state != "adopted"
        ):
            raise ValueError("Actual parked native child callback handoff required")
        self.validate_owner(self.engine)
        return self._child.ident

    def request_prepare_acknowledgement(self) -> None:
        """Defer41e60's outer barrier until the inline child callback unwinds."""
        if threading.current_thread() not in (self._child, self._outer):
            raise ValueError("Prepare catch-all belongs to an actual native job thread")
        self.engine._require_owned_phase()
        self._prepare_pending.set()

    def request_external_prepare_acknowledgement(self, retry) -> None:
        """External5e950/5d830 native catch waits for the actual child+1c."""
        self.validate_owner(self.engine)
        self.engine._validate_retry_controller(retry)
        if threading.current_thread() in (self._child, self._outer):
            raise ValueError("External native acknowledgement caller required")
        if self.worker.native_prepare_handshake != 2 or not self.native_worker_exists:
            raise ValueError("Actual pending native prepare acknowledgement required")
        self._prepare_pending.set()
        self._wait_child_parked()

    def wait_prepare_acknowledgement(self) -> None:
        """41e60 polls the real child+1c every500ms; hosts cannot set this flag."""
        if threading.current_thread() is not self._outer:
            raise ValueError(
                "Prepare acknowledgement barrier belongs to native outer thread"
            )
        self._wait_child_parked()

    def _wait_child_parked(self) -> None:
        deadline = time.monotonic() + min(
            self.controller.runtime.check(), self.controller.runtime.cleanup_timeout
        )
        try:
            while not self._child_parked.wait(
                min(0.5, max(0, deadline - time.monotonic()))
            ):
                self.controller.runtime.check()
                if time.monotonic() >= deadline:
                    raise TimeoutError(
                        "Native prepare acknowledgement exceeded host deadline"
                    )
        finally:
            self._prepare_pending.clear()

    def _reject_self_join(self) -> None:
        if threading.current_thread() in (self._child, self._outer):
            raise ValueError("Native thread cannot join itself")

    @property
    def native_work_pending(self) -> bool:
        """Actual reserved work through the outer's late CFE2 clear boundary."""
        return self._lease is not None

    @property
    def native_worker_exists(self) -> bool:
        outer = self._outer
        return outer is not None

    @property
    def host_stop_requested(self) -> bool:
        return self._host_stop

    def stop(self, timeout: float = 5.0) -> None:
        """Host interruption, actual native-loop exit, then bounded external join."""
        self._stop_and_join(timeout, host_interruption=True)

    def stop_native(self, timeout: float = 5.0) -> None:
        """Join only after an actual engine native-stop producer set callback12."""
        if not self.engine.native_cancelled():
            raise ValueError("Actual engine native cancellation must precede its join")
        self._stop_and_join(timeout, host_interruption=False)
        with self._lock:
            self._outer = self._child = None

    def _stop_and_join(self, timeout: float, *, host_interruption: bool) -> None:
        deadline = _timeout_deadline(timeout)
        self._reject_self_join()
        if not self._lock.acquire(timeout=max(0, deadline - time.monotonic())):
            raise TimeoutError("Native stop ownership wait exceeded host deadline")
        try:
            self._stop = True
            self._host_stop = self._host_stop or host_interruption
            self._child_resume.set()
            self._resume.set()
            outer = self._outer
        finally:
            self._lock.release()
        if outer is not None:
            outer.join(max(0, deadline - time.monotonic()))
            if outer.is_alive():
                raise TimeoutError("Native outer thread join exceeded host deadline")
        self._resume.clear()
        self._child_resume.clear()
        self._child_done.clear()
        self._child_parked.clear()
        self._prepare_pending.clear()


def _issue_engine_thread_job(engine, controller) -> EngineThreadJob2026:
    from scripts.cuw_2026 import CUWEngine2026
    from scripts.programming_2026_common import ControlCommPhase2026

    if (
        type(engine) is not CUWEngine2026
        or type(controller) is not ControlCommPhase2026
    ):
        raise TypeError("Concrete engine and controller required")
    if engine.worker.controller is not controller:
        raise ValueError("Actual issued worker controller required")
    existing = getattr(engine, "_thread_job", None)
    if existing is not None:
        if type(existing) is not EngineThreadJob2026:
            raise ValueError("Engine has a foreign native thread job")
        existing.validate_owner(engine, controller)
        return existing
    return EngineThreadJob2026(engine, controller, _token=_TOKEN)
