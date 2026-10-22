"""CUW2026 shared contracts, with explicit bounded host primitives.

No transport is created here. Host limits are policy, not observed OEM limits.
"""

import ctypes
import ctypes.util
import hashlib
import hmac
import math
import re
import struct
import threading
import time
from collections.abc import Callable, Mapping
from contextlib import contextmanager, nullcontext
from dataclasses import dataclass, field, replace
from datetime import datetime
from types import MappingProxyType
from typing import TYPE_CHECKING, Self, cast
from weakref import WeakValueDictionary, ref

from scripts.calibration_2026 import (  # noqa: F401 - compatibility exports for family consumers
    Native2026Metadata,
    native2026_cpu_type,
    native2026_global_cpu_index,
    native2026_metadata,
    native2026_metadata_for_cpu,
    native2026_node_index,
    native2026_node_values,
    native2026_selection_metadata,
    native2026_validate_runtime_metadata,
    native2026_with_cpu_type,
    native2026_with_parser_parameters,
)
from scripts.j2534_2026 import (  # noqa: F401 - compatibility export
    J2534Device2026,
    j2534_indication,
)
from scripts.native_modules import NativeModuleIdentity, identify_native_module
from scripts.programming import NativeTransportError

if TYPE_CHECKING:
    from scripts.cuw_parameter_pool import ControlParameterPool2026

DIAG_COMM_PROTOCOL_CANFD = "02"
DIAG_COMM_PROTOCOL_ETHERNET = "03"
_CURRENT_DEVICE_VIEW = object()
_CHANNEL_CHILD_RELEASES = frozenset(
    (
        "stop_filter",
        "stop_periodic",
        "logical_disconnect",
        "logical_disconnect_udp_discovery",
    )
)


def _system_local_milliseconds_of_day() -> int:
    timestamp = time.time_ns()
    current = time.localtime(timestamp // 1_000_000_000)
    return (current.tm_hour * 3600 + current.tm_min * 60 + current.tm_sec) * 1000 + (
        timestamp // 1_000_000
    ) % 1000


def _system_local_seconds_of_day() -> int:
    return _system_local_milliseconds_of_day() // 1000


class NativeRuntime2026:
    """Deadline/cancellation boundary for injected J2534/CAN primitives.

    A provider receives an operation dictionary and remaining seconds. It must
    implement only that primitive; it cannot decide preparation/programming success.
    """

    def __init__(
        self,
        action: Callable[[dict, float], object],
        *,
        timeout: float = 30,
        clock: Callable[[], float] = time.monotonic,
        cancelled: Callable[[], bool] = lambda: False,
        cleanup_timeout: float = 5,
        cleanup_action: Callable[[dict, float], object] | None = None,
        max_calls: int = 65536,
        native_cancelled: Callable[[], bool] | None = None,
        local_seconds_of_day: Callable[[], int] = _system_local_seconds_of_day,
        local_milliseconds_of_day: Callable[
            [], int
        ] = _system_local_milliseconds_of_day,
    ):
        for value in (timeout, cleanup_timeout):
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                or value <= 0
            ):
                raise ValueError("Finite positive runtime and cleanup timeout required")
        if not all(callable(value) for value in (action, clock, cancelled)):
            raise TypeError("Callable primitive, clock and cancellation required")
        if type(max_calls) is not int or not 1 <= max_calls <= 16777216:
            raise ValueError("Bounded positive host primitive call budget required")
        self.max_calls = max_calls
        self.max_cleanup_calls = max_calls * 2 + 256
        if native_cancelled is not None and not callable(native_cancelled):
            raise TypeError("Callable native cancellation observation required")
        if not callable(local_seconds_of_day) or not callable(
            local_milliseconds_of_day
        ):
            raise TypeError("Native local time observations must be callable")
        self.local_seconds_of_day = local_seconds_of_day
        self.local_milliseconds_of_day = local_milliseconds_of_day
        self.native_cancelled = native_cancelled
        self._security_composer = None
        self._smc_hmac = None
        self._central_gateway_key = None
        self._p5_online = None
        self._recorded_device2026 = None
        owner = getattr(action, "__self__", None)
        if (
            cleanup_action is None
            and type(owner) is J2534Device2026
            and action == owner.primitive
        ):
            cleanup_action = owner.cleanup_primitive
        if cleanup_action is not None and not callable(cleanup_action):
            raise TypeError("Callable cleanup primitive capability required")
        self.action, self.clock, self.cancelled = action, clock, cancelled
        self.cleanup_action = action if cleanup_action is None else cleanup_action
        self.deadline = clock() + timeout
        self.cleanup_timeout = cleanup_timeout
        self.calls = 0
        self.cleanup_calls = 0
        self._resources: list[dict] = []
        self._resource_views: dict[int, tuple] = {}
        self._resource_channel_anchors: dict[int, tuple] = {}
        self._device_calls = threading.local()
        self._thread_job_host = None

    @contextmanager
    def thread_job_host_boundary(self, job):
        """Bound host job-stop observation without changing native cancellation."""
        from scripts.cuw_engine_threads import EngineThreadJob2026

        if type(job) is not EngineThreadJob2026:
            raise TypeError("Concrete native thread job required")
        job.validate_owner(job.engine, job.controller)
        if job.controller.runtime is not self:
            raise ValueError("Native thread job belongs to another runtime")
        previous = self._thread_job_host
        if previous is not None and previous is not job:
            raise ValueError("Another native thread job boundary is already active")
        self._thread_job_host = job
        try:
            yield
        finally:
            self._thread_job_host = previous

    @contextmanager
    def engine_device_calls(self, engine):
        """Route actual engine-receiver primitives without replacing this runtime."""
        from scripts.cuw_2026 import CUWEngine2026

        if type(engine) is not CUWEngine2026:
            raise TypeError("Concrete native engine required for its interface view")
        engine._require_owned_phase()
        worker = engine.worker
        if worker.controller.runtime is not self:
            raise ValueError("Engine interface view belongs to another runtime")
        pair, device = engine.interface_pair, engine.engine_runtime_device()
        if pair is None or pair.engine is not device:
            raise ValueError("Actual native engine interface pair required")
        current = getattr(self._device_calls, "view", None)
        view = (pair, device)
        if current is not None and not self._same_device_view(current, view):
            raise ValueError("Another engine interface view is already active")
        self._device_calls.view = view
        try:
            yield
        finally:
            self._device_calls.view = current

    @staticmethod
    def _same_device_view(first, second) -> bool:
        return first is second or (
            first is not None
            and second is not None
            and first[0] is second[0]
            and first[1] is second[1]
        )

    def native_channel_connected2026(self) -> bool | None:
        """Observe the concrete native CJ channel; opaque providers have no view."""
        view = getattr(self._device_calls, "view", None)
        device = view[1] if view is not None else self.recorded_device2026()
        if device is None:
            candidate = getattr(self.action, "__self__", None)
            if (
                type(candidate) is not J2534Device2026
                or self.action != candidate.primitive
            ):
                return None
            device = candidate
        if type(device) is not J2534Device2026 or type(device.connecting) is not bool:
            raise ValueError("Actual native interface channel state required")
        if device.connecting and device.interface_pair is not None:
            pair = device.interface_pair
            pair.validate_channel_lease(device, pair.channel_lease(device))
        return device.connecting

    def _channel_resource_anchor(self, operation: str) -> tuple | None:
        from scripts.j2534_2026 import J2534InterfacePair2026

        if operation not in _CHANNEL_CHILD_RELEASES:
            return None
        view = getattr(self._device_calls, "view", None)
        if view is not None:
            pair, device = view
        else:
            device = self.recorded_device2026()
            if device is None:
                candidate = getattr(self.action, "__self__", None)
                if (
                    type(candidate) is not J2534Device2026
                    or self.action != candidate.primitive
                ):
                    return None
                device = candidate
            pair = device.interface_pair
            if pair is None:
                return None
        if (
            type(pair) is not J2534InterfacePair2026
            or type(device) is not J2534Device2026
        ):
            raise ValueError("Actual paired channel resource owner required")
        return pair, pair.channel_lease(device), device

    def _track_resource(self, entry: dict, channel_anchor: tuple | None) -> None:
        self._resources.append(entry)
        view = getattr(self._device_calls, "view", None)
        if view is not None:
            self._resource_views[id(entry)] = view
        if channel_anchor is not None:
            self._resource_channel_anchors[id(entry)] = channel_anchor

    def _forget_resource_entry(self, entry: dict) -> None:
        index = next(
            index for index, current in enumerate(self._resources) if current is entry
        )
        self._resources.pop(index)
        self._resource_views.pop(id(entry), None)
        self._resource_channel_anchors.pop(id(entry), None)

    def bind_recorded_device2026(self, trace, device: J2534Device2026) -> None:
        """Retain only the actual recorded driver/device executed by this runtime."""
        from scripts.programming_replay import ProgrammingTrace

        if type(trace) is not ProgrammingTrace or type(device) is not J2534Device2026:
            raise TypeError("Concrete programming trace and native device required")
        if self._recorded_device2026 is None and (
            self.calls or self.cleanup_calls or self._resources
        ):
            raise ValueError("Recorded native device must bind before runtime actions")
        if (
            self.action != trace.action
            or getattr(self.action, "__self__", None) is not trace
            or device.provider != trace.driver_primitive
            or getattr(device.provider, "__self__", None) is not trace
            or trace.device is not device
            or self.cleanup_action not in (trace.action, trace.cleanup_primitive)
        ):
            raise ValueError("Recorded device does not own this runtime transport")
        if self._recorded_device2026 is not None:
            previous_trace, previous_device = self._recorded_device2026
            if previous_trace is not trace or previous_device is not device:
                raise ValueError("Runtime already has another recorded native device")
        self._recorded_device2026 = (trace, device)
        self.cleanup_action = trace.cleanup_primitive

    def recorded_device2026(self) -> J2534Device2026 | None:
        if self._recorded_device2026 is None:
            return None
        trace, device = self._recorded_device2026
        self.bind_recorded_device2026(trace, device)
        return device

    def bind_p5_online(
        self, controller, chronology, *, advance_clock: Callable[[float], None]
    ) -> None:
        """Bind callback26/27's concrete controller and private primitive capture."""
        from scripts.cuw_online import OnlineKeyController2026, OnlineReplay2026

        if (
            type(controller) is not OnlineKeyController2026
            or type(chronology) is not OnlineReplay2026
        ):
            raise TypeError("Concrete native online controller and chronology required")
        controller.validate_source()
        if controller.worker.runtime is not self or not callable(advance_clock):
            raise ValueError(
                "Online controller must own this runtime and clock primitive"
            )
        if self._p5_online is not None:
            previous, recording, _advance = self._p5_online
            if previous is controller and recording is chronology:
                return
            if not recording.used:
                raise ValueError("Previous online chronology is still unused")
        if chronology.used:
            raise ValueError("Unused native online chronology required")
        self._p5_online = (controller, chronology, advance_clock)

    def validate_online_binding(self, engine, advance_clock) -> bool:
        """Check a retained factory binding without resetting capture consumption."""
        from scripts.cuw_2026 import CUWEngine2026

        if type(engine) is not CUWEngine2026 or not callable(advance_clock):
            raise TypeError("Concrete online engine and clock sink required")
        if self._p5_online is None:
            return False
        controller, _chronology, sink = self._p5_online
        controller.worker.validate_source(engine=engine)
        if controller.worker.runtime is not self or sink != advance_clock:
            raise ValueError("Online factory engine/runtime/clock binding differs")
        return True

    def bound_online_controller2026(self):
        """Expose the retained source controller without replacing capture ownership.

        Worker replacement validates the closed previous worker in its actual
        engine transaction. This accessor preserves that chronology for rebind.
        """
        from scripts.cuw_online import OnlineKeyController2026, OnlineReplay2026

        if self._p5_online is None:
            return None
        controller, chronology, sink = self._p5_online
        if (
            type(controller) is not OnlineKeyController2026
            or type(chronology) is not OnlineReplay2026
            or controller.worker.runtime is not self
            or not callable(sink)
        ):
            raise ValueError("Actual retained online runtime binding required")
        return controller

    def _online_primitive(self, action: dict, remaining: float):
        from scripts.cuw_online import OnlineKey2026

        if self._p5_online is None:
            raise ValueError("Source-issued online controller binding required")
        operation = action.get("operation")
        if not isinstance(operation, str):
            raise TypeError("Native online operation name required")
        expected = {
            "calculate_p5_gateway_key": (16, 256),
            "calculate_dh_gateway_online_key": (8, 64),
            "calculate_esw1_key": (16, 256),
        }.get(operation)
        if (
            expected is None
            or set(action) != {"operation", "seed"}
            or type(action["seed"]) is not bytes
            or len(action["seed"]) != expected[0]
        ):
            raise ValueError("Exact native online seed operation required")
        controller, chronology, advance_clock = self._p5_online
        controller.validate_source()
        previous_elapsed = chronology.consumed_elapsed_seconds
        failure = None
        try:
            key = controller.calculate(
                action["seed"],
                chronology,
                timeout=min(remaining, 600),
                cancelled=self.cancelled,
                clock=self.clock,
            )
            if key is None:
                return False
            if type(key) is not OnlineKey2026 or len(key.value) != expected[1]:
                raise ValueError("Native online controller output size differs")
            return key.value
        except (Exception, KeyboardInterrupt) as error:
            failure = error
            raise
        finally:
            elapsed = chronology.consumed_elapsed_seconds - previous_elapsed
            if elapsed:
                try:
                    advance_clock(elapsed)
                except (Exception, KeyboardInterrupt) as error:
                    if failure is None:
                        raise
                    failure.add_note(
                        "Online clock accounting failure: " + type(error).__name__
                    )

    def bind_central_gateway_key(self, binding: "NativeCentralGatewayKey2026") -> None:
        """Bind slot20's distinct source-issued mode1 AES key."""
        if type(binding) is not NativeCentralGatewayKey2026:
            raise TypeError("Source-issued native central gateway AES binding required")
        binding._validate_native_binding()
        if self._central_gateway_key is not None:
            if self._central_gateway_key.source_sha256 != binding.source_sha256:
                raise ValueError("Runtime central gateway source differs")
            return
        self._central_gateway_key = binding

    def bind_smc_hmac(self, binding: "NativeSMCHmac2026") -> None:
        """Load only the authored port issued from exact private dependency bytes."""
        if type(binding) is not NativeSMCHmac2026:
            raise TypeError("Source-issued native SMC HMAC binding required")
        binding._validate_native_binding()
        if self._smc_hmac is not None:
            if self._smc_hmac.source_sha256 != binding.source_sha256:
                raise ValueError("Runtime SMC library source binding differs")
            return
        self._smc_hmac = binding

    def _authorization_primitive(self, action: dict, remaining: float):
        # Suzuki1750 invokes callback26; other authorization slots are distinct.
        if action.get("family") == "suzuki_uds" and action.get("stage") == "gateway":
            if (
                set(action) != {"operation", "family", "stage", "seed", "key_length"}
                or type(action.get("key_length")) is not int
                or action["key_length"] != 256
            ):
                raise ValueError("Exact Suzuki callback26 authorization required")
            return self._online_primitive(
                {"operation": "calculate_p5_gateway_key", "seed": action["seed"]},
                remaining,
            )
        return self.action(action, remaining)

    def _provider(
        self, operation: str, cleanup: bool = False, *, device_view=_CURRENT_DEVICE_VIEW
    ):
        if operation == "observe_authorization_key" and not cleanup:
            return self._authorization_primitive
        if operation in (
            "calculate_p5_gateway_key",
            "calculate_dh_gateway_online_key",
            "calculate_esw1_key",
        ):
            if cleanup:
                raise ValueError("Online calculation cannot run as resource cleanup")
            return self._online_primitive
        if (
            self._central_gateway_key is not None
            and operation == "calculate_central_gateway_key"
        ):
            return self._central_gateway_key.primitive
        if self._smc_hmac is not None and operation in _SMC_OPERATIONS:
            return self._smc_hmac.primitive
        view = (
            getattr(self._device_calls, "view", None)
            if device_view is _CURRENT_DEVICE_VIEW
            else device_view
        )
        if view is not None:
            from scripts.j2534_2026 import J2534InterfacePair2026
            from scripts.programming_replay import (
                DEVICE_ACTIONS2026,
                native_device_action2026,
            )

            if not isinstance(view, tuple) or len(view) != 2:
                raise ValueError("Actual source-issued engine view required")
            pair, device = view
            if type(pair) is not J2534InterfacePair2026:
                raise TypeError("Concrete native interface pair required")
            pair.validate_views()
            if device is not pair.engine:
                raise ValueError("Owned engine resource interface changed")
            if operation in DEVICE_ACTIONS2026:
                return lambda action, remaining: native_device_action2026(
                    device, action, remaining, cleanup=cleanup
                )
        return self.cleanup_action if cleanup else self.action

    def bind_security_composer(self, composer: "NativeSecurityComposer2026") -> None:
        """Bind source-computed internal AES without changing transport ownership."""
        if type(composer) is not NativeSecurityComposer2026:
            raise TypeError("Concrete factory-issued native security composer required")
        composer.client._validate_native_binding()
        if self._security_composer is not None and (
            self._security_composer.client.source_sha256
            != composer.client.source_sha256
        ):
            raise ValueError("Native runtime security source binding differs")
        self._security_composer = composer

    def check(self) -> float:
        job = self._thread_job_host
        if self.cancelled() or (job is not None and job.host_stop_requested):
            raise InterruptedError("CUW2026 operation cancelled")
        remaining = self.deadline - self.clock()
        if not math.isfinite(remaining) or remaining <= 0:
            raise TimeoutError("CUW2026 operation deadline expired")
        return remaining

    def read_local_milliseconds_of_day(self) -> int:
        self.check()
        try:
            value = self.local_milliseconds_of_day()
        except (Exception, KeyboardInterrupt):
            self.check()
            raise
        self.check()
        if type(value) is not int or not 0 <= value < 86400000:
            raise ValueError("Native local milliseconds within day required")
        return value

    def read_local_seconds_of_day(self) -> int:
        self.check()
        try:
            value = self.local_seconds_of_day()
        except (Exception, KeyboardInterrupt):
            self.check()
            raise
        self.check()
        if type(value) is not int or not 0 <= value < 86400:
            raise ValueError("Native whole local seconds within day required")
        return value

    def native_cancellation_requested(self) -> bool:
        """Observe callback12, retaining independent host boundary precedence."""
        if self.native_cancelled is None:
            raise ValueError("Native cancellation callback is not bound")
        self.check()
        try:
            cancelled = self.native_cancelled()
        except (Exception, KeyboardInterrupt):
            self.check()
            raise
        self.check()
        if type(cancelled) is not bool:
            raise ValueError("Native cancellation callback must return Boolean")
        return cancelled

    def check_native_cancelled(self) -> None:
        """Receive-loop callback12 true throws the native empty CException."""
        if self.native_cancellation_requested():
            raise NativeException2026("")

    def call(self, operation: str, *, cleanup: bool = False, **values):
        if not isinstance(operation, str) or not 0 < len(operation) <= 96:
            raise ValueError("Bounded primitive operation name required")
        remaining = self.cleanup_timeout if cleanup else self.check()
        if cleanup:
            self.cleanup_calls += 1
            if self.cleanup_calls > self.max_cleanup_calls:
                raise ValueError("Host cleanup call budget exceeded")
        else:
            self.calls += 1
            if self.calls > self.max_calls:
                raise ValueError("Host primitive call budget exceeded")
        started = self.clock()
        try:
            # CONTROL's native callback10/11 publishes the complete worker-owned
            # vector before the provider observes the corresponding notification.
            # The ordinary runtime path remains unchanged outside an authenticated
            # lexical export target.
            if operation in (
                "notify_progress_count",
                "notify_progress_percent",
            ):
                self._publish_scoped_control_progress2026(operation)
            provider = self._provider(operation, cleanup)
            if (
                not cleanup
                and self._security_composer is not None
                and operation in ("decrypt_secret_info", "calculate_security_key")
            ):
                provider = self._security_composer.primitive
            result = provider({"operation": operation, **values}, remaining)
        except (Exception, KeyboardInterrupt):
            if not cleanup:
                self.check()
            raise
        if cleanup:
            if self.clock() - started >= remaining:
                raise TimeoutError("CUW2026 cleanup primitive exceeded deadline")
        else:
            self.check()
        return result

    def _publish_scoped_control_progress2026(self, operation: str) -> None:
        active = getattr(self._device_calls, "control_export", None)
        if active is None:
            return
        engine, controller, target = active
        controller = engine._controller_execution
        target.validate(engine, controller)
        context = controller.native_control_context2026(engine)
        kind = "count" if operation == "notify_progress_count" else "percent"
        job = self._thread_job_host
        if job is not None:
            job.dispatch_control_progress(context, kind)
        else:
            publish = getattr(
                engine.worker,
                "publish_control_count2026"
                if kind == "count"
                else "publish_control_percent2026",
                None,
            )
            if not callable(publish):
                raise NotImplementedError("114 CONTROL publication API is pending")
            publish(context)

    def acquire(
        self,
        operation: str,
        release_operation: str,
        *,
        release_key: str = "identifier",
        null_is_failure: bool = False,
        **values,
    ) -> int:
        """Register a returned handle before checking callback cancellation/time."""
        remaining = self.check()
        if type(null_is_failure) is not bool:
            raise ValueError("Native null-handle policy must be Boolean")
        if len(self._resources) >= 256 or self.calls >= self.max_calls:
            raise ValueError("Host resource/call budget exceeded")
        if not all(
            isinstance(value, str) and 0 < len(value) <= 96
            for value in (operation, release_operation, release_key)
        ):
            raise ValueError("Bounded primitive and release names required")
        channel_anchor = self._channel_resource_anchor(release_operation)
        self.calls += 1
        identifier = self._provider(operation)(
            {"operation": operation, **values}, remaining
        )
        if type(identifier) is not int or not 0 <= identifier <= 0xFFFFFFFF:
            raise ValueError("Acquisition primitive must return native unsigned handle")
        if null_is_failure and identifier == 0:
            self.check()
            return identifier
        release = {"operation": release_operation, release_key: identifier}
        self._track_resource(release, channel_anchor)
        try:
            self.check()
        except (InterruptedError, TimeoutError) as error:
            try:
                self.release(release_operation, **{release_key: identifier})
            except (Exception, KeyboardInterrupt) as cleanup_error:  # noqa: BLE001 - preserve cause
                error.add_note(
                    "Acquisition rollback failure: " + type(cleanup_error).__name__
                )
            raise
        return identifier

    def call_result_owned(
        self,
        operation: str,
        release_operation: str,
        *,
        owned_result: int = 1,
        release_values: Mapping | None = None,
        **values,
    ):
        """Own a static release only after an exact native DWORD result matches."""
        if (
            type(owned_result) is not int
            or not 0 <= owned_result <= 0xFFFFFFFF
            or any(
                not isinstance(name, str) or not 0 < len(name) <= 96
                for name in (operation, release_operation)
            )
            or release_values is not None
            and not isinstance(release_values, Mapping)
        ):
            raise ValueError(
                "Bounded operation names and native DWORD ownership result required"
            )
        release = dict(release_values or {})
        if "operation" in release:
            raise ValueError("Release values cannot replace its primitive operation")
        remaining = self.check()
        if len(self._resources) >= 256 or self.calls >= self.max_calls:
            raise ValueError("Host resource/call budget exceeded")
        anchor = self._channel_resource_anchor(release_operation)
        self.calls += 1
        result = self._provider(operation)(
            {"operation": operation, **values}, remaining
        )
        entry = None
        if type(result) is int and result == owned_result:
            entry = {"operation": release_operation, **release}
            self._track_resource(entry, anchor)
        try:
            self.check()
        except (Exception, KeyboardInterrupt) as error:
            if entry is not None:
                try:
                    self._release_resource_entry(entry)
                except (Exception, KeyboardInterrupt) as cleanup_error:  # noqa: BLE001 - preserve the post-acquisition failure
                    error.add_note(
                        "Conditional acquisition rollback failure: "
                        + type(cleanup_error).__name__
                    )
            raise
        return result

    def call_owned(
        self,
        operation: str,
        release_operation: str,
        *,
        release_values: Mapping | None = None,
        **values,
    ):
        """Own a void primitive's compensating release before invoking it.

        This conservative host cleanup policy also releases after partial failure;
        providers must make stop/disconnect safe when acquisition did not finish.
        """
        self.check()
        release = dict(release_values or {})
        self.own(release_operation, **release)
        try:
            return self.call(operation, **values)
        except (Exception, KeyboardInterrupt) as error:
            try:
                self.release(release_operation, **release)
            except (Exception, KeyboardInterrupt) as cleanup_error:  # noqa: BLE001 - preserve cause
                error.add_note(
                    "Void acquisition rollback failure: " + type(cleanup_error).__name__
                )
            raise

    def owns_resource(self, operation: str, **values) -> bool:
        item = {"operation": operation, **values}
        view = getattr(self._device_calls, "view", None)
        return any(
            entry == item
            and self._same_device_view(self._resource_views.get(id(entry)), view)
            for entry in self._resources
        )

    def owned_identifiers(
        self, operation: str, *, release_key: str = "identifier"
    ) -> tuple[int, ...]:
        """Inspect exact handle-only ownership, including failed acquire rollback.

        This performs no provider call or cancellation check. A caller may use
        the IDs after a successful source-proven parent invalidation, but this
        snapshot itself does not establish that invalidation.
        """
        if (
            not isinstance(operation, str)
            or not 0 < len(operation) <= 96
            or not isinstance(release_key, str)
            or not 0 < len(release_key) <= 96
            or release_key == "operation"
        ):
            raise ValueError("Bounded cleanup operation and handle key required")
        values = []
        view = getattr(self._device_calls, "view", None)
        for entry in tuple(self._resources):
            if entry["operation"] != operation or not self._same_device_view(
                self._resource_views.get(id(entry)), view
            ):
                continue
            if (
                set(entry) != {"operation", release_key}
                or type(entry[release_key]) is not int
                or not 0 <= entry[release_key] <= 0xFFFFFFFF
            ):
                raise ValueError("Exact unsigned handle-only cleanup entry required")
            values.append(entry[release_key])
        return tuple(values)

    def forget_invalidated_resource(self, operation: str, **values) -> None:
        """Retire one child already invalidated by a source-proven parent release.

        The concrete caller must establish the successful parent disconnect first;
        this bookkeeping operation never attempts or asserts a native release.
        """
        item = {"operation": operation, **values}
        view = getattr(self._device_calls, "view", None)
        for entry in self._resources:
            if entry == item and self._same_device_view(
                self._resource_views.get(id(entry)), view
            ):
                self._forget_resource_entry(entry)
                return
        raise ValueError("Invalidated resource is not owned by this runtime view")

    def abandon_resource(self, operation: str, **values) -> None:
        """Forget a source-proven native abandonment, without claiming a release.

        The concrete caller must establish the native unwind that abandons this
        ownership. Host failures and cancellation still require compensation.
        """
        item = {"operation": operation, **values}
        view = getattr(self._device_calls, "view", None)
        for entry in self._resources:
            if entry == item and self._same_device_view(
                self._resource_views.get(id(entry)), view
            ):
                self._forget_resource_entry(entry)
                return
        raise ValueError("Abandoned resource is not owned by this runtime view")

    def _forget_disconnected_children(self) -> None:
        """Retire only children whose authenticated physical channel was released."""
        for entry in tuple(self._resources):
            anchor = self._resource_channel_anchors.get(id(entry))
            if anchor is not None and anchor[0].channel_lease_retired(anchor[1]):
                self._forget_resource_entry(entry)

    def release(self, operation: str, **values) -> None:
        """Release exactly one owned handle, retaining it when release fails."""
        self.release_with_result(operation, **values)

    def release_with_result(self, operation: str, **values):
        """Return the completed provider release result, consuming ownership once."""
        item = {"operation": operation, **values}
        view = getattr(self._device_calls, "view", None)
        entry = next(
            (
                entry
                for entry in self._resources
                if entry == item
                and self._same_device_view(self._resource_views.get(id(entry)), view)
            ),
            None,
        )
        if entry is None:
            raise ValueError("Resource is not owned by this runtime view")
        return self._release_resource_entry(entry)

    def _release_resource_entry(self, entry: dict):
        operation = entry["operation"]
        if not isinstance(operation, str) or not 0 < len(operation) <= 96:
            raise ValueError("Bounded primitive operation name required")
        anchor = self._resource_channel_anchors.get(id(entry))
        if anchor is not None:
            pair, lease, device = anchor
            if pair.channel_lease_retired(lease):
                self._forget_resource_entry(entry)
                return
            pair.validate_channel_lease(device, lease)
        self.cleanup_calls += 1
        if self.cleanup_calls > self.max_cleanup_calls:
            raise ValueError("Host cleanup call budget exceeded")
        started = self.clock()
        result = self._provider(
            operation, True, device_view=self._resource_views.get(id(entry))
        )(entry.copy(), self.cleanup_timeout)
        # A provider success consumes the resource before the elapsed-time check.
        # A genuinely failing provider leaves it owned for another attempt.
        self._forget_resource_entry(entry)
        if self.clock() - started >= self.cleanup_timeout:
            raise TimeoutError("CUW2026 cleanup primitive exceeded deadline")
        return result

    def own(self, operation: str, **values) -> None:
        """Register cleanup only after the corresponding acquisition succeeded."""
        if len(self._resources) >= 256:
            raise ValueError("Host resource budget exceeded")
        self._track_resource(
            {"operation": operation, **values}, self._channel_resource_anchor(operation)
        )

    def close(self) -> list[str]:
        """Attempt every release in reverse order, including after cancellation."""
        errors = []
        for item in reversed(tuple(self._resources)):
            try:
                self._release_resource_entry(item)
            except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - attempt all releases
                errors.append(type(exc).__name__)
        return errors


@dataclass
class NotificationBool:
    """Native CNotificationBool assignment/enable/disable behavior.

    Assignment always notifies, even when the value did not change. Native copy
    and move assignment copy the handler state without invoking the handler.
    """

    value: bool = False
    context: object = None
    handler: Callable[[object, bool], None] | None = None
    saved_handler: Callable[[object, bool], None] | None = None

    def __post_init__(self):
        if type(self.value) is not bool:
            raise ValueError("Native Boolean required")

    def __bool__(self):
        return self.value

    def assign(self, value: "bool | NotificationBool") -> "NotificationBool":
        if isinstance(value, NotificationBool):
            self.value, self.context, self.handler, self.saved_handler = (
                value.value,
                value.context,
                value.handler,
                value.saved_handler,
            )
        else:
            if type(value) is not bool:
                raise ValueError("Native Boolean required")
            self.value = value
            if self.context is not None and self.handler is not None:
                self.handler(self.context, value)
        return self

    def set_event_handler(
        self, context: object, handler: Callable[[object, bool], None] | None
    ) -> None:
        if handler is not None and not callable(handler):
            raise TypeError("Callable native event handler required")
        self.context, self.handler = context, handler

    def disable_event_handler(self) -> None:
        if self.handler is not None:
            self.saved_handler, self.handler = self.handler, None

    def enable_event_handler(self) -> None:
        if self.saved_handler is not None:
            self.handler = self.saved_handler

    def reset(self) -> None:
        self.value, self.context, self.handler, self.saved_handler = (
            False,
            None,
            None,
            None,
        )


def basic_conversion(seed: bytes, material: bytes) -> bytes:
    """CommonPrepare RVA10a0: preserve trailing half, XOR leading half."""
    if (
        not isinstance(seed, bytes)
        or len(seed) != 4
        or not isinstance(material, bytes)
        or len(material) < 2
    ):
        raise ValueError("Four-byte seed and two-byte conversion material required")
    return seed[2:4] + bytes((seed[0] ^ material[0], seed[1] ^ material[1]))


def seed_key_two_byte(seed: bytes, material: bytes) -> bytes:
    """CommonPrepare RVA10f0, native big-endian unsigned-short subtraction."""
    if any(
        not isinstance(value, bytes) or len(value) != 2 for value in (seed, material)
    ):
        raise ValueError("Two native two-byte values required")
    return (
        (int.from_bytes(material, "big") + ~int.from_bytes(seed, "big")) & 0xFFFF
    ).to_bytes(2, "big")


def seed_key_six_byte(seed: bytes) -> bytes:
    """CommonPrepare RVA11e0: sequential in-place six-byte transformation."""
    if not isinstance(seed, bytes) or len(seed) != 6:
        raise ValueError("Six-byte native seed required")
    value = bytearray(seed)
    for index, shift in enumerate((1, 2, 3, 3, 2, 1)):
        byte = seed[index]
        rotation = ((byte >> shift) & 3) + 1
        source = (byte & 7) % 6
        rotated = ((byte << rotation) | (byte >> (8 - rotation))) & 0xFF
        value[index] = (rotated + value[source]) & 0xFF
    return bytes(value)


def seed_key_four_round(seed: bytes, materials: tuple[bytes, ...]) -> bytes:
    """CommonPrepare RVA1390: four ordered BasicConversion rounds."""
    if not isinstance(materials, tuple) or len(materials) != 4:
        raise ValueError("Four native conversion materials required")
    for material in materials:
        seed = basic_conversion(seed, material)
    return seed


def cpu_bus_type(image: bytes, address: str = "") -> int:
    """CommonPrepare RVA1740:0/1 image byte,2 when address/value unavailable.

    Native strtol prefix/default conversion is retained; host bounds the read.
    """
    if not isinstance(image, bytes) or len(image) > 64 * 1024 * 1024:
        raise ValueError("Bounded CPU image required")
    if not address:
        return 2
    if not isinstance(address, str) or len(address) > 259:
        raise ValueError("Bounded native communication-speed address required")
    offset = _native_long(address, 16) or 0
    if not 0 <= offset < len(image):
        raise ValueError("Communication-speed address outside supplied CPU image")
    return image[offset] if image[offset] in (0, 1) else 2


def diagnostic_mask(runtime: NativeRuntime2026, wait_ms: int = 0) -> None:
    """CommonPrepare RVA1680: three raw mask writes followed by native waits."""
    if type(wait_ms) is not int or not 0 <= wait_ms <= 0xFFFFFFFF:
        raise ValueError("Native unsigned diagnostic mask wait required")
    for _ in range(3):
        CanDiag2026(runtime).write(bytes.fromhex("00000720a027"))
        runtime.call("wait", milliseconds=wait_ms)


class CommonResponseError(ValueError):
    """Native CPassThruException code, without private file paths or messages."""

    def __init__(self, code: int, response: bytes = b""):
        self.response = response
        self.code = code
        super().__init__(f"Native communication error {code}")


class CanDiag2026:
    """Recovered CanDiag communication over J2534 Data bytes, never a device.

    Provider read_specified_can_message returns immutable full Data (address +
    payload). The provider owns J2534 RxStatus filtering, not response semantics.
    """

    def __init__(self, runtime: NativeRuntime2026):
        self.runtime = runtime

    @staticmethod
    def phase6_addresses(target: bytes) -> tuple[bytes, bytes]:
        if not isinstance(target, bytes) or len(target) != 1:
            raise ValueError("One-byte native Phase6 target required")
        return b"\x18\xda" + target + b"\xe0", b"\x18\xda\xe0" + target

    def assign(self, other: "CanDiag2026") -> "CanDiag2026":
        """1020/1040 copy callback/device pointers; neither form clears the source."""
        if type(other) is not CanDiag2026:
            raise TypeError("Concrete native diagnostic utility required")
        self.runtime = other.runtime
        return self

    def write(self, data: bytes, tx_flags: int = 0) -> None:
        if not isinstance(data, bytes) or not 4 < len(data) <= 4128:
            raise ValueError("Bounded J2534 CAN Data required")
        count = self.runtime.call(
            "write_messages", protocol=6, tx_flags=tx_flags, data=data, count=1
        )
        if type(count) is not int or count != 1:
            raise ValueError("J2534 primitive must report one written message")

    def start_filter(self, request_address: bytes, response_address: bytes) -> int:
        self._addresses(request_address, response_address)
        identifier = self.runtime.acquire(
            "start_flow_control_filter",
            "stop_filter",
            request_address=request_address,
            response_address=response_address,
        )
        if type(identifier) is not int or not 0 <= identifier <= 0xFFFFFFFF:
            raise ValueError("Native unsigned filter identifier required")
        return identifier

    @staticmethod
    def _addresses(request: bytes, response: bytes) -> None:
        if any(
            not isinstance(v, bytes) or len(v) not in (4, 5)
            for v in (request, response)
        ) or len(request) != len(response):
            raise ValueError("Matching four/five-byte native CAN addresses required")

    def set_block_size(self, size: int) -> None:
        if type(size) is not int or not 0 <= size <= 255:
            raise ValueError("Native ECU block size byte required")
        self.runtime.call("control_io", ioctl=2, parameters=((0x1E, size),))

    def call(
        self,
        request_address: bytes,
        response_address: bytes,
        payload: bytes,
        expected: bytes | None,
        *,
        minimum: int = 0,
        error_code: int = 9999,
        phase5: bool = False,
        delay_ms: int = 0,
        pending_limit: int = 0x95,
        busy_limit: int = 0xFF,
        send_tester_present: bool = True,
        pending_timeout_ms: int = 5000,
        tx_flags: int = 0,
        unified_utils: bool = False,
        receive_only: bool = False,
        check_native_cancel: bool = False,
    ) -> bytes:
        self._addresses(request_address, response_address)
        if not isinstance(payload, bytes) or not 0 < len(payload) <= 4128 - len(
            request_address
        ):
            raise ValueError("Bounded native CAN payload required")
        if expected is not None and (
            not isinstance(expected, bytes)
            or not 0 < len(expected) <= 4128 - len(request_address)
        ):
            raise ValueError("Bounded expected response prefix required")
        if any(
            type(v) is not int or not 0 <= v <= 0xFFFFFFFF
            for v in (
                minimum,
                error_code,
                delay_ms,
                pending_limit,
                busy_limit,
                pending_timeout_ms,
                tx_flags,
            )
        ):
            raise ValueError("Native unsigned communication options required")
        if minimum > 4128 - len(request_address):
            raise ValueError("Native minimum outside message bounds")
        if any(
            type(value) is not bool
            for value in (
                phase5,
                unified_utils,
                receive_only,
                send_tester_present,
                check_native_cancel,
            )
        ):
            raise ValueError("Native communication Boolean flags required")
        lock_transactions = phase5 or unified_utils
        rt = self.runtime
        if check_native_cancel and rt.native_cancelled is None:
            raise ValueError("Native receive cancellation callback is not bound")
        previous = rt.call("get_timeout")
        if type(previous) is not int or not 0 <= previous <= 0xFFFFFFFF:
            raise ValueError(
                "Native timeout primitive must return unsigned milliseconds"
            )
        flags = tx_flags | (0x80 if len(request_address) == 5 else 0)
        locked = False

        def lock():
            nonlocal locked
            rt.call_owned("lock", "unlock")
            locked = True

        def unlock():
            nonlocal locked
            if locked:
                try:
                    rt.release("unlock")
                finally:
                    # Success, including a late success, has consumed ownership.
                    locked = False

        failure = None
        try:
            busy = 0
            while True:
                if lock_transactions:
                    lock()
                if not receive_only:
                    self.write(request_address + payload, flags)
                    rt.call("wait", milliseconds=delay_ms)
                pending = 0
                pending_started = None
                pending_local_start = None
                timeout_count = 0
                while True:
                    if check_native_cancel:
                        rt.check_native_cancelled()
                    if lock_transactions and pending_started is not None:
                        lock()
                    try:
                        try:
                            response = rt.call(
                                "read_specified_can_message",
                                address=response_address,
                                count=1,
                                frame=2,
                            )
                        finally:
                            if lock_transactions and pending_started is not None:
                                unlock()
                    except NativeTransportError as exc:
                        if (
                            not lock_transactions
                            or pending_started is None
                            or exc.code not in (9, 16)
                        ):
                            raise
                        timeout_count += 1
                        maximum = (
                            max(previous, 5000 if unified_utils else busy_limit) // 1000
                        )
                        if timeout_count >= maximum:
                            raise
                        if timeout_count == maximum - 1:
                            rt.call(
                                "set_timeout",
                                milliseconds=(
                                    max(previous, 5000 if unified_utils else busy_limit)
                                    % 1000
                                )
                                + 1000,
                            )
                        continue
                    if (
                        not isinstance(response, bytes)
                        or not len(request_address) <= len(response) <= 4128
                        or not response.startswith(response_address)
                    ):
                        raise ValueError(
                            "Malformed or incorrectly addressed native CAN read"
                        )
                    data = response[len(request_address) :]
                    if len(data) < 3 or data[:3] != bytes((0x7F, payload[0], 0x78)):
                        break
                    pending += 1
                    timeout_count = 0
                    if lock_transactions and pending_started is None:
                        if phase5:
                            pending_local_start = rt.read_local_seconds_of_day()
                        pending_started = 0.0 if phase5 else rt.clock()
                        unlock()
                    if phase5:
                        if pending_local_start is None:
                            raise AssertionError(
                                "Native Phase5 pending start was not captured"
                            )
                        current = rt.read_local_seconds_of_day()
                        if current // 3600 < pending_local_start // 3600:
                            current += 86400
                        exhausted = (
                            (current - pending_local_start) & 0xFFFFFFFF
                        ) >= pending_limit
                    else:
                        exhausted = pending > pending_limit
                        busy = 0
                    if exhausted:
                        if send_tester_present or unified_utils or receive_only:
                            if lock_transactions:
                                lock()
                            try:
                                self.write(
                                    request_address
                                    + (b"\x3e\x00" if phase5 else b"\x3e"),
                                    flags,
                                )
                            finally:
                                if lock_transactions:
                                    unlock()
                        raise CommonResponseError(error_code, data)
                    if lock_transactions:
                        rt.call("set_timeout", milliseconds=1000)
                    elif previous < 5000:
                        rt.call("set_timeout", milliseconds=pending_timeout_ms)
                unlock()
                rt.call("set_timeout", milliseconds=previous)
                if (
                    not phase5
                    and not receive_only
                    and len(data) >= 3
                    and data[:3] == bytes((0x7F, payload[0], 0x21))
                ):
                    busy += 1
                    if busy > busy_limit:
                        raise CommonResponseError(error_code, data)
                    continue
                if len(data) < minimum or (
                    expected is not None and not data.startswith(expected)
                ):
                    raise CommonResponseError(error_code, data)
                return data
        except (Exception, KeyboardInterrupt) as error:
            failure = error
            raise
        finally:
            cleanup_failure = None
            for cleanup in (
                unlock,
                lambda: rt.call("set_timeout", cleanup=True, milliseconds=previous),
            ):
                try:
                    cleanup()
                except (Exception, KeyboardInterrupt) as error:  # noqa: BLE001 - both native restorations are required
                    if failure is not None:
                        failure.add_note(
                            "Native diagnostic cleanup failure: " + type(error).__name__
                        )
                    elif cleanup_failure is None:
                        cleanup_failure = error
                    else:
                        cleanup_failure.add_note(
                            "Native diagnostic cleanup failure: " + type(error).__name__
                        )
            if failure is None and cleanup_failure is not None:
                raise cleanup_failure

    def receive(
        self,
        request_address: bytes,
        response_address: bytes,
        request_payload: bytes,
        expected: bytes | None,
        *,
        minimum: int = 0,
        error_code: int = 9999,
        pending_limit: int = 0,
        check_native_cancel: bool = False,
    ) -> bytes:
        return self.call(
            request_address,
            response_address,
            request_payload,
            expected,
            minimum=minimum,
            error_code=error_code,
            pending_limit=pending_limit,
            receive_only=True,
            check_native_cancel=check_native_cancel,
        )

    def call_phase6(
        self,
        target: bytes,
        payload: bytes,
        expected: bytes | None,
        *,
        minimum: int = 0,
        error_code: int = 9999,
        pending_limit: int = 0xB4,
        check_native_cancel: bool = False,
    ) -> bytes:
        request, response = self.phase6_addresses(target)
        return self.call(
            request,
            response,
            payload,
            expected,
            minimum=minimum,
            error_code=error_code,
            phase5=True,
            pending_limit=pending_limit,
            busy_limit=0x159A,
            tx_flags=0x100,
            check_native_cancel=check_native_cancel,
        )


class Unified2026:
    """Source-backed UnifiedUtils operations; crypto stays an authorized primitive.

    Crypto callbacks compute a specified cryptographic operation on explicit
    material. They never assert that a gateway or programming step succeeded.
    """

    def __init__(self, runtime: NativeRuntime2026):
        self.runtime = runtime
        self.diag = CanDiag2026(runtime)

    def assign(self, other: "Unified2026") -> None:
        if not isinstance(other, Unified2026):
            raise TypeError("Native UnifiedUtils binding required")
        self.runtime, self.diag = other.runtime, other.diag

    def _require_native_cancel_binding(self) -> None:
        if self.runtime.native_cancelled is None:
            raise ValueError("Native cancellation callback binding required")

    def calc_seed_key(
        self, client: "SecretInfoClient", service_auth_key: bytes, seed: bytes
    ) -> bytes:
        return security_up_key(self.runtime, client, seed, service_auth_key)

    def send_request(
        self,
        request: bytes,
        response: bytes,
        payload: bytes,
        expected: bytes | None,
        *,
        minimum: int = 0,
        error_code: int = 9999,
        delay_ms: int = 0,
        pending_limit: int = 149,
        busy_limit: int = 255,
        check_native_cancel: bool = False,
    ) -> bytes:
        return self.diag.call(
            request,
            response,
            payload,
            expected,
            minimum=minimum,
            error_code=error_code,
            delay_ms=delay_ms,
            pending_limit=pending_limit,
            check_native_cancel=check_native_cancel,
            busy_limit=busy_limit,
            unified_utils=True,
        )

    def send_request_phase6(
        self,
        target: bytes,
        payload: bytes,
        expected: bytes | None,
        *,
        minimum: int = 0,
        error_code: int = 9999,
        pending_limit: int = 180,
        check_native_cancel: bool = False,
    ) -> bytes:
        return self.diag.call_phase6(
            target,
            payload,
            expected,
            minimum=minimum,
            error_code=error_code,
            pending_limit=pending_limit,
            check_native_cancel=check_native_cancel,
        )

    @contextmanager
    def filtered(self, request: bytes, response: bytes):
        identifier = self.diag.start_filter(request, response)
        failure = None
        try:
            yield
        except (Exception, KeyboardInterrupt) as error:
            failure = error
            raise
        finally:
            try:
                self.runtime.release("stop_filter", identifier=identifier)
            except (Exception, KeyboardInterrupt) as error:
                if failure is None:
                    raise
                failure.add_note(
                    "Native filter cleanup failure: " + type(error).__name__
                )

    @contextmanager
    def block_size_filtered(self, request: bytes, response: bytes):
        """Restore block size before stopping this helper's filter; attempt both."""
        release = {"ioctl": 2, "parameters": ((0x1E, 0),)}
        self.runtime.call_owned(
            "control_io",
            "control_io",
            release_values=release,
            ioctl=2,
            parameters=((0x1E, 1),),
        )
        identifier = None
        failure = None
        original_failure = False
        try:
            identifier = self.diag.start_filter(request, response)
            yield
        except (Exception, KeyboardInterrupt) as error:
            failure, original_failure = error, True
            raise
        finally:
            cleanups = [("control_io", release)]
            if identifier is not None:
                cleanups.append(("stop_filter", {"identifier": identifier}))
            for operation, values in cleanups:
                try:
                    self.runtime.release(operation, **values)
                except (Exception, KeyboardInterrupt) as error:  # noqa: BLE001 - attempt both releases
                    if failure is None:
                        failure = error
                    else:
                        failure.add_note(
                            "Native helper cleanup failure: " + type(error).__name__
                        )
            if failure is not None and not original_failure:
                raise failure

    @contextmanager
    def phase6_filtered(self, target: bytes):
        with self.filtered(*self.diag.phase6_addresses(target)):
            yield

    @staticmethod
    def calc_millisecond(hour: int, minute: int, second: int, millisecond: int) -> int:
        if any(
            type(value) is not int for value in (hour, minute, second, millisecond)
        ) or not (
            0 <= hour < 24
            and 0 <= minute < 60
            and 0 <= second < 60
            and 0 <= millisecond < 1000
        ):
            raise ValueError("Valid native local clock fields required")
        return ((hour * 60 + minute) * 60 + second) * 1000 + millisecond

    @staticmethod
    def calc_elapsed_time(start: datetime, end: datetime) -> int:
        """Positive SYSTEMTIME/FILETIME whole seconds, native unsigned result."""
        if any(
            not isinstance(value, datetime)
            or value.tzinfo is not None
            or value.year < 1601
            or value.microsecond % 1000
            for value in (start, end)
        ):
            raise ValueError("Valid millisecond Windows SYSTEMTIME values required")
        difference = end - start
        return (
            max(0, difference.days * 86400 + difference.seconds) & 0xFFFFFFFF
            if end > start
            else 0
        )

    @staticmethod
    def get_passed_time(start: int, current: int) -> int:
        """Explicit local-clock sample with the native one-midnight wrap."""
        if any(
            type(value) is not int or not 0 <= value < 86400000
            for value in (start, current)
        ):
            raise ValueError("Native milliseconds within local day required")
        return current - start + (86400000 if current < start else 0)

    def read_software_id(self, request: bytes, response: bytes) -> bytes:
        """UnifiedUtils47f0: ordinary Phase5 DID F181 request."""
        self._require_native_cancel_binding()
        return self.diag.call(
            request,
            response,
            bytes.fromhex("22f181"),
            bytes.fromhex("62f181"),
            minimum=4,
            error_code=3,
            phase5=True,
            pending_limit=180,
            busy_limit=0x159A,
            check_native_cancel=True,
        )

    def check_rid(self, request: bytes, response: bytes) -> bytes:
        """UnifiedUtils22a0: routine1000 start request."""
        return self.diag.call(
            request,
            response,
            bytes.fromhex("31011000"),
            bytes.fromhex("71011000"),
            minimum=4,
            error_code=3,
            phase5=True,
            pending_limit=180,
            busy_limit=0x159A,
        )

    def read_rob(self, request: bytes, response: bytes, rob: int) -> bytes:
        """UnifiedUtils46f0: native two-byte AB service."""
        if type(rob) is not int or not 0 <= rob <= 255:
            raise ValueError("Native RoB byte required")
        return self.diag.call(
            request,
            response,
            bytes((0xAB, rob)),
            bytes((0xEB, rob)),
            minimum=2,
            error_code=0x5B,
            phase5=True,
            pending_limit=180,
            busy_limit=0x159A,
        )

    def ordinary_session(
        self, request: bytes, response: bytes, *, extended: bool = False
    ) -> bytes:
        """UnifiedUtils3230/39d0: filtered default/extended session."""
        self._require_native_cancel_binding()
        if self.runtime.native_cancellation_requested():
            return b""
        if type(extended) is not bool:
            raise ValueError("Native session selection Boolean required")
        mode = 3 if extended else 1
        with self.filtered(request, response):
            return self.diag.call(
                request,
                response,
                bytes((0x10, mode)),
                bytes((0x50, mode)),
                minimum=6,
                error_code=0x58 if extended else 0x29,
                phase5=True,
                pending_limit=180,
                busy_limit=0x159A,
                check_native_cancel=True,
            )

    def read_programming_mode_control_state(self) -> int:
        """UnifiedUtils43d0: DID1005 response low status bit."""
        request, response = bytes.fromhex("00000751"), bytes.fromhex("00000761")
        with self.filtered(request, response):
            data = self.diag.call(
                request,
                response,
                bytes.fromhex("221005"),
                bytes.fromhex("621005"),
                minimum=4,
                error_code=0x3FA,
                phase5=True,
                pending_limit=180,
                busy_limit=0x159A,
            )
        return data[3] & 1

    def central_gateway_session(self, *, programming: bool = False) -> bytes:
        """P4 central gateway default session or change-mode request."""
        if type(programming) is not bool:
            raise ValueError("Native gateway session Boolean required")
        request, response = bytes.fromhex("000007505f"), bytes.fromhex("000007585f")
        with self.filtered(request, response):
            return self.diag.call(
                request,
                response,
                bytes((0x10, 0x60 if programming else 1)),
                b"\x50",
                minimum=1,
                error_code=0x32 if programming else 0x3F9,
                unified_utils=True,
                send_tester_present=False,
            )

    def collate_seed_key_central_gateway(self) -> None:
        """Native central wire flow; source-issued slot20 AES can bind internally."""
        request, response = bytes.fromhex("000007505f"), bytes.fromhex("000007585f")
        with self.block_size_filtered(request, response):
            seed_response = self.diag.call(
                request,
                response,
                bytes.fromhex("2751"),
                bytes.fromhex("6751"),
                minimum=18,
                error_code=0x10,
                unified_utils=True,
                send_tester_present=False,
            )
            key = self.runtime.call(
                "calculate_central_gateway_key", seed=seed_response[2:18]
            )
            if not isinstance(key, bytes) or len(key) != 16:
                raise ValueError("Central gateway crypto must return sixteen bytes")
            self.runtime.call("wait", milliseconds=100)
            self.diag.call(
                request,
                response,
                bytes.fromhex("2752") + key,
                bytes.fromhex("675234"),
                minimum=3,
                error_code=0x11,
                unified_utils=True,
                send_tester_present=False,
            )

    def smc_gateway_key(self, seed: bytes) -> bytes:
        """CalculationHmacAPI input is the literal11 byte followed by seed32."""
        if not isinstance(seed, bytes) or len(seed) != 32:
            raise ValueError("Native SMC seed32 required")
        if self.runtime._smc_hmac is None:
            raise ValueError("Source-issued native SMC HMAC binding required")
        return self.smc_gateway_key_loaded(seed)

    def smc_gateway_key_loaded(self, seed: bytes) -> bytes:
        """3f80: load, resolve, invoke exact HMAC export, then free the library."""
        if not isinstance(seed, bytes) or len(seed) != 32:
            raise ValueError("Native SMC seed32 required")
        rt = self.runtime
        library = rt.acquire(
            "load_smc_hmac_library", "free_smc_hmac_library", null_is_failure=True
        )
        if not library:
            raise NativePassThruException2026(
                0x11, "TCUWUnifiedUtils.dll:RVA8210", 0xB87
            )
        failure = None
        try:
            symbol = rt.call(
                "resolve_smc_hmac_export", library=library, name="MakeSendKeyCGWHmac"
            )
            if type(symbol) is not int or not 0 <= symbol <= 0xFFFFFFFF:
                raise ValueError("Native SMC export address must be unsigned")
            if not symbol:
                raise NativePassThruException2026(
                    0x11, "TCUWUnifiedUtils.dll:RVA8210", 0xB96
                )
            result = rt.call(
                "invoke_smc_hmac_export",
                library=library,
                symbol=symbol,
                data=b"\x11" + seed,
            )
            if result is not False and (
                not isinstance(result, bytes) or len(result) != 32
            ):
                raise ValueError("SMC HMAC export must return32 bytes or False")
        except (Exception, KeyboardInterrupt) as error:
            failure = error
            raise
        finally:
            try:
                rt.release("free_smc_hmac_library", identifier=library)
            except (Exception, KeyboardInterrupt) as error:
                if failure is None:
                    raise
                failure.add_note("SMC library release failure: " + type(error).__name__)
        if result is False:
            raise CommonResponseError(0x11)
        return result

    def collate_seed_key_smc_gateway(self) -> None:
        request, response = bytes.fromhex("00000751"), bytes.fromhex("00000761")
        with self.filtered(request, response):
            seed_response = self.diag.call(
                request,
                response,
                bytes.fromhex("2711"),
                bytes.fromhex("6711"),
                minimum=34,
                error_code=0x10,
                phase5=True,
                pending_limit=180,
                busy_limit=0x159A,
            )
            key = self.smc_gateway_key(seed_response[2:34])
            self.diag.call(
                request,
                response,
                bytes.fromhex("2712") + key,
                bytes.fromhex("6712"),
                minimum=2,
                error_code=0x11,
                phase5=True,
                pending_limit=180,
                busy_limit=0x159A,
            )

    def routine_smc_gateway(self, routine: int) -> None:
        if type(routine) is not int or not -0x80000000 <= routine <= 0x7FFFFFFF:
            raise ValueError("Native signed routine enum required")
        subtype, middle, final, error = (
            (1, 0xC0, 1, 0x31)
            if routine == 2
            else ((2, 0xC0, 1, 0x3FB) if routine == 4 else (0, 0, 0, 9999))
        )
        request, response = bytes.fromhex("00000751"), bytes.fromhex("00000761")
        with self.filtered(request, response):
            self.diag.call(
                request,
                response,
                bytes((0x31, subtype, middle, final, 0)),
                bytes((0x71, subtype, middle, final)),
                minimum=4,
                error_code=error,
                phase5=True,
                pending_limit=180,
                busy_limit=0x159A,
            )

    @staticmethod
    def _charge_local_bus_payload(routine: int) -> bytes:
        if type(routine) is not int or not -0x80000000 <= routine <= 0x7FFFFFFF:
            raise ValueError("Native signed charge-bus routine enum required")
        return (
            bytes((0x31, routine + 1, 0x11, 0x7E))
            if routine in (0, 1)
            else bytes.fromhex("31000000")
        )

    def routine_charge_local_bus(
        self,
        request: bytes,
        response: bytes,
        routine: int,
        *,
        start_filter: bool = True,
    ) -> None:
        """Native charge-local-bus wire routine, with mandatory host cancellation."""
        self.runtime.check()
        self._require_native_cancel_binding()
        if self.runtime.native_cancellation_requested():
            return
        if type(start_filter) is not bool:
            raise ValueError("Native filter selection Boolean required")
        payload = self._charge_local_bus_payload(routine)
        with self.filtered(request, response) if start_filter else nullcontext():
            self.diag.call(
                request,
                response,
                payload,
                b"\x71" + payload[1:],
                minimum=4,
                error_code=0x19,
                phase5=True,
                pending_limit=180,
                busy_limit=0x159A,
                check_native_cancel=True,
            )

    def routine_charge_local_bus_phase6(self, routine: int) -> None:
        self.runtime.check()
        self._require_native_cancel_binding()
        if self.runtime.native_cancellation_requested():
            return
        payload = self._charge_local_bus_payload(routine)
        # Native static CBytes constructor binds the exported target to hex49.
        with self.phase6_filtered(b"\x49"):
            self.diag.call_phase6(
                b"\x49",
                payload,
                b"\x71" + payload[1:],
                minimum=4,
                error_code=0x19,
                check_native_cancel=True,
            )

    def judge_repro_gateway_node(self, repro_sequence: int = 0) -> int:
        """CommonPrepare RVA1820: sequence1 skips the older tester-present probe."""
        if type(repro_sequence) is not int or not 0 <= repro_sequence <= 0xFFFFFFFF:
            raise ValueError("Native reprogramming sequence required")
        request, response = bytes.fromhex("000007505f"), bytes.fromhex("000007585f")
        with self.filtered(request, response):
            if repro_sequence != 1:
                try:
                    self.diag.call(
                        request, response, b"\x3e", b"\x7e", minimum=1, error_code=0x50
                    )
                    return 2
                except NativeTransportError as exc:
                    if exc.code not in (9, 16):
                        raise
                except CommonResponseError as exc:
                    if exc.response == bytes.fromhex("7f3e78"):
                        raise
            self.diag.call(
                request,
                response,
                b"\x3e\x00",
                b"\x7e\x00",
                minimum=2,
                error_code=0x4F,
                phase5=True,
                pending_limit=0xB4,
                busy_limit=0x159A,
            )
            return 1

    def change_mode(self, mode: int, request: bytes, response: bytes) -> bytes:
        if type(mode) is not int or not 0 <= mode <= 0xFFFFFFFF:
            raise ValueError("Native change-mode enum required")
        return self.diag.call(
            request,
            response,
            b"\x10" + bytes((2 if mode == 0 else 0x60,)),
            b"\x50",
            minimum=1,
            error_code=0x12 if mode == 0 else 0x31,
        )

    def cancel_automatic_ig_off(
        self, allow_target_failure: bool = False, target: bytes | None = None
    ) -> None:
        if type(allow_target_failure) is not bool or (
            target is not None and not isinstance(target, bytes)
        ):
            raise ValueError("Native Boolean/target required")
        active = allow_target_failure and target is not None
        if not self.cancel_automatic_ig_off_phase6(active and target == b"\x72"):
            self.cancel_automatic_ig_off_phase4_5(
                active and target == bytes.fromhex("0750e9")
            )

    def cancel_automatic_ig_off_phase4_5(self, allow_failure: bool = False) -> None:
        if type(allow_failure) is not bool:
            raise ValueError("Native Boolean required")
        request, response = bytes.fromhex("00000750e9"), bytes.fromhex("00000758e9")
        with self.filtered(request, response):
            try:
                data = self.diag.call(
                    request,
                    response,
                    bytes.fromhex("222001"),
                    bytes.fromhex("622001"),
                    minimum=5,
                    error_code=0x57,
                    phase5=True,
                    pending_limit=0xB4,
                    busy_limit=0x159A,
                )
            except NativeTransportError as exc:
                if exc.code not in (9, 16):
                    raise
                return
            except CommonResponseError as exc:
                if allow_failure:
                    return
                if exc.response != bytes.fromhex("7f2211"):
                    raise
                try:
                    self.diag.call(
                        request,
                        response,
                        bytes.fromhex("1070"),
                        b"\x50",
                        minimum=1,
                        error_code=0x4E,
                    )
                except CommonResponseError as fallback:
                    if fallback.response not in (
                        bytes.fromhex("7f1011"),
                        bytes.fromhex("7f1012"),
                        bytes.fromhex("7f1013"),
                    ):
                        raise
                return
            self.diag.call(
                request,
                response,
                bytes.fromhex("2e2001") + bytes((data[3], data[4] | 0x40)),
                bytes.fromhex("6e2001"),
                minimum=3,
                error_code=0x4E,
                phase5=True,
                pending_limit=0xB4,
                busy_limit=0x159A,
            )

    def collate_seed_key_phase5_gateway(self) -> None:
        request, response = bytes.fromhex("000007505f"), bytes.fromhex("000007585f")
        with self.block_size_filtered(request, response):
            retried = False
            while True:
                try:
                    seed = self.diag.call(
                        request,
                        response,
                        bytes.fromhex("2721"),
                        bytes.fromhex("6721"),
                        minimum=18,
                        error_code=0x10,
                        phase5=True,
                        pending_limit=0xB4,
                        busy_limit=0x159A,
                    )
                except CommonResponseError as exc:
                    if exc.response in (
                        bytes.fromhex("7f2712"),
                        bytes.fromhex("7f277f"),
                    ):
                        raise CommonResponseError(0x17, exc.response) from exc
                    if exc.response == bytes.fromhex("7f2737") and not retried:
                        self.runtime.call("wait", milliseconds=10000)
                        retried = True
                        continue
                    raise
                key = self.runtime.call("calculate_p5_gateway_key", seed=seed[2:18])
                if not isinstance(key, bytes) or len(key) != 256:
                    raise CommonResponseError(0x11)
                try:
                    self.diag.call(
                        request,
                        response,
                        bytes.fromhex("2722") + key,
                        bytes.fromhex("6722"),
                        minimum=2,
                        error_code=0x11,
                        phase5=True,
                        pending_limit=0xB4,
                        busy_limit=0x159A,
                    )
                except CommonResponseError as exc:
                    if exc.response in (
                        bytes.fromhex("7f2713"),
                        bytes.fromhex("7f2735"),
                        bytes.fromhex("7f2736"),
                    ):
                        raise CommonResponseError(0x60, exc.response) from exc
                    raise
                break

    def default_session_phase6(self, target: bytes) -> bytes:
        self._require_native_cancel_binding()
        if self.runtime.native_cancellation_requested():
            return b""
        with self.phase6_filtered(target):
            return self.diag.call_phase6(
                target,
                b"\x10\x01",
                b"\x50\x01",
                minimum=6,
                error_code=0x29,
                check_native_cancel=True,
            )

    def extended_session_phase6(self, target: bytes) -> bytes:
        self._require_native_cancel_binding()
        if self.runtime.native_cancellation_requested():
            return b""
        with self.phase6_filtered(target):
            return self.diag.call_phase6(
                target,
                b"\x10\x03",
                b"\x50\x03",
                minimum=6,
                error_code=0x58,
                check_native_cancel=True,
            )

    def ecu_reset_phase6(self, target: bytes) -> None:
        request, _response = self.diag.phase6_addresses(target)
        self.diag.write(request + b"\x11\x01", 0x100)

    @staticmethod
    def extract_user_defined_dtcs(response: bytes) -> tuple[bytes, ...]:
        """RVA3ec0:4-byte response header, then uninterpreted4-byte records."""
        if (
            not isinstance(response, bytes)
            or not 4 <= len(response) <= 4124
            or (len(response) - 4) % 4
        ):
            raise CommonResponseError(0x3FF)
        return tuple(
            response[offset : offset + 4] for offset in range(4, len(response), 4)
        )

    def get_user_defined_dtcs(self, target: bytes) -> tuple[bytes, ...]:
        self._require_native_cancel_binding()
        if self.runtime.native_cancellation_requested():
            return ()
        with self.phase6_filtered(target):
            response = self.diag.call_phase6(
                target,
                bytes.fromhex("19170112"),
                bytes.fromhex("591712"),
                minimum=4,
                error_code=0x3FF,
                check_native_cancel=True,
            )
            if self.runtime.native_cancellation_requested():
                return ()
            return self.extract_user_defined_dtcs(response)

    def routine_phase5_gateway(self, mode: int) -> bytes:
        if type(mode) is not int or mode not in range(4):
            raise ValueError("Recovered gateway routine mode0..3 required")
        subfunction = 1 if mode in (0, 2) else 3
        routine = 0x11 if mode in (0, 1) else 0x12
        request, response = bytes.fromhex("000007505f"), bytes.fromhex("000007585f")
        payload = bytes((0x31, subfunction, 0x10, routine))
        expected = bytes((0x71, subfunction, 0x10, routine)) + (
            b"\x01" if subfunction == 3 else b""
        )
        with self.filtered(request, response):
            return self.diag.call(
                request,
                response,
                payload,
                expected,
                minimum=len(expected),
                phase5=True,
                pending_limit=0xB4,
                busy_limit=0x159A,
                error_code=(0x51, 0x52, 0x31, 0x53)[mode],
            )

    def cancel_automatic_ig_off_phase6(self, allow_failure: bool = False) -> bool:
        if type(allow_failure) is not bool:
            raise ValueError("Native Boolean required")
        target = b"\x72"
        with self.phase6_filtered(target):
            try:
                response = self.diag.call_phase6(
                    target,
                    bytes.fromhex("222103"),
                    bytes.fromhex("622103"),
                    minimum=5,
                    error_code=0x57,
                )
                if response[3] & 1:
                    self.diag.call_phase6(
                        target,
                        bytes.fromhex("2e2103") + bytes((response[3], response[4] | 1)),
                        bytes.fromhex("6e2103"),
                        minimum=3,
                        error_code=0x4E,
                    )
                return True
            except NativeTransportError as exc:
                if exc.code not in (9, 16):
                    raise
                return False
            except CommonResponseError:
                if not allow_failure:
                    raise
                return False

    def stop_ota_reprogramming(self) -> None:
        """RVA5c70: CAN switch, start/poll DB05, bounded180-second native wait."""
        previous = self.runtime.call("get_protocol_id")
        if type(previous) is not int or not 0 <= previous <= 0xFFFFFFFF:
            raise ValueError("Native protocol identifier required")
        switched = previous == 0x800F
        if switched:
            self.runtime.call_owned(
                "switch_connection",
                "switch_connection",
                release_values={"protocol": previous},
                protocol=6,
            )
        failure = None
        try:
            try:
                with self.phase6_filtered(b"\x1c"):
                    started = None
                    while True:
                        self.diag.call_phase6(
                            b"\x1c",
                            bytes.fromhex("3101db05"),
                            bytes.fromhex("7101db05"),
                            minimum=4,
                            error_code=0x400,
                        )
                        self.runtime.call("wait", milliseconds=10000)
                        response = self.diag.call_phase6(
                            b"\x1c",
                            bytes.fromhex("3103db05"),
                            bytes.fromhex("7103db05"),
                            minimum=6,
                            error_code=0x401,
                        )
                        if response[5] != 3:
                            break
                        if started is None:
                            started = self.runtime.read_local_milliseconds_of_day()
                        current = self.runtime.read_local_milliseconds_of_day()
                        elapsed = (
                            current - started + (86400000 if current < started else 0)
                        )
                        if elapsed > 180000:
                            break
                        self.runtime.call("wait", milliseconds=1000)
            except NativeTransportError as exc:
                if exc.code not in (9, 16):
                    raise
            except CommonResponseError:
                pass
        except (Exception, KeyboardInterrupt) as error:
            failure = error
            raise
        finally:
            if switched:
                try:
                    self.runtime.release("switch_connection", protocol=previous)
                except (Exception, KeyboardInterrupt) as error:
                    if failure is None:
                        raise
                    failure.add_note(
                        "Native OTA connection restoration failure: "
                        + type(error).__name__
                    )


_SECRET_INFO_CLIENTS: WeakValueDictionary[int, "SecretInfoClient"] = (
    WeakValueDictionary()
)


@dataclass(repr=False, frozen=True)
class SecretInfoClient:
    """SecretInfo native client binding with private, caller-supplied module bytes.

    Original authorization bytes and records are never included in repr/reports.
    An unrecognized client receives the native empty fallback, not a working key.
    """

    _client: bytes = field(repr=False)
    _records: tuple[tuple[int, bytes], ...] = field(repr=False)
    source_sha256: str
    _authorized: bool = field(default=False, init=False, repr=False)

    def __repr__(self) -> str:
        return "SecretInfoClient(<private native binding>)"

    @classmethod
    def from_native_modules(
        cls, secret_info_bytes: bytes, cuw_bytes: bytes
    ) -> "SecretInfoClient":
        """Bind the exact native CUW authorization call to its SecretInfo module.

        Neither caller authorization material nor a key is accepted as input.
        Native client bytes are read privately from the authenticated call site.
        """
        if (
            not isinstance(cuw_bytes, bytes)
            or not 0 < len(cuw_bytes) <= 64 * 1024 * 1024
        ):
            raise ValueError("Bounded immutable native CUW inspection bytes required")
        identity = identify_native_module(
            hashlib.sha256(cuw_bytes).hexdigest(), "CUW.dll"
        )
        if (
            identity.cuw_build != "2026"
            or identity.artifact_form != "reconstructed-inspection"
        ):
            raise ValueError("Exact reconstructed2026 CUW caller required")
        client = cls.from_native_module(secret_info_bytes)
        # Authenticated CUW call-site pushes its client string, then invokes the
        # imported AuthorizeSecretInfo; image offsets equal recovered RVAs.
        offset = 0x34087
        if (
            cuw_bytes[offset] != 0x68
            or cuw_bytes[offset + 5 : offset + 7] != b"\xff\x15"
        ):
            raise ValueError("Native SecretInfo authorization call-site layout differs")
        address = struct.unpack_from("<I", cuw_bytes, offset + 1)[0] - 0x10000000
        if not 0 <= address < len(cuw_bytes):
            raise ValueError("Native authorization string pointer outside image")
        end = cuw_bytes.find(b"\0", address, min(address + 16, len(cuw_bytes)))
        if end < 0:
            raise ValueError("Native authorization string is not bounded")
        client.authorize(cuw_bytes[address:end])
        if not client._authorized:
            raise PermissionError("Native CUW client authorization was rejected")
        return client

    @classmethod
    def from_native_module(cls, data: bytes) -> "SecretInfoClient":
        if not isinstance(data, bytes) or len(data) > 16 * 1024 * 1024:
            raise ValueError("Bounded immutable native module bytes required")
        digest = hashlib.sha256(data).hexdigest()
        identity = identify_native_module(digest, "SecretInfo.dll")
        if (
            identity.cuw_build != "2026"
            or identity.artifact_form != "reconstructed-inspection"
        ):
            raise ValueError("Exact reconstructed2026 SecretInfo module required")
        # Exact authenticated inspection PE uses image RVA == file offset.
        length, capacity = struct.unpack_from("<II", data, 0xC010)
        if not 0 <= length <= 15 or capacity != 15:
            raise ValueError("Native SecretInfo client string layout differs")
        records = []
        for index in range(64):
            start = 0x30A8 + index * 0x208
            text = data[start : start + 0x200]
            terminator = text.find(b"\0")
            if terminator < 0:
                raise ValueError("Native SecretInfo record has no terminator")
            records.append(
                (struct.unpack_from("<I", data, start + 0x204)[0], text[:terminator])
            )
        binding = cls(data[0xC000 : 0xC000 + length], tuple(records), digest)
        _SECRET_INFO_CLIENTS[id(binding)] = binding
        return binding

    def _validate_native_binding(self) -> None:
        if _SECRET_INFO_CLIENTS.get(id(self)) is not self:
            raise PermissionError(
                "SecretInfo binding was not issued from exact native bytes"
            )

    def authorize(self, client: bytes) -> None:
        self._validate_native_binding()
        if not isinstance(client, bytes) or len(client) > 4096:
            raise ValueError("Bounded native client bytes required")
        object.__setattr__(
            self,
            "_authorized",
            hmac.compare_digest(client.split(b"\0", 1)[0], self._client),
        )

    def get(self, identifier: int) -> bytes:
        self._validate_native_binding()
        if type(identifier) is not int or not 0 <= identifier <= 0xFFFFFFFF:
            raise ValueError("Native unsigned secret identifier required")
        selected = identifier if self._authorized else 0x3F
        return next(
            (value for number, value in self._records[:63] if number == selected),
            self._records[63][1],
        )


def native_aes128_ecb_block(key: bytes, block: bytes, *, encrypt: bool = True) -> bytes:
    """CUW15520/158a0: AES128 ECB, one block, native Final=FALSE/no padding."""
    if (
        type(key) is not bytes
        or type(block) is not bytes
        or len(key) != 16
        or len(block) != 16
        or type(encrypt) is not bool
    ):
        raise ValueError("AES128 requires sixteen-byte key/block and Boolean direction")
    library = ctypes.util.find_library("crypto")
    if library is None:
        raise ValueError("System libcrypto is required for native AES")
    crypto = ctypes.CDLL(library)
    pointer = ctypes.c_void_p
    for name, args, result in (
        ("EVP_CIPHER_CTX_new", [], pointer),
        ("EVP_CIPHER_CTX_free", [pointer], None),
        ("EVP_aes_128_ecb", [], pointer),
        (
            "EVP_CipherInit_ex",
            [pointer, pointer, pointer, pointer, pointer, ctypes.c_int],
            ctypes.c_int,
        ),
        ("EVP_CIPHER_CTX_set_padding", [pointer, ctypes.c_int], ctypes.c_int),
        (
            "EVP_CipherUpdate",
            [pointer, pointer, pointer, pointer, ctypes.c_int],
            ctypes.c_int,
        ),
        ("EVP_CipherFinal_ex", [pointer, pointer, pointer], ctypes.c_int),
    ):
        function = getattr(crypto, name)
        function.argtypes, function.restype = args, result
    output = ctypes.create_string_buffer(32)
    key_buffer, data_buffer = (
        ctypes.create_string_buffer(key),
        ctypes.create_string_buffer(block),
    )
    length, final_length = ctypes.c_int(), ctypes.c_int()
    context = crypto.EVP_CIPHER_CTX_new()
    try:
        if not context:
            raise ValueError("Could not allocate native AES context")
        cipher = crypto.EVP_aes_128_ecb()
        if (
            not cipher
            or crypto.EVP_CipherInit_ex(
                context, cipher, None, key_buffer, None, int(encrypt)
            )
            != 1
            or crypto.EVP_CIPHER_CTX_set_padding(context, 0) != 1
            or crypto.EVP_CipherUpdate(
                context, output, ctypes.byref(length), data_buffer, 16
            )
            != 1
        ):
            raise ValueError("System libcrypto could not process native AES block")
        if not 0 <= length.value <= 16:
            raise ValueError("System libcrypto returned invalid native AES length")
        if (
            crypto.EVP_CipherFinal_ex(
                context, ctypes.byref(output, length.value), ctypes.byref(final_length)
            )
            != 1
            or length.value + final_length.value != 16
        ):
            raise ValueError("System libcrypto returned invalid native AES block")
        return output.raw[:16]
    finally:
        if context:
            crypto.EVP_CIPHER_CTX_free(context)
        for buffer in (key_buffer, data_buffer, output):
            ctypes.memset(buffer, 0, len(buffer))


_CENTRAL_GATEWAY_TOKEN = object()
_CENTRAL_GATEWAY_BINDINGS: WeakValueDictionary[int, "NativeCentralGatewayKey2026"] = (
    WeakValueDictionary()
)


@dataclass(frozen=True, repr=False)
class NativeCentralGatewayKey2026:
    """585c0→5b400→1b700 mode1; distinct from the mode0 gateway handshake."""

    _key: bytes = field(repr=False)
    source_sha256: str
    _token: object = field(repr=False)

    def __post_init__(self):
        if (
            self._token is not _CENTRAL_GATEWAY_TOKEN
            or type(self._key) is not bytes
            or len(self._key) != 16
        ):
            raise TypeError("Central gateway key must be issued from native source")

    def __repr__(self):
        return "NativeCentralGatewayKey2026(<private native binding>)"

    def _validate_native_binding(self):
        if _CENTRAL_GATEWAY_BINDINGS.get(id(self)) is not self:
            raise PermissionError("Central gateway binding was not source-issued")

    @classmethod
    def from_native_module(cls, data: bytes):
        from scripts.cuw_persistence import decode_nibble_text

        if type(data) is not bytes or not 0 < len(data) <= 64 * 1024 * 1024:
            raise ValueError("Bounded immutable native CUW bytes required")
        digest = hashlib.sha256(data).hexdigest()
        identity = identify_native_module(digest, "CUW.dll")
        if (
            identity.cuw_builds != ("2026",)
            or identity.artifact_form != "reconstructed-inspection"
        ):
            raise ValueError("Exact reconstructed CUW2026 key source required")
        decoded = decode_nibble_text(data[0x7AC40:0x7AC80])
        if re.fullmatch(b"[0-9a-fA-F]{32}", decoded) is None:
            raise ValueError("Native slot20 AES key encoding differs")
        binding = cls(
            bytes.fromhex(decoded.decode("ascii")), digest, _CENTRAL_GATEWAY_TOKEN
        )
        _CENTRAL_GATEWAY_BINDINGS[id(binding)] = binding
        return binding

    def calculate(self, seed: bytes) -> bytes:
        self._validate_native_binding()
        return native_aes128_ecb_block(self._key, seed)

    def primitive(self, action: dict, remaining: float) -> bytes:
        if (
            type(action) is not dict
            or set(action) != {"operation", "seed"}
            or action["operation"] != "calculate_central_gateway_key"
            or isinstance(remaining, bool)
            or not isinstance(remaining, (int, float))
            or not math.isfinite(remaining)
            or remaining <= 0
        ):
            raise ValueError("Bounded native central gateway AES primitive required")
        return self.calculate(action["seed"])


def native_smc_hmac_sha256(key: bytes, data: bytes) -> bytes:
    """CalculationHmacAPI1010/1160: fixed key32, input33, SHA256 inner/outer."""
    if (
        type(key) is not bytes
        or len(key) != 32
        or type(data) is not bytes
        or len(data) != 33
    ):
        raise ValueError("Native SMC key32 and input33 required")
    return hmac.digest(key, data, "sha256")


_SMC_HMAC_TOKEN = object()
_SMC_HMAC_BINDINGS: WeakValueDictionary[int, "NativeSMCHmac2026"] = (
    WeakValueDictionary()
)
_SMC_OPERATIONS = frozenset(
    (
        "load_smc_hmac_library",
        "resolve_smc_hmac_export",
        "invoke_smc_hmac_export",
        "free_smc_hmac_library",
    )
)


@dataclass(repr=False, frozen=True)
class NativeSMCHmac2026:
    """Authored static port; private PE supplies identity and key, never executes."""

    _key: bytes = field(repr=False)
    _token: object = field(repr=False)
    source_sha256: str
    _loaded: int = field(default=0, init=False, repr=False)

    def __post_init__(self):
        if (
            self._token is not _SMC_HMAC_TOKEN
            or self.source_sha256
            != ("e1e6cc8a531e8a3f3c899e3f11a48d4e0556e0903bc15cb944ef289c2f79eeef")
            or type(self._key) is not bytes
            or len(self._key) != 32
        ):
            raise TypeError("SMC binding must be issued from exact native bytes")

    def _validate_native_binding(self):
        if _SMC_HMAC_BINDINGS.get(id(self)) is not self:
            raise PermissionError("SMC binding was not issued from exact native bytes")

    def __repr__(self):
        return "NativeSMCHmac2026(<private native binding>)"

    @classmethod
    def from_native_module(cls, data: bytes):
        if (
            type(data) is not bytes
            or len(data) != 45056
            or hashlib.sha256(data).hexdigest()
            != ("e1e6cc8a531e8a3f3c899e3f11a48d4e0556e0903bc15cb944ef289c2f79eeef")
        ):
            raise ValueError("Exact2026 CalculationHmacAPI DLL bytes required")
        # Authenticated original PE has matching raw offsets and RVAs here.
        if data[0x6108:0x6148] != b"\x36" * 64 or data[0x6148:0x6188] != b"\x5c" * 64:
            raise ValueError("Native HMAC-SHA256 pads differ")
        binding = cls(
            data[0x60E8:0x6108], _SMC_HMAC_TOKEN, hashlib.sha256(data).hexdigest()
        )
        _SMC_HMAC_BINDINGS[id(binding)] = binding
        return binding

    def primitive(self, action: dict, remaining: float):
        self._validate_native_binding()
        if (
            not isinstance(action, dict)
            or isinstance(remaining, bool)
            or not isinstance(remaining, (int, float))
            or not math.isfinite(remaining)
            or remaining <= 0
        ):
            raise ValueError("Bounded native SMC library primitive required")
        operation = action.get("operation")
        if action == {"operation": "load_smc_hmac_library"}:
            object.__setattr__(self, "_loaded", self._loaded + 1)
            return 1
        if not self._loaded:
            raise ValueError("SMC library is not loaded")
        if type(action.get("identifier")) is int and action == {
            "operation": "free_smc_hmac_library",
            "identifier": 1,
        }:
            object.__setattr__(self, "_loaded", self._loaded - 1)
            return None
        if type(action.get("library")) is int and action == {
            "operation": "resolve_smc_hmac_export",
            "library": 1,
            "name": "MakeSendKeyCGWHmac",
        }:
            return 0x1010
        if (
            operation == "invoke_smc_hmac_export"
            and set(action) == {"operation", "library", "symbol", "data"}
            and type(action["library"]) is int
            and action["library"] == 1
            and type(action["symbol"]) is int
            and action["symbol"] == 0x1010
        ):
            return native_smc_hmac_sha256(self._key, action["data"])
        raise ValueError("Unknown SMC native library primitive")


_SECURITY_COMPOSER_TOKEN = object()


@dataclass(frozen=True, repr=False)
class NativeSecurityComposer2026:
    """Concrete callback22 AES-decrypt then callback21 AES-encrypt composition."""

    client: SecretInfoClient = field(repr=False)
    _token: object = field(repr=False)

    def __post_init__(self):
        if (
            self._token is not _SECURITY_COMPOSER_TOKEN
            or type(self.client) is not SecretInfoClient
        ):
            raise TypeError("Security composer requires exact native client issuance")
        self.client._validate_native_binding()

    def __repr__(self) -> str:
        return "NativeSecurityComposer2026(<private native binding>)"

    @classmethod
    def from_native_modules(cls, secret_info_bytes: bytes, cuw_bytes: bytes):
        return cls(
            SecretInfoClient.from_native_modules(secret_info_bytes, cuw_bytes),
            _SECURITY_COMPOSER_TOKEN,
        )

    def decrypt_secret_info(self, secret: bytes, service_auth_key: bytes) -> bytes:
        expected = self.client.get(0)
        if (
            not expected
            or not isinstance(secret, bytes)
            or not hmac.compare_digest(secret, expected)
        ):
            raise PermissionError(
                "Crypto material differs from authorized native record"
            )
        try:
            key = NativeBytes2026.from_hex(secret.decode("ascii")).data
        except (ValueError, UnicodeError) as error:
            raise ValueError("Native secret AES key encoding is invalid") from error
        return native_aes128_ecb_block(key, service_auth_key, encrypt=False)

    @staticmethod
    def calculate_security_key(key_hex: bytes, seed: bytes) -> bytes:
        if not isinstance(key_hex, bytes) or len(key_hex) != 32:
            raise ValueError("Native sixteen-byte hexadecimal AES key required")
        try:
            key = NativeBytes2026.from_hex(key_hex.decode("ascii")).data
        except (ValueError, UnicodeError) as error:
            raise ValueError("Native derived AES key encoding is invalid") from error
        return native_aes128_ecb_block(key, seed)

    def derive(self, seed: bytes, service_auth_key: bytes) -> bytes:
        key = self.decrypt_secret_info(self.client.get(0), service_auth_key)
        return self.calculate_security_key(key.hex().upper().encode("ascii"), seed)

    def primitive(self, action: dict, remaining: float) -> bytes:
        if (
            not isinstance(action, dict)
            or isinstance(remaining, bool)
            or not isinstance(remaining, (int, float))
            or not math.isfinite(remaining)
            or remaining <= 0
        ):
            raise ValueError("Typed bounded native crypto primitive required")
        if (
            set(action) == {"operation", "secret", "service_auth_key"}
            and action["operation"] == "decrypt_secret_info"
        ):
            return self.decrypt_secret_info(
                action["secret"], action["service_auth_key"]
            )
        if (
            set(action) == {"operation", "key_hex", "seed"}
            and action["operation"] == "calculate_security_key"
        ):
            return self.calculate_security_key(action["key_hex"], action["seed"])
        raise ValueError("Unknown native security crypto primitive")


def security_up_key(
    runtime: NativeRuntime2026,
    client: SecretInfoClient,
    seed: bytes,
    service_auth_key: bytes,
) -> bytes:
    """RVA14a0/1450 two-stage authorized crypto callback contract.

    Neither cryptographic algorithm nor a secret is invented. The exact callback
    implementations must be supplied; they return bytes, never success Booleans.
    """
    if type(client) is not SecretInfoClient:
        raise TypeError("Concrete factory-issued SecretInfo binding required")
    client._validate_native_binding()
    if any(
        not isinstance(value, bytes) or len(value) != 16
        for value in (seed, service_auth_key)
    ):
        raise ValueError("Native sixteen-byte seed/service authentication key required")
    secret = client.get(0)
    if not secret:
        raise PermissionError("SecretInfo client is not authorized")
    intermediate = runtime.call(
        "decrypt_secret_info", secret=secret, service_auth_key=service_auth_key
    )
    if not isinstance(intermediate, bytes) or len(intermediate) != 16:
        raise ValueError("Authorized native crypto primitive must return sixteen bytes")
    result = runtime.call(
        "calculate_security_key",
        key_hex=intermediate.hex().upper().encode("ascii"),
        seed=seed,
    )
    if not isinstance(result, bytes) or len(result) != 16:
        raise ValueError("Authorized native crypto primitive must return sixteen bytes")
    return result


@dataclass
class NativeBytes2026:
    """Recovered512-byte CBytes value semantics with strict host memory bounds."""

    data: bytes = b""

    def __setattr__(self, name: str, value) -> None:
        if name == "data" and (not isinstance(value, bytes) or len(value) > 512):
            raise ValueError("Native CBytes capacity512 required")
        object.__setattr__(self, name, value)

    @classmethod
    def from_unsigned(cls, value: int, width: int = 4):
        if (
            type(value) is not int
            or width not in (2, 4)
            or not 0 <= value < 1 << (width * 8)
        ):
            raise ValueError("Native unsigned short/long value required")
        return cls(value.to_bytes(width, "big"))

    @classmethod
    def from_hex(cls, value: str):
        """1380 constructor consumes each pair with full Windows strtol parsing."""
        if not isinstance(value, str) or len(value) > 1024 or len(value) % 2:
            raise ValueError("Even bounded native hexadecimal string required")
        result = bytearray()
        for index in range(0, len(value), 2):
            pair = value[index : index + 2]
            if re.fullmatch(r"[ \t\n\r\v\f]*[+-]?[0-9a-fA-F]+", pair) is None:
                raise ValueError("Native hexadecimal constructor pair is invalid")
            result.append(int(pair, 16) & 255)
        return cls(bytes(result))

    def set_bytes_from_hex(self, value: str) -> None:
        """1990 uses strict digit conversion, unlike the strtol constructor.

        Host rejects malformed input before mutation rather than exposing a native
        partially initialized backing buffer after its exception.
        """
        if (
            not isinstance(value, str)
            or len(value) > 1024
            or len(value) % 2
            or any(c not in "0123456789abcdefABCDEF" for c in value)
        ):
            raise ValueError("Even bounded hexadecimal digits required")
        self.data = bytes.fromhex(value)

    def assign(self, other: "NativeBytes2026") -> None:
        if not isinstance(other, NativeBytes2026):
            raise TypeError("Native CBytes value required")
        self.data = other.data

    def __len__(self) -> int:
        return len(self.data)

    def __getitem__(self, index: int) -> int:
        if type(index) is not int or not 0 <= index < len(self.data):
            raise IndexError("Native CBytes index outside initialized data")
        return self.data[index]

    def __setitem__(self, index: int, value: int) -> None:
        self[index]
        if type(value) is not int or not 0 <= value <= 255:
            raise ValueError("Native unsigned byte required")
        self.data = self.data[:index] + bytes((value,)) + self.data[index + 1 :]

    def set_num(self, size: int) -> None:
        if type(size) is not int or not 0 <= size <= 512:
            raise ValueError("Native CBytes size outside host capacity")
        self.data = self.data[-size:].rjust(size, b"\0") if size else b""

    def clear(self) -> None:
        self.data = b""

    def checksum(self) -> int:
        return sum(self.data) & 255

    def convert_endian(self, width: int = 0) -> None:
        if type(width) is not int or not 0 <= width <= 0xFFFFFFFF:
            raise ValueError("Native unsigned endian width required")
        width = width or len(self.data)
        if width == 0:
            return
        whole = len(self.data) // width * width
        self.data = (
            b"".join(
                self.data[start : start + width][::-1]
                for start in range(0, whole, width)
            )
            + self.data[whole:]
        )

    def unsigned(self, width: int = 4) -> int:
        if width not in (2, 4):
            raise ValueError("Native unsigned short/long width required")
        result = 0
        for index, byte in enumerate(reversed(self.data)):
            result |= byte << ((index * 8) & 31)
        return result & ((1 << (width * 8)) - 1)

    @staticmethod
    def convert_bytes_to_string(
        data: bytes, count: int, destination: bytearray, capacity: int
    ) -> None:
        """17d0 leaves the destination untouched unless all pairs plus NUL fit."""
        if (
            type(data) is not bytes
            or len(data) > 64 * 1024 * 1024
            or type(count) is not int
            or not 0 <= count <= len(data)
            or type(destination) is not bytearray
            or type(capacity) is not int
            or not 0 <= capacity <= min(len(destination), 64 * 1024 * 1024)
        ):
            raise ValueError("Bounded initialized native byte/string spans required")
        if count * 2 <= capacity - 1:
            destination[: count * 2 + 1] = (
                data[:count].hex().upper().encode("ascii") + b"\0"
            )

    def hex_string(self, capacity: int) -> str:
        if type(capacity) is not int or capacity < 0 or capacity > 1025:
            raise ValueError("Bounded destination string capacity required")
        if capacity <= len(self.data) * 2:
            raise ValueError("Native hex destination must include NUL byte")
        return self.data.hex().upper()


def make_send_data_records(
    records: tuple[tuple[int, int, bytes], ...], address: int, size: int
) -> bytes:
    """UnifiedUtils RVA4360: skip first S1, append eligible whole records.

    Host rejects the native buffer overrun/incomplete cases rather than returning
    undefined trailing bytes. Addresses are selection thresholds, not hole filling.
    """
    if (
        type(address) is not int
        or not 0 <= address <= 0xFFFFFFFF
        or type(size) is not int
        or not 0 < size <= 64 * 1024 * 1024
    ):
        raise ValueError("Bounded native address and output length required")
    if not isinstance(records, tuple) or len(records) > 1048576:
        raise ValueError("Bounded immutable S-format records required")
    output = bytearray()
    first_s1 = True
    for record in records:
        if not isinstance(record, tuple) or len(record) != 3:
            raise ValueError("Native S-format kind/address/data record required")
        kind, start, payload = record
        if (
            type(kind) is not int
            or not 0 <= kind <= 9
            or type(start) is not int
            or not 0 <= start <= 0xFFFFFFFF
            or not isinstance(payload, bytes)
            or len(payload) > 255
        ):
            raise ValueError("Malformed native S-format record")
        if kind == 1 and first_s1:
            first_s1 = False
            continue
        if kind not in (1, 2, 3) or start < address:
            continue
        output.extend(payload)
        if len(output) >= size:
            if len(output) != size:
                raise ValueError("Native MakeSendData would overrun its output")
            return bytes(output)
    raise ValueError("Native MakeSendData output is incomplete")


@dataclass(frozen=True)
class NativeBlockInfo:
    start_index: int
    size_kib: int
    count: int

    def __post_init__(self):
        if any(
            type(value) is not int or not 0 <= value <= 65535
            for value in (self.start_index, self.size_kib, self.count)
        ):
            raise ValueError("Bounded native block information required")


@dataclass(frozen=True)
class NativeMemoryInfo:
    start_address: int
    end_address: int
    block_size_kib: int
    firmware_version: int


def extract_memory_info(data: bytes) -> NativeMemoryInfo:
    """FlashWriterUtils1d10:3-byte addresses for8bytes,4-byte for10bytes."""
    if not isinstance(data, bytes) or len(data) not in (8, 10):
        raise ValueError("Native eight/ten-byte memory information required")
    width = 3 if len(data) == 8 else 4
    return NativeMemoryInfo(
        int.from_bytes(data[:width], "big"),
        int.from_bytes(data[width : width * 2], "big"),
        data[width * 2],
        data[width * 2 + 1],
    )


def native_block_info(parameters: Mapping[str, str]) -> tuple[NativeBlockInfo, ...]:
    """FlashWriterUtils1e70: decimal BlockSizeInfo triples, delimiters , : x."""
    text = parameters.get("BlockSizeInfo", "")
    if not isinstance(text, str) or len(text) > 259:
        raise ValueError("Bounded native BlockSizeInfo parameter required")
    tokens = [part.strip() for part in re.split(r"[,:x]+", text) if part]
    if len(tokens) % 3:
        raise ValueError("Complete native block triples required")
    return tuple(
        NativeBlockInfo(
            *((_native_long(value, 10) or 0) for value in tokens[index : index + 3])
        )
        for index in range(0, len(tokens), 3)
    )


def complete_block_info(
    blocks: tuple[NativeBlockInfo, ...], memory: NativeMemoryInfo
) -> tuple[NativeBlockInfo, ...]:
    """FlashWriterUtils1c60: replace zero size/count using observed memory bytes."""
    if (
        not isinstance(blocks, tuple)
        or not blocks
        or len(blocks) > 65535
        or any(not isinstance(block, NativeBlockInfo) for block in blocks)
        or not isinstance(memory, NativeMemoryInfo)
    ):
        raise ValueError("Native block rows and observed memory information required")
    if (
        not 0 <= memory.start_address <= memory.end_address <= 0xFFFFFFFF
        or not 0 < memory.block_size_kib <= 255
    ):
        raise ValueError("Native memory interval/block size invalid")
    result = [
        NativeBlockInfo(
            block.start_index, block.size_kib or memory.block_size_kib, block.count
        )
        for block in blocks
    ]
    last = result[-1]
    if not last.count:
        count = (
            (memory.end_address - memory.start_address + 1) // (last.size_kib << 10)
            - last.start_index
        ) + result[0].start_index
        result[-1] = NativeBlockInfo(last.start_index, last.size_kib, count)
    return tuple(result)


def calc_block_sizes(blocks: tuple[NativeBlockInfo, ...]) -> tuple[int, ...]:
    """FlashWriterUtils19d0: each row's size also covers preceding index gaps."""
    if (
        not isinstance(blocks, tuple)
        or len(blocks) > 65535
        or any(not isinstance(block, NativeBlockInfo) for block in blocks)
    ):
        raise ValueError("Bounded native block rows required")
    result = []
    for index, block in enumerate(blocks):
        gap = (
            0
            if index == 0
            else block.start_index
            - (blocks[index - 1].start_index + blocks[index - 1].count)
        )
        if gap < 0 or len(result) + gap + block.count > 65535 or block.size_kib == 0:
            raise ValueError(
                "Native block overlap, unresolved size or host count limit"
            )
        result.extend([block.size_kib << 10] * (gap + block.count))
    return tuple(result)


def block_ranges_from_info(
    blocks: tuple[NativeBlockInfo, ...],
) -> tuple[tuple[int, int], ...]:
    if (
        not isinstance(blocks, tuple)
        or len(blocks) > 65535
        or any(
            not isinstance(block, NativeBlockInfo) or not block.count
            for block in blocks
        )
    ):
        raise ValueError("Complete native block rows required")
    return tuple(
        (block.start_index + 1, block.start_index + block.count) for block in blocks
    )


def set_block_ranges(
    first: int, last: int, ranges: tuple[tuple[int, int], ...] = ()
) -> tuple[tuple[int, int], ...]:
    """FlashWriterUtils23f0 appends one-based singleton ranges, inclusive.

    The native ushort loop wraps forever at last=65535; host policy rejects it.
    """
    if (
        any(
            type(value) is not int or not 0 <= value <= 65535 for value in (first, last)
        )
        or not isinstance(ranges, tuple)
        or len(ranges) > 65535
        or any(
            not isinstance(pair, tuple)
            or len(pair) != 2
            or any(
                type(value) is not int or not 0 <= value <= 0xFFFFFFFF for value in pair
            )
            for pair in ranges
        )
    ):
        raise ValueError("Bounded native ushort indices and block ranges required")
    if first > last:
        return ranges
    if last == 65535 or len(ranges) + last - first + 1 > 65535:
        raise ValueError("Native block-range loop would wrap or exceed host limit")
    return ranges + tuple((index + 1, index + 1) for index in range(first, last + 1))


def block_ranges_from_sizes(sizes: tuple[int, ...]) -> tuple[tuple[int, int], ...]:
    if (
        not isinstance(sizes, tuple)
        or not 0 < len(sizes) <= 65535
        or any(type(size) is not int or not 0 < size <= 0xFFFFFFFF for size in sizes)
    ):
        raise ValueError("Bounded native block sizes required")
    return tuple((index, index) for index in range(1, len(sizes) + 1))


def block_ranges_from_image(data: bytes) -> tuple[tuple[int, int], ...]:
    """FlashWriterUtils2240/23f0: scan native AA55AA55 block range tables."""
    if not isinstance(data, bytes) or len(data) > 64 * 1024 * 1024:
        raise ValueError("Bounded native image required")
    result = []
    offset = 0
    while offset < len(data):
        if data[offset : offset + 4] != bytes.fromhex("aa55aa55"):
            offset += 1
            continue
        if offset + 8 > len(data):
            raise ValueError("Truncated native block range header")
        count = data[offset + 7]
        end = offset + 8 + count * 4
        if end > len(data):
            raise ValueError("Truncated native block range table")
        for start in range(offset + 8, end, 4):
            first, last = struct.unpack_from(">HH", data, start)
            if last == 65535 or len(result) + max(0, last - first + 1) > 65535:
                raise ValueError("Native block range wraps or exceeds host budget")
            result.extend((index + 1, index + 1) for index in range(first, last + 1))
        offset = end
    return tuple(result)


def check_block_ranges(
    flash_size: int, sizes: tuple[int, ...], ranges: tuple[tuple[int, int], ...]
) -> None:
    """FlashWriterUtils1ac0 checks first index of each native range record."""
    if (
        type(flash_size) is not int
        or not 0 <= flash_size <= 0xFFFFFFFF
        or not isinstance(sizes, tuple)
        or not isinstance(ranges, tuple)
        or len(ranges) > 65535
    ):
        raise ValueError("Bounded native flash size/sizes/ranges required")
    previous = 0
    total = 0
    for entry in ranges:
        if not isinstance(entry, tuple) or len(entry) != 2:
            raise ValueError("Native range pair required")
        first, _last = entry
        if type(first) is not int or not previous < first <= len(sizes):
            raise CommonResponseError(6)
        size = sizes[first - 1]
        if type(size) is not int or not 0 <= size <= 0xFFFFFFFF:
            raise ValueError("Native unsigned block size required")
        total = (total + size) & 0xFFFFFFFF
        previous = first
    if flash_size != total:
        raise CommonResponseError(6)


def check_cpu_type_from_firmware(
    firmware: int, parameters: Mapping[str, str], shrink: bool
) -> bool:
    """FlashWriterUtils1b70 firmware bits and CPUIDNo/ShrinkFlag agreement."""
    if (
        type(firmware) is not int
        or not 0 <= firmware <= 255
        or type(shrink) is not bool
    ):
        raise ValueError("Native firmware byte and shrink Boolean required")
    # Native ignores failed getter/strtol conversions and keeps initialized zeros.
    cpu = (_native_long(parameters.get("CPUIDNo", ""), 16) or 0) & 255
    parsed_flag = _native_long(parameters.get("ShrinkFlag", ""), 10) or 0
    return (parsed_flag != 0) == shrink and cpu == (
        firmware & 0x7F if shrink else (firmware >> 4) & 7
    )


def receive_response_for_finish(
    parameters: "NativeParameter2026",
    kind_of_ecu: str,
    cpu_types: tuple[str, ...],
    contact_type: str,
) -> bool:
    """FlashWriterUtils queries each CPU's selected parameter row until true."""
    if (
        not isinstance(parameters, NativeParameter2026)
        or not isinstance(cpu_types, tuple)
        or len(cpu_types) > 65535
    ):
        raise TypeError("Native parameter matrix and immutable CPU type list required")
    return any(
        parameters.boolean_with_keys(
            "FlagToReceiveRespForFinish", kind_of_ecu, cpu, contact_type
        )
        is True
        for cpu in cpu_types
    )


def select_retry_password(retry: bool, error: int, previous: bool) -> bool:
    if (
        type(retry) is not bool
        or type(previous) is not bool
        or type(error) is not int
        or not -0x80000000 <= error <= 0x7FFFFFFF
    ):
        raise ValueError("Native retry/error/previous values required")
    return True if retry else not previous if error == 7 else False


def _native_long(text: str, base: int = 10) -> int | None:
    """Windows32-bit strtol prefix conversion, including ignored overflow errno."""
    if (
        not isinstance(text, str)
        or len(text) > 1023
        or "\0" in text
        or base not in (10, 16)
    ):
        raise ValueError("Bounded native parameter text and radix required")
    if text == "":
        return 0
    pattern = (
        r"^[ \t\n\r\v\f]*([+-]?[0-9]+)"
        if base == 10
        else r"^[ \t\n\r\v\f]*([+-]?(?:0[xX])?[0-9a-fA-F]+)"
    )
    match = re.match(pattern, text)
    if match is None:
        return None
    return max(-0x80000000, min(0x7FFFFFFF, int(match[1], base)))


def _parse_native_parameter_csv(
    data: bytes,
) -> tuple[tuple[str, ...], tuple[tuple[tuple[str, ...], ...], ...]]:
    """ParameterForVC13d0 scanner, with bounds before each native append.

    A field's first byte chooses quote/comma termination. Double quotes collapse
    even inside unquoted fields; bare LF separates values only after the header.
    """
    headers: tuple[str, ...] | None = None
    rows: list[tuple[tuple[str, ...], ...]] = []
    row: list[tuple[str, ...]] = []
    index = value_count = cell_count = character_count = 0
    while index < len(data):
        if headers is None and data[index : index + 2] == b"\r\n":
            if row:
                headers = tuple(cell[0] for cell in row)
                row = []
            index += 2
            continue
        quoted = data[index] == 34
        if quoted:
            index += 1
        values: list[str] = []
        current = bytearray()
        while True:
            if index >= len(data):
                raise ValueError("Native CSV field lacks a bounded terminator")
            byte = data[index]
            following = data[index + 1 : index + 2]
            if byte == 34 and following == b'"':
                current.append(34)
                index += 2
            elif byte == (34 if quoted else 44):
                break
            elif not quoted and data[index : index + 2] == b"\r\n":
                if headers is not None and len(row) + 1 != len(headers):
                    raise ValueError("Native CSV row width mismatch")
                break
            elif byte == 10:
                if headers is not None:
                    values.append(current.decode("latin1"))
                    character_count += len(current)
                    current.clear()
                    value_count += 1
                index += 1
            else:
                current.append(byte)
                index += 1
            if len(current) > 1023 or len(values) >= 4096 or value_count >= 131072:
                raise ValueError("Native CSV field/value host budget exceeded")
            if character_count > 16 * 1024 * 1024:
                raise ValueError("Native CSV aggregate character budget exceeded")
        values.append(current.decode("latin1"))
        character_count += len(current)
        value_count += 1
        if value_count > 131072 or character_count > 16 * 1024 * 1024:
            raise ValueError("Native CSV aggregate value/character budget exceeded")
        row.append(tuple(values))
        if len(row) > 256:
            raise ValueError("Native CSV column host budget exceeded")
        if quoted:
            if index + 1 >= len(data):
                raise ValueError("Native CSV closing quote lacks its delimiter")
            index += 1 if data[index + 1] == 13 else 2
        elif data[index] == 44:
            index += 1
        if headers is not None and len(row) == len(headers):
            cell_count += len(row)
            if cell_count > 65536 or len(rows) >= 4096:
                raise ValueError("Native CSV matrix host budget exceeded")
            rows.append(tuple(row))
            row = []
            if data[index : index + 2] == b"\r\n":
                index += 2
    if headers is None or row:
        raise ValueError("Native CSV header/complete rows required")
    return headers, tuple(rows)


class NativeParameter2026:
    """ParameterForVC row selection and typed first/multiple cell access.

    Native key order is kind_of_ecu + contact_type + cpu_type. CSV multi-line
    quoted cells retain ordered values. Imports never discover/open a path.
    """

    headers: tuple[str, ...]
    rows: tuple[tuple[tuple[str, ...], ...], ...]

    def __init__(
        self,
        headers: tuple[str, ...] = (),
        rows: tuple[tuple[tuple[str, ...], ...], ...] = (),
        key_column: str = "ParamFileKeySystemProtocolMicon",
    ):
        if (
            not isinstance(headers, tuple)
            or len(headers) > 256
            or not isinstance(rows, tuple)
            or len(rows) > 4096
            or (not headers and rows)
        ):
            raise ValueError("Bounded native parameter matrix required")
        cell_count = value_count = character_count = 0
        for header in headers:
            if not isinstance(header, str) or len(header) > 1023 or "\0" in header:
                raise ValueError("Bounded native column name required")
            character_count += len(header)
        for row in rows:
            if not isinstance(row, tuple) or len(row) != len(headers):
                raise ValueError("Native parameter row width mismatch")
            cell_count += len(row)
            if cell_count > 65536:
                raise ValueError("Native parameter aggregate cell budget exceeded")
            for cell in row:
                if not isinstance(cell, tuple) or len(cell) > 4096:
                    raise ValueError("Bounded native multi-value cell required")
                value_count += len(cell)
                if value_count > 131072:
                    raise ValueError("Native parameter aggregate value budget exceeded")
                for value in cell:
                    if not isinstance(value, str) or len(value) > 1023 or "\0" in value:
                        raise ValueError("Bounded native multi-value cell required")
                    character_count += len(value)
                    if character_count > 16 * 1024 * 1024:
                        raise ValueError(
                            "Native parameter aggregate character budget exceeded"
                        )
        self.headers, self.rows = headers, rows
        column = self.search_column(key_column)
        self.key_column = column if headers else 0
        self.row_index = 0  # Native constructor selects the header row until SetKeys.

    @classmethod
    def from_csv(cls, data: bytes, key_column: str = "ParamFileKeySystemProtocolMicon"):
        if not isinstance(data, bytes) or len(data) > 16 * 1024 * 1024 or b"\0" in data:
            raise ValueError("Bounded native CSV bytes required")
        data = data.split(b"\xff", 1)[0]
        if b"\r\n" not in data:
            raise ValueError("Native parameter header requires CRLF")
        headers, rows = _parse_native_parameter_csv(data)
        return cls(headers, rows, key_column)

    @classmethod
    def from_encoded(
        cls, data: bytes, key_column: str = "ParamFileKeySystemProtocolMicon"
    ):
        from scripts.calibration import decode_cuw_text

        return cls.from_csv(decode_cuw_text(data), key_column)

    def search_column(self, name: str) -> int:
        if not isinstance(name, str) or len(name) > 1023 or "\0" in name:
            raise ValueError("Bounded native column lookup required")
        return next(
            (index for index, header in enumerate(self.headers) if header == name), -1
        )

    def search_row(self, column: int, key: str) -> int:
        if (
            type(column) is not int
            or not isinstance(key, str)
            or len(key) > 1023
            or "\0" in key
        ):
            raise ValueError("Bounded native row key lookup required")
        if not 0 <= column < len(self.headers):
            return -1
        return next(
            (
                index
                for index, row in enumerate(self.rows, start=1)
                if row[column] and row[column][0] == key
            ),
            -1,
        )

    def set_keys(self, kind_of_ecu: str, cpu_type: str, contact_type: str) -> bool:
        if any(
            not isinstance(value, str) or len(value) > 260 or "\0" in value
            for value in (kind_of_ecu, cpu_type, contact_type)
        ):
            raise ValueError("Bounded native selection key strings required")
        self.row_index = self.search_row(
            self.key_column, kind_of_ecu + contact_type + cpu_type
        )
        return self.row_index != -1

    def values(self, name: str) -> tuple[str, ...] | None:
        column = self.search_column(name)
        if column < 0:
            return None
        if self.row_index == 0:
            return (self.headers[column],)
        if not 1 <= self.row_index <= len(self.rows):
            return None
        cell = self.rows[self.row_index - 1][column]
        return cell or None

    def string(self, name: str) -> str | None:
        values = self.values(name)
        return values[0] if values else None

    def long(self, name: str) -> int | None:
        value = self.string(name)
        return _native_long(value) if value is not None else None

    def boolean(self, name: str) -> bool | None:
        value = self.long(name)
        return value != 0 if value is not None else None

    def exists(self, name: str) -> bool:
        return self.search_column(name) != -1

    def values_with_keys(
        self, name: str, kind_of_ecu: str, cpu_type: str, contact_type: str
    ) -> tuple[str, ...] | None:
        previous = self.row_index
        try:
            self.set_keys(kind_of_ecu, cpu_type, contact_type)
            return self.values(name)
        finally:
            self.row_index = previous

    def string_with_keys(
        self, name: str, kind_of_ecu: str, cpu_type: str, contact_type: str
    ) -> str | None:
        values = self.values_with_keys(name, kind_of_ecu, cpu_type, contact_type)
        return values[0] if values else None

    def long_with_keys(
        self, name: str, kind_of_ecu: str, cpu_type: str, contact_type: str
    ) -> int | None:
        value = self.string_with_keys(name, kind_of_ecu, cpu_type, contact_type)
        return _native_long(value) if value is not None else None

    def boolean_with_keys(
        self, name: str, kind_of_ecu: str, cpu_type: str, contact_type: str
    ) -> bool | None:
        value = self.long_with_keys(name, kind_of_ecu, cpu_type, contact_type)
        return value != 0 if value is not None else None

    def parameters(
        self, name: str, capacity: int
    ) -> tuple[tuple[str, ...], int] | None:
        """Native multi-value getter returns total count even after truncation."""
        if type(capacity) is not int or not 0 <= capacity <= 4096:
            raise ValueError("Bounded native multi-value output capacity required")
        values = self.values(name)
        if values is None:
            return None
        copied = values[:capacity]
        if any(len(value.encode("latin1")) >= 260 for value in copied):
            raise ValueError("Native parameter would exceed its 260-byte output slot")
        return copied, len(values)

    def parameters_with_keys(
        self,
        name: str,
        kind_of_ecu: str,
        cpu_type: str,
        contact_type: str,
        capacity: int,
    ) -> tuple[tuple[str, ...], int] | None:
        """2c80 selects a local row; the object's SetKeys selection is retained."""
        previous = self.row_index
        try:
            self.set_keys(kind_of_ecu, cpu_type, contact_type)
            return self.parameters(name, capacity)
        finally:
            self.row_index = previous

    def get_data(self, row: int, column: int) -> tuple[str, ...]:
        """CCSVFile uses row zero for the header; invalid indices yield empty."""
        if type(row) is not int or type(column) is not int:
            raise TypeError("Native integer matrix indices required")
        if not 0 <= column < len(self.headers):
            return ()
        if row == 0:
            return (self.headers[column],)
        if 0 < row <= len(self.rows):
            return self.rows[row - 1][column]
        return ()

    def delete(self) -> None:
        # CCSVFile::Delete clears only the matrix, not CParameter's derived indices.
        self.headers, self.rows = (), ()


_control_base_parameters2026: WeakValueDictionary[
    int, "NativeControlParameterBase2026"
] = WeakValueDictionary()


@dataclass(frozen=True, init=False)
class NativeControlParameterBase2026:
    """Issued pool BASE; constructor-zero until the first native row load."""

    def __init__(self):
        raise TypeError("Native control parameter base must be controller-issued")

    def validate(self, engine) -> None:
        from scripts.cuw_2026 import CUWEngine2026

        if (
            _control_base_parameters2026.get(id(self)) is not self
            or type(engine) is not CUWEngine2026
            or self._engine is not engine
            or engine.worker.controller is not self._controller
        ):
            raise ValueError("Current issued control parameter base required")
        engine._require_owned_phase()
        if self._pool is None:
            if (
                self._controller._has_loaded_control_parameters2026()
                or engine.native_metadata is not self.metadata
            ):
                raise ValueError("Current constructor-issued empty parameter required")
        else:
            self._pool.validate(engine, self._controller)
            context = self._controller.native_control_context2026(engine)
            if (
                context is not self._context
                or self.metadata.source_container
                is not context._capture.metadata.source_container
            ):
                raise ValueError("Actual held CONTROL base parameter view required")
        native2026_validate_runtime_metadata(self.metadata)

    @property
    def engine(self):
        from scripts.cuw_2026 import CUWEngine2026

        engine = self._engine
        if type(engine) is not CUWEngine2026:
            raise ValueError("Actual issued control parameter base engine required")
        self.validate(engine)
        return engine

    @property
    def parameter(self) -> NativeParameter2026:
        self.validate(self._engine)
        return (
            NativeParameter2026()
            if self._pool is None
            else self._pool.slot(0).parameter
        )

    def value(self, name: str) -> str:
        # Native2470 returns false for the absent column and leaves output alone.
        return self.parameter.string(name) or ""

    _engine: object = field(repr=False)
    _controller: "ControlCommPhase2026" = field(repr=False)
    metadata: Native2026Metadata = field(repr=False)
    _pool: "ControlParameterPool2026 | None" = field(default=None, repr=False)
    _context: "NativeControlContext2026 | None" = field(default=None, repr=False)


class ControlCommPhase2026:
    """Exact ControlCommPhase exports and the raw same-Execute stage machine.

    The controller retains one explicit module-runtime address history. Its
    `execute` method runs live native phases over one held FILE/interface view
    and retained parameter array; the thread job owns the surrounding
    orchestration and the outer host owns final shared-trace validation.
    """

    def __init__(self, identity: NativeModuleIdentity, runtime: NativeRuntime2026):
        if not isinstance(identity, NativeModuleIdentity):
            raise TypeError("Authenticated native module identity required")
        actual = identify_native_module(identity.sha256, "TCUWControlCommPhase.dll")
        if actual != identity or actual.cuw_build != "2026":
            raise ValueError("Exact2026 ControlCommPhase identity required")
        if not isinstance(runtime, NativeRuntime2026):
            raise TypeError("Bounded shared runtime required")
        self.identity, self.runtime = actual, runtime
        self.dh_mode_could_be_changed = False
        # Native CAddress static storage survives resolver and per-CPU constructors.
        # One host controller represents one explicit loaded module runtime.
        self.address_history = []
        self.alternate_cid_used = False
        self._parameter_session = None
        self._native_control_context2026 = None
        self._native_control_raw_execution2026 = None
        self._native_control_helper_entry2026 = None
        self._native_control_export_lease2026 = None
        self._control_parameter_pool2026: ControlParameterPool2026 | None = None

    def _begin_native_control_context2026(self, engine, capture):
        """Install the once-imported raw CONTROL context for the owned phase."""
        from scripts.cuw_2026 import CUWEngine2026
        from scripts.cuw_engine_worker import ControlFileCapture2026

        if type(engine) is not CUWEngine2026 or engine.worker.controller is not self:
            raise ValueError("Actual controller-owned engine required")
        engine._require_owned_phase()
        if type(capture) is not ControlFileCapture2026:
            raise TypeError("Actual once-imported CONTROL FILE capture required")
        capture.validate(engine, self)
        if self._native_control_context2026 is not None:
            raise ValueError("A CONTROL context is already active for this controller")
        context = NativeControlContext2026._issue(engine, self, capture)
        self._native_control_context2026 = context
        return context

    def _end_native_control_context2026(self, engine, context) -> None:
        """Expire the capability before its owned phase releases the held FILE."""
        if (
            self._native_control_context2026 is not context
            or type(context) is not NativeControlContext2026
            or context._engine is not engine
            or context._controller is not self
            or _NATIVE_CONTROL_CONTEXTS_2026.get(id(context)) is not context
        ):
            raise ValueError("Exact active CONTROL context required for expiration")
        _NATIVE_CONTROL_CONTEXTS_2026.pop(id(context), None)
        _NATIVE_CONTROL_RETURN_SNAPSHOTS_2026.pop(id(context), None)
        _NATIVE_CONTROL_GETTER_RESULTS_2026.pop(id(context), None)
        self._native_control_context2026 = None
        object.__setattr__(context, "_expired", True)

    def native_control_context2026(self, engine):
        """Return only this controller's active source-issued CONTROL context."""
        context = self._native_control_context2026
        if type(context) is not NativeControlContext2026:
            raise ValueError("No active source-issued CONTROL context")
        context.validate(engine, self)
        return context

    def _begin_native_control_raw_execution2026(self, engine):
        """Authorize helper leases only while the actual Execute driver runs."""
        context = self.native_control_context2026(engine)
        if self._native_control_raw_execution2026 is not None:
            raise ValueError("A raw CONTROL Execute driver is already active")
        token = object()
        _NATIVE_CONTROL_RAW_EXECUTIONS_2026[id(token)] = (token, engine, self, context)
        self._native_control_raw_execution2026 = token
        return token

    def _end_native_control_raw_execution2026(self, engine, token) -> None:
        if (
            self._native_control_raw_execution2026 is not token
            or _NATIVE_CONTROL_RAW_EXECUTIONS_2026.get(id(token))
            != (token, engine, self, self._native_control_context2026)
            or self._native_control_export_lease2026 is not None
            or self._native_control_helper_entry2026 is not None
        ):
            raise ValueError("Exact idle raw CONTROL Execute authority required")
        _NATIVE_CONTROL_RAW_EXECUTIONS_2026.pop(id(token), None)
        self._native_control_raw_execution2026 = None

    def _begin_native_control_helper_entry2026(self, engine, *, helper: str):
        """Open the exact source-helper boundary before any row load or preflight."""
        context = self.native_control_context2026(engine)
        if (
            helper not in ("6f20", "8990", "a250", "9370", "4c10", "5c30")
            or self._native_control_raw_execution2026 is None
            or self._native_control_helper_entry2026 is not None
            or self._native_control_export_lease2026 is not None
            or _NATIVE_CONTROL_RAW_EXECUTIONS_2026.get(
                id(self._native_control_raw_execution2026)
            )
            != (
                self._native_control_raw_execution2026,
                engine,
                self,
                context,
            )
        ):
            raise ValueError("Active raw CONTROL driver and exact helper required")
        lease = object()
        state = {
            "context": context,
            "controller": self,
            "engine": engine,
            "helper": helper,
            "saved_raw": False,
            "primary_return_seen": False,
        }
        _NATIVE_CONTROL_HELPER_ENTRIES_2026[id(lease)] = (lease, state)
        self._native_control_helper_entry2026 = lease
        return lease

    def _end_native_control_helper_entry2026(self, engine, *, lease) -> None:
        record = _NATIVE_CONTROL_HELPER_ENTRIES_2026.get(id(lease))
        if (
            self._native_control_helper_entry2026 is not lease
            or record is None
            or record[0] is not lease
            or record[1]["engine"] is not engine
            or record[1]["controller"] is not self
            or self._native_control_export_lease2026 is not None
        ):
            raise ValueError("Exact completed CONTROL helper entry required")
        _NATIVE_CONTROL_HELPER_ENTRIES_2026.pop(id(lease), None)
        self._native_control_helper_entry2026 = None

    def _begin_native_control_helper2026(
        self,
        engine,
        *,
        target,
        stage,
        export: str,
        helper: str,
        required_exports: tuple[str, ...],
        _addresses: tuple = (),
    ):
        """Issue an export lease after the actual raw helper's module preflight."""
        from scripts.calibration_catalog import inspect_module_bytes
        from scripts.native_modules import identify_native_module
        from scripts.programming_replay import ProgrammingReplay

        context = self.native_control_context2026(engine)
        entry = _NATIVE_CONTROL_HELPER_ENTRIES_2026.get(
            id(self._native_control_helper_entry2026)
        )
        if (
            type(target) is not NativeControlExportTarget2026
            or type(stage) is not ProgrammingReplay
            or self._native_control_raw_execution2026 is None
            or _NATIVE_CONTROL_RAW_EXECUTIONS_2026.get(
                id(self._native_control_raw_execution2026)
            )
            != (
                self._native_control_raw_execution2026,
                engine,
                self,
                context,
            )
            or self._native_control_export_lease2026 is not None
            or self._native_control_helper_entry2026 is None
            or entry is None
            or entry[0] is not self._native_control_helper_entry2026
            or entry[1]["engine"] is not engine
            or entry[1]["controller"] is not self
            or entry[1]["context"] is not context
            or entry[1]["helper"] != helper
            or helper not in ("6f20", "8990", "a250", "9370", "4c10", "5c30")
            or type(export) is not str
            or not export
            or type(required_exports) is not tuple
            or not required_exports
            or any(type(name) is not str or not name for name in required_exports)
            or len(set(required_exports)) != len(required_exports)
            or export not in required_exports
            or stage._engine2026 is not engine
            or stage._controller2026 is not self
            or stage._control_target2026 is not target
            or stage._control_export2026 != export
        ):
            raise ValueError("Exact active raw CONTROL helper preflight required")
        target.validate(engine, self)
        from scripts.j2534_2026 import NativeCommunicationAddress

        if type(_addresses) is not tuple or any(
            type(address) is not NativeCommunicationAddress for address in _addresses
        ):
            raise TypeError("Source-preflighted immutable address vector required")
        if target._context is not context or (
            target.entry_cpu_index != context.cpu_index
            and not (
                helper == "5c30"
                and entry[1]["primary_return_seen"]
                and target.entry_cpu_index < context.cpu_index
            )
        ):
            raise ValueError("CONTROL helper target differs from its live entry cursor")
        operation_for_export = {
            "StartGetCID": "get_cid",
            "StartPrepareWrite": "prepare",
            "ChangeToReprogGatewayMode": "change_gateway",
            "StartFlashWrite": "write",
            "PrepareRetry": "write",
            "IsFinishReprogramming": "write",
            "ProcessBeforeIGOffOnAtRetry": target.binding.operation,
        }
        operation = operation_for_export.get(export)
        if operation is None or target.binding.operation != operation:
            raise ValueError("CONTROL helper export differs from its exact loaded row")
        module_name = target.module_binding.module_name
        module = stage.modules.get(module_name)
        module_data = stage._module_files.get(module_name)
        if module is None or module_data is None:
            raise _control_preflight_failure2026(
                helper, "version_read", target.binding.alternate_cid
            )
        if (
            type(module_data) is not bytes
            or hashlib.sha256(module_data).hexdigest() != module.sha256
            or module.native_identity is None
        ):
            raise ValueError("Selected CONTROL module bytes are unavailable")
        identity = identify_native_module(module.sha256, module_name)
        module_version = inspect_module_bytes(module_data, module_name)["version"]
        if (
            type(module.native_identity) is not type(identity)
            or module.native_identity != identity
            or module.file_version != module_version
        ):
            raise ValueError("Selected CONTROL module authentication changed")
        module_state = _pooled_binding_state2026(target.module_binding)
        if module_state is None:
            raise ValueError("Actual loaded module row lineage required")
        preflight_key = (
            id(module_state["slot"]),
            module_state["revision"],
            module_name,
            target.binding.alternate_cid,
        )
        checked = entry[1].setdefault("module_preflights", set())
        if preflight_key not in checked:
            version_binding = (
                target.binding
                if target.binding.alternate_cid
                else target.module_binding
            )
            version_name = (
                "EnableAlternateDLLVersionsInformationForGetCID"
                if target.binding.alternate_cid
                else "EnableDLLVersionInformation"
            )
            versions = version_binding.lines(version_name)
            expected_count = 1 if target.binding.alternate_cid else 4
            if (
                len(versions) != expected_count
                or type(module.file_version) is not str
                or not module.file_version
                or "\0" in module.file_version
            ):
                raise _control_preflight_failure2026(
                    helper, "version_compare", target.binding.alternate_cid
                )
            phase_index = 0 if target.binding.alternate_cid else engine.comm_phase
            if module.file_version.encode("latin1") < versions[phase_index].encode(
                "latin1"
            ):
                raise _control_preflight_failure2026(
                    helper, "version_compare", target.binding.alternate_cid
                )
            checked.add(preflight_key)
        for required in required_exports:
            if (
                required not in identity.callable_exports
                or required not in module.exports
            ):
                if helper == "5c30" and required in (
                    "PrepareRetry",
                    "IsFinishReprogramming",
                ):
                    # 8780(false,false,Phase6) permits a NULL optional entry;
                    # 3b90's later indirect call is not a new loader CPass catch.
                    raise NotImplementedError(
                        "Native3b90 optional entry is NULL: " + required
                    )
                raise _control_loader_failure2026(helper, required)
        lease = object()
        state = {
            "controller": self,
            "addresses": _addresses,
            "context": context,
            "engine": engine,
            "export": export,
            "helper": helper,
            "identity": identity,
            "module": module_name,
            "module_binding": target.module_binding,
            "module_version_checked": True,
            "required_exports": required_exports,
            "revision": target.entry_revision,
            "slot": target.entry_slot,
            "stage": stage,
            "target": target,
        }
        _NATIVE_CONTROL_HELPER_LEASES_2026[id(lease)] = (lease, state)
        self._native_control_export_lease2026 = lease
        return lease

    def _end_native_control_helper2026(self, engine, *, lease) -> None:
        record = _NATIVE_CONTROL_HELPER_LEASES_2026.get(id(lease))
        if (
            self._native_control_export_lease2026 is not lease
            or record is None
            or record[0] is not lease
            or record[1]["engine"] is not engine
            or record[1]["controller"] is not self
        ):
            raise ValueError("Exact active raw CONTROL helper lease required")
        _NATIVE_CONTROL_HELPER_LEASES_2026.pop(id(lease), None)
        self._native_control_export_lease2026 = None

    def empty_control_parameter(self, engine) -> NativeControlParameterBase2026:
        """Issue the literal initial pool element; never synthesize a selected row."""
        from scripts.cuw_2026 import CUWEngine2026

        if type(engine) is not CUWEngine2026 or engine.worker.controller is not self:
            raise ValueError("Actual controller-owned engine required")
        engine._require_owned_phase()
        if self._has_loaded_control_parameters2026():
            raise ValueError("The native parameter pool has already been loaded")
        result = object.__new__(NativeControlParameterBase2026)
        object.__setattr__(result, "_engine", engine)
        object.__setattr__(result, "_controller", self)
        object.__setattr__(
            result,
            "metadata",
            native2026_validate_runtime_metadata(engine.native_metadata),
        )
        _control_base_parameters2026[id(result)] = result
        return result

    def _control_base_parameter2026(self, engine):
        """b280/DH tail receive pool BASE, including rows retained from older FILEs."""
        context = self.native_control_context2026(engine)
        pool = self._control_pool2026()
        pool.validate(engine, self)
        result = object.__new__(NativeControlParameterBase2026)
        for name, value in (
            ("_engine", engine),
            ("_controller", self),
            ("_pool", pool),
            ("_context", context),
            ("metadata", context._capture.metadata),
        ):
            object.__setattr__(result, name, value)
        _control_base_parameters2026[id(result)] = result
        result.validate(engine)
        return result

    def runtime_device(self) -> J2534Device2026:
        """Return only the actual runtime's bound device, never a provider snapshot."""
        recorded = self.runtime.recorded_device2026()
        if recorded is not None:
            return recorded
        device = getattr(self.runtime.action, "__self__", None)
        if (
            type(device) is not J2534Device2026
            or self.runtime.action != device.primitive
        ):
            raise ValueError("Controller runtime has no concrete bound J2534 device")
        return device

    def read_control_battery_voltage(self) -> float:
        """a190 reads only this module's CJ2534IF READ_VBATT DWORD.

        CUW33f80 is a separate engine-side version/configuration probe. This
        static control helper neither calls it nor catches provider failures.
        """
        self.runtime.check()
        value = self.runtime_device().control_io(3)
        if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
            raise ValueError("Actual READ_VBATT unsigned DWORD required")
        return value / 1000.0

    def query_control_error(self, engine) -> None:
        """4780/4886/4a54 query and reconnect, using the two literal native views."""
        from scripts.cuw_2026 import CUWEngine2026

        if type(engine) is not CUWEngine2026:
            raise TypeError("Concrete native engine required for control error query")
        engine._require_owned_phase()
        worker = engine.worker
        if worker.controller is not self:
            raise ValueError("Control error query belongs to another native worker")
        if getattr(self.runtime._device_calls, "view", None) is not None:
            raise ValueError("Control error query cannot run in an engine wire view")
        pair = engine.interface_pair
        control, native_engine = self.runtime_device(), engine.engine_runtime_device()
        if pair is None or pair.control is not control:
            raise ValueError("Actual paired native control interface required")
        retry = engine.bind_retry_controller()
        while True:
            self.runtime.check()
            engine.notify_native_error_kind()
            engine.notify_native_errors()
            # Slots24/25 are opened-byte copies, never full interface imports.
            native_engine.set_opened(control.opened)
            worker.begin_control_error_query()
            engine.publish_control_failed(self)
            job = engine.thread_job
            if job is None:
                retry.callback3()
            else:
                job.dispatch_retry_callback()
            worker.import_control_error_query_decision(retry)
            control.set_opened(native_engine.opened)
            if not worker.control_state.failed:
                return
            try:
                control.disconnect()
            except (Exception, KeyboardInterrupt) as error:
                # Catch_All487a suppresses only the explicitly native domain.
                if not is_native_exception2026(error):
                    raise
            else:
                self.runtime._forget_disconnected_children()
            caught = False
            try:
                context = self._native_control_context2026
                metadata = (
                    context.metadata if context is not None else engine.native_metadata
                )
                contact = metadata.vehicle.get("contacttype", "")
                protocol = (
                    3
                    if contact == "SIL"
                    else 0x800F
                    if contact == "Ethernet"
                    else 0x8012
                    if contact in ("P5-Unified", "Phase6")
                    and metadata.protocol_at_node == DIAG_COMM_PROTOCOL_CANFD
                    else 6
                )
                control.connect_native(protocol)
                if self.read_control_battery_voltage() <= 1.0:
                    raise NativePassThruException2026(
                        0x3F0, "TCUWControlCommPhase.dll:RVA4886", 0x63A
                    )
            except (
                NativePassThruException2026,
                NativeTransportError,
                CommonResponseError,
            ) as error:
                primary, status = native_error_fields2026(error)
                state = engine.dh_state
                state.record_native_error(
                    3, primary, state.passthru_error if status is None else status
                )
                if status is not None:
                    engine.notify_native_error_kind()
                caught = True
            # 4a54 exports even after a caught native reconnect fault; slot35
            # then imports that exact issued snapshot into the engine view.
            snapshot = pair.export_from(control)
            self._interface_data = snapshot
            pair.import_into(native_engine, snapshot)
            if not caught:
                return

    def remember_cid_address(self, address) -> None:
        """Apply the native getter's static SetCanIDs assignment, preserving duplicates.

        The getter calls this at its actual assignment point, so an earlier ECU's
        history survives a later host failure. Resolving an address does not learn it.
        """
        from scripts.j2534_2026 import NativeCommunicationAddress

        if type(address) is not NativeCommunicationAddress:
            raise TypeError("Concrete native communication address required")
        if len(self.address_history) >= 4096:
            raise ValueError("Host native address history capacity exceeded")
        self.address_history.append(address)

    def _run_control_export2026(self, engine, session) -> dict:
        """Run one staged family export without replacing raw CONTROL phase state."""
        from scripts.cuw_2026 import CUWEngine2026
        from scripts.programming_replay import ProgrammingReplay

        if (
            type(engine) is not CUWEngine2026
            or type(session) is not ProgrammingReplay
            or engine._controller_execution is not self
            or engine.worker.controller is not self
            or self._native_control_raw_execution2026 is None
        ):
            raise ValueError("Actual raw CONTROL helper execution required")
        engine._require_owned_phase()
        session.bind_controller2026(self)
        session.bind_engine2026(engine)
        session.bind_runtime2026(self.runtime)
        session._validate_control_stage2026()
        current = getattr(self.runtime._device_calls, "control_export", None)
        if current is not None:
            raise ValueError("Nested scoped CONTROL runtime export is forbidden")
        self.runtime._device_calls.control_export = (
            engine,
            self,
            session._control_target2026,
        )
        try:
            return session.run_bound2026(self.runtime)
        finally:
            self.runtime._device_calls.control_export = current

    def _invoke_control_export2026(
        self,
        engine,
        root_session,
        target,
        export: str,
        *,
        helper: str,
        required_exports: tuple[str, ...],
    ) -> dict:
        """Clone, lease and run exactly one source-selected CONTROL export."""
        if self._native_control_raw_execution2026 is None:
            raise ValueError("CONTROL exports require the active raw Execute driver")
        stage = root_session._next_control_export2026(target, export)
        entry = _NATIVE_CONTROL_HELPER_ENTRIES_2026[
            id(_control_helper_entry2026(target._context))
        ][1]
        addresses = entry.get("addresses", {}).get(target.entry_index)
        if addresses is None:
            addresses = self._preflight_control_helper2026(engine, target, helper)
            entry.setdefault("addresses", {})[target.entry_index] = addresses
        lease = self._begin_native_control_helper2026(
            engine,
            target=target,
            stage=stage,
            export=export,
            helper=helper,
            required_exports=required_exports,
            _addresses=addresses,
        )
        try:
            return self._run_control_export2026(engine, stage)
        finally:
            self._end_native_control_helper2026(engine, lease=lease)

    def _preflight_control_helper2026(self, engine, target, helper: str):
        """Resolve source-selected helper addresses before issuing its export lease."""
        from scripts.calibration_2026 import (
            native2026_global_cpu_index,
            native2026_location_id,
            native2026_node_count,
            native2026_node_values,
        )
        from scripts.j2534_2026 import CommunicationAddress2026

        if type(target) is not NativeControlExportTarget2026:
            raise TypeError("Exact issued CONTROL target required")
        target.validate(engine, self)
        binding = target.binding
        selectors = binding.selector_functions
        if helper == "3b90":
            selectors = binding.lines("GetCANIDFunctionNameForPrepareWrite")
            if len(selectors) > 4:
                raise ValueError("Native retry selector vector exceeds four slots")
        if not selectors:
            return ()
        parameter = binding.parameter
        address_parameters = {
            name: values
            for name in (
                "CanIDForGetCID",
                "CanIDForPrepareWrite",
                "CanIDForReprogGateway",
                "CanIDMatchedPartOfCID",
                "CIDForCalcCpuNum",
            )
            if (values := parameter.values(name)) is not None
        }
        metadata = target.metadata
        node_diag_ids = tuple(
            native2026_node_values(metadata, index).get("diagid", "")
            for index in range(native2026_node_count(metadata))
        )
        frontend = engine.frontend_parameters
        callback_aware = helper in ("6f20", "a250", "9370", "5c30")

        class LazyResponseLookup(dict):
            def get(self, key, default=None):
                # Native callback17 resolves only when its selector is reached.
                # Classic8990/4c10 construct CCommunicationAddress with NULL callbacks.
                if not callback_aware:
                    return default
                target.validate(engine, target._controller)
                if frontend is None:
                    raise NativeCallbackLookupError()
                value = frontend.parameter("CanIDTable.ini").string_with_keys(
                    "ResponseCANID", key, "", ""
                )
                if value is None:
                    raise NativeCallbackLookupError()
                return value

        cids = (
            tuple(value.decode("latin1") for value in target._context.identifiers)
            if helper in ("6f20", "8990", "a250", "3b90")
            else ()
        )
        load_metadata = binding.loaded_parameter_metadata or binding.metadata
        location_id = (
            native2026_location_id(
                load_metadata, native2026_global_cpu_index(load_metadata)
            )
            if helper == "4c10"
            else None
        )
        resolver = CommunicationAddress2026(
            address_parameters,
            node_diag_ids=node_diag_ids,
            response_canids={},
            suzuki_ids=(
                metadata.vehicle.get("canidtx_phys_usdt", ""),
                metadata.vehicle.get("canidrx_phys_usdt", ""),
            )
            if metadata.format_version in (10, 12)
            else None,
            history=self.address_history,
        )
        resolver.response_canids = cast(MappingProxyType, LazyResponseLookup())
        success, addresses = resolver.resolve(
            selectors, cids=cids, location_id=location_id
        )
        if not success:
            failures = {
                "6f20": ("TCUWControlCommPhase.dll:RVA6f20", 0x6D1),
                "8990": ("TCUWControlCommPhase.dll:RVA8990", 0x79E),
                "a250": ("TCUWControlCommPhase.dll:RVAa250", 0x837),
                "9370": ("TCUWControlCommPhase.dll:RVA9370", 0xA67),
                "4c10": ("TCUWControlCommPhase.dll:RVA4c10", 0x8FF),
                "5c30": ("TCUWControlCommPhase.dll:RVA5c30", 0xB9C),
                "3b90": ("TCUWControlCommPhase.dll:RVA3b90", 0x4AE),
            }
            source, line = failures[helper]
            raise NativePassThruException2026(9999, source, line)
        return addresses

    def _begin_execute_pair(self, engine):
        """Apply the source-issued engine→CONTROL ImportData view transition."""
        pair = engine.interface_pair
        if pair is None:
            return None
        if getattr(self.runtime._device_calls, "view", None) is not None:
            raise ValueError("Execute cannot start in an engine wire view")
        control = self.runtime_device()
        if pair.control is not control:
            raise ValueError("Actual paired native control interface required")
        wire = pair.export_from(pair.engine)
        pair.import_into(control, wire)
        return pair, wire

    def execute(self, engine, session) -> dict:
        """b3e0: one imported FILE, shared primitive cursor and live phase tests."""
        from scripts.cuw_2026 import CUWEngine2026
        from scripts.cuw_parameter_pool import ControlParameterPool2026
        from scripts.programming_replay import ProgrammingReplay

        if type(engine) is not CUWEngine2026 or type(session) is not ProgrammingReplay:
            raise TypeError("Concrete native engine and replay required")
        context = self.native_control_context2026(engine)
        if session.used:
            raise ValueError("Unused raw CONTROL recording required")
        token = self._begin_native_control_raw_execution2026(engine)
        reports = []
        try:
            session._bind_control_root2026(engine, self, self.runtime)
            self._parameter_session = session
            pool = ControlParameterPool2026.issue(
                engine, self, session._catalog_sources, encoded=True
            )
            self._control_parameter_pool2026 = pool
            pair = self._begin_execute_pair(engine)
            entry_phase = engine.comm_phase
            returned = False
            if entry_phase == 0:
                returned = self._run_control_helper2026(
                    engine, session, "6f20", reports
                )
            elif context.metadata.vehicle.get("contacttype", "") in (
                "P5-Unified",
                "Phase6",
                "Ethernet",
            ):
                if engine.comm_phase == 1:
                    returned = self._run_control_helper2026(
                        engine, session, "9370", reports
                    )
                if engine.comm_phase == 2:
                    returned = self._run_control_helper2026(
                        engine, session, "5c30", reports
                    )
            else:
                # b3e0 reads the existing slot before8990 overwrites the pool.
                parameter = pool.slot(context.cpu_index).parameter
                start = context.cpu_index
                end = (
                    len(context.target_indices)
                    if parameter.boolean("CpuLoopBetweenPrepareAndWriteFlag")
                    else start + 1
                )
                for outer_index in range(start, end):
                    self.runtime.check()
                    returned = True
                    if engine.comm_phase == 1:
                        returned = self._run_control_helper2026(
                            engine, session, "8990", reports
                        )
                    if engine.comm_phase == 3:
                        returned = self._run_control_helper2026(
                            engine, session, "a250", reports, incoming=returned
                        )
                    if engine.comm_phase == 2:
                        returned = self._run_control_helper2026(
                            engine, session, "4c10", reports
                        )
                    if not returned:
                        break
                    if outer_index + 1 < end:
                        if self._control_general2026(
                            engine,
                            outer_index + 1,
                            "FlagToDoIGOFFONAtCPUTypeChange",
                        ):
                            break
                        engine.set_comm_phase(1, controller=self)
                if (
                    self.dh_mode_could_be_changed
                    and returned
                    and engine.comm_phase == 2
                ):
                    self._control_dh_tail2026(engine, session)
            # Only ordinary flow reaches4be0; a host/non-CPass exception bypasses it.
            snapshot = _record_control_return2026(engine, self, pair)
            session.used = True
            return {
                "native_phase": entry_phase,
                "native_return": returned,
                "exports": tuple(reports),
                "control_snapshot": snapshot,
                "identifiers": _control_getter_return_values2026(context)
                if entry_phase == 0
                else (),
                "programming_completed": False,
            }
        finally:
            # Expire host capabilities only. Never import interfaces or write native
            # outputs here: native unwind is not the ordinary4be0 return path.
            self._end_native_control_raw_execution2026(engine, token)

    def _run_control_helper2026(
        self, engine, session, helper, reports, *, incoming=False
    ):
        from scripts.j2534_2026 import NativePassThruError2026

        context = self.native_control_context2026(engine)
        entry = self._begin_native_control_helper_entry2026(engine, helper=helper)
        state = _NATIVE_CONTROL_HELPER_ENTRIES_2026[id(entry)][1]
        state.update(addresses={}, getter_al=False, identifiers=context.identifiers)
        try:
            try:
                returned = {
                    "6f20": self._control_getter2026,
                    "8990": self._control_classic_prepare2026,
                    "a250": self._control_gateway2026,
                    "9370": self._control_modern_prepare2026,
                    "4c10": self._control_classic_write2026,
                    "5c30": self._control_modern_write2026,
                }[helper](engine, session, entry, reports, incoming)
            except (NativePassThruException2026, NativePassThruError2026) as error:
                engine.worker._record_control_helper_cpass2026(context, error, entry)
                returned = (
                    state["getter_al"]
                    if helper == "6f20"
                    else False
                    if helper == "a250"
                    else _control_saved_family_return2026(context, entry)
                )
            if helper == "6f20":
                _record_control_getter_result2026(
                    context, entry, returned, state["identifiers"]
                )
            return returned
        finally:
            self._end_native_control_helper_entry2026(engine, lease=entry)

    def _has_loaded_control_parameters2026(self) -> bool:
        pool = self._control_parameter_pool2026
        return pool is not None and any(
            pool.slot(i).loaded for i in range(pool.capacity)
        )

    def _control_pool2026(self) -> "ControlParameterPool2026":
        pool = self._control_parameter_pool2026
        if pool is None:
            raise ValueError("Raw CONTROL parameter array has not been issued")
        return pool

    def _close_control_pool2026(self, engine) -> None:
        """b980 detach: destroy only this engine's inactive loaded module array."""
        pool = self._control_parameter_pool2026
        if pool is None or pool._state.engine is not engine:
            return
        if (
            engine.active
            or self._native_control_context2026 is not None
            or self._native_control_raw_execution2026 is not None
            or self._native_control_helper_entry2026 is not None
            or self._native_control_export_lease2026 is not None
        ):
            raise ValueError("Active CONTROL module array cannot be detached")
        pool._require_state(engine, self, active=False, check_capacity=False)
        pool.close()
        self._control_parameter_pool2026 = None

    def _control_target2026(self, engine, index, operation):
        target = NativeControlExportTarget2026.issue(
            engine, self, self._control_pool2026(), index, operation
        )
        return target

    def _control_call2026(self, engine, session, target, export, helper, reports):
        required = self._control_required_exports2026(engine, target, helper)
        report = self._invoke_control_export2026(
            engine,
            session,
            target,
            export,
            helper=helper,
            required_exports=tuple(dict.fromkeys((*required, export))),
        )
        reports.append(report)
        return report

    def _control_required_exports2026(self, engine, target, helper):
        parameter = target.binding.parameter
        if helper == "6f20":
            return ("StartGetCID",)
        if helper == "a250":
            return ("ChangeToReprogGatewayMode",)
        phase6 = target.metadata.vehicle.get("contacttype", "") == "Phase6"
        if helper in ("8990", "9370"):
            return ("StartPrepareWrite",) + (
                ("ProcessBeforeIGOffOnAtRetry",) if helper == "9370" and phase6 else ()
            )
        required = ["StartFlashWrite"]
        if helper == "4c10":
            if parameter.boolean("PrepareRetryFlag"):
                required.append("PrepareRetry")
            current = (
                self._control_pool2026()
                .slot(self.native_control_context2026(engine).cpu_index)
                .parameter
            )
            if current.boolean("ConfirmAfterEndOfFlashingFlag"):
                required.append("IsFinishReprogramming")
        elif phase6:
            required.append("ProcessBeforeIGOffOnAtRetry")
        return tuple(required)

    def _control_bool2026(self, report):
        returned = report.get("native_return")
        if type(returned) is not bool:
            raise NotImplementedError("Concrete family native BOOL is source-unknown")
        return returned

    def _control_getter2026(self, engine, session, entry, reports, _incoming):
        pool = self._control_pool2026()
        pool.load_for(engine, self, "get_cid")
        target = self._control_target2026(engine, 0, "get_cid")
        report = self._control_call2026(
            engine, session, target, "StartGetCID", "6f20", reports
        )
        values = self._cid_vector(report)
        self.alternate_cid_used = False
        state = _NATIVE_CONTROL_HELPER_ENTRIES_2026[id(entry)][1]
        state["getter_al"] = _control_alternate_getter_byte2026(target, report)
        if not values:
            alternate = target._alternate_getter2026()
            if alternate is not None:
                engine.dh_state.record_native_error(None, 0, 0)
                report = self._control_call2026(
                    engine, session, alternate, "StartGetCID", "6f20", reports
                )
                state["getter_al"] = _control_alternate_getter_byte2026(
                    alternate, report
                )
                values = self._cid_vector(report)
                self.alternate_cid_used = bool(values)
        engine._publish_control_alternate_cache2026(worker=engine.worker)
        state["identifiers"] = values
        return state["getter_al"]

    def _control_classic_prepare2026(self, engine, session, entry, reports, _incoming):
        self._control_pool2026().load_for(engine, self, "prepare")
        target = self._control_target2026(
            engine, self.native_control_context2026(engine).cpu_index, "prepare"
        )
        self._control_bool2026(
            self._control_call2026(
                engine, session, target, "StartPrepareWrite", "8990", reports
            )
        )
        engine.worker.finish_classic_prepare()
        engine._publish_control_ssmid_cache2026(worker=engine.worker)
        engine._publish_control_dh_type_cache2026(worker=engine.worker)
        return _control_saved_family_return2026(target._context, entry)

    def _control_gateway2026(self, engine, session, entry, reports, incoming):
        if incoming:
            self._control_pool2026().load_for(engine, self, "change_gateway")
            name = (
                self._control_pool2026()
                .slot(0)
                .parameter.string("DLLFileNameForChangeToReprogGatewayMode")
            )
            if name:
                target = self._control_target2026(engine, 0, "change_gateway")
                report = self._control_call2026(
                    engine,
                    session,
                    target,
                    "ChangeToReprogGatewayMode",
                    "a250",
                    reports,
                )
                # This exact field is *param7 in original Body export100010d0.
                if (
                    target.module_binding.module_name
                    != "TCUWP4CanBodyPrepareWriter.dll"
                ):
                    raise NotImplementedError(
                        "a250 gateway out-byte source adapter unavailable"
                    )
                changed = report.get("gateway_mode_changed")
                if type(changed) is not bool:
                    raise NotImplementedError(
                        "Actual gateway out-byte is source-unknown"
                    )
                if changed:
                    incoming = self._control_bool2026(report)
            if incoming:
                engine.set_comm_phase(2, controller=self)
                return True
        self._retry_control2026(engine, session, None, "a250", reports)
        if not engine.worker.control_state.failed:
            engine.worker._fatal = True
        return False

    def _control_modern_prepare2026(self, engine, session, entry, reports, _incoming):
        self._control_pool2026().load_for(engine, self, "prepare")
        target = self._control_target2026(engine, 0, "prepare")
        report = self._control_call2026(
            engine, session, target, "StartPrepareWrite", "9370", reports
        )
        returned = self._control_bool2026(report)
        engine.worker.record_callback_24(engine.repro_gateway_node)
        if returned:
            engine.set_comm_phase(2, controller=self)
        else:
            self._retry_control2026(engine, session, target, "9370", reports)
            self._control_retry_tail2026(engine, session, target, "9370", reports)
        return returned

    def _control_retry_tail2026(self, engine, session, target, helper, reports):
        if not engine.worker.control_state.failed:
            engine.worker._fatal = True
        elif target.metadata.vehicle.get("contacttype", "") == "Phase6":
            self._control_call2026(
                engine, session, target, "ProcessBeforeIGOffOnAtRetry", helper, reports
            )

    def _control_general2026(self, engine, index, name):
        metadata = self.native_control_context2026(engine).metadata_for_cpu(index)
        return engine.general_parameter_boolean(
            metadata.vehicle.get("kindofecu", ""),
            native2026_cpu_type(metadata, native2026_global_cpu_index(metadata)),
            metadata.vehicle.get("contacttype", ""),
            name,
            controller=self,
        )

    def _control_write_success2026(self, engine, index, end, *, logical):
        context = self.native_control_context2026(engine)
        engine.dh_state.record_native_error(None, 0, 0)
        engine.dh_state._native_context_964 = False
        engine.worker._failed = False
        persistence = engine.persistence
        if persistence is not None:
            if index == end:
                persistence.notification.assign(False)
            persistence.last_block_notification.assign(False)
        if not logical:
            entry = _control_helper_entry2026(context)
            state = _NATIVE_CONTROL_HELPER_ENTRIES_2026[id(entry)][1]
            if (
                state["helper"] not in ("4c10", "5c30")
                or not state["primary_return_seen"]
            ):
                raise ValueError(
                    "Actual successful source writer cursor store required"
                )
            if index != context.cpu_index + 1 or index > len(context.target_indices):
                raise ValueError("Source writer cursor must advance by exactly one")
            object.__setattr__(context, "_cpu_index", index)

    def _control_before_write2026(self, engine, entry, *, modern):
        context = self.native_control_context2026(engine)
        if not engine.worker.control_state.recovery_mode:
            return False
        _clear_control_saved_family_return2026(context, entry)
        if modern:
            engine.worker.publish_callback_25_gateway_node()
        else:
            engine.set_comm_phase(
                engine.native_control_phase_cache2026, controller=self
            )
            self.alternate_cid_used = engine.native_control_alternate_cache2026
            engine.worker.read_control_callback_29_2026(context)
            engine.dh_state._divided_image_index = (
                engine.native_control_divided_index2026
            )
            engine.worker.publish_control_callback_30_2026(context)
        return True

    def _control_classic_write2026(self, engine, session, entry, reports, _incoming):
        from scripts.cuw_2026 import set_communication_log_mode

        context = self.native_control_context2026(engine)
        pool = self._control_pool2026()
        # 151 must yield one row, then that row's full preflight, before next load.
        for index in pool.load_steps_for(engine, self, "write"):
            target = self._control_target2026(engine, index, "write")
            self._control_preflight_only2026(engine, session, target, "4c10")
        parameter = pool.slot(context.cpu_index).parameter
        end = (
            context.cpu_index + 1
            if parameter.boolean("CpuLoopBetweenPrepareAndWriteFlag")
            else len(context.target_indices)
        )
        while context.cpu_index < end:
            self.runtime.check()
            target = self._control_target2026(engine, context.cpu_index, "write")
            while True:
                if self._control_before_write2026(engine, entry, modern=False):
                    returned = False
                else:
                    set_communication_log_mode(self.runtime, 2)
                    returned = self._control_bool2026(
                        self._control_call2026(
                            engine, session, target, "StartFlashWrite", "4c10", reports
                        )
                    )
                    set_communication_log_mode(self.runtime, int(not returned))
                    engine._publish_control_retry_cache2026(worker=engine.worker)
                    engine._publish_control_phase_cache2026(worker=engine.worker)
                if returned:
                    break
                self._retry_control2026(engine, session, target, "4c10", reports)
                state = engine.worker.control_state
                if not state.failed:
                    return not state.fatal
                if engine.comm_phase == 1 or target.binding.parameter.boolean(
                    "IGOffRetriableFlag"
                ):
                    return False
            self._control_write_success2026(
                engine, context.cpu_index + 1, end, logical=False
            )
            if context.cpu_index < end and self._control_general2026(
                engine, context.cpu_index, "FlagToDoIGOFFONAtCPUTypeChange"
            ):
                break
        return _control_saved_family_return2026(context, entry)

    def _control_modern_write2026(self, engine, session, entry, reports, _incoming):
        from scripts.calibration_2026 import native2026_node_logical_block_count

        context = self.native_control_context2026(engine)
        loaded = self._control_pool2026().load_for(engine, self, "write")
        target = self._control_target2026(engine, context.cpu_index, "write")
        end = max(loaded, default=context.cpu_index - 1) + 1
        metadata = context.metadata
        logical = (
            native2026_node_logical_block_count(
                metadata,
                native2026_node_index(metadata, native2026_global_cpu_index(metadata)),
            )
            > 0
        )
        local_index = context.cpu_index
        while local_index < end:
            self.runtime.check()
            if self._control_before_write2026(engine, entry, modern=True):
                returned = False
            else:
                returned = self._control_bool2026(
                    self._control_call2026(
                        engine, session, target, "StartFlashWrite", "5c30", reports
                    )
                )
            if not returned:
                self._retry_control2026(engine, session, target, "5c30", reports)
                if not engine.worker.control_state.failed:
                    return not engine.worker.control_state.fatal
                self._control_retry_tail2026(engine, session, target, "5c30", reports)
                break
            local_index += 1
            self._control_write_success2026(engine, local_index, end, logical=logical)
            if logical:
                break
            if local_index < end:
                target = target._next_writer_cpu2026()
        return _control_saved_family_return2026(context, entry)

    def _control_preflight_only2026(self, engine, session, target, helper):
        stage = session._next_control_export2026(target, "StartFlashWrite")
        addresses = self._preflight_control_helper2026(engine, target, helper)
        lease = self._begin_native_control_helper2026(
            engine,
            target=target,
            stage=stage,
            export="StartFlashWrite",
            helper=helper,
            required_exports=self._control_required_exports2026(engine, target, helper),
            _addresses=addresses,
        )
        self._end_native_control_helper2026(engine, lease=lease)
        state = _NATIVE_CONTROL_HELPER_ENTRIES_2026[
            id(_control_helper_entry2026(target._context))
        ][1]
        state["addresses"][target.entry_index] = addresses

    def _control_dh_tail2026(self, engine, session):
        from scripts.programming_2026_dh import DHGateway2026

        selection = self._control_base_parameter2026(engine)
        dependency = session.modules.get("TCUWDHUtils.dll")
        composer = self.runtime._security_composer
        if dependency is None or dependency.native_identity is None or composer is None:
            raise ValueError("Actual final DHUtils source dependencies required")
        gateway = DHGateway2026(
            self.runtime,
            selection,
            dependency.native_identity,
            composer.client,
            engine_state=engine.dh_state,
        )
        try:
            gateway.end_reprogramming_mode(0x3FC)
        except BaseException as error:
            if not is_native_exception2026(error):
                raise
        self.dh_mode_could_be_changed = False

    def _retry_control2026(self, engine, session, target, helper, reports):
        """3b90 uses the live held pool row while retaining its loaded DLL."""
        from scripts.calibration_2026 import native2026_cpu_file_list_flag

        context = self.native_control_context2026(engine)
        pool = self._control_pool2026()
        parameter = pool.slot(context.cpu_index).parameter
        contact = context.metadata.vehicle.get("contacttype", "")
        retry_parameter = (
            pool.slot(0).parameter if contact == "P5-Unified" else parameter
        )
        ig_retriable = retry_parameter.boolean("IGOffRetriableFlag") or False
        state, worker = engine.dh_state, engine.worker
        saved_primary, saved_status = state.primary_error, state.passthru_error
        retry = engine.bind_retry_controller()
        checkpoint = False

        def query():
            self.query_control_error(engine)
            worker.copy_control_retry_decision(retry)

        def general(name):
            return self._control_general2026(engine, context.cpu_index, name)

        if not ig_retriable and engine.comm_phase == 2 and state.error_kind == 2:
            worker.set_control_error_kind(4)
        query()
        while worker.control_state.failed and engine.comm_phase == 2:
            self.runtime.check()
            proceed = ig_retriable
            if not ig_retriable:
                proceed = (
                    not general("FlagToCancelAutomaticIGOFF")
                    or engine.bind_gateway_startup().callback29()
                )
                if proceed and worker.control_state.initial_command_retry:
                    if engine.repro_gateway_node == 1:
                        retry.record_callback30(1)
                        checkpoint = True
                    if not engine.bind_gateway_startup().callback14():
                        worker.set_control_error_kind(5 if checkpoint else 3)
                        proceed = False
                elif not proceed:
                    worker.set_control_error_kind(3)
            if not proceed:
                query()
                continue
            state.mark_native_retry()
            if not parameter.boolean("PrepareRetryFlag"):
                break
            if target is None or target.binding.operation != "write":
                raise NotImplementedError(
                    "3b90 PrepareRetry requires its actual loaded writer"
                )
            if not ig_retriable and (
                worker.control_state.source_mode == 2
                or native2026_cpu_file_list_flag(context.metadata, 0)
            ):
                retry.record_callback30(1)
                checkpoint = True
            state.record_native_error(None, saved_primary, saved_status)
            timeout = parameter.long("ReceiveTimeoutBeforePrepareRetry") or 0
            if timeout > 0:
                self.runtime.call("set_timeout", milliseconds=timeout)
            report = self._control_call2026(
                engine, session, target, "PrepareRetry", helper, reports
            )
            if self._control_bool2026(report):
                state.record_native_error(None, 0, 0)
                break
            if not parameter.boolean("FlagToNonSetEerrorKindConnect"):
                worker.set_control_error_kind(5 if checkpoint else 3)
            engine.notify_native_error_kind()
            query()
        if (
            worker.control_state.failed
            and engine.comm_phase == 2
            and parameter.boolean("ConfirmAfterEndOfFlashingFlag")
        ):
            ended = worker.control_state.native_context_970
            if not parameter.boolean("IGOffRetriableFlag") or ended:
                self.runtime.call("wait", milliseconds=5000)
                if ended:
                    if target is None or target.binding.operation != "write":
                        raise NotImplementedError(
                            "3b90 IsFinish requires its actual loaded writer"
                        )
                    # 4ae uses prepare selectors, current row and original CID list.
                    self._preflight_control_helper2026(engine, target, "3b90")
                    report = self._control_call2026(
                        engine,
                        session,
                        target,
                        "IsFinishReprogramming",
                        helper,
                        reports,
                    )
                    if self._control_bool2026(report):
                        worker.finish_recovery_probe(self)
        if (
            not checkpoint
            and worker.control_state.failed
            and not ig_retriable
            and engine.comm_phase == 2
        ):
            retry.record_callback30(1)

    @staticmethod
    def _cid_vector(report: dict) -> tuple[bytes, ...]:
        values = report.get("identifiers", report.get("cids"))
        if (
            not isinstance(values, (tuple, list))
            or len(values) > 34
            or any(
                type(value) is not bytes or len(value) > 33 or b"\0" in value
                for value in values
            )
        ):
            raise ValueError("Actual bounded native CID result vector required")
        return tuple(values)

    def change_dh_gateway(self, gateway) -> bool:
        """Native ChangeDHGateway invokes concrete DHUtils and saves its flag."""
        from scripts.programming_2026_dh import DHGateway2026

        if type(gateway) is not DHGateway2026 or gateway.runtime is not self.runtime:
            raise TypeError(
                "Concrete DHUtils binding on the controller device required"
            )
        if type(gateway.selection) is NativeControlParameterBase2026:
            if gateway.selection.engine.worker.controller is not self:
                raise ValueError("Empty parameter pool belongs to another controller")
        elif not isinstance(gateway.selection, NativeParameterBinding2026):
            raise TypeError("Actual2026 parameter source binding required")
        gateway.start_reprogramming_mode(0x3FC)
        result = gateway.mode_could_be_changed
        if type(result) is not bool:
            raise ValueError("Native DH gateway state flag must be Boolean")
        self.dh_mode_could_be_changed = result
        return result

    def bind_startup_session(self, engine, session) -> None:
        """59710 retains actual loaded module dependencies before 5a835 startup."""
        from scripts.cuw_2026 import CUWEngine2026
        from scripts.cuw_parameter_pool import ControlParameterPool2026
        from scripts.programming_replay import ProgrammingReplay

        if type(engine) is not CUWEngine2026 or type(session) is not ProgrammingReplay:
            raise TypeError("Concrete startup engine and unused replay required")
        engine._require_owned_phase()
        if engine.worker.controller is not self:
            raise ValueError("Startup dependencies belong to another controller")
        module = session.modules.get("TCUWControlCommPhase.dll")
        module_data = session._module_files.get("TCUWControlCommPhase.dll")
        if (
            module is None
            or module.native_identity != self.identity
            or type(module_data) is not bytes
            or hashlib.sha256(module_data).hexdigest() != self.identity.sha256
        ):
            raise ValueError("Actual selected control module source required")
        session._bind_control_prelude2026(engine, self, self.runtime)
        self._parameter_session = session
        self._control_parameter_pool2026 = ControlParameterPool2026.issue(
            engine, self, session._catalog_sources, encoded=True
        )
        secret, cuw = (
            session._module_files.get(name) for name in ("SecretInfo.dll", "CUW.dll")
        )
        if secret is not None and cuw is not None:
            self.runtime.bind_security_composer(
                NativeSecurityComposer2026.from_native_modules(secret, cuw)
            )

    def gateway_startup_fallback(self, engine) -> bool | None:
        """Optional59710 +30 binding invokes b280 with the retained parameter pool."""
        from scripts.cuw_2026 import CUWEngine2026
        from scripts.programming_2026_dh import DHGateway2026
        from scripts.programming_replay import ProgrammingReplay

        if type(engine) is not CUWEngine2026:
            raise TypeError("Concrete native engine required for gateway fallback")
        engine._require_owned_phase()
        if engine.worker.controller is not self:
            raise ValueError("Gateway fallback belongs to another native worker")
        if "ChangeToReprogGWModeForDHCentralGW" not in self.identity.callable_exports:
            return None
        session = self._parameter_session
        if type(session) is not ProgrammingReplay:
            raise ValueError("Native DH fallback module dependencies are not bound")
        selection = self._control_base_parameter2026(engine)
        dependency = session.modules.get("TCUWDHUtils.dll")
        composer = self.runtime._security_composer
        if dependency is None or dependency.native_identity is None or composer is None:
            raise ValueError("Native DH fallback source dependencies are not bound")
        gateway = DHGateway2026(
            self.runtime,
            selection,
            dependency.native_identity,
            composer.client,
            engine_state=engine.dh_state,
        )
        with self.runtime.engine_device_calls(engine):
            return self.change_dh_gateway(gateway)

    def is_sending_sync_periodic_msg_to_ecu(self) -> bool:
        """Export1181→b850 forwards CJ2534IF::IsSendingSyncPeriodicMsg."""
        result = self.runtime.call("is_sending_sync_periodic")
        if type(result) is not bool:
            raise ValueError("J2534 sync query must return Boolean")
        return result

    def disconnect_j2534_connection(self) -> None:
        """Export10cd→b3d0 forwards CJ2534IF::Disconnect."""
        if self.runtime.owns_resource("disconnect"):
            self.runtime.release("disconnect")
        else:
            self.runtime.call("disconnect", cleanup=True)


class NativeException2026(Exception):
    """Owned message vector; messages are copied by GetMsgs and assignment."""

    def __init__(self, message: str):
        self._messages: list[str] = []
        self.add_message(message)
        super().__init__("CUW2026 native exception")

    def add_message(self, message: str) -> None:
        if (
            not isinstance(message, str)
            or "\0" in message
            or len(message.encode("latin1")) > 4096
            or len(self._messages) >= 256
        ):
            raise ValueError("Bounded native exception message required")
        self._messages.append(message)

    def messages(self) -> tuple[str, ...]:
        return tuple(self._messages)

    @classmethod
    def copy_of(cls, other: "NativeException2026", *, move: bool = False) -> Self:
        """Native copy/move construction preserves the copied message vector."""
        if (
            cls
            not in (
                NativeException2026,
                NativePassThruException2026,
                NativeJ2534Exception2026,
            )
            or type(other) is not cls
        ):
            raise TypeError("Matching concrete native exception class required")
        value = cls.__new__(cls)
        Exception.__init__(value, "CUW2026 native exception")
        value.assign(other, move=move)
        return value

    def assign(self, other: "NativeException2026", *, move: bool = False) -> Self:
        if type(self) is not type(other) or type(move) is not bool:
            raise TypeError("Matching native exception type and move Boolean required")
        self._messages = list(other._messages)
        return self


class NativePassThruException2026(NativeException2026):
    """Native error, original source location, and appended source history."""

    def __init__(self, error: int, source: str, line: int):
        self.set_error(error)
        self._validate_location(source, line)
        self.source, self.line = source, line
        super().__init__(self.create_error_message(source, line))

    @staticmethod
    def _validate_location(source: str, line: int) -> None:
        if (
            not isinstance(source, str)
            or "\0" in source
            or type(line) is not int
            or not -0x80000000 <= line <= 0x7FFFFFFF
            or len(f"{source}({line})".encode("latin1")) >= 260
        ):
            raise ValueError("Native exception location exceeds source buffer")

    @classmethod
    def create_error_message(cls, source: str, line: int) -> str:
        cls._validate_location(source, line)
        return f"{source}({line})"

    def set_error(self, error: int) -> None:
        if type(error) is not int or not -0x80000000 <= error <= 0x7FFFFFFF:
            raise ValueError("Native signed error enum required")
        self.error = error

    def set_error_info(self, source: str, line: int) -> None:
        self.add_message(self.create_error_message(source, line))

    @property
    def native_error_code(self) -> int:
        return self.error

    @property
    def passthru_status(self) -> int | None:
        return None

    def assign(self, other: "NativeException2026", *, move: bool = False) -> Self:
        super().assign(other, move=move)
        assert isinstance(other, NativePassThruException2026)
        self.error, self.source, self.line = other.error, other.source, other.line
        if move and self is not other:
            other.source = ""
        return self


class NativeJ2534Exception2026(NativePassThruException2026):
    ERROR_NO_INDICATION_RXSTART = 999
    ERROR_NO_INDICATION_TXDONE = 998

    def __init__(self, j2534_error: int, source: str, line: int):
        if type(j2534_error) is not int or not -0x80000000 <= j2534_error <= 0x7FFFFFFF:
            raise ValueError("Native signed J2534 error required")
        super().__init__(1, source, line)
        self.j2534_error = j2534_error

    @property
    def passthru_status(self) -> int:
        return self.j2534_error

    def assign(self, other: "NativeException2026", *, move: bool = False) -> Self:
        super().assign(other, move=move)
        assert isinstance(other, NativeJ2534Exception2026)
        self.j2534_error = other.j2534_error
        return self


_PARAMETER_STAGES_2026 = {
    "get_cid": ("GetCID", "StartGetCID", 0),
    "prepare": ("PrepareWrite", "StartPrepareWrite", 1),
    "write": ("FlashWrite", "StartFlashWrite", 2),
    "change_gateway": ("ChangeToReprogGatewayMode", "ChangeToReprogGatewayMode", 3),
}


_NATIVE_CONTROL_CONTEXTS_2026: dict[int, "NativeControlContext2026"] = {}
_NATIVE_CONTROL_RAW_EXECUTIONS_2026: dict[int, tuple] = {}
_NATIVE_CONTROL_HELPER_ENTRIES_2026: dict[int, tuple] = {}
_NATIVE_CONTROL_HELPER_LEASES_2026: dict[int, tuple] = {}
_NATIVE_CONTROL_RETURN_SNAPSHOTS_2026: dict[int, tuple] = {}
_NATIVE_CONTROL_GETTER_RESULTS_2026: dict[int, tuple] = {}
_POOLED_PARAMETER_BINDINGS_2026: dict[
    int, tuple[Callable[[], object | None], dict]
] = {}
_NATIVE_CONTROL_EXPORT_TARGETS_2026: WeakValueDictionary[
    int, "NativeControlExportTarget2026"
] = WeakValueDictionary()


def _register_pooled_binding2026(binding, state: dict) -> None:
    key = id(binding)

    def retire(_reference):
        _POOLED_PARAMETER_BINDINGS_2026.pop(key, None)

    _POOLED_PARAMETER_BINDINGS_2026[key] = (ref(binding, retire), state)


class NativeControlContext2026:
    """CONTROL-local FILE/order/target authority captured at the real59ab0 import."""

    __slots__ = (
        "__weakref__",
        "_capture",
        "_controller",
        "_cpu_index",
        "_engine",
        "_expired",
        "_identifiers",
        "_runtime",
        "_worker",
    )

    def __new__(cls, *args, **kwargs):
        raise TypeError("Native CONTROL contexts are issued by their controller")

    @classmethod
    def _issue(cls, engine, controller, capture):
        from scripts.cuw_2026 import CUWEngine2026
        from scripts.cuw_engine_worker import ControlFileCapture2026

        if (
            type(engine) is not CUWEngine2026
            or type(capture) is not ControlFileCapture2026
            or engine.worker.controller is not controller
            or engine.worker.runtime is not controller.runtime
        ):
            raise TypeError("Exact CONTROL capture and native owners required")
        capture.validate(engine, controller)
        result = object.__new__(cls)
        object.__setattr__(result, "_engine", engine)
        object.__setattr__(result, "_controller", controller)
        object.__setattr__(result, "_capture", capture)
        object.__setattr__(result, "_worker", engine.worker)
        object.__setattr__(result, "_runtime", controller.runtime)
        object.__setattr__(result, "_identifiers", tuple(engine.received_identifiers))
        object.__setattr__(result, "_cpu_index", capture.control_cpu_start)
        if type(result._cpu_index) is not int or result._cpu_index < 0:
            raise ValueError("Captured CONTROL local CPU index is invalid")
        object.__setattr__(result, "_expired", False)
        _NATIVE_CONTROL_CONTEXTS_2026[id(result)] = result
        return result

    def __repr__(self) -> str:
        return "NativeControlContext2026(<source-issued>)"

    def __setattr__(self, name, value):
        raise AttributeError("Native CONTROL context is immutable")

    @property
    def cpu_index(self) -> int:
        self.validate(self._engine, self._controller)
        return self._cpu_index

    @property
    def metadata(self) -> Native2026Metadata:
        return self.metadata_for_cpu(self.cpu_index)

    @property
    def target_indices(self) -> tuple[int, ...]:
        self.validate(self._engine, self._controller)
        return self._capture.target_indices

    @property
    def identifiers(self) -> tuple[bytes, ...]:
        """59ab0 copies caller59c/118 once; outer FILE movement cannot replace it."""
        self.validate(self._engine, self._controller)
        return self._identifiers

    @property
    def target_index(self) -> int:
        index = self.cpu_index
        targets = self.target_indices
        if index >= len(targets):
            raise IndexError("CONTROL local CPU index exceeds captured target vector")
        return targets[index]

    def metadata_for_cpu(self, native_index: int) -> Native2026Metadata:
        self.validate(self._engine, self._controller)
        if type(native_index) is not int or native_index < 0:
            raise IndexError("Unsigned CONTROL native CPU index required")
        return self._capture.metadata_for_cpu(native_index)

    def native_index_for_source_cpu(self, source_index: int) -> int:
        """Map a held post-rebuild CPU index to this FILE's ordered index."""
        self.validate(self._engine, self._controller)
        if type(source_index) is not int or source_index < 0:
            raise IndexError("Unsigned held CONTROL source CPU index required")
        try:
            return self._capture.native_order.index(source_index)
        except ValueError as error:
            raise ValueError(
                "CPU is absent from the held CONTROL FILE order"
            ) from error

    @property
    def count_scratch(self) -> tuple[int, ...]:
        self.validate(self._engine, self._controller)
        getter = getattr(self._worker, "_control_progress_scratch2026", None)
        if not callable(getter):
            raise NotImplementedError("114 worker-owned CONTROL scratch API is pending")
        counts, _percentages = getter(self)
        if type(counts) is not tuple:
            raise TypeError("Immutable worker-owned CONTROL count scratch required")
        return counts

    @property
    def percentage_scratch(self) -> tuple[int, ...]:
        self.validate(self._engine, self._controller)
        getter = getattr(self._worker, "_control_progress_scratch2026", None)
        if not callable(getter):
            raise NotImplementedError("114 worker-owned CONTROL scratch API is pending")
        _counts, percentages = getter(self)
        if type(percentages) is not tuple:
            raise TypeError(
                "Immutable worker-owned CONTROL percentage scratch required"
            )
        return percentages

    def _store_count2026(self, target, index: int, value: int) -> None:
        self.validate(self._engine, self._controller)
        target.validate(self._engine, self._controller)
        if target._context is not self:
            raise ValueError("CONTROL count target belongs to another context")
        store = getattr(self._worker, "_store_control_count2026", None)
        if not callable(store):
            raise NotImplementedError("114 worker-owned CONTROL count store is pending")
        store(self, target, index, value)

    def _store_percentage2026(self, target, index: int, value: int) -> None:
        self.validate(self._engine, self._controller)
        target.validate(self._engine, self._controller)
        if target._context is not self:
            raise ValueError("CONTROL percentage target belongs to another context")
        store = getattr(self._worker, "_store_control_percentage2026", None)
        if not callable(store):
            raise NotImplementedError(
                "114 worker-owned CONTROL percentage store is pending"
            )
        store(self, target, index, value)

    def validate(self, engine, controller) -> None:
        from scripts.cuw_2026 import CUWEngine2026
        from scripts.cuw_engine_worker import ControlFileCapture2026

        if (
            _NATIVE_CONTROL_CONTEXTS_2026.get(id(self)) is not self
            or self._expired
            or self._engine is not engine
            or self._controller is not controller
            or controller._native_control_context2026 is not self
            or type(engine) is not CUWEngine2026
            or engine.worker is not self._worker
            or engine.worker.controller is not controller
            or engine.worker.runtime is not self._runtime
            or controller.runtime is not self._runtime
            or type(self._capture) is not ControlFileCapture2026
        ):
            raise ValueError("CONTROL context is foreign, stale, or unowned")
        engine._require_owned_phase()
        self._capture.validate(engine, controller)


def _pooled_binding_state2026(binding: "NativeParameterBinding2026") -> dict | None:
    entry = _POOLED_PARAMETER_BINDINGS_2026.get(id(binding))
    if entry is None or entry[0]() is not binding:
        return None
    return entry[1]


@dataclass(frozen=True)
class NativeParameterBinding2026:
    """One exact native parameter file/selected row, frozen before events."""

    source_name: str
    source_sha256: str
    key: str
    operation: str
    values: Mapping[str, tuple[str, ...]] = field(repr=False)
    metadata: Native2026Metadata = field(repr=False)
    headers: tuple[str, ...] = field(repr=False)
    rows: tuple[tuple[tuple[str, ...], ...], ...] = field(repr=False)
    cpu_type: str
    encoded: bool
    catalog_sources: Mapping[str, bytes] = field(repr=False)
    module_binding: "NativeParameterBinding2026 | None" = field(
        default=None, repr=False
    )
    origin_metadata: Native2026Metadata | None = field(default=None, repr=False)
    alternate_cid: bool = False
    loaded_parameter_metadata: Native2026Metadata | None = field(
        default=None, repr=False
    )
    _pool_issued: bool = field(default=False, repr=False, compare=False)

    @property
    def getter_parameter_metadata(self) -> Native2026Metadata | None:
        return self.loaded_parameter_metadata if self.operation == "get_cid" else None

    def rebind_getter_metadata(
        self, live_metadata: Native2026Metadata
    ) -> "NativeParameterBinding2026":
        """6f20/7c20 retain the row while CalibrationFile may change."""
        if self.operation != "get_cid" or self.origin_metadata is not None:
            raise ValueError("Original getter parameter selection required")
        return self._rebind_loaded_metadata(live_metadata)

    def rebind_prepare_metadata(
        self, live_metadata: Native2026Metadata
    ) -> "NativeParameterBinding2026":
        """9370 retains the prepare DLL for ProcessBeforeIGOffOnAtRetry."""
        if self.operation != "prepare" or self.alternate_cid:
            raise ValueError("Actual loaded prepare parameter selection required")
        return self._rebind_loaded_metadata(live_metadata)

    def rebind_writer_metadata(
        self, live_metadata: Native2026Metadata
    ) -> "NativeParameterBinding2026":
        """8780/3b90 retain the actual loaded writer and its parameter row."""
        if self.operation != "write" or self.alternate_cid:
            raise ValueError("Actual loaded writer parameter selection required")
        return self._rebind_loaded_metadata(live_metadata)

    def _rebind_loaded_metadata(
        self, live_metadata: Native2026Metadata
    ) -> "NativeParameterBinding2026":
        if self._pool_issued:
            raise ValueError("Source-issued pooled rows cannot be rebound")
        if type(live_metadata) is not Native2026Metadata:
            raise TypeError("Actual live native metadata required")
        original = self.loaded_parameter_metadata or self.metadata
        if (
            live_metadata.source_container != original.source_container
            or live_metadata.node != original.node
            or live_metadata.cpu_index != original.cpu_index
            or live_metadata.region != original.region
        ):
            raise ValueError("Live parameter source and target must remain unchanged")
        self.validate_against(
            original.source_container,
            operation=self.operation,
            node=original.node,
            cpu_index=original.cpu_index,
            alternate_cpu=self.origin_metadata is not None,
        )
        native2026_validate_runtime_metadata(live_metadata)
        if live_metadata.parser_parameters_validated:
            general = NativeGeneralParameters2026.from_sources(
                self.catalog_sources, encoded=self.encoded
            )
            if general != live_metadata.parser_general_parameters:
                raise ValueError("Live parameter General source differs from catalog")
        return replace(self, metadata=live_metadata, loaded_parameter_metadata=original)

    def require_control_versions(self) -> None:
        """3a30/7c20 require native total4 or alternate total1, even if absent."""
        field_name = (
            "EnableAlternateDLLVersionsInformationForGetCID"
            if self.alternate_cid
            else "EnableDLLVersionInformation"
        )
        required = 1 if self.alternate_cid else 4
        source = self if self.alternate_cid else (self.module_binding or self)
        if len(source.lines(field_name)) != required:
            raise ValueError("Native control requires exact phase version count")

    def alternate_cid_binding(self) -> "NativeParameterBinding2026 | None":
        """7c20: source first filename, total version count, one native output slot."""
        if self._pool_issued:
            raise ValueError("A pooled getter must reuse its actual loaded slot")
        if self.operation != "get_cid" or self.alternate_cid:
            raise ValueError("Primary native getter binding required")
        names = self.lines("AlternateDLLFileNamesForGetCID")
        if not names or not names[0]:
            return None
        versions = self.lines("EnableAlternateDLLVersionsInformationForGetCID")
        if not versions or not versions[0]:
            return None
        if len(versions) != 1:
            raise ValueError(
                "Native alternate CID versions exceed one initialized slot"
            )
        if not re.fullmatch(r"[A-Za-z0-9_-]+\.dll", names[0]):
            raise ValueError("Native alternate getter filename is invalid")
        return replace(self, alternate_cid=True)

    @property
    def source_file(self) -> str:
        return self.source_name

    @property
    def module_name(self) -> str:
        if self.alternate_cid:
            return self.lines("AlternateDLLFileNamesForGetCID")[0]
        if self.module_binding is not None:
            return self.module_binding.module_name
        suffix = _PARAMETER_STAGES_2026[self.operation][0]
        return self.value("DLLFileNameFor" + suffix)

    @property
    def selector_functions(self) -> tuple[str, ...]:
        suffix = _PARAMETER_STAGES_2026[self.operation][0]
        values = self.lines("GetCANIDFunctionNameFor" + suffix)
        if not values or not values[0]:
            return ()
        classic_prepare = self.operation == "prepare" and self.metadata.vehicle.get(
            "contacttype", ""
        ) not in ("P5-Unified", "Phase6", "Ethernet")
        if classic_prepare:
            if len(values) > 4:
                raise ValueError(
                    "Native classic prepare selector count exceeds four output slots"
                )
            return values
        return values[:1]

    def reselect_alternate_cpu(self) -> "NativeParameterBinding2026":
        """Pure parameter reload using this exact row's AlternateCPUType field.

        This does not mutate source CUW metadata or redispatch a loaded writer.
        The concrete caller owns the native SetCPUType/firmware condition.
        """
        if self._pool_issued:
            raise ValueError("A pooled binding cannot select another parameter row")
        alternate = self.value("AlternateCPUType")
        if (
            not alternate
            or len(alternate) > 128
            or not re.fullmatch(r"[A-Za-z0-9_-]+", alternate)
        ):
            raise LookupError("Native selected AlternateCPUType unavailable")
        prefix = self.key[: -len(self.cpu_type)] if self.cpu_type else self.key
        key = prefix + alternate
        filename = key + ".ini"
        if filename not in self.catalog_sources:
            raise LookupError("Exact alternate CPU parameter file unavailable")
        data = self.catalog_sources[filename]
        parameter = (
            NativeParameter2026.from_encoded(data)
            if self.encoded
            else NativeParameter2026.from_csv(data)
        )
        parameter.row_index = parameter.search_row(parameter.key_column, key)
        if parameter.row_index < 0:
            raise LookupError("Exact alternate CPU parameter row unavailable")
        selected = parameter.rows[parameter.row_index - 1]
        selected_values = {}
        for name, value in zip(parameter.headers, selected, strict=True):
            selected_values.setdefault(name, value)
        values = MappingProxyType(selected_values)
        return NativeParameterBinding2026(
            filename,
            hashlib.sha256(data).hexdigest(),
            key,
            self.operation,
            values,
            native2026_with_cpu_type(
                self.metadata, native2026_global_cpu_index(self.metadata), alternate
            ),
            parameter.headers,
            parameter.rows,
            alternate,
            self.encoded,
            self.catalog_sources,
            None,
            self.origin_metadata or self.metadata,
        )

    def validate_against(
        self,
        container,
        *,
        operation: str,
        node: int = 1,
        cpu_index: int = 0,
        alternate_cpu: bool = False,
    ) -> "NativeParameterBinding2026":
        """Reproduce exact file/row binding from immutable catalog and CUW bytes."""
        if self._pool_issued:
            if _pooled_binding_state2026(self) is None:
                raise ValueError("Exact source-issued pooled binding identity required")
            _validate_pooled_binding2026(self, container, operation)
            return self
        if type(alternate_cpu) is not bool:
            raise TypeError("Explicit native alternate-CPU branch Boolean required")
        retained = self.loaded_parameter_metadata
        selected_alternate = alternate_cpu or (
            retained is not None and self.origin_metadata is not None
        )
        if retained is not None and (
            operation != self.operation
            or operation not in ("get_cid", "prepare", "write")
            or (operation == "get_cid" and selected_alternate)
        ):
            raise ValueError("Retained parameter row cannot select another branch")
        expected = bind_native_parameter2026(
            container,
            self.catalog_sources,
            operation,
            node=node,
            cpu_index=cpu_index,
            encoded=self.encoded,
            metadata_state=(
                self.origin_metadata
                if selected_alternate
                else (retained or self.metadata)
            ),
        )
        if selected_alternate:
            expected = expected.reselect_alternate_cpu()
        if self.alternate_cid:
            if selected_alternate:
                raise ValueError("Alternate getter and alternate CPU selections differ")
            alternate = expected.alternate_cid_binding()
            if alternate is None:
                raise ValueError("Native source has no alternate getter selection")
            expected = alternate
        if retained is not None:
            expected = expected._rebind_loaded_metadata(self.metadata)
        if self != expected:
            raise ValueError(
                "Native parameter binding differs from actual source selection"
            )
        return expected

    @property
    def parameter(self) -> NativeParameter2026:
        """Return a mutable native parameter instance from the frozen source rows."""
        state = _pooled_binding_state2026(self)
        if self._pool_issued:
            if state is None:
                raise ValueError("Exact source-issued pooled binding identity required")
            _validate_pooled_binding2026(
                self, self.metadata.source_container, self.operation
            )
            result = NativeParameter2026(self.headers, self.rows)
            result.key_column = state["key_column"]
            result.row_index = state["row_index"]
            return result
        result = NativeParameter2026(
            self.headers, self.rows, "ParamFileKeySystemProtocolMicon"
        )
        result.row_index = result.search_row(result.key_column, self.key)
        return result

    def lines(self, name: str) -> tuple[str, ...]:
        if self._pool_issued:
            _validate_pooled_binding2026(
                self, self.metadata.source_container, self.operation
            )
        return self.values.get(name, ())

    def value(self, name: str) -> str:
        values = self.lines(name)
        return values[0] if values else ""

    def dispatch(
        self,
        module_files: Mapping[str, bytes],
        *,
        module_versions: Mapping[str, str] | None = None,
    ) -> dict:
        if self._pool_issued:
            _validate_pooled_binding2026(
                self, self.metadata.source_container, self.operation
            )
        _suffix, export, phase_index = _PARAMETER_STAGES_2026[self.operation]
        module = self.module_name
        if not re.fullmatch(r"[A-Za-z0-9_-]+\.dll", module):
            raise LookupError("Native selected DLL field is unavailable or invalid")
        if not isinstance(module_files, Mapping) or module not in module_files:
            raise LookupError("Exact selected native DLL bytes unavailable")
        data = module_files[module]
        if not isinstance(data, bytes) or not 0 < len(data) <= 64 * 1024 * 1024:
            raise ValueError("Bounded immutable native DLL bytes required")
        identity = identify_native_module(hashlib.sha256(data).hexdigest(), module)
        if identity.cuw_build != "2026":
            raise ValueError("Selected parameter DLL belongs to another native build")
        required = [export]
        if self.operation == "write":
            for flag, extra in (
                ("PrepareRetryFlag", "PrepareRetry"),
                ("ConfirmAfterEndOfFlashingFlag", "IsFinishReprogramming"),
            ):
                if _native_long(self.value(flag)):
                    required.append(extra)
        if any(name not in identity.callable_exports for name in required):
            raise LookupError("Selected native DLL export is unavailable")
        versions = (
            (self.module_binding or self).lines("EnableDLLVersionInformation")
            if not self.alternate_cid
            else self.lines("EnableAlternateDLLVersionsInformationForGetCID")
        )
        checked = False
        if versions:
            if (
                len(versions) != (1 if self.alternate_cid else 4)
                or module_versions is None
                or module not in module_versions
            ):
                raise LookupError("Native phase DLL version dependency unavailable")
            actual = module_versions[module]
            if not isinstance(actual, str) or "\0" in actual or len(actual) > 259:
                raise ValueError("Bounded native DLL version required")
            if actual.encode("latin1") < versions[phase_index].encode("latin1"):
                raise ValueError("Selected DLL FileVersion is below native requirement")
            checked = True
        return {
            "module": module,
            "operation": export,
            "required_exports": tuple(required),
            "selectors": self.selector_functions,
            "identity": identity,
            "module_version_checked": checked,
            "source_name": self.source_name,
            "source_sha256": self.source_sha256,
            "key": self.key,
        }


def bind_native_parameter2026(
    container,
    catalog_sources: Mapping[str, bytes],
    operation: str,
    *,
    node: int = 1,
    cpu_index: int = 0,
    encoded: bool = True,
    metadata_state: Native2026Metadata | None = None,
    region: int | None = None,
) -> NativeParameterBinding2026:
    """ControlCommPhase file/row selectors, directly from actual2026 metadata.

    Source keys are exact native filenames. A similar filename, another build,
    or an unselected row never supplies a fallback.
    """
    if operation not in _PARAMETER_STAGES_2026 or type(encoded) is not bool:
        raise ValueError("Known native parameter stage and encoding flag required")
    if (
        not isinstance(catalog_sources, Mapping)
        or len(catalog_sources) > 4096
        or any(
            not isinstance(name, str) or len(name) > 259 or not isinstance(data, bytes)
            for name, data in catalog_sources.items()
        )
        or sum(len(data) for data in catalog_sources.values()) > 64 * 1024 * 1024
    ):
        raise TypeError("Bounded exact immutable parameter source mapping required")
    catalog_sources = MappingProxyType(dict(catalog_sources))
    if metadata_state is not None and not isinstance(
        metadata_state, Native2026Metadata
    ):
        raise TypeError("Actual native runtime metadata state required")
    if region is None:
        region = metadata_state.region if metadata_state is not None else 0
    if type(region) is not int or not 0 <= region <= 3:
        raise ValueError("Native zero-based region0..3 required")
    metadata = native2026_metadata(
        container, node=node, cpu_index=cpu_index, region=region
    )
    if metadata_state is not None:
        if metadata_state.source_container != container:
            raise ValueError(
                "Runtime metadata source container differs from actual source"
            )
        native2026_validate_runtime_metadata(metadata_state)
        if (
            metadata_state.node != node
            or metadata_state.cpu_index != cpu_index
            or metadata_state.region != region
        ):
            raise ValueError("Runtime metadata target differs from requested target")
        if metadata_state.parser_parameters_validated:
            general = NativeGeneralParameters2026.from_sources(
                catalog_sources, encoded=encoded
            )
            if general != metadata_state.parser_general_parameters:
                raise ValueError(
                    "Runtime parser General source differs from bound catalog"
                )
        metadata = metadata_state
    kind = metadata.vehicle.get("kindofecu", "")
    contact = metadata.vehicle.get("contacttype", "")
    modern = contact in ("P5-Unified", "Phase6", "Ethernet")
    if operation == "change_gateway" and modern:
        raise ValueError("Phase3 gateway export belongs only to classic control flow")
    selected_index = native2026_global_cpu_index(metadata)
    cpu = native2026_cpu_type(
        metadata,
        selected_index if operation in ("prepare", "write") and not modern else 0,
    )
    module_binding = None
    if operation == "prepare" and not modern and selected_index != 0:
        # 8990 selects per-CPU parameters, but its DLL/version come from CPU0.
        first_node = native2026_node_index(metadata, 0) + 1
        first_state = native2026_metadata_for_cpu(metadata, 0)
        module_binding = bind_native_parameter2026(
            container,
            catalog_sources,
            operation,
            node=first_node,
            cpu_index=0,
            encoded=encoded,
            metadata_state=first_state,
        )
    protocol = ""
    if operation == "get_cid":
        if metadata.format_version >= 101:
            protocol = native2026_node_values(metadata, 0).get("protocol", "")
    elif modern:
        required = metadata.node_values.get("requiredspecreprover", "02")
        if required != "02":
            if contact == "Phase6":
                protocol = metadata.protocol_at_node
            else:
                protocol = required
    components = (kind, contact, protocol, cpu)
    if any(
        not isinstance(value, str)
        or not value.isascii()
        or "\0" in value
        or len(value) > 128
        for value in components
    ):
        raise ValueError("Bounded native parameter key components required")
    key = "".join(components)
    if not key or not re.fullmatch(r"[A-Za-z0-9_-]+", key) or len(key) > 255:
        raise ValueError("Native selected parameter key is invalid")
    filename = key + ".ini"
    if filename not in catalog_sources:
        raise LookupError("Exact native selected parameter file unavailable")
    data = catalog_sources[filename]
    parameter = (
        NativeParameter2026.from_encoded(data)
        if encoded
        else NativeParameter2026.from_csv(data)
    )
    if not parameter.set_keys(kind, cpu, contact + protocol):
        raise LookupError("Exact native parameter row key unavailable")
    selected = parameter.rows[parameter.row_index - 1]
    selected_values = {}
    for name, value in zip(parameter.headers, selected, strict=True):
        selected_values.setdefault(name, value)
    values = MappingProxyType(selected_values)
    return NativeParameterBinding2026(
        filename,
        hashlib.sha256(data).hexdigest(),
        key,
        operation,
        values,
        metadata,
        parameter.headers,
        parameter.rows,
        cpu,
        encoded,
        catalog_sources,
        module_binding,
    )


def _validate_pooled_binding2026(binding, container, operation) -> None:
    state = _pooled_binding_state2026(binding)
    if state is None:
        raise ValueError("Exact source-issued pooled parameter binding required")
    engine, controller, pool = state["engine"], state["controller"], state["pool"]
    if (
        container is not binding.metadata.source_container
        or operation != binding.operation
    ):
        raise ValueError("Pooled binding source or operation differs")
    pool.validate(engine, controller)
    context = controller.native_control_context2026(engine)
    context.validate(engine, controller)
    if (
        context is not state["context"]
        or context._capture is not state["capture"]
        or context._capture.metadata.source_container
        is not state["load_metadata"].source_container
    ):
        raise ValueError("Pooled binding is outside its held CONTROL FILE")
    native2026_validate_runtime_metadata(binding.metadata)
    native2026_validate_runtime_metadata(state["load_metadata"])
    slot, loaded_metadata = pool._binding_state2026(engine, controller, state["index"])
    if (
        slot is not state["slot"]
        or loaded_metadata is not state["load_metadata"]
        or slot.revision != state["revision"]
        or slot.filename != binding.source_name
        or slot.source_sha256 != binding.source_sha256
        or slot.loaded is not True
    ):
        raise ValueError("Pooled binding slot was replaced or unloaded")
    parameter = slot.parameter
    if (
        parameter.headers != binding.headers
        or parameter.rows != binding.rows
        or parameter.key_column != state["key_column"]
        or parameter.row_index != state["row_index"]
    ):
        raise ValueError("Pooled binding no longer matches its loaded native row")
    catalog_sources = pool.catalog_sources
    if (
        pool.encoded is not state["encoded"]
        or dict(catalog_sources) != dict(state["catalog_sources"])
        or hashlib.sha256(catalog_sources[binding.source_name]).hexdigest()
        != binding.source_sha256
    ):
        raise ValueError("Pooled binding catalog identity changed")


def _binding_from_control_pool2026(
    engine, controller, pool, index: int, operation: str
) -> NativeParameterBinding2026:
    """Issue a binding from one exact loaded pool row, never by key reselection."""
    from scripts.cuw_2026 import CUWEngine2026
    from scripts.cuw_parameter_pool import (
        ControlParameterPool2026,
        ControlParameterSlot2026,
    )

    if (
        type(engine) is not CUWEngine2026
        or type(controller) is not ControlCommPhase2026
        or type(pool) is not ControlParameterPool2026
        or type(index) is not int
        or index < 0
        or operation not in _PARAMETER_STAGES_2026
    ):
        raise TypeError("Concrete CONTROL pool binding inputs required")
    pool.validate(engine, controller)
    context = controller.native_control_context2026(engine)
    context.validate(engine, controller)
    slot, load_metadata = pool._binding_state2026(engine, controller, index)
    if type(slot) is not ControlParameterSlot2026:
        raise TypeError("Exact source-issued CONTROL pool slot required")
    if type(load_metadata) is not Native2026Metadata:
        raise TypeError("Strict load-time native metadata required")
    native2026_validate_runtime_metadata(load_metadata)
    metadata = native2026_validate_runtime_metadata(context.metadata)
    if (
        load_metadata.source_container is not context._capture.metadata.source_container
        or metadata.source_container is not load_metadata.source_container
        or not slot.loaded
        or slot.filename is None
        or slot.source_sha256 is None
    ):
        raise ValueError("Loaded pool row must belong to the held CONTROL FILE")
    encoded = pool.encoded
    catalog_sources = pool.catalog_sources
    if type(encoded) is not bool:
        raise TypeError("Source-issued pool encoding flag required")
    catalog = dict(catalog_sources)
    data = catalog.get(slot.filename)
    if (
        type(data) is not bytes
        or hashlib.sha256(data).hexdigest() != slot.source_sha256
    ):
        raise ValueError("Loaded pool source differs from the exact bound catalog")
    parameter = slot.parameter
    row_index = slot.row_index
    if (
        type(row_index) is not int
        or row_index <= 0
        or row_index > len(parameter.rows)
        or parameter.row_index != row_index
        or not 0 <= parameter.key_column < len(parameter.headers)
    ):
        raise ValueError("Loaded CONTROL slot has no valid selected native row")
    row = parameter.rows[row_index - 1]
    key_cell = row[parameter.key_column]
    if not key_cell:
        raise ValueError("Loaded CONTROL row has no native key")
    key = key_cell[0]
    values = {}
    for name, cell in zip(parameter.headers, row, strict=True):
        values.setdefault(name, cell)
    values = MappingProxyType(values)
    contact = load_metadata.vehicle.get("contacttype", "")
    modern = contact in ("P5-Unified", "Phase6", "Ethernet")
    cpu_index = (
        native2026_global_cpu_index(load_metadata)
        if operation in ("prepare", "write") and not modern
        else 0
    )
    cpu_type = native2026_cpu_type(load_metadata, cpu_index)
    catalog_snapshot = MappingProxyType(catalog)
    binding = NativeParameterBinding2026(
        slot.filename,
        slot.source_sha256,
        key,
        operation,
        values,
        metadata,
        parameter.headers,
        parameter.rows,
        cpu_type,
        encoded,
        catalog_snapshot,
        None,
        None,
        False,
        load_metadata,
        _pool_issued=True,
    )
    state = {
        "engine": engine,
        "controller": controller,
        "pool": pool,
        "index": index,
        "slot": slot,
        "revision": slot.revision,
        "context": context,
        "capture": context._capture,
        "load_metadata": load_metadata,
        "catalog_sources": catalog_snapshot,
        "encoded": encoded,
        "key_column": parameter.key_column,
        "row_index": row_index,
    }
    _register_pooled_binding2026(binding, state)
    if operation == "prepare" and not modern and index != 0:
        module_binding = _binding_from_control_pool2026(
            engine, controller, pool, 0, operation
        )
        binding = replace(binding, module_binding=module_binding)
        # Replacing a frozen dataclass intentionally loses the unregistered object;
        # register the exact returned identity with the same frozen pool evidence.
        _register_pooled_binding2026(binding, state)
    return binding


class NativeControlExportTarget2026:
    """Frozen entry module/slot with live CONTROL metadata and local CPU projection."""

    __slots__ = (
        "__weakref__",
        "_binding",
        "_context",
        "_controller",
        "_engine",
        "_entry_cpu_index",
        "_entry_index",
        "_entry_revision",
        "_entry_slot",
        "_module_binding",
        "_pool",
    )

    def __new__(cls, *args, **kwargs):
        raise TypeError("CONTROL export targets are issued from loaded pool slots")

    @classmethod
    def issue(cls, engine, controller, pool, index: int, operation: str):
        binding = _binding_from_control_pool2026(
            engine, controller, pool, index, operation
        )
        context = controller.native_control_context2026(engine)
        slot = pool.slot(index)
        result = object.__new__(cls)
        object.__setattr__(result, "_engine", engine)
        object.__setattr__(result, "_controller", controller)
        object.__setattr__(result, "_pool", pool)
        object.__setattr__(result, "_context", context)
        object.__setattr__(result, "_entry_slot", slot)
        object.__setattr__(result, "_entry_index", index)
        object.__setattr__(result, "_entry_revision", slot.revision)
        object.__setattr__(result, "_binding", binding)
        object.__setattr__(result, "_module_binding", binding.module_binding or binding)
        object.__setattr__(result, "_entry_cpu_index", context.cpu_index)
        _NATIVE_CONTROL_EXPORT_TARGETS_2026[id(result)] = result
        result.validate(engine, controller)
        return result

    def __repr__(self) -> str:
        return "NativeControlExportTarget2026(<source-issued>)"

    def _alternate_getter2026(self):
        """7c20 retains slot0 and changes only its source-named getter DLL."""
        self.validate(self._engine, self._controller)
        if self.binding.operation != "get_cid" or self.binding.alternate_cid:
            raise ValueError("Actual primary pooled getter required")
        context = self._context
        entry = _control_helper_entry2026(context)
        if _NATIVE_CONTROL_HELPER_ENTRIES_2026[id(entry)][1]["helper"] != "6f20":
            raise ValueError("Alternate getter belongs to the actual6f20 helper")
        names = self.binding.lines("AlternateDLLFileNamesForGetCID")
        versions = self.binding.lines("EnableAlternateDLLVersionsInformationForGetCID")
        if not names or not names[0] or not versions:
            return None
        if len(versions) != 1 or not re.fullmatch(r"[A-Za-z0-9_-]+\.dll", names[0]):
            raise ValueError("Bounded one-slot native alternate getter required")
        binding = replace(self.binding, alternate_cid=True)
        binding_state = _pooled_binding_state2026(self.binding)
        if binding_state is None:
            raise ValueError("Actual pooled getter row lineage required")
        _register_pooled_binding2026(binding, binding_state)
        result = object.__new__(type(self))
        for name in self.__slots__:
            if name != "__weakref__":
                object.__setattr__(result, name, getattr(self, name))
        object.__setattr__(result, "_binding", binding)
        object.__setattr__(result, "_module_binding", binding)
        _NATIVE_CONTROL_EXPORT_TARGETS_2026[id(result)] = result
        result.validate(self._engine, self._controller)
        return result

    def _next_writer_cpu2026(self):
        """5c30 passes the next row/FILE CPU while retaining its entry DLL."""
        engine, controller, context = self._engine, self._controller, self._context
        self.validate(engine, controller)
        lease = _control_helper_entry2026(context)
        entry = _NATIVE_CONTROL_HELPER_ENTRIES_2026[id(lease)][1]
        if (
            entry["helper"] != "5c30"
            or not entry["primary_return_seen"]
            or context.cpu_index != self.entry_cpu_index + 1
        ):
            raise ValueError("Actual modern writer source cursor advance required")
        result = type(self).issue(
            engine, controller, self._pool, context.cpu_index, "write"
        )
        binding = replace(result.binding, module_binding=self.module_binding)
        binding_state = _pooled_binding_state2026(result.binding)
        if binding_state is None:
            raise ValueError("Actual pooled writer row lineage required")
        _register_pooled_binding2026(binding, binding_state)
        object.__setattr__(result, "_binding", binding)
        object.__setattr__(result, "_module_binding", self.module_binding)
        entry["addresses"][result.entry_index] = entry["addresses"][self.entry_index]
        result.validate(engine, controller)
        return result

    def __setattr__(self, name, value):
        raise AttributeError("Native CONTROL export target is immutable")

    def validate(self, engine, controller) -> None:
        if (
            _NATIVE_CONTROL_EXPORT_TARGETS_2026.get(id(self)) is not self
            or self._engine is not engine
            or self._controller is not controller
        ):
            raise ValueError("CONTROL export target is foreign or stale")
        self._context.validate(engine, controller)
        self._pool.validate(engine, controller)
        if (
            controller.native_control_context2026(engine) is not self._context
            or self._pool.slot(self._entry_index) is not self._entry_slot
            or self._entry_slot.revision != self._entry_revision
        ):
            raise ValueError("CONTROL export entry slot or execution context changed")
        self._binding.validate_against(
            self._binding.metadata.source_container,
            operation=self._binding.operation,
        )
        if self._module_binding is not self._binding:
            self._module_binding.validate_against(
                self._module_binding.metadata.source_container,
                operation=self._module_binding.operation,
            )

    @property
    def entry_slot(self):
        self.validate(self._engine, self._controller)
        return self._entry_slot

    @property
    def entry_index(self) -> int:
        self.validate(self._engine, self._controller)
        return self._entry_index

    @property
    def entry_revision(self) -> int:
        self.validate(self._engine, self._controller)
        return self._entry_revision

    @property
    def binding(self) -> NativeParameterBinding2026:
        self.validate(self._engine, self._controller)
        return self._binding

    @property
    def module_binding(self) -> NativeParameterBinding2026:
        self.validate(self._engine, self._controller)
        return self._module_binding

    @property
    def entry_cpu_index(self) -> int:
        self.validate(self._engine, self._controller)
        return self._entry_cpu_index

    @property
    def metadata(self) -> Native2026Metadata:
        self.validate(self._engine, self._controller)
        return self._context.metadata

    @property
    def cpu_index(self) -> int:
        self.validate(self._engine, self._controller)
        return self._context.cpu_index

    @property
    def target_index(self) -> int:
        self.validate(self._engine, self._controller)
        return self._context.target_index


def _control_export_dispatch2026(target, export: str):
    """Expose dispatch metadata only inside the actual raw helper export lease."""
    from scripts.cuw_2026 import CUWEngine2026

    if type(target) is not NativeControlExportTarget2026 or type(export) is not str:
        raise TypeError("Exact source-issued CONTROL target and export required")
    engine, controller = target._engine, target._controller
    if type(engine) is not CUWEngine2026:
        raise ValueError("CONTROL dispatch target has no concrete engine")
    target.validate(engine, controller)
    lease = controller._native_control_export_lease2026
    record = _NATIVE_CONTROL_HELPER_LEASES_2026.get(id(lease))
    if (
        lease is None
        or record is None
        or record[0] is not lease
        or record[1]["target"] is not target
        or record[1]["context"] is not target._context
        or record[1]["export"] != export
        or record[1]["stage"]._control_target2026 is not target
        or record[1]["stage"]._control_export2026 != export
        or engine._controller_export_target2026 is not target
        or controller._native_control_raw_execution2026 is None
        or controller.native_control_context2026(engine) is not target._context
    ):
        raise ValueError("Active raw CONTROL helper export lease required")
    state = record[1]
    binding = target.binding
    identity = state["identity"]
    return MappingProxyType(
        {
            "module": state["module"],
            "operation": export,
            "required_exports": state["required_exports"],
            "selectors": binding.selector_functions,
            "identity": identity,
            "module_version_checked": state["module_version_checked"],
            "source_name": binding.source_name,
            "source_sha256": binding.source_sha256,
            "key": binding.key,
        }
    )


def _control_preflight_failure2026(helper, kind, alternate=False):
    lines = {
        "6f20": (0x6E5, 0x6F0),
        "8990": (0x7B2, 0x7BD),
        "a250": (0x842, 0x84D),
        "9370": (0xA7B, 0xA86),
        "4c10": (0x913, 0x91E),
        "5c30": (0xBB3, 0xBC1),
    }
    line = ((0xC77, 0xC7D) if alternate else lines[helper])[
        0 if kind == "version_read" else 1
    ]
    return NativePassThruException2026(
        9999, "TCUWControlCommPhase.dll:RVA" + ("7c20" if alternate else helper), line
    )


def _control_loader_failure2026(helper, export):
    line = {
        "StartGetCID": 0x245,
        "StartPrepareWrite": 0x26A,
        "ChangeToReprogGatewayMode": 0x294,
        "StartFlashWrite": 0x2C1,
        "PrepareRetry": 0x2C8,
        "IsFinishReprogramming": 0x2D0,
        "ProcessBeforeIGOffOnAtRetry": 0x273 if helper == "9370" else 0x2DA,
    }[export]
    return NativePassThruException2026(9999, "TCUWControlCommPhase.dll:RVAloader", line)


# Source wrappers store this exact process BOOL through StartGetCID param7.
# The native function return is the CID vector, not that byte. See6f20 ASM073bf.
_CONTROL_GETTER_OUT_FIELDS_2026 = {
    "TCUWP4P5CanCIDGetter.dll": "bool_out",
    "TCUWP5CanCIDGetter.dll": "bool_out",
    "TCUWP5CanCIDGetterWithSetBS.dll": "bool_out",
    "TCUWP6CanCIDGetter.dll": "native_success",
    "TCUWCanDCMPRLVersionGetter.dll": "native_success",
    "TCUWCanMMCCIDGetter.dll": "native_success",
    "TCUWCanSBRSoftwareIDGetter.dll": "native_success",
    "TCUWCanHINOCIDGetter.dll": "native_success",
    "TCUWCanHINOCIDGetterForDSS.dll": "native_success",
    "TCUWCanHINOCIDGetterForVCS.dll": "native_success",
    "TCUWCanCIDGetter.dll": "native_success",
    "TCUWCanSuzukiUDSSoftwareIDGetter.dll": "native_success",
    "TCUWSilCIDGetter.dll": "native_success",
    "TCUWSilDCMPRLVersionGetter.dll": "native_success",
    "TCUWSilDHSoftwareIDGetter.dll": "native_success",
    "TCUWSilHINOCIDGetterForAMT.dll": "native_success",
    "TCUWCanUnifiedCIDGetter.dll": "native_return",
    "TCUWEthernetCIDGetter.dll": "native_return",
    "TCUWCanDHSoftwareIDGetter.dll": "native_return",
    "TCUWCanDHUDSSoftwareIDGetter.dll": "native_return",
    "TCUWCanDHSoftMaskIDGetter.dll": "native_return",
    "TCUWCanDHSoftwareIDAndSoftMaskIDGetter.dll": "native_return",
    "TCUWP5CanDHVehicleInfoCIDGetter.dll": "native_return",
    "TCUWCanDHWritableCIDGetter.dll": "native_return",
    "TCUWCanDHWritableSoftMaskIDAndCIDGetter.dll": "native_return",
}


def _control_alternate_getter_byte2026(target, report):
    target.validate(target._engine, target._controller)
    if target.binding.operation != "get_cid" or type(report) is not dict:
        raise TypeError("Actual getter target and concrete report required")
    name = target.module_binding.module_name
    field_name = _CONTROL_GETTER_OUT_FIELDS_2026.get(name)
    value = report.get(field_name) if field_name is not None else None
    if type(value) is not bool:
        raise NotImplementedError("Source getter param7 byte unavailable for " + name)
    return value


def _record_control_getter_family_return2026(target, report):
    """Save primary or alternate getter param7 before post-export callbacks."""
    if type(target) is not NativeControlExportTarget2026:
        raise TypeError("Exact issued getter target required")
    engine, controller = target._engine, target._controller
    target.validate(engine, controller)
    entry_lease = _control_helper_entry2026(target._context)
    entry = _NATIVE_CONTROL_HELPER_ENTRIES_2026[id(entry_lease)][1]
    lease = _NATIVE_CONTROL_HELPER_LEASES_2026.get(
        id(controller._native_control_export_lease2026)
    )
    if (
        entry["helper"] != "6f20"
        or lease is None
        or lease[0] is not controller._native_control_export_lease2026
        or lease[1]["target"] is not target
        or lease[1]["export"] != "StartGetCID"
        or engine._controller_export_target2026 is not target
    ):
        raise ValueError("Actual active6f20 getter return boundary required")
    entry["getter_al"] = _control_alternate_getter_byte2026(target, report)


def _control_helper_entry2026(context: NativeControlContext2026):
    """Look up the opaque source-helper entry lease for worker CPass handling."""
    if type(context) is not NativeControlContext2026:
        raise TypeError("Exact active CONTROL context required")
    context.validate(context._engine, context._controller)
    controller = context._controller
    lease = controller._native_control_helper_entry2026
    record = _NATIVE_CONTROL_HELPER_ENTRIES_2026.get(id(lease))
    if (
        lease is None
        or record is None
        or record[0] is not lease
        or record[1]["context"] is not context
        or record[1]["engine"] is not context._engine
        or record[1]["controller"] is not controller
        or controller.native_control_context2026(context._engine) is not context
    ):
        raise ValueError("No active source-issued CONTROL helper entry lease")
    return lease


def _record_control_family_return2026(target, export: str, returned: bool) -> None:
    """Save the actual primary helper AL before its later callbacks can throw."""
    if (
        type(target) is not NativeControlExportTarget2026
        or type(export) is not str
        or type(returned) is not bool
    ):
        raise TypeError("Exact staged CONTROL export and native BOOL required")
    engine, controller = target._engine, target._controller
    target.validate(engine, controller)
    context = controller.native_control_context2026(engine)
    entry_lease = controller._native_control_helper_entry2026
    entry = _NATIVE_CONTROL_HELPER_ENTRIES_2026.get(id(entry_lease))
    export_lease = controller._native_control_export_lease2026
    lease = _NATIVE_CONTROL_HELPER_LEASES_2026.get(id(export_lease))
    if (
        entry is None
        or entry[0] is not entry_lease
        or entry[1]["context"] is not context
        or entry[1]["engine"] is not engine
        or entry[1]["controller"] is not controller
        or lease is None
        or lease[0] is not export_lease
        or lease[1]["target"] is not target
        or lease[1]["context"] is not context
        or lease[1]["export"] != export
        or engine._controller_export_target2026 is not target
    ):
        raise ValueError("Actual active CONTROL helper return boundary required")
    expected = {
        "8990": "StartPrepareWrite",
        "9370": "StartPrepareWrite",
        "4c10": "StartFlashWrite",
        "5c30": "StartFlashWrite",
    }
    helper = entry[1]["helper"]
    if expected.get(helper) != export:
        raise ValueError("Auxiliary CONTROL export cannot replace the helper BOOL")
    entry[1]["saved_raw"] = returned
    entry[1]["primary_return_seen"] = True


def _control_saved_family_return2026(
    context: NativeControlContext2026, helper_lease
) -> bool:
    """Read the source helper's initialized-or-saved local result byte."""
    if (
        type(context) is not NativeControlContext2026
        or type(helper_lease) is not object
    ):
        raise TypeError("Exact CONTROL context and helper-entry lease required")
    context.validate(context._engine, context._controller)
    entry = _NATIVE_CONTROL_HELPER_ENTRIES_2026.get(id(helper_lease))
    if (
        entry is None
        or entry[0] is not helper_lease
        or entry[1]["context"] is not context
        or context._controller._native_control_helper_entry2026 is not helper_lease
        or type(entry[1]["saved_raw"]) is not bool
    ):
        raise ValueError("Active source-issued saved CONTROL helper result required")
    return entry[1]["saved_raw"]


def _control_helper_primary_return_seen2026(
    context: NativeControlContext2026, helper_lease, helper: str
) -> bool:
    """Validate a helper's completed primary return for post-scope callbacks."""
    if (
        type(context) is not NativeControlContext2026
        or type(helper_lease) is not object
        or type(helper) is not str
    ):
        raise TypeError("Exact CONTROL context, helper lease and name required")
    context.validate(context._engine, context._controller)
    entry = _NATIVE_CONTROL_HELPER_ENTRIES_2026.get(id(helper_lease))
    if (
        entry is None
        or entry[0] is not helper_lease
        or entry[1]["context"] is not context
        or entry[1]["helper"] != helper
        or context._controller._native_control_helper_entry2026 is not helper_lease
        or type(entry[1]["primary_return_seen"]) is not bool
    ):
        raise ValueError("Exact active CONTROL helper return lineage required")
    return entry[1]["primary_return_seen"]


def _clear_control_saved_family_return2026(
    context: NativeControlContext2026, helper_lease
) -> None:
    """Apply callback22's source-issued raw/result clear before retry."""
    if (
        type(context) is not NativeControlContext2026
        or type(helper_lease) is not object
    ):
        raise TypeError("Exact CONTROL context and helper-entry lease required")
    context.validate(context._engine, context._controller)
    entry = _NATIVE_CONTROL_HELPER_ENTRIES_2026.get(id(helper_lease))
    if (
        entry is None
        or entry[0] is not helper_lease
        or entry[1]["context"] is not context
        or entry[1]["helper"] not in ("4c10", "5c30")
        or context._controller._native_control_helper_entry2026 is not helper_lease
    ):
        raise ValueError("Actual writer callback22 helper lease required")
    entry[1]["saved_raw"] = False


def _control_helper_addresses2026(target):
    """Return only the immutable resolver vector preflighted for the active lease."""
    if type(target) is not NativeControlExportTarget2026:
        raise TypeError("Exact source-issued CONTROL target required")
    target.validate(target._engine, target._controller)
    lease = target._controller._native_control_export_lease2026
    record = _NATIVE_CONTROL_HELPER_LEASES_2026.get(id(lease))
    if (
        lease is None
        or record is None
        or record[0] is not lease
        or record[1]["target"] is not target
        or record[1]["context"] is not target._context
        or target._engine._controller_export_target2026 is not target
    ):
        raise ValueError("Active source-preflighted CONTROL helper lease required")
    addresses = record[1]["addresses"]
    if type(addresses) is not tuple:
        raise TypeError("Immutable source-preflighted address vector required")
    return addresses


def _control_return_snapshot2026(context: NativeControlContext2026):
    """Look up only the returned pair snapshot issued by the ordinary raw tail."""
    if type(context) is not NativeControlContext2026:
        raise TypeError("Exact active CONTROL context required")
    context.validate(context._engine, context._controller)
    record = _NATIVE_CONTROL_RETURN_SNAPSHOTS_2026.get(id(context))
    if record is None or record[0] is not context:
        raise ValueError("No ordinary raw CONTROL return snapshot was issued")
    _snapshot, pair = record[1], record[2]
    from scripts.j2534_2026 import J2534InterfacePair2026, NativeInterfaceData2026

    if (
        type(pair) is not J2534InterfacePair2026
        or type(_snapshot) is not NativeInterfaceData2026
        or pair.control is not context._controller.runtime_device()
        or pair._issued.get(pair.control, (None,))[0] is not _snapshot
    ):
        raise ValueError("Returned CONTROL pair snapshot is stale or foreign")
    pair.validate_views()
    return _snapshot


def _control_has_ordinary_getter_return2026(context: NativeControlContext2026) -> bool:
    """Identify the actual outer getter handoff, never a phase-only prediction."""
    if type(context) is not NativeControlContext2026:
        raise TypeError("Exact active CONTROL context required")
    context.validate(context._engine, context._controller)
    result = _NATIVE_CONTROL_GETTER_RESULTS_2026.get(id(context))
    snapshot = _NATIVE_CONTROL_RETURN_SNAPSHOTS_2026.get(id(context))
    if result is None or snapshot is None:
        return False
    if (
        result[0] is not context
        or snapshot[0] is not context
        or context._capture._phase != 0
    ):
        raise ValueError("Ordinary CONTROL getter return lineage is stale or foreign")
    _control_getter_return_al2026(context)
    _control_getter_return_values2026(context)
    _control_return_snapshot2026(context)
    return True


def _record_control_getter_result2026(context, entry_lease, raw_al, identifiers):
    """Retain the actual 6f20 return byte and final vector for outer 5a050."""
    from scripts.cuw_engine_worker import ControlFileCapture2026

    if (
        type(context) is not NativeControlContext2026
        or type(entry_lease) is not object
        or type(raw_al) is not bool
        or type(identifiers) is not tuple
        or any(type(value) is not bytes or b"\0" in value for value in identifiers)
    ):
        raise TypeError("Actual bounded CONTROL getter outputs required")
    context.validate(context._engine, context._controller)
    entry = _NATIVE_CONTROL_HELPER_ENTRIES_2026.get(id(entry_lease))
    if (
        entry is None
        or entry[0] is not entry_lease
        or entry[1]["context"] is not context
        or entry[1]["helper"] != "6f20"
        or context._capture._phase != 0
        or context._controller._native_control_helper_entry2026 is not entry_lease
        or not isinstance(context._capture, ControlFileCapture2026)
        or id(context) in _NATIVE_CONTROL_GETTER_RESULTS_2026
        or len(identifiers) > 34
        or any(len(value) > 33 for value in identifiers)
    ):
        raise ValueError("Active source-issued ordinary getter result required")
    _NATIVE_CONTROL_GETTER_RESULTS_2026[id(context)] = (
        context,
        raw_al,
        identifiers,
    )


def _control_getter_return_values2026(context: NativeControlContext2026):
    if type(context) is not NativeControlContext2026:
        raise TypeError("Exact active CONTROL context required")
    context.validate(context._engine, context._controller)
    record = _NATIVE_CONTROL_GETTER_RESULTS_2026.get(id(context))
    if record is None or record[0] is not context or context._capture._phase != 0:
        raise ValueError("Actual ordinary CONTROL getter result is unavailable")
    return record[2]


def _control_getter_return_al2026(context: NativeControlContext2026) -> bool:
    if type(context) is not NativeControlContext2026:
        raise TypeError("Exact active CONTROL context required")
    context.validate(context._engine, context._controller)
    record = _NATIVE_CONTROL_GETTER_RESULTS_2026.get(id(context))
    if record is None or record[0] is not context or context._capture._phase != 0:
        raise ValueError("Actual ordinary CONTROL getter return byte is unavailable")
    return record[1]


def _record_control_return2026(engine, controller, pair_context):
    """Publish the real b74a ExportData snapshot without reverse-importing it."""
    from scripts.cuw_2026 import CUWEngine2026
    from scripts.j2534_2026 import J2534InterfacePair2026

    if (
        type(engine) is not CUWEngine2026
        or type(controller) is not ControlCommPhase2026
    ):
        raise TypeError("Concrete CONTROL return owners required")
    context = controller.native_control_context2026(engine)
    token = controller._native_control_raw_execution2026
    if (
        token is None
        or _NATIVE_CONTROL_RAW_EXECUTIONS_2026.get(id(token))
        != (token, engine, controller, context)
        or controller._native_control_export_lease2026 is not None
    ):
        raise ValueError("Ordinary return is outside the raw CONTROL Execute driver")
    if pair_context is None:
        return None
    if (
        type(pair_context) is not tuple
        or len(pair_context) != 2
        or type(pair_context[0]) is not J2534InterfacePair2026
        or pair_context[0] is not engine.interface_pair
        or pair_context[0].control is not controller.runtime_device()
    ):
        raise ValueError("Exact engine-to-CONTROL pair transfer required")
    pair, imported = pair_context
    snapshot = pair.export_from(pair.control, previous=imported)
    _NATIVE_CONTROL_RETURN_SNAPSHOTS_2026[id(context)] = (
        context,
        snapshot,
        pair,
    )
    recorder = getattr(engine.worker, "record_control_return2026", None)
    if not callable(recorder):
        raise NotImplementedError("114 ordinary CONTROL return recorder is pending")
    recorder(context, snapshot)
    return snapshot


# Public spelling shared with the bytes-only loader/importer.
bind_parameter2026 = bind_native_parameter2026


class CommonDefinitions2026:
    """Data-export state: two fixed protocol strings and mutable CPU capacity.

    The native CPU-capacity DWORD starts at zero and is assigned by the CUW
    configuration setter. Engine active-state guards belong to that setter.
    """

    diag_comm_protocol_canfd = DIAG_COMM_PROTOCOL_CANFD
    diag_comm_protocol_ethernet = DIAG_COMM_PROTOCOL_ETHERNET

    def __init__(self):
        self._num_cpu_maxnum = 0

    @property
    def num_cpu_maxnum(self) -> int:
        return self._num_cpu_maxnum

    @num_cpu_maxnum.setter
    def num_cpu_maxnum(self, value: int) -> None:
        if type(value) is not int or not 0 <= value <= 65535:
            raise ValueError(
                "Native CPU capacity exceeds bounded host allocation policy"
            )
        self._num_cpu_maxnum = value


class NativeCallbackLookupError(ValueError):
    """CUW parameter callbacks throw native DWORD2 when a typed lookup fails."""

    code = 2

    def __init__(self):
        super().__init__("Native parameter callback lookup failed (2)")


@dataclass(frozen=True)
class NativeGeneralParameters2026:
    """Actual global Parameter.ini source used by CUW callback slots, not a DLL row."""

    source_sha256: str
    headers: tuple[str, ...] = field(repr=False)
    rows: tuple[tuple[tuple[str, ...], ...], ...] = field(repr=False)

    @classmethod
    def from_sources(
        cls, catalog_sources: Mapping[str, bytes], *, encoded: bool = True
    ):
        if (
            not isinstance(catalog_sources, Mapping)
            or "Parameter.ini" not in catalog_sources
        ):
            raise LookupError("Exact global native Parameter.ini source unavailable")
        if type(encoded) is not bool:
            raise TypeError("Native parameter encoding Boolean required")
        data = catalog_sources["Parameter.ini"]
        parameter = (
            NativeParameter2026.from_encoded(data)
            if encoded
            else NativeParameter2026.from_csv(data)
        )
        if parameter.key_column < 0:
            raise ValueError("Native global parameter key column unavailable")
        return cls(hashlib.sha256(data).hexdigest(), parameter.headers, parameter.rows)

    @classmethod
    def from_binding(cls, binding: NativeParameterBinding2026):
        if not isinstance(binding, NativeParameterBinding2026):
            raise TypeError("Actual native parameter binding required")
        return cls.from_sources(binding.catalog_sources, encoded=binding.encoded)

    def _parameter(self) -> NativeParameter2026:
        return NativeParameter2026(
            self.headers, self.rows, "ParamFileKeySystemProtocolMicon"
        )

    def boolean_with_keys(self, kind: str, cpu: str, contact: str, name: str) -> bool:
        value = self._parameter().boolean_with_keys(name, kind, cpu, contact)
        if value is None:
            raise NativeCallbackLookupError()
        return value

    def long_with_keys(self, kind: str, cpu: str, contact: str, name: str) -> int:
        value = self._parameter().long_with_keys(name, kind, cpu, contact)
        if value is None:
            raise NativeCallbackLookupError()
        return value

    def string_with_keys(self, kind: str, cpu: str, contact: str, name: str) -> str:
        value = self._parameter().string_with_keys(name, kind, cpu, contact)
        if value is None:
            raise NativeCallbackLookupError()
        return value


@dataclass(frozen=True)
class NativeFrontendParameters2026:
    """34050's distinct global tables, before any SetForMazda replacement."""

    general: NativeGeneralParameters2026
    source_sha256: Mapping[str, str]
    tables: Mapping[str, tuple] = field(repr=False)
    sources: Mapping[str, bytes] = field(repr=False)
    encoded: bool = True

    @classmethod
    def from_sources(
        cls, catalog_sources: Mapping[str, bytes], *, encoded: bool = True
    ) -> "NativeFrontendParameters2026":
        if type(encoded) is not bool:
            raise TypeError("Native frontend parameter encoding Boolean required")
        names = ("Parameter.ini", "CanIDTable.ini", "LogicalAddressTable.ini")
        if not isinstance(catalog_sources, Mapping) or any(
            name not in catalog_sources for name in names
        ):
            raise LookupError("Exact native frontend parameter sources unavailable")
        sources = {}
        for name in names:
            data = catalog_sources[name]
            if type(data) is not bytes or len(data) > 16 * 1024 * 1024:
                raise ValueError("Bounded immutable frontend parameter bytes required")
            sources[name] = data
        general = NativeGeneralParameters2026.from_sources(sources, encoded=encoded)
        tables = {}
        for name, key in (
            ("CanIDTable.ini", "RequestCANID"),
            ("LogicalAddressTable.ini", "LogicalAddress"),
        ):
            data = sources[name]
            parameter = (
                NativeParameter2026.from_encoded(data, key)
                if encoded
                else NativeParameter2026.from_csv(data, key)
            )
            if parameter.key_column < 0:
                raise ValueError("Native frontend parameter key column unavailable")
            tables[name] = (parameter.headers, parameter.rows, key)
        return cls(
            general,
            MappingProxyType(
                {
                    name: hashlib.sha256(data).hexdigest()
                    for name, data in sources.items()
                }
            ),
            MappingProxyType(tables),
            MappingProxyType(sources),
            encoded,
        )

    def validate_source(self) -> None:
        if self != type(self).from_sources(self.sources, encoded=self.encoded):
            raise ValueError("Frontend tables differ from their exact source bytes")

    def parameter(self, name: str) -> NativeParameter2026:
        if name not in ("CanIDTable.ini", "LogicalAddressTable.ini"):
            raise LookupError("Exact native frontend table name required")
        self.validate_source()
        headers, rows, key = self.tables[name]
        return NativeParameter2026(headers, rows, key)


class CommonPrepare2026:
    """Exact common prepare binding; shared functions preserve their typed inputs."""

    def __init__(self, identity: NativeModuleIdentity, runtime: NativeRuntime2026):
        if not isinstance(identity, NativeModuleIdentity):
            raise TypeError("Authenticated common prepare module identity required")
        actual = identify_native_module(
            identity.sha256, "TCUWCanCommonPrepareWriter.dll"
        )
        if identity != actual or actual.cuw_build != "2026":
            raise ValueError("Exact2026 common prepare identity required")
        if not isinstance(runtime, NativeRuntime2026):
            raise TypeError("Bounded primitive runtime required")
        self.identity, self.runtime = actual, runtime
        self._wire = Unified2026(runtime)

    basic_conversion = staticmethod(basic_conversion)
    seed_key_two_byte = staticmethod(seed_key_two_byte)
    seed_key_six_byte = staticmethod(seed_key_six_byte)
    seed_key_four_round = staticmethod(seed_key_four_round)

    def calc_seed_key(
        self, seed: bytes, material: bytes | tuple[bytes, ...] | None = None
    ) -> bytes:
        if material is None:
            return seed_key_six_byte(seed)
        if isinstance(material, tuple):
            return seed_key_four_round(seed, material)
        return seed_key_two_byte(seed, material)

    def calc_seed_key_for_security_up(
        self, client: SecretInfoClient, seed: bytes, service_auth_key: bytes
    ) -> bytes:
        return security_up_key(self.runtime, client, seed, service_auth_key)

    def change_mode(self, mode: int, request: bytes, response: bytes) -> bytes:
        return self._wire.change_mode(mode, request, response)

    def diagnostic_mask(self, parameter: NativeParameter2026) -> None:
        if not isinstance(parameter, NativeParameter2026):
            raise TypeError("Actual native selected parameter required")
        wait = parameter.long("WaitTimeAfterDiagnosticMask") or 0
        diagnostic_mask(self.runtime, wait & 0xFFFFFFFF)

    @staticmethod
    def get_bus_type_from_cpu_image(
        image: bytes, parameter: NativeParameter2026
    ) -> int:
        if not isinstance(parameter, NativeParameter2026):
            raise TypeError("Actual native selected parameter required")
        return cpu_bus_type(
            image, parameter.string("CANCommunicationSpeedAddress") or ""
        )

    def judge_repro_gateway_node(self, repro_sequence: int = 0) -> int:
        return self._wire.judge_repro_gateway_node(repro_sequence)

    def judge_repro_gateway_node_for_p4_and_p5(self, repro_sequence: int = 0) -> int:
        return self._wire.judge_repro_gateway_node(repro_sequence)


native_parameter_long2026 = _native_long


def native_error_fields2026(error: BaseException) -> tuple[int, int | None]:
    """Known error fields as native DWORD bit patterns; unknown driver stays None."""
    from scripts.j2534_2026 import NativePassThruError2026

    if isinstance(error, NativePassThruException2026):
        primary, status = error.native_error_code, error.passthru_status
    elif isinstance(error, CommonResponseError):
        primary, status = error.code, None
    elif isinstance(error, NativePassThruError2026):
        primary, status = error.native_error_code, error.passthru_status
    elif isinstance(error, NativeTransportError):
        primary = getattr(error, "native_error_code", 1)
        status = getattr(error, "passthru_status", error.code)
    else:
        raise TypeError("Exception has no proven native enum/driver fields")
    if type(primary) is not int or not -0x80000000 <= primary <= 0xFFFFFFFF:
        raise TypeError("Bounded native primary error required")
    if status is not None and (
        type(status) is not int or not -0x80000000 <= status <= 0xFFFFFFFF
    ):
        raise TypeError("Bounded native driver error required")
    return primary & 0xFFFFFFFF, None if status is None else status & 0xFFFFFFFF


def is_native_exception2026(error: BaseException) -> bool:
    """Only explicit native-domain faults enter native catch-all handlers.

    Untyped provider failures remain host failures; their Python exception class
    never supplies an invented native terminal Boolean or error enum.
    """
    from scripts.j2534_2026 import NativePassThruError2026

    return isinstance(
        error,
        (
            NativeException2026,
            CommonResponseError,
            NativeTransportError,
            NativePassThruError2026,
            NativeCallbackLookupError,
        ),
    )
