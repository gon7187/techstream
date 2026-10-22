"""CUW2026 5b1e0/1ad30 central gateway startup over the issued device.

This is CUW.dll's startup classifier, not UnifiedUtils' gateway-node judge.
The engine worker owns the separate 5a835 phase/parameter gate and BE0/980.
"""

from __future__ import annotations

import threading
import weakref
from dataclasses import dataclass

from scripts.j2534_2026 import (
    J2534Device2026,
    NativeJ2534Error2026,
    NativeMessage,
    NativePassThruError2026,
)
from scripts.programming_2026_common import (
    CanDiag2026,
    CommonResponseError,
    NativeCentralGatewayKey2026,
    NativeJ2534Exception2026,
    NativePassThruException2026,
    is_native_exception2026,
    native_error_fields2026,
)

_TOKEN = object()
_LOCK = threading.Lock()
_ISSUED = weakref.WeakKeyDictionary()
_REQUEST = bytes.fromhex("000007505f")
_RESPONSE = bytes.fromhex("000007585f")


@dataclass(frozen=True)
class GatewayStartupState2026:
    """Actual CUW BE48/BE34,5b1e0 AL/output flag and typed local error writes."""

    classification: int
    periodic_identifier: int | None
    returned: bool
    output_flag: bool = False
    primary_error: int | None = None
    passthru_status: int | None = None
    classification_returned: bool = False


@dataclass(frozen=True)
class GatewayCancelState2026:
    """Actual5b690 AL and typed exception fields copied to controller68/70."""

    returned: bool | None
    primary_error: int | None
    passthru_status: int | None


def _issue_gateway_startup(engine, worker):
    from scripts.cuw_2026 import CUWEngine2026
    from scripts.cuw_engine_worker import EngineWorker2026

    if type(engine) is not CUWEngine2026 or type(worker) is not EngineWorker2026:
        raise TypeError("Concrete CUW2026 engine and issued worker required")
    worker.validate_source(engine)
    if engine.worker is not worker:
        raise ValueError("Gateway worker differs from actual engine owner")
    with _LOCK:
        previous = _ISSUED.get(engine)
        if previous is not None:
            instance = previous()
            if instance is not None:
                instance.validate_owner(engine, worker)
                return instance
        instance = GatewayStartup2026(engine, worker, _token=_TOKEN)
        _ISSUED[engine] = weakref.ref(instance)
        return instance


def _revoke_gateway_startup(engine) -> None:
    """Close/reload retires the source lease without performing device I/O."""
    with _LOCK:
        _ISSUED.pop(engine, None)


class GatewayStartup2026:
    """Only a real issued engine worker may execute or consume startup state."""

    def __init__(self, engine, worker, *, _token=None):
        if _token is not _TOKEN:
            raise TypeError("Gateway startup must be issued by CUWEngine2026")
        self._engine, self._worker = engine, worker
        self._runtime = worker.runtime
        self._device = engine.engine_runtime_device()
        if type(self._device) is not J2534Device2026:
            raise TypeError("Concrete source-bound J2534 device required")
        self._diag = CanDiag2026(self._runtime)
        self._classification = 0
        self._periodic = None
        self._returned = False
        self._output_flag = False
        self._primary_error = None
        self._passthru_status = None
        self._classification_returned = False
        self._running = False
        self._cancel_state = GatewayCancelState2026(None, None, None)

    @property
    def engine(self):
        return self._engine

    @property
    def worker(self):
        return self._worker

    @property
    def source_state(self) -> GatewayStartupState2026:
        return GatewayStartupState2026(
            self._classification,
            self._periodic,
            self._returned,
            self._output_flag,
            self._primary_error,
            self._passthru_status,
            self._classification_returned,
        )

    @property
    def cancel_state(self) -> GatewayCancelState2026:
        return self._cancel_state

    def validate_owner(self, engine, worker) -> None:
        if self.engine is not engine or self.worker is not worker:
            raise ValueError("Gateway startup belongs to another engine worker")
        worker.validate_source(engine)
        if (
            engine.worker is not worker
            or worker.runtime is not self._runtime
            or engine.engine_runtime_device() is not self._device
        ):
            raise ValueError("Gateway runtime device ownership changed")

    def rebind_worker(self, old, new) -> None:
        """59070 replaces a stopped worker while CUW gateway globals survive."""
        from scripts.cuw_engine_worker import EngineWorker2026

        if type(old) is not EngineWorker2026 or type(new) is not EngineWorker2026:
            raise TypeError("Actual previous and replacement engine workers required")
        with _LOCK:
            reference = _ISSUED.get(self.engine)
            if (
                reference is None
                or reference() is not self
                or self.worker is not old
                or old.engine is not self.engine
                or new.engine is not self.engine
                or new is not self.engine.worker
                or old.controller is not new.controller
                or getattr(new.controller, "worker", None) is not new
                or old.runtime is not self._runtime
                or new.runtime is not self._runtime
                or self.engine.engine_runtime_device() is not self._device
                or not old._closed
                or new._closed
                or self.engine.active
                or self._running
            ):
                raise ValueError("Actual stopped-worker gateway replacement required")
            new.validate_source(self.engine)
            self._worker = new

    def _call(self, payload, expected, minimum, code, *, phase5=False):
        return self._diag.call(
            _REQUEST,
            _RESPONSE,
            payload,
            expected,
            minimum=minimum,
            error_code=code,
            phase5=phase5,
            pending_limit=0xB4 if phase5 else 0x95,
            busy_limit=0x159A if phase5 else 0xFF,
        )

    def _classify(self) -> int:
        """1ba20 plus native catch continuations omitted by the decompiler."""
        try:
            self._call(b"\x3e", b"\x7e", 1, 0x50)
            return 2
        except CommonResponseError as error:
            if error.response == b"\x7f\x3e\x78":
                raise
        except (NativeJ2534Error2026, NativeJ2534Exception2026) as error:
            if error.passthru_status not in (9, 16):
                raise
        except (NativePassThruError2026, NativePassThruException2026):
            pass
        self._call(b"\x3e\x00", b"\x7e\x00", 2, 0x4F, phase5=True)
        return 1

    def _recovery_info(self):
        from scripts.cuw_persistence import CUWPersistence

        persistence = self.engine.persistence
        if persistence is None:
            return None
        if type(persistence) is not CUWPersistence:
            raise TypeError("Concrete source-bound CUW recovery state required")
        persistence.validate_engine_owner(self.engine)
        self.engine.validate_persistence_binding(persistence)
        persistence.state.validate()
        return persistence

    def _start_periodic(self) -> int:
        identifier = self._runtime.acquire(
            "start_periodic",
            "stop_periodic",
            message=NativeMessage(6, _REQUEST + b"\x3e\x80", tx_flags=0x80),
            interval=2000,
        )
        self._periodic = identifier
        self.engine.bind_retry_controller().accept_gateway_startup(self)
        return identifier

    def _p5_startup(self) -> None:
        self._call(b"\x10\x03", b"\x50\x03", 6, 0x58, phase5=True)
        seed = self._call(b"\x27\x21", b"\x67\x21", 18, 0x10, phase5=True)
        temporary = self._start_periodic()
        try:
            key = self._runtime.call("calculate_p5_gateway_key", seed=seed[2:18])
        except (Exception, KeyboardInterrupt) as error:
            # Native1be60 enters Try0 only after callback26 returns. Host
            # callback failures get extra bounded containment, retaining cause.
            if not is_native_exception2026(error):
                try:
                    self._runtime.release("stop_periodic", identifier=temporary)
                except (Exception, KeyboardInterrupt) as cleanup_error:  # noqa: BLE001 - preserve the host callback primary during containment
                    error.add_note(
                        "Gateway periodic cleanup failed: "
                        + type(cleanup_error).__name__
                    )
            raise
        try:
            self._runtime.release("stop_periodic", identifier=temporary)
        except (Exception, KeyboardInterrupt) as error:
            if not is_native_exception2026(error):
                raise
            # Try0 catch-all1c020 resumes1c038 and still sends the computed key.
        if key is False:
            raise NativePassThruException2026(0x3F2, "CUW.dll", 0x776)
        if type(key) is not bytes or len(key) != 256:
            raise ValueError("Native gateway online key must contain256 bytes")
        self._call(b"\x27\x22" + key, b"\x67\x22", 2, 0x11, phase5=True)
        for mode, service, routine, code in (
            (0, 1, 0x11, 0x51),
            (1, 3, 0x11, 0x52),
            (2, 1, 0x12, 0x31),
            (3, 3, 0x12, 0x53),
        ):
            payload = bytes((0x31, service, 0x10, routine))
            expected = bytes((0x71, service, 0x10, routine))
            if mode in (1, 3):
                expected += b"\x01"
            self._call(payload, expected, len(expected), code, phase5=True)
            if mode in (0, 2):
                self._runtime.call("wait", milliseconds=1500)
        self._periodic = self._start_periodic()

    def _p4_startup(self) -> None:
        binding = self._runtime._central_gateway_key
        if (
            type(binding) is not NativeCentralGatewayKey2026
            or binding.source_sha256 != self.engine.identity.sha256
        ):
            raise ValueError("Same-engine native central gateway AES binding required")
        seed = self._call(b"\x27\x51", b"\x67\x51", 18, 0x10)
        key = self._runtime.call("calculate_central_gateway_key", seed=seed[2:18])
        if type(key) is not bytes or len(key) != 16:
            raise ValueError("Native central gateway AES key must contain16 bytes")
        self._runtime.call("wait", milliseconds=100)
        self._call(b"\x27\x52" + key, b"\x67\x52\x34", 3, 0x11)
        self._runtime.call("wait", milliseconds=100)
        self._call(b"\x10\x60", b"\x50", 1, 0x32)
        self._runtime.call("wait", milliseconds=1500)

    def run(self) -> GatewayStartupState2026:
        """Complete5b1e0 AL/output-flag wrapper; BE0 belongs to5a835."""
        self.validate_owner(self.engine, self.worker)
        self.engine._require_owned_phase()
        with self._runtime.engine_device_calls(self.engine):
            self._output_flag = False
            self._primary_error = self._passthru_status = None
            self._classification_returned = False
            try:
                try:
                    self._run_engine_wire()
                except (
                    NativePassThruException2026,
                    NativePassThruError2026,
                    CommonResponseError,
                ) as error:
                    primary, status = native_error_fields2026(error)
                    if status is not None and status not in (9, 16):
                        self._output_flag = True
                        raise
                    if status is None and primary == 1010:
                        self._output_flag = True
                        self._primary_error = primary
                        raise
                    # 5b279 calls the optional selected ControlCommPhase export.
                    changed = self.worker.controller.gateway_startup_fallback(
                        self.engine
                    )
                    self._output_flag = changed is True
                    self._returned = self._output_flag
                    return self.source_state
                self.engine.set_repro_gateway_node(self._classification)
                self._output_flag = True
                return self.source_state
            except (
                NativePassThruException2026,
                NativePassThruError2026,
                CommonResponseError,
            ) as error:
                primary, status = native_error_fields2026(error)
                if status is not None and status not in (9, 16):
                    self._primary_error, self._passthru_status = primary, status
                    self._output_flag = True
                self._returned = False
                if self._primary_error is not None:
                    self.worker._accept_gateway_startup_failure(self)
                return self.source_state

    def run_classifier(self) -> GatewayStartupState2026:
        """Direct1ad30 source operation, retaining its native exception contract."""
        self.validate_owner(self.engine, self.worker)
        self.engine._require_owned_phase()
        with self._runtime.engine_device_calls(self.engine):
            self._output_flag = False
            self._primary_error = self._passthru_status = None
            return self._run_engine_wire()

    def _run_engine_wire(self) -> GatewayStartupState2026:
        if self._running:
            raise ValueError("Gateway startup is already running")
        self._running, self._returned = True, False
        self._classification_returned = False
        filter_id = None
        failure = None
        business = False
        try:
            self._diag.set_block_size(1)
            business = True
            filter_id = self._diag.start_filter(_REQUEST, _RESPONSE)
            recovery = self._recovery_info()
            self._classification = self.engine.native_gateway_cache
            if self._classification == 0:
                self._classification = self._classify()
                self.engine._publish_gateway_classifier_cache(self)
                self.engine.bind_retry_controller().accept_gateway_startup(self)
                if recovery is not None and recovery.state.logged:
                    recovery.persist()
            else:
                self.engine.bind_retry_controller().accept_gateway_startup(self)
            if self._classification == 1:
                self._p5_startup()
            else:
                self._p4_startup()
        except (Exception, KeyboardInterrupt) as error:
            failure = error
            if (
                business
                and is_native_exception2026(error)
                and not isinstance(
                    error,
                    (
                        NativePassThruException2026,
                        NativePassThruError2026,
                        CommonResponseError,
                    ),
                )
            ):
                failure = NativePassThruException2026(9999, "CUW.dll", 0x246)
                raise failure from error
            raise
        finally:
            try:
                self._restore(filter_id, failure, business=business)
            finally:
                self._running = False
        self._classification_returned = True
        self._returned = True
        return self.source_state

    def callback14(self) -> bool:
        """58530 calls5b1e0 directly: copy BF9 and return AL1, without BE0."""
        return self.run().returned

    def callback29(self) -> bool:
        """588c0→5b690 cancel automatic IG-off, including native view switches."""
        self.validate_owner(self.engine, self.worker)
        self.engine._require_owned_phase()
        with self._runtime.engine_device_calls(self.engine):
            return self._callback29_engine_wire()

    def _callback29_engine_wire(self) -> bool:
        self._cancel_state = GatewayCancelState2026(None, None, None)
        contact = self.engine.native_metadata.vehicle.get("contacttype", "")
        operation = (
            "switch_connection"
            if contact == "SIL"
            else "switch_connection_with_version"
            if contact == "Ethernet"
            else None
        )
        try:
            if operation is not None:
                self._runtime.call(operation, protocol=6)
            if not self._cancel_p6():
                self._cancel_p5()
            if operation is not None:
                self._runtime.call(
                    operation, protocol=3 if contact == "SIL" else 0x800F
                )
        except (
            NativePassThruException2026,
            NativePassThruError2026,
            CommonResponseError,
        ) as error:
            primary, status = native_error_fields2026(error)
            self._cancel_state = GatewayCancelState2026(False, primary, status)
            self.worker._accept_gateway_cancel(self)
            return False
        self._cancel_state = GatewayCancelState2026(True, None, None)
        return True

    def _cancel_call(
        self,
        request,
        response,
        payload,
        expected,
        minimum,
        code,
        *,
        phase5=True,
        phase6=False,
    ):
        return self._diag.call(
            request,
            response,
            payload,
            expected,
            minimum=minimum,
            error_code=code,
            phase5=phase5,
            pending_limit=0xB4 if phase5 else 0x95,
            busy_limit=0x159A if phase5 else 0xFF,
            tx_flags=0x100 if phase6 else 0,
        )

    @staticmethod
    def _cancel_native_error(error, line):
        if is_native_exception2026(error) and not isinstance(
            error,
            (NativePassThruException2026, NativePassThruError2026, CommonResponseError),
        ):
            raise NativePassThruException2026(9999, "CUW.dll", line) from error

    def _cancel_filter_stop(self, identifier, failure):
        if identifier is None:
            return
        try:
            self._runtime.release("stop_filter", identifier=identifier)
        except (Exception, KeyboardInterrupt) as error:
            if not is_native_exception2026(error):
                if failure is None:
                    raise
                failure.add_note(
                    "Cancel IG filter cleanup failed: " + type(error).__name__
                )
            # Native1a5ce/1abd8 catch-all resumes after the owned filter stop.

    def _cancel_p6(self) -> bool:
        """1a210: only the initial P6 session's CJ9/16 selects P5 fallback."""
        request, response = CanDiag2026.phase6_addresses(b"\x72")
        identifier, failure = None, None
        try:
            identifier = self._diag.start_filter(request, response)
            try:
                self._cancel_call(
                    request, response, b"\x10\x03", b"\x50\x03", 6, 0x58, phase6=True
                )
            except (NativeJ2534Error2026, NativeJ2534Exception2026) as error:
                if error.passthru_status not in (9, 16):
                    raise
                return False
            data = self._cancel_call(
                request,
                response,
                b"\x22\x21\x03",
                b"\x62\x21\x03",
                5,
                0x57,
                phase6=True,
            )
            if data[3] & 1:
                self._cancel_call(
                    request,
                    response,
                    b"\x2e\x21\x03" + bytes((data[3], data[4] | 1)),
                    b"\x6e\x21\x03",
                    3,
                    0x4E,
                    phase6=True,
                )
            return True
        except (Exception, KeyboardInterrupt) as error:
            failure = error
            self._cancel_native_error(error, 0x1CB)
            raise
        finally:
            self._cancel_filter_stop(identifier, failure)

    def _cancel_p5(self) -> None:
        """1a6b0: initial1003 timeout or its exact7f1012→1070 fallback."""
        request, response = bytes.fromhex("00000750e9"), bytes.fromhex("00000758e9")
        identifier, failure = None, None
        try:
            identifier = self._diag.start_filter(request, response)
            try:
                self._cancel_call(request, response, b"\x10\x03", b"\x50\x03", 6, 0x58)
            except CommonResponseError as error:
                if error.response != b"\x7f\x10\x12":
                    raise
                try:
                    self._cancel_call(
                        request, response, b"\x10\x70", b"\x50", 1, 0x4E, phase5=False
                    )
                except CommonResponseError as fallback:
                    if fallback.response not in (
                        b"\x7f\x10\x11",
                        b"\x7f\x10\x12",
                        b"\x7f\x10\x13",
                    ):
                        raise
                return
            except (NativeJ2534Error2026, NativeJ2534Exception2026) as error:
                if error.passthru_status not in (9, 16):
                    raise
                return
            data = self._cancel_call(
                request, response, b"\x22\x20\x01", b"\x62\x20\x01", 5, 0x57
            )
            if data[3] & 0x40:
                self._cancel_call(
                    request,
                    response,
                    b"\x2e\x20\x01" + bytes((data[3], data[4] | 0x40)),
                    b"\x6e\x20\x01",
                    3,
                    0x4E,
                )
        except (Exception, KeyboardInterrupt) as error:
            failure = error
            self._cancel_native_error(error, 0x327)
            raise
        finally:
            self._cancel_filter_stop(identifier, failure)

    def _restore(self, filter_id, failure, *, business):
        # Initial SET_CONFIG is outside native business catches; host failures
        # get extra containment without changing their Python exception identity.
        if not business and failure is not None and is_native_exception2026(failure):
            return
        cleanup_failure = None
        try:
            self._runtime.call(
                "control_io", cleanup=True, ioctl=2, parameters=((0x1E, 0),)
            )
        except (Exception, KeyboardInterrupt) as error:
            if is_native_exception2026(error) and (
                failure is None or is_native_exception2026(failure)
            ):
                raise  # Native state4 restore fault skips StopFilter/free.
            if failure is not None:
                failure.add_note("Gateway restore failed: " + type(error).__name__)
            else:
                cleanup_failure = error
        if filter_id is not None:
            try:
                self._runtime.release("stop_filter", identifier=filter_id)
            except (Exception, KeyboardInterrupt) as error:  # noqa: BLE001 - native StopFilter catch-all; host faults retain identity
                if not is_native_exception2026(error):
                    if failure is not None:
                        failure.add_note(
                            "Gateway filter cleanup failed: " + type(error).__name__
                        )
                    elif cleanup_failure is None:
                        cleanup_failure = error
                # Native Try8 catch-all1b016 suppresses StopFilter faults.
                # Failed resources remain owned for bounded runtime close.
        if failure is None and cleanup_failure is not None:
            raise cleanup_failure
