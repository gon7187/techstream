"""Individually recovered CUW2026 legacy helpers over injected host providers.

Recognition of an older family name never selects a CUW12/18 implementation.
No vendor library, transport or external service is executed here.
"""

from collections.abc import Callable, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from types import MappingProxyType
from weakref import WeakValueDictionary

from scripts.calibration import CalibrationContainer
from scripts.calibration_catalog import Address
from scripts.j2534_2026 import (
    NativeCommunicationAddress,
    communication_addresses_from_parameter,
)
from scripts.native_modules import NativeModuleIdentity, identify_native_module
from scripts.programming import NativeTransportError
from scripts.programming_2026_common import (
    CanDiag2026,
    CommonResponseError,
    NativeException2026,
    NativeJ2534Exception2026,
    NativeParameterBinding2026,
    NativePassThruException2026,
    NativeRuntime2026,
    diagnostic_mask,
)
from scripts.programming_vendor import NativeTransportError as VendorTransportError

_BOUND_CONTEXTS: WeakValueDictionary[int, object] = WeakValueDictionary()

_NATIVE_DRIVER_ERRORS = (
    NativeTransportError,
    VendorTransportError,
    NativeJ2534Exception2026,
    NativeException2026,
)
_NATIVE_BASE_ERRORS = (
    CommonResponseError,
    NativeTransportError,
    VendorTransportError,
    NativePassThruException2026,
)


@contextmanager
def _cleanup_on_exit(cleanup):
    """Host policy: keep a primary abort and attach any cleanup failure."""
    failure = None
    try:
        yield
    except (Exception, KeyboardInterrupt) as error:
        failure = error
        raise
    finally:
        try:
            cleanup()
        except (Exception, KeyboardInterrupt) as error:
            if failure is None:
                raise
            failure.add_note("Native cleanup failure: " + type(error).__name__)


def writing_error_dispose(
    cpu_index: int,
    counts: list[int],
    percentages: list[int],
    notify: Callable[[str], None],
) -> None:
    """CommonFlashWriter RVA4080: reset count/notify, then percent/notify.

    Native callbacks observe the updated array immediately. A failing callback
    propagates before the following native instruction; it is never swallowed.
    The 256-CPU array cap is host policy, not a recovered OEM limit.
    """
    if (
        type(cpu_index) is not int
        or type(counts) is not list
        or type(percentages) is not list
        or not 0 < len(counts) == len(percentages) <= 256
        or not 0 <= cpu_index < len(counts)
        or any(
            type(value) is not int or not 0 <= value <= 0xFFFFFFFF for value in counts
        )
        or any(
            type(value) is not int or not 0 <= value <= 0xFFFFFFFF
            for value in percentages
        )
        or not callable(notify)
    ):
        raise ValueError(
            "Bounded unsigned native progress arrays and callback required"
        )
    counts[cpu_index] = 0
    notify("count")
    percentages[cpu_index] = 0
    notify("percent")


_P4_SECURITY = "TCUWP4CanSecurityPowerTrainPrepareWriter.dll"


@dataclass(frozen=True)
class P4SecurityPowerTrainContext:
    identity: NativeModuleIdentity
    target_metadata: tuple[Address, ...]
    ecu_auth_key: bytes = field(repr=False)
    service_auth_key: bytes = field(repr=False)
    seed_wait_ms: int = 0
    key_wait_ms: int = 0
    mask_wait_ms: int = 0
    native_retry_flag_964: bool = False
    _binding: tuple | None = field(default=None, repr=False, compare=False)

    def __post_init__(self):
        if (
            not isinstance(self.identity, NativeModuleIdentity)
            or self.identity
            != identify_native_module(self.identity.sha256, _P4_SECURITY)
            or self.identity.cuw_build != "2026"
            or type(self.target_metadata) is not tuple
            or len(self.target_metadata) > 4
            or any(not isinstance(item, Address) for item in self.target_metadata)
            or any(
                type(v) is not bytes or len(v) != 16
                for v in (self.ecu_auth_key, self.service_auth_key)
            )
            or any(
                type(v) is not int or not 0 <= v <= 0xFFFFFFFF
                for v in (self.seed_wait_ms, self.key_wait_ms, self.mask_wait_ms)
            )
            or type(self.native_retry_flag_964) is not bool
        ):
            raise ValueError(
                "Exact CUW2026 P4 security source and imported bounded context required"
            )


def bind_native_context(
    container: CalibrationContainer,
    node: int,
    observed_cids: tuple[str, ...],
    selection: NativeParameterBinding2026,
    identity: NativeModuleIdentity,
    attachments: Mapping[str, bytes],
    observations: Mapping,
) -> P4SecurityPowerTrainContext:
    """Bind the audited P4 security preparation export to imported CPU/catalog data.

    The CAN getter uses bind_can_cid_context; shared helper classes do not select
    a stage. Attachments can supply authorized keys, never address geometry.
    """
    if (
        not isinstance(identity, NativeModuleIdentity)
        or identity.module_name != _P4_SECURITY
        or identity != identify_native_module(identity.sha256, identity.module_name)
        or identity.cuw_build != "2026"
        or not isinstance(selection, NativeParameterBinding2026)
        or selection.operation != "prepare"
        or selection.value("DLLFileNameForPrepareWrite") != _P4_SECURITY
        or not isinstance(attachments, Mapping)
        or set(attachments) - {"ecu_auth_key", "service_auth_key"}
        or not isinstance(observations, Mapping)
        or set(observations)
        - {"stage", "cpu_index", "previous_addresses", "native_retry_flag_964"}
        or observations.get("stage", "prepare") != "prepare"
    ):
        raise ValueError(
            "Audited CUW2026 P4 preparation export and native metadata required"
        )
    selection = selection.validate_against(
        container,
        operation="prepare",
        node=node,
        cpu_index=observations.get("cpu_index", 0),
    )
    metadata = selection.metadata
    history = observations.get("previous_addresses", ())
    if (
        type(history) is not tuple
        or len(history) > 4096
        or any(not isinstance(item, NativeCommunicationAddress) for item in history)
    ):
        raise ValueError("Immutable bounded native getter address history required")
    producer = communication_addresses_from_parameter(
        container, selection.parameter, history=list(history)
    )
    success, native_addresses = producer.resolve(
        selection.selector_functions,
        cids=observed_cids,
        location_id=metadata.cpu.values.get("locationid") or None,
    )
    if not success:
        raise ValueError("Native communication address selector did not resolve")
    addresses = tuple(
        Address(item.request, item.response, item.extended) for item in native_addresses
    )

    def key(name, metadata_name):
        text = metadata.vehicle.get(metadata_name, "")
        native = (
            (
                metadata.global_ecu_auth_key_bytes
                if name == "ecu_auth_key"
                else metadata.global_service_auth_key_bytes
            )
            if text
            else None
        )
        attached = attachments.get(name)
        if attached is not None and (
            type(attached) is not bytes or len(attached) != 16
        ):
            raise ValueError("Authorization attachment must contain sixteen bytes")
        if native is not None and attached is not None and native != attached:
            raise ValueError(
                "Authorization attachment conflicts with imported metadata"
            )
        result = native if native is not None else attached
        if result is None:
            raise ValueError("Explicit authorized global security material required")
        return result

    def wait(name):
        text = selection.value(name) or "0"
        if (
            not text.isascii()
            or not text.isdecimal()
            or not 0 <= int(text) <= 0xFFFFFFFF
        ):
            raise ValueError(
                "Native wait parameter must be unsigned decimal milliseconds"
            )
        return int(text)

    context = P4SecurityPowerTrainContext(
        identity,
        addresses,
        key("ecu_auth_key", "ecuauthkey"),
        key("service_auth_key", "serviceauthkey"),
        wait("WaitTimeAfterSeedData"),
        wait("WaitTimeAfterSeedKey"),
        wait("WaitTimeAfterDiagnosticMask"),
        observations.get("native_retry_flag_964", False),
        (
            container,
            node,
            tuple(observed_cids),
            selection,
            identity,
            MappingProxyType(dict(attachments)),
            MappingProxyType(dict(observations)),
        ),
    )
    _BOUND_CONTEXTS[id(context)] = context
    return context


def prepare_p4_security_powertrain(
    context: P4SecurityPowerTrainContext,
    runtime: NativeRuntime2026,
    key_provider: Callable[[bytes, bytes], bytes],
) -> dict:
    """Recovered1160→1240/1ab0 preparation; crypto remains explicitly authorized.

    The provider transforms (seed16, service_auth_key16) to key16. It cannot
    report preparation success. Filters and literal wire decisions remain here.
    """
    if (
        not isinstance(context, P4SecurityPowerTrainContext)
        or not isinstance(runtime, NativeRuntime2026)
        or not callable(key_provider)
    ):
        raise TypeError(
            "Bound native P4 context, runtime and authorized crypto provider required"
        )
    diag = CanDiag2026(runtime)
    addresses = tuple(
        (b"\0\0" + a.request, b"\0\0" + a.response) for a in context.target_metadata
    )
    prepared = []
    skipped = []
    filters = []

    def cleanup_filters():
        errors = []
        while filters:
            identifier = filters.pop(0)  # At most four; preserve native release order.
            try:
                runtime.release("stop_filter", identifier=identifier)
            except (Exception, KeyboardInterrupt) as error:  # noqa: BLE001 - attempt all owned filter releases
                errors.append(type(error).__name__)
        return errors

    def exchange(index, payload, expected, minimum, native_error):
        request, response = addresses[index]
        try:
            data = diag.call(request, response, payload, None, error_code=native_error)
        except CommonResponseError as error:
            if (
                payload[1] == 1
                and len(error.response) == 3
                and error.response[:2] == b"\x7f\x27"
            ):
                raise CommonResponseError(23) from error
            raise
        if len(data) == 3 and data[:2] == b"\x7f\x27":
            if payload[1] == 1:
                raise CommonResponseError(23)
            if data[2] == 0x35:
                raise CommonResponseError(1002)
        if len(data) < minimum or not data.startswith(expected):
            raise CommonResponseError(native_error)
        return data

    try:
        for request, response in addresses:
            filters.append(diag.start_filter(request, response))
        for index in range(len(addresses)):
            wire = True
            try:
                seed = exchange(
                    index, b"\x27\x01" + context.ecu_auth_key, b"\x67\x01", 18, 16
                )[2:18]
                wire = False
                runtime.check()
                key = key_provider(seed, context.service_auth_key)
                runtime.check()
                if type(key) is not bytes or len(key) != 16:
                    raise ValueError(
                        "Authorized security provider must return sixteen bytes"
                    )
                runtime.call("wait", milliseconds=context.seed_wait_ms)
                wire = True
                exchange(index, b"\x27\x02" + key, b"\x67\x02", 2, 17)
                wire = False
                prepared.append(index)
            except _NATIVE_BASE_ERRORS as error:
                runtime.check()
                if not wire:
                    raise
                if _is_driver_error(error):
                    if _driver_code(error) not in (9, 16):
                        raise
                    skipped.append((index, 22))
                elif _native_enum(error) in (22, 23):
                    skipped.append((index, _native_enum(error)))
                else:
                    raise
            runtime.call("wait", milliseconds=context.key_wait_ms)
        if not prepared and not context.native_retry_flag_964:
            raise CommonResponseError(17)
        if prepared:
            diagnostic_mask(runtime, context.mask_wait_ms)
            for index in prepared:
                request, response = addresses[index]
                diag.call(
                    request, response, b"\x10\x02", b"\x50", minimum=1, error_code=18
                )
        runtime.check()
    except BaseException as error:
        cleanup = cleanup_filters()
        if cleanup:
            error.add_note("Native filter cleanup failures: " + ",".join(cleanup))
        raise
    cleanup = cleanup_filters()
    if cleanup:
        raise OSError("Native filter cleanup failures: " + ",".join(cleanup))
    return {
        "state": "prepare_completed",
        "prepared_targets": tuple(prepared),
        "skipped_targets": tuple(skipped),
        "native_retry_skip": not prepared,
        "programming_completed": False,
    }


def _validate_bound_context(context, expected_type, binder):
    if not isinstance(context, expected_type):
        raise TypeError("Concrete native context required")
    if _BOUND_CONTEXTS.get(id(context)) is not context or context._binding is None:
        raise ValueError("Native context was not issued by the binding factory")
    if binder(*context._binding) != context:
        raise ValueError("Bound native context changed before execution")


def run_p4_security_powertrain(context, runtime, key_provider) -> dict:
    """Source-bound export; raw ABI vectors stay inside the lower-level helper."""
    _validate_bound_context(context, P4SecurityPowerTrainContext, bind_native_context)
    return _run_p4_security_powertrain_abi(context, runtime, key_provider)


def _run_p4_security_powertrain_abi(context, runtime, key_provider) -> dict:
    """StartPrepareWrite1160 direct BOOL and1240 native exception-output ABI.

    None error fields mean that the native handler leaves the caller's prior
    value intact. Validation, host aborts and failed cleanup remain host errors.
    """
    if not isinstance(runtime, NativeRuntime2026):
        raise TypeError("Bound native runtime required")
    try:
        result = prepare_p4_security_powertrain(context, runtime, key_provider)
    except (InterruptedError, TimeoutError):
        raise
    except _NATIVE_BASE_ERRORS + (NativeException2026,) as error:
        runtime.check()
        typed = isinstance(error, _NATIVE_BASE_ERRORS)
        if getattr(error, "__notes__", ()) or str(error).startswith(
            "Native filter cleanup failures:"
        ):
            raise
        return {
            "state": "failed",
            "native_return": False,
            "native_success": None,
            "native_error_code": _native_enum(error) if typed else None,
            "driver_error_code": _driver_code(error)
            if _is_driver_error(error)
            else None,
            "error_kind": 1 if typed else None,
            "programming_completed": False,
        }
    return {
        **result,
        "native_return": True,
        "native_success": None,
        "native_error_code": None,
        "driver_error_code": None,
        "error_kind": None,
    }


def hino_can_command(runtime: NativeRuntime2026, operation: str) -> None:
    """HINOUtils1510..20d0: exact single-message mask/communication commands."""
    commands = {
        "DiagnosticMaskP4": "00000720a08502",
        "DiagnosticMaskP5": "000007208582",
        "DiagnosticUnMaskP4": "00000720a08501",
        "DiagnosticUnMaskP5": "000007208581",
        "StartCommunicationP4": "00000720a02801",
        "StartCommunicationP5": "00000720288001",
        "StopCommunicationP4": "00000720a02802",
        "StopCommunicationP5": "00000720288101",
    }
    if (
        not isinstance(runtime, NativeRuntime2026)
        or not isinstance(operation, str)
        or operation not in commands
    ):
        raise ValueError("Native runtime and an audited HINO CAN operation required")
    CanDiag2026(runtime).write(bytes.fromhex(commands[operation]))


def hino_extract_cid(message_data: bytes, offset: int, width: int) -> str:
    """HINOUtils1710: strncpy(Data+offset,width), then native ANSI/NUL string.

    The input is J2534 Data only; its native24-byte structure header is excluded.
    Bounds reject native out-of-buffer reads and the zero-width allocation bug.
    """
    if (
        type(message_data) is not bytes
        or not 0 < len(message_data) <= 4128
        or type(offset) is not int
        or type(width) is not int
        or not 0 <= offset < len(message_data)
        or not 1 <= width <= len(message_data) - offset
    ):
        raise ValueError("Bounded native J2534 Data CID slice required")
    return message_data[offset : offset + width].split(b"\0", 1)[0].decode("latin1")


def _hino_sil(channel):
    # Local import permits SIL family runners to reuse these helpers without a cycle.
    from scripts.programming_2026_sil import SILChannel

    if not isinstance(channel, SILChannel):
        raise TypeError("Recovered SIL primitive channel required")
    channel.check()
    return channel


def hino_set_baud_rate(channel, baud_rate: int) -> None:
    """HINOUtils1f10: SET_CONFIG with native DATA_RATE parameter1."""
    if type(baud_rate) is not int or not 1 <= baud_rate <= 0xFFFFFFFF:
        raise ValueError("Native positive uint32 baud rate required")
    from scripts.programming_2026_sil import SILChannel

    if isinstance(channel, SILChannel):
        channel._void("ioctl", ioctl=2, config=((1, baud_rate),))
    elif isinstance(channel, NativeRuntime2026):
        result = channel.call("control_io", ioctl=2, parameters=((1, baud_rate),))
        if result is not None:
            raise TypeError("Native configuration primitive must return None")
    else:
        raise TypeError("Actual2026 native runtime required")


def hino_fast_init(channel, target: int, tester: int) -> None:
    """HINOUtils17c0: actual SIL FastInit(target,tester,communication3)."""
    _hino_sil(channel).fast_init(target, tester, 3)


def hino_halt(channel, target: int, tester: int) -> bytes:
    """HINOUtils virtual vtable0/17e0: service82, positiveC2, native error1007."""
    from scripts.programming_2026_sil import sil_message

    return _hino_sil(channel).exchange(
        sil_message(b"\x82", target, tester),
        minimum=4,
        payload_prefix=b"\xc2",
        pending_limit=0x95,
        busy_limit=0xFF,
        wait_ms=0,
        stop_on_pending_limit=True,
        error_code=1007,
        check_native_cancel=True,
    )


def _native_cancel_requested(runtime):
    # Shared runtime/channel observers own strict bool and host-abort precedence.
    if isinstance(runtime, NativeRuntime2026):
        return runtime.native_cancellation_requested()
    return runtime.native_cancel_requested()


def hino_tester_present_amt(channel, target: int, tester: int) -> bytes | None:
    """HINOUtils2230: service3e, positive7e, native error1006.

    Host cancellation is checked before wire I/O rather than becoming success.
    """
    from scripts.programming_2026_sil import sil_message

    channel = _hino_sil(channel)
    if _native_cancel_requested(channel):
        return None
    return channel.exchange(
        sil_message(b"\x3e", target, tester),
        minimum=4,
        payload_prefix=b"\x7e",
        pending_limit=0x95,
        busy_limit=0xFF,
        wait_ms=0,
        stop_on_pending_limit=True,
        error_code=1006,
        check_native_cancel=True,
    )


class NativeMappedTransportError(NativeTransportError):
    """Native CJ2534 driver code plus its inherited CPassThru error enum."""

    def __init__(self, driver_code: int, native_error_code: int):
        super().__init__(driver_code)
        if (
            type(native_error_code) is not int
            or not 0 <= native_error_code <= 0xFFFFFFFF
        ):
            raise ValueError("Native primary error enum must be uint32")
        self.native_error_code = native_error_code
        self.passthru_status = driver_code


def _is_driver_error(error):
    if isinstance(error, NativeJ2534Exception2026):
        return True
    if not isinstance(error, (NativeTransportError, VendorTransportError)):
        return False
    return getattr(error, "passthru_status", True) is not None


def _driver_code(error):
    if isinstance(error, NativeJ2534Exception2026):
        return error.j2534_error
    return getattr(error, "passthru_status", error.code)


def _native_enum(error):
    if isinstance(error, NativePassThruException2026):
        return error.error
    return getattr(
        error, "native_error_code", 1 if _is_driver_error(error) else error.code
    )


def _mapped_transport(exc, native_error_code):
    if isinstance(exc, NativeJ2534Exception2026):
        result = NativeJ2534Exception2026(exc.j2534_error, exc.source, exc.line)
        result.assign(exc)
        result.set_error(native_error_code)
        return result
    return NativeMappedTransportError(_driver_code(exc), native_error_code)


class CommonFlash2026:
    """Recovered CommonFlashWriter primitives; addresses include the CAN header.

    The 4096-read cap is host policy for a nonadvancing injected clock. Native
    transport errors remain distinct from recovered CPassThru error codes.
    """

    def __init__(self, runtime: NativeRuntime2026):
        if not isinstance(runtime, NativeRuntime2026):
            raise TypeError("Native2026 runtime required")
        self.runtime = runtime
        self.diag = CanDiag2026(runtime)

    def _observe(self, observer, *values):
        self.runtime.check()
        result = observer(*values)
        self.runtime.check()
        return result

    @staticmethod
    def _address(address, *, extended=False):
        if type(address) is not bytes or len(address) not in (
            (4, 5) if extended else (4,)
        ):
            raise ValueError("Full native CAN address required")

    @staticmethod
    def _uint(value):
        if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
            raise ValueError("Native unsigned integer required")

    def _write(self, request, payload, *, extended=False):
        self._address(request, extended=extended)
        self.diag.write(request + payload, tx_flags=0x80 if len(request) == 5 else 0)

    def _read(self, response, frame=0):
        self._address(response, extended=True)
        data = self.runtime.call(
            "read_specified_can_message", address=response, count=1, frame=frame
        )
        if (
            type(data) is not bytes
            or not len(response) <= len(data) <= 4128
            or not data.startswith(response)
        ):
            raise ValueError(
                "Bounded correctly addressed immutable full CAN Data required"
            )
        return data

    def _wait(self, milliseconds):
        self._uint(milliseconds)
        result = self.runtime.call("wait", milliseconds=milliseconds)
        if result is not None:
            raise TypeError("Native wait provider must return None")

    def receive_ack(self, response: bytes) -> bool:
        self._address(response, extended=True)
        for _ in range(4096):
            try:
                data = self._read(response)
            except _NATIVE_DRIVER_ERRORS as exc:
                if _is_driver_error(exc) and _driver_code(exc) in (9, 16):
                    return False
                raise
            # Native2670 tests literal DataSize5 and Data[4], including for
            # an extended caller address; it does not use address length here.
            if len(data) == 5 and data[4] == 0x3C:
                return True
        raise TimeoutError("Host CommonFlash acknowledgment read cap exhausted")

    def _ack(self, response, code):
        if not self.receive_ack(response):
            raise CommonResponseError(code)

    def get_status_once(self, request: bytes, response: bytes) -> int:
        self._address(response, extended=True)
        self._write(request, b"\x50")
        self._ack(response, 4)
        data = self._read(response)
        # Native21c0 zeroes PASSTHRU_MSG before reading fixed Data[4].
        status = data[4] if len(data) > 4 else 0
        self._ack(response, 4)
        return status

    def get_status(self, request: bytes, response: bytes, retries: bool = True) -> int:
        if type(retries) is not bool:
            raise ValueError("Native retry flag required")
        for attempt in range(4 if retries else 1):
            try:
                return self.get_status_once(request, response)
            except _NATIVE_BASE_ERRORS:
                if attempt == (3 if retries else 0):
                    raise
        raise AssertionError("Unreachable status retry state")

    def change_next_cpu(self, request: bytes, response: bytes) -> None:
        self._address(response, extended=True)
        try:
            self._write(request, b"\x65")
            self._ack(response, 19)
        except _NATIVE_DRIVER_ERRORS as exc:
            if not _is_driver_error(exc):
                raise
            raise _mapped_transport(exc, 19) from exc

    def check_finish_reprogramming(self, request: bytes, response: bytes) -> None:
        self._address(response, extended=True)
        self._write(request, b"\x3e", extended=True)
        self._read(response)

    def finish_reprogramming(
        self, request: bytes, response: bytes | None = None
    ) -> None:
        if response is not None:
            self._address(response, extended=True)
        try:
            self._write(request, b"\x80", extended=True)
            if response is not None:
                self._ack(response, 35)
        except _NATIVE_DRIVER_ERRORS as exc:
            if not _is_driver_error(exc):
                raise
            raise _mapped_transport(exc, 35) from exc

    def detect_falsify(self, request: bytes, response: bytes) -> None:
        self._address(response, extended=True)
        try:
            self._write(request, b"\x47")
            self._ack(response, 73)
            for _ in range(4096):
                status = self.get_status(request, response)
                if status != 0x50:
                    if status:
                        raise CommonResponseError(73)
                    return
            raise TimeoutError("Host CommonFlash status poll cap exhausted")
        except _NATIVE_DRIVER_ERRORS as exc:
            if not _is_driver_error(exc):
                raise
            raise _mapped_transport(exc, 73) from exc

    def get_memory_info(self, request: bytes, response: bytes, wide: bool = False):
        from scripts.programming_2026_common import extract_memory_info

        self._address(response, extended=True)
        if type(wide) is not bool:
            raise ValueError("Native memory width flag required")
        try:
            self._write(request, b"\x76")
            extended = self.receive_ack(response)
            if not extended:
                self._write(request, b"\x75")
                self._ack(response, 10)
            data = self._read(response, frame=1)
            expected = (15 if wide else 13) if extended else 12
            if len(data) != expected:
                raise CommonResponseError(10)
            info = extract_memory_info(data[4 : expected - 1] if extended else data[4:])
            self._ack(response, 10)
            return info, extended
        except _NATIVE_DRIVER_ERRORS as exc:
            if not _is_driver_error(exc):
                raise
            raise _mapped_transport(exc, 10) from exc

    def _security_parts(self, request, response, values, wait_ms, code):
        self._address(request)
        self._address(response, extended=True)
        self._uint(wait_ms)
        if any(type(value) is not bytes or len(value) != 16 for _, value in values):
            raise ValueError(
                "Explicit authorized sixteen-byte security values required"
            )
        parts = tuple(
            bytes((opcode + i,)) + value[start:end]
            for opcode, value in values
            for i, (start, end) in enumerate(((0, 6), (6, 12), (12, 16)))
        )
        try:
            for index, payload in enumerate(parts):
                self._write(request, payload)
                if index < len(parts) - 1:
                    self._wait(wait_ms)
            self._ack(response, code)
        except _NATIVE_DRIVER_ERRORS as exc:
            if not _is_driver_error(exc):
                raise
            raise _mapped_transport(exc, code) from exc

    def send_nonce(self, request, response, nonce: bytes, wait_ms: int) -> None:
        self._security_parts(request, response, ((0x37, nonce),), wait_ms, 71)

    def send_seed_key(self, request, response, key: bytes, wait_ms: int) -> None:
        self._security_parts(request, response, ((0x3A, key),), wait_ms, 72)

    def send_nonce_and_seed_key(
        self, request, response, nonce: bytes, key: bytes, wait_ms: int
    ) -> None:
        self._security_parts(
            request, response, ((0x37, nonce), (0x3A, key)), wait_ms, 72
        )

    def check_id_with_wait_of_sfs(
        self,
        request,
        response,
        location_id: bytes,
        password: int,
        wait_ms: int,
        initial_timeout: int = 0,
        swap_endian: bool = False,
    ) -> None:
        self._address(request)
        self._address(response, extended=True)
        for value in (password, wait_ms, initial_timeout):
            self._uint(value)
        if (
            type(location_id) is not bytes
            or len(location_id) != 8
            or type(swap_endian) is not bool
        ):
            raise ValueError("Native eight-byte LocationID and endian flag required")
        secret = password.to_bytes(4, "big")
        if swap_endian:
            location_id = b"".join(location_id[i : i + 2][::-1] for i in range(0, 8, 2))
            secret = secret[::-1]
        parts = (
            b"\0",
            b"\0",
            bytes(location_id[i] for i in (7, 6, 3, 2, 1, 0)),
            location_id[5:3:-1],
            secret[::-1],
        )
        try:
            for index, payload in enumerate(parts):
                self._write(request, payload)
                if index != 4:
                    self._wait(wait_ms)
            self._ack(response, 7)
            if initial_timeout:
                result = self.runtime.call("set_timeout", milliseconds=initial_timeout)
                if result is not None:
                    raise TypeError("Native timeout setter must return None")
            self._read(response, frame=1)
            self._write(request, b"\x3c")
        except _NATIVE_DRIVER_ERRORS as exc:
            if not _is_driver_error(exc):
                raise
            raise _mapped_transport(exc, 7) from exc

    def _block_operation(self, request, response, first, last, parameter, wide, mode):
        from scripts.programming_2026_common import NativeParameter2026

        self._address(request)
        self._address(response, extended=True)
        if (
            not isinstance(parameter, NativeParameter2026)
            or type(wide) is not bool
            or type(first) is not int
            or type(last) is not int
            or not 1 <= first <= last <= (65536 if wide else 256)
        ):
            raise ValueError("Bound native parameter and block range required")
        opcode, code, wait_name = {
            "check": (0x35, 11, "WaitTimeBeforeStatusCheckForBlankCheck"),
            "erase": (0x25, 12, "WaitTimeBeforeStatusCheckForEraseBlock"),
            "verify": (0x47, 14, "WaitTimeBeforeStatusCheckForInVerify"),
        }[mode]
        wait_ms = parameter.long(wait_name) or 0
        self._uint(wait_ms)
        payload = (
            bytes((opcode + 1,))
            + (first - 1).to_bytes(2, "big")
            + (last - 1).to_bytes(2, "big")
            if wide
            else bytes((opcode, first - 1))
        )
        try:
            self._write(request, payload)
            self._ack(response, code)
            for _ in range(4096):
                self._wait(wait_ms)
                status = self.get_status(request, response)
                pending = (
                    status == {"check": 0x10, "verify": 0x40}.get(mode)
                    if mode != "erase"
                    else status != 0 and status & 0xF == 0
                )
                if not pending:
                    if mode == "check":
                        return status == 0
                    if status:
                        raise CommonResponseError(code)
                    return None
            raise TimeoutError("Host CommonFlash block poll cap exhausted")
        except _NATIVE_DRIVER_ERRORS as exc:
            if not _is_driver_error(exc):
                raise
            raise _mapped_transport(exc, code) from exc

    def check_block(
        self, request, response, parameter, first: int, last: int, wide: bool = False
    ) -> bool:
        return bool(
            self._block_operation(
                request, response, first, last, parameter, wide, "check"
            )
        )

    def erase_block(
        self, request, response, first: int, last: int, parameter, wide: bool = False
    ) -> None:
        self._block_operation(request, response, first, last, parameter, wide, "erase")

    def in_verify_block(
        self, request, response, parameter, first: int, last: int, wide: bool = False
    ) -> None:
        self._block_operation(request, response, first, last, parameter, wide, "verify")

    def is_finish_reprogramming(self, groups) -> bool:
        from scripts.j2534_2026 import NativeCommunicationAddress

        if (
            type(groups) is not tuple
            or not groups
            or type(groups[0]) is not tuple
            or not groups[0]
            or not isinstance(groups[0][0], NativeCommunicationAddress)
        ):
            raise ValueError("Native communication-address groups required")
        request, response = groups[0][0].headers()
        identifier = None
        with _cleanup_on_exit(
            lambda: (
                self.runtime.release("stop_filter", identifier=identifier)
                if identifier is not None
                else None
            )
        ):
            try:
                identifier = self.diag.start_filter(request, response)
                self.check_finish_reprogramming(request, response)
                return True
            except _NATIVE_BASE_ERRORS:
                self.runtime.check()
                return False
            except NativeException2026:
                self.runtime.check()
                return False

    @staticmethod
    def _progress(cpu_index, counts, percentages, notify):
        if (
            type(cpu_index) is not int
            or type(counts) is not list
            or type(percentages) is not list
            or not 0 < len(counts) == len(percentages) <= 256
            or not 0 <= cpu_index < len(counts)
            or any(
                type(v) is not int or not 0 <= v <= 0xFFFFFFFF
                for v in counts + percentages
            )
            or not callable(notify)
        ):
            raise ValueError("Bounded native progress arrays and observer required")

    def write_bytes(
        self,
        request,
        cpu_index: int,
        size: int,
        cursor: list[int],
        base_offset: int,
        image: bytes,
        total_size: int,
        counts: list[int],
        percentages: list[int],
        notify: Callable[[str], None],
        percent_base: int = -1,
    ) -> None:
        self._address(request)
        self._progress(cpu_index, counts, percentages, notify)
        if (
            type(image) is not bytes
            or not 0 < len(image) <= 64 * 1024 * 1024
            or type(size) is not int
            or not 0 < size <= 4124
            or type(cursor) is not list
            or len(cursor) != 1
            or type(cursor[0]) is not int
            or type(base_offset) is not int
            or not 0 <= base_offset <= len(image)
            or not 0 <= cursor[0] <= len(image) - base_offset - size
            or type(total_size) is not int
            or not 0 < total_size <= 64 * 1024 * 1024
            or type(percent_base) is not int
            or not -1 <= percent_base <= 100
            or counts[cpu_index] + size > 0xFFFFFFFF
        ):
            raise ValueError(
                "Bounded imported image slice and native progress required"
            )
        start = base_offset + cursor[0]
        self._write(request, image[start : start + size])
        cursor[0] += size
        counts[cpu_index] += size
        self._observe(notify, "count")
        percentages[cpu_index] = int(
            counts[cpu_index] / (total_size * 2) * 100.0
            if percent_base == -1
            else (base_offset + cursor[0]) / total_size * 50.0 + percent_base
        )
        self._observe(notify, "percent")

    @staticmethod
    def _geometry(first, last, sizes, image, chunk):
        if (
            type(first) is not int
            or type(last) is not int
            or type(sizes) is not tuple
            or not 0 < len(sizes) <= 65536
            or any(type(v) is not int or not 0 <= v <= 64 * 1024 * 1024 for v in sizes)
            or not 1 <= first <= last <= len(sizes)
            or type(image) is not bytes
            or not 0 < len(image) <= 64 * 1024 * 1024
        ):
            raise ValueError(
                "Imported native block-size vector and bounded image required"
            )
        offset = sum(sizes[: first - 1])
        extent = (last - first + 1) * sizes[first - 1]
        # Native transfer loops always emit a complete chunk and assume equal
        # block sizes within one range. Reject unsafe caller geometry up front.
        if (
            not sizes[first - 1]
            or len(set(sizes[first - 1 : last])) != 1
            or extent % chunk
            or offset + extent > len(image)
        ):
            raise ValueError(
                "Native uniform complete-chunk range exceeds imported image"
            )
        return offset, extent

    def _poll_zero(self, request, response, wait_ms, code, retries=True):
        for _ in range(4096):
            self._wait(wait_ms)
            status = self.get_status(request, response, retries)
            if status == 0:
                return
            if status & 0xF:
                raise CommonResponseError(code)
        raise TimeoutError("Host CommonFlash transfer status cap exhausted")

    def write_block(
        self,
        request,
        response,
        cpu_index,
        first,
        last,
        sizes,
        memory,
        image,
        total_size,
        parameter,
        counts,
        percentages,
        notify,
        notify_error: Callable[[int], None],
        wait_ms: int = 0,
        wide: bool = False,
    ) -> None:
        from scripts.programming_2026_common import (
            NativeMemoryInfo,
            NativeParameter2026,
        )

        self._address(request)
        self._address(response, extended=True)
        self._progress(cpu_index, counts, percentages, notify)
        self._uint(wait_ms)
        if (
            not isinstance(memory, NativeMemoryInfo)
            or not isinstance(parameter, NativeParameter2026)
            or type(wide) is not bool
            or not callable(notify_error)
        ):
            raise ValueError(
                "Bound native memory, parameter and error observer required"
            )
        transfer_type = parameter.long("SendDataByteForWriteBlockType") or 0
        chunk, marker = {1: (512, 0x7F), 2: (128, 0x1F)}.get(
            transfer_type, (1024, 0xFF)
        )
        offset, extent = self._geometry(first, last, sizes, image, chunk)
        address = memory.start_address + offset
        width = 4 if wide else 3
        if not 0 <= address < 1 << (width * 8):
            raise ValueError("Native write address exceeds selected address width")
        poll_wait = parameter.long("WaitTimeBeforeStatusCheckForWriteBlock") or 0
        self._uint(poll_wait)
        if (
            type(total_size) is not int
            or not 0 < total_size <= 64 * 1024 * 1024
            or counts[cpu_index] + extent > 0xFFFFFFFF
        ):
            raise ValueError("Bounded native total size and progress required")
        cursor = [0]
        try:
            self._observe(notify_error, 13)
            self._write(request, b"\x41")
            self._ack(response, 13)
            self._write(request, address.to_bytes(width, "big") + bytes((marker,)))
            if wait_ms:
                self._wait(wait_ms)
            while cursor[0] < extent:
                if cursor[0]:
                    self._write(request, b"\x45")
                    self._ack(response, 13)
                self.write_bytes(
                    request,
                    cpu_index,
                    chunk,
                    cursor,
                    offset,
                    image,
                    total_size,
                    counts,
                    percentages,
                    notify,
                )
                self._ack(response, 13)
                self._poll_zero(request, response, poll_wait, 13)
            self._observe(notify_error, 9999)
        except _NATIVE_BASE_ERRORS as exc:
            raise (
                _mapped_transport(exc, 13)
                if _is_driver_error(exc)
                else CommonResponseError(13)
            ) from exc

    def _poll_verify(self, request, response, wait_ms, final):
        prior_status = 0
        for _ in range(4096):
            self._wait(wait_ms)
            try:
                status = self.get_status(request, response, retries=final)
            except _NATIVE_BASE_ERRORS:
                # Native inner base-class catch includes derived driver errors.
                # A nonfinal fault uses the previous status byte; the first
                # failed status read retains its initialized zero value.
                if final:
                    raise
                if prior_status:
                    raise CommonResponseError(15)
                return
            prior_status = status
            if status == 0:
                return
            if status & 0xF:
                raise CommonResponseError(15)
        raise TimeoutError("Host CommonFlash verify status cap exhausted")

    def _verify_transfer(
        self,
        request,
        response,
        cpu_index,
        first,
        last,
        sizes,
        image,
        total_size,
        parameter,
        counts,
        percentages,
        notify,
        notify_error,
        wide,
        alternate,
    ):
        from scripts.programming_2026_common import NativeParameter2026

        self._address(request)
        self._address(response, extended=True)
        self._progress(cpu_index, counts, percentages, notify)
        if (
            not isinstance(parameter, NativeParameter2026)
            or type(wide) is not bool
            or (not alternate and not callable(notify_error))
        ):
            raise ValueError("Bound native parameter and observers required")
        chunk = 128 if alternate else 256
        offset, extent = self._geometry(first, last, sizes, image, chunk)
        if first > (65536 if wide or alternate else 256) or last > (
            65536 if wide or alternate else 256
        ):
            raise ValueError("Native verify range exceeds selected width")
        if (
            type(total_size) is not int
            or not 0 < total_size <= 64 * 1024 * 1024
            or counts[cpu_index] + extent > 0xFFFFFFFF
        ):
            raise ValueError("Bounded native total size and progress required")
        wait_ms = parameter.long("WaitTimeBeforeStatusCheckForVerify") or 0
        self._uint(wait_ms)
        try:
            if not alternate:
                self._observe(notify_error, 15)
            payload = (
                bytes((0x18 if alternate else 0x16,))
                + (first - 1).to_bytes(2, "big")
                + (last - 1).to_bytes(2, "big")
                if wide or alternate
                else bytes((0x15, first - 1))
            )
            self._write(request, payload)
            self._ack(response, 15)
            cursor = [0]
            while cursor[0] < extent:
                self.write_bytes(
                    request,
                    cpu_index,
                    chunk,
                    cursor,
                    offset,
                    image,
                    total_size,
                    counts,
                    percentages,
                    notify,
                )
                self._ack(response, 15)
                final = cursor[0] == extent
                self._poll_verify(request, response, wait_ms, final)
            if not alternate:
                self._observe(notify_error, 9999)
        except _NATIVE_BASE_ERRORS as exc:
            raise (
                _mapped_transport(exc, 15)
                if _is_driver_error(exc)
                else CommonResponseError(15)
            ) from exc

    def verify_block(
        self,
        request,
        response,
        cpu_index,
        first,
        last,
        sizes,
        image,
        total_size,
        parameter,
        counts,
        percentages,
        notify,
        notify_error,
        wide=False,
    ):
        self._verify_transfer(
            request,
            response,
            cpu_index,
            first,
            last,
            sizes,
            image,
            total_size,
            parameter,
            counts,
            percentages,
            notify,
            notify_error,
            wide,
            False,
        )

    def verify_block2(
        self,
        request,
        response,
        cpu_index,
        first,
        last,
        sizes,
        image,
        total_size,
        parameter,
        counts,
        percentages,
        notify,
    ):
        self._verify_transfer(
            request,
            response,
            cpu_index,
            first,
            last,
            sizes,
            image,
            total_size,
            parameter,
            counts,
            percentages,
            notify,
            None,
            True,
            True,
        )


@dataclass(frozen=True)
class HINODSSPreparationResult:
    prepared: bool
    native_error_code: int | None = None
    driver_error_code: int | None = None
    result_code: int | None = None


class HINOUtils2026:
    """Recovered CAN HINO utility flows over actual2026 diagnostic primitives."""

    def __init__(
        self,
        runtime: NativeRuntime2026,
        pending_timeout_ms: int = 5000,
        *,
        sil_channel=None,
    ):
        from scripts.programming_2026_sil import SILChannel

        if sil_channel is not None and not isinstance(sil_channel, SILChannel):
            raise TypeError(
                "Actual2026 SIL channel or absent native SIL pointer required"
            )
        if not isinstance(runtime, NativeRuntime2026):
            raise TypeError("Native2026 runtime required")
        CommonFlash2026._uint(pending_timeout_ms)
        self.runtime = runtime
        self.diag = CanDiag2026(runtime)
        self.pending_timeout_ms = pending_timeout_ms
        self.sil_channel = sil_channel

    def _observe(self, observer, *values):
        self.runtime.check()
        result = observer(*values)
        self.runtime.check()
        return result

    def clone(self):
        # Native copy/move constructors copy references without bus activity.
        result = object.__new__(HINOUtils2026)
        return result.assign_from(self)

    def assign_from(self, other):
        if not isinstance(other, HINOUtils2026):
            raise TypeError("Native HINO utility source object required")
        self.runtime = other.runtime
        self.diag = other.diag
        self.pending_timeout_ms = other.pending_timeout_ms
        self.sil_channel = other.sil_channel
        return self

    def _call(
        self,
        request,
        response,
        payload,
        expected,
        minimum,
        code,
        *,
        fixed_timeout=False,
    ):
        return self.diag.call(
            request,
            response,
            payload,
            expected,
            minimum=minimum,
            error_code=code,
            pending_timeout_ms=5000 if fixed_timeout else self.pending_timeout_ms,
        )

    def collate_seed_key_dss(self, request: bytes, response: bytes) -> None:
        seed_response = self._call(
            request, response, b"\x27\x03", b"\x67\x03", 6, 16, fixed_timeout=True
        )
        key = bytes(value ^ 0xFF for value in seed_response[2:6])
        self._call(
            request,
            response,
            b"\x27\x04" + key,
            b"\x67\x04\x34",
            3,
            17,
            fixed_timeout=True,
        )

    def programming_session_dss(self, request: bytes, response: bytes) -> None:
        self._call(
            request, response, b"\x10\x85", b"\x50\x85", 2, 41, fixed_timeout=True
        )

    def request_transfer_exit(self, request: bytes, response: bytes) -> None:
        self._call(request, response, b"\x37", b"\x77", 1, 28)

    def tester_present(
        self, request: bytes, response: bytes, *, vcs: bool = False
    ) -> None:
        if type(vcs) is not bool:
            raise ValueError("Native VCS tester-present flag required")
        # Native callback12 skips tester-present; host cancellation/deadline
        # remain exceptions, independently checked around that observation.
        if _native_cancel_requested(self.runtime):
            return
        self._call(request, response, b"\x3e\x01" if vcs else b"\x3e", b"\x7e", 1, 3)

    def transfer_data(
        self, request, response, size: int, image: bytes, cursor: list[int]
    ) -> None:
        CanDiag2026._addresses(request, response)
        if (
            type(image) is not bytes
            or len(image) > 64 * 1024 * 1024
            or type(size) is not int
            or not 0 <= size <= 4123
            or type(cursor) is not list
            or len(cursor) != 1
            or type(cursor[0]) is not int
            or not 0 <= cursor[0] <= len(image) - size
        ):
            raise ValueError("Bounded imported HINO transfer slice required")
        self._call(
            request,
            response,
            b"\x36" + image[cursor[0] : cursor[0] + size],
            b"\x76",
            1,
            34,
        )
        cursor[0] += size

    def send_data(
        self,
        request,
        response,
        image: bytes,
        chunk_size: int,
        data_type: int,
        counts: list[int],
        percentages: list[int],
        notify: Callable[[str], None],
    ) -> None:
        CanDiag2026._addresses(request, response)
        if (
            type(image) is not bytes
            or len(image) > 64 * 1024 * 1024
            or type(chunk_size) is not int
            or not 0 < chunk_size <= 4123
            or type(data_type) is not int
            or not -0x80000000 <= data_type <= 0x7FFFFFFF
        ):
            raise ValueError(
                "Bounded imported HINO image/chunk and native data type required"
            )
        CommonFlash2026._progress(0, counts, percentages, notify)
        if len(counts) != 1:
            raise ValueError("HINO native single progress values required")
        cursor = [0]
        while cursor[0] < len(image):
            self.transfer_data(
                request,
                response,
                min(chunk_size, len(image) - cursor[0]),
                image,
                cursor,
            )
            if data_type == 1:
                counts[0] = cursor[0]
                self._observe(notify, "count")
                percentages[0] = int(cursor[0] / len(image) * 100.0)
                self._observe(notify, "percent")

    def prepare_write_dss(
        self, request: bytes, response: bytes, notification: Callable[[], bool]
    ) -> HINODSSPreparationResult:
        CanDiag2026._addresses(request, response)
        if not callable(notification):
            raise TypeError("Native notification reader required")
        identifier = None
        error = None
        with _cleanup_on_exit(
            lambda: (
                self.runtime.release("stop_filter", identifier=identifier)
                if identifier is not None
                else None
            )
        ):
            try:
                identifier = self.diag.start_filter(request, response)
                for operation in (
                    "DiagnosticMaskP4",
                    "DiagnosticMaskP5",
                    "StopCommunicationP4",
                    "StopCommunicationP5",
                ):
                    hino_can_command(self.runtime, operation)
                result = self.runtime.call("wait", milliseconds=1000)
                if result is not None:
                    raise TypeError("Native wait provider must return None")
                self.programming_session_dss(request, response)
                self.collate_seed_key_dss(request, response)
            except _NATIVE_BASE_ERRORS as exc:
                self.runtime.check()
                error = exc
            except NativeException2026:
                self.runtime.check()
                # Native1920 catch-all reports primary9999 for an unclassified
                # native fault. Host cancellation/deadline remain host exceptions.
                error = CommonResponseError(9999)

        if error is None:
            return HINODSSPreparationResult(True)
        flag = self._observe(notification)
        if type(flag) is not bool:
            raise TypeError("Native notification reader must return bool")
        driver = _is_driver_error(error)
        return HINODSSPreparationResult(
            False,
            _native_enum(error),
            _driver_code(error) if driver else None,
            int(flag) + 1,
        )


_CAN_CID = "TCUWCanCIDGetter.dll"


@dataclass(frozen=True)
class CanCIDContext2026:
    identity: NativeModuleIdentity
    addresses: tuple
    receive_timeout_ms: int
    timeout_allowing_id: bytes = b""
    breaking_response_id: bytes = b""
    _binding: tuple | None = field(default=None, repr=False, compare=False)

    def __post_init__(self):
        from scripts.j2534_2026 import NativeCommunicationAddress

        if (
            not isinstance(self.identity, NativeModuleIdentity)
            or self.identity != identify_native_module(self.identity.sha256, _CAN_CID)
            or self.identity.cuw_build != "2026"
            or type(self.addresses) is not tuple
            or len(self.addresses) > 256
            or any(
                not isinstance(address, NativeCommunicationAddress)
                for address in self.addresses
            )
            or any(
                type(value) is not bytes or len(value) not in (0, 2, 3)
                for value in (self.timeout_allowing_id, self.breaking_response_id)
            )
        ):
            raise ValueError(
                "Exact2026 CAN CID source and native address context required"
            )
        CommonFlash2026._uint(self.receive_timeout_ms)


def bind_can_cid_context(
    container, node, observed_cids, selection, identity, attachments, observations
) -> CanCIDContext2026:
    if (
        not isinstance(selection, NativeParameterBinding2026)
        or selection.operation != "get_cid"
        or selection.module_name != _CAN_CID
        or not isinstance(attachments, Mapping)
        or not isinstance(observations, Mapping)
        or attachments
        or set(observations) - {"stage", "cpu_index"}
        or observations.get("stage", "get_cid") != "get_cid"
        or observations.get("cpu_index", 0) != 0
    ):
        raise ValueError(
            "Native2026 getter parameter binding without manual overrides required"
        )
    selection = selection.validate_against(
        container, operation="get_cid", node=node, cpu_index=0
    )
    producer = communication_addresses_from_parameter(container, selection.parameter)
    success, addresses = producer.resolve(
        selection.selector_functions,
        cids=observed_cids,
        location_id=selection.metadata.cpu.values.get("locationid") or None,
    )
    if not success:
        raise ValueError("Native getter address selectors did not resolve")

    def optional_id(name):
        value = selection.value(name)
        if not value:
            return b""
        if len(value) not in (4, 6) or any(
            c not in "0123456789abcdefABCDEF" for c in value
        ):
            raise ValueError(
                "Native optional request CAN ID requires two/three hexadecimal bytes"
            )
        return bytes.fromhex(value)

    context = CanCIDContext2026(
        identity,
        addresses,
        selection.parameter.long("ReceiveTimeoutBeforeGetCID") or 0,
        optional_id("RequestCANIDAllowingTimeout"),
        optional_id("RequestCANIDBreakingResponse"),
        (
            container,
            node,
            tuple(observed_cids),
            selection,
            identity,
            MappingProxyType(dict(attachments)),
            MappingProxyType(dict(observations)),
        ),
    )
    _BOUND_CONTEXTS[id(context)] = context
    return context


def decode_can_cids2026(data: bytes) -> tuple[str, ...]:
    """CanCID1970: full J2534 Data, conditional seven/eight-byte header."""
    if type(data) is not bytes or not 7 <= len(data) <= 4128:
        raise CommonResponseError(3)
    header = 8 if data[5:7] == b"\x49\x04" else 7
    if len(data) < header + 16 or len(data) != header + data[header - 1] * 16:
        raise CommonResponseError(3)
    return tuple(
        value.decode("latin-1")
        for offset in range(header, len(data), 16)
        if (value := data[offset : offset + 16].split(b"\0", 1)[0])
    )


def run_can_cid(
    context: CanCIDContext2026,
    runtime: NativeRuntime2026,
    *,
    controller=None,
    engine=None,
) -> dict:
    """Source-bound pointer-return export with a revalidated issued context."""
    _validate_bound_context(context, CanCIDContext2026, bind_can_cid_context)
    return _run_can_cid_abi(context, runtime, controller=controller, engine=engine)


def _run_can_cid_abi(
    context: CanCIDContext2026,
    runtime: NativeRuntime2026,
    *,
    controller=None,
    engine=None,
) -> dict:
    if not isinstance(context, CanCIDContext2026) or not isinstance(
        runtime, NativeRuntime2026
    ):
        raise TypeError("Bound actual2026 CAN getter and runtime required")
    if controller is not None:
        from scripts.programming_2026_common import ControlCommPhase2026

        if (
            type(controller) is not ControlCommPhase2026
            or controller.runtime is not runtime
        ):
            raise TypeError("Concrete same-runtime native history controller required")
    if engine is not None:
        from scripts.cuw_2026 import CUWEngine2026

        if type(engine) is not CUWEngine2026:
            raise TypeError("Concrete native engine required for query-record writes")
        if (
            context._binding is None
            or engine.source_sha256 != context._binding[0].digest
            or engine.native_metadata.node != context._binding[1]
        ):
            raise ValueError("Native engine and getter source selection differ")
        engine._require_owned_phase()
    if context.addresses and runtime.native_cancelled is None:
        raise ValueError("Native getter callback12 observation is not bound")
    if runtime.owns_resource("disconnect"):
        raise ValueError("CAN getter requires its own connection scope")
    diag = CanDiag2026(runtime)
    cids, history, query_ids = [], [], []
    failure = None
    connected = False

    def exchange(address, payload, check_native_cancel, probe=False):
        request, response = address.headers()
        identifier = diag.start_filter(request, response)
        with _cleanup_on_exit(
            lambda: runtime.release("stop_filter", identifier=identifier)
        ):
            if check_native_cancel and _native_cancel_requested(runtime):
                return None
            try:
                return diag.call(
                    request,
                    response,
                    payload,
                    None,
                    error_code=3,
                    check_native_cancel=check_native_cancel,
                )
            except _NATIVE_DRIVER_ERRORS as exc:
                if (
                    not probe
                    or not _is_driver_error(exc)
                    or _driver_code(exc) not in (9, 16)
                ):
                    raise
                return None

    with _cleanup_on_exit(lambda: runtime.release("disconnect") if connected else None):
        try:
            result = runtime.call_owned("connect", "disconnect", protocol=6)
            connected = True
            if result is not None:
                raise TypeError("Native connection primitive must return None")
            result = runtime.call(
                "set_timeout", milliseconds=context.receive_timeout_ms
            )
            if result is not None:
                raise TypeError("Native timeout setter must return None")
            for address in context.addresses:
                probe = exchange(address, b"\x09\x00", False, probe=True)
                supported = (
                    probe is not None and len(probe) == 6 and bool(probe[2] & 0x30)
                )
                if not supported:
                    if address.request != context.timeout_allowing_id:
                        raise CommonResponseError(3)
                    continue
                payload = exchange(address, b"\x09\x04", True)
                _, response = address.headers()
                decoded = (
                    () if payload is None else decode_can_cids2026(response + payload)
                )
                if len(cids) + len(decoded) > 4096:
                    raise ValueError("Host CID vector capacity exceeded")
                start = len(cids)
                cids.extend(decoded)
                query_ids.extend(
                    address.request.hex().upper().encode("ascii")
                    for _ in range(start, min(len(cids), 34))
                )
                if engine is not None:
                    engine.apply_can_cid_queries(
                        context.identity, tuple(query_ids), (0,) * len(query_ids)
                    )
                if controller is not None:
                    controller.remember_cid_address(address)
                history.append(address)
                if address.request == context.breaking_response_id:
                    break
        except _NATIVE_BASE_ERRORS as exc:
            runtime.check()
            failure = exc
        except NativeException2026 as exc:
            runtime.check()
            failure = exc

    driver = _is_driver_error(failure)
    return {
        "state": "read_completed" if failure is None else "failed",
        "native_return": None,
        "native_success": failure is None,
        "cids": tuple(value.encode("latin-1") for value in cids),
        "history": tuple(history),
        "query_ids": tuple(query_ids),
        "query_cpu_indices": (0,) * len(query_ids),
        "native_error_code": _native_enum(failure)
        if isinstance(failure, _NATIVE_BASE_ERRORS)
        else None,
        "driver_error_code": _driver_code(failure) if driver else None,
        "programming_completed": False,
    }
