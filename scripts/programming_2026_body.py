"""Source-bound CUW2026 retained body operations over typed host primitives.

MODULE_EXPORTS is the allocation, not a claim that every allocated export is
implemented. IMPLEMENTED_EXPORTS enumerates only independently auditable ports.
"""

from collections.abc import Mapping
from dataclasses import asdict, dataclass, field

from scripts.calibration_2026 import native2026_archive, native2026_metadata
from scripts.j2534_2026 import (
    NativeCommunicationAddress,
    NativePassThruError2026,
    communication_addresses_from_parameter,
)
from scripts.native_modules import NativeModuleIdentity, identify_native_module
from scripts.programming import NativeTransportError
from scripts.programming_2026_common import (
    CanDiag2026,
    CommonResponseError,
    NativeJ2534Exception2026,
    NativeParameterBinding2026,
    NativePassThruException2026,
    NativeRuntime2026,
    NotificationBool,
    SecretInfoClient,
    cpu_bus_type,
    diagnostic_mask,
    is_native_exception2026,
    security_up_key,
    seed_key_four_round,
    seed_key_six_byte,
    seed_key_two_byte,
)
from scripts.programming_2026_legacy import CommonFlash2026

MODULE_EXPORTS = {
    "TCUWP4CanAirbagFlashWriter.dll": ("IsFinishReprogramming", "StartFlashWrite"),
    "TCUWP4CanAirbagPrepareWriter.dll": ("StartPrepareWrite",),
    "TCUWP4CanBodyFlashWriter.dll": ("StartFlashWrite",),
    "TCUWP4CanBodyFlashWriterForCXPI.dll": ("StartFlashWrite",),
    "TCUWP4CanBodyPrepareWriter.dll": (
        "ChangeToReprogGatewayMode",
        "StartPrepareWrite",
    ),
    "TCUWP4CanCentralGWPrepareWriter.dll": ("StartPrepareWrite",),
    "TCUWP4CanChassisShrinkFlashWriter.dll": ("StartFlashWrite",),
    "TCUWP4CanChassisShrinkPrepareWriter.dll": ("StartPrepareWrite",),
    "TCUWP4CanClearanceSonarFlashWriter.dll": ("StartFlashWrite",),
    "TCUWP4CanClearanceSonarPrepareWriter.dll": ("StartPrepareWrite",),
    "TCUWP4CanDSS1FlashWriter.dll": ("IsFinishReprogramming", "StartFlashWrite"),
    "TCUWP4CanPowerTrainPrepareWriter.dll": ("StartPrepareWrite",),
    "TCUWP4CanSecurityAirbagFlashWriter.dll": (
        "IsFinishReprogramming",
        "StartFlashWrite",
    ),
    "TCUWP4CanSecurityAirbagPrepareWriter.dll": ("StartPrepareWrite",),
    "TCUWP4CanSecurityChassisShrinkFlashWriter.dll": ("StartFlashWrite",),
    "TCUWP4CanSecurityChassisShrinkPrepareWriter.dll": ("StartPrepareWrite",),
    "TCUWP5CanBodyFlashWriter.dll": ("StartFlashWrite",),
}
_PASSWORD_PREPARERS = (
    "TCUWP4CanAirbagPrepareWriter.dll",
    "TCUWP4CanClearanceSonarPrepareWriter.dll",
)
_SECURITY_AIRBAG = "TCUWP4CanSecurityAirbagPrepareWriter.dll"
_BODY_PREPARER = "TCUWP4CanBodyPrepareWriter.dll"
_CENTRAL_GATEWAY = "TCUWP4CanCentralGWPrepareWriter.dll"
_P4_POWERTRAIN = "TCUWP4CanPowerTrainPrepareWriter.dll"
_CHASSIS = (
    "TCUWP4CanChassisShrinkPrepareWriter.dll",
    "TCUWP4CanSecurityChassisShrinkPrepareWriter.dll",
)
_FINISH_WRAPPERS = (
    "TCUWP4CanAirbagFlashWriter.dll",
    "TCUWP4CanSecurityAirbagFlashWriter.dll",
    "TCUWP4CanDSS1FlashWriter.dll",
)
IMPLEMENTED_EXPORTS = {
    **dict.fromkeys(_PASSWORD_PREPARERS, ("StartPrepareWrite",)),
    _BODY_PREPARER: ("ChangeToReprogGatewayMode", "StartPrepareWrite"),
    _SECURITY_AIRBAG: ("StartPrepareWrite",),
    **dict.fromkeys(_CHASSIS, ("StartPrepareWrite",)),
    _CENTRAL_GATEWAY: ("StartPrepareWrite",),
    _P4_POWERTRAIN: ("StartPrepareWrite",),
    **dict.fromkeys(_FINISH_WRAPPERS, ("IsFinishReprogramming",)),
}


def _source(identity: NativeModuleIdentity) -> None:
    if (
        not isinstance(identity, NativeModuleIdentity)
        or identity.module_name not in MODULE_EXPORTS
        or identity.cuw_build != "2026"
        or identity != identify_native_module(identity.sha256, identity.module_name)
    ):
        raise ValueError("Exact registered CUW2026 retained body identity required")


def _unsigned(value, name):
    if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
        raise ValueError(f"{name} must be a native uint32")
    return value


@dataclass(frozen=True)
class BodyPrepareContext2026:
    identity: NativeModuleIdentity
    binding: NativeParameterBinding2026 = field(repr=False)
    addresses: tuple[NativeCommunicationAddress, ...]
    bus: int
    password: bytes = field(repr=False)
    key_material: bytes = field(repr=False)
    seed_wait_ms: int
    key_wait_ms: int
    mask_wait_ms: int
    ig_off_retriable: bool = False
    cpu_count: int = 1
    external_memory: bool = False

    def __post_init__(self):
        _source(self.identity)
        if (
            self.identity.module_name
            not in (*_PASSWORD_PREPARERS, _SECURITY_AIRBAG, _BODY_PREPARER)
            or not isinstance(self.binding, NativeParameterBinding2026)
            or self.binding.operation
            not in (
                ("prepare", "change_gateway")
                if self.identity.module_name == _BODY_PREPARER
                else ("prepare",)
            )
            or self.binding.module_name != self.identity.module_name
            or type(self.addresses) is not tuple
            or not 1 <= len(self.addresses) <= 4
            or any(
                not isinstance(a, NativeCommunicationAddress) for a in self.addresses
            )
            or type(self.bus) is not int
            or self.bus not in (0, 1, 2)
            or any(
                type(v) is not bytes
                or len(v)
                != (
                    16
                    if self.identity.module_name == _SECURITY_AIRBAG
                    else 0
                    if self.identity.module_name == _BODY_PREPARER
                    else 2
                )
                for v in (self.password, self.key_material)
            )
            or type(self.ig_off_retriable) is not bool
            or type(self.cpu_count) is not int
            or not 0 <= self.cpu_count <= 256
            or (self.identity.module_name != _SECURITY_AIRBAG and self.cpu_count != 1)
            or type(self.external_memory) is not bool
            or (self.identity.module_name == _SECURITY_AIRBAG and self.bus != 2)
        ):
            raise ValueError("Bound selected native body preparation inputs required")
        for value in (self.seed_wait_ms, self.key_wait_ms, self.mask_wait_ms):
            _unsigned(value, "Native preparation wait")


def bind_native_context(
    container, node, observed_cids, selection, identity, attachments, observations
):
    """Bind first-address/CPU0 preparation semantics to actual47/31/48 producers."""
    _source(identity)
    if (
        isinstance(selection, NativeParameterBinding2026)
        and selection.operation == "write"
        and identity.module_name in _WRITER_MODULES
    ):
        return _bind_body_write_context(
            container,
            node,
            observed_cids,
            selection,
            identity,
            attachments,
            observations,
        )
    if identity.module_name == _P4_POWERTRAIN:
        return bind_powertrain_context(
            container,
            node,
            observed_cids,
            selection,
            identity,
            attachments,
            observations,
        )
    if identity.module_name == _CENTRAL_GATEWAY:
        if (
            not isinstance(selection, NativeParameterBinding2026)
            or selection.operation != "prepare"
            or selection.module_name != _CENTRAL_GATEWAY
            or attachments
            or observations
        ):
            raise ValueError(
                "Selected actual2026 CentralGW preparation without overrides required"
            )
        selection.validate_against(
            container,
            operation="prepare",
            node=node,
            cpu_index=selection.metadata.cpu_index,
        )
        return CentralGatewayContext2026(
            identity,
            selection,
            _unsigned(
                selection.parameter.long("WaitTimeAfterReprogrammingMode") or 0,
                "Gateway wait",
            ),
        )
    if identity.module_name in _CHASSIS:
        return bind_chassis_context(
            container,
            node,
            observed_cids,
            selection,
            identity,
            attachments,
            observations,
        )
    if (
        not isinstance(selection, NativeParameterBinding2026)
        or selection.operation
        not in (
            ("prepare", "change_gateway")
            if identity.module_name == _BODY_PREPARER
            else ("prepare",)
        )
        or selection.module_name != identity.module_name
        or identity.module_name
        not in (*_PASSWORD_PREPARERS, _SECURITY_AIRBAG, _BODY_PREPARER)
        or not isinstance(attachments, Mapping)
        or set(attachments)
        - (
            {"ecu_auth_key", "service_auth_key"}
            if identity.module_name == _SECURITY_AIRBAG
            else set()
        )
        or not isinstance(observations, Mapping)
        or observations
    ):
        raise ValueError(
            "Selected actual2026 preparation without manual overrides required"
        )
    selection.validate_against(
        container,
        operation=selection.operation,
        node=node,
        cpu_index=selection.metadata.cpu_index,
    )
    producer = communication_addresses_from_parameter(container, selection.parameter)
    success, addresses = producer.resolve(
        selection.selector_functions,
        cids=observed_cids,
        location_id=selection.metadata.cpu.values.get("locationid") or None,
    )
    if not success or not addresses:
        raise ValueError("Native preparation address selector did not resolve")
    first = native2026_metadata(container, node=node, cpu_index=0)
    if identity.module_name == _SECURITY_AIRBAG:
        passwords = []
        for native, field_name in (
            (first.global_ecu_auth_key_bytes, "ecu_auth_key"),
            (first.global_service_auth_key_bytes, "service_auth_key"),
        ):
            attached = attachments.get(field_name)
            if attached is not None and (
                type(attached) is not bytes or len(attached) != 16 or attached != native
            ):
                raise ValueError(
                    "Security attachment must match projected native global key"
                )
            passwords.append(native)
        bus = 2
    elif identity.module_name in _PASSWORD_PREPARERS:
        texts = selection.lines("SecurityAccessPassword")
        if len(texts) < 2 or any(
            len(v) != 4 or any(c not in "0123456789abcdefABCDEF" for c in v)
            for v in texts[:2]
        ):
            raise ValueError(
                "Native two-entry two-byte SecurityAccessPassword required"
            )
        passwords = [bytes.fromhex(value) for value in texts[:2]]
        archive = native2026_archive(first)
        if archive.data is None:
            raise ValueError(
                "Native CPU0 contiguous archive required for bus selection"
            )
        bus = cpu_bus_type(
            archive.data, selection.value("CANCommunicationSpeedAddress")
        )
    else:
        passwords = [b"", b""]
        if selection.parameter.boolean("ExternalMemoryFlag"):
            bus = 0
        else:
            archive = native2026_archive(first)
            if archive.data is None:
                raise ValueError(
                    "Native CPU0 archive required for gateway bus selection"
                )
            bus = cpu_bus_type(
                archive.data, selection.value("CANCommunicationSpeedAddress")
            )
    parameter = selection.parameter
    return BodyPrepareContext2026(
        identity,
        selection,
        addresses,
        bus,
        passwords[0],
        passwords[1],
        _unsigned(parameter.long("WaitTimeAfterSeedData") or 0, "Seed wait"),
        _unsigned(parameter.long("WaitTimeAfterSeedKey") or 0, "Key wait"),
        _unsigned(parameter.long("WaitTimeAfterDiagnosticMask") or 0, "Mask wait"),
        parameter.boolean("IGOffRetriableFlag") or False,
        len(first.cpus) if identity.module_name == _SECURITY_AIRBAG else 1,
        parameter.boolean("ExternalMemoryFlag") or False,
    )


@dataclass(frozen=True)
class BodyPrepareResult2026:
    returned: bool
    prepared: bool
    result_status_update: int | None = None
    native_error_code: int | None = None
    driver_error_code: int | None = None
    gateway_mode_changed: bool | None = None

    def report(self):
        return {
            "state": (
                "gateway_skipped"
                if self.gateway_mode_changed is False and self.returned
                else "prepare_completed"
                if self.prepared
                else "prepare_failed"
            ),
            **asdict(self),
            "native_return": self.returned,
            "native_success": None,
            "programming_completed": False,
        }


def prepare_body(
    context: BodyPrepareContext2026,
    runtime: NativeRuntime2026,
    *,
    retry_notification: bool | NotificationBool = False,
    secret_info: SecretInfoClient | None = None,
    gateway_only: bool = False,
) -> dict:
    """Airbag/Sonar1310→1000/153f/1593/1576; native retry only in Airbag1630."""
    if (
        not isinstance(context, BodyPrepareContext2026)
        or not isinstance(runtime, NativeRuntime2026)
        or not (
            type(retry_notification) is bool
            or isinstance(retry_notification, NotificationBool)
        )
        or type(gateway_only) is not bool
        or (gateway_only and context.identity.module_name != _BODY_PREPARER)
    ):
        raise TypeError("Typed body context/runtime and native retry Boolean required")
    if context.binding.operation == "change_gateway" and not gateway_only:
        raise ValueError(
            "Native change_gateway context requires gateway-only execution"
        )
    diag = CanDiag2026(runtime)
    security = context.identity.module_name == _SECURITY_AIRBAG
    body = context.identity.module_name == _BODY_PREPARER
    if gateway_only and (context.external_memory or context.bus != 1):
        runtime.check()
        return BodyPrepareResult2026(True, False, gateway_mode_changed=False).report()
    if security and not isinstance(secret_info, SecretInfoClient):
        raise TypeError("Typed authorized native SecretInfo client required")
    request, response = context.addresses[0].headers()
    identifier = None
    bs_owned = False
    body_inner = False
    failure = None
    state = BodyPrepareResult2026(True, True)
    try:
        if (body and context.addresses[0].extended) or (not body and context.bus == 1):
            runtime.call_owned(
                "control_io",
                "control_io",
                release_values={"ioctl": 2, "parameters": ((0x1E, 0),)},
                ioctl=2,
                parameters=((0x1E, 1),),
            )
            bs_owned = True
        body_inner = body
        identifier = diag.start_filter(request, response)
        for index in range(context.cpu_count):
            seed = diag.call(
                request,
                response,
                b"\x27\x61" if body else b"\x27\x03" + context.password,
                b"\x67\x61" if body else b"\x67\x03",
                minimum=8 if body else 19 if security else 5,
                error_code=16,
            )
            if not body and seed[18 if security else 4] != 0x34:
                raise CommonResponseError(16, seed)
            if security:
                assert secret_info is not None
                key = security_up_key(
                    runtime, secret_info, seed[2:18], context.key_material
                )
            elif body:
                key = seed_key_six_byte(seed[2:8])
            else:
                key = seed_key_two_byte(seed[2:4], context.key_material)
            runtime.call("wait", milliseconds=context.seed_wait_ms)
            try:
                diag.call(
                    request,
                    response,
                    (b"\x27\x62" if body else b"\x27\x04") + key,
                    b"\x67\x62\x34" if body else b"\x67\x04\x34",
                    minimum=3,
                    error_code=17,
                )
            except CommonResponseError as error:
                if security and error.response == b"\x7f\x27\x35":
                    raise CommonResponseError(1002, error.response) from error
                raise
            runtime.call("wait", milliseconds=context.key_wait_ms)
            if index == 0 and not gateway_only:
                diagnostic_mask(runtime, context.mask_wait_ms)
            diag.call(
                request,
                response,
                b"\x10\x60" if gateway_only else b"\x10\x02",
                b"\x50",
                minimum=1,
                error_code=49 if gateway_only else 18,
            )
    except NativePassThruError2026 as error:
        state = BodyPrepareResult2026(
            False, False, 1, error.native_error_code, error.passthru_status
        )
    except (NativeJ2534Exception2026, NativeTransportError) as error:
        native = error.error if isinstance(error, NativeJ2534Exception2026) else 1
        driver = (
            error.j2534_error
            if isinstance(error, NativeJ2534Exception2026)
            else error.code
        )
        state = BodyPrepareResult2026(False, False, 1, native, driver)
    except (NativePassThruException2026, CommonResponseError) as error:
        code = (
            error.error
            if isinstance(error, NativePassThruException2026)
            else error.code
        )
        state = BodyPrepareResult2026(False, False, 1, code)
    except (Exception, KeyboardInterrupt) as error:  # noqa: BLE001 - preserve host failures; source-native Body state5 ALL only
        if body_inner and is_native_exception2026(error):
            state = BodyPrepareResult2026(False, False, 1, 9999)
        else:
            failure = error
    cleanup_errors = []
    if bs_owned:
        try:
            runtime.release("control_io", ioctl=2, parameters=((0x1E, 0),))
        except (Exception, KeyboardInterrupt) as error:  # noqa: BLE001 - attempt every native release
            cleanup_errors.append(error)
    if identifier is not None:
        try:
            runtime.release("stop_filter", identifier=identifier)
        except (Exception, KeyboardInterrupt) as error:  # noqa: BLE001 - attempt every native release
            cleanup_errors.append(error)
    if failure is not None:
        for error in cleanup_errors:
            failure.add_note("Native body cleanup failure: " + type(error).__name__)
        raise failure
    native_cleanup_suppressed = bool(cleanup_errors) and (
        context.identity.module_name
        in (*_PASSWORD_PREPARERS, _SECURITY_AIRBAG, _BODY_PREPARER)
        and all(is_native_exception2026(error) for error in cleanup_errors)
    )
    if cleanup_errors and not native_cleanup_suppressed:
        host_error = next(
            (error for error in cleanup_errors if not is_native_exception2026(error)),
            None,
        )
        if host_error is not None:
            raise host_error
        raise OSError("Native body cleanup did not complete") from cleanup_errors[0]
    runtime.check()
    if (
        not state.returned
        and (
            body
            or (
                context.identity.module_name
                in (_PASSWORD_PREPARERS[0], _SECURITY_AIRBAG)
                and context.ig_off_retriable
            )
        )
        and not gateway_only
        and retry_notification
    ):
        state = BodyPrepareResult2026(
            True,
            False,
            state.result_status_update,
            state.native_error_code,
            state.driver_error_code,
        )
    if gateway_only:
        state = BodyPrepareResult2026(
            state.returned,
            state.prepared,
            state.result_status_update,
            state.native_error_code,
            state.driver_error_code,
            True,
        )
    report = state.report()
    if native_cleanup_suppressed:
        report.update(
            host_result="cleanup_failed",
            cleanup_errors=tuple(type(error).__name__ for error in cleanup_errors),
        )
    return report


def is_finish_reprogramming(
    identity: NativeModuleIdentity, runtime: NativeRuntime2026, groups: tuple
) -> bool:
    """Airbag1a90/SecurityAirbag1ca0/DSS1b00 delegate exact CommonFlash probe."""
    _source(identity)
    if identity.module_name not in _FINISH_WRAPPERS or not isinstance(
        runtime, NativeRuntime2026
    ):
        raise ValueError("Exact retained2026 finish-probe wrapper required")
    finished = CommonFlash2026(runtime).is_finish_reprogramming(groups)
    runtime.check()
    return finished


def run_native_context(context, runtime: NativeRuntime2026, **options):
    if isinstance(context, BodyWriteContext2026):
        runners = {
            _SONAR_WRITER: run_sonar_write,
            _AIRBAG_WRITER: run_airbag_write,
            _SECURITY_AIRBAG_WRITER: run_security_airbag_write,
            _DSS_WRITER: run_dss_write,
            **dict.fromkeys(_SHRINK_WRITERS, run_shrink_write),
            **dict.fromkeys(_BODY_WRITERS, run_body_write),
        }
        return runners[context.identity.module_name](context, runtime, **options)
    if isinstance(context, PowerTrainPrepareContext2026):
        return prepare_powertrain(context, runtime, **options)
    if isinstance(context, CentralGatewayContext2026):
        return prepare_central_gateway(context, runtime, **options)
    if isinstance(context, ChassisPrepareContext2026):
        return prepare_chassis(context, runtime, **options)
    if (
        isinstance(context, BodyPrepareContext2026)
        and context.binding.operation == "change_gateway"
    ):
        if options.get("gateway_only", True) is not True:
            raise ValueError("Native change_gateway selection requires gateway mode")
        options["gateway_only"] = True
    return prepare_body(context, runtime, **options)


@dataclass(frozen=True)
class CentralGatewayContext2026:
    identity: NativeModuleIdentity
    binding: NativeParameterBinding2026 = field(repr=False)
    wait_after_reprogramming_ms: int

    def __post_init__(self):
        _source(self.identity)
        if (
            self.identity.module_name != _CENTRAL_GATEWAY
            or not isinstance(self.binding, NativeParameterBinding2026)
            or self.binding.operation != "prepare"
            or self.binding.module_name != _CENTRAL_GATEWAY
        ):
            raise ValueError("Source-bound native CentralGW preparation required")
        _unsigned(self.wait_after_reprogramming_ms, "Gateway wait")


def prepare_central_gateway(
    context: CentralGatewayContext2026,
    runtime: NativeRuntime2026,
    *,
    engine,
    retry_notification: bool | NotificationBool = False,
):
    """CentralGW1000→actual CUW callback15(58560/5b350/1b0f0), never a UI Boolean."""
    from scripts.cuw_2026 import CUWEngine2026

    if (
        not isinstance(context, CentralGatewayContext2026)
        or not isinstance(runtime, NativeRuntime2026)
        or type(engine) is not CUWEngine2026
        or not (
            type(retry_notification) is bool
            or isinstance(retry_notification, NotificationBool)
        )
    ):
        raise TypeError(
            "Bound CentralGW context/runtime and concrete native CUW engine required"
        )
    metadata = context.binding.metadata
    if engine.metadata_for(metadata.node, metadata.cpu_index) != metadata:
        raise ValueError(
            "CentralGW callback engine differs from selected native calibration"
        )
    runtime.check()
    prepared = engine.gateway_callback(runtime)
    if prepared:
        runtime.call("wait", milliseconds=context.wait_after_reprogramming_ms)
    runtime.check()
    state = BodyPrepareResult2026(
        prepared or bool(retry_notification), prepared, None if prepared else 1
    )
    return {
        **state.report(),
        "gateway_callback_error_state": {
            "error_kind": engine.dh_state.error_kind,
            "primary_error": engine.dh_state.primary_error,
            "passthru_error": engine.dh_state.passthru_error,
        },
    }


@dataclass(frozen=True)
class ChassisPrepareContext2026:
    identity: NativeModuleIdentity
    binding: NativeParameterBinding2026 = field(repr=False)
    addresses: tuple[NativeCommunicationAddress, ...]
    selectors: tuple[int, ...]
    keys: tuple[bytes, ...] = field(repr=False)
    ecu_auth_key: bytes = field(repr=False)
    service_auth_key: bytes = field(repr=False)

    def __post_init__(self):
        _source(self.identity)
        security = self.identity.module_name == _CHASSIS[1]
        if (
            self.identity.module_name not in _CHASSIS
            or not isinstance(self.binding, NativeParameterBinding2026)
            or self.binding.operation != "prepare"
            or self.binding.module_name != self.identity.module_name
            or type(self.addresses) is not tuple
            or not 1 <= len(self.addresses) <= 2
            or any(
                not isinstance(a, NativeCommunicationAddress) for a in self.addresses
            )
            or type(self.selectors) is not tuple
            or len(self.selectors) != len(self.addresses)
            or any(type(v) is not int or not 0 <= v <= 2 for v in self.selectors)
            or type(self.keys) is not tuple
            or len(self.keys) != (0 if security else 4)
            or any(type(v) is not bytes or len(v) != 2 for v in self.keys)
            or any(
                type(v) is not bytes or len(v) != (16 if security else 0)
                for v in (self.ecu_auth_key, self.service_auth_key)
            )
        ):
            raise ValueError("Bound native chassis preparation context required")


def bind_chassis_context(
    container, node, observed_cids, selection, identity, attachments, observations
):
    _source(identity)
    if (
        identity.module_name not in _CHASSIS
        or not isinstance(selection, NativeParameterBinding2026)
        or selection.operation != "prepare"
        or selection.module_name != identity.module_name
        or not isinstance(attachments, Mapping)
        or attachments
        or not isinstance(observations, Mapping)
        or observations
    ):
        raise ValueError(
            "Selected actual2026 chassis preparation without overrides required"
        )
    selection.validate_against(
        container,
        operation="prepare",
        node=node,
        cpu_index=selection.metadata.cpu_index,
    )
    producer = communication_addresses_from_parameter(container, selection.parameter)
    success, addresses = producer.resolve(
        selection.selector_functions,
        cids=observed_cids,
        location_id=selection.metadata.cpu.values.get("locationid") or None,
    )
    if not success or not 1 <= len(addresses) <= 2:
        raise ValueError(
            "Native chassis preparation requires one/two selected addresses"
        )
    selectors = (
        (1, 0)
        if len(addresses) == 2 and selection.metadata.vehicle.get("kindofecu") == "13"
        else (0, 2)
    )
    security = identity.module_name == _CHASSIS[1]
    keys = ()
    if not security:
        values = selection.lines("SecurityKey")
        if len(values) < 4 or any(
            len(v) != 4 or any(c not in "0123456789abcdefABCDEF" for c in v)
            for v in values[:4]
        ):
            raise ValueError(
                "Native chassis four two-byte SecurityKey entries required"
            )
        keys = tuple(bytes.fromhex(v) for v in values[:4])
    return ChassisPrepareContext2026(
        identity,
        selection,
        addresses,
        selectors[: len(addresses)],
        keys,
        selection.metadata.global_ecu_auth_key_bytes if security else b"",
        selection.metadata.global_service_auth_key_bytes if security else b"",
    )


def prepare_chassis(
    context: ChassisPrepareContext2026,
    runtime: NativeRuntime2026,
    *,
    secret_info: SecretInfoClient | None = None,
    completion_notification: NotificationBool | None = None,
):
    """Chassis/SecurityChassis10e0: repeat first address, per-iteration mask, no BS."""
    if not isinstance(context, ChassisPrepareContext2026) or not isinstance(
        runtime, NativeRuntime2026
    ):
        raise TypeError("Typed chassis preparation context/runtime required")
    security = context.identity.module_name == _CHASSIS[1]
    if security and not isinstance(secret_info, SecretInfoClient):
        raise TypeError("Typed authorized native SecretInfo client required")
    if completion_notification is not None and not isinstance(
        completion_notification, NotificationBool
    ):
        raise TypeError("Typed native completion notification required")
    runtime.check()
    if completion_notification is not None:
        completion_notification.assign(False)
    diag = CanDiag2026(runtime)
    request, response = context.addresses[0].headers()
    identifier, failure = None, None
    state = BodyPrepareResult2026(True, True)
    parameter = context.binding.parameter
    seed_wait = _unsigned(parameter.long("WaitTimeAfterSeedData") or 0, "Seed wait")
    key_wait = _unsigned(parameter.long("WaitTimeAfterSeedKey") or 0, "Key wait")
    mask_wait = _unsigned(
        parameter.long("WaitTimeAfterDiagnosticMask") or 0, "Mask wait"
    )
    try:
        identifier = diag.start_filter(request, response)
        for selector in context.selectors:
            seed = diag.call(
                request,
                response,
                b"\x27\x01" + bytes((selector,)) + context.ecu_auth_key,
                b"\x67\x01",
                minimum=18 if security else 6,
                error_code=16,
            )
            if security:
                assert secret_info is not None
                key = security_up_key(
                    runtime, secret_info, seed[2:18], context.service_auth_key
                )
            else:
                key = seed_key_four_round(seed[2:6], context.keys)
            runtime.call("wait", milliseconds=seed_wait)
            diag.call(
                request,
                response,
                b"\x27\x02" + key,
                b"\x67\x02",
                minimum=2,
                error_code=17,
            )
            runtime.call("wait", milliseconds=key_wait)
            diagnostic_mask(runtime, mask_wait)
            diag.call(request, response, b"\x10\x02", b"\x50", minimum=1, error_code=18)
    except NativePassThruError2026 as error:
        state = BodyPrepareResult2026(
            False, False, 1, error.native_error_code, error.passthru_status
        )
    except NativeJ2534Exception2026 as error:
        state = BodyPrepareResult2026(False, False, 1, error.error, error.j2534_error)
    except NativeTransportError as error:
        state = BodyPrepareResult2026(False, False, 1, 1, error.code)
    except (CommonResponseError, NativePassThruException2026) as error:
        state = BodyPrepareResult2026(
            False,
            False,
            1,
            error.code if isinstance(error, CommonResponseError) else error.error,
        )
    except (Exception, KeyboardInterrupt) as error:  # noqa: BLE001 - preserve host fault through native cleanup
        failure = error
    cleanup_error = None
    if identifier is not None:
        try:
            runtime.release("stop_filter", identifier=identifier)
        except (Exception, KeyboardInterrupt) as error:
            cleanup_error = error
            if failure is not None:
                failure.add_note(
                    "Native chassis cleanup failure: " + type(error).__name__
                )
            elif not is_native_exception2026(error):
                raise
    if failure is not None:
        raise failure
    runtime.check()
    report = {**state.report(), "completion_flag_update": False}
    if cleanup_error is not None:
        report.update(
            host_result="cleanup_failed", cleanup_errors=(type(cleanup_error).__name__,)
        )
    return report


@dataclass(frozen=True)
class PowerTrainPrepareContext2026:
    identity: NativeModuleIdentity
    binding: NativeParameterBinding2026 = field(repr=False)
    addresses: tuple[NativeCommunicationAddress, ...]
    keys: tuple[bytes, ...] = field(repr=False)
    native_retry_flag_964: bool = False

    def __post_init__(self):
        _source(self.identity)
        if (
            self.identity.module_name != _P4_POWERTRAIN
            or not isinstance(self.binding, NativeParameterBinding2026)
            or self.binding.operation != "prepare"
            or self.binding.module_name != _P4_POWERTRAIN
            or type(self.addresses) is not tuple
            or len(self.addresses) > 4
            or any(
                not isinstance(v, NativeCommunicationAddress) for v in self.addresses
            )
            or type(self.keys) is not tuple
            or len(self.keys) != 4
            or any(type(v) is not bytes or len(v) != 2 for v in self.keys)
            or type(self.native_retry_flag_964) is not bool
        ):
            raise ValueError("Exact native P4 PowerTrain preparation context required")


def bind_powertrain_context(
    container, node, observed_cids, selection, identity, attachments, observations
):
    _source(identity)
    if (
        identity.module_name != _P4_POWERTRAIN
        or not isinstance(selection, NativeParameterBinding2026)
        or selection.operation != "prepare"
        or selection.module_name != _P4_POWERTRAIN
        or not isinstance(attachments, Mapping)
        or attachments
        or not isinstance(observations, Mapping)
        or set(observations) - {"native_retry_flag_964"}
    ):
        raise ValueError(
            "Selected native P4 PowerTrain preparation without geometry overrides required"
        )
    selection.validate_against(
        container,
        operation="prepare",
        node=node,
        cpu_index=selection.metadata.cpu_index,
    )
    producer = communication_addresses_from_parameter(container, selection.parameter)
    success, addresses = producer.resolve(
        selection.selector_functions,
        cids=observed_cids,
        location_id=selection.metadata.cpu.values.get("locationid") or None,
    )
    if not success or len(addresses) > 4:
        raise ValueError("Native P4 PowerTrain address selection did not resolve")
    values = selection.lines("SecurityKey")
    if len(values) < 4 or any(
        len(v) != 4 or any(c not in "0123456789abcdefABCDEF" for c in v)
        for v in values[:4]
    ):
        raise ValueError(
            "Native P4 PowerTrain four two-byte SecurityKey entries required"
        )
    return PowerTrainPrepareContext2026(
        identity,
        selection,
        addresses,
        tuple(bytes.fromhex(v) for v in values[:4]),
        observations.get("native_retry_flag_964", False),
    )


def prepare_powertrain(
    context: PowerTrainPrepareContext2026,
    runtime: NativeRuntime2026,
    *,
    retry_notification: bool | NotificationBool = False,
):
    """P4PowerTrain1290/1825/1cb0, including typed unavailable targets and TVD/PG2."""
    if (
        not isinstance(context, PowerTrainPrepareContext2026)
        or not isinstance(runtime, NativeRuntime2026)
        or not (
            type(retry_notification) is bool
            or isinstance(retry_notification, NotificationBool)
        )
    ):
        raise TypeError(
            "Typed native P4 PowerTrain context/runtime and retry Boolean required"
        )
    parameter = context.binding.parameter

    def wait_value(name):
        return _unsigned(parameter.long(name) or 0, name)

    seed_wait, key_wait, normal_wait, mask_wait = (
        wait_value(name)
        for name in (
            "WaitTimeAfterSeedData",
            "WaitTimeAfterSeedKey",
            "WaitTimeAfterNormalMode",
            "WaitTimeAfterDiagnosticMask",
        )
    )
    kind = context.binding.metadata.vehicle.get("kindofecu", "")
    special_tvd = kind == "51" and context.binding.cpu_type == "11"
    double_mode = kind == "3" or special_tvd
    mode = b"\x10\x60" if special_tvd else b"\x10\x02"
    addresses = tuple(address.headers() for address in context.addresses)
    diag, filters, prepared, skipped = CanDiag2026(runtime), [], [], []
    state, failure = BodyPrepareResult2026(True, True), None
    try:
        for request, response in addresses:
            filters.append(diag.start_filter(request, response))
        for index, (request, response) in enumerate(addresses):
            try:
                try:
                    seed = diag.call(
                        request,
                        response,
                        b"\x27\x01",
                        b"\x67\x01",
                        minimum=6,
                        error_code=16,
                    )
                except NativePassThruError2026 as error:
                    if error.passthru_status in (9, 16):
                        raise CommonResponseError(22) from error
                    raise
                except NativeJ2534Exception2026 as error:
                    if error.j2534_error in (9, 16):
                        raise CommonResponseError(22) from error
                    raise
                except NativeTransportError as error:
                    if error.code in (9, 16):
                        raise CommonResponseError(22) from error
                    raise
                except CommonResponseError as error:
                    if len(error.response) == 3 and error.response[:2] == b"\x7f\x27":
                        raise CommonResponseError(23, error.response) from error
                    raise
                key = seed_key_four_round(seed[2:6], context.keys)
                runtime.call("wait", milliseconds=seed_wait)
                diag.call(
                    request,
                    response,
                    b"\x27\x02" + key,
                    b"\x67\x02",
                    minimum=2,
                    error_code=17,
                )
                prepared.append(index)
            except CommonResponseError as error:
                if error.code not in (22, 23):
                    raise
                skipped.append((index, error.code))
            except NativePassThruError2026 as error:
                if error.native_error_code not in (22, 23):
                    raise
                skipped.append((index, error.native_error_code))
            except NativePassThruException2026 as error:
                if error.error not in (22, 23):
                    raise
                skipped.append((index, error.error))
            except Exception as error:
                if not is_native_exception2026(error):
                    raise
                raise CommonResponseError(9999) from error
            runtime.call("wait", milliseconds=key_wait)
        if not prepared and not context.native_retry_flag_964:
            raise CommonResponseError(17)
        if prepared:
            diagnostic_mask(runtime, mask_wait)
            for index in prepared:
                request, response = addresses[index]
                diag.call(
                    request,
                    response,
                    mode,
                    b"\x50",
                    minimum=1,
                    error_code=49 if special_tvd else 18,
                )
                if double_mode:
                    runtime.call("wait", milliseconds=normal_wait)
                    diag.call(
                        request,
                        response,
                        mode,
                        b"\x50",
                        minimum=1,
                        error_code=49 if special_tvd else 18,
                    )
        state = BodyPrepareResult2026(True, bool(prepared))
    except NativePassThruError2026 as error:
        state = BodyPrepareResult2026(
            False, False, 1, error.native_error_code, error.passthru_status
        )
    except NativeJ2534Exception2026 as error:
        state = BodyPrepareResult2026(False, False, 1, error.error, error.j2534_error)
    except NativeTransportError as error:
        state = BodyPrepareResult2026(False, False, 1, 1, error.code)
    except (CommonResponseError, NativePassThruException2026) as error:
        state = BodyPrepareResult2026(
            False,
            False,
            1,
            error.code if isinstance(error, CommonResponseError) else error.error,
        )
    except (Exception, KeyboardInterrupt) as error:  # noqa: BLE001 - release every filter before propagating host fault
        failure = error
    cleanup_errors = []
    for identifier in filters:
        try:
            runtime.release("stop_filter", identifier=identifier)
        except (Exception, KeyboardInterrupt) as error:  # noqa: BLE001 - attempt every owned release in native order
            cleanup_errors.append(error)
            if is_native_exception2026(error):
                # State15 CatchAll1b7b exits the native filter loop immediately.
                break
    if failure is not None:
        for error in cleanup_errors:
            failure.add_note(
                "Native P4 PowerTrain cleanup failure: " + type(error).__name__
            )
        raise failure
    if cleanup_errors:
        host_error = next(
            (error for error in cleanup_errors if not is_native_exception2026(error)),
            None,
        )
        if host_error is not None:
            raise host_error
    runtime.check()
    if (
        not state.returned
        and (parameter.boolean("IGOffRetriableFlag") or False)
        and retry_notification
    ):
        state = BodyPrepareResult2026(
            True,
            False,
            state.result_status_update,
            state.native_error_code,
            state.driver_error_code,
        )
    return {
        **state.report(),
        **(
            {
                "host_result": "cleanup_failed",
                "cleanup_errors": tuple(
                    type(error).__name__ for error in cleanup_errors
                ),
            }
            if cleanup_errors
            else {}
        ),
        "prepared_targets": tuple(prepared),
        "skipped_targets": tuple(skipped),
        "native_retry_skip": state.returned
        and not prepared
        and context.native_retry_flag_964,
    }


_SONAR_WRITER = "TCUWP4CanClearanceSonarFlashWriter.dll"
_AIRBAG_WRITER = "TCUWP4CanAirbagFlashWriter.dll"
_DSS_WRITER = "TCUWP4CanDSS1FlashWriter.dll"
_SECURITY_AIRBAG_WRITER = "TCUWP4CanSecurityAirbagFlashWriter.dll"
_BODY_WRITERS = (
    "TCUWP4CanBodyFlashWriter.dll",
    "TCUWP4CanBodyFlashWriterForCXPI.dll",
    "TCUWP5CanBodyFlashWriter.dll",
)
_SHRINK_WRITERS = (
    "TCUWP4CanChassisShrinkFlashWriter.dll",
    "TCUWP4CanSecurityChassisShrinkFlashWriter.dll",
)

_WRITER_MODULES = (
    _SONAR_WRITER,
    _AIRBAG_WRITER,
    _SECURITY_AIRBAG_WRITER,
    _DSS_WRITER,
    *_SHRINK_WRITERS,
    *_BODY_WRITERS,
)


@dataclass(frozen=True)
class BodyWriteContext2026:
    identity: NativeModuleIdentity
    binding: NativeParameterBinding2026 = field(repr=False)
    address: NativeCommunicationAddress
    finish_address: NativeCommunicationAddress
    image: bytes = field(repr=False)
    flash_size: int
    location_id: bytes
    password: int = field(repr=False)
    retry_password: bool = False
    initial_command_retry: bool = False
    address_groups: tuple[tuple[NativeCommunicationAddress, ...], ...] = ()
    target_index: int = 0

    def __post_init__(self):
        _source(self.identity)
        if (
            self.identity.module_name
            not in (
                _SONAR_WRITER,
                _AIRBAG_WRITER,
                _DSS_WRITER,
                _SECURITY_AIRBAG_WRITER,
                *_SHRINK_WRITERS,
                *_BODY_WRITERS,
            )
            or not isinstance(self.binding, NativeParameterBinding2026)
            or self.binding.operation != "write"
            or self.binding.module_name != self.identity.module_name
            or any(
                not isinstance(value, NativeCommunicationAddress)
                for value in (self.address, self.finish_address)
            )
            or type(self.image) is not bytes
            or not 0 < len(self.image) <= 64 * 1024 * 1024
            or type(self.flash_size) is not int
            or not 0 < self.flash_size <= len(self.image)
            or type(self.location_id) is not bytes
            or len(self.location_id) != 8
            or type(self.password) is not int
            or not 0 <= self.password <= 0xFFFFFFFF
            or type(self.retry_password) is not bool
            or type(self.initial_command_retry) is not bool
        ):
            raise ValueError("Source-bound native retained writer context required")


def _bind_body_write_context(
    container, node, observed_cids, selection, identity, attachments, observations
):
    from scripts.calibration_2026 import (
        native2026_archive_password,
        native2026_cpu_targets,
        native2026_global_cpu_index,
        native2026_new_password,
    )
    from scripts.programming_2026_vendor import native2026_write_address_groups

    _source(identity)
    if (
        identity.module_name
        not in (
            _SONAR_WRITER,
            _AIRBAG_WRITER,
            _DSS_WRITER,
            _SECURITY_AIRBAG_WRITER,
            *_SHRINK_WRITERS,
            *_BODY_WRITERS,
        )
        or not isinstance(selection, NativeParameterBinding2026)
        or selection.operation != "write"
        or selection.module_name != identity.module_name
        or not isinstance(attachments, Mapping)
        or attachments
        or not isinstance(observations, Mapping)
        or set(observations)
        - {"target_index", "retry_password", "native_initial_command_retry_980"}
    ):
        raise ValueError("Selected native retained writer inputs required")
    selection.validate_against(
        container, operation="write", node=node, cpu_index=selection.metadata.cpu_index
    )
    metadata = selection.metadata
    groups = native2026_write_address_groups(container, selection)
    current_addresses = groups[native2026_global_cpu_index(metadata)]
    first_addresses = groups[
        native2026_global_cpu_index(metadata)
        if identity.module_name in _BODY_WRITERS
        else 0
    ]
    if not current_addresses or len(first_addresses) < 2:
        raise ValueError(
            "Native current programming and source-selected finish address pair required"
        )
    archive = native2026_archive(metadata)
    targets = native2026_cpu_targets(metadata)
    target = observations.get("target_index", 0)
    if type(target) is not int or not 0 <= target < len(targets):
        raise ValueError("Native selected target password absent")
    retry = observations.get("retry_password", False)
    values = {key: selection.value(key) for key in selection.values}
    password = (
        (
            native2026_new_password(metadata, values)
            if identity.module_name
            in (_SHRINK_WRITERS[1], _SECURITY_AIRBAG_WRITER, *_BODY_WRITERS)
            else native2026_archive_password(archive, values)
        )
        if retry
        and not (
            identity.module_name in _BODY_WRITERS
            and (selection.parameter.boolean("ExternalMemoryFlag") or False)
        )
        else targets[target].password
    )
    if archive.data is None:
        raise ValueError("Materialized native writer archive absent")
    return BodyWriteContext2026(
        identity,
        selection,
        current_addresses[0],
        first_addresses[1],
        archive.data,
        archive.flash_size,
        bytes.fromhex(metadata.cpu.values.get("locationid", "")),
        password,
        retry,
        observations.get("native_initial_command_retry_980", False),
        groups,
        target,
    )


def _validate_body_write_data(context):
    from scripts.calibration_2026 import (
        native2026_archive_password,
        native2026_cpu_targets,
        native2026_new_password,
    )

    metadata = context.binding.metadata
    archive = native2026_archive(metadata)
    targets = native2026_cpu_targets(metadata)
    if type(context.target_index) is not int or not 0 <= context.target_index < len(
        targets
    ):
        raise ValueError("Selected native target password index absent")
    values = {key: context.binding.value(key) for key in context.binding.values}
    password = targets[context.target_index].password
    if context.retry_password and not (
        context.identity.module_name in _BODY_WRITERS
        and (context.binding.parameter.boolean("ExternalMemoryFlag") or False)
    ):
        password = (
            native2026_new_password(metadata, values)
            if context.identity.module_name
            in (_SHRINK_WRITERS[1], _SECURITY_AIRBAG_WRITER, *_BODY_WRITERS)
            else native2026_archive_password(archive, values)
        )
    if (
        context.image != archive.data
        or context.flash_size != archive.flash_size
        or context.location_id
        != bytes.fromhex(metadata.cpu.values.get("locationid", ""))
        or context.password != password
    ):
        raise ValueError("Writer context differs from selected calibration data")


def bind_sonar_write_context(*args, **kwargs):
    context = _bind_body_write_context(*args, **kwargs)
    if context.identity.module_name != _SONAR_WRITER:
        raise ValueError("Native Sonar module required")
    return context


def bind_airbag_write_context(*args, **kwargs):
    context = _bind_body_write_context(*args, **kwargs)
    if context.identity.module_name != _AIRBAG_WRITER:
        raise ValueError("Native Airbag module required")
    return context


def bind_shrink_write_context(*args, **kwargs):
    context = _bind_body_write_context(*args, **kwargs)
    if context.identity.module_name not in _SHRINK_WRITERS:
        raise ValueError("Native ChassisShrink writer module required")
    return context


def bind_dss_write_context(*args, **kwargs):
    context = _bind_body_write_context(*args, **kwargs)
    if context.identity.module_name != _DSS_WRITER:
        raise ValueError("Native DSS1 writer module required")
    return context


def bind_security_airbag_write_context(*args, **kwargs):
    context = _bind_body_write_context(*args, **kwargs)
    if context.identity.module_name != _SECURITY_AIRBAG_WRITER:
        raise ValueError("Native SecurityAirbag writer module required")
    return context


def _run_security_airbag_write_algorithm(
    context, runtime, *, engine, notify=lambda *_: None
):
    if context.identity.module_name != _SECURITY_AIRBAG_WRITER:
        raise ValueError("Native SecurityAirbag writer module required")
    return _run_airbag_write_algorithm(context, runtime, engine=engine, notify=notify)


def bind_body_write_context(*args, **kwargs):
    context = _bind_body_write_context(*args, **kwargs)
    if context.identity.module_name not in _BODY_WRITERS:
        raise ValueError("Native Body writer module required")
    return context


def _cxpi_erase_block(context, writer, request, response, first, last, parameter):
    """CXPI1f20 uses an extended prepare-address keepalive during erase."""
    writer.diag.write(
        request
        + b"\x26"
        + (first - 1).to_bytes(2, "big")
        + (last - 1).to_bytes(2, "big")
    )
    if not writer.receive_ack(response):
        raise CommonResponseError(12)
    selector = parameter.string("GetCANIDFunctionNameForPrepareWrite") or ""
    resolver = communication_addresses_from_parameter(
        context.binding.metadata.source_container, parameter
    )
    success, addresses = resolver.resolve((selector,), cids=(), location_id=None)
    if not success or not addresses:
        raise ValueError("Native CXPI prepare address unavailable")
    address = addresses[0].request
    header = bytes(2) + (address + bytes(3))[:3]
    # Native loop condition sleeps once more after the third transmission.
    for index in range(4):
        writer.runtime.call("wait", milliseconds=2000)
        if index < 3:
            writer.diag.write(header + b"\x3e\x02", tx_flags=0x80)
    writer._poll_zero(
        request,
        response,
        parameter.long("WaitTimeBeforeStatusCheckForEraseBlock") or 0,
        12,
    )


def _run_sonar_write_algorithm(
    context: BodyWriteContext2026,
    runtime: NativeRuntime2026,
    *,
    engine,
    retry_notification: NotificationBool | None = None,
    completion_notification: NotificationBool | None = None,
    notify=lambda *_: None,
) -> dict:
    """Sonar1000/16a6/1712; only cleanup StopFilter state8 has CatchAll1745."""
    from scripts.calibration_2026 import (
        native2026_cpu_count,
        native2026_global_cpu_index,
    )
    from scripts.cuw_2026 import CUWEngine2026
    from scripts.programming_2026_common import (
        block_ranges_from_sizes,
        calc_block_sizes,
        check_cpu_type_from_firmware,
        complete_block_info,
        native_block_info,
        select_retry_password,
    )
    from scripts.programming_2026_legacy import writing_error_dispose

    if (
        not isinstance(context, BodyWriteContext2026)
        or context.identity.module_name != _SONAR_WRITER
        or not isinstance(runtime, NativeRuntime2026)
        or type(engine) is not CUWEngine2026
        or engine.metadata_for(
            context.binding.metadata.node, context.binding.metadata.cpu_index
        )
        != context.binding.metadata
        or not callable(notify)
        or retry_notification is not None
        and not isinstance(retry_notification, NotificationBool)
        or completion_notification is not None
        and not isinstance(completion_notification, NotificationBool)
    ):
        raise TypeError(
            "Native Sonar context, concrete engine and notifications required"
        )
    engine.validate_address_groups(context.binding, context.address_groups)
    _validate_body_write_data(context)

    if (
        context.address
        != context.address_groups[
            native2026_global_cpu_index(context.binding.metadata)
        ][0]
        or context.finish_address != context.address_groups[0][1]
    ):
        raise ValueError("Sonar addresses differ from actual engine field748")
    native_retry = engine.notification
    native_completion = engine.last_block_notification
    if retry_notification is not None and retry_notification is not native_retry:
        raise ValueError(
            "Sonar retry notification must be the actual engine/84 field968"
        )
    if (
        completion_notification is not None
        and completion_notification is not native_completion
    ):
        raise ValueError(
            "Sonar completion notification must be the actual engine/84 field96c"
        )
    retry_notification, completion_notification = native_retry, native_completion
    if engine.dh_state.use_new_password != context.retry_password:
        raise ValueError("Sonar password selection differs from actual native field760")
    metadata, parameter = context.binding.metadata, context.binding.parameter
    values = {key: context.binding.value(key) for key in context.binding.values}
    cpu, count = native2026_global_cpu_index(metadata), native2026_cpu_count(metadata)
    counts, percentages = (
        list(engine.dh_state.transferred_bytes),
        list(engine.dh_state.progress),
    )
    if len(counts) < count or len(percentages) < count:
        raise ValueError("Actual engine native CPU progress vectors unavailable")
    writer = CommonFlash2026(runtime)
    request = bytes(2) + context.address.request[:2]
    response = bytes(2) + context.address.response[:2]
    finish, _ = context.finish_address.headers()
    saved_timeout = saved_send_timeout = identifier = None
    completed = flashing_ended = business = False
    retry_password = context.retry_password
    native_context_75c_update = None
    native_error = driver_error = result_status = None
    failure = None
    cleanup_errors = []

    def observe(*event):
        runtime.check()
        if event and event[0] == "count":
            engine.dh_state.set_native_count(cpu, counts[cpu])
        elif event and event[0] == "percent":
            engine.dh_state.set_native_percentage(cpu, percentages[cpu])
        notify(*event)
        runtime.check()

    try:
        engine.dh_state.set_flashing_ended(False)
        observe("flashing_ended", False)
        retry_notification.assign(True)
        saved_timeout = runtime.call("get_timeout")
        runtime.call(
            "set_timeout",
            milliseconds=parameter.long("ReceiveTimeoutBeforeFlashWrite") or 0,
        )
        saved_send_timeout = runtime.call("get_send_timeout")
        runtime.call(
            "set_send_timeout",
            milliseconds=parameter.long("SendTimeoutBeforePrepareWrite") or 0,
        )
        business = (
            True  # Source CBytes constructors establish state2 before StartFilter.
        )
        identifier = writer.diag.start_filter(request, response)
        runtime.call(
            "wait", milliseconds=parameter.long("WaitTimeAfterReprogrammingMode") or 0
        )
        between = parameter.long("WaitTimeBetweenSF") or 0
        writer.check_id_with_wait_of_sfs(
            request,
            response,
            context.location_id,
            context.password,
            between,
            10000
            if context.initial_command_retry
            else parameter.long("ReceiveTimeoutBeforeInitialCommand") or 0,
            parameter.boolean("BigEndianFlag") or False,
        )
        runtime.call("wait", milliseconds=between)
        memory, wide = writer.get_memory_info(request, response, False)
        if not check_cpu_type_from_firmware(memory.firmware_version, values, wide):
            raise CommonResponseError(10)
        sizes = calc_block_sizes(complete_block_info(native_block_info(values), memory))
        ranges = block_ranges_from_sizes(sizes)
        for position, (first, last) in enumerate(ranges):
            if position:
                completion_notification.assign(True)
            writer.erase_block(request, response, first, last, parameter, wide)
            writer.write_block(
                request,
                response,
                cpu,
                first,
                last,
                sizes,
                memory,
                context.image,
                context.flash_size,
                parameter,
                counts,
                percentages,
                observe,
                engine.notify_native_errors,
                between,
                False,
            )
            writer.in_verify_block(request, response, parameter, first, last, wide)
            writer.verify_block(
                request,
                response,
                cpu,
                first,
                last,
                sizes,
                context.image,
                context.flash_size,
                parameter,
                counts,
                percentages,
                observe,
                engine.notify_native_errors,
                wide,
            )
        retry_password = False
        engine.dh_state.set_use_new_password(False)
        observe("retry_password", False)
        flashing_ended = True
        engine.dh_state.set_flashing_ended(True)
        observe("flashing_ended", True)
        writer.finish_reprogramming(finish, response)
        native_context_75c_update = False
        engine.dh_state.set_write_complete(False)
        observe("native_context_75c", False)
        engine.notify_write_complete()
        observe("native_callback7")
        retry_notification.assign(False)
        completed = True
    except (
        NativePassThruError2026,
        NativeJ2534Exception2026,
        NativeTransportError,
        NativePassThruException2026,
        CommonResponseError,
    ) as error:
        if not business:
            failure = error
        else:
            if isinstance(error, NativePassThruError2026):
                native_error, driver_error = (
                    error.native_error_code,
                    error.passthru_status,
                )
            elif isinstance(error, NativeJ2534Exception2026):
                native_error, driver_error = error.error, error.j2534_error
            elif isinstance(error, NativeTransportError):
                native_error, driver_error = (
                    getattr(error, "native_error_code", 1),
                    getattr(error, "passthru_status", error.code),
                )
            else:
                native_error = (
                    error.error
                    if isinstance(error, NativePassThruException2026)
                    else error.code
                )
            engine.dh_state.record_native_error(None, native_error, driver_error)
            try:
                writing_error_dispose(
                    cpu,
                    counts,
                    percentages,
                    lambda field: observe(field, counts[:], percentages[:]),
                )
                result_status = 2
            except (Exception, KeyboardInterrupt) as caught:  # noqa: BLE001 - preserve observer fault through cleanup
                failure = caught
    except (Exception, KeyboardInterrupt) as error:  # noqa: BLE001 - unknown native business exceptions are not caught by source
        failure = error
    if identifier is not None:
        try:
            runtime.release("stop_filter", identifier=identifier)
        except (Exception, KeyboardInterrupt) as error:  # noqa: BLE001 - source-native cleanup ALL; host errors propagate
            cleanup_errors.append(error)
            if not is_native_exception2026(error) and failure is None:
                failure = error
    if result_status is not None and failure is None:
        engine.dh_state.record_native_error(
            result_status, engine.dh_state.primary_error
        )
    for saved, operation in (
        (saved_timeout, "set_timeout"),
        (saved_send_timeout, "set_send_timeout"),
    ):
        if saved is not None:
            try:
                runtime.call(operation, cleanup=True, milliseconds=saved)
            except (Exception, KeyboardInterrupt) as error:  # noqa: BLE001 - restoration is outside native catch scopes
                if failure is None:
                    failure = error
                else:
                    failure.add_note(
                        "Sonar timeout restoration failure: " + type(error).__name__
                    )
    if failure is not None:
        for error in cleanup_errors:
            failure.add_note("Sonar filter cleanup failure: " + type(error).__name__)
        raise failure
    runtime.check()
    primary = engine.dh_state.primary_error
    retry_password = (
        False
        if completed
        else select_retry_password(
            bool(completion_notification), primary, retry_password
        )
    )
    engine.dh_state.set_use_new_password(retry_password)
    return {
        "native_return": completed,
        "native_success": None,
        "state": "write_completed" if completed else "write_failed",
        "programming_completed": completed,
        "flashing_ended": flashing_ended,
        "native_context_970": flashing_ended,
        "counts": tuple(counts),
        "percentages": tuple(percentages),
        "native_error_code": native_error,
        "driver_error_code": driver_error,
        "result_status_update": result_status,
        "retry_password": retry_password,
        "retry_notification": bool(retry_notification),
        "completion_notification": bool(completion_notification),
        "native_context_75c_update": native_context_75c_update,
        **(
            {
                "host_result": "cleanup_failed",
                "cleanup_errors": tuple(
                    type(error).__name__ for error in cleanup_errors
                ),
            }
            if cleanup_errors
            else {}
        ),
    }


def _run_shrink_write_algorithm(
    context: BodyWriteContext2026,
    runtime: NativeRuntime2026,
    *,
    engine,
    retry_notification: NotificationBool | None = None,
    completion_notification: NotificationBool | None = None,
    notify=lambda *_: None,
) -> dict:
    """Chassis1160; security variant adds nonce, seed-key and falsification test."""
    from scripts.calibration_2026 import (
        native2026_cpu_count,
        native2026_global_cpu_index,
    )
    from scripts.cuw_2026 import CUWEngine2026
    from scripts.programming_2026_common import (
        block_ranges_from_info,
        calc_block_sizes,
        check_cpu_type_from_firmware,
        complete_block_info,
        native_block_info,
        select_retry_password,
    )
    from scripts.programming_2026_legacy import writing_error_dispose

    if (
        not isinstance(context, BodyWriteContext2026)
        or context.identity.module_name not in _SHRINK_WRITERS
        or not isinstance(runtime, NativeRuntime2026)
        or type(engine) is not CUWEngine2026
        or engine.metadata_for(
            context.binding.metadata.node, context.binding.metadata.cpu_index
        )
        != context.binding.metadata
        or not callable(notify)
        or retry_notification is not None
        and not isinstance(retry_notification, NotificationBool)
        or completion_notification is not None
        and not isinstance(completion_notification, NotificationBool)
    ):
        raise TypeError(
            "Native ChassisShrink context, concrete engine and notifications required"
        )
    engine.validate_address_groups(context.binding, context.address_groups)
    _validate_body_write_data(context)

    if (
        context.address
        != context.address_groups[
            native2026_global_cpu_index(context.binding.metadata)
        ][0]
        or context.finish_address != context.address_groups[0][1]
    ):
        raise ValueError("ChassisShrink addresses differ from actual engine field748")
    native_retry = engine.notification
    native_completion = engine.last_block_notification
    if retry_notification is not None and retry_notification is not native_retry:
        raise ValueError(
            "ChassisShrink retry notification must be the actual engine/84 field968"
        )
    if (
        completion_notification is not None
        and completion_notification is not native_completion
    ):
        raise ValueError(
            "ChassisShrink completion notification must be the actual engine/84 field96c"
        )
    retry_notification, completion_notification = native_retry, native_completion
    if engine.dh_state.use_new_password != context.retry_password:
        raise ValueError(
            "ChassisShrink password selection differs from actual native field760"
        )
    metadata, parameter = context.binding.metadata, context.binding.parameter
    values = {key: context.binding.value(key) for key in context.binding.values}
    cpu, count = native2026_global_cpu_index(metadata), native2026_cpu_count(metadata)
    counts, percentages = (
        list(engine.dh_state.transferred_bytes),
        list(engine.dh_state.progress),
    )
    if len(counts) < count or len(percentages) < count:
        raise ValueError("Actual engine native CPU progress vectors unavailable")
    security = context.identity.module_name in (
        _SHRINK_WRITERS[1],
        _SECURITY_AIRBAG_WRITER,
    )
    writer = CommonFlash2026(runtime)
    request = bytes(2) + context.address.request[:2]
    response = bytes(2) + context.address.response[:2]
    saved_timeout = identifier = None
    completed = business = False
    flashing_ended = engine.dh_state.flashing_ended
    retry_password = context.retry_password
    native_context_75c_update = None
    native_error = driver_error = result_status = None
    failure = None
    cleanup_errors = []

    def observe(*event):
        runtime.check()
        if event and event[0] == "count":
            engine.dh_state.set_native_count(cpu, counts[cpu])
        elif event and event[0] == "percent":
            engine.dh_state.set_native_percentage(cpu, percentages[cpu])
        notify(*event)
        runtime.check()

    try:
        retry_notification.assign(True)
        saved_timeout = runtime.call("get_timeout")
        runtime.call(
            "set_timeout",
            milliseconds=parameter.long("ReceiveTimeoutBeforeFlashWrite") or 0,
        )
        business = (
            True  # Source CBytes constructors establish state2 before StartFilter.
        )
        identifier = writer.diag.start_filter(request, response)
        runtime.call(
            "wait", milliseconds=parameter.long("WaitTimeAfterReprogrammingMode") or 0
        )
        between = parameter.long("WaitTimeBetweenSF") or 0
        writer.check_id_with_wait_of_sfs(
            request,
            response,
            context.location_id,
            context.password,
            between,
            10000
            if context.initial_command_retry
            else parameter.long("ReceiveTimeoutBeforeInitialCommand") or 0,
            parameter.boolean("BigEndianFlag") or False,
        )
        if security:
            from scripts.calibration_2026 import native2026_cpu_security_bytes

            writer.send_nonce(
                request,
                response,
                native2026_cpu_security_bytes(metadata, "nonce", cpu),
                between,
            )
            writer.send_seed_key(
                request,
                response,
                native2026_cpu_security_bytes(metadata, "seedkey", cpu),
                between,
            )
        runtime.call("wait", milliseconds=between)
        memory, wide = writer.get_memory_info(request, response, False)
        if not check_cpu_type_from_firmware(memory.firmware_version, values, wide):
            raise CommonResponseError(10)
        blocks = complete_block_info(native_block_info(values), memory)
        sizes = calc_block_sizes(blocks)
        ranges = block_ranges_from_info(blocks)
        # Native vector::_Insert_n inserts zero-size slots before the first range.
        if ranges and ranges[0][0] != 1:
            sizes = (0,) * (ranges[0][0] - 1) + sizes
        for position, (first, last) in enumerate(ranges):
            completion_notification.assign(position == len(ranges) - 1)
            writer.erase_block(request, response, first, last, parameter, wide)
            writer.write_block(
                request,
                response,
                cpu,
                first,
                last,
                sizes,
                memory,
                context.image,
                context.flash_size,
                parameter,
                counts,
                percentages,
                observe,
                engine.notify_native_errors,
                between,
                False,
            )
            writer.in_verify_block(request, response, parameter, first, last, wide)
            writer.verify_block(
                request,
                response,
                cpu,
                first,
                last,
                sizes,
                context.image,
                context.flash_size,
                parameter,
                counts,
                percentages,
                observe,
                engine.notify_native_errors,
                wide,
            )
        if security:
            writer.detect_falsify(request, response)
        retry_password = False
        engine.dh_state.set_use_new_password(False)
        observe("retry_password", False)
        if cpu < count - 1:
            deferred = None
            try:
                writer.change_next_cpu(request, response)
            except (Exception, KeyboardInterrupt) as error:
                if not is_native_exception2026(error):
                    raise
                deferred = error
            engine.notify_next_cpu()
            retry_notification.assign(False)
            completion_notification.assign(False)
            if deferred is not None:
                if is_native_exception2026(deferred) and not isinstance(
                    deferred,
                    (
                        NativePassThruError2026,
                        NativeJ2534Exception2026,
                        NativeTransportError,
                        NativePassThruException2026,
                        CommonResponseError,
                    ),
                ):
                    raise CommonResponseError(9999) from deferred
                raise deferred
            runtime.call("wait", milliseconds=0)
        else:
            flashing_ended = True
            engine.dh_state.set_flashing_ended(True)
            # These two modules deliberately ignore address extension at finish.
            try:
                writer.finish_reprogramming(
                    bytes(2) + context.finish_address.request[:2], None
                )
            except (Exception, KeyboardInterrupt) as error:
                if not is_native_exception2026(error):
                    raise
            native_context_75c_update = False
            engine.dh_state.set_write_complete(False)
            engine.notify_write_complete()
            retry_notification.assign(False)
        completed = True
    except (
        NativePassThruError2026,
        NativeJ2534Exception2026,
        NativeTransportError,
        NativePassThruException2026,
        CommonResponseError,
    ) as error:
        if not business:
            failure = error
        else:
            if isinstance(error, NativePassThruError2026):
                native_error, driver_error = (
                    error.native_error_code,
                    error.passthru_status,
                )
            elif isinstance(error, NativeJ2534Exception2026):
                native_error, driver_error = error.error, error.j2534_error
            elif isinstance(error, NativeTransportError):
                native_error, driver_error = (
                    getattr(error, "native_error_code", 1),
                    getattr(error, "passthru_status", error.code),
                )
            else:
                native_error = (
                    error.error
                    if isinstance(error, NativePassThruException2026)
                    else error.code
                )
            engine.dh_state.record_native_error(None, native_error, driver_error)
            try:
                writing_error_dispose(
                    cpu,
                    counts,
                    percentages,
                    lambda field: observe(field, counts[:], percentages[:]),
                )
                result_status = 2
            except (Exception, KeyboardInterrupt) as caught:  # noqa: BLE001 - preserve observer fault through cleanup
                failure = caught
    except (Exception, KeyboardInterrupt) as error:  # noqa: BLE001 - unknown native business exceptions are not caught by source
        failure = error
    if identifier is not None:
        try:
            runtime.release("stop_filter", identifier=identifier)
        except (Exception, KeyboardInterrupt) as error:  # noqa: BLE001 - source-native cleanup ALL; host errors propagate
            cleanup_errors.append(error)
            if not is_native_exception2026(error) and failure is None:
                failure = error
    if result_status is not None and failure is None:
        engine.dh_state.record_native_error(
            result_status, engine.dh_state.primary_error
        )
    for saved, operation in ((saved_timeout, "set_timeout"),):
        if saved is not None:
            try:
                runtime.call(operation, cleanup=True, milliseconds=saved)
            except (Exception, KeyboardInterrupt) as error:  # noqa: BLE001 - restoration is outside native catch scopes
                if failure is None:
                    failure = error
                else:
                    failure.add_note(
                        "ChassisShrink timeout restoration failure: "
                        + type(error).__name__
                    )
    if failure is not None:
        for error in cleanup_errors:
            failure.add_note(
                "ChassisShrink filter cleanup failure: " + type(error).__name__
            )
        raise failure
    runtime.check()
    primary = engine.dh_state.primary_error
    retry_password = (
        False
        if completed
        else select_retry_password(
            bool(completion_notification), primary, retry_password
        )
    )
    engine.dh_state.set_use_new_password(retry_password)
    return {
        "native_return": completed,
        "native_success": None,
        "state": "write_completed" if completed else "write_failed",
        "programming_completed": completed,
        "flashing_ended": flashing_ended,
        "native_context_970": flashing_ended,
        "counts": tuple(counts),
        "percentages": tuple(percentages),
        "native_error_code": native_error,
        "driver_error_code": driver_error,
        "result_status_update": result_status,
        "retry_password": retry_password,
        "retry_notification": bool(retry_notification),
        "completion_notification": bool(completion_notification),
        "native_context_75c_update": native_context_75c_update,
        **(
            {
                "host_result": "cleanup_failed",
                "cleanup_errors": tuple(
                    type(error).__name__ for error in cleanup_errors
                ),
            }
            if cleanup_errors
            else {}
        ),
    }


def _run_airbag_write_algorithm(context, runtime, *, engine, notify=lambda *_: None):
    """Airbag1140/1484/174a/17b0/17e3/17ef, source state5..8 catches."""
    from scripts.calibration_2026 import (
        native2026_archive_password,
        native2026_cpu_count,
        native2026_cpu_security_bytes,
        native2026_global_cpu_index,
        native2026_new_password,
    )
    from scripts.cuw_2026 import CUWEngine2026
    from scripts.programming_2026_common import (
        block_ranges_from_sizes,
        calc_block_sizes,
        check_cpu_type_from_firmware,
        native_block_info,
        select_retry_password,
    )
    from scripts.programming_2026_legacy import writing_error_dispose

    if (
        not isinstance(context, BodyWriteContext2026)
        or context.identity.module_name not in (_AIRBAG_WRITER, _SECURITY_AIRBAG_WRITER)
        or not isinstance(runtime, NativeRuntime2026)
        or type(engine) is not CUWEngine2026
        or not callable(notify)
    ):
        raise TypeError("Source-bound Airbag context and concrete engine required")
    engine.validate_address_groups(context.binding, context.address_groups)
    _validate_body_write_data(context)
    metadata, parameter = context.binding.metadata, context.binding.parameter
    cpu = native2026_global_cpu_index(metadata)
    if (
        context.address != context.address_groups[cpu][0]
        or context.finish_address != context.address_groups[0][1]
    ):
        raise ValueError("Airbag addresses differ from native field748")
    if engine.dh_state.use_new_password != context.retry_password:
        raise ValueError("Airbag password flag differs from native field760")
    values = {key: context.binding.value(key) for key in context.binding.values}
    counts, percentages = (
        list(engine.dh_state.transferred_bytes),
        list(engine.dh_state.progress),
    )
    if len(counts) < native2026_cpu_count(metadata) or len(percentages) < len(counts):
        raise ValueError("Native CPU progress vectors absent")
    security = context.identity.module_name == _SECURITY_AIRBAG_WRITER
    writer = CommonFlash2026(runtime)
    request, response = (
        bytes(2) + context.address.request[:2],
        bytes(2) + context.address.response[:2],
    )
    finish, _ = context.finish_address.headers()
    retry, completion = engine.notification, engine.last_block_notification
    saved_timeout = identifier = None
    completed = business = False
    retry_password = context.retry_password
    cleanup_errors = []
    failure = None
    native_error = driver_error = result_status = None

    def observe(*event):
        runtime.check()
        if event and event[0] == "count":
            engine.dh_state.set_native_count(cpu, counts[cpu])
        elif event and event[0] == "percent":
            engine.dh_state.set_native_percentage(cpu, percentages[cpu])
        notify(*event)
        runtime.check()

    try:
        engine.dh_state.set_flashing_ended(False)
        runtime.call(
            "wait", milliseconds=parameter.long("WaitTimeAfterReprogrammingMode") or 0
        )
        saved_timeout = runtime.call("get_timeout")
        runtime.call(
            "set_timeout",
            milliseconds=parameter.long("ReceiveTimeoutBeforeFlashWrite") or 0,
        )
        # Native constructs its static block tables before entering state5.
        sizes = calc_block_sizes(native_block_info(values))
        ranges = block_ranges_from_sizes(sizes)
        business = True
        identifier = writer.diag.start_filter(request, response)
        attempts = 11 if bool(retry) else 1
        for attempt in range(attempts):
            password = (
                (
                    native2026_new_password(metadata, values)
                    if security
                    else native2026_archive_password(
                        native2026_archive(metadata), values
                    )
                )
                if retry_password
                else context.password
            )
            try:
                writer.check_id_with_wait_of_sfs(
                    request,
                    response,
                    context.location_id,
                    password,
                    parameter.long("WaitTimeBetweenSF") or 0,
                    parameter.long("ReceiveTimeoutBeforeInitialCommand") or 0,
                    parameter.boolean("BigEndianFlag") or False,
                )
                break
            except (NativePassThruException2026, CommonResponseError) as error:
                code = (
                    error.error
                    if isinstance(error, NativePassThruException2026)
                    else error.code
                )
                native_error = code
                engine.dh_state.record_native_error(None, code)
                if attempt == attempts - 1 or code != 7:
                    raise
                runtime.call(
                    "wait",
                    milliseconds=parameter.long("WaitTimeAfterInitialCommandError")
                    or 0,
                )
                retry_password = select_retry_password(False, code, retry_password)
                engine.dh_state.set_use_new_password(retry_password)
        if security:
            between = parameter.long("WaitTimeBetweenSF") or 0
            writer.send_nonce(
                request,
                response,
                native2026_cpu_security_bytes(metadata, "nonce", cpu),
                between,
            )
            writer.send_seed_key(
                request,
                response,
                native2026_cpu_security_bytes(metadata, "seedkey", cpu),
                between,
            )
        memory, wide = writer.get_memory_info(request, response, False)
        if not check_cpu_type_from_firmware(memory.firmware_version, values, wide):
            raise CommonResponseError(10)
        retry.assign(True)
        completion.assign(True)
        for first, last in ranges:
            writer.erase_block(request, response, first, last, parameter, wide)
            writer.write_block(
                request,
                response,
                cpu,
                first,
                last,
                sizes,
                memory,
                context.image,
                context.flash_size,
                parameter,
                counts,
                percentages,
                observe,
                engine.notify_native_errors,
                0,
                False,
            )
            writer.in_verify_block(request, response, parameter, first, last, wide)
            writer.verify_block(
                request,
                response,
                cpu,
                first,
                last,
                sizes,
                context.image,
                context.flash_size,
                parameter,
                counts,
                percentages,
                observe,
                engine.notify_native_errors,
                wide,
            )
        if security:
            writer.detect_falsify(request, response)
            retry_password = False
            engine.dh_state.set_use_new_password(False)
        if security and cpu < native2026_cpu_count(metadata) - 1:
            deferred = None
            try:
                writer.change_next_cpu(request, response)
            except (Exception, KeyboardInterrupt) as error:
                if not is_native_exception2026(error):
                    raise
                deferred = error
            engine.notify_next_cpu()
            completion.assign(False)
            if deferred is not None:
                if is_native_exception2026(deferred) and not isinstance(
                    deferred,
                    (
                        NativePassThruError2026,
                        NativeJ2534Exception2026,
                        NativeTransportError,
                        NativePassThruException2026,
                        CommonResponseError,
                    ),
                ):
                    raise CommonResponseError(9999) from deferred
                raise deferred
        else:
            engine.dh_state.set_flashing_ended(True)
            writer.finish_reprogramming(finish, response)
            runtime.call(
                "wait", milliseconds=parameter.long("WaitTimeAfterEndOfFlashing") or 0
            )
            engine.dh_state.set_write_complete(False)
            engine.notify_write_complete()
        completed = True
    except (
        NativePassThruError2026,
        NativeJ2534Exception2026,
        NativeTransportError,
        NativePassThruException2026,
        CommonResponseError,
    ) as error:
        if not business:
            failure = error
        else:
            if isinstance(error, NativePassThruError2026):
                native_error, driver_error = (
                    error.native_error_code,
                    error.passthru_status,
                )
            elif isinstance(error, NativeJ2534Exception2026):
                native_error, driver_error = error.error, error.j2534_error
            elif isinstance(error, NativeTransportError):
                native_error, driver_error = (
                    getattr(error, "native_error_code", 1),
                    getattr(error, "passthru_status", error.code),
                )
            else:
                native_error = (
                    error.error
                    if isinstance(error, NativePassThruException2026)
                    else error.code
                )
            engine.dh_state.record_native_error(None, native_error, driver_error)
            try:
                writing_error_dispose(
                    cpu,
                    counts,
                    percentages,
                    lambda field: observe(field, counts[:], percentages[:]),
                )
            except (Exception, KeyboardInterrupt) as caught:  # noqa: BLE001 - preserve observer fault through cleanup
                failure = caught
            if failure is None:
                result_status = -1
    except (Exception, KeyboardInterrupt) as error:  # noqa: BLE001 - preserve original host error through cleanup
        failure = error
    if identifier is not None:
        try:
            runtime.release("stop_filter", identifier=identifier)
        except (Exception, KeyboardInterrupt) as error:  # noqa: BLE001 - preserve original host error through cleanup
            cleanup_errors.append(error)
            if not is_native_exception2026(error) and failure is None:
                failure = error
    if result_status is not None and failure is None:
        result_status = 2 if bool(retry) else 1
        engine.dh_state.record_native_error(
            result_status, engine.dh_state.primary_error
        )
        if result_status == 1:
            engine.dh_state.mark_flash_code_failed()
    if saved_timeout is not None:
        try:
            runtime.call("set_timeout", cleanup=True, milliseconds=saved_timeout)
        except (Exception, KeyboardInterrupt) as error:  # noqa: BLE001 - preserve original host error through cleanup
            if failure is None:
                failure = error
            else:
                failure.add_note(
                    "Airbag timeout restoration failed: " + type(error).__name__
                )
    if failure is not None:
        for error in cleanup_errors:
            failure.add_note("Airbag filter cleanup failed: " + type(error).__name__)
        raise failure
    runtime.check()
    if not completed:
        retry_password = select_retry_password(
            bool(completion), engine.dh_state.primary_error, retry_password
        )
        engine.dh_state.set_use_new_password(retry_password)
    return {
        "native_return": completed,
        "native_success": None,
        "programming_completed": completed,
        "state": "write_completed" if completed else "write_failed",
        "counts": tuple(counts),
        "percentages": tuple(percentages),
        "retry_password": retry_password,
        "retry_notification": bool(retry),
        "completion_notification": bool(completion),
        "native_error_code": native_error,
        "driver_error_code": driver_error,
        "result_status_update": result_status,
        "native_context_978_update": 1 if result_status == 1 else None,
        **(
            {
                "host_result": "cleanup_failed",
                "cleanup_errors": tuple(
                    type(error).__name__ for error in cleanup_errors
                ),
            }
            if cleanup_errors
            else {}
        ),
    }


def _run_dss_write_algorithm(context, runtime, *, engine, notify=lambda *_: None):
    """DSS1000/152b/1575/17d0/183e/187d with exact CPU continuation."""
    from scripts.calibration_2026 import (
        native2026_cpu_count,
        native2026_global_cpu_index,
    )
    from scripts.cuw_2026 import CUWEngine2026
    from scripts.programming_2026_common import (
        block_ranges_from_sizes,
        calc_block_sizes,
        check_cpu_type_from_firmware,
        native_block_info,
        select_retry_password,
    )
    from scripts.programming_2026_legacy import writing_error_dispose

    if (
        not isinstance(context, BodyWriteContext2026)
        or context.identity.module_name != _DSS_WRITER
        or not isinstance(runtime, NativeRuntime2026)
        or type(engine) is not CUWEngine2026
        or not callable(notify)
    ):
        raise TypeError("Source-bound DSS1 context and concrete engine required")
    engine.validate_address_groups(context.binding, context.address_groups)
    _validate_body_write_data(context)
    metadata, parameter = context.binding.metadata, context.binding.parameter
    cpu = native2026_global_cpu_index(metadata)
    if (
        context.address != context.address_groups[cpu][0]
        or context.finish_address != context.address_groups[0][1]
    ):
        raise ValueError("DSS1 addresses differ from native field748")
    if engine.dh_state.use_new_password != context.retry_password:
        raise ValueError("DSS1 password flag differs from native field760")
    values = {key: context.binding.value(key) for key in context.binding.values}
    counts, percentages = (
        list(engine.dh_state.transferred_bytes),
        list(engine.dh_state.progress),
    )
    if len(counts) < native2026_cpu_count(metadata) or len(percentages) < len(counts):
        raise ValueError("Native CPU progress vectors absent")
    writer = CommonFlash2026(runtime)
    request, response = (
        bytes(2) + context.address.request[:2],
        bytes(2) + context.address.response[:2],
    )
    finish, _ = context.finish_address.headers()
    retry, completion = engine.notification, engine.last_block_notification
    saved_timeout = identifier = None
    completed = business = False
    retry_password = context.retry_password
    cleanup_errors = []
    failure = None
    native_error = driver_error = result_status = None

    def observe(*event):
        runtime.check()
        if event and event[0] == "count":
            engine.dh_state.set_native_count(cpu, counts[cpu])
        elif event and event[0] == "percent":
            engine.dh_state.set_native_percentage(cpu, percentages[cpu])
        notify(*event)
        runtime.check()

    try:
        engine.dh_state.set_flashing_ended(False)
        runtime.call(
            "wait", milliseconds=parameter.long("WaitTimeAfterReprogrammingMode") or 0
        )
        saved_timeout = runtime.call("get_timeout")
        business = True
        runtime.call(
            "set_timeout",
            milliseconds=parameter.long("ReceiveTimeoutBeforeFlashWrite") or 0,
        )
        # Native constructs its static block tables before entering state5.
        sizes = calc_block_sizes(native_block_info(values))
        ranges = block_ranges_from_sizes(sizes)
        business = True
        identifier = writer.diag.start_filter(request, response)
        between = parameter.long("WaitTimeBetweenSF") or 0
        writer.check_id_with_wait_of_sfs(
            request,
            response,
            context.location_id,
            context.password,
            between,
            parameter.long("ReceiveTimeoutBeforeInitialCommand") or 0,
            parameter.boolean("BigEndianFlag") or False,
        )
        runtime.call("wait", milliseconds=between)
        memory, wide = writer.get_memory_info(request, response, False)
        if not check_cpu_type_from_firmware(memory.firmware_version, values, wide):
            raise CommonResponseError(10)
        retry.assign(True)
        for position, (first, last) in enumerate(ranges):
            if position == len(ranges) - 1:
                completion.assign(True)
            writer.erase_block(request, response, first, last, parameter, wide)
            writer.write_block(
                request,
                response,
                cpu,
                first,
                last,
                sizes,
                memory,
                context.image,
                context.flash_size,
                parameter,
                counts,
                percentages,
                observe,
                engine.notify_native_errors,
                between,
                False,
            )
            writer.in_verify_block(request, response, parameter, first, last, wide)
            writer.verify_block(
                request,
                response,
                cpu,
                first,
                last,
                sizes,
                context.image,
                context.flash_size,
                parameter,
                counts,
                percentages,
                observe,
                engine.notify_native_errors,
                wide,
            )
        if cpu + 1 < native2026_cpu_count(metadata):
            deferred = None
            try:
                writer.change_next_cpu(request, response)
            except (Exception, KeyboardInterrupt) as error:
                if not is_native_exception2026(error):
                    raise
                deferred = error
            engine.notify_next_cpu()
            runtime.call("wait", milliseconds=0)
            if deferred is not None:
                if is_native_exception2026(deferred) and not isinstance(
                    deferred,
                    (
                        NativePassThruError2026,
                        NativeJ2534Exception2026,
                        NativeTransportError,
                        NativePassThruException2026,
                        CommonResponseError,
                    ),
                ):
                    raise CommonResponseError(9999) from deferred
                raise deferred
        else:
            engine.dh_state.set_flashing_ended(True)
            writer.finish_reprogramming(finish, response)
            runtime.call(
                "wait", milliseconds=parameter.long("WaitTimeAfterEndOfFlashing") or 0
            )
        retry_password = False
        engine.dh_state.set_use_new_password(False)
        engine.dh_state.set_write_complete(False)
        engine.notify_write_complete()
        completed = True
    except (
        NativePassThruError2026,
        NativeJ2534Exception2026,
        NativeTransportError,
        NativePassThruException2026,
        CommonResponseError,
    ) as error:
        if not business:
            failure = error
        else:
            if isinstance(error, NativePassThruError2026):
                native_error, driver_error = (
                    error.native_error_code,
                    error.passthru_status,
                )
            elif isinstance(error, NativeJ2534Exception2026):
                native_error, driver_error = error.error, error.j2534_error
            elif isinstance(error, NativeTransportError):
                native_error, driver_error = (
                    getattr(error, "native_error_code", 1),
                    getattr(error, "passthru_status", error.code),
                )
            else:
                native_error = (
                    error.error
                    if isinstance(error, NativePassThruException2026)
                    else error.code
                )
            engine.dh_state.record_native_error(None, native_error, driver_error)
            try:
                writing_error_dispose(
                    cpu,
                    counts,
                    percentages,
                    lambda field: observe(field, counts[:], percentages[:]),
                )
            except (Exception, KeyboardInterrupt) as caught:  # noqa: BLE001 - preserve observer fault through cleanup
                failure = caught
            if failure is None:
                result_status = -1
    except (Exception, KeyboardInterrupt) as error:  # noqa: BLE001 - preserve original host error through cleanup
        failure = error
    if identifier is not None:
        try:
            runtime.release("stop_filter", identifier=identifier)
        except (Exception, KeyboardInterrupt) as error:  # noqa: BLE001 - preserve original host error through cleanup
            cleanup_errors.append(error)
            if not is_native_exception2026(error) and failure is None:
                failure = error
    if result_status is not None and failure is None:
        result_status = 2 if bool(retry) else 1
        engine.dh_state.record_native_error(
            result_status, engine.dh_state.primary_error
        )
        if result_status == 1:
            engine.dh_state.mark_flash_code_failed()
    if saved_timeout is not None:
        try:
            runtime.call("set_timeout", cleanup=True, milliseconds=saved_timeout)
        except (Exception, KeyboardInterrupt) as error:  # noqa: BLE001 - preserve original host error through cleanup
            if failure is None:
                failure = error
            else:
                failure.add_note(
                    "DSS1 timeout restoration failed: " + type(error).__name__
                )
    if failure is not None:
        for error in cleanup_errors:
            failure.add_note("DSS1 filter cleanup failed: " + type(error).__name__)
        raise failure
    runtime.check()
    if not completed:
        retry_password = select_retry_password(
            bool(completion), engine.dh_state.primary_error, retry_password
        )
        engine.dh_state.set_use_new_password(retry_password)
    return {
        "native_return": completed,
        "native_success": None,
        "programming_completed": completed,
        "state": "write_completed" if completed else "write_failed",
        "counts": tuple(counts),
        "percentages": tuple(percentages),
        "retry_password": retry_password,
        "retry_notification": bool(retry),
        "completion_notification": bool(completion),
        "native_error_code": native_error,
        "driver_error_code": driver_error,
        "result_status_update": result_status,
        "native_context_978_update": 1 if result_status == 1 else None,
        **(
            {
                "host_result": "cleanup_failed",
                "cleanup_errors": tuple(
                    type(error).__name__ for error in cleanup_errors
                ),
            }
            if cleanup_errors
            else {}
        ),
    }


def _run_body_write_algorithm(context, runtime, *, engine, notify=lambda *_: None):
    """Body1170, CXPI12e0 and P5Body1170 with native local row reload."""
    from scripts.calibration_2026 import (
        native2026_cpu_count,
        native2026_cpu_values,
        native2026_global_cpu_index,
    )
    from scripts.cuw_2026 import CUWEngine2026
    from scripts.programming_2026_common import (
        NativeParameter2026,
        block_ranges_from_image,
        block_ranges_from_sizes,
        calc_block_sizes,
        check_block_ranges,
        check_cpu_type_from_firmware,
        native_block_info,
        select_retry_password,
    )
    from scripts.programming_2026_legacy import writing_error_dispose

    if (
        not isinstance(context, BodyWriteContext2026)
        or context.identity.module_name not in _BODY_WRITERS
        or not isinstance(runtime, NativeRuntime2026)
        or type(engine) is not CUWEngine2026
        or not callable(notify)
    ):
        raise TypeError("Source-bound Body context and concrete engine required")
    engine.validate_address_groups(context.binding, context.address_groups)
    _validate_body_write_data(context)
    metadata, parameter = context.binding.metadata, context.binding.parameter
    cpu = native2026_global_cpu_index(metadata)
    if (
        context.address != context.address_groups[cpu][0]
        or context.finish_address != context.address_groups[cpu][1]
    ):
        raise ValueError("Body addresses differ from native field748")
    if engine.dh_state.use_new_password != context.retry_password:
        raise ValueError("Body password flag differs from native field760")
    values = {key: context.binding.value(key) for key in context.binding.values}
    counts, percentages = (
        list(engine.dh_state.transferred_bytes),
        list(engine.dh_state.progress),
    )
    if len(counts) < native2026_cpu_count(metadata) or len(percentages) < len(counts):
        raise ValueError("Native CPU progress vectors absent")
    cxpi = context.identity.module_name == _BODY_WRITERS[1]
    phase5 = context.identity.module_name == _BODY_WRITERS[2]
    writer = CommonFlash2026(runtime)
    request, response = (
        bytes(2) + context.address.request[:2],
        bytes(2) + context.address.response[:2],
    )
    finish, _ = context.finish_address.headers()
    retry, completion = engine.notification, engine.last_block_notification
    saved_timeout = identifier = None
    completed = business = False
    retry_password = context.retry_password
    cleanup_errors = []
    failure = None
    native_error = driver_error = result_status = None
    bs_active = False

    def observe(*event):
        runtime.check()
        if event and event[0] == "count":
            engine.dh_state.set_native_count(cpu, counts[cpu])
        elif event and event[0] == "percent":
            engine.dh_state.set_native_percentage(cpu, percentages[cpu])
        notify(*event)
        runtime.check()

    try:
        engine.dh_state.set_flashing_ended(False)
        runtime.call(
            "wait", milliseconds=parameter.long("WaitTimeAfterReprogrammingMode") or 0
        )
        business = True
        saved_timeout = 0
        if cxpi:
            bs_active = True
            writer.diag.set_block_size(1)
        saved_timeout = runtime.call("get_timeout")
        runtime.call(
            "set_timeout",
            milliseconds=parameter.long("ReceiveTimeoutBeforeFlashWrite") or 0,
        )
        # Native constructs its static block tables before entering state5.
        sizes = calc_block_sizes(native_block_info(values))
        if parameter.boolean("ReadBlockRangeFromS0HeaderFlag") or False:
            ranges = block_ranges_from_image(native2026_archive(metadata).header)
            check_block_ranges(context.flash_size, sizes, ranges)
        else:
            ranges = block_ranges_from_sizes(sizes)
        business = True
        identifier = writer.diag.start_filter(request, response)
        between = parameter.long("WaitTimeBetweenSF") or 0
        getter_cpu = engine.native_getter_cpu_type984
        kind, contact = (
            metadata.vehicle.get("kindofecu", ""),
            metadata.vehicle.get("contacttype", ""),
        )
        source = context.binding.catalog_sources.get(
            kind + contact + getter_cpu + ".ini"
        )
        if source is None:
            raise CommonResponseError(9999)
        local_parameter = (
            NativeParameter2026.from_encoded(source)
            if context.binding.encoded
            else NativeParameter2026.from_csv(source)
        )
        local_parameter.set_keys(kind, getter_cpu, contact)
        attempts = 11 if bool(retry) else 1
        for attempt in range(attempts):
            try:
                writer.check_id_with_wait_of_sfs(
                    request,
                    response,
                    context.location_id,
                    context.password,
                    between,
                    parameter.long("ReceiveTimeoutBeforeInitialCommand") or 0,
                    local_parameter.boolean("BigEndianFlag") or False,
                )
                break
            except (Exception, KeyboardInterrupt) as error:
                if not is_native_exception2026(error) or attempt == attempts - 1:
                    raise
        runtime.call("wait", milliseconds=between)
        memory, wide = writer.get_memory_info(
            request, response, parameter.boolean("ExternalMemoryFlag") or False
        )
        if not check_cpu_type_from_firmware(memory.firmware_version, values, wide):
            raise CommonResponseError(10)
        retry.assign(True)
        nonverify = parameter.boolean("FlagToNonVerifyProcess") or False
        for position, (first, last) in enumerate(ranges):
            if position == len(ranges) - 1:
                completion.assign(True)
            if cxpi:
                _cxpi_erase_block(
                    context, writer, request, response, first, last, parameter
                )
            else:
                writer.erase_block(request, response, first, last, parameter, wide)
            writer.write_block(
                request,
                response,
                cpu,
                first,
                last,
                sizes,
                memory,
                context.image,
                context.flash_size // 2 if nonverify else context.flash_size,
                parameter,
                counts,
                percentages,
                observe,
                engine.notify_native_errors,
                between,
                parameter.boolean("ExternalMemoryFlag") or False,
            )
            writer.in_verify_block(request, response, parameter, first, last, wide)
            if not nonverify:
                verify_arguments = (
                    request,
                    response,
                    cpu,
                    first,
                    last,
                    sizes,
                    context.image,
                    context.flash_size,
                    parameter,
                    counts,
                    percentages,
                    observe,
                )
                if cxpi:
                    writer.verify_block2(*verify_arguments)
                else:
                    writer.verify_block(
                        *verify_arguments, engine.notify_native_errors, wide
                    )
        has_next = cpu + 1 < native2026_cpu_count(metadata)
        change_ignition = False
        if phase5 and has_next:
            change_ignition = engine.general_parameter_boolean(
                kind,
                native2026_cpu_values(metadata, cpu + 1).get("cputype", ""),
                contact,
                "FlagToDoIGOFFONAtCPUTypeChange",
            )
        if phase5 and has_next and not change_ignition:
            deferred = None
            try:
                writer.change_next_cpu(request, response)
            except (Exception, KeyboardInterrupt) as error:
                if not is_native_exception2026(error):
                    raise
                deferred = error
            engine.notify_next_cpu()
            retry.assign(False)
            completion.assign(False)
            if deferred is not None:
                if is_native_exception2026(deferred) and not isinstance(
                    deferred,
                    (
                        NativePassThruError2026,
                        NativeJ2534Exception2026,
                        NativeTransportError,
                        NativePassThruException2026,
                        CommonResponseError,
                    ),
                ):
                    raise CommonResponseError(9999) from deferred
                raise deferred
            runtime.call("wait", milliseconds=0)
            runtime.call("wait", milliseconds=0)
        else:
            engine.dh_state.set_flashing_ended(True)
            finish_header = (
                bytes(2) + (context.finish_address.request + bytes(3))[:3]
                if cxpi
                else finish
            )
            writer.finish_reprogramming(finish_header, response)
            runtime.call(
                "wait", milliseconds=parameter.long("WaitTimeAfterEndOfFlashing") or 0
            )
            if not phase5 and has_next:
                change_ignition = engine.general_parameter_boolean(
                    kind,
                    native2026_cpu_values(metadata, cpu + 1).get("cputype", ""),
                    contact,
                    "FlagToDoIGOFFONAtCPUTypeChange",
                )
                if not change_ignition:
                    engine.notify_next_cpu()
            if phase5:
                retry.assign(False)
            completion.assign(False)
        retry_password = False
        engine.dh_state.set_use_new_password(False)
        engine.dh_state.set_write_complete(False)
        engine.notify_write_complete()
        completed = True
    except (
        NativePassThruError2026,
        NativeJ2534Exception2026,
        NativeTransportError,
        NativePassThruException2026,
        CommonResponseError,
    ) as error:
        if not business:
            failure = error
        else:
            if isinstance(error, NativePassThruError2026):
                native_error, driver_error = (
                    error.native_error_code,
                    error.passthru_status,
                )
            elif isinstance(error, NativeJ2534Exception2026):
                native_error, driver_error = error.error, error.j2534_error
            elif isinstance(error, NativeTransportError):
                native_error, driver_error = (
                    getattr(error, "native_error_code", 1),
                    getattr(error, "passthru_status", error.code),
                )
            else:
                native_error = (
                    error.error
                    if isinstance(error, NativePassThruException2026)
                    else error.code
                )
            engine.dh_state.record_native_error(None, native_error, driver_error)
            try:
                writing_error_dispose(
                    cpu,
                    counts,
                    percentages,
                    lambda field: observe(field, counts[:], percentages[:]),
                )
            except (Exception, KeyboardInterrupt) as caught:  # noqa: BLE001 - preserve observer fault through cleanup
                failure = caught
            if failure is None:
                result_status = -1
    except (Exception, KeyboardInterrupt) as error:  # noqa: BLE001 - preserve original host error through cleanup
        failure = error
    if bs_active:
        try:
            runtime.call("control_io", cleanup=True, ioctl=2, parameters=((0x1E, 0),))
        except (Exception, KeyboardInterrupt) as error:  # noqa: BLE001 - native CXPI cleanup CatchAll; unknown host faults propagate
            cleanup_errors.append(error)
            if not is_native_exception2026(error) and failure is None:
                failure = error
    if identifier is not None:
        try:
            runtime.release("stop_filter", identifier=identifier)
        except (Exception, KeyboardInterrupt) as error:  # noqa: BLE001 - preserve original host error through cleanup
            cleanup_errors.append(error)
            if not is_native_exception2026(error) and failure is None:
                failure = error
    if result_status is not None and failure is None:
        result_status = 2 if bool(retry) else 1
        engine.dh_state.record_native_error(
            result_status, engine.dh_state.primary_error
        )
        if result_status == 1:
            engine.dh_state.mark_flash_code_failed()
    if saved_timeout is not None:
        try:
            runtime.call("set_timeout", cleanup=True, milliseconds=saved_timeout)
        except (Exception, KeyboardInterrupt) as error:  # noqa: BLE001 - preserve original host error through cleanup
            if failure is None:
                failure = error
            else:
                failure.add_note(
                    "Body timeout restoration failed: " + type(error).__name__
                )
    if failure is not None:
        for error in cleanup_errors:
            failure.add_note("Body filter cleanup failed: " + type(error).__name__)
        raise failure
    runtime.check()
    if not completed:
        retry_password = select_retry_password(
            bool(completion), engine.dh_state.primary_error, retry_password
        )
        engine.dh_state.set_use_new_password(retry_password)
    return {
        "native_return": completed,
        "native_success": None,
        "programming_completed": completed,
        "state": "write_completed" if completed else "write_failed",
        "counts": tuple(counts),
        "percentages": tuple(percentages),
        "retry_password": retry_password,
        "retry_notification": bool(retry),
        "completion_notification": bool(completion),
        "native_error_code": native_error,
        "driver_error_code": driver_error,
        "result_status_update": result_status,
        "native_context_978_update": 1 if result_status == 1 else None,
        **(
            {
                "host_result": "cleanup_failed",
                "cleanup_errors": tuple(
                    type(error).__name__ for error in cleanup_errors
                ),
            }
            if cleanup_errors
            else {}
        ),
    }


def _validate_native_writer_inputs(context, engine):
    from scripts.cuw_2026 import CUWEngine2026

    if (
        not isinstance(context, BodyWriteContext2026)
        or type(engine) is not CUWEngine2026
    ):
        raise TypeError(
            "Source-bound writer context and concrete native engine required"
        )
    if context.target_index != engine.native_writer_target_index:
        raise ValueError("Writer target index differs from actual native field73c")
    if (
        context.identity.module_name in (_SONAR_WRITER, *_SHRINK_WRITERS)
        and context.initial_command_retry != engine.native_initial_command_retry980
    ):
        raise ValueError(
            "Writer initial command flag differs from actual native field980"
        )


def run_sonar_write(context, runtime, *, engine, **options):
    _validate_native_writer_inputs(context, engine)
    return _run_sonar_write_algorithm(context, runtime, engine=engine, **options)


def run_shrink_write(context, runtime, *, engine, **options):
    _validate_native_writer_inputs(context, engine)
    return _run_shrink_write_algorithm(context, runtime, engine=engine, **options)


def run_airbag_write(context, runtime, *, engine, **options):
    _validate_native_writer_inputs(context, engine)
    return _run_airbag_write_algorithm(context, runtime, engine=engine, **options)


def run_dss_write(context, runtime, *, engine, **options):
    _validate_native_writer_inputs(context, engine)
    return _run_dss_write_algorithm(context, runtime, engine=engine, **options)


def run_body_write(context, runtime, *, engine, **options):
    _validate_native_writer_inputs(context, engine)
    return _run_body_write_algorithm(context, runtime, engine=engine, **options)


def run_security_airbag_write(context, runtime, *, engine, **options):
    _validate_native_writer_inputs(context, engine)
    return _run_security_airbag_write_algorithm(
        context, runtime, engine=engine, **options
    )


@dataclass(frozen=True)
class FinishProbeContext2026:
    identity: NativeModuleIdentity
    binding: NativeParameterBinding2026 = field(repr=False)
    groups: tuple[tuple[NativeCommunicationAddress, ...], ...]

    def __post_init__(self):
        _source(self.identity)
        if (
            self.identity.module_name not in _FINISH_WRAPPERS
            or not isinstance(self.binding, NativeParameterBinding2026)
            or self.binding.operation != "write"
            or self.binding.module_name != self.identity.module_name
            or type(self.groups) is not tuple
            or not self.groups
            or any(
                type(group) is not tuple
                or not group
                or any(
                    not isinstance(address, NativeCommunicationAddress)
                    for address in group
                )
                for group in self.groups
            )
        ):
            raise ValueError("Actual native retained finish-probe groups required")


def bind_finish_context(
    container, node, observed_cids, selection, identity, attachments, observations
) -> FinishProbeContext2026:
    """Exact wrappers use shared probe over Control4c10's CPU0/first entry."""
    from scripts.programming_2026_vendor import native2026_write_address_groups

    _source(identity)
    if (
        identity.module_name not in _FINISH_WRAPPERS
        or not isinstance(selection, NativeParameterBinding2026)
        or selection.operation != "write"
        or selection.module_name != identity.module_name
        or not isinstance(attachments, Mapping)
        or attachments
        or not isinstance(observations, Mapping)
        or observations
    ):
        raise ValueError(
            "Selected native finish probe without manual address overrides required"
        )
    selection.validate_against(
        container, operation="write", node=node, cpu_index=selection.metadata.cpu_index
    )
    return FinishProbeContext2026(
        identity, selection, native2026_write_address_groups(container, selection)
    )
