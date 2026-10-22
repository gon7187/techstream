"""Exact CUW2026 P4/P5 powertrain preparation over owned primitive sessions."""

from collections.abc import Mapping
from dataclasses import dataclass, field

from scripts.calibration_2026 import native2026_metadata
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
    NativeException2026,
    NativeParameterBinding2026,
    NativePassThruException2026,
    NativeRuntime2026,
    NotificationBool,
    SecretInfoClient,
    Unified2026,
    diagnostic_mask,
    native_error_fields2026,
    security_up_key,
    seed_key_four_round,
    seed_key_six_byte,
)

DUAL = "TCUWP4P5CanPowerTrainPrepareWriter.dll"
POWER = "TCUWP5CanPowerTrainPrepareWriter.dll"
BODY = "TCUWP5CanPowerTrainPrepareWriterForBodyMicon.dll"
SOLAR = "TCUWP5CanPowerTrainPrepareWriterForSolar.dll"
SECURITY = "TCUWP5CanSecurityPowerTrainPrepareWriter.dll"
MODULE_EXPORTS = dict.fromkeys(
    (DUAL, POWER, BODY, SOLAR, SECURITY), ("StartPrepareWrite",)
)
IMPLEMENTED_EXPORTS = MODULE_EXPORTS.copy()
PARTIAL_EXPORTS = {}
_NATIVE_ERRORS = (
    NativePassThruException2026,
    NativePassThruError2026,
    NativeTransportError,
    CommonResponseError,
)


def _source(identity):
    if (
        not isinstance(identity, NativeModuleIdentity)
        or identity.module_name not in MODULE_EXPORTS
        or identity.cuw_build != "2026"
        or identity != identify_native_module(identity.sha256, identity.module_name)
    ):
        raise ValueError("Exact registered CUW2026 P5 preparation identity required")


@dataclass(frozen=True)
class P5PrepareContext2026:
    identity: NativeModuleIdentity
    binding: NativeParameterBinding2026 = field(repr=False)
    addresses: tuple[NativeCommunicationAddress, ...]
    materials: tuple[bytes, ...] = field(repr=False)
    ecu_auth_key: bytes = field(repr=False)
    service_auth_key: bytes = field(repr=False)
    native_retry_flag_964: bool = False

    def __post_init__(self):
        _source(self.identity)
        if (
            not isinstance(self.binding, NativeParameterBinding2026)
            or self.binding.operation != "prepare"
            or self.binding.module_name != self.identity.module_name
            or type(self.addresses) is not tuple
            or len(self.addresses) > 4
            or any(
                not isinstance(a, NativeCommunicationAddress) for a in self.addresses
            )
            or type(self.native_retry_flag_964) is not bool
            or type(self.materials) is not tuple
        ):
            raise ValueError("Bound native preparation context required")
        if self.identity.module_name in (DUAL, POWER, SOLAR):
            if len(self.materials) != 4 or any(
                type(v) is not bytes or len(v) != 2 for v in self.materials
            ):
                raise ValueError("Four native two-byte SecurityKey values required")
        elif self.materials:
            raise ValueError("This preparation does not consume SecurityKey values")
        width = 16 if self.identity.module_name == SECURITY else 0
        if any(
            type(v) is not bytes or len(v) != width
            for v in (self.ecu_auth_key, self.service_auth_key)
        ):
            raise ValueError("Projected native authentication key width mismatch")


def bind_native_context(
    container, node, observed_cids, selection, identity, attachments, observations
):
    _source(identity)
    if (
        not isinstance(selection, NativeParameterBinding2026)
        or selection.operation != "prepare"
        or selection.module_name != identity.module_name
        or not isinstance(attachments, Mapping)
        or set(attachments)
        - (
            {"ecu_auth_key", "service_auth_key"}
            if identity.module_name == SECURITY
            else set()
        )
        or not isinstance(observations, Mapping)
        or set(observations) - {"native_retry_flag_964"}
    ):
        raise ValueError(
            "Actual selected2026 metadata without manual overrides required"
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
    if not success:
        raise ValueError("Native preparation address selector failed")
    materials = ()
    if identity.module_name in (DUAL, POWER, SOLAR):
        values = selection.lines("SecurityKey")[:4]
        if len(values) != 4 or any(
            len(v) != 4 or any(c not in "0123456789abcdefABCDEF" for c in v)
            for v in values
        ):
            raise ValueError("Four selected native SecurityKey values required")
        materials = tuple(bytes.fromhex(v) for v in values)
    keys = (b"", b"")
    if identity.module_name == SECURITY:
        first = native2026_metadata(container, node=node, cpu_index=0)
        keys = (first.global_ecu_auth_key_bytes, first.global_service_auth_key_bytes)
        for name, value in zip(("ecu_auth_key", "service_auth_key"), keys):
            if name in attachments and attachments[name] != value:
                raise ValueError("Attachment differs from native projected global key")
    return P5PrepareContext2026(
        identity,
        selection,
        addresses,
        materials,
        *keys,
        observations.get("native_retry_flag_964", False),
    )


def run_native_context(context, runtime, *, retry_notification=None, secret_info=None):
    """Run five exact exports, keeping native Boolean separate from host failures."""
    if not isinstance(context, P5PrepareContext2026) or not isinstance(
        runtime, NativeRuntime2026
    ):
        raise TypeError("Typed selected context and bounded runtime required")
    if retry_notification is None:
        retry_notification = NotificationBool()
    if not isinstance(retry_notification, NotificationBool):
        raise TypeError("Native notification Boolean required")
    module = context.identity.module_name
    if module == SECURITY and not isinstance(secret_info, SecretInfoClient):
        raise TypeError("Authorized SecretInfo client required")
    diag = CanDiag2026(runtime)
    filters = []
    bs_owned = False
    error_code = driver_error = status = None
    completed = False
    native_return = False
    failure = None
    # All five cores copy two bytes from each ID and SetNum(4), including
    # security's dynamically sized message helper; extension bytes are ignored.
    addresses = tuple(
        (b"\0\0" + a.request[:2], b"\0\0" + a.response[:2]) for a in context.addresses
    )

    def call(pair, payload, expected, minimum, code, phase5=True):
        return diag.call(
            pair[0],
            pair[1],
            payload,
            expected,
            minimum=minimum,
            error_code=code,
            phase5=phase5,
            pending_limit=180 if phase5 else 149,
            busy_limit=0x159A if phase5 else 255,
        )

    def probe(pair):
        try:
            call(pair, b"\x10\x02", b"\x50\x02", 6, 41)
        except _NATIVE_ERRORS as error:
            _, raw = native_error_fields2026(error)
            if raw in (9, 16):
                raise CommonResponseError(55, b"") from error
            # BodyMicon source checks SID27 here; other variants check SID10.
            sid = 0x27 if module == BODY else 0x10
            if (
                isinstance(error, CommonResponseError)
                and len(error.response) == 3
                and error.response[:2] == bytes((0x7F, sid))
            ):
                raise CommonResponseError(56, error.response) from error
            raise
        except NativeException2026 as error:
            if module != DUAL:
                raise CommonResponseError(9999, b"") from error
            raise

    def key(pair, phase5=True):
        security = module == SECURITY
        size = 16 if security else 6 if module == BODY else 4
        try:
            seed = call(
                pair,
                b"\x27\x01" + context.ecu_auth_key,
                b"\x67\x01",
                size + 2,
                16,
                phase5,
            )[2 : 2 + size]
        except CommonResponseError as error:
            # Native Catch1480 checks the retained seed buffer, not the later
            # key response buffer: only a seed negative is converted to23.
            if (
                not phase5
                and len(error.response) == 3
                and error.response[:2] == b"\x7f\x27"
            ):
                raise CommonResponseError(23, error.response) from error
            raise
        except _NATIVE_ERRORS as error:
            if not phase5 and native_error_fields2026(error)[1] in (9, 16):
                raise CommonResponseError(22, b"") from error
            raise
        if security:
            assert isinstance(secret_info, SecretInfoClient)
            value = security_up_key(
                runtime, secret_info, seed, context.service_auth_key
            )
        else:
            value = (
                seed_key_six_byte(seed)
                if module == BODY
                else seed_key_four_round(seed, context.materials)
            )
        if not phase5:
            wait = context.binding.parameter.long("WaitTimeAfterSeedData") or 0
            runtime.call("wait", milliseconds=wait & 0xFFFFFFFF)
        try:
            call(pair, b"\x27\x02" + value, b"\x67\x02", 2, 17, phase5)
        except CommonResponseError as error:
            if security and error.response == b"\x7f\x27\x35":
                raise CommonResponseError(1002, error.response) from error
            raise
        except _NATIVE_ERRORS as error:
            if not phase5 and native_error_fields2026(error)[1] in (9, 16):
                raise CommonResponseError(22, b"") from error
            raise

    def mask():
        diagnostic_mask(
            runtime,
            (context.binding.parameter.long("WaitTimeAfterDiagnosticMask") or 0)
            & 0xFFFFFFFF,
        )

    def routine(pair):
        call(pair, bytes.fromhex("31011003"), bytes.fromhex("71011003"), 4, 25)

    try:
        if module == BODY:
            runtime.own("control_io", ioctl=2, parameters=((0x1E, 0),))
            bs_owned = True
            diag.set_block_size(1)
        for pair in addresses:
            filters.append(diag.start_filter(*pair))
        if module == DUAL:
            if len(addresses) < 2:
                raise ValueError(
                    "Native dual preparation requires both initialized address slots"
                )
            pair, p4_pair = addresses[:2]
            p5_skipped = p4_skipped = False
            try:
                probe(pair)
                key(pair)
            except _NATIVE_ERRORS as error:
                if (
                    native_error_fields2026(error)[0] not in (55, 56)
                    or not context.native_retry_flag_964
                ):
                    raise
                p5_skipped = True
            try:
                key(p4_pair, False)
                runtime.call(
                    "wait",
                    milliseconds=(
                        context.binding.parameter.long("WaitTimeAfterSeedKey") or 0
                    )
                    & 0xFFFFFFFF,
                )
            except _NATIVE_ERRORS as error:
                if (
                    native_error_fields2026(error)[0] not in (22, 23)
                    or not context.native_retry_flag_964
                ):
                    raise
                p4_skipped = True
            if not (p5_skipped and p4_skipped):
                mask()
                if not p5_skipped:
                    routine(pair)
                    runtime.call("wait", milliseconds=10)
                if not p4_skipped:
                    Unified2026(runtime).change_mode(0, *p4_pair)
        else:
            responsive = []
            for pair in addresses:
                try:
                    probe(pair)
                    responsive.append(pair)
                except _NATIVE_ERRORS as error:
                    if native_error_fields2026(error)[0] not in (55, 56):
                        raise
            if not responsive and not context.native_retry_flag_964:
                raise CommonResponseError(41, b"")
            for pair in responsive:
                key(pair)
            if responsive:
                mask()
                if module == SOLAR:
                    retry_notification.assign(True)
                for index, pair in enumerate(responsive):
                    routine(pair)
                    if index + 1 < len(responsive):
                        runtime.call("wait", milliseconds=10)
        completed = native_return = True
    except _NATIVE_ERRORS as error:
        error_code, driver_error = native_error_fields2026(error)
        status = 2 if module == SOLAR and bool(retry_notification) else 1
    except (Exception, KeyboardInterrupt) as error:  # noqa: BLE001 - preserve host fault while releasing all filters
        failure = error
    cleanup_errors = []
    if bs_owned:
        try:
            runtime.release("control_io", ioctl=2, parameters=((0x1E, 0),))
        except (Exception, KeyboardInterrupt) as error:  # noqa: BLE001 - restore BS before every filter release
            cleanup_errors.append(error)
    for identifier in filters:
        try:
            runtime.release("stop_filter", identifier=identifier)
        except (Exception, KeyboardInterrupt) as error:  # noqa: BLE001 - attempt every acquired filter
            cleanup_errors.append(error)
    if failure is not None:
        for error in cleanup_errors:
            failure.add_note("P5 filter cleanup failure: " + type(error).__name__)
        raise failure
    host_cleanup_errors = [
        error
        for error in cleanup_errors
        if not isinstance(error, (*_NATIVE_ERRORS, NativeException2026))
    ]
    if host_cleanup_errors:
        raise OSError("P5 host resource cleanup incomplete") from host_cleanup_errors[0]
    # Native cleanup EH catches all StopFilter exceptions, preserving
    # the Boolean already stored. Host ownership still records a failed release.
    runtime.check()
    retry_update = True if module == SOLAR and status == 2 else None
    if (
        module in (POWER, BODY)
        and not native_return
        and context.binding.parameter.boolean("IGOffRetriableFlag")
        and bool(retry_notification)
    ):
        native_return = True
    return {
        "state": "prepare_cleanup_failed"
        if cleanup_errors
        else "prepare_completed"
        if completed
        else "prepare_failed",
        "host_result": "cleanup_failed" if cleanup_errors else "completed",
        "host_succeeded": completed and not cleanup_errors,
        "cleanup_failures": tuple(type(error).__name__ for error in cleanup_errors),
        "native_return": native_return,
        "prepared": completed,
        "result_status_update": status,
        "native_error_code": error_code,
        "driver_error_code": driver_error,
        "native_retry_flag_964_update": retry_update,
        "programming_completed": False,
        "source_module": module,
        "source_sha256": context.identity.sha256,
        "parameter_sha256": context.binding.source_sha256,
    }
