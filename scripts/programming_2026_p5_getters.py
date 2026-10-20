"""Exact CUW2026 P4/P5 getter exports over the shared native host contracts."""

from collections.abc import Mapping
from dataclasses import dataclass, field

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
    NativeJ2534Exception2026,
    NativeParameterBinding2026,
    NativePassThruException2026,
    NativeRuntime2026,
)

MIXED = "TCUWP4P5CanCIDGetter.dll"
P5 = "TCUWP5CanCIDGetter.dll"
SET_BS = "TCUWP5CanCIDGetterWithSetBS.dll"
MODULE_EXPORTS = dict.fromkeys((MIXED, P5, SET_BS), ("StartGetCID",))
IMPLEMENTED_EXPORTS = MODULE_EXPORTS.copy()
PARTIAL_EXPORTS = {}


def _source(identity):
    if (
        not isinstance(identity, NativeModuleIdentity)
        or identity.module_name not in MODULE_EXPORTS
        or identity.cuw_build != "2026"
        or identity != identify_native_module(identity.sha256, identity.module_name)
    ):
        raise ValueError("Exact registered CUW2026 P4/P5 getter identity required")


@dataclass(frozen=True)
class P5GetterContext2026:
    identity: NativeModuleIdentity
    binding: NativeParameterBinding2026 = field(repr=False)
    addresses: tuple[NativeCommunicationAddress, ...]
    receive_timeout_ms: int
    timeout_allowing_id: bytes = b""

    def __post_init__(self):
        _source(self.identity)
        if (
            not isinstance(self.binding, NativeParameterBinding2026)
            or self.binding.operation != "get_cid"
            or self.binding.module_name != self.identity.module_name
            or type(self.addresses) is not tuple
            or not 0 <= len(self.addresses) <= 256
            or any(
                not isinstance(a, NativeCommunicationAddress) for a in self.addresses
            )
            or (self.identity.module_name == MIXED and len(self.addresses) != 2)
            or type(self.receive_timeout_ms) is not int
            or not 0 <= self.receive_timeout_ms <= 0xFFFFFFFF
            or type(self.timeout_allowing_id) is not bytes
            or len(self.timeout_allowing_id) not in (0, 2, 3)
        ):
            raise ValueError("Bounded native getter parameter/address inputs required")


def bind_native_context(
    container, node, observed_cids, selection, identity, attachments, observations
):
    _source(identity)
    if (
        not isinstance(selection, NativeParameterBinding2026)
        or selection.operation != "get_cid"
        or selection.module_name != identity.module_name
        or not isinstance(attachments, Mapping)
        or attachments
        or not isinstance(observations, Mapping)
        or observations
    ):
        raise ValueError(
            "Actual selected native getter binding without overrides required"
        )
    selection = selection.validate_against(
        container,
        operation="get_cid",
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
        raise ValueError("Native getter address selector did not resolve")
    text = selection.value("RequestCANIDAllowingTimeout")
    if text and (
        len(text) not in (4, 6) or any(c not in "0123456789abcdefABCDEF" for c in text)
    ):
        raise ValueError("Native optional CAN ID requires two/three hexadecimal bytes")
    return P5GetterContext2026(
        identity,
        selection,
        addresses,
        selection.parameter.long("ReceiveTimeoutBeforeGetCID") or 0,
        bytes.fromhex(text) if text else b"",
    )


def decode_p5_cids2026(data: bytes, *, mixed=False, set_bs=False) -> tuple[bytes, ...]:
    """Native DataSize/count and fixed sixteen-byte ANSI records; no Unicode guess."""
    if type(data) is not bytes or not 0 <= len(data) <= 4128:
        raise CommonResponseError(3)
    header = 8 if mixed or set_bs else 9 if data[5:8] == b"\x62\xf1\x81" else 8
    if len(data) < header + 16 or len(data) != header + data[header - 1] * 16:
        raise CommonResponseError(3)
    return tuple(
        value
        for offset in range(header, len(data), 16)
        if (value := data[offset : offset + 16].split(b"\0", 1)[0])
    )


def _native_cancel(runtime):
    runtime.check()
    result = runtime.native_cancelled()
    runtime.check()
    if type(result) is not bool:
        raise ValueError("Native cancellation callback must return Boolean")
    return result


def _driver(error):
    if isinstance(error, NativePassThruError2026):
        return error.passthru_status
    if isinstance(error, NativeJ2534Exception2026):
        return error.j2534_error
    if isinstance(error, NativeTransportError):
        return error.code
    return None


def run_native_context(context: P5GetterContext2026, runtime: NativeRuntime2026):
    """Source entrypoints1180/1fe0/1fb0; vector pointer and BOOL out stay separate."""
    if not isinstance(context, P5GetterContext2026) or not isinstance(
        runtime, NativeRuntime2026
    ):
        raise TypeError("Typed native getter context/runtime required")
    if runtime.native_cancelled is None or runtime.owns_resource("disconnect"):
        raise ValueError(
            "Bound native cancellation and exclusive connection scope required"
        )
    diag = CanDiag2026(runtime)
    mixed = context.identity.module_name == MIXED
    set_bs = context.identity.module_name == SET_BS
    cids, query_ids, history, filters = [], [], [], []
    failure = None
    host_failure = None
    completed = False

    def native_call(*args, **options):
        try:
            return diag.call(*args, **options)
        except NativeException2026 as error:
            if isinstance(error, NativePassThruException2026):
                raise
            raise CommonResponseError(9999) from error

    def exchange(address):
        request, response = address.headers()
        identifier = diag.start_filter(request, response)
        filters.append(identifier)
        try:
            if _native_cancel(runtime):
                return None
            return native_call(
                request,
                response,
                b"\x22\xf1\x81",
                None,
                error_code=3,
                phase5=True,
                pending_limit=0xB4,
                busy_limit=0x159A,
                check_native_cancel=True,
            )
        finally:
            runtime.release("stop_filter", identifier=identifier)

    try:
        runtime.call_owned("connect", "disconnect", protocol=6)
        runtime.call("set_timeout", milliseconds=context.receive_timeout_ms)
        if set_bs:
            runtime.call_owned(
                "control_io",
                "control_io",
                ioctl=2,
                parameters=((0x1E, 1),),
                release_values={"ioctl": 2, "parameters": ((0x1E, 0),)},
            )
        for index, original in enumerate(context.addresses):
            # Native mixed/BS always use two bytes; plain P5 respects extension.
            address = (
                NativeCommunicationAddress(original.request[:2], original.response[:2])
                if mixed or set_bs
                else original
            )
            phase5 = not mixed or index == 0
            start = len(cids)
            try:
                if not phase5:
                    # Secondary phase4 owns one filter across support probe and CID.
                    request, response = address.headers()
                    identifier = diag.start_filter(request, response)
                    filters.append(identifier)
                    try:
                        if _native_cancel(runtime):
                            payload = None
                        else:
                            try:
                                probe = native_call(
                                    request, response, b"\x09\x00", None, error_code=3
                                )
                            except (
                                NativePassThruError2026,
                                NativeJ2534Exception2026,
                                NativeTransportError,
                            ) as error:
                                if _driver(error) not in (9, 16):
                                    raise
                                raise CommonResponseError(3) from error
                            if len(probe) != 6 or not probe[2] & 0x30:
                                raise CommonResponseError(3)
                            payload = native_call(
                                request,
                                response,
                                b"\x09\x04",
                                None,
                                error_code=3,
                                check_native_cancel=True,
                            )
                    finally:
                        runtime.release("stop_filter", identifier=identifier)
                else:
                    payload = exchange(address)
                if payload is not None:
                    _, response = address.headers()
                    if not phase5:
                        data = response + payload
                        if len(data) < 23 or len(data) != 7 + data[6] * 16:
                            raise CommonResponseError(3)
                        decoded = tuple(
                            v
                            for i in range(7, len(data), 16)
                            if (v := data[i : i + 16].split(b"\0", 1)[0])
                        )
                    else:
                        decoded = decode_p5_cids2026(
                            response + payload, mixed=mixed, set_bs=set_bs
                        )
                    if len(cids) + len(decoded) > 4096:
                        raise ValueError("Host CID vector capacity exceeded")
                    cids.extend(decoded)
                if phase5:
                    # Preserve '!' records; remove '#' at byte10 only when no '!' exists.
                    cids[start:] = [
                        v for v in cids[start:] if b"!" in v or v[10:11] != b"#"
                    ]
                    if len(cids) == start:
                        raise CommonResponseError(3)
                query_ids.extend(
                    address.request for _ in range(start, min(len(cids), 34))
                )
                history.append(address)
            except (
                NativePassThruError2026,
                NativeJ2534Exception2026,
                NativeTransportError,
            ) as error:
                if (
                    mixed
                    or _driver(error) not in (9, 16)
                    or address.request != context.timeout_allowing_id
                ):
                    raise
        completed = True
    except (
        NativePassThruError2026,
        NativeTransportError,
        NativeException2026,
        CommonResponseError,
    ) as error:
        failure = error
    except (Exception, KeyboardInterrupt) as error:  # noqa: BLE001 - release resources before propagating host failure
        host_failure = error
    cleanup_errors = []
    if set_bs and runtime.owns_resource("control_io", ioctl=2, parameters=((0x1E, 0),)):
        try:
            runtime.release("control_io", ioctl=2, parameters=((0x1E, 0),))
        except (Exception, KeyboardInterrupt) as error:  # noqa: BLE001 - attempt all native releases
            cleanup_errors.append(error)
    if any(runtime.owns_resource("stop_filter", identifier=i) for i in filters):
        cleanup_errors.append(OSError("Native getter filter release did not complete"))
    if runtime.owns_resource("disconnect"):
        try:
            runtime.release("disconnect")
        except (Exception, KeyboardInterrupt) as error:  # noqa: BLE001 - attempt all native releases
            cleanup_errors.append(error)
    if host_failure is not None:
        for error in cleanup_errors:
            host_failure.add_note("Getter cleanup failure: " + type(error).__name__)
        raise host_failure
    if cleanup_errors:
        raise OSError("Native getter cleanup incomplete") from cleanup_errors[0]
    runtime.check()
    return {
        "state": "read_completed" if completed else "failed",
        "native_return": None,
        "native_result": completed,
        "bool_out": completed,
        "cids": tuple(cids),
        "query_ids": tuple(query_ids),
        "history": tuple(history),
        "native_error_code": failure.native_error_code
        if isinstance(failure, (NativePassThruError2026, NativePassThruException2026))
        else failure.code
        if isinstance(failure, CommonResponseError)
        else 1
        if isinstance(failure, NativeTransportError)
        else None,
        "driver_error_code": _driver(failure),
        "programming_completed": False,
    }
