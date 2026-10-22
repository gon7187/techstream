"""Source-bound CUW2026 K-line primitives; no native execution or device discovery."""

from __future__ import annotations

import hashlib
import re
import time
from collections.abc import Callable, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from functools import wraps
from types import MappingProxyType
from typing import NoReturn
from weakref import WeakValueDictionary

from scripts.native_modules import NativeModuleIdentity, identify_native_module
from scripts.programming import NativeTransportError
from scripts.programming_2026_common import (
    CommonResponseError,
    NativeBytes2026,
    NativeException2026,
    NativeJ2534Exception2026,
    NativeParameterBinding2026,
    NativePassThruException2026,
    NativeRuntime2026,
    j2534_indication,
    native_parameter_long2026,
    select_retry_password,
)


def bind_sil_identity(module: bytes, name: str) -> NativeModuleIdentity:
    """Authenticate the actual protected or inspection module before dispatch."""
    if not isinstance(module, bytes) or not 1 <= len(module) <= 64 * 1024 * 1024:
        raise ValueError("Bounded immutable native module bytes required")
    identity = identify_native_module(hashlib.sha256(module).hexdigest(), name)
    if identity.cuw_build != "2026" or not identity.module_name.startswith("TCUWSil"):
        raise ValueError("Exact2026 SIL module identity required")
    return identity


def sil_prepare(identity: NativeModuleIdentity) -> bool:
    """Native SIL prepare RVA1000 is literally mov al,1;ret and performs no I/O."""
    if (
        not isinstance(identity, NativeModuleIdentity)
        or identity.cuw_build != "2026"
        or identity.module_name != "TCUWSilPrepareWriter.dll"
    ):
        raise ValueError("Authenticated2026 SIL prepare identity required")
    authenticated = identify_native_module(identity.sha256, identity.module_name)
    if authenticated != identity:
        raise ValueError("Forged SIL identity")
    return True


def ecu_kind(code: str) -> int:
    """RVA1380 compares native CalibrationFile literals0/1, else enum3."""
    if not isinstance(code, str) or len(code) > 259:
        raise ValueError("Bounded native ECU kind string required")
    return 0 if code == "0" else 2 if code == "1" else 3


def physical_address(communication: int, ecu_kind: int) -> int:
    """CSilDiagCommUtils::GetPhysicalAddress, recovered2026 RVA13d0."""
    if any(
        type(value) is not int or not 0 <= value <= 3
        for value in (communication, ecu_kind)
    ):
        raise ValueError("Native communication and ECU-kind enums required")
    value = bytes.fromhex("10131013000019191616001600000000")[
        communication + ecu_kind * 4
    ]
    if value == 0:
        raise LookupError("Native physical address is unavailable for these enums")
    return value


def sil_message(
    payload: bytes, target: int, source: int, *, explicit_length: bool = False
) -> bytes:
    """Native three-byte SIL header and additive checksum, with extended length."""
    if not isinstance(payload, bytes) or not 1 <= len(payload) <= 255:
        raise ValueError("One to255 immutable SIL payload bytes required")
    if any(
        type(value) is not int or not 0 <= value <= 255 for value in (target, source)
    ):
        raise ValueError("Byte target and source required")
    if type(explicit_length) is not bool:
        raise ValueError("Boolean explicit length required")
    # Native callers select the length representation; do not infer another format.
    if not explicit_length and len(payload) > 63:
        raise ValueError("Compact SIL length exceeds six bits")
    header = bytes((0x80 if explicit_length else 0x80 | len(payload), target, source))
    message = header + (bytes((len(payload),)) if explicit_length else b"") + payload
    return message + bytes((sum(message) & 255,))


def sil_j2534_action(device):
    """Adapt the actual J2534Device2026 primitive API to native SIL operations."""
    from scripts.j2534_2026 import J2534Device2026, NativeMessage

    if not isinstance(device, J2534Device2026):
        raise TypeError("Actual J2534Device2026 primitive adapter required")

    def action(event: dict, remaining: float):
        name = event["operation"]
        if name == "connect":
            if (
                device.device_id is not None
                or device.opened
                or device.channel_id is not None
                or device.connecting
            ):
                raise ValueError(
                    "SIL getter acquisition owns an unopened native device lifecycle"
                )
            try:
                device.primitive(event, remaining)
                if device.channel_id is None:
                    raise ValueError("Native connection did not acquire a channel")
                return device.channel_id
            except (Exception, KeyboardInterrupt) as error:
                try:
                    device.disconnect()
                except (Exception, KeyboardInterrupt) as cleanup_error:  # noqa: BLE001 - preserve primary error
                    error.add_note(
                        "Native SIL connection rollback: "
                        + type(cleanup_error).__name__
                    )
                raise
        if name == "ioctl":
            ioctl = event["ioctl"]
            if ioctl == 4:
                return device.primitive(
                    {"operation": "five_baud_init", "data": event["input"]}, remaining
                )
            if ioctl == 5:
                message = device.primitive(
                    {"operation": "fast_init", "data": event["input"], "tx_flags": 0},
                    remaining,
                )
                if not isinstance(message, NativeMessage):
                    raise TypeError("Actual native FAST_INIT message required")
                return {
                    "data": message.data,
                    "rx_status": message.rx_status,
                    "can_frame_padding": device.padding,
                }
            return device.primitive(
                {
                    "operation": "control_io",
                    "ioctl": ioctl,
                    "parameters": event.get("config", ()),
                },
                remaining,
            )
        if name == "write_messages":
            return device.primitive({**event, "protocol": 3, "tx_flags": 0}, remaining)
        if name in ("read_messages", "wrap_read_messages"):
            device.deadline = min(device.deadline, device.clock() + remaining)
            # ReadMsgs4840 discards ReadIndication4630, then WrapReadMsgs4887.
            # The FAST_INIT drain invokes WrapReadMsgs directly, without indication.
            messages = (
                device.read_after_indication()
                if name == "read_messages"
                else device.read_messages()
            )
            return messages[0].data if messages else b""
        return device.primitive(event, remaining)

    return action


class _NativeSILCancel(Exception):
    """Native ALL return: callback retains buffer; post-memset faults return empty."""

    def __init__(self, response: bytes):
        super().__init__("Native SIL callback branch")
        self.response = response


@contextmanager
def _sil_cleanup_scope(cleanup: Callable[[], None]):
    primary = None
    try:
        yield
    except BaseException as error:
        primary = error
        raise
    finally:
        try:
            cleanup()
        except BaseException as error:
            if isinstance(error, (NativeException2026, CommonResponseError)):
                error.__dict__.pop("_sil_abi_token", None)
            if primary is None or isinstance(
                primary,
                (
                    NativeException2026,
                    CommonResponseError,
                    NativeTransportError,
                    SILInitialCommandError,
                ),
            ):
                raise
            primary.add_note(f"SIL cleanup failed: {type(error).__name__}")


class SILChannel(NativeRuntime2026):
    """Primitive J2534 actions, absolute deadline and bounded pending reception.

    action accepts an operation dictionary and remaining seconds. It performs
    only IOCTL/read/write/timeout primitives; business outcomes are decoded here.
    """

    def __init__(
        self,
        action: Callable[[dict, float], object],
        *,
        timeout: float = 30,
        cancelled: Callable[[], bool] = lambda: False,
        clock: Callable[[], float] = time.monotonic,
        native_cancelled: Callable[[], bool] = lambda: False,
        max_calls: int = 65536,
    ):
        super().__init__(
            action,
            timeout=timeout,
            cancelled=cancelled,
            clock=clock,
            cleanup_timeout=30,
            native_cancelled=native_cancelled,
            max_calls=max_calls,
        )

    def call(self, operation: str, *, cleanup: bool = False, **values):
        try:
            return super().call(operation, cleanup=cleanup, **values)
        except NativeTransportError as error:
            _sil_rethrow_transport(error, 1)

    def acquire(
        self,
        operation: str,
        release_operation: str,
        *,
        release_key: str = "identifier",
        **values,
    ) -> int:
        try:
            return super().acquire(
                operation, release_operation, release_key=release_key, **values
            )
        except NativeTransportError as error:
            _sil_rethrow_transport(error, 1)

    def native_cancel_requested(self) -> bool:
        self.check()
        if self.native_cancelled is None:
            raise ValueError("Source native cancellation callback12 must be bound")
        try:
            result = self.native_cancelled()
        except NativeTransportError as error:
            _sil_rethrow_transport(error, 1)
        finally:
            self.check()
        if type(result) is not bool:
            raise ValueError("Native cancellation callback12 must return Boolean")
        self.check()
        return result

    def remaining(self) -> float:
        return self.check()

    def host(self, operation: str, **parameters):
        return self.call(operation, **parameters)

    def _void(self, operation: str, **parameters) -> None:
        if self.host(operation, **parameters) is not None:
            raise ValueError("Native void primitive returned a value")

    def five_baud_init(self) -> None:
        """RVA12e0: FIVE_BAUD_INIT33 with256-byte output capacity."""
        result = self.host("ioctl", ioctl=4, input=b"\x33", output_capacity=256)
        if not isinstance(result, bytes) or len(result) > 256:
            raise ValueError("Malformed five-baud initialization output")

    def fast_init(
        self,
        target: int,
        source: int,
        communication: int,
        *,
        can_frame_padding: bool = False,
    ) -> None:
        """RVA1100: native P4_MIN/P5_MIN then FAST_INIT81 + checksum."""
        physical_address(communication, 0)
        if type(can_frame_padding) is not bool:
            raise ValueError("Native CAN padding flag required")
        request = sil_message(b"\x81", target, source)
        self._void(
            "ioctl", ioctl=2, config=((0x14, 0x23 if communication == 1 else 0x19),)
        )
        self._void("ioctl", ioctl=2, config=((0x15, 0x32),))
        response = self.host("ioctl", ioctl=5, input=request, output_capacity=4152)
        if not isinstance(response, dict) or set(response) not in (
            {"data", "rx_status"},
            {"data", "rx_status", "can_frame_padding"},
        ):
            raise ValueError("Typed FAST_INIT response required")
        can_frame_padding = response.get("can_frame_padding", can_frame_padding)
        if type(can_frame_padding) is not bool:
            raise ValueError("Native CAN padding flag required")
        data, rx_status = response["data"], response["rx_status"]
        if not isinstance(data, bytes) or len(data) > 4128:
            raise ValueError("Malformed FAST_INIT response")
        if j2534_indication(rx_status, can_frame_padding) != 3:
            wrapped = self.host("wrap_read_messages", count=1)
            if not isinstance(wrapped, bytes) or len(wrapped) > 4128:
                raise ValueError("Malformed wrapped SIL initialization message")

    def _read(self) -> bytes:
        result = self.host("read_messages", count=1)
        if not isinstance(result, bytes) or not 0 <= len(result) <= 4128:
            raise ValueError("Malformed SIL J2534 message")
        return result

    def receive(
        self,
        request: bytes,
        *,
        minimum: int,
        header: bytes = b"",
        payload_prefix: bytes = b"",
        pending_limit: int = 0,
        header_length: int = 3,
        error_code: int = 9999,
        check_native_cancel: bool = False,
        initial_response: bytes = b"",
    ) -> bytes:
        """RVA14a0: pending7f/SID/78, exact header/body-prefix validation.

        Timeout is restored even after malformed responses, cancellation or an
        IO fault. Cleanup has an independent bounded allowance.
        """
        if not isinstance(request, bytes) or not 4 <= len(request) <= 4128:
            raise ValueError("SIL request including header required")
        if type(header_length) is not int or header_length not in (3, 4):
            raise ValueError("Native SIL header length must be three or four")
        if len(request) <= header_length:
            raise ValueError("SIL request lacks service byte")
        if type(minimum) is not int or not 0 <= minimum <= 4128:
            raise ValueError("Bounded SIL minimum required")
        if (
            not isinstance(header, bytes)
            or len(header) > 4128
            or not isinstance(payload_prefix, bytes)
            or len(payload_prefix) > 4125
        ):
            raise ValueError("Immutable bounded SIL response prefixes required")
        if type(pending_limit) is not int or not 0 <= pending_limit <= 65535:
            raise ValueError("Bounded SIL pending count required")
        if type(error_code) is not int or not 0 <= error_code <= 0xFFFFFFFF:
            raise ValueError("Native uint32 response error required")
        if not isinstance(initial_response, bytes) or len(initial_response) > 4128:
            raise ValueError("Bounded immutable native previous response required")
        if type(check_native_cancel) is not bool:
            raise ValueError("Native callback call-site flag must be Boolean")
        old = self.host("get_timeout")
        if type(old) is not int or not 0 <= old <= 0xFFFFFFFF:
            raise ValueError("Native uint32 timeout required")
        with _sil_cleanup_scope(lambda: self._restore_timeout(old)):
            try:
                response, _ = self._pending_response(
                    request,
                    header_length,
                    pending_limit,
                    old,
                    error_code,
                    sil_message(b"\x82", request[1], request[2]),
                    check_native_cancel,
                    initial_response,
                )
                if (
                    len(response) < minimum
                    or not response.startswith(header)
                    or not response[header_length:].startswith(payload_prefix)
                ):
                    raise CommonResponseError(error_code)
                return response
            except _NativeSILCancel as native_cancel:
                return native_cancel.response
            except (NativeTransportError, NativeJ2534Exception2026) as error:
                _sil_rethrow_transport(error, error_code)

    def _restore_timeout(self, old: int) -> None:
        result = self.call("set_timeout", milliseconds=old, cleanup=True)
        if result is not None:
            raise ValueError("Native timeout cleanup must return None")

    def _pending_response(
        self,
        request: bytes,
        header_length: int,
        pending_limit: int,
        old: int,
        error_code: int,
        stop: bytes = b"",
        check_native_cancel: bool = False,
        previous_response: bytes = b"",
    ) -> tuple[bytes, int]:
        response = previous_response
        try:
            for pending in range(pending_limit + 1):
                if check_native_cancel and self.native_cancel_requested():
                    raise _NativeSILCancel(response)
                response = b""  # Native memset precedes the driver read.
                response = self._read()
                if len(response) >= header_length + 3 and response[
                    header_length : header_length + 3
                ] == bytes((0x7F, request[header_length], 0x78)):
                    if pending == pending_limit:
                        if stop:
                            count = self.host("write_messages", data=stop, count=1)
                            if type(count) is not int or count != 1:
                                raise OSError("Partial or unproven SIL stop write")
                        raise CommonResponseError(error_code)
                    if old < 5000:
                        self._void("set_timeout", milliseconds=5000)
                    continue
                self._void("set_timeout", milliseconds=old)
                return response, pending
        except NativePassThruException2026:
            raise
        except NativeException2026 as error:
            raise _NativeSILCancel(response) from error
        raise AssertionError("Unreachable bounded SIL receive")

    def exchange(
        self,
        request: bytes,
        *,
        minimum: int,
        header: bytes = b"",
        payload_prefix: bytes = b"",
        pending_limit: int = 0,
        busy_limit: int = 0,
        wait_ms: int = 0,
        explicit_length: bool = False,
        stop_on_pending_limit: bool = False,
        error_code: int = 9999,
        check_native_cancel: bool = False,
    ) -> bytes:
        """RVA1960: write/wait/read; NRC21 resends, NRC78 only reads."""
        if not isinstance(request, bytes) or not 5 <= len(request) <= 4128:
            raise ValueError("Bounded complete SIL request required")
        if any(
            type(value) is not int or not 0 <= value <= 65535
            for value in (pending_limit, busy_limit)
        ):
            raise ValueError("Bounded native pending and busy limits required")
        if (
            type(wait_ms) is not int
            or not 0 <= wait_ms <= 0xFFFFFFFF
            or type(explicit_length) is not bool
            or type(stop_on_pending_limit) is not bool
        ):
            raise ValueError("Native wait and explicit length required")
        if type(minimum) is not int or not 0 <= minimum <= 4128:
            raise ValueError("Bounded SIL minimum required")
        if (
            not isinstance(header, bytes)
            or len(header) > 4128
            or not isinstance(payload_prefix, bytes)
            or len(payload_prefix) > 4125
        ):
            raise ValueError("Immutable bounded SIL response prefixes required")
        header_length = 4 if explicit_length else 3
        stop = (
            sil_message(
                b"\x82", request[1], request[2], explicit_length=explicit_length
            )
            if stop_on_pending_limit
            else b""
        )
        if type(error_code) is not int or not 0 <= error_code <= 0xFFFFFFFF:
            raise ValueError("Native uint32 response error required")
        if type(check_native_cancel) is not bool:
            raise ValueError("Native callback call-site flag must be Boolean")
        old = self.host("get_timeout")
        if type(old) is not int or not 0 <= old <= 0xFFFFFFFF:
            raise ValueError("Native uint32 timeout required")
        with _sil_cleanup_scope(lambda: self._restore_timeout(old)):
            try:
                busy = 0
                response = b""
                while True:
                    count = self.host("write_messages", data=request, count=1)
                    if type(count) is not int or count != 1:
                        raise OSError(
                            "Partial or unproven SIL write; outcome uncertain"
                        )
                    self._void("wait", milliseconds=wait_ms)
                    response, pending = self._pending_response(
                        request,
                        header_length,
                        pending_limit,
                        old,
                        error_code,
                        stop,
                        check_native_cancel,
                        response,
                    )
                    if pending:
                        busy = 0
                    if response[header_length : header_length + 3] == bytes(
                        (0x7F, request[header_length], 0x21)
                    ):
                        if busy == busy_limit:
                            raise CommonResponseError(error_code)
                        busy += 1
                        continue
                    if (
                        len(response) < minimum
                        or not response.startswith(header)
                        or not response[header_length:].startswith(payload_prefix)
                    ):
                        raise CommonResponseError(error_code)
                    return response
            except _NativeSILCancel as native_cancel:
                return native_cancel.response
            except (NativeTransportError, NativeJ2534Exception2026) as error:
                _sil_rethrow_transport(error, error_code)
            except NativePassThruException2026:
                raise
            except NativeException2026:
                return response


def _require_identity(identity: NativeModuleIdentity, name: str) -> None:
    if (
        not isinstance(identity, NativeModuleIdentity)
        or identity.cuw_build != "2026"
        or identity.module_name != name
        or identify_native_module(identity.sha256, name) != identity
    ):
        raise ValueError("Exact authenticated2026 SIL operation identity required")


def _sil_setup_timeout(channel: SILChannel, milliseconds: int, previous: int) -> None:
    """Native timeout setup precedes process EH; host abort still rolls it back."""
    try:
        channel._void("set_timeout", milliseconds=milliseconds)
    except (NativeException2026, CommonResponseError):
        raise
    except BaseException as error:
        try:
            channel._restore_timeout(previous)
        except BaseException as cleanup:  # noqa: BLE001 - preserve the original host abort.
            error.add_note(f"Timeout setup rollback failed: {type(cleanup).__name__}")
        raise


def _write(channel: SILChannel, data: bytes) -> None:
    count = channel.host("write_messages", data=data, count=1)
    if type(count) is not int or count != 1:
        raise OSError("Partial or unproven SIL write; outcome uncertain")


def _cid_fragments(
    channel: SILChannel,
    target: int,
    count: int,
    first: bytes | None,
    receive: Callable[[], bytes],
    collected: list[str],
) -> tuple[str, ...]:
    """CIDGetter1a20/1f00: four matching four-byte fragments per sixteen-byte CID."""
    if type(count) is not int or not 1 <= count <= 255 or count & 3:
        raise CommonResponseError(3)
    assembled = bytearray()
    result = []
    accepted = 0
    response = first
    while accepted < count:
        if channel.native_cancel_requested():
            return tuple(result)
        if response is None:
            response = receive()
        if len(response) > 9 and response[4] == 4 and response[2] == target:
            assembled.extend(response[6:10])
            accepted += 1
            if accepted % 4 == 0:
                result.append(bytes(assembled).split(b"\0", 1)[0].decode("latin1"))
                if len(collected) >= 4096:
                    raise ValueError("Host SIL identifier vector budget exceeded")
                collected.append(result[-1])
                assembled.clear()
        response = None
    channel._void("ioctl", ioctl=8, input=None, output=None)
    return tuple(result)


def _sil_cid_attempt(
    channel: SILChannel, communication: int, kind: int, collected: list[str]
) -> tuple[str, ...]:
    channel._void("ioctl", ioctl=8, input=None, output=None)
    try:
        target = physical_address(communication, kind)
    except LookupError as exc:
        raise CommonResponseError(3) from exc
    channel._void(
        "ioctl", ioctl=2, config=((1, 9600 if communication == 1 else 10400),)
    )
    if communication == 0:
        channel.five_baud_init()
    else:
        channel.fast_init(target, 0xF1, communication)
    if channel.native_cancel_requested():
        return ()
    channel._void("wait", milliseconds=100)
    if channel.native_cancel_requested():
        return ()
    if communication == 0:
        request = b"\x68\x6a\xf1\x09\x03"
        request += bytes((sum(request) & 255,))
        _write(channel, request)
        if channel.native_cancel_requested():
            return ()
        channel._void("wait", milliseconds=100)
        while True:
            if channel.native_cancel_requested():
                return ()
            response = channel._read()
            if len(response) < 6 or response[5] == 0 or response[5] & 3:
                raise CommonResponseError(3)
            if response[2] == target:
                count = response[5]
                break
        if channel.native_cancel_requested():
            return ()
        channel._void("wait", milliseconds=100)
        if channel.native_cancel_requested():
            return ()
        request = b"\x68\x6a\xf1\x09\x04"
        request += bytes((sum(request) & 255,))
        _write(channel, request)
        if channel.native_cancel_requested():
            return ()
        channel._void("wait", milliseconds=100)
        return _cid_fragments(channel, target, count, None, channel._read, collected)
    request = sil_message(b"\x09\x03", target, 0xF1)
    response = channel.exchange(
        request,
        minimum=0,
        pending_limit=149,
        busy_limit=255,
        wait_ms=100,
        stop_on_pending_limit=True,
        error_code=3,
        check_native_cancel=True,
    )
    while True:
        if channel.native_cancel_requested():
            return ()
        if len(response) < 6 or response[5] == 0 or response[5] & 3:
            raise CommonResponseError(3)
        if response[2] == target:
            count = response[5]
            break
        response = channel.receive(
            request,
            minimum=0,
            pending_limit=149,
            error_code=3,
            check_native_cancel=True,
            initial_response=response,
        )
    if channel.native_cancel_requested():
        return ()
    channel._void("wait", milliseconds=100)
    if channel.native_cancel_requested():
        return ()
    request = sil_message(b"\x09\x04", target, 0xF1)
    response = channel.exchange(
        request,
        minimum=0,
        pending_limit=149,
        busy_limit=255,
        wait_ms=100,
        stop_on_pending_limit=True,
        error_code=3,
        check_native_cancel=True,
    )
    latest = response

    def read_fragment():
        nonlocal latest
        latest = channel.receive(
            request,
            minimum=0,
            pending_limit=149,
            error_code=3,
            check_native_cancel=True,
            initial_response=latest,
        )
        return latest

    return _cid_fragments(channel, target, count, response, read_fragment, collected)


@dataclass
class SILCIDState2026:
    identifiers: list[str] = field(default_factory=list, repr=False)
    contact_type: str | None = None

    def extend(self, values: tuple[str, ...]):
        if len(self.identifiers) + len(values) > 4096:
            raise ValueError("Host SIL identifier vector budget exceeded")
        self.identifiers.extend(values)
        self.validate()

    def validate(self):
        if (
            not isinstance(self.identifiers, list)
            or len(self.identifiers) > 4096
            or any(
                not isinstance(value, str) or len(value) > 256
                for value in self.identifiers
            )
        ):
            raise ValueError("Bounded caller-owned native SIL CID vector required")


def _sil_cid_output(function):
    @wraps(function)
    def call(*args, **kwargs):
        state = kwargs.get("state")
        if state is None:
            state = SILCIDState2026()
            kwargs["state"] = state
        if not isinstance(state, SILCIDState2026):
            raise TypeError("Typed native SIL CID output vector required")
        state.validate()
        try:
            return function(*args, **kwargs)
        except (Exception, KeyboardInterrupt) as error:
            error.__dict__["sil_cid_state"] = state
            raise

    return call


@_sil_cid_output
def sil_cid(
    channel: SILChannel,
    identity: NativeModuleIdentity,
    kind_of_ecu: str,
    receive_timeout_ms: int,
    *,
    state: SILCIDState2026 | None = None,
) -> tuple[str, ...]:
    """CIDGetter1710+EH193e: protocol3, four fallback modes, disconnect on exit."""
    _require_identity(identity, "TCUWSilCIDGetter.dll")
    kind = ecu_kind(kind_of_ecu)
    if type(receive_timeout_ms) is not int or not 0 <= receive_timeout_ms <= 0xFFFFFFFF:
        raise ValueError("Native uint32 receive timeout required")
    if state is None:
        state = SILCIDState2026()
    state.validate()
    collected = state.identifiers
    channel._void("set_timeout", milliseconds=receive_timeout_ms)
    handle = None
    with _sil_cleanup_scope(
        lambda: (
            channel.release("disconnect", identifier=handle)
            if handle is not None
            else None
        )
    ):
        try:
            handle = channel.acquire("connect", "disconnect", protocol=3)
            channel._void("wait", milliseconds=1000)
            for communication in range(4):
                try:
                    _sil_cid_attempt(channel, communication, kind, collected)
                except (
                    NativeTransportError,
                    CommonResponseError,
                    NativePassThruException2026,
                ):
                    channel.remaining()
                    if communication == 3:
                        raise
                    continue
                if kind_of_ecu == "0" and communication in (2, 3):
                    try:
                        _sil_cid_attempt(channel, communication, 1, collected)
                    except (
                        NativeTransportError,
                        CommonResponseError,
                        NativePassThruException2026,
                    ):
                        # Native state4/18de swallows secondary ECT failure, retaining primary IDs.
                        channel.remaining()
                if channel.native_cancel_requested():
                    raise CommonResponseError(3)
                return tuple(collected)
            raise AssertionError("Unreachable native SIL fallback loop")
        except (NativeException2026, CommonResponseError) as error:
            error.__dict__["sil_cid_state"] = state
            error.__dict__["_sil_abi_token"] = channel.__dict__.get("_sil_abi_token")
            raise


def native_sil_cid_inputs(
    container, selection, *, node: int = 1, cpu_index: int = 0
) -> tuple[str, int]:
    """Actual CUW KindOfECU plus selected ReceiveTimeoutBeforeGetCID parameter."""
    from scripts.calibration_catalog import CalibrationSelection
    from scripts.programming_2026_common import native2026_metadata

    if not isinstance(selection, (CalibrationSelection, NativeParameterBinding2026)):
        raise TypeError("Native selected parameter row required")
    metadata = native2026_metadata(container, node=node, cpu_index=cpu_index)
    raw = selection.value("ReceiveTimeoutBeforeGetCID")
    if len(raw) > 259:
        raise ValueError("Native receive timeout parameter exceeds field bound")
    try:
        timeout_ms = int(raw, 10) if raw else 0
    except ValueError as exc:
        raise ValueError("Malformed native receive timeout parameter") from exc
    if not 0 <= timeout_ms <= 0xFFFFFFFF:
        raise ValueError("Native receive timeout parameter outside uint32")
    return metadata.vehicle.get("kindofecu", ""), timeout_ms


@_sil_cid_output
def sil_dcmprl_version(
    channel: SILChannel,
    identity: NativeModuleIdentity,
    kind_of_ecu: str,
    receive_timeout_ms: int,
    *,
    received_cid_count: int = 0,
    state: SILCIDState2026 | None = None,
) -> tuple[tuple[str, ...], str | None]:
    """VersionGetter15b0/1710:7000ms delay, C7/F1 session,21/26 or21/27."""
    _require_identity(identity, "TCUWSilDCMPRLVersionGetter.dll")
    ecu_kind(kind_of_ecu)
    if (
        type(receive_timeout_ms) is not int
        or not 0 <= receive_timeout_ms <= 0xFFFFFFFF
        or type(received_cid_count) is not int
        or not 0 <= received_cid_count <= 4096
    ):
        raise ValueError("Native timeout and observed CID count required")
    handle = None
    prl = kind_of_ecu == "8"
    contact = "SIL" if prl and received_cid_count == 0 else None
    assert state is not None

    def finished(values: tuple[str, ...]):
        state.extend(values)
        if contact is not None:
            state.contact_type = contact
        return tuple(state.identifiers), contact

    with _sil_cleanup_scope(
        lambda: (
            channel.release("disconnect", identifier=handle)
            if handle is not None
            else None
        )
    ):
        try:
            handle = channel.acquire("connect", "disconnect", protocol=3)
            channel._void("set_timeout", milliseconds=receive_timeout_ms)
            channel._void("wait", milliseconds=1000)
            for _ in range(14):
                channel._void("wait", milliseconds=500)
                if channel.native_cancel_requested():
                    return finished(())
            channel._void("ioctl", ioctl=2, config=((1, 10400),))
            channel.fast_init(0xC7, 0xF1, 3)
            if channel.native_cancel_requested():
                return finished(())
            channel._void("wait", milliseconds=100)
            if channel.native_cancel_requested():
                return finished(())
            sub = 0x27 if prl else 0x26
            response = channel.exchange(
                sil_message(bytes((0x21, sub)), 0xC7, 0xF1),
                minimum=6,
                payload_prefix=bytes((0x61, sub)),
                pending_limit=149,
                busy_limit=255,
                wait_ms=100,
                stop_on_pending_limit=True,
                error_code=3,
                check_native_cancel=True,
            )
            value = (
                response[5 : 5 + (5 if prl else 20)].split(b"\0", 1)[0].decode("latin1")
            )
            return finished((value,))
        except (NativeException2026, CommonResponseError) as error:
            error.__dict__["_sil_abi_token"] = channel.__dict__.get("_sil_abi_token")
            raise


@_sil_cid_output
def sil_dh_software_id(
    channel: SILChannel,
    identity: NativeModuleIdentity,
    target: int,
    conversion_records: bytes,
    receive_timeout_ms: int,
    *,
    state: SILCIDState2026 | None = None,
) -> tuple[str, ...]:
    """DHSoftwareIDGetter1dc0/1fe0/1ae0, actual14-byte conversion records."""
    _require_identity(identity, "TCUWSilDHSoftwareIDGetter.dll")
    if (
        type(target) is not int
        or not 0 <= target <= 255
        or type(receive_timeout_ms) is not int
        or not 0 <= receive_timeout_ms <= 0xFFFFFFFF
    ):
        raise ValueError("Native target byte and receive timeout required")
    if (
        not isinstance(conversion_records, bytes)
        or len(conversion_records) % 14
        or len(conversion_records) > 14 * 65536
    ):
        raise ValueError(
            "Bounded immutable fourteen-byte native conversion records required"
        )
    conversions = []
    for offset in range(0, len(conversion_records), 14):
        raw = conversion_records[offset + 2 : offset + 14]
        if b"\0" not in raw:
            raise ValueError("Native conversion string lacks bounded terminator")
        conversions.append(
            (
                int.from_bytes(conversion_records[offset : offset + 2], "little"),
                raw.split(b"\0", 1)[0].decode("latin1"),
            )
        )
    channel._void("set_timeout", milliseconds=receive_timeout_ms)
    handle = None
    with _sil_cleanup_scope(
        lambda: (
            channel.release("disconnect", identifier=handle)
            if handle is not None
            else None
        )
    ):
        try:
            handle = channel.acquire("connect", "disconnect", protocol=3)
            channel._void("ioctl", ioctl=2, config=((1, 10400),))
            channel.fast_init(target, 0xF0, 3)
            channel._void("wait", milliseconds=100)
            result = ()
            if not channel.native_cancel_requested():
                response = channel.exchange(
                    sil_message(b"\x1a", target, 0xF0),
                    minimum=7,
                    payload_prefix=b"\x5a",
                    pending_limit=99,
                    busy_limit=255,
                    wait_ms=100,
                    stop_on_pending_limit=True,
                    error_code=3,
                    check_native_cancel=True,
                )
                code = int.from_bytes(response.ljust(6, b"\0")[4:6], "big")
                result = tuple(
                    name for identifier, name in conversions if identifier == code
                )
                if not result:
                    raise CommonResponseError(3)
            assert state is not None
            state.extend(result)
            if channel.native_cancel_requested():
                raise CommonResponseError(3)
            return tuple(state.identifiers)
        except (NativeException2026, CommonResponseError) as error:
            error.__dict__["_sil_abi_token"] = channel.__dict__.get("_sil_abi_token")
            raise


def native_sil_dh_inputs(
    container, selection, *, node: int = 1, cpu_index: int = 0
) -> tuple[int, int]:
    """DH1dc0 target comes from selected ECUTargetAddressForSIL, never an operator guess."""
    _, timeout_ms = native_sil_cid_inputs(
        container, selection, node=node, cpu_index=cpu_index
    )
    raw = selection.value("ECUTargetAddressForSIL")
    if not isinstance(raw, str) or len(raw) != 2:
        raise ValueError("Exact selected native SIL target byte required")
    try:
        target = bytes.fromhex(raw)
    except ValueError as exc:
        raise ValueError("Malformed native SIL target byte") from exc
    if len(target) != 1:
        raise ValueError("Exact selected native SIL target byte required")
    return target[0], timeout_ms


def sil_dcmprl_key(seed: bytes) -> bytes:
    """PrepareWriter1040's literal two-byte seed transformation, no stored key."""
    if not isinstance(seed, bytes) or len(seed) != 2:
        raise ValueError("Native two-byte DCMPRL seed required")
    return bytes(((seed[1] + 0x3B) & 255, (seed[1] + seed[0] + 0x13) & 255))


def sil_dcmprl_prepare(
    channel: SILChannel,
    identity: NativeModuleIdentity,
    cpu_type: str,
    kind_of_ecu: str,
    *,
    reset_requested: bool,
    prepare_status: int = 0,
    transfer: SILTransferState2026 | None = None,
) -> bool:
    """PrepareWriter14a0/1090/1350 over the caller-owned SIL connection."""
    _require_identity(identity, "TCUWSilDCMPRLPrepareWriter.dll")
    if (
        not isinstance(cpu_type, str)
        or len(cpu_type) > 259
        or not isinstance(kind_of_ecu, str)
        or len(kind_of_ecu) > 259
        or type(reset_requested) is not bool
        or type(prepare_status) is not int
        or not 0 <= prepare_status <= 0xFFFFFFFF
    ):
        raise ValueError(
            "Bounded native CPU/kind and observed preparation flags required"
        )
    if transfer is None:
        transfer = SILTransferState2026(
            status=prepare_status, reset_requested=reset_requested
        )
    transfer.validate()
    if transfer.status != prepare_status or transfer.reset_requested != reset_requested:
        raise ValueError(
            "Native preparation state differs from source-bound observations"
        )
    denso = cpu_type == "31"
    delay, inter = (50, 0) if denso else (100, 100)
    old = channel.host("get_timeout")
    if type(old) is not int or not 0 <= old <= 0xFFFFFFFF:
        raise ValueError("Native uint32 timeout required")
    _sil_setup_timeout(channel, 10000, old)
    native_completed = False
    native_caught = False
    with _sil_cleanup_scope(lambda: channel._restore_timeout(old)):
        try:
            channel._void("ioctl", ioctl=2, config=((1, 10400),))
            mode = 0 if denso else 5 if kind_of_ecu == "8" else 1
            channel._void("ioctl", ioctl=2, config=((0x0C, mode * 2),))
            if denso:
                channel._void("ioctl", ioctl=2, config=((0x0A, 2),))
            channel.fast_init(0xC7, 0xF1, 3)
            if reset_requested:
                if inter:
                    channel._void("wait", milliseconds=inter)
                channel.exchange(
                    sil_message(b"\x11\x01", 0xC7, 0xF1),
                    minimum=5,
                    payload_prefix=b"\x51\x01",
                    pending_limit=149,
                    busy_limit=255,
                    wait_ms=delay,
                    stop_on_pending_limit=True,
                    error_code=0x18,
                )
                channel._void("wait", milliseconds=15000)
                channel.fast_init(0xC7, 0xF1, 3)
            if inter:
                channel._void("wait", milliseconds=inter)
            response = channel.exchange(
                sil_message(b"\x27\x01", 0xC7, 0xF1),
                minimum=7,
                payload_prefix=b"\x67\x01",
                pending_limit=149,
                busy_limit=255,
                wait_ms=delay,
                stop_on_pending_limit=True,
                error_code=0x10,
            )
            key = sil_dcmprl_key(response.ljust(7, b"\0")[5:7])
            if inter:
                channel._void("wait", milliseconds=inter)
            channel.exchange(
                sil_message(b"\x27\x02" + key, 0xC7, 0xF1),
                minimum=5,
                payload_prefix=b"\x67\x02",
                pending_limit=149,
                busy_limit=255,
                wait_ms=delay,
                stop_on_pending_limit=True,
                error_code=0x11,
            )
            native_completed = True
            return transfer.reset_requested or transfer.status == 1
        except (NativeException2026, CommonResponseError) as error:
            native_caught = True
            error.__dict__["_sil_abi_token"] = channel.__dict__.get("_sil_abi_token")
            if isinstance(error, (NativePassThruException2026, CommonResponseError)):
                transfer.record_error(error)
            else:
                transfer.error = 9999
            transfer.status = 1
            raise
        finally:
            if (native_completed or native_caught) and transfer.status == 1:
                transfer.reset_requested = True


def native_sil_dcmprl_prepare_inputs(
    container, *, node: int = 1, cpu_index: int = 0
) -> tuple[str, str]:
    from scripts.calibration_2026 import (
        native2026_cpu_type,
        native2026_global_cpu_index,
    )
    from scripts.programming_2026_common import native2026_metadata

    metadata = native2026_metadata(container, node=node, cpu_index=cpu_index)
    return native2026_cpu_type(
        metadata, native2026_global_cpu_index(metadata)
    ), metadata.vehicle.get("kindofecu", "")


def _dcmprl_blocks(cpu_type: str, image: bytes) -> tuple[tuple[int, int, int], ...]:
    """FlashWriter1220/2110: source offset, actual fixed target, byte size."""
    if (
        not isinstance(cpu_type, str)
        or len(cpu_type) > 259
        or not isinstance(image, bytes)
        or not 0 < len(image) <= 64 * 1024 * 1024
    ):
        raise ValueError("Bounded native CPU type and materialized image required")
    sizes = (
        (1024,) * 4 + (4, 256)
        if cpu_type == "34"
        else (1024,) * (len(image) // 1024)
        + ((len(image) % 1024,) if len(image) % 1024 else ())
    )
    if len(sizes) > 65536:
        raise ValueError("Host SIL block count exceeded")
    base = {"32": 0x6000, "33": 0x80000, "34": 0x400000}.get(cpu_type, 0)
    offset = 0
    result = []
    for index, size in enumerate(sizes):
        extra = (
            (0x300E if index == 4 else 0x31FC if index == 5 else 0)
            if cpu_type == "34"
            else 0
        )
        if offset + extra + size > len(image) or base + extra + offset + size > 1 << 24:
            raise ValueError(
                "Native SIL block exceeds materialized data or uint24 address"
            )
        result.append((offset + extra, base + extra + offset, size))
        offset += size
    return tuple(result)


def sil_dcmprl_write(
    channel: SILChannel,
    identity: NativeModuleIdentity,
    cpu_type: str,
    kind_of_ecu: str,
    image: bytes,
    wait_end_ms: int,
    *,
    flash_size: int | None = None,
    progress: SILProgress2026 | None = None,
    transfer: SILTransferState2026 | None = None,
) -> int:
    """FlashWriter1620: erase, native blocks/download/transfer/checksum, verify/reset."""
    _require_identity(identity, "TCUWSilDCMPRLFlashWriter.dll")
    ecu_kind(kind_of_ecu)
    blocks = _dcmprl_blocks(cpu_type, image)
    actual_size = (
        4356 if cpu_type == "34" else len(image) if flash_size is None else flash_size
    )
    if progress is None:
        progress = SILProgress2026(actual_size)
    elif progress.flash_size != actual_size:
        raise ValueError(
            "DCM progress size differs from actual native archive/PIC constant"
        )
    if (
        type(wait_end_ms) is not int
        or not 0 <= wait_end_ms <= 120000
        or wait_end_ms % 500
    ):
        raise ValueError("Bounded native500ms end-of-flashing countdown required")
    delay, inter = (50, 0) if cpu_type == "31" else (100, 100)
    if transfer is None:
        transfer = SILTransferState2026()
    transfer.validate()
    old = channel.host("get_timeout")
    if type(old) is not int or not 0 <= old <= 0xFFFFFFFF:
        raise ValueError("Native uint32 timeout required")

    def command(payload: bytes, expected: bytes, minimum: int, code: int) -> bytes:
        if inter:
            channel._void("wait", milliseconds=inter)
        return channel.exchange(
            sil_message(payload, 0xC7, 0xF1),
            minimum=minimum,
            payload_prefix=expected,
            pending_limit=149,
            busy_limit=255,
            wait_ms=delay,
            stop_on_pending_limit=True,
            error_code=code,
        )

    written = 0
    _sil_setup_timeout(channel, 10000, old)
    with _sil_cleanup_scope(lambda: channel._restore_timeout(old)):
        try:
            transfer.changed(channel, "wait_end_ms", wait_end_ms)
            transfer.changed(channel, "writing", True)
            rid = (0x201 if kind_of_ecu == "8" else 0x200).to_bytes(2, "big")
            command(b"\x31\x01" + rid, b"\x71\x01" + rid, 7, 0x19)
            for source, address, size in blocks:
                command(
                    b"\x34\x00\x33"
                    + address.to_bytes(3, "big")
                    + size.to_bytes(3, "big"),
                    b"\x74\x30",
                    8,
                    0x1A,
                )
                data = image[source : source + size]
                for sequence, offset in enumerate(range(0, size, 60), 1):
                    chunk = data[offset : offset + 60]
                    command(b"\x36" + bytes((sequence,)) + chunk, b"\x76", 5, 0x1B)
                    written += len(chunk)
                    progress.update(
                        channel,
                        progress.count + 2 * len(chunk),
                        2 * progress.flash_size,
                    )
                command(
                    b"\x37" + (sum(data) & 0xFFFF).to_bytes(2, "big"), b"\x77", 4, 0x1C
                )
            command(b"\x31\x02" + rid + b"\x01", b"\x71\x02" + rid + b"\x01", 8, 0x19)
            command(b"\x11\x01", b"\x51\x01", 5, 0x18)
            for _ in range(wait_end_ms // 500):
                channel._void("wait", milliseconds=500)
                transfer.changed(channel, "wait_end_ms", transfer.wait_end_ms - 500)
            transfer.changed(channel, "writing", False)
            return written
        except (NativeException2026, CommonResponseError) as error:
            error.__dict__["_sil_abi_token"] = channel.__dict__.get("_sil_abi_token")
            if isinstance(error, (NativePassThruException2026, CommonResponseError)):
                transfer.record_error(error)
            else:
                transfer.error = 9999
            transfer.status = 2
            if isinstance(error, (NativeException2026, CommonResponseError)):
                # Native1866 continuation clears count then percent and notifies.
                _sil_native_progress_reset(channel, progress)
            raise


def _hino_command(
    channel: SILChannel,
    payload: bytes,
    expected: bytes,
    minimum: int,
    code: int,
    *,
    explicit_length: bool = False,
    check_native_cancel: bool = False,
) -> bytes:
    return channel.exchange(
        sil_message(payload, 0x19, 0xF0, explicit_length=explicit_length),
        minimum=minimum,
        payload_prefix=expected,
        pending_limit=149,
        busy_limit=255,
        wait_ms=0,
        stop_on_pending_limit=True,
        error_code=code,
        explicit_length=explicit_length,
        check_native_cancel=check_native_cancel,
    )


@_sil_cid_output
def sil_hino_cid(
    channel: SILChannel,
    identity: NativeModuleIdentity,
    *,
    state: SILCIDState2026 | None = None,
) -> tuple[str, ...]:
    """HINOCIDGetterForAMT1780/15f0: literal target19/F0 and shared HINO primitives."""
    from scripts.programming_2026_legacy import (
        hino_extract_cid,
        hino_fast_init,
        hino_halt,
        hino_set_baud_rate,
        hino_tester_present_amt,
    )

    _require_identity(identity, "TCUWSilHINOCIDGetterForAMT.dll")
    channel._void("set_timeout", milliseconds=180000)
    handle = None
    with _sil_cleanup_scope(
        lambda: (
            channel.release("disconnect", identifier=handle)
            if handle is not None
            else None
        )
    ):
        try:
            handle = channel.acquire("connect", "disconnect", protocol=3)
            hino_set_baud_rate(channel, 10400)
            hino_fast_init(channel, 0x19, 0xF0)
            channel._void("wait", milliseconds=100)
            hino_tester_present_amt(channel, 0x19, 0xF0)
            value = ""
            if not channel.native_cancel_requested():
                response = _hino_command(
                    channel, b"\x1a\x81", b"\x5a\x03", 16, 3, check_native_cancel=True
                )
                value = hino_extract_cid(response.ljust(16, b"\0"), 5, 11)
                if not value:
                    raise CommonResponseError(3)
            assert state is not None
            state.extend((value,))
            hino_halt(channel, 0x19, 0xF0)
            if channel.native_cancel_requested():
                raise CommonResponseError(3)
            return tuple(state.identifiers)
        except (NativeException2026, CommonResponseError) as error:
            error.__dict__["_sil_abi_token"] = channel.__dict__.get("_sil_abi_token")
            raise


def sil_hino_prepare(
    channel: SILChannel,
    identity: NativeModuleIdentity,
    *,
    transfer: SILTransferState2026 | None = None,
) -> None:
    """HINOPrepareWriterForAMT14f0/1050/1640/13b0, caller-owned connection."""
    from scripts.programming_2026_legacy import (
        hino_fast_init,
        hino_set_baud_rate,
        hino_tester_present_amt,
    )

    _require_identity(identity, "TCUWSilHINOPrepareWriterForAMT.dll")
    if transfer is None:
        transfer = SILTransferState2026()
    transfer.validate()
    old = channel.host("get_timeout")
    if type(old) is not int or not 0 <= old <= 0xFFFFFFFF:
        raise ValueError("Native uint32 timeout required")
    _sil_setup_timeout(channel, 180000, old)
    with _sil_cleanup_scope(lambda: channel._restore_timeout(old)):
        try:
            hino_set_baud_rate(channel, 10400)
            hino_fast_init(channel, 0x19, 0xF0)
            channel._void("wait", milliseconds=100)
            hino_tester_present_amt(channel, 0x19, 0xF0)
            _hino_command(channel, b"\x10\x85\x02", b"\x50\x85", 5, 0x29)
            response = _hino_command(channel, b"\x27\x01", b"\x67\x01", 17, 0x10)
            key = bytes(value ^ 255 for value in response.ljust(17, b"\0")[5:17])
            _hino_command(channel, b"\x27\x02" + key, b"\x67\x02", 5, 0x11)
            _hino_command(channel, b"\x10\x85\x02", b"\x50\x85", 5, 0x29)
            _hino_command(
                channel, b"\x83\x03\x12\xfe\x02\xfe\x01", b"\xc3\x03", 5, 0x29
            )
        except (NativeException2026, CommonResponseError) as error:
            error.__dict__["_sil_abi_token"] = channel.__dict__.get("_sil_abi_token")
            if isinstance(error, (NativePassThruException2026, CommonResponseError)):
                transfer.record_error(error)
            else:
                transfer.error = 9999
            # Native15e9 reads the same notification968 retained by Start1770.
            transfer.status = 1 + int(transfer.writing)
            raise


def _hino_start(selection, name: str) -> int:
    from scripts.calibration_catalog import CalibrationSelection

    if not isinstance(selection, (CalibrationSelection, NativeParameterBinding2026)):
        raise TypeError("Actual selected native parameter row required")
    rows = (
        selection.lines(name)
        if isinstance(selection, NativeParameterBinding2026)
        else selection.value(name).splitlines()
    )
    if not 1 <= len(rows) <= 2 or not 2 <= len(rows[0]) <= 8 or len(rows[0]) % 2:
        raise ValueError("Native HINO start-address parameter missing or malformed")
    try:
        value = bytes.fromhex(rows[0])
    except ValueError as exc:
        raise ValueError("Malformed native HINO start-address byte string") from exc
    if len(value) * 2 != len(rows[0]):
        raise ValueError("Malformed native HINO start-address byte string")
    return int.from_bytes(value, "big")


def sil_hino_write(
    channel: SILChannel,
    identity: NativeModuleIdentity,
    sbl: bytes,
    image: bytes,
    selection,
    *,
    progress: SILProgress2026 | None = None,
    transfer: SILTransferState2026 | None = None,
) -> int:
    """HINOFlashWriterForAMT1050/1700/1970: SBL then data in128-byte packets."""
    from scripts.programming_2026_legacy import hino_halt

    _require_identity(identity, "TCUWSilHINOFlashWriterForAMT.dll")
    spans = (
        (sbl, _hino_start(selection, "SBLStartAddressSize")),
        (image, _hino_start(selection, "DATAStartAddressSize")),
    )
    for data, address in spans:
        if (
            not isinstance(data, bytes)
            or not 0 < len(data) <= 64 * 1024 * 1024
            or address + len(data) > 1 << 24
        ):
            raise ValueError(
                "Native HINO data exceeds materialized input or uint24 address"
            )
    if progress is None:
        progress = SILProgress2026(len(image))
    elif progress.flash_size != len(image):
        raise ValueError("HINO progress size differs from actual DATA archive length")
    if transfer is None:
        transfer = SILTransferState2026()
    transfer.validate()
    old = channel.host("get_timeout")
    if type(old) is not int or not 0 <= old <= 0xFFFFFFFF:
        raise ValueError("Native uint32 timeout required")
    written = 0
    _sil_setup_timeout(channel, 180000, old)
    with _sil_cleanup_scope(lambda: channel._restore_timeout(old)):
        try:
            for index, (data, address) in enumerate(spans):
                _hino_command(channel, b"\x34", b"\x74\x84", 5, 0x1A)
                for offset in range(0, len(data), 128):
                    chunk = data[offset : offset + 128]
                    _hino_command(
                        channel,
                        b"\x36" + (address + offset).to_bytes(3, "big") + chunk,
                        b"\x76",
                        5,
                        0x1B,
                        explicit_length=True,
                    )
                    written += len(chunk)
                    if index == 1:
                        progress.update(channel, offset + len(chunk), len(image))
                _hino_command(channel, b"\x37", b"\x77", 4, 0x1C)
                # Native expected DataSize4 compares only71; subfunction is outside it.
                _hino_command(channel, b"\x31\x02", b"\x71", 4, 0x59)
                if index == 0:
                    _hino_command(channel, b"\x31\x01", b"\x71", 4, 0x5A)
                    transfer.changed(channel, "writing", True)
                    channel._void("wait", milliseconds=1000)
            hino_halt(channel, 0x19, 0xF0)
            transfer.changed(channel, "writing", False)
            return written
        except (NativeException2026, CommonResponseError) as error:
            error.__dict__["_sil_abi_token"] = channel.__dict__.get("_sil_abi_token")
            if isinstance(error, (NativePassThruException2026, CommonResponseError)):
                transfer.record_error(error)
            else:
                transfer.error = 9999
            if isinstance(error, (NativeException2026, CommonResponseError)):
                # Native118a resets arrays/callbacks, then reads notification968.
                _sil_native_progress_reset(channel, progress)
                transfer.status = 1 + int(transfer.writing)
            raise


@dataclass
class SILProgress2026:
    """Native per-CPU transfer count/percent slots, observed after each packet."""

    flash_size: int
    count: int = 0
    percent: int = 0
    observer: Callable[[str, int], None] | None = field(default=None, repr=False)

    def __post_init__(self):
        if (
            type(self.flash_size) is not int
            or not 0 < self.flash_size <= 64 * 1024 * 1024
            or type(self.count) is not int
            or not 0 <= self.count <= 0xFFFFFFFF
            or type(self.percent) is not int
            or self.observer is not None
            and not callable(self.observer)
        ):
            raise ValueError(
                "Bounded native SIL progress slots and optional observer required"
            )

    def update(self, channel: SILChannel, count: int, denominator: int):
        channel.check()
        self.count = count & 0xFFFFFFFF
        if self.observer is not None:
            self.observer("count", self.count)
        channel.check()
        self.percent = int(self.count / denominator * 100)
        if self.observer is not None:
            self.observer("percent", self.percent)
        channel.check()

    def packet(self, channel: SILChannel, size: int):
        self.update(channel, self.count + size, 2 * self.flash_size)

    def reset(self, channel: SILChannel):
        self.update(channel, 0, 2 * self.flash_size)


def _sil_native_progress_reset(channel: SILChannel, progress: SILProgress2026) -> None:
    try:
        progress.reset(channel)
    except (NativeException2026, CommonResponseError) as error:
        error.__dict__.pop("_sil_abi_token", None)
        raise  # These EH-state-minus-one cleanup callbacks are outside the catch.


def _sil_rethrow_transport(error, value: int) -> NoReturn:
    from scripts.j2534_2026 import NativeJ2534Error2026, NativePassThruError2026

    if isinstance(error, NativePassThruError2026) and not isinstance(
        error, NativeJ2534Error2026
    ):
        code = error.native_error_code
        code = code if code < 0x80000000 else code - 0x100000000
        raise NativePassThruException2026(code, "J2534Device2026", 0) from error
    value = value if value < 0x80000000 else value - 0x100000000
    if isinstance(error, NativeJ2534Exception2026):
        error.set_error(value)
        raise error
    driver = error.code if error.code < 0x80000000 else error.code - 0x100000000
    native = NativeJ2534Exception2026(driver, "J2534Device2026", 0)
    native.set_error(value)
    raise native from error


def _sil_error_boundary(code):
    """Native CJ2534 catch: change the business enum, retain driver detail."""

    def decorate(function):
        @wraps(function)
        def call(*args, **kwargs):
            from scripts.programming import NativeTransportError

            value = (
                code.get(args[1] if len(args) > 1 else kwargs.get("operation"), 0)
                if isinstance(code, dict)
                else code
            )
            try:
                return function(*args, **kwargs)
            except (NativeJ2534Exception2026, NativeTransportError) as error:
                _sil_rethrow_transport(error, value)

        return call

    return decorate


class SILRawProgramming:
    """Generic SILFlashWriter's unframed serial byte protocol, not KWP exchange."""

    def __init__(self, channel: SILChannel, progress: SILProgress2026 | None = None):
        if not isinstance(channel, SILChannel):
            raise TypeError("Actual SIL primitive channel required")
        if progress is not None and not isinstance(progress, SILProgress2026):
            raise TypeError("Typed native SIL progress required")
        self.channel, self.progress = channel, progress
        self.detected_shrink: bool | None = None

    def read_exact(self, length: int) -> bytes:
        if type(length) is not int or not 0 <= length <= 4128:
            raise ValueError("Bounded native serial byte count required")
        result = bytearray()
        while len(result) < length:
            data = self.channel.host("read_messages", count=1)
            if not isinstance(data, bytes) or len(data) > 4128:
                raise ValueError("Malformed native serial read")
            # Native2970 discards bytes beyond the remaining requested count.
            result.extend(data[: length - len(result)])
        return bytes(result)

    def ack(self) -> bool:
        from scripts.programming import NativeTransportError

        while True:
            try:
                data = self.channel.host("read_messages", count=1)
            except (NativeTransportError, NativeJ2534Exception2026) as exc:
                driver = (
                    exc.j2534_error
                    if isinstance(exc, NativeJ2534Exception2026)
                    else exc.code
                )
                if driver in (9, 16):
                    return False
                raise
            if not isinstance(data, bytes) or len(data) > 4128:
                raise ValueError("Malformed native serial acknowledgement")
            if data and data[0] == 0x3C:
                return True

    def status(self, retry: bool = True) -> int:
        from scripts.programming import NativeTransportError

        if type(retry) is not bool:
            raise ValueError("Native status retry flag required")
        attempts = 4 if retry else 1
        for attempt in range(attempts):
            if attempt:
                self.channel._void("wait", milliseconds=10)
            _write(self.channel, b"\x50")
            try:
                response = self.read_exact(3)
            except (
                NativeTransportError,
                NativePassThruException2026,
                CommonResponseError,
            ):
                if attempt + 1 == attempts:
                    raise
                continue
            if response[0] == 0x3C and response[2] == 0x3C:
                return response[1]
        raise CommonResponseError(4)

    def handshake(self, mode: int = 0) -> None:
        if type(mode) is not int or not 0 <= mode <= 255:
            raise ValueError("Native serial mode byte required")
        _write(self.channel, b"\x60")
        first = self.read_exact(1)
        if first != b"\x3c":
            # Native initial-command exception codes are distinct from PassThru.
            raise SILInitialCommandError(1 if first == b"\xff" else 2)
        _write(self.channel, bytes((mode,)))
        if not self.ack():
            raise CommonResponseError(5)
        self.channel._void("wait", milliseconds=100)
        _write(self.channel, b"\x05")
        if not self.ack():
            raise CommonResponseError(5)

    @_sil_error_boundary(7)
    def initialize(self, location: bytes, password: int) -> None:
        """GenericFlash15e0:70/80 timing, ten-byte FAST_INIT, then3c."""
        if (
            not isinstance(location, bytes)
            or len(location) != 4
            or type(password) is not int
            or not 0 <= password <= 0xFFFFFFFF
        ):
            raise ValueError(
                "Actual four-byte CUW location and uint32 password required"
            )
        self.channel._void("ioctl", ioctl=2, config=((0x14, 70),))
        self.channel._void("ioctl", ioctl=2, config=((0x15, 80),))
        response = self.channel.host(
            "ioctl",
            ioctl=5,
            input=b"\0\0" + location[::-1] + password.to_bytes(4, "little"),
            output_capacity=4152,
        )
        if (
            not isinstance(response, dict)
            or set(response)
            not in ({"data", "rx_status"}, {"data", "rx_status", "can_frame_padding"})
            or not isinstance(response["data"], bytes)
            or len(response["data"]) > 4128
        ):
            raise ValueError("Malformed native serial FAST_INIT output")
        padding = response.get("can_frame_padding", False)
        if type(padding) is not bool:
            raise ValueError("Native CAN padding flag required")
        if j2534_indication(response["rx_status"], padding) != 3:
            wrapped = self.channel.host("wrap_read_messages", count=1)
            if not isinstance(wrapped, bytes) or len(wrapped) > 4128:
                raise ValueError("Malformed wrapped native serial initialization")
        _write(self.channel, b"\x3c")

    @_sil_error_boundary({"blank": 11, "erase": 12, "inverify": 14})
    def block_command(
        self, operation: str, first: int, last: int, *, wide: bool
    ) -> bool:
        from scripts.programming_vendor import common_block_request

        # Actual2026 SIL1470/1880/26f0/2fb0 proves these pure bytes equal the shared codec.
        codes = {"blank": (0x10, 0x0B), "erase": (0x80, 0x0C), "inverify": (0x40, 0x0E)}
        request = common_block_request(
            operation, first, last if wide else first, wide=wide
        )
        if operation not in codes:
            raise ValueError("Native polling block operation required")
        pending, error = codes[operation]
        _write(self.channel, request)
        if not self.ack():
            raise CommonResponseError(error)
        while True:
            self.channel._void("wait", milliseconds=10)
            status = self.status()
            if status != pending:
                break
        if operation == "blank":
            return status == 0
        if status:
            raise CommonResponseError(error)
        return True

    def _data_packet(self, data: bytes) -> None:
        if not isinstance(data, bytes) or not 1 <= len(data) <= 260:
            raise ValueError("Bounded native serial programming packet required")
        self.channel._void("set_send_timeout", milliseconds=10000)
        try:
            _write(self.channel, data)
        finally:
            value = self.channel.call(
                "set_send_timeout", milliseconds=1000, cleanup=True
            )
            if value is not None:
                raise ValueError("Native serial send-timeout cleanup must return None")
        if self.progress is not None:
            self.progress.packet(self.channel, 256)

    @_sil_error_boundary(13)
    def write_group(self, data: bytes, address: int) -> int:
        """GenericFlash3400/38b0: four256-byte packets per1024-byte burst."""
        if (
            not isinstance(data, bytes)
            or not 1024 <= len(data) <= 64 * 1024 * 1024
            or len(data) % 1024
            or type(address) is not int
            or not 0 <= address < 1 << 24
            or address + len(data) > 1 << 24
        ):
            raise ValueError(
                "Actual complete1024-byte native group and uint24 address required"
            )
        for burst in range(0, len(data), 1024):
            _write(self.channel, b"\x41" if burst == 0 else b"\x45")
            if not self.ack():
                raise CommonResponseError(0x0D)
            for offset in range(burst, burst + 1024, 256):
                prefix = address.to_bytes(3, "big") + b"\xff" if offset == 0 else b""
                self._data_packet(prefix + data[offset : offset + 256])
            self.channel._void("set_timeout", milliseconds=2000)
            self.ack()
            self.channel._void("set_timeout", milliseconds=1000)
            while True:
                self.channel._void("wait", milliseconds=5)
                status = self.status()
                if status != 0x40:
                    break
            if status:
                raise CommonResponseError(0x0D)
        return len(data)

    @_sil_error_boundary(15)
    def verify_group(self, data: bytes, first: int, last: int, *, wide: bool) -> None:
        from scripts.programming_vendor import common_block_request

        request = common_block_request(
            "verify", first, last if wide else first, wide=wide
        )
        if (
            not isinstance(data, bytes)
            or not data
            or len(data) % 256
            or len(data) > 64 * 1024 * 1024
        ):
            raise ValueError(
                "Actual complete256-byte native verification group required"
            )
        _write(self.channel, request)
        if not self.ack():
            raise CommonResponseError(0x0F)
        for offset in range(0, len(data), 256):
            _write(self.channel, data[offset : offset + 256])
            if self.progress is not None:
                self.progress.packet(self.channel, 256)
            self.ack()
            status = 0
            while True:
                self.channel._void("wait", milliseconds=5)
                from scripts.programming import NativeTransportError

                try:
                    status = self.status(retry=offset + 256 == len(data))
                except (
                    NativeTransportError,
                    NativePassThruException2026,
                    CommonResponseError,
                ):
                    if offset + 256 == len(data):
                        raise
                    break  # Native3344 retains the last successfully read status.
                if status != 0x20:
                    break
            if status:
                raise CommonResponseError(0x0F)


class SILInitialCommandError(OSError):
    def __init__(self, code: int):
        self.code = code
        super().__init__(f"Native SIL initial-command error {code}")


def _sil_raw_memory(
    raw: SILRawProgramming,
    shrink: bool,
    detect_32bh: bool,
    *,
    parse_descriptor: bool = True,
):
    from scripts.programming_2026_common import extract_memory_info

    if detect_32bh and raw.detected_shrink is None:
        _write(raw.channel, b"\x75")
        try:
            response = raw.read_exact(10)
        except (NativeException2026, CommonResponseError):
            # Native23dc catches the first read only, then zeroes the marker.
            response = bytes(11)
        if response[0] == response[-1] == 0x3C:
            shrink = False
        else:
            _write(raw.channel, b"\x76")
            response = raw.read_exact(11)
            if response[0] != 0x3C or response[-1] != 0x3C:
                raise CommonResponseError(10)
            shrink = True
    else:
        if detect_32bh:
            shrink = bool(raw.detected_shrink)
        _write(raw.channel, b"\x76" if shrink else b"\x75")
        response = raw.read_exact(11 if shrink else 10)
        if response[0] != 0x3C or response[-1] != 0x3C:
            raise CommonResponseError(10)
    # NativeSIL2290 passes exactly8 bytes even for the11-byte shrink reply.
    if detect_32bh:
        raw.detected_shrink = shrink
    return extract_memory_info(response[1:9]) if parse_descriptor else None, shrink


def _sil_parameters(selection) -> dict[str, str]:
    from scripts.calibration_catalog import CalibrationSelection

    if not isinstance(selection, (CalibrationSelection, NativeParameterBinding2026)):
        raise TypeError("Actual selected native parameter row required")
    result = {
        name: selection.value(name)
        for name in (
            "BlockSizeInfo",
            "CPUIDNo",
            "ShrinkFlag",
            "32BHFlag",
            "AlternateCPUType",
        )
    }
    if any(not isinstance(value, str) or len(value) > 259 for value in result.values()):
        raise ValueError("Native SIL parameter field bound exceeded")
    for name in ("ShrinkFlag", "32BHFlag"):
        result[name] = "1" if native_parameter_long2026(result[name]) else "0"
    return result


def _sil_geometry(parameters, memory, image: bytes | None = None):
    from scripts.programming_2026_common import (
        block_ranges_from_info,
        calc_block_sizes,
        complete_block_info,
        native_block_info,
    )

    info = complete_block_info(native_block_info(parameters), memory)
    sizes = calc_block_sizes(info)
    ranges = block_ranges_from_info(info)
    groups = []
    for first, last in ranges:
        if not 1 <= first <= last <= len(sizes):
            raise ValueError("Native SIL range exceeds actual block-size table")
        offset = sum(sizes[: first - 1])
        size = (last - first + 1) * sizes[first - 1]
        if (
            size != sum(sizes[first - 1 : last])
            or size % 1024
            or (image is not None and offset + size > len(image))
            or memory.start_address + offset + size > 1 << 24
        ):
            raise ValueError("Native SIL group exceeds actual image/address bounds")
        groups.append((first, last, offset, size))
    return sizes, tuple(groups)


def _sil_bootstrap(
    raw: SILRawProgramming, parameters, shrink: bool, detect_32bh: bool
) -> bool:
    """GenericFlash2c90 assembly: three baud candidates, literal100-step loops."""
    from scripts.programming import NativeTransportError

    previous_initial_failure = False
    for baud_index, baud in enumerate((9600, 9800, 10000)):
        try:
            raw.channel._void("ioctl", ioctl=2, config=((1, baud),))
            attempt, first_attempt_count = 0, 0
            while attempt < 100:
                if attempt == 0:
                    first_attempt_count += 1
                try:
                    raw.handshake()
                except SILInitialCommandError as exc:
                    if (
                        exc.code == 1
                        and attempt == 0
                        and baud_index > 0
                        and first_attempt_count < 2
                        and previous_initial_failure
                    ):
                        continue
                    previous_initial_failure = True
                    raise CommonResponseError(5) from exc
                previous_initial_failure = False
                attempt += 1
            memory = None
            for index in range(100):
                observed, shrink = _sil_raw_memory(
                    raw, shrink, detect_32bh, parse_descriptor=index == 0
                )
                if index == 0:
                    memory = observed
            _, groups = _sil_geometry(parameters, memory)
            first, last, _, _ = groups[0]
            for _ in range(100):
                try:
                    raw.block_command("blank", first, last, wide=shrink)
                except (
                    CommonResponseError,
                    NativePassThruException2026,
                    NativeTransportError,
                ):
                    # Native2f59 covers only the blank-check stage, then outer2efe retries baud.
                    _write(raw.channel, b"\x05")
                    raw.read_exact(1)
                    raise
            return shrink
        except (
            CommonResponseError,
            NativePassThruException2026,
            NativeTransportError,
        ) as exc:
            raw.channel.remaining()
            if baud_index == 2:
                raise CommonResponseError(0x15) from exc
    raise AssertionError("Unreachable native SIL bootstrap loop")


@dataclass
class SILTransferState2026:
    use_new_password: bool = False
    writing: bool = False
    last_block: bool = False
    error: int = 0
    j2534_error: int = 0
    wait_end_ms: int = 0
    status: int = 0
    reset_requested: bool = False
    cpu_type_override: str | None = None
    metadata_state: object | None = field(default=None, repr=False)
    engine: object | None = field(default=None, repr=False)
    _block_phase: bool = field(default=False, init=False, repr=False)
    _active_progress: SILProgress2026 | None = field(
        default=None, init=False, repr=False
    )
    observer: Callable[[str, int | bool], None] | None = field(default=None, repr=False)

    def changed(self, channel: SILChannel, name: str, value: int | bool):
        channel.check()
        self.__dict__[name] = value
        if self.observer is not None:
            self.observer(name, value)
        channel.check()

    def record_error(self, error):
        if isinstance(error, NativeJ2534Exception2026):
            self.error, self.j2534_error = error.error, error.j2534_error
        elif isinstance(error, NativePassThruException2026):
            self.error = error.error
        elif isinstance(error, CommonResponseError):
            self.error = error.code

    def validate(self):
        if (
            type(self.wait_end_ms) is not int
            or not 0 <= self.wait_end_ms <= 0xFFFFFFFF
            or self.observer is not None
            and not callable(self.observer)
        ):
            raise ValueError(
                "Bounded native countdown and optional state observer required"
            )
        if any(
            type(value) is not bool
            for value in (
                self.use_new_password,
                self.writing,
                self.last_block,
                self.reset_requested,
            )
        ) or any(
            type(value) is not int or not -0x80000000 <= value <= 0x7FFFFFFF
            for value in (self.error, self.j2534_error, self.status)
        ):
            raise ValueError("Typed native SIL transfer flags and error slots required")


def _sil_write_native(
    channel: SILChannel,
    identity: NativeModuleIdentity,
    image: bytes,
    location: bytes,
    password: int,
    selection,
    kind_of_ecu: str,
    contact_type: str,
    *,
    flash_size: int | None = None,
    progress: SILProgress2026 | None = None,
    transfer: SILTransferState2026 | None = None,
) -> dict:
    """GenericSILFlash1a10 over literal2026 serial primitives and FlashWriterUtils."""
    from scripts.programming_2026_common import (
        check_cpu_type_from_firmware,
        native_block_info,
    )

    _require_identity(identity, "TCUWSilFlashWriter.dll")
    parameters = _sil_parameters(selection)
    if not native_block_info(parameters):
        raise ValueError("Actual native SIL BlockSizeInfo rows required")
    if (
        not isinstance(image, bytes)
        or not 0 < len(image) <= 64 * 1024 * 1024
        or not isinstance(location, bytes)
        or len(location) != 4
        or type(password) is not int
        or not 0 <= password <= 0xFFFFFFFF
    ):
        raise ValueError(
            "Actual bounded materialized CPU image, location and password required"
        )
    ecu_kind(kind_of_ecu)
    if not isinstance(contact_type, str) or not 1 <= len(contact_type) <= 128:
        raise ValueError("Actual native contact type required")
    configured_shrink = parameters["ShrinkFlag"] == "1"
    detect_32bh = parameters["32BHFlag"] == "1"
    shrink = False if detect_32bh else configured_shrink
    actual_flash_size = len(image) if flash_size is None else flash_size
    if progress is None:
        progress = SILProgress2026(actual_flash_size)
    elif progress.flash_size != actual_flash_size:
        raise ValueError("Progress flash size differs from actual native archive")
    raw = SILRawProgramming(channel, progress)
    assert transfer is not None
    transfer._active_progress = progress
    if transfer is not None and transfer.engine is not None:
        from scripts.cuw_2026 import CUWEngine2026

        if (
            type(transfer.engine) is not CUWEngine2026
            or not isinstance(selection, NativeParameterBinding2026)
            or transfer.engine.source_sha256 != selection.metadata.source_sha256
        ):
            raise ValueError(
                "Source-bound actual CUW engine mutation capability required"
            )
    channel._void("ioctl", ioctl=2, config=((1, 9600),))
    channel._void("ioctl", ioctl=2, config=((0x0C, 0),))
    raw.initialize(location, password)
    shrink = _sil_bootstrap(raw, parameters, shrink, detect_32bh)
    raw.handshake()
    memory, shrink = _sil_raw_memory(raw, shrink, detect_32bh)
    assert memory is not None
    cpu_type = ""
    if detect_32bh and shrink != configured_shrink:
        cpu_type = parameters["AlternateCPUType"]
        assert transfer is not None
        transfer.cpu_type_override = cpu_type
        if transfer.engine is not None:
            from scripts.calibration_2026 import native2026_global_cpu_index
            from scripts.cuw_2026 import CUWEngine2026

            assert isinstance(transfer.engine, CUWEngine2026)
            transfer.engine.apply_cpu_type(
                native2026_global_cpu_index(selection.metadata), cpu_type
            )
        try:
            if isinstance(selection, NativeParameterBinding2026):
                selection = selection.reselect_alternate_cpu()
                assert transfer is not None
                transfer.metadata_state = selection.metadata
            else:
                selection = selection.catalog.select_metadata(
                    kind_of_ecu, cpu_type, contact_type, stage="write"
                )
        except LookupError as exc:
            raise CommonResponseError(10) from exc
        assert transfer is not None
        parameters = _sil_parameters(selection)
    if not check_cpu_type_from_firmware(memory.firmware_version, parameters, shrink):
        raise CommonResponseError(10)
    transfer._block_phase = True  # Native1d04 enters the block-scope EH states5..9.
    _, groups = _sil_geometry(parameters, memory, image)
    progress.reset(channel)
    assert transfer is not None
    transfer.changed(channel, "writing", True)
    written, verified = 0, 0
    for index, (first, last, offset, size) in enumerate(groups):
        transfer.changed(channel, "last_block", index + 1 == len(groups))
        if kind_of_ecu == "63" or not raw.block_command(
            "blank", first, last, wide=shrink
        ):
            raw.block_command("erase", first, last, wide=shrink)
        data = image[offset : offset + size]
        written += raw.write_group(data, memory.start_address + offset)
        raw.block_command("inverify", first, last, wide=shrink)
        raw.verify_group(data, first, last, wide=shrink)
        verified += size
    transfer.changed(channel, "writing", False)
    return {
        "bytes_written": written,
        "bytes_verified": verified,
        "alternate_cpu_type": cpu_type,
        "shrink": shrink,
        "memory_start": memory.start_address,
        "memory_end": memory.end_address,
        "count": progress.count,
        "percent": progress.percent,
    }


def sil_write(
    channel: SILChannel,
    identity: NativeModuleIdentity,
    image: bytes,
    location: bytes,
    password: int,
    selection,
    kind_of_ecu: str,
    contact_type: str,
    *,
    flash_size: int | None = None,
    progress: SILProgress2026 | None = None,
    use_new_password: bool = False,
    transfer: SILTransferState2026 | None = None,
) -> dict:
    """Native1a10 controller flags, error slots and raw programming operation."""
    if type(use_new_password) is not bool:
        raise ValueError("Actual native use-new-password flag required")
    if transfer is None:
        transfer = SILTransferState2026(use_new_password=use_new_password)
    transfer.validate()
    if transfer.use_new_password != use_new_password:
        raise ValueError("Native transfer flag differs from source-bound observation")
    native_caught = False
    native_completed = False
    transfer._block_phase, transfer._active_progress = False, None
    try:
        result = _sil_write_native(
            channel,
            identity,
            image,
            location,
            password,
            selection,
            kind_of_ecu,
            contact_type,
            flash_size=flash_size,
            progress=progress,
            transfer=transfer,
        )
        native_completed = True
        return result
    except NativeJ2534Exception2026 as error:
        native_caught = True
        error.__dict__["_sil_abi_token"] = channel.__dict__.get("_sil_abi_token")
        transfer.error, transfer.j2534_error = error.error, error.j2534_error
        raise
    except NativePassThruException2026 as error:
        native_caught = True
        error.__dict__["_sil_abi_token"] = channel.__dict__.get("_sil_abi_token")
        transfer.error = error.error
        raise
    except CommonResponseError as error:
        native_caught = True
        error.__dict__["_sil_abi_token"] = channel.__dict__.get("_sil_abi_token")
        transfer.error = error.code
        raise
    except SILInitialCommandError as error:
        native_caught = True
        transfer.error = 5
        converted = CommonResponseError(5)
        converted.__dict__["_sil_abi_token"] = channel.__dict__.get("_sil_abi_token")
        raise converted from error
    except NativeException2026 as error:
        native_caught = True
        error.__dict__["_sil_abi_token"] = channel.__dict__.get("_sil_abi_token")
        # Native CException reaches ALL220e ->2178 without changing error slots.
        raise
    finally:
        if native_caught or native_completed:
            transfer.use_new_password = False
        if native_caught:
            if transfer._block_phase:
                assert transfer._active_progress is not None
                _sil_native_progress_reset(channel, transfer._active_progress)
                transfer.status = 2
            else:
                transfer.status = 1
            transfer.use_new_password = select_retry_password(
                transfer.last_block, transfer.error, False
            )


def native_sil_image_password(image: bytes, selection) -> int:
    """Actual CalibrationFile33c0 ASM: four image bytes, ByteOrder's low16 bits."""
    from scripts.calibration_catalog import CalibrationSelection

    if not isinstance(
        selection, (CalibrationSelection, NativeParameterBinding2026)
    ) or not isinstance(image, bytes):
        raise TypeError("Actual selected row and materialized native image required")
    text = selection.value("PasswordAddress")
    if not isinstance(text, str) or len(text) > 259 or len(text) % 2:
        raise ValueError(
            "Native CBytes PasswordAddress requires bounded complete pairs"
        )
    address = []
    for index in range(0, len(text), 2):
        pair = text[index : index + 2]
        if not re.fullmatch(r"[ \t\n\r\v\f]*[+-]?[0-9a-fA-F]+", pair):
            raise ValueError("Malformed native CBytes PasswordAddress pair")
        address.append(int(pair, 16) & 255)
    offset = NativeBytes2026(bytes(address)).unsigned(4)
    byte_order = native_parameter_long2026(selection.value("ByteOrder")) or 0
    if offset + 4 > len(image):
        raise ValueError("Native password extraction exceeds actual image")
    return int.from_bytes(
        image[offset : offset + 4], "big" if byte_order & 0xFFFF else "little"
    )


SIL_OPERATIONS = MappingProxyType(
    {
        "TCUWSilCIDGetter.dll": "cid",
        "TCUWSilPrepareWriter.dll": "prepare",
        "TCUWSilFlashWriter.dll": "write",
        "TCUWSilDCMPRLVersionGetter.dll": "dcmprl_version",
        "TCUWSilDCMPRLPrepareWriter.dll": "dcmprl_prepare",
        "TCUWSilDCMPRLFlashWriter.dll": "dcmprl_write",
        "TCUWSilDHSoftwareIDGetter.dll": "dh_software_id",
        "TCUWSilHINOCIDGetterForAMT.dll": "hino_cid",
        "TCUWSilHINOPrepareWriterForAMT.dll": "hino_prepare",
        "TCUWSilHINOFlashWriterForAMT.dll": "hino_write",
    }
)


@dataclass(frozen=True)
class SILContext:
    identity: NativeModuleIdentity
    calibration_sha256: str
    operation: str
    arguments: tuple = field(repr=False)
    keywords: Mapping = field(repr=False)

    def report(self) -> dict:
        return {
            "module": self.identity.module_name,
            "module_sha256": self.identity.sha256,
            "calibration_sha256": self.calibration_sha256,
            "operation": self.operation,
        }


_ISSUED_SIL_CONTEXTS: WeakValueDictionary[int, SILContext] = WeakValueDictionary()


def bind_context(
    container,
    node: int,
    observed_cids: tuple[str, ...],
    selection,
    identity: NativeModuleIdentity,
    attachments: Mapping[str, bytes],
    observations: Mapping,
) -> SILContext:
    """Resolve every operational value from authenticated identity and actual CUW fields."""
    from scripts.calibration_2026 import (
        native2026_archive,
        native2026_cpu_targets,
        native2026_cpu_values,
        native2026_global_cpu_index,
    )
    from scripts.calibration_catalog import SelectionContext

    if (
        not isinstance(identity, NativeModuleIdentity)
        or identity.module_name not in SIL_OPERATIONS
    ):
        raise ValueError("Actual2026 SIL programming-family identity required")
    _require_identity(identity, identity.module_name)
    SelectionContext(observed_cids)
    if (
        not isinstance(selection, NativeParameterBinding2026)
        or not isinstance(attachments, Mapping)
        or not isinstance(observations, Mapping)
    ):
        raise TypeError(
            "Actual native selection, attachments and observations required"
        )
    if set(attachments) - {"id_conversion_records"} or set(observations) - {
        "cpu_index",
        "use_new_password",
        "reset_requested",
        "prepare_status",
        "received_cid_count",
    }:
        raise ValueError("SIL binding rejects manual geometry and undeclared overrides")
    cpu_index = observations.get("cpu_index", 0)
    operation = SIL_OPERATIONS[identity.module_name]
    stage = (
        "write"
        if operation in ("write", "dcmprl_write", "hino_write")
        else "prepare"
        if operation in ("prepare", "dcmprl_prepare", "hino_prepare")
        else "get_cid"
    )
    selection = selection.validate_against(
        container, operation=stage, node=node, cpu_index=cpu_index
    )
    metadata = selection.metadata
    cpu_values = native2026_cpu_values(metadata, native2026_global_cpu_index(metadata))
    if selection.module_name != identity.module_name:
        raise ValueError(
            "Actual native selected stage module differs from SIL identity"
        )
    kind = metadata.vehicle.get("kindofecu", "")
    args, kwargs = (), {}

    def archive(flash_code=False):
        value = native2026_archive(
            metadata,
            flash_code=flash_code,
            preserve_srecords=False
            if flash_code
            else bool(selection.parameter.boolean("FlagToHoldSFormatRecords")),
        )
        if value.data is None:
            raise ValueError(
                "SIL byte protocol requires actual materialized archive data"
            )
        return value

    def parameter_long(name):
        value = selection.parameter.long(name)
        return (value or 0) & 0xFFFFFFFF

    if operation == "cid":
        args = (kind, parameter_long("ReceiveTimeoutBeforeGetCID"))
    elif operation == "dcmprl_version":
        args = (kind, parameter_long("ReceiveTimeoutBeforeGetCID"))
        kwargs = {
            "received_cid_count": observations.get(
                "received_cid_count", len(observed_cids)
            )
        }
    elif operation == "dh_software_id":
        raw = selection.value("ECUTargetAddressForSIL")
        if len(raw) != 2 or any(c not in "0123456789abcdefABCDEF" for c in raw):
            raise ValueError("Actual selected ECUTargetAddressForSIL byte required")
        records = attachments.get("id_conversion_records", b"")
        if (
            not isinstance(records, bytes)
            or not records
            or len(records) % 14
            or len(records) > 14 * 65536
            or any(
                b"\0" not in records[offset + 2 : offset + 14]
                for offset in range(0, len(records), 14)
            )
        ):
            raise ValueError("Actual bounded14-byte ID conversion records required")
        args = (int(raw, 16), records, parameter_long("ReceiveTimeoutBeforeGetCID"))
    elif operation == "dcmprl_prepare":
        if (
            "reset_requested" not in observations
            or type(observations["reset_requested"]) is not bool
        ):
            raise ValueError("Actual native reset-request observation required")
        args = (cpu_values.get("cputype", ""), kind)
        kwargs = {
            "reset_requested": observations["reset_requested"],
            "prepare_status": observations.get("prepare_status", 0),
        }
    elif operation == "dcmprl_write":
        image = archive()
        assert image.data is not None
        kwargs["flash_size"] = image.flash_size
        args = (
            cpu_values.get("cputype", ""),
            kind,
            image.data,
            parameter_long("WaitTimeAfterEndOfFlashing"),
        )
        _dcmprl_blocks(args[0], image.data)
    elif operation == "hino_write":
        sbl, image = archive(True), archive()
        _hino_start(selection, "SBLStartAddressSize")
        _hino_start(selection, "DATAStartAddressSize")
        args = (sbl.data, image.data, selection)
    elif operation == "write":
        image = archive()
        assert image.data is not None
        raw_location = cpu_values.get("locationid", "")
        if (
            not 8 <= len(raw_location) <= 512
            or len(raw_location) % 2
            or any(c not in "0123456789abcdefABCDEF" for c in raw_location)
        ):
            raise ValueError("Actual four-byte native CUW LocationID required")
        if (
            "use_new_password" not in observations
            or type(observations["use_new_password"]) is not bool
        ):
            raise ValueError(
                "Actual native Transfer760 use-new-password observation required"
            )
        if observations["use_new_password"]:
            password = native_sil_image_password(image.data, selection)
        else:
            matches = [
                target.password
                for target in native2026_cpu_targets(metadata)
                if target.calibration in observed_cids
            ]
            if not matches or len(set(matches)) != 1:
                raise ValueError(
                    "Observed CID does not select one actual native target data"
                )
            password = matches[0]
        kwargs["flash_size"] = image.flash_size
        kwargs["use_new_password"] = observations["use_new_password"]
        args = (
            image.data,
            bytes.fromhex(raw_location)[:4],
            password,
            selection,
            kind,
            metadata.vehicle.get("contacttype", ""),
        )
    context = SILContext(
        identity, container.digest, operation, args, MappingProxyType(kwargs)
    )
    _ISSUED_SIL_CONTEXTS[id(context)] = context
    return context


def execute_context(
    context: SILContext,
    runtime: NativeRuntime2026,
    *,
    progress: SILProgress2026 | None = None,
    transfer: SILTransferState2026 | None = None,
    cid_state: SILCIDState2026 | None = None,
):
    """Execute the bound native family using this runtime's primitive provider only."""
    if not isinstance(context, SILContext) or not isinstance(
        runtime, NativeRuntime2026
    ):
        raise TypeError("Bound actual SIL context and primitive runtime required")
    if _ISSUED_SIL_CONTEXTS.get(id(context)) is not context:
        raise ValueError(
            "SIL execution requires the exact live source-binder-issued context"
        )
    _require_identity(context.identity, context.identity.module_name)
    if context.operation != SIL_OPERATIONS.get(context.identity.module_name):
        raise ValueError("SIL operation differs from authenticated module identity")
    if context.operation == "prepare":
        runtime.check()
        return sil_prepare(context.identity)
    runtime.check()
    if isinstance(runtime, SILChannel):
        channel = runtime
    else:
        # A protocol view shares the exact deadline, ownership and call budgets.
        # Constructing another runtime would reset those safety boundaries.
        channel = object.__new__(SILChannel)
        channel.__dict__ = runtime.__dict__
    runners = {
        "cid": sil_cid,
        "write": sil_write,
        "dcmprl_version": sil_dcmprl_version,
        "dcmprl_prepare": sil_dcmprl_prepare,
        "dcmprl_write": sil_dcmprl_write,
        "dh_software_id": sil_dh_software_id,
        "hino_cid": sil_hino_cid,
        "hino_prepare": sil_hino_prepare,
        "hino_write": sil_hino_write,
    }
    keywords = dict(context.keywords)
    if progress is not None:
        if context.operation not in ("write", "dcmprl_write", "hino_write"):
            raise ValueError("SIL packet progress supplied to an unsupported operation")
        keywords["progress"] = progress
    if transfer is not None:
        if context.operation not in (
            "write",
            "dcmprl_write",
            "hino_write",
            "dcmprl_prepare",
            "hino_prepare",
        ):
            raise ValueError("SIL transfer state supplied to an unsupported operation")
        keywords["transfer"] = transfer
    if cid_state is not None:
        if context.operation not in (
            "cid",
            "dcmprl_version",
            "dh_software_id",
            "hino_cid",
        ):
            raise ValueError("SIL CID vector supplied to a non-getter operation")
        cid_state.validate()
        # Each native StartGetCID clears its global vector before GetCIDProcess.
        # Inner communication retries retain partial output from this invocation.
        cid_state.identifiers.clear()
        keywords["state"] = cid_state
    return runners[context.operation](
        channel, context.identity, *context.arguments, **keywords
    )


@dataclass(frozen=True)
class SILExecutionResult2026:
    """Native export BOOL or getter out-BOOL, separate from internal results."""

    native_return: bool | None
    native_success: bool | None
    result: object = field(default=None, repr=False)
    native_error: NativeException2026 | CommonResponseError | None = field(
        default=None, repr=False
    )
    error_code: int | None = None
    j2534_error: int | None = None
    status: int | None = None
    use_new_password: bool | None = None


def execute_context_report(
    context: SILContext,
    runtime: NativeRuntime2026,
    *,
    progress: SILProgress2026 | None = None,
    transfer: SILTransferState2026 | None = None,
    cid_state: SILCIDState2026 | None = None,
) -> SILExecutionResult2026:
    """Apply the exact Start-export ABI; host failures remain host exceptions.

    Four getters return a vector pointer and write GetCIDProcess BOOL to param7.
    Six prepare/write exports return their process BOOL directly. Native catches
    leave that BOOL false; their normal end assigns true. Reset flags, byte counts
    and returned identifier vectors are independent of that source BOOL.
    """

    def report(native_return, native_success, result=None, error=None):
        enum = transfer.error if transfer is not None else None
        driver = transfer.j2534_error if transfer is not None else None
        if isinstance(error, NativePassThruException2026):
            enum = error.error
            if isinstance(error, NativeJ2534Exception2026):
                driver = error.j2534_error
        elif isinstance(error, CommonResponseError):
            enum = error.code
        elif isinstance(error, NativeException2026) and context.operation != "write":
            enum = 9999  # Nongeneric outer ALL handlers explicitly assign9999.
        return SILExecutionResult2026(
            native_return,
            native_success,
            result,
            error,
            enum,
            driver,
            transfer.status if transfer is not None else None,
            transfer.use_new_password if transfer is not None else None,
        )

    token = object()
    runtime.__dict__["_sil_abi_token"] = token
    try:
        result = execute_context(
            context, runtime, progress=progress, transfer=transfer, cid_state=cid_state
        )
    except (NativeException2026, CommonResponseError) as error:
        if error.__dict__.get("_sil_abi_token") is not token:
            raise  # Native setup/cleanup outside the process catch still propagates.
        if context.operation in ("cid", "dcmprl_version", "dh_software_id", "hino_cid"):
            output = error.__dict__.get("sil_cid_state", cid_state)
            partial = (
                tuple(output.identifiers) if isinstance(output, SILCIDState2026) else ()
            )
            return report(None, False, partial, error)
        return report(False, None, error=error)
    if context.operation in ("cid", "dcmprl_version", "dh_software_id", "hino_cid"):
        return report(None, True, result)
    return report(True, None, result)
