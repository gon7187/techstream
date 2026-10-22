"""Source-specific CUW2026 Unified/Ethernet software primitives.

Imports never open a transport. Providers implement individual J2534 operations;
security callbacks return key material, never a programming-success decision.
"""

import sys
import time
from collections.abc import Callable, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from types import MappingProxyType
from weakref import WeakValueDictionary

from scripts.calibration import CalibrationContainer
from scripts.calibration_2026 import Native2026Metadata, native2026_metadata
from scripts.cuw_large import NativeLargeContainer2026
from scripts.j2534_2026 import (
    NativeCommunicationAddress,
    communication_addresses_from_parameter,
)
from scripts.native_modules import NativeModuleIdentity, identify_native_module
from scripts.programming import NativeTransportError
from scripts.programming_2026_common import (
    CommonResponseError,
    NativeException2026,
    NativeJ2534Exception2026,
    NativeParameterBinding2026,
    NativePassThruException2026,
    NativeRuntime2026,
    SecretInfoClient,
    Unified2026,
    is_native_exception2026,
    native_error_fields2026,
)

ETHERNET_UTILS_SHA256 = (
    "04e4506ead85500b2639a0d01161321a48ab3e71e0d545a7391dc467d80cb492"
)
DEVICE_ADDRESS = bytes.fromhex("0E80")
FUNCTIONAL_ADDRESS = bytes.fromhex("E400")
ADS_ADDRESS = bytes.fromhex("0100")
ESW1_ADDRESS = bytes.fromhex("0103")


class NativeRestorationCancelled(InterruptedError):
    """Cancellation evidence does not assert that a vehicle session was restored."""

    def __init__(self, flow: str):
        super().__init__(
            "CUW2026 cancelled; charge-bus protocol restoration unconfirmed"
        )
        self.evidence = MappingProxyType(
            {
                "charge_flow": flow,
                "protocol_restored": False,
                "resource_cleanup_attempted": True,
            }
        )


def _bytes(value: object, minimum: int, maximum: int = 4128) -> bytes:
    if type(value) is not bytes or not minimum <= len(value) <= maximum:
        raise ValueError("Bounded immutable native message bytes required")
    return value


def _uint(value: object) -> int:
    if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
        raise ValueError("Native unsigned DWORD required")
    return value


def convert_specific_char(data: bytes, offset: int, length: int) -> bytes:
    """EthernetUtils RVA1540; NUL is retained, forbidden SU bytes become '_'."""
    _bytes(data, 0)
    _uint(offset)
    _uint(length)
    if offset > len(data) or length > len(data) - offset:
        raise ValueError("SU conversion span exceeds input")
    result = bytearray(data)
    for index in range(offset, offset + length):
        value = result[index]
        if value in (0x22, 0x5C, 0x2F) or value != 0 and not 0x20 <= value <= 0x7E:
            result[index] = 0x5F
    return bytes(result)


def parse_software_ids(data: bytes, *, ethernet: bool = False) -> tuple[bytes, ...]:
    """Actual2026 CID getters RVA1550/1580, full address-prefixed Data.

    Native C strings terminate at the first NUL; empty slots are skipped. Keeping
    bytes avoids inventing a character encoding for original calibration IDs.
    """
    _bytes(data, 0)
    if type(ethernet) is not bool:
        raise TypeError("Explicit native transport Boolean required")
    header = 8 if ethernet or data[5:8] != b"\x62\xf1\x81" else 9
    source = "EthernetCIDGetter" if ethernet else "UnifiedCIDGetter"
    if len(data) < header + 16:
        raise NativePassThruException2026(3, source, 0x255 if ethernet else 0x347)
    count = data[header - 1]
    if len(data) != header + 16 * count:
        raise NativePassThruException2026(3, source, 0x25D if ethernet else 0x34F)
    return tuple(
        slot.split(b"\0", 1)[0]
        for index in range(count)
        if (slot := data[header + index * 16 : header + (index + 1) * 16])[0]
    )


def ecu_information_dids(data: bytes) -> tuple[int, ...]:
    """EthernetCIDGetter RVA1d90 bit positions and exact native order."""
    offset = 9 if data[5:9] == b"\x71\x01\x10\0" else 8
    _bytes(data, 8)
    return tuple(
        did
        for position, bit, did in (
            (offset, 0x10, 1),
            (offset, 8, 0x11),
            (offset + 2, 0x10, 0x21),
            (offset + 2, 8, 0x31),
        )
        if (data[position] if position < len(data) else 0) & bit
    )


class EthernetUtils2026:
    """Actual2026 EthernetUtils primitives, with bounded host lifetimes.

    TCP reads return the native stripped message: source(2), target(2), payload.
    Writes retain the twelve-byte OEM DoIP wrapper. No socket is opened here.
    """

    def __init__(
        self,
        runtime: NativeRuntime2026,
        *,
        seconds_clock: Callable[[], int] | None = None,
    ):
        if not isinstance(runtime, NativeRuntime2026):
            raise TypeError("CUW2026 bounded runtime required")
        self.runtime = runtime
        self._channels: list[int] = [
            protocol
            for protocol in (0x8203, 0x8205, 0x8206)
            if runtime.owns_resource("logical_disconnect", protocol=protocol)
        ]
        self._periodic = runtime.owns_resource("stop_sync_periodic")
        if seconds_clock is not None and not callable(seconds_clock):
            raise TypeError("Native time-of-day seconds primitive required")
        self.seconds_clock = seconds_clock or runtime.local_seconds_of_day

    def __copy__(self):
        return type(self)(self.runtime, seconds_clock=self.seconds_clock)

    def assign(self, other: "EthernetUtils2026", *, move: bool = False):
        """Native1080/10a0/10c0 copy both pointers; move retains the source."""
        if type(other) is not type(self) or type(move) is not bool:
            raise TypeError(
                "Matching native Ethernet utility and move Boolean required"
            )
        self.__init__(other.runtime, seconds_clock=other.seconds_clock)
        return self

    @staticmethod
    def _local_seconds() -> int:
        value = time.localtime()
        return value.tm_hour * 3600 + value.tm_min * 60 + value.tm_sec

    def _seconds(self) -> int:
        value = self.seconds_clock()
        if type(value) is not int or not 0 <= value < 86400:
            raise ValueError("Native local day integer seconds required")
        return value

    @staticmethod
    def frame(target: bytes, payload: bytes) -> bytes:
        _bytes(target, 2, 2)
        _bytes(payload, 1, 4116)
        return (
            b"\x02\xfd\x80\x01"
            + (4 + len(payload)).to_bytes(4, "big")
            + DEVICE_ADDRESS
            + target
            + payload
        )

    def _write(self, operation: str, data: bytes, protocol: int = 0x8208) -> None:
        _bytes(data, 1)
        count = self.runtime.call(
            operation, protocol=protocol, tx_flags=1, data=data, count=1
        )
        if type(count) is not int or count != 1:
            raise ValueError("Native write must return exactly one message")

    @contextmanager
    def _timeout(self, milliseconds: int):
        old = _uint(self.runtime.call("get_timeout"))
        try:
            self.runtime.call("set_timeout", milliseconds=milliseconds)
            yield old
        finally:
            with _export_cleanup(native_return_unknown=False):
                self.runtime.call("set_timeout", milliseconds=old, cleanup=True)

    def check_link_up(self) -> bool:
        result = self.runtime.call(
            "control_io", ioctl=1, parameters=((0x8060, 0),), size=0x10
        )
        return _uint(result) == 1

    def link_up(self) -> None:
        with self._timeout(5000):
            self.runtime.call(
                "control_io", ioctl=2, parameters=((0x805F, 1),), size=0x10
            )
            _bytes(self.runtime.call("read_messages", protocol=0x800F, count=1), 0)

    def _connect(self, protocol: int, descriptor: bytes = b"") -> None:
        self.runtime.call_owned(
            "logical_connect",
            "logical_disconnect",
            release_values={"protocol": protocol},
            protocol=protocol,
            descriptor=descriptor,
        )
        self._channels.append(protocol)

    def _disconnect(self, protocol: int) -> None:
        self.runtime.release("logical_disconnect", protocol=protocol)
        self._channels.remove(protocol)

    def request_vehicle_identification(self) -> bytes:
        with self._timeout(2000):
            self._write(
                "queue_messages", bytes.fromhex("FFFFFFFF3458FF00000100000000"), 0x8205
            )
            data = _bytes(
                self.runtime.call("read_messages", protocol=0x8205, count=1), 4
            )
            return data[:4]

    def routing_activation(self) -> None:
        self._write(
            "queue_messages",
            bytes.fromhex("02FD000500000007") + DEVICE_ADDRESS + b"\0" * 5,
        )
        data = _bytes(self.runtime.call("read_tcp", count=1), 0)
        if len(data) != 9 or data[4] != 0x10:
            raise NativePassThruException2026(0x5D, "EthernetUtils", 0x205)

    def prepare_diag_comm(self) -> None:
        """RVA17e0/19f6; rollback owned logical channels on every failure."""
        if self._channels:
            raise ValueError("Ethernet logical channels already owned")
        try:
            if not self.check_link_up():
                self.link_up()
            self._connect(0x8203)
            self._connect(0x8205)
            self.runtime.call_owned(
                "logical_connect_udp_discovery", "logical_disconnect_udp_discovery"
            )
            try:
                descriptor = self.request_vehicle_identification()
            finally:
                with _export_cleanup(native_return_unknown=False):
                    self.runtime.release("logical_disconnect_udp_discovery")
            self._connect(0x8206, bytes(4) + descriptor + bytes(12))
            self.routing_activation()
        except BaseException:
            self.finish_diag_comm()
            raise

    def finish_diag_comm(self) -> tuple[str, ...]:
        """RVA1580/15d8/15f9 attempts 8206,8205,8203 even after a failure."""
        primary = sys.exception()
        errors = []
        for protocol in tuple(reversed(self._channels)):
            try:
                self._disconnect(protocol)
            except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - native attempts every disconnect
                errors.append(exc)
        if errors:
            failure = errors[0]
            for error in errors[1:]:
                failure.add_note(
                    "Additional logical cleanup failure: " + type(error).__name__
                )
            if primary is not None and not is_native_exception2026(primary):
                primary.add_note("Logical cleanup failure: " + type(failure).__name__)
                raise primary from failure
            raise failure
        return ()

    def send_functional(self, payload: bytes, *, synchronous: bool) -> None:
        if type(synchronous) is not bool:
            raise TypeError("Explicit native queue/write Boolean required")
        self._write(
            "write_tcp" if synchronous else "queue_messages",
            self.frame(FUNCTIONAL_ADDRESS, payload),
        )

    def start_sync_periodic(self, delay_ms: int, enabled: bool) -> None:
        _uint(delay_ms)
        if type(enabled) is not bool:
            raise TypeError("Explicit native periodic Boolean required")
        self.runtime.call_owned(
            "start_sync_periodic_0500",
            "stop_sync_periodic",
            data=self.frame(FUNCTIONAL_ADDRESS, b"\x3e\x80"),
            protocol=0x8208,
            tx_flags=1,
            interval_ms=2000,
            poll_ms=100,
            count=1,
            delay_ms=delay_ms,
            enabled=enabled,
        )
        self._periodic = True

    def stop_periodic(self) -> None:
        if self._periodic:
            self.runtime.release("stop_sync_periodic")
            self._periodic = False
        else:
            self.runtime.call("stop_sync_periodic")

    def send_request(
        self,
        target: bytes,
        payload: bytes,
        expected: bytes | None,
        *,
        minimum: int,
        error: int,
        pending_seconds: int = 180,
        udp_discovery: bool = False,
        check_native_cancel: bool = False,
    ) -> bytes:
        """RVA2020 address filtering, response-pending and literal prefix check.

        Host call budget and deadline additionally bound irrelevant responses.
        Native pending time uses local HH:MM:SS, discards milliseconds and
        adds24h only when the current hour precedes the starting hour.
        The runtime monotonic deadline independently bounds every primitive.
        """
        frame = self.frame(target, payload)
        if expected is not None:
            _bytes(expected, 0)
        _uint(minimum)
        _uint(pending_seconds)
        if (
            type(error) is not int
            or not 0 <= error <= 0x7FFFFFFF
            or type(udp_discovery) is not bool
        ):
            raise ValueError("Bounded native error and discovery Boolean required")
        if type(check_native_cancel) is not bool:
            raise TypeError("Native callback cancellation flag required")
        if check_native_cancel and self.runtime.native_cancelled is None:
            raise LookupError("Native caller cancellation callback is unavailable")
        pending_start = None
        previous = _uint(self.runtime.call("get_timeout"))
        retries = 0
        pending_retries = 0
        reconnected = False
        discovery_owned = False
        locked = False

        def lock():
            nonlocal locked
            if not locked:
                self.runtime.call_owned("lock", "unlock")
                locked = True

        def unlock():
            nonlocal locked
            if locked:
                self.runtime.release("unlock")
                locked = False

        def retry_read():
            nonlocal retries, pending_retries, reconnected, discovery_owned
            while True:
                lock()
                try:
                    return _bytes(self.runtime.call("read_tcp", count=1), 0)
                except (NativeJ2534Exception2026, NativeTransportError) as exc:
                    _, code = native_error_fields2026(exc)
                    if code not in (9, 0x10):
                        raise
                    if udp_discovery and not reconnected:
                        if not self.check_link_up():
                            self.link_up()
                        discovery = _bytes(
                            self.runtime.call("read_udp_discovery", count=1), 0
                        )
                        if len(discovery) == 0x2E and discovery[8:10] == b"\0\x04":
                            unlock()
                            self.stop_periodic()
                            if discovery_owned:
                                self.runtime.release("logical_disconnect_udp_discovery")
                                discovery_owned = False
                            self.finish_diag_comm()
                            self.prepare_diag_comm()
                            reconnected = True
                            pending_retries = 0
                            self.start_sync_periodic(1000, False)
                            continue
                    limit = (
                        max(0x26DE, previous) if pending_start is not None else previous
                    )
                    if pending_start is None:
                        retries += 1
                        count = retries
                    else:
                        pending_retries += 1
                        count = pending_retries
                    if count >= limit // 1000:
                        raise
                    if count == limit // 1000 - 1:
                        self.runtime.call(
                            "set_timeout", milliseconds=1000 + limit % 1000
                        )
                    unlock()

        try:
            lock()
            if udp_discovery:
                self.runtime.call_owned(
                    "logical_connect_udp_discovery", "logical_disconnect_udp_discovery"
                )
                discovery_owned = True
            self.runtime.call("set_timeout", milliseconds=1000)
            self._write("write_tcp", frame)
            while True:
                if check_native_cancel:
                    self.runtime.check_native_cancelled()
                data = retry_read()
                # Native receives into a zero-initialized PASSTHRU_MSG backing
                # buffer and ignores the returned count before address checks.
                if data[:4].ljust(4, b"\0") != target + DEVICE_ADDRESS:
                    unlock()
                    continue
                unlock()
                if data[4:7] == b"\x7f" + payload[:1] + b"\x78":
                    now = self._seconds()
                    if pending_start is None:
                        pending_start = now
                    elapsed = (
                        now
                        - pending_start
                        + (86400 if now // 3600 < pending_start // 3600 else 0)
                    )
                    if elapsed & 0xFFFFFFFF >= pending_seconds:
                        lock()
                        try:
                            self._write("queue_messages", self.frame(target, b"\x3e"))
                        finally:
                            with _export_cleanup(native_return_unknown=False):
                                unlock()
                        raise NativePassThruException2026(error, "EthernetUtils", 0x4E4)
                    self.runtime.call("set_timeout", milliseconds=1000)
                    pending_retries = 0
                    continue
                if len(data) < minimum:
                    raise NativePassThruException2026(error, "EthernetUtils", 0x4F6)
                if expected is not None and not data[4:].startswith(expected):
                    raise NativePassThruException2026(error, "EthernetUtils", 0x4FE)
                return data
        finally:
            with _export_cleanup(native_return_unknown=False):
                try:
                    if discovery_owned:
                        self.runtime.release("logical_disconnect_udp_discovery")
                finally:
                    with _export_cleanup(native_return_unknown=False):
                        try:
                            unlock()
                        finally:
                            with _export_cleanup(native_return_unknown=False):
                                self.runtime.call(
                                    "set_timeout", milliseconds=previous, cleanup=True
                                )

    def routine_control_esw1(self, operation: int) -> bytes:
        if type(operation) is not int or operation not in (0, 1):
            raise ValueError("Native ESW1 start/result operation required")
        sub = 1 if operation == 0 else 3
        expected = bytes((0x71, sub, 0x10, 0x11)) + (b"\x01" if operation else b"")
        return self.send_request(
            ESW1_ADDRESS,
            bytes((0x31, sub, 0x10, 0x11)),
            expected,
            minimum=9 if operation else 8,
            error=0x52 if operation else 0x51,
        )

    def collate_seed_key_esw1(
        self, key_provider: Callable[[bytes], bytes | None]
    ) -> None:
        if not callable(key_provider):
            raise TypeError("Explicit external ESW1 key primitive required")
        data = self.send_request(
            ESW1_ADDRESS, b"\x27\x21", b"\x67\x21", minimum=22, error=0x10
        )
        self.stop_periodic()
        self.start_sync_periodic(1000, True)
        self.runtime.check()
        key = key_provider(data[6:22])
        self.runtime.check()
        if key is None:
            raise NativePassThruException2026(0x11, "EthernetUtils", 0x2CC)
        _bytes(key, 256, 256)
        self.stop_periodic()
        self.start_sync_periodic(1000, False)
        self.send_request(
            ESW1_ADDRESS, b"\x27\x22" + key, b"\x67\x22", minimum=6, error=0x11
        )


def _filter_cids(values: tuple[bytes, ...]) -> tuple[bytes, ...]:
    # Native retain '!' anywhere; discard '#' at offset10 only otherwise.
    return tuple(value for value in values if b"!" in value or value[10:11] != b"#")


def _information_state(
    values: tuple[bytes, ...], check: Callable[[], bytes], read: Callable[[int], bytes]
) -> bool:
    if any(b"!" in value for value in values):
        return True
    data = check()
    for did in ecu_information_dids(data):
        response = read(did)
        body = response[7 if response[5:6] == b"\xeb" else 6 :]
        if len(body) % 2:
            body += b"\0"  # Native PASSTHRU_MSG storage is zeroed before the read.
        if any(
            body[index : index + 2] in (b"\xf0\x21", b"\xf0\x22")
            for index in range(0, len(body), 2)
        ):
            return True
    return False


_GETTERS = frozenset(("TCUWCanUnifiedCIDGetter.dll", "TCUWEthernetCIDGetter.dll"))
_PREPARERS = frozenset(
    ("TCUWCanUnifiedPrepareWriter.dll", "TCUWEthernetReprostdPrepareWriter.dll")
)
_WRITERS = frozenset(
    (
        "TCUWCanUnifiedFlashWriter.dll",
        "TCUWCanUnifiedFlashWriterEachArea.dll",
        "TCUWEthernetReprostdFlashWriter.dll",
    )
)


@dataclass(frozen=True)
class UnifiedContext2026:
    identity: NativeModuleIdentity
    metadata: Native2026Metadata = field(repr=False)
    parameter: NativeParameterBinding2026 = field(repr=False)
    nodes: tuple[Native2026Metadata, ...] = field(repr=False)
    addresses: tuple[NativeCommunicationAddress, ...]
    observations: Mapping = field(repr=False)
    attachments: Mapping = field(repr=False)
    observed_cids: tuple[str, ...] = field(repr=False)


_BOUND_CONTEXTS: WeakValueDictionary[int, UnifiedContext2026] = WeakValueDictionary()


def _set_native_progress(
    context: UnifiedContext2026, field_name: str, cpu_index: int, value: int
):
    """Mutate the actual native vector before invoking the void observer."""
    _uint(value)
    state = context.observations.get("dh_state")
    if state is not None:
        if field_name == "count":
            state.set_native_count(cpu_index, value)
        elif field_name == "percent":
            state.set_native_percentage(cpu_index, value)
        else:
            raise ValueError("Known native progress vector required")


def _record_native_error(
    context: UnifiedContext2026, result: Mapping, kind: int | None = None
):
    state = context.observations.get("dh_state")
    if state is not None:
        state.record_native_error(
            kind,
            result.get("native_primary_error", state.primary_error),
            result.get("native_passthru_error"),
        )


def _notify_wait(context: UnifiedContext2026, runtime: NativeRuntime2026, value: int):
    state = context.observations.get("dh_state")
    if state is not None:
        state.set_wait_remaining_ms(value)
    runtime.call("notify", field="wakeup", value=value)


@contextmanager
def _native_inner_catch_all():
    try:
        yield
    except (Exception, KeyboardInterrupt) as error:
        if not is_native_exception2026(error):
            raise


@contextmanager
def _export_cleanup(*, native_return_unknown=True):
    primary = sys.exception()
    try:
        yield
    except (Exception, KeyboardInterrupt) as error:
        if (
            primary is not None
            and not is_native_exception2026(primary)
            and not (
                isinstance(primary, InterruptedError)
                and isinstance(error, NativeRestorationCancelled)
            )
        ):
            primary.add_note("Export cleanup failed: " + type(error).__name__)
            raise primary from error
        if native_return_unknown and is_native_exception2026(error):
            # These source continuations are outside the native BOOL catch.
            error.__dict__["_native_export_return_unknown"] = True
        raise


def bind_native_context(
    container: CalibrationContainer | NativeLargeContainer2026,
    node: int,
    observed_cids: tuple[str, ...],
    selection: NativeParameterBinding2026,
    identity: NativeModuleIdentity,
    attachments: Mapping,
    observations: Mapping,
) -> UnifiedContext2026:
    """Actual47 imported CUW ->31 native selector ->48 native address context."""
    if (
        not isinstance(identity, NativeModuleIdentity)
        or identity != identify_native_module(identity.sha256, identity.module_name)
        or identity.cuw_build != "2026"
        or identity.module_name not in _GETTERS | _PREPARERS | _WRITERS
        or not isinstance(selection, NativeParameterBinding2026)
        or selection.module_name != identity.module_name
        or not isinstance(attachments, Mapping)
        or set(attachments)
        - {
            "secret_info_module",
            "cuw_module",
            "rks_ini",
            "dh_utils_module",
            "suzuki_utils_module",
        }
        or any(type(value) is not bytes for value in attachments.values())
        or not isinstance(observed_cids, tuple)
        or len(observed_cids) > 4096
        or any(type(value) is not str or len(value) > 256 for value in observed_cids)
        or not isinstance(observations, Mapping)
        or set(observations)
        - {
            "cpu_index",
            "native_cid_flag_9c4",
            "native_prepare_flag_a0c",
            "native_prepare_flag_964",
            "rks_software_identity",
            "dh_state",
            "gateway_state",
        }
    ):
        raise ValueError(
            "Exact CUW2026 Unified/Ethernet selected native context required"
        )
    expected_stage = (
        "get_cid"
        if identity.module_name in _GETTERS
        else "prepare"
        if identity.module_name in _PREPARERS
        else "write"
    )
    if selection.operation != expected_stage:
        raise ValueError("Selected native operation differs from exact export")
    selection = selection.validate_against(
        container,
        operation=expected_stage,
        node=node,
        cpu_index=observations.get("cpu_index", 0),
    )
    metadata = selection.metadata
    flag = observations.get("native_cid_flag_9c4", 0)
    if type(flag) is not int or not 0 <= flag <= 255:
        raise ValueError("Native caller CID flag byte required")
    for name in ("native_prepare_flag_a0c", "native_prepare_flag_964"):
        _uint(observations.get(name, 0))
    if "rks_software_identity" in observations:
        from scripts.cuw_2026 import RKSSoftwareIdentity2026

        retained = observations["rks_software_identity"]
        if type(retained) is not RKSSoftwareIdentity2026:
            raise TypeError("Source-produced retained native RKS identity required")
        retained.__post_init__()
    if "dh_state" in observations:
        from scripts.cuw_2026 import DHControllerState2026

        state = observations["dh_state"]
        if type(state) is not DHControllerState2026 or state.metadata != metadata:
            raise TypeError("Same imported engine-owned DH state required")
    if "gateway_state" in observations:
        from scripts.cuw_2026 import CUWEngine2026

        engine = observations["gateway_state"]
        if (
            type(engine) is not CUWEngine2026
            or engine.metadata_for(node, metadata.cpu_index) != metadata
        ):
            raise TypeError(
                "Same imported engine-owned gateway classification required"
            )
    ethernet = identity.module_name.startswith("TCUWEthernet")
    addresses = ()
    if not ethernet or selection.selector_functions:
        producer = communication_addresses_from_parameter(
            container, selection.parameter
        )
        success, addresses = producer.resolve(
            selection.selector_functions,
            cids=observed_cids,
            location_id=(metadata.cpu.values.get("locationid") or None)
            if metadata.cpus
            else None,
        )
        if not success:
            raise ValueError("Native communication selector did not resolve")
    count_text = metadata.vehicle.get("numberofnode", "")
    if (
        not count_text.isascii()
        or not count_text.isdecimal()
        or not 1 <= int(count_text) <= 9
    ):
        raise ValueError("Imported native node count required")
    nodes = tuple(
        native2026_metadata(container, node=index)
        for index in range(1, int(count_text) + 1)
    )
    ethernet = identity.module_name.startswith("TCUWEthernet")
    if ethernet:
        for item in nodes:
            text = item.node_values.get("logicaladdress", "")
            if len(text) != 4 or any(
                char not in "0123456789abcdefABCDEF" for char in text
            ):
                raise ValueError("Imported two-byte native logical address required")
    elif len(addresses) < len(nodes):
        raise ValueError("Native getter needs one selected CAN address per CUW node")
    context = UnifiedContext2026(
        identity,
        metadata,
        selection,
        nodes,
        addresses,
        MappingProxyType(dict(observations)),
        MappingProxyType(dict(attachments)),
        observed_cids,
    )
    _BOUND_CONTEXTS[id(context)] = context
    return context


def _get_cid(context: UnifiedContext2026, runtime: NativeRuntime2026) -> dict:
    ethernet = context.identity.module_name == "TCUWEthernetCIDGetter.dll"
    client = EthernetUtils2026(runtime)
    unified = Unified2026(runtime)
    protocol = 0x800F if ethernet else 6
    timeout = context.parameter.parameter.long("ReceiveTimeoutBeforeGetCID")
    timeout = _uint(0 if timeout is None else timeout)
    runtime.call_owned("connect", "disconnect", protocol=protocol)
    results = []
    all_cids: list[bytes] = []
    flag = context.observations.get("native_cid_flag_9c4", 0)
    charge_finish = None
    try:
        runtime.call("set_timeout", milliseconds=timeout)
        runtime.call(
            "wait",
            milliseconds=max(
                (item.wakeup_ms for item in context.nodes if item.cpus), default=0
            ),
        )
        if ethernet:
            client.prepare_diag_comm()
        else:
            charge = next(
                (
                    item
                    for item in context.nodes
                    if item.node_values.get("chargelocalbusecureprogrammingflow", "")
                    in ("01", "02")
                ),
                None,
            )
            if charge is not None:
                flow = charge.node_values["chargelocalbusecureprogrammingflow"]
                if flow == "01":
                    text = charge.node_values.get(
                        "chargelocalbuspoweroncontrollingecudiagid", ""
                    )
                    if len(text) != 4 or any(
                        c not in "0123456789abcdefABCDEF" for c in text
                    ):
                        raise ValueError(
                            "Imported native charge-controller diagnostic ID required"
                        )
                    identifier = bytes.fromhex(text)
                    charge_request = b"\0\0" + identifier
                    charge_response = b"\0\0" + bytes(
                        (identifier[0], (identifier[1] + 8) & 255)
                    )
                    unified.ordinary_session(
                        charge_request, charge_response, extended=True
                    )
                else:
                    charge_request, charge_response = unified.diag.phase6_addresses(
                        b"\x49"
                    )
                    unified.extended_session_phase6(b"\x49")
                runtime.call_owned(
                    "start_sync_periodic",
                    "stop_sync_periodic",
                    frames=(
                        (charge_request + b"\x3e\x80", 0 if flow == "01" else 0x100),
                    ),
                    interval_ms=2000,
                    retry_ms=100,
                    count=1,
                    delay_ms=1000,
                )

                def charge_cleanup(
                    flow=flow,
                    charge_request=charge_request,
                    charge_response=charge_response,
                ):
                    if runtime.cancelled():
                        if runtime.owns_resource("stop_sync_periodic"):
                            runtime.release("stop_sync_periodic")
                        raise NativeRestorationCancelled(flow)
                    try:
                        if flow == "01":
                            unified.routine_charge_local_bus(
                                charge_request, charge_response, 1
                            )
                        else:
                            unified.routine_charge_local_bus_phase6(1)
                    finally:
                        with _export_cleanup(native_return_unknown=False):
                            if runtime.owns_resource("stop_sync_periodic"):
                                runtime.release("stop_sync_periodic")
                    if flow == "01":
                        unified.ordinary_session(charge_request, charge_response)
                    else:
                        unified.default_session_phase6(b"\x49")

                charge_finish = charge_cleanup
                if flow == "01":
                    unified.routine_charge_local_bus(charge_request, charge_response, 0)
                else:
                    unified.routine_charge_local_bus_phase6(0)
                runtime.call("wait", milliseconds=charge.charge_local_bus_start_ms)
        for index, node in enumerate(context.nodes):
            runtime.check()
            runtime.check_native_cancelled()
            ids = ()
            pending_error = None
            information = False
            filter_id = None
            block_size_set = False
            if ethernet:
                target = bytes.fromhex(node.node_values["logicaladdress"])

                def ethernet_call(payload, expected, minimum, error, target=target):
                    return client.send_request(
                        target,
                        payload,
                        expected,
                        minimum=minimum,
                        error=error,
                        check_native_cancel=True,
                    )

                call = ethernet_call
            else:
                request, response = context.addresses[index].headers()
                if context.addresses[index].extended:
                    unified.diag.set_block_size(1)
                    block_size_set = True
                filter_id = unified.diag.start_filter(request, response)

                def can_call(
                    payload,
                    expected,
                    minimum,
                    error,
                    request=request,
                    response=response,
                ):
                    body = unified.diag.call(
                        request,
                        response,
                        payload,
                        expected,
                        minimum=4 if payload[0] in (0x22, 0x31) else 2,
                        error_code=error,
                        phase5=True,
                        pending_limit=180,
                        busy_limit=0x159A,
                        check_native_cancel=payload[:1] == b"\x22",
                    )
                    return response + body

                call = can_call

            try:
                try:
                    ids = parse_software_ids(
                        call(
                            b"\x22\xf1\x81",
                            b"\x62\xf1\x81",
                            8
                            if ethernet
                            else 4 + len(context.addresses[index].response),
                            3,
                        ),
                        ethernet=ethernet,
                    )
                except (
                    NativePassThruException2026,
                    NativeTransportError,
                    CommonResponseError,
                ) as exc:
                    pending_error = exc
                if flag == 1:
                    information = _information_state(
                        ids,
                        lambda call=call: call(
                            b"\x31\x01\x10\0", b"\x71\x01\x10\0", 40, 3
                        ),
                        lambda did, call=call: call(
                            bytes((0xAB, did)), bytes((0xEB, did)), 6, 0x5B
                        ),
                    )
                if pending_error is not None and not information:
                    raise pending_error
                if not information:
                    ids = _filter_cids(ids)
                    if not ids:
                        raise NativePassThruException2026(
                            3,
                            "EthernetCIDGetter" if ethernet else "UnifiedCIDGetter",
                            0x1C8 if ethernet else 0x214,
                        )
                all_cids.extend(ids)
                results.append(
                    {
                        "node": index,
                        "cids": [value.decode("latin1") for value in ids],
                        "information_state": information,
                        "address": node.node_values.get(
                            "logicaladdress" if ethernet else "diagid", ""
                        ),
                    }
                )
            finally:
                with _export_cleanup(native_return_unknown=False):
                    try:
                        if filter_id is not None:
                            runtime.release("stop_filter", identifier=filter_id)
                    finally:
                        with _export_cleanup(native_return_unknown=False):
                            if block_size_set:
                                runtime.call(
                                    "control_io",
                                    cleanup=True,
                                    ioctl=2,
                                    parameters=((0x1E, 0),),
                                )
        return {
            "complete": True,
            "native_return": True,
            "operation": "StartGetCID",
            "module": context.identity.module_name,
            "source_sha256": context.identity.sha256,
            "cids": [value.decode("latin1") for value in all_cids],
            "identifiers": list(all_cids),
            "nodes": results,
            "provenance": "source-recovered-2026-injected-primitives",
        }
    finally:
        with _export_cleanup(native_return_unknown=False):
            try:
                if charge_finish is not None:
                    charge_finish()
            finally:
                with _export_cleanup(native_return_unknown=False):
                    try:
                        errors = client.finish_diag_comm()
                        if errors:
                            raise RuntimeError(
                                "Owned Ethernet cleanup failed: " + ",".join(errors)
                            )
                    finally:
                        with _export_cleanup(native_return_unknown=False):
                            runtime.release("disconnect")


def execute_context(context: UnifiedContext2026, runtime: NativeRuntime2026) -> dict:
    if not isinstance(context, UnifiedContext2026) or not isinstance(
        runtime, NativeRuntime2026
    ):
        raise TypeError("Bound source-specific native context and runtime required")
    if _BOUND_CONTEXTS.get(id(context)) is not context:
        raise ValueError("Native context was not issued by the binding factory")
    expected = bind_native_context(
        context.metadata.source_container,
        context.metadata.node,
        context.observed_cids,
        context.parameter,
        context.identity,
        context.attachments,
        context.observations,
    )
    if expected != context:
        raise ValueError("Bound native context changed before execution")
    try:
        return _execute_context(context, runtime)
    except (NativeException2026, NativeTransportError, CommonResponseError) as error:
        result = {
            "complete": False,
            "native_return": None
            if getattr(error, "_native_export_return_unknown", False)
            else False,
            "state": "failed",
            "error": type(error).__name__,
        }
        try:
            primary, secondary = native_error_fields2026(error)
        except TypeError:
            pass
        else:
            result["native_primary_error"] = primary
            if secondary is not None:
                result["native_passthru_error"] = secondary
        _record_native_error(context, result)
        return result


def _execute_context(context: UnifiedContext2026, runtime: NativeRuntime2026) -> dict:
    if context.identity.module_name in _GETTERS:
        return _get_cid(context, runtime)
    if context.identity.module_name == "TCUWCanUnifiedPrepareWriter.dll":
        return _prepare_unified(context, runtime)
    if context.identity.module_name == "TCUWEthernetReprostdPrepareWriter.dll":
        return _prepare_ethernet(context, runtime)
    if context.identity.module_name == "TCUWEthernetReprostdFlashWriter.dll":
        return _ethernet_writer(context, runtime)
    if context.identity.module_name in _WRITERS:
        return _unified_writer(context, runtime)
    raise NotImplementedError(
        "CUW2026 retained Unified/Ethernet selected operation remains OPEN"
    )


def _prepare_ethernet(context: UnifiedContext2026, runtime: NativeRuntime2026) -> dict:
    """Actual2026 StartPrepareWrite1be0 ->13a0/1604/1a50/1000."""
    metadata = context.metadata
    if not metadata.logical_blocks:
        raise ValueError(
            "Ethernet prepare requires imported first logical-block timeout"
        )
    if any(
        type(context.attachments.get(name)) is not bytes
        for name in ("secret_info_module", "cuw_module")
    ):
        raise LookupError("Exact native SecretInfo/CUW dependency bytes unavailable")
    secret = SecretInfoClient.from_native_modules(
        context.attachments["secret_info_module"], context.attachments["cuw_module"]
    )
    target = bytes.fromhex(metadata.node_values["logicaladdress"])
    key_material = metadata.service_auth_key_bytes
    pending = metadata.logical_blocks[0].routine_response_pending_limit
    client = EthernetUtils2026(runtime)
    unified = Unified2026(runtime)
    previous = _uint(runtime.call("get_timeout"))
    try:
        runtime.call("set_local_time_to_previous_send_time")
        timeout = context.parameter.parameter.long("ReceiveTimeoutBeforeGetCID")
        runtime.call("set_timeout", milliseconds=0 if timeout is None else timeout)
        client.prepare_diag_comm()
        client.send_functional(b"\x10\x83", synchronous=True)
        runtime.call("wait", milliseconds=1000)
        client.start_sync_periodic(1000, False)
        gateways = metadata.gateway_values
        if (
            gateways
            and gateways[0]["gatewaylogicaladdress"].upper()
            == ESW1_ADDRESS.hex().upper()
        ):

            def key_provider(seed):
                return _bytes(runtime.call("calculate_esw1_key", seed=seed), 256, 256)

            client.collate_seed_key_esw1(key_provider)
            client.routine_control_esw1(0)
            runtime.call("wait", milliseconds=1500)
            client.routine_control_esw1(1)
        client.stop_periodic()
        for payload, previous_time in (
            (b"\x85\x82", False),
            (b"\x3e\x80", True),
            (b"\x28\x81\x01", False),
            (b"\x3e\x80", True),
            (b"\x28\x83\x01", False),
        ):
            client.send_functional(payload, synchronous=True)
            if previous_time:
                runtime.call("set_local_time_to_previous_send_time")
            runtime.call("wait", milliseconds=1000)
        for delay in (2000, 1000, 1000):
            client.send_functional(b"\x3e\x80", synchronous=False)
            runtime.call("set_local_time_to_previous_send_time")
            runtime.call("wait", milliseconds=delay)
        runtime.call("control_io", ioctl=8, size=0x10)
        client.start_sync_periodic(1000, False)
        client.send_request(
            target,
            b"\x10\x02",
            b"\x50\x02",
            minimum=10,
            error=0x29,
            pending_seconds=pending,
            udp_discovery=target == ESW1_ADDRESS,
        )
        client.stop_periodic()
        client.start_sync_periodic(0, False)
        runtime.call("wait", milliseconds=metadata.wakeup_ms)
        seed = client.send_request(
            target,
            b"\x27\x01",
            b"\x67\x01",
            minimum=22,
            error=0x10,
            pending_seconds=pending,
        )[6:22]
        key = unified.calc_seed_key(secret, key_material, seed)
        client.send_request(
            target,
            b"\x27\x02" + key,
            b"\x67\x02",
            minimum=6,
            error=0x11,
            pending_seconds=pending,
        )
        return {
            "complete": True,
            "native_return": True,
            "operation": "StartPrepareWrite",
            "module": context.identity.module_name,
            "source_sha256": context.identity.sha256,
            "retained_resources": ["logical_channels", "sync_periodic"],
            "runtime_reuse_required": True,
            "provenance": "source-recovered-2026-injected-primitives",
        }
    except BaseException:
        try:
            if client._periodic:
                client.stop_periodic()
        finally:
            with _export_cleanup(native_return_unknown=False):
                client.finish_diag_comm()
        raise
    finally:
        with _export_cleanup(native_return_unknown=False):
            runtime.call("set_timeout", milliseconds=previous, cleanup=True)


def _unified_writer(context: UnifiedContext2026, runtime: NativeRuntime2026) -> dict:
    """2026 Unified13a0/EachArea10f0 core; export fault/history closure remains OPEN."""
    from scripts.calibration_2026 import (
        native2026_archive,
        native2026_cpu_p4_server_max_time,
        native2026_cpu_security_bytes,
        native2026_global_cpu_index,
        native2026_header_info,
        native2026_node_cpu_count,
    )
    from scripts.programming import (
        reprostd_block_size,
        unified_download_request,
        unified_fingerprint_requests,
        unified_routine_request,
    )
    from scripts.programming_2026_common import make_send_data_records

    metadata = context.metadata
    gateway_engine = context.observations.get("gateway_state")
    gateway_node = (
        gateway_engine.repro_gateway_node if gateway_engine is not None else 0
    )
    if metadata.wakeup_ms % 50:
        raise ValueError("Native wake counter must terminate in50ms increments")
    cpu = metadata.cpu
    global_cpu_index = native2026_global_cpu_index(metadata)
    last = metadata.cpu_index + 1 == native2026_node_cpu_count(
        metadata, metadata.node - 1
    )
    failure_report = None
    each_area = context.identity.module_name.endswith("EachArea.dll")
    address = context.addresses[metadata.node - 1]
    request, response = address.headers()
    offset_bytes = native2026_cpu_security_bytes(
        metadata, "OffsetAddress", global_cpu_index
    )
    offset = int.from_bytes(offset_bytes, "big")
    calibration_key = native2026_cpu_security_bytes(
        metadata, "SeedKey", global_cpu_index
    )
    nonce = native2026_cpu_security_bytes(metadata, "Nonce", global_cpu_index)
    security_text = cpu.values.get("securityproperty2", "")
    if len(security_text) != 2 or any(
        char not in "0123456789abcdefABCDEF" for char in security_text
    ):
        raise ValueError("Imported one-byte SecurityProperty2 required")
    security = int(security_text, 16)
    archive = native2026_archive(metadata, preserve_srecords=True)
    geometry = tuple(
        native2026_header_info(metadata, kind=kind).numeric_areas()
        for kind in ("erase_routine", "write_routine", "image")
    )
    erase_areas, write_areas, image_areas = geometry
    if (
        not image_areas
        or any(size <= 0 for group in geometry for _, size in group)
        or sum(len(group) for group in geometry) > 4096
    ):
        raise ValueError("Bounded imported Unified image geometry required")
    if each_area and any(
        len(group) not in (0, len(image_areas)) for group in geometry[:2]
    ):
        raise ValueError("Native EachArea requires parallel populated headers")
    groups = tuple(
        tuple(
            (start, make_send_data_records(archive.kind_records, start, size))
            for start, size in group
        )
        for group in geometry
    )
    pending = native2026_cpu_p4_server_max_time(metadata, global_cpu_index)
    from scripts.programming_2026_dh import central_gateway_request_can_id

    gateway_id = (
        metadata.gateway_values[0]["gatewaydiagid"] if metadata.gateway_values else ""
    )
    dh_gateway = None
    if gateway_id and bytes.fromhex(gateway_id) == central_gateway_request_can_id():
        from scripts.cuw_2026 import DHControllerState2026
        from scripts.programming_2026_dh import bind_gateway_client

        state = context.observations.get("dh_state")
        if not isinstance(state, DHControllerState2026):
            raise LookupError("Engine-owned DH gateway state unavailable")
        dh_gateway = bind_gateway_client(
            runtime,
            context.parameter,
            state,
            **{
                name: _bytes(context.attachments.get(name), 1, 64 * 1024 * 1024)
                for name in ("dh_utils_module", "secret_info_module", "cuw_module")
            },
        )
    unified = Unified2026(runtime)
    transferred = 0
    progress = 0
    stub_total, routine_total, image_total = (
        sum(len(data) for _, data in group) for group in groups
    )
    total = stub_total + routine_total + image_total
    first_stub = len(groups[0][0][1]) if each_area and groups[0] else stub_total
    percent_denominator = total - first_stub
    if total <= 0 or percent_denominator <= 0:
        raise ValueError("Native Unified progress denominator cannot be zero")

    filter_id = unified.diag.start_filter(request, response)

    def send(payload, expected, error, minimum=0, *, pending_limit=pending):
        return unified.diag.call(
            request,
            response,
            payload,
            expected,
            minimum=minimum or len(expected),
            error_code=error,
            phase5=True,
            pending_limit=pending_limit,
            busy_limit=0x159A,
        )

    def notify_programming(value):
        runtime.call("programming_notification", value=value)

    def routine(operation, areas):
        errors = {
            "stub_check": 0x4B,
            "erase": 0x45,
            "routine_check": 0x4C,
            "verify": 0x4D,
        }
        for start, size in areas:
            payload, expected = unified_routine_request(operation, offset, start, size)
            send(payload, expected, errors[operation])

    def fingerprint():
        for (payload, expected), error in zip(
            unified_fingerprint_requests(offset_bytes, calibration_key, nonce),
            (0x4A, 0x48, 0x47),
            strict=True,
        ):
            send(payload, expected, error)

    def download(group, stage):
        nonlocal transferred, progress
        memory_type = 1 if stage in (0, 2) else 0
        encrypted = bool(security & 8)
        for start, data in group:
            reply = send(
                unified_download_request(
                    offset,
                    start,
                    len(data),
                    encrypted=encrypted,
                    memory_type=memory_type,
                ),
                b"\x74",
                0x1A,
                minimum=3,
            )
            size = reprostd_block_size(reply)
            previous = _uint(runtime.call("get_send_timeout"))
            frames = (size + 2 + (7 if address.extended else 6) - 1) // (
                7 if address.extended else 6
            )
            runtime.call("set_send_timeout", milliseconds=frames * 161 + 1000)
            try:
                for sequence, index in enumerate(range(0, len(data), size), 1):
                    block = data[index : index + size]
                    counter = sequence & 255
                    send(bytes((0x36, counter)) + block, bytes((0x76, counter)), 0x22)
                    transferred += len(block)
                    if stage != 0:
                        progress += len(block)
                        count_value = int(archive.flash_size * (transferred / total))
                        percent_value = int(
                            (transferred - first_stub) / percent_denominator * 100
                        )
                        _set_native_progress(
                            context, "count", global_cpu_index, count_value
                        )
                        runtime.call(
                            "progress",
                            field="count",
                            value=count_value,
                        )
                        _set_native_progress(
                            context, "percent", global_cpu_index, percent_value
                        )
                        runtime.call(
                            "progress",
                            field="percent",
                            value=percent_value,
                        )
            finally:
                with _export_cleanup(native_return_unknown=False):
                    runtime.call(
                        "set_send_timeout", milliseconds=previous, cleanup=True
                    )
            send(b"\x37", b"\x77", 0x1C)

    try:
        _notify_wait(
            context,
            runtime,
            metadata.wakeup_ms
            if metadata.cpu_index + 1
            == native2026_node_cpu_count(metadata, metadata.node - 1)
            else 0,
        )
        if each_area:
            for index, (start, data) in enumerate(groups[2]):
                fingerprint()
                if groups[0]:
                    download((groups[0][index],), 0)
                    routine(
                        "stub_check", ((groups[0][index][0], len(groups[0][index][1])),)
                    )
                notify_programming(True)
                routine("erase", ((start, len(data)),))
                if groups[1]:
                    download((groups[1][index],), 2)
                    routine(
                        "routine_check",
                        ((groups[1][index][0], len(groups[1][index][1])),),
                    )
                download(((start, data),), 3)
                routine("verify", ((start, len(data)),))
        else:
            fingerprint()
            download(groups[0], 0)
            routine("stub_check", erase_areas)
            notify_programming(True)
            routine("erase", image_areas)
            download(groups[1], 2)
            routine("routine_check", write_areas)
            download(groups[2], 3)
            routine("verify", image_areas)
        if last:
            send(b"\x11\x01", b"\x51\x01", 0x18, pending_limit=180)
            if runtime.owns_resource("stop_sync_periodic"):
                runtime.release("stop_sync_periodic")
            else:
                runtime.call("stop_sync_periodic")
            wake = metadata.wakeup_ms
            if wake % 50:
                raise ValueError("Native wake counter must terminate in50ms increments")
            while wake:
                runtime.call("wait", milliseconds=50)
                wake -= 50
                _notify_wait(context, runtime, wake)
            for data, flags in (
                (bytes.fromhex("000007771081"), 0),
                (bytes.fromhex("0000077FFE1081"), 0x80),
                (bytes.fromhex("18DB33E01081"), 0x100),
            ):
                unified.diag.write(data, flags)
            gateways = metadata.gateway_values
            if gateways:
                gateway_id = gateways[0]["gatewaydiagid"]
                from scripts.programming_2026_dh import central_gateway_request_can_id

                central_id = central_gateway_request_can_id()
                if gateway_id and bytes.fromhex(gateway_id) == central_id:
                    assert dh_gateway is not None
                    # Std192c / EachArea17ae guard only the DH finalization.
                    with _native_inner_catch_all():
                        dh_gateway.end_reprogramming_mode_for_multi_types()
                if gateway_id == "0751":
                    send_gateway = lambda: unified.diag.call(
                        bytes.fromhex("00000751"),
                        bytes.fromhex("00000761"),
                        b"\x10\x01",
                        b"\x50\x01",
                        # Native DataSize10 includes the four-byte CAN address.
                        minimum=6,
                        error_code=0x3F9,
                        phase5=True,
                        pending_limit=180,
                        busy_limit=0x159A,
                    )
                    if not each_area:
                        send_gateway()
                        # Std19c0 ->19d8 continues NotificationBool(false).
                        with _native_inner_catch_all():
                            if unified.read_programming_mode_control_state() != 0:
                                unified.routine_smc_gateway(4)
        else:
            runtime.call("notify", field="next_cpu", value=global_cpu_index + 1)
        notify_programming(False)
        return {
            "complete": True,
            "native_return": True,
            "operation": "StartFlashWrite",
            "module": context.identity.module_name,
            "source_sha256": context.identity.sha256,
            "transferred": transferred,
            "last_cpu": last,
            "provenance": "source-recovered-2026-injected-primitives",
        }
    except (NativeException2026, NativeTransportError, CommonResponseError) as error:
        for field_name in ("count", "percent"):
            _set_native_progress(context, field_name, global_cpu_index, 0)
            runtime.call(
                "progress", field=field_name, cpu_index=global_cpu_index, value=0
            )
        failure_report = {
            "complete": False,
            "native_return": False,
            "state": "failed",
            "error": type(error).__name__,
        }
        try:
            primary, secondary = native_error_fields2026(error)
        except TypeError:
            pass
        else:
            failure_report["native_primary_error"] = primary
            if secondary is not None:
                failure_report["native_passthru_error"] = secondary
        _record_native_error(context, failure_report)
        return failure_report
    finally:
        with _export_cleanup():
            with _native_inner_catch_all():
                runtime.release("stop_filter", identifier=filter_id)
            if failure_report is not None:
                runtime.call("set_history_enabled", enabled=False, cleanup=True)
            if last and gateway_node == 2:
                unified.central_gateway_session()
            runtime.call("set_history_enabled", enabled=True, cleanup=True)
            if failure_report is not None:
                if runtime.owns_resource("stop_sync_periodic"):
                    runtime.release("stop_sync_periodic")
                else:
                    runtime.call("stop_sync_periodic", cleanup=True)
                notification = runtime.call("get_programming_notification")
                if type(notification) is not bool:
                    raise TypeError("Actual shared native NotificationBool required")
                failure_report["native_outcome"] = 2 if notification else 1
                _record_native_error(context, failure_report, 2 if notification else 1)
                if not notification:
                    failure_report["native_comm_phase"] = 1
                    if context.observations.get("dh_state") is not None:
                        context.observations["dh_state"].mark_flash_code_failed()


def _prepare_unified(context: UnifiedContext2026, runtime: NativeRuntime2026) -> dict:
    """2026 native preparation1c00 base path, source helpers1500/19a0/27c0/2980."""
    from scripts.calibration_2026 import (
        native2026_cpu_p4_server_max_time,
        native2026_global_cpu_index,
    )
    from scripts.programming_2026_common import diagnostic_mask

    metadata = context.metadata
    from scripts.cuw_2026 import CUWEngine2026
    from scripts.programming_2026_dh import bind_gateway_client, su_tester_present

    gateways = tuple(item["gatewaydiagid"] for item in metadata.gateway_values)
    first_gateway = gateways[0] if gateways else ""
    gateway_engine = context.observations.get("gateway_state")
    if gateways and not isinstance(gateway_engine, CUWEngine2026):
        raise LookupError("Shared engine gateway classification unavailable")
    dh_gateway = None
    dh_state = context.observations.get("dh_state")
    if first_gateway == "0786":
        from scripts.cuw_2026 import DHControllerState2026

        if not isinstance(dh_state, DHControllerState2026):
            raise LookupError("Engine-owned DH gateway state unavailable")
        dh_gateway = bind_gateway_client(
            runtime,
            context.parameter,
            dh_state,
            **{
                name: _bytes(context.attachments.get(name), 1, 64 * 1024 * 1024)
                for name in ("dh_utils_module", "secret_info_module", "cuw_module")
            },
        )
    suzuki = None
    if first_gateway == "0751":
        import hashlib

        from scripts.programming_2026_suzuki_fhi import SuzukiUtils2026

        module = _bytes(
            context.attachments.get("suzuki_utils_module"), 1, 64 * 1024 * 1024
        )
        suzuki = SuzukiUtils2026(
            identify_native_module(
                hashlib.sha256(module).hexdigest(), "TCUWCanSuzukiUDSUtils.dll"
            ),
            runtime,
            container=metadata.source_container,
            parameters=context.parameter.parameter,
        )
    if any(
        type(context.attachments.get(name)) is not bytes
        for name in ("secret_info_module", "cuw_module")
    ):
        raise LookupError("Exact native SecretInfo/CUW dependency bytes unavailable")
    secret = SecretInfoClient.from_native_modules(
        context.attachments["secret_info_module"], context.attachments["cuw_module"]
    )
    address = context.addresses[metadata.node - 1]
    request, response = address.headers()
    ecu_key, service_key = metadata.ecu_auth_key_bytes, metadata.service_auth_key_bytes
    pending = native2026_cpu_p4_server_max_time(
        metadata, native2026_global_cpu_index(metadata)
    )
    delay = metadata.emissions_delay_ms
    wait = context.parameter.parameter.long("WaitTimeAfterDiagnosticMask") or 0
    _uint(wait)
    unified = Unified2026(runtime)
    flags = (0, 0x80, 0x100)
    functional = (
        bytes.fromhex("00000777"),
        bytes.fromhex("0000077FFE"),
        bytes.fromhex("18DB33E0"),
    )
    filter_id = None
    succeeded = False

    def broadcast(payloads):
        for target, tx_flags, payload in zip(functional, flags, payloads, strict=True):
            unified.diag.write(target + payload, tx_flags)

    def tester():
        for frame, flag in periodic_frames():
            unified.diag.write(frame, flag)
        runtime.call("set_local_time_to_previous_send_time")

    def gateway_node():
        return gateway_engine.repro_gateway_node if gateway_engine is not None else 0

    def periodic_frames(with_central=True):
        frames = [(functional[0] + b"\x3e\x80", 0), (functional[1] + b"\x3e\x80", 0x80)]
        if first_gateway == "0751":
            frames.append((bytes.fromhex("000007003E80"), 0))
        if with_central and gateway_node() == 2:
            frames.append((bytes.fromhex("000007505F3E02"), 0x80))
        frames.append((functional[2] + b"\x3e\x80", 0x100))
        if dh_state is not None and dh_state.central_gateway_type == 2:
            frames.append((su_tester_present(), 0))
        return tuple(frames)

    def stop_periodic():
        if runtime.owns_resource("stop_sync_periodic"):
            runtime.release("stop_sync_periodic")
        else:
            runtime.call("stop_sync_periodic")

    def periodic(milliseconds, *, with_central=True):
        frames = periodic_frames(with_central)
        runtime.call_owned(
            "start_sync_periodic",
            "stop_sync_periodic",
            frames=frames,
            interval_ms=2000,
            retry_ms=100,
            count=len(frames),
            delay_ms=milliseconds,
        )

    def communication_control():
        unified.diag.write(functional[0] + b"\x28\x81\x01")
        if delay == 0:
            runtime.call("wait", milliseconds=1000)
            tester()
            runtime.call("wait", milliseconds=1000)
        unified.diag.write(functional[1] + b"\x28\x81\x01", flags[1])
        unified.diag.write(functional[2] + b"\x28\x83\x01", flags[2])
        remaining = delay or 1000
        while remaining > 2000:
            runtime.call("wait", milliseconds=2000)
            tester()
            remaining -= 2000
        runtime.call("wait", milliseconds=remaining)

    try:
        runtime.call("set_local_time_to_previous_send_time")
        runtime.call("wait", milliseconds=metadata.wakeup_ms)
        if first_gateway == "07505F" and gateway_node() == 0:
            assert gateway_engine is not None
            gateway_engine.set_repro_gateway_node(unified.judge_repro_gateway_node(0))
        elif dh_gateway is not None:
            dh_gateway.start_reprogramming_mode_for_multi_types()
        for gateway in gateways:
            if gateway == "07505F" and gateway_node() == 2:
                unified.collate_seed_key_central_gateway()
        stop_periodic()
        if suzuki is not None:
            with unified.filtered(bytes.fromhex("00000751"), bytes.fromhex("00000761")):
                suzuki.send(
                    bytes.fromhex("00000751"),
                    bytes.fromhex("00000761"),
                    b"\x10\x03",
                    b"\x50\x03",
                    minimum=6,
                    error_code=0x58,
                )
        unified.diag.write(functional[0] + b"\x10\x83")
        runtime.call("wait", milliseconds=1000)
        tester()
        runtime.call("wait", milliseconds=1000)
        unified.diag.write(functional[1] + b"\x10\x83", flags[1])
        unified.diag.write(functional[2] + b"\x10\x83", flags[2])
        runtime.call("wait", milliseconds=1000)
        periodic(1000)
        if (
            context.observations.get("native_prepare_flag_a0c", 0) != 1
            and first_gateway != "0751"
        ):
            unified.cancel_automatic_ig_off(
                bool(context.observations.get("native_prepare_flag_964", 0)),
                address.request,
            )
        if gateway_node() == 1:
            unified.collate_seed_key_phase5_gateway()
            unified.routine_phase5_gateway(0)
            runtime.call("wait", milliseconds=1500)
            unified.routine_phase5_gateway(1)
        elif suzuki is not None:
            if suzuki.supports_wired_repro(with_filter=True):
                suzuki.gateway_authorize(None, with_filter=True)
            else:
                unified.collate_seed_key_smc_gateway()
        stop_periodic()
        for target, tx_flags in zip(functional[:2], flags[:2], strict=True):
            unified.diag.write(target + b"\x85\x82", tx_flags)
            runtime.call("wait", milliseconds=1000)
            tester()
            runtime.call("wait", milliseconds=1000)
        if first_gateway != "0751":
            diagnostic_mask(runtime, wait)
            runtime.call("wait", milliseconds=900)
        if delay == 0:
            tester()
            runtime.call("wait", milliseconds=1000)
            communication_control()
        periodic(1000)
        filter_id = unified.diag.start_filter(request, response)
        # Native checks first selected address's extension flag, not selected node.
        if context.addresses[0].extended:
            unified.diag.set_block_size(1)
        unified.read_software_id(request, response)
        stop_periodic()
        periodic(1000, with_central=False)
        for gateway in gateways:
            if gateway == "07505F":
                if gateway_node() == 1:
                    unified.routine_phase5_gateway(2)
                    runtime.call("wait", milliseconds=1500)
                    unified.routine_phase5_gateway(3)
                else:
                    unified.central_gateway_session(programming=True)
                    runtime.call("wait", milliseconds=1500)
            elif gateway == "0751":
                unified.routine_smc_gateway(2)
                runtime.call("wait", milliseconds=1500)
        stop_periodic()
        if delay:
            communication_control()
        periodic(1000 if delay == 0 else 0)
        try:
            unified.diag.call(
                request,
                response,
                b"\x10\x02",
                b"\x50\x02",
                minimum=6,
                error_code=0x29,
                phase5=True,
                pending_limit=pending,
                busy_limit=0x159A,
            )
        except (NativeTransportError, NativeJ2534Exception2026) as error:
            _, status = native_error_fields2026(error)
            if not gateways and status in (9, 16):
                raise NativePassThruException2026(
                    0x3EC, "UnifiedPrepareWriter", 0x301
                ) from error
            raise
        if delay == 0:
            stop_periodic()
            periodic(0)
        runtime.call("wait", milliseconds=2000)
        seed = unified.diag.call(
            request,
            response,
            b"\x27\x01" + ecu_key,
            b"\x67\x01",
            minimum=18,
            error_code=0x10,
            phase5=True,
            pending_limit=pending,
            busy_limit=0x159A,
        )[2:18]
        key = unified.calc_seed_key(secret, service_key, seed)
        unified.diag.call(
            request,
            response,
            b"\x27\x02" + key,
            b"\x67\x02",
            minimum=2,
            error_code=0x11,
            phase5=True,
            pending_limit=pending,
            busy_limit=0x159A,
        )
        succeeded = True
        return {
            "complete": True,
            "native_return": True,
            "operation": "StartPrepareWrite",
            "module": context.identity.module_name,
            "source_sha256": context.identity.sha256,
            "retained_resources": ["sync_periodic"],
            "runtime_reuse_required": True,
            "provenance": "source-recovered-2026-injected-primitives",
        }
    finally:
        with _export_cleanup(native_return_unknown=False):
            try:
                if not succeeded:
                    if runtime.owns_resource("stop_sync_periodic"):
                        runtime.release("stop_sync_periodic")
                    else:
                        runtime.call("stop_sync_periodic", cleanup=True)
            finally:
                with _export_cleanup(native_return_unknown=False):
                    try:
                        if context.addresses[0].extended:
                            runtime.call(
                                "control_io",
                                cleanup=True,
                                ioctl=2,
                                parameters=((0x1E, 0),),
                            )
                    finally:
                        with _export_cleanup(native_return_unknown=False):
                            if filter_id is not None:
                                runtime.release("stop_filter", identifier=filter_id)


def ethernet_programming_information(
    subtype: int, nonce: bytes, caller_information: bytes, system_time: object
) -> tuple[tuple[bytes, bytes, int], ...]:
    """FlashWriter43a0 and static initializers1000/1150/12a0, not P6 tables."""
    if type(subtype) is not int or not 1 <= subtype <= 16:
        raise ValueError("Native Ethernet initialized DID table slot1..16 required")
    _bytes(nonce, 16, 16)
    _bytes(caller_information, 32, 64)
    if (
        type(system_time) is not tuple
        or len(system_time) != 8
        or any(
            type(value) is not int or not 0 <= value <= 65535 for value in system_time
        )
    ):
        raise ValueError("Observed native UTC SYSTEMTIME eight WORDs required")
    nonce_did = 0x0202 if subtype == 1 else 0x023F + subtype
    fields = (
        (nonce_did, nonce, 0x47),
        # Native4532/4539 copy32 bytes into the zeroed64-byte wire field.
        (0x021F + subtype, caller_information[:32] + bytes(32), 0x54),
        (
            0x022F + subtype,
            b"".join(value.to_bytes(2, "big") for value in system_time),
            0x55,
        ),
    )
    return tuple(
        (
            b"\x2e" + did.to_bytes(2, "big") + value,
            b"\x6e" + did.to_bytes(2, "big"),
            error,
        )
        for did, value, error in fields
    )


def ethernet_routine_request(
    mode: int, area, required_spec: str
) -> tuple[bytes, bytes, int]:
    """Actual EthernetFlash2ab0 uses10F5/FF00/10F6 plus native CRC/CMAC/RSA."""
    from scripts.calibration_2026 import NativeLogicalArea2026

    if (
        type(mode) is not int
        or mode not in (0, 1, 2)
        or not isinstance(area, NativeLogicalArea2026)
    ):
        raise ValueError("Native routine mode and imported2026 logical area required")
    if type(required_spec) is not str or required_spec not in ("01", "03", "04"):
        raise ValueError("Recovered logical RequiredSpecReproVer required")
    if not 0 <= area.address <= 0xFFFFFFFF or not 0 < area.length <= 0xFFFFFFFF:
        raise ValueError("Native four-byte address/length required")
    rid = (b"\x10\xf5", b"\xff\0", b"\x10\xf6")[mode]
    payload = (
        b"\x31\x01"
        + rid
        + b"\x44"
        + area.address.to_bytes(4, "big")
        + area.length.to_bytes(4, "big")
    )
    if mode != 1:
        if area.crc is None:
            payload += b"\0\xff\xff\xff\xff"
        else:
            payload += b"\x04" + _bytes(area.crc, 4, 4)
        if required_spec == "03":
            payload += b"\0\x10" + _bytes(area.cmac, 16, 16)
        else:
            payload += b"\x01\0" + _bytes(area.digital_signature, 256, 256)
    return payload, b"\x71\x01" + rid, (0x56, 0x45, 0x4D)[mode]


def ethernet_srecord_stream_blocks(
    source,
    end: int,
    groups: tuple[tuple[int, int, int], ...],
    address: int,
    transfer_length: int,
    block_size: int,
    runtime: NativeRuntime2026 | None = None,
):
    """EthernetFlash3130: two descriptor groups and distinct first-S1 flag.

    Parser1bd0 equals P6 parser1980 after address-only normalization. The stream
    state machine differs: Ethernet consumes +118/+124 prefix flags; P6 does not.
    """
    from scripts.cuw_large import LargeSource2026
    from scripts.programming_2026_p6 import parse_phase6_srecord_window

    if (
        not isinstance(source, (bytes, LargeSource2026))
        or not 0 < len(source) <= 0xFFFFFFFF
    ):
        raise ValueError(
            "Authorized bounded source bytes or pinned large source required"
        )
    if type(end) is not int or not 0 <= end < len(source):
        raise ValueError("Native inclusive stream end required")
    if type(groups) is not tuple or not 1 <= len(groups) <= 2:
        raise ValueError("Ethernet native one/two descriptor groups required")
    for group in groups:
        if (
            type(group) is not tuple
            or len(group) != 3
            or any(
                type(value) is not int or not 0 <= value <= 0xFFFFFFFF
                for value in group
            )
            or group[1] > end
        ):
            raise ValueError("Native address/offset/first-S1 descriptor tuple required")
    _uint(address)
    if (
        type(transfer_length) is not int
        or not 0 < transfer_length <= 0xFFFFFFFF
        or type(block_size) is not int
        or not 1 <= block_size <= 0x1012
    ):
        raise ValueError("Bounded native Ethernet transfer/block size required")
    matches = [(offset, prefix) for start, offset, prefix in groups if start == address]
    if not matches:
        raise NativePassThruException2026(9999, "EthernetFlashWriter", 0x42F)
    start, prefix = matches[0]
    cursor = start
    first_s1 = prefix == 1
    sequence = 1
    written = 0
    pending = bytearray()
    window = b""
    window_start = cursor
    retried = False
    while start and cursor <= end and written < transfer_length:
        if runtime is not None:
            runtime.check()
        local = cursor - window_start
        if local >= len(window):
            window_start = cursor
            window = source[cursor : min(cursor + 0x500000, end + 1)]
            local = 0
        fragment = window[local:]
        record = parse_phase6_srecord_window(fragment)
        if record.status != 0 and not retried:
            retried = True
            window, window_start = b"", cursor
            continue
        if record.status == 2:
            raise NativePassThruException2026(9999, "EthernetFlashWriter", 0x48B)
        retried = False
        if cursor == start and (record.address or 0) < address:
            raise NativePassThruException2026(9999, "EthernetFlashWriter", 0x49E)
        if record.consumed <= 0:
            raise ValueError("Native stream parser made no progress")
        payload = record.payload
        if not first_s1 and fragment[1:2] == b"1":
            first_s1 = True
            payload = b""
        cursor += record.consumed
        payload = payload[: transfer_length - written - len(pending)]
        if len(pending) + len(payload) > block_size:
            raise NativePassThruException2026(9999, "EthernetFlashWriter", 0x4BD)
        pending.extend(payload)
        if pending and (
            len(pending) >= block_size
            or cursor > end
            or written + len(pending) >= transfer_length
        ):
            if cursor > end and written + len(pending) < transfer_length:
                pending.extend(
                    bytes(min(block_size, transfer_length - written) - len(pending))
                )
            yield sequence & 255, bytes(pending)
            written += len(pending)
            sequence += 1
            pending.clear()
    if pending:
        raise ValueError("Native Ethernet stream retains incomplete block")
    sequence = 1
    while written < transfer_length:
        if runtime is not None:
            runtime.check()
        size = min(block_size, transfer_length - written)
        yield sequence & 255, bytes(size)
        written += size
        sequence += 1


def _ethernet_writer(context: UnifiedContext2026, runtime: NativeRuntime2026) -> dict:
    """Actual Ethernet StartFlashWrite5750 ->21d0; retained prepared runtime."""
    import struct

    from scripts.calibration_2026 import (
        native2026_logical_archive,
        native2026_logical_cpu_flash_size,
        native2026_node_cpu_count,
    )
    from scripts.cuw_2026 import rks_software_identity2026
    from scripts.cuw_large import LargeSource2026, validate_large_materialization_2026
    from scripts.programming import ethernet_block_size
    from scripts.programming_2026_common import make_send_data_records

    metadata = context.metadata
    if not metadata.logical_blocks:
        raise ValueError("Imported Ethernet logical blocks required")
    rks_identity = context.observations.get("rks_software_identity")
    if rks_identity is None:
        rks_source = context.attachments.get("rks_ini")
        if type(rks_source) is not bytes:
            raise LookupError("Source-bound native RKS SoftwareID producer unavailable")
        rks_identity = rks_software_identity2026(rks_source)
    software_id = _bytes(rks_identity.software_id32, 32, 32)
    target = bytes.fromhex(metadata.node_values["logicaladdress"])
    client = EthernetUtils2026(runtime)
    if set(client._channels) != {0x8203, 0x8205, 0x8206}:
        raise ValueError(
            "Ethernet writer requires the retained prepared logical channels"
        )
    blocks = []
    totals: dict[int, int] = {}
    for block in metadata.logical_blocks:
        areas = {area.kind: area for area in block.areas}
        if "ReproData" not in areas:
            raise ValueError("Imported native ReproData area required")
        image = areas["ReproData"]
        routine = areas.get("EraseAndReproRoutine")
        if block.repro_method == "01" and routine is None:
            raise ValueError("Whole-package method01 requires native routine geometry")
        # Validate all required cryptographic widths before changing ECU state.
        ethernet_programming_information(
            block.did_subtype, block.nonce, software_id, (0,) * 8
        )
        ethernet_routine_request(1, image, block.required_spec)
        ethernet_routine_request(2, image, block.required_spec)
        if block.repro_method == "01":
            ethernet_routine_request(0, routine, block.required_spec)
        archives = {
            "ReproData": native2026_logical_archive(metadata, block, "ReproData")
        }
        if block.repro_method == "01":
            archives["EraseAndReproRoutine"] = native2026_logical_archive(
                metadata, block, "EraseAndReproRoutine"
            )
        for archive in archives.values():
            if archive.streamed:
                validate_large_materialization_2026(
                    metadata.source_container, archive.backing
                )
        totals[block.cpu_index] = (
            totals.get(block.cpu_index, 0)
            + image.length
            + (routine.length if routine is not None else 0)
        )
        blocks.append((block, image, routine, archives))
    baseline = blocks[0][2].length if blocks[0][2] is not None else 0
    written = dict.fromkeys(totals, 0)
    transferred = 0
    previous = _uint(runtime.call("get_timeout"))
    succeeded = False

    def send(block, payload, expected, error, minimum=None, pending=None):
        return client.send_request(
            target,
            payload,
            expected,
            minimum=4 + len(expected) if minimum is None else minimum,
            error=error,
            pending_seconds=block.routine_response_pending_limit
            if pending is None
            else pending,
        )

    def notify_progress(block, ordinal):
        value = written[block.cpu_index]
        if ordinal != 0 or value > baseline:
            total = totals[block.cpu_index]
            denominator = total if ordinal else total - baseline
            if total <= 0 or denominator <= 0:
                raise ValueError("Native Ethernet progress denominator cannot be zero")
            count_value = int(
                value
                / total
                * native2026_logical_cpu_flash_size(metadata, block.cpu_index)
            )
            percent_value = int(
                (value if ordinal else value - baseline) / denominator * 100
            )
            _set_native_progress(context, "count", block.cpu_index, count_value)
            runtime.call(
                "progress",
                field="count",
                cpu_index=block.cpu_index,
                value=count_value,
            )
            _set_native_progress(context, "percent", block.cpu_index, percent_value)
            runtime.call(
                "progress",
                field="percent",
                cpu_index=block.cpu_index,
                value=percent_value,
            )

    def transfer(block, area, archive, ordinal):
        nonlocal transferred
        request = (
            b"\x34\x01\x44"
            + area.address.to_bytes(4, "big")
            + area.length.to_bytes(4, "big")
        )
        reply = send(block, request, b"\x74", 0x1A, minimum=7)
        try:
            block_size = ethernet_block_size(reply[4:])
        except ValueError as error:
            raise NativePassThruException2026(
                0x1A, "EthernetFlashWriter", 899
            ) from error
        if archive.streamed:
            descriptor = archive.data
            if type(descriptor) is not bytes or len(descriptor) != 0x144:
                raise ValueError(
                    "Authenticated native large archive descriptor required"
                )
            source = LargeSource2026(metadata.source_container)
            end = struct.unpack_from("<I", descriptor, 0x10C)[0]
            if archive.backing.binary:
                start = struct.unpack_from("<I", descriptor, 0x114)[0]
                data_length = archive.length
                if start > end + 1 or data_length > end + 1 - start:
                    raise ValueError("Native binary backing span exceeds source")

                def binary_blocks():
                    for sequence, offset in enumerate(
                        range(0, data_length, block_size), 1
                    ):
                        runtime.check()
                        size = min(block_size, data_length - offset)
                        yield (
                            sequence & 255,
                            source[start + offset : start + offset + size],
                        )

                packets = binary_blocks()
            else:
                groups = tuple(
                    struct.unpack_from("<III", descriptor, offset)
                    for offset in (0x110, 0x11C)
                )
                packets = ethernet_srecord_stream_blocks(
                    source, end, groups, area.address, area.length, block_size, runtime
                )
        else:
            data = (
                make_send_data_records(archive.kind_records, area.address, area.length)
                if archive.kind_records
                else archive.data
            )
            _bytes(data, 1, 64 * 1024 * 1024)
            assert isinstance(data, bytes)
            packets = (
                (sequence & 255, data[offset : offset + block_size])
                for sequence, offset in enumerate(range(0, len(data), block_size), 1)
            )
        for counter, payload in packets:
            send(block, bytes((0x36, counter)) + payload, bytes((0x76, counter)), 0x22)
            written[block.cpu_index] += len(payload)
            transferred += len(payload)
            notify_progress(block, ordinal)
        send(block, b"\x37", b"\x77", 0x1C)

    try:
        timeout = context.parameter.parameter.long("ReceiveTimeoutBeforeGetCID")
        runtime.call(
            "set_timeout", milliseconds=_uint(0 if timeout is None else timeout)
        )
        for ordinal, (block, image, routine, archives) in enumerate(blocks):
            runtime.call("notify", field="logical_block", value=ordinal)
            if target == ESW1_ADDRESS:
                last_cpu = blocks[-1][0].cpu_index
                _notify_wait(
                    context,
                    runtime,
                    metadata.wakeup_ms if block.cpu_index == last_cpu else 0,
                )
            information = ethernet_programming_information(
                block.did_subtype, block.nonce, software_id, (0,) * 8
            )
            for payload, expected, error in information[:2]:
                send(block, payload, expected, error)
            words = runtime.call("get_system_time")
            payload, expected, error = ethernet_programming_information(
                block.did_subtype, block.nonce, software_id, words
            )[2]
            send(block, payload, expected, error)
            if block.repro_method == "01":
                transfer(block, routine, archives["EraseAndReproRoutine"], ordinal)
                payload, expected, error = ethernet_routine_request(
                    0, routine, block.required_spec
                )
                send(block, payload, expected, error)
            runtime.call("programming_notification", value=True)
            payload, expected, error = ethernet_routine_request(
                1, image, block.required_spec
            )
            send(block, payload, expected, error)
            transfer(block, image, archives["ReproData"], ordinal)
            payload, expected, error = ethernet_routine_request(
                2, image, block.required_spec
            )
            send(block, payload, expected, error)
            if (
                ordinal + 1 != len(blocks)
                and block.cpu_index != blocks[ordinal + 1][0].cpu_index
            ):
                runtime.call(
                    "notify", field="next_cpu", value=blocks[ordinal + 1][0].cpu_index
                )
        final = blocks[-1][0]
        send(final, b"\x11\x01", b"\x51\x01", 0x18, pending=180)
        client.stop_periodic()
        if target == ESW1_ADDRESS:
            errors = client.finish_diag_comm()
            if errors:
                raise RuntimeError("Ethernet logical teardown failed")
            remaining = metadata.wakeup_ms
            if remaining % 50:
                raise ValueError(
                    "Native Ethernet wake counter must terminate in50ms increments"
                )
            while remaining:
                runtime.call("wait", milliseconds=50)
                remaining -= 50
                _notify_wait(context, runtime, remaining)
            client.prepare_diag_comm()
        client.send_functional(b"\x10\x81", synchronous=True)
        errors = client.finish_diag_comm()
        if errors:
            raise RuntimeError("Ethernet logical teardown failed")
        runtime.call("programming_notification", value=False)
        succeeded = True
        return {
            "complete": True,
            "native_return": True,
            "operation": "StartFlashWrite",
            "module": context.identity.module_name,
            "source_sha256": context.identity.sha256,
            "transferred": transferred,
            "logical_blocks": len(blocks),
            "provenance": "source-recovered-2026-injected-primitives",
        }
    except (NativeException2026, NativeTransportError) as error:
        # Native2720 clears both arrays for every CPU in the selected node,
        # invokes their observers, tears down transport, then reads the shared
        # notification object. Other native handlers can change that object.
        first_cpu = sum(
            native2026_node_cpu_count(metadata, node_index)
            for node_index in range(metadata.node - 1)
        )
        for cpu_index in range(
            first_cpu,
            first_cpu + native2026_node_cpu_count(metadata, metadata.node - 1),
        ):
            for field_name in ("count", "percent"):
                _set_native_progress(context, field_name, cpu_index, 0)
        for field_name in ("count", "percent"):
            runtime.call("progress", field=field_name, value=0)
        client.stop_periodic()
        cleanup_errors = client.finish_diag_comm()
        if cleanup_errors:
            raise RuntimeError("Ethernet native fault teardown failed") from error
        notification = runtime.call("get_programming_notification")
        if type(notification) is not bool:
            raise TypeError("Actual shared native NotificationBool required")
        result = {
            "complete": False,
            "native_return": False,
            "state": "failed",
            "native_outcome": 2 if notification else 1,
            "error": type(error).__name__,
        }
        if not notification:
            result["native_comm_phase"] = 1
            if context.observations.get("dh_state") is not None:
                context.observations["dh_state"].mark_flash_code_failed()
        try:
            primary, secondary = native_error_fields2026(error)
        except TypeError:
            pass
        else:
            result["native_primary_error"] = primary
            if secondary is not None:
                result["native_passthru_error"] = secondary
        _record_native_error(context, result, 2 if notification else 1)
        return result
    finally:
        with _export_cleanup(native_return_unknown=False):
            try:
                runtime.call("set_timeout", milliseconds=previous, cleanup=True)
            finally:
                with _export_cleanup(native_return_unknown=False):
                    if not succeeded:
                        try:
                            if runtime.owns_resource("stop_sync_periodic"):
                                runtime.release("stop_sync_periodic")
                        finally:
                            with _export_cleanup(native_return_unknown=False):
                                client.finish_diag_comm()
