"""Native modern CID discovery with explicit, bounded host I/O providers."""

import math
import time
from collections.abc import Callable
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass

from scripts.programming import (
    NativeEthernetChannel,
    NativeNegativeResponse,
    NativePendingTimeout,
    NativeProgrammingChannel,
    NativeTransportError,
    NativeUnexpectedResponse,
    decode_native_data,
    native_data_request,
)
from scripts.programming_vendor import VendorP5Channel


@dataclass(frozen=True)
class CIDNode:
    request_id: bytes
    response_id: bytes
    extended_addressing: bool = False
    wake_ms: int = 0

    def __post_init__(self):
        if type(self.extended_addressing) is not bool:
            raise ValueError("Boolean native addressing flag required")
        width = 3 if self.extended_addressing else 2
        if any(
            not isinstance(v, bytes) or len(v) != width
            for v in (self.request_id, self.response_id)
        ):
            raise ValueError("Resolved two/three-byte native diagnostic IDs required")
        if type(self.wake_ms) is not int or not 0 <= self.wake_ms <= 0xFFFFFFFF:
            raise ValueError("Native unsigned wake time required")


@dataclass(frozen=True)
class ChargeBus:
    controller: CIDNode
    start_ms: int = 0

    def __post_init__(self):
        if (
            not isinstance(self.controller, CIDNode)
            or self.controller.extended_addressing
        ):
            raise ValueError("Two-byte charge-bus controller required")
        if type(self.start_ms) is not int or not 0 <= self.start_ms <= 0xFFFFFFFF:
            raise ValueError("Native unsigned charge start time required")


def decode_software_ids(response: bytes) -> list[str]:
    """Count plus fixed sixteen-byte records, exactly as the modern getters."""
    if (
        not isinstance(response, bytes)
        or not 20 <= len(response) <= 4116
        or not response.startswith(b"\x62\xf1\x81")
    ):
        raise ValueError("Malformed modern software ID response")
    if len(response) != 4 + response[3] * 16:
        raise ValueError("Software ID count/length mismatch")
    # Latin-1 preserves native string bytes without inventing UTF-8 semantics.
    return [
        record.split(b"\0", 1)[0].decode("latin1")
        for offset in range(4, len(response), 16)
        if (record := response[offset : offset + 16])[0]
    ]


def supported_rob(response: bytes) -> tuple[int, ...]:
    if (
        not isinstance(response, bytes)
        or not 7 <= len(response) <= 4116
        or not response.startswith(b"\x71\x01\x10\x00")
    ):
        raise ValueError("Malformed native supported-RID response")
    return tuple(
        rob
        for offset, mask, rob in ((4, 16, 1), (4, 8, 0x11), (6, 16, 0x21), (6, 8, 0x31))
        if response[offset] & mask
    )


def _swin(response: bytes) -> str:
    if (
        not isinstance(response, bytes)
        or not 3 <= len(response) <= 4116
        or not response.startswith(b"\x62\x1f\xff")
    ):
        raise ValueError("Malformed SWIN response")
    payload = response[3:33]
    if any(byte != 0 and not 0x20 <= byte <= 0x7E for byte in payload):
        return ""
    return payload.split(b"\0", 1)[0].decode("ascii")


@contextmanager
def ethernet_diagnostic_lifecycle(
    action: Callable[[dict, float], object],
    deadline: float,
    *,
    clock: Callable[[], float] = time.monotonic,
    cancelled: Callable[[], bool] = lambda: False,
    cleanup_timeout: float = 30,
):
    """Recovered EthernetUtils link/discovery/routing lifecycle over host primitives.

    Logical channels are resource-owned here; the outer caller owns Connect0500.
    Read events return J2534 payload bytes, not socket packets or invented peers.
    """

    if (
        isinstance(deadline, bool)
        or not isinstance(deadline, (int, float))
        or not math.isfinite(deadline)
    ):
        raise ValueError("Finite absolute preparation deadline required")
    if (
        isinstance(cleanup_timeout, bool)
        or not isinstance(cleanup_timeout, (int, float))
        or not math.isfinite(cleanup_timeout)
        or cleanup_timeout <= 0
    ):
        raise ValueError("Finite positive cleanup timeout required")

    def host(operation: str, *, cleanup: bool = False, **values):
        if not cleanup:
            if cancelled():
                raise InterruptedError("Ethernet preparation cancelled")
            if clock() >= deadline:
                raise TimeoutError("Ethernet preparation deadline expired")
        return action(
            {"operation": operation, **values},
            cleanup_timeout if cleanup else max(0.0, deadline - clock()),
        )

    def read(protocol: int, minimum: int = 0) -> bytes:
        value = host("read_messages", protocol=protocol, count=1)
        if not isinstance(value, bytes) or not minimum <= len(value) <= 4128:
            raise ValueError("Bounded native Ethernet read bytes required")
        return value

    def timed_read(timeout_ms: int, operation: Callable[[], bytes]):
        old = host("get_timeout")
        if type(old) is not int or not 0 <= old <= 0xFFFFFFFF:
            raise ValueError("Prior native timeout required")
        try:
            host("set_timeout", milliseconds=timeout_ms)
            return operation()
        finally:
            host("set_timeout", cleanup=True, milliseconds=old)

    with ExitStack() as resources:
        status = host("control_io", ioctl=1, parameter=0x8060)
        if type(status) is not int or not 0 <= status <= 0xFFFFFFFF:
            raise ValueError("Native Ethernet link status required")
        if status != 1:

            def link_up():
                host("control_io", ioctl=2, parameter=0x805F, value=1)
                return read(0x800F)

            timed_read(5000, link_up)
        for protocol in (0x8203, 0x8205):
            host("logical_connect", protocol=protocol)
            resources.callback(
                lambda protocol=protocol: host(
                    "logical_disconnect", cleanup=True, protocol=protocol
                )
            )
        with ExitStack() as discovery:
            host("logical_connect_udp_discovery")
            discovery.callback(
                lambda: host("logical_disconnect_udp_discovery", cleanup=True)
            )

            def identify():
                host(
                    "queue_messages",
                    protocol=0x8205,
                    tx_flags=1,
                    count=1,
                    payload_hex="ffffffff3458ff00000100000000",
                )
                return read(0x8205, 4)

            peer = timed_read(2000, identify)[:4]
        host("logical_connect", protocol=0x8206, peer_ipv4_hex=peer.hex())
        resources.callback(
            lambda: host("logical_disconnect", cleanup=True, protocol=0x8206)
        )
        host(
            "queue_messages",
            protocol=0x8208,
            tx_flags=1,
            count=1,
            payload_hex="02fd0005000000070e800000000000",
        )
        response = host("read_tcp_message")
        if not isinstance(response, bytes) or len(response) != 9 or response[4] != 0x10:
            raise ValueError("Native routing activation failed (0x5d)")
        if cancelled():
            raise InterruptedError("Ethernet routing activation cancelled")
        if clock() >= deadline:
            raise TimeoutError("Ethernet routing activation exceeded deadline")
        yield {"peer_ipv4_hex": peer.hex()}


def get_cids(
    action: Callable[[dict, float], object],
    exchange: Callable[[str, bytes], bytes],
    nodes: tuple[CIDNode, ...],
    *,
    family: str,
    mode: int,
    receive_timeout_ms: int,
    version: int = 18,
    charge_bus: ChargeBus | None = None,
    timeout_allowing_id: bytes | None = None,
    timeout: float = 30,
    cancelled: Callable[[], bool] = lambda: False,
    clock: Callable[[], float] = time.monotonic,
    receive: Callable[[str], bytes] | None = None,
    channel_factory: Callable[..., NativeProgrammingChannel] | None = None,
) -> dict:
    """Run StartGetCID's modern node loop; no device or network is opened.

    action performs actual host callbacks, receives remaining seconds, raises on failure,
    and returns the prior integer timeout for get_timeout and an opaque non-None
    owned token for start_filter/start_periodic. No callback means no lifecycle.
    Channels normalize UDS; IDs/filtering and Ethernet routing remain explicit.
    """
    if type(version) is not int or version not in (12, 18):
        raise ValueError("Verified CUW12/18 source version required")
    if channel_factory is not None and (
        family != "unified" or not callable(channel_factory)
    ):
        raise ValueError("Native CAN P5 channel factory required")
    if version == 12 and (family == "ethernet" or charge_bus is not None):
        raise ValueError("CUW12 contains neither Ethernet nor charge-bus getter paths")
    if (
        family not in ("unified", "ethernet")
        or type(mode) is not int
        or mode not in (1, 2)
    ):
        raise ValueError("Recovered modern family and CID mode 1/2 required")
    if (
        not isinstance(nodes, tuple)
        or len(nodes) > 4096
        or any(not isinstance(node, CIDNode) for node in nodes)
    ):
        raise ValueError("Bounded resolved CID node tuple required")
    if type(receive_timeout_ms) is not int or not 0 <= receive_timeout_ms <= 0xFFFFFFFF:
        raise ValueError("Resolved native receive timeout required")
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(timeout)
        or timeout <= 0
    ):
        raise ValueError("Finite positive discovery timeout required")
    if charge_bus is not None and (
        family != "unified" or not isinstance(charge_bus, ChargeBus)
    ):
        raise ValueError("Charge bus is a Unified-only resolved controller")
    if timeout_allowing_id is not None and (
        family != "unified"
        or not isinstance(timeout_allowing_id, bytes)
        or len(timeout_allowing_id) not in (2, 3)
    ):
        raise ValueError("Unified request ID required for native allowed timeout")
    if family == "ethernet" and any(
        node.extended_addressing or node.request_id != node.response_id
        for node in nodes
    ):
        raise ValueError(
            "Ethernet uses one two-byte logical address for request/response"
        )
    deadline = clock() + timeout
    events: list[dict] = []
    result: dict = {
        "family": family,
        "version": version,
        "mode": mode,
        "compatibility_evaluated": version == 18 and mode == 1,
        "nodes": [],
        "compatible": False if version == 18 else None,
        "events": events,
    }

    def host(operation: str, *, cleanup: bool = False, **values):
        if not cleanup and (cancelled() or clock() >= deadline):
            if cancelled():
                raise InterruptedError("CID discovery cancelled")
            raise TimeoutError("CID discovery deadline expired")
        event = {"operation": operation, **values}
        events.append(event)
        value = action(event, timeout if cleanup else max(0.0, deadline - clock()))
        return value

    def can_channel(exchange, ecu, budget, cancellation, received, *, cleanup=False):
        def saved_timeout():
            value = host("get_timeout", cleanup=cleanup)
            if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
                raise ValueError("Native P5 timeout must be uint32")
            return value

        def set_timeout(value):
            late = cleanup or cancelled() or clock() >= deadline
            result = host("set_timeout", cleanup=late, milliseconds=value)
            if result is not None:
                raise TypeError("Native P5 timeout setter must return None")

        def expired_write(target, payload):
            count = host(
                "write_diagnostic",
                cleanup=cleanup,
                request_id_hex=target,
                payload_hex=payload.hex(),
            )
            if type(count) is not int or count != 1:
                raise OSError("Native pending-expiry write was not accepted")

        arguments = (exchange, ecu, budget, cancellation, clock, received)
        options = {
            "pending_response_timeout_seconds": 180,
            "pending_timeout_write": expired_write,
        }
        if channel_factory is None:
            value = VendorP5Channel(
                *arguments,
                **options,
                get_timeout=saved_timeout,
                set_timeout=set_timeout,
                minimum_response_timeout_ms=5530,
            )
        else:
            value = channel_factory(*arguments, **options)
        if not isinstance(value, VendorP5Channel):
            raise TypeError("CID channel must preserve the native P5 receive policy")
        return value

    def channel(node: CIDNode):
        remaining = deadline - clock()
        if remaining <= 0:
            raise TimeoutError("CID discovery deadline expired")
        if family == "ethernet":
            return NativeEthernetChannel(
                exchange,
                node.request_id.hex(),
                node.request_id,
                remaining,
                cancelled,
                clock,
                receive,
            )
        return can_channel(
            exchange, node.request_id.hex(), remaining, cancelled, receive
        )

    def call(ch: NativeProgrammingChannel, request: bytes, prefix: bytes, minimum: int):
        response = ch.call(request, prefix)
        if len(response) < minimum:
            raise NativeUnexpectedResponse(request, response)
        return response

    def token(operation: str, **values):
        value = host(operation, **values)
        if value is None:
            raise ValueError(f"{operation} must return an owned resource token")
        return value

    def cleanup_call(ch: NativeProgrammingChannel, request: bytes, prefix: bytes):
        # Cleanup uses the same provider even after cancellation/deadline.
        cleanup = (
            can_channel(
                ch.exchange, ch.ecu, timeout, lambda: False, receive, cleanup=True
            )
            if family == "unified"
            else NativeProgrammingChannel(
                ch.exchange,
                ch.ecu,
                timeout,
                clock=clock,
                receive=ch.receive,
                message_limit=ch.message_limit,
            )
        )
        cleanup.call(request, prefix)

    def ethernet_host(event: dict, remaining_seconds: float):
        events.append(event)
        return action(event, remaining_seconds)

    with ExitStack() as lifecycle:
        host("connect", protocol=6 if family == "unified" else 0x800F)
        lifecycle.callback(lambda: host("disconnect", cleanup=True))
        old_timeout = host("get_timeout")
        if type(old_timeout) is not int or not 0 <= old_timeout <= 0xFFFFFFFF:
            raise ValueError(
                "Host get_timeout must return prior native unsigned timeout"
            )
        lifecycle.callback(
            lambda: host("set_timeout", cleanup=True, milliseconds=old_timeout)
        )
        host("set_timeout", milliseconds=receive_timeout_ms)
        wake = max((node.wake_ms for node in nodes), default=0)
        if wake:
            host("wait", milliseconds=wake)
        if family == "ethernet":
            lifecycle.enter_context(
                ethernet_diagnostic_lifecycle(
                    ethernet_host,
                    deadline,
                    clock=clock,
                    cancelled=cancelled,
                    cleanup_timeout=timeout,
                )
            )
        if charge_bus is not None:
            controller = charge_bus.controller
            controller_ch = channel(controller)
            with ExitStack() as charge_filter:
                resource = token(
                    "start_filter",
                    request_id_hex=controller.request_id.hex(),
                    response_id_hex=controller.response_id.hex(),
                )
                charge_filter.callback(
                    lambda: host("stop_filter", cleanup=True, token=resource)
                )
                call(controller_ch, b"\x10\x03", b"\x50\x03", 2)

            def default_session():
                with ExitStack() as filters:
                    resource = host(
                        "start_filter",
                        cleanup=True,
                        request_id_hex=controller.request_id.hex(),
                        response_id_hex=controller.response_id.hex(),
                    )
                    if resource is None:
                        raise ValueError(
                            "Default session requires an owned filter token"
                        )
                    filters.callback(
                        lambda: host("stop_filter", cleanup=True, token=resource)
                    )
                    cleanup_call(controller_ch, b"\x10\x01", b"\x50\x01")

            lifecycle.callback(default_session)
            periodic = token(
                "start_periodic",
                request_id_hex=controller.request_id.hex(),
                payload_hex="3e80",
                interval_ms=2000,
                wait_ms=100,
                count=1,
                timeout_ms=1000,
            )
            lifecycle.callback(
                lambda: host("stop_periodic", cleanup=True, token=periodic)
            )

            def power(off: bool, cleanup: bool = False):
                with ExitStack() as filters:
                    resource = host(
                        "start_filter",
                        cleanup=cleanup,
                        request_id_hex=controller.request_id.hex(),
                        response_id_hex=controller.response_id.hex(),
                    )
                    if resource is None:
                        raise ValueError(
                            "Charge routine requires an owned filter token"
                        )
                    filters.callback(
                        lambda: host("stop_filter", cleanup=True, token=resource)
                    )
                    request = bytes((0x31, 2 if off else 1, 0x11, 0x7E))
                    prefix = bytes((0x71, request[1], 0x11, 0x7E))
                    if cleanup:
                        cleanup_call(controller_ch, request, prefix)
                    else:
                        call(controller_ch, request, prefix, 4)

            # Register inverse before attempting power-on: failed calls can mutate ECU.
            lifecycle.callback(lambda: power(True, True))
            power(False)
            if charge_bus.start_ms:
                host("wait", milliseconds=charge_bus.start_ms)
        all_ids: list[str] = []
        for node in nodes:
            ch = channel(node)
            entry: dict = {
                "request_id_hex": node.request_id.hex(),
                "software_ids": [],
                "timed_out": False,
            }
            result["nodes"].append(entry)
            with ExitStack() as local:
                if family == "unified":
                    if node.extended_addressing:
                        host("set_bs_to_ecu", enabled=True)
                        local.callback(
                            lambda: host("set_bs_to_ecu", cleanup=True, enabled=False)
                        )
                    resource = token(
                        "start_filter",
                        request_id_hex=node.request_id.hex(),
                        response_id_hex=node.response_id.hex(),
                        extended_addressing=node.extended_addressing,
                    )
                    local.callback(
                        lambda resource=resource: host(
                            "stop_filter", cleanup=True, token=resource
                        )
                    )
                try:
                    ids = decode_software_ids(
                        call(ch, b"\x22\xf1\x81", b"\x62\xf1\x81", 20)
                    )
                    entry["software_ids"] = ids
                    all_ids.extend(ids)
                    if version == 18 and mode == 1:
                        compatible = any("!" in cid for cid in all_ids)
                        if not compatible:
                            support = supported_rob(
                                call(
                                    ch,
                                    b"\x31\x01\x10\x00",
                                    b"\x71\x01\x10\x00",
                                    36 if family == "ethernet" else 7,
                                )
                            )
                            for rob in support:
                                response = call(
                                    ch, bytes((0xAB, rob)), bytes((0xEB, rob)), 2
                                )
                                payload = response[2:]
                                if len(payload) % 2:
                                    raise ValueError("Partial native RoB DID pair")
                                if any(
                                    payload[offset : offset + 2]
                                    in (b"\xf0\x21", b"\xf0\x22")
                                    for offset in range(0, len(payload), 2)
                                ):
                                    compatible = True
                                    break
                        entry["compatible"] = compatible
                        result["compatible"] |= compatible
                    elif version == 18:
                        for name in ("slave_cid", "assembly_p5", "serial", "cbest"):
                            spec = native_data_request(name)
                            try:
                                response = call(
                                    ch,
                                    bytes.fromhex(spec["request_hex"]),
                                    bytes.fromhex(spec["response_prefix_hex"]),
                                    spec["minimum_response_bytes"],
                                )
                            except (
                                NativeNegativeResponse,
                                NativeTransportError,
                                NativePendingTimeout,
                                NativeUnexpectedResponse,
                            ) as exc:
                                entry[name] = [] if name == "slave_cid" else ""
                                entry.setdefault("optional_errors", {})[name] = {
                                    "type": type(exc).__name__,
                                    "code": getattr(exc, "code", None),
                                }
                                continue
                            entry[name] = decode_native_data(name, response)
                except NativeTransportError as exc:
                    if timeout_allowing_id != node.request_id or exc.code not in (
                        9,
                        16,
                    ):
                        raise
                    entry["timed_out"] = True
            if (
                version == 18
                and mode == 2
                and node.request_id
                == (b"\x07\x92" if family == "unified" else b"\x01\x00")
            ):
                if wake < 5000:
                    host("wait", milliseconds=5000 - wake)
                # FCM owns a separate native filter; ADS shares prepared Ethernet.
                with ExitStack() as swin_filter:
                    if family == "unified":
                        resource = token(
                            "start_filter",
                            request_id_hex="0792",
                            response_id_hex="079a",
                        )
                        swin_filter.callback(
                            lambda resource=resource: host(
                                "stop_filter", cleanup=True, token=resource
                            )
                        )
                        swin_ch = channel(CIDNode(b"\x07\x92", b"\x07\x9a"))
                    else:
                        swin_ch = ch
                    try:
                        entry["swin"] = _swin(
                            call(swin_ch, b"\x22\x1f\xff", b"\x62\x1f\xff", 3)
                        )
                    except (
                        NativeNegativeResponse,
                        NativeTransportError,
                        NativePendingTimeout,
                        NativeUnexpectedResponse,
                    ) as exc:
                        entry["swin"] = ""
                        entry.setdefault("optional_errors", {})["swin"] = {
                            "type": type(exc).__name__,
                            "code": getattr(exc, "code", None),
                        }
        if cancelled():
            raise InterruptedError("CID discovery cancelled")
        if clock() >= deadline:
            raise TimeoutError("CID discovery deadline expired")
    if cancelled():
        raise InterruptedError("CID discovery cancelled after cleanup")
    if clock() >= deadline:
        raise TimeoutError("CID discovery deadline expired after cleanup")
    result["native_result"] = True
    return result
