"""Evidence-backed, injected JLR CAN/firmware ISO/K-line. PHYSICAL_UNCONFIRMED.

No USB discovery, opening, ECU requests, or firmware changes happen on import.
See docs/jlr-channels.md for wire evidence and deliberately limited semantics.
"""

from __future__ import annotations

import math
import struct
import threading
import time
from builtins import ExceptionGroup
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass

from scripts.diagnostics import validate_ecu
from scripts.isotp import Peer, ProtocolError, Receiver, Sender
from scripts.jlr import JLRClient


@dataclass(frozen=True)
class CANRoute:
    slot: int
    board_type: int
    target: int
    resource: int
    pin1: int
    pin2: int


def can_routes(board_reply: bytes) -> tuple[CANRoute, ...]:
    """Advertised raw CAN routes; reject unknown boards and unlisted pin pairs."""
    if len(board_reply) != 180:
        raise ValueError("Board109 requires header20 and eight records20")
    if struct.unpack_from("<3H", board_reply) != (0, 1, 0x8109):
        raise ValueError("Not a device1 Board109 reply")
    if struct.unpack_from("<I", board_reply, 12)[0]:
        raise ValueError("Board109 returned an error")
    routes = []
    for index in range(8):
        board_type = board_reply[20 + index * 20]
        # Default CAN rows for types1..11 share family0/variant0/kind1, pins6/14.
        if 1 <= board_type <= 11:
            slot = 1 << index
            routes.append(CANRoute(slot, board_type, 0x0500 | slot, 1, 6, 14))
            if board_type in (5, 7, 8, 11):
                resource = {5: 4, 7: 5, 8: 3, 11: 3}[board_type]
                routes.append(
                    CANRoute(slot, board_type, 0x1500 | slot, resource, 3, 11)
                )
                if board_type in (8, 11):
                    routes.append(
                        CANRoute(slot, board_type, 0x1500 | slot, resource, 12, 13)
                    )
    return tuple(routes)


def can_data(can_id: int, data: bytes, extended: bool = False) -> bytes:
    if not 0 <= can_id <= (0x1FFFFFFF if extended else 0x7FF) or len(data) > 8:
        raise ValueError("Invalid Classical CAN identifier/data")
    return can_id.to_bytes(4, "big") + data


@dataclass(frozen=True)
class CANFrame:
    status: int
    timestamp: int
    can_id: int
    data: bytes


def decode_can_event(payload: bytes, target: int) -> CANFrame:
    if len(payload) < 28 or struct.unpack_from("<3H", payload) != (0, target, 9):
        raise ValueError("Not a complete CAN RX event for this channel")
    status, timestamp, _unknown, size = struct.unpack_from("<IIHH", payload, 12)
    if not 4 <= size <= 12 or len(payload) != 24 + size:
        raise ValueError("Invalid CAN RX size")
    can_id = int.from_bytes(payload[24:28], "big")
    data = payload[28:]
    can_data(can_id, data, bool(status & 0x100))
    return CANFrame(status, timestamp, can_id, data)


@dataclass(frozen=True)
class TxEvent:
    source: int
    sequence: int
    remaining_count: int
    status: int
    timestamp: int
    tail: bytes


def decode_tx_event(payload: bytes, target: int) -> TxEvent:
    if len(payload) < 20 or struct.unpack_from("<3H", payload) != (0, target, 0x0A):
        raise ValueError("Not a complete CAN TX event for this channel")
    _, source, _, sequence, count, _ = struct.unpack_from("<6H", payload)
    status, timestamp = struct.unpack_from("<II", payload, 12)
    return TxEvent(source, sequence, count, status, timestamp, payload[20:])


@dataclass(frozen=True)
class Submission:
    target: int
    sequence: int
    remaining_count: int
    ack_status: int
    deadline: float

    def correlates(self, event: TxEvent) -> bool:
        return (self.target, self.sequence, self.remaining_count) == (
            event.source,
            event.sequence,
            event.remaining_count,
        )


@dataclass(frozen=True)
class TxTimeout:
    submission: Submission


class CANSession:
    """One exclusively owned device/channel with a bounded receive worker.

    Transport is injected; caller explicitly invokes open. Caller owns the USB
    transport and must close it even if this session's close raises. Protocol
    subclasses share this bounded lifecycle; no physical completion is promised.
    """

    def __init__(
        self,
        client: JLRClient,
        board_reply: bytes,
        route: CANRoute,
        baud: int,
        receive_id: int,
        *,
        extended: bool = False,
        queue_limit: int = 256,
        pending_limit: int = 32,
    ):
        route_fields = ("slot", "board_type", "target", "resource", "pin1", "pin2")
        if not any(
            all(
                getattr(route, field) == getattr(candidate, field)
                for field in route_fields
            )
            and (
                not isinstance(candidate, ProtocolRoute)
                or (
                    isinstance(route, ProtocolRoute)
                    and route.protocol == candidate.protocol
                )
            )
            for candidate in self.routes(board_reply)
        ):
            raise ValueError("Route is not advertised by supplied Board109 reply")
        if not 1 <= baud <= 0xFFFFFFFF:
            raise ValueError("Invalid CAN baud")
        if not 1 <= queue_limit <= 1024 or not 1 <= pending_limit <= 255:
            raise ValueError("Invalid queue bounds")
        can_data(receive_id, b"", extended)
        self.client, self.route, self.baud = client, route, baud
        self.receive_id, self.flags = receive_id, 0x100 if extended else 0
        self.queue_limit, self.pending_limit = queue_limit, pending_limit
        self._events: deque[CANFrame | DataFrame | TxEvent | TxTimeout | bytes] = (
            deque()
        )
        self._pending: dict[int, Submission] = {}
        self._used_sequences: set[int] = set()
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._worker: threading.Thread | None = None
        self._error: Exception | None = None
        self._device = self._connected = self._pins = self._filter_attempt = False
        self._filter: int | None = None
        self._extra_filters: set[tuple[int, int]] = set()
        self._extra_filter_modes: set[int] = set()
        self._periodics: set[int] = set()
        self._periodic_attempt = False
        self._repeat_attempt = False
        self._functional_attempt = False
        self._repeats: set[int] = set()
        self._ready = False
        self._finished = False
        self._cleanup_failed = False

    routes = staticmethod(can_routes)
    filter_mode = 0

    @property
    def periodic_target(self) -> int:
        return self.route.target

    def _configure_open(self) -> None:
        pass

    def _filter_body(self) -> bytes:
        return (
            struct.pack("<IHBB", 0, self.flags, 1, 4)
            + b"\xff" * 4
            + self.receive_id.to_bytes(4, "big")
        )

    def _decode_rx(self, payload: bytes):
        return decode_can_event(payload, self.route.target)

    def _command(self, target: int, opcode: int, body: bytes = b"", **kwargs) -> bytes:
        try:
            return self.client.transact(
                target, opcode, body, timeout=kwargs.pop("timeout", 0.5), **kwargs
            )
        except Exception:
            if not kwargs.get("cleanup", False):
                self._ready = False
                self._stop.set()
            raise

    def open(self) -> None:
        if self._device or self._finished:
            raise RuntimeError("Session has already been opened or closed")
        with self.client.io_lock:
            if self.client.channel_owner is not None:
                raise RuntimeError("JLR client already owns a channel")
            self.client.channel_owner = self
        # Attempts are recorded before I/O: a lost reply may still have applied.
        self._device = True
        try:
            self._command(1, 3)
            self._connected = True
            self._command(
                self.route.target, 6, struct.pack("<II", self.flags, self.baud)
            )
            self._pins = True
            self._command(
                self.route.target,
                0x12,
                struct.pack("<III", 1, self.route.pin1, self.route.pin2),
            )
            self._configure_open()
            body = self._filter_body()
            self._filter_attempt = True
            reply = self._command(self.route.target, 0x0D, body)
            if len(reply) < 24:
                raise ValueError("Filter reply lacks hardware ID")
            self._filter = struct.unpack_from("<I", reply, 20)[0]
            self._ready = True
            self._worker = threading.Thread(
                target=self._pump, name="jlr-can-rx", daemon=True
            )
            self._worker.start()
        except Exception as original:
            try:
                self.close()
            except Exception as cleanup:  # noqa: BLE001 - preserve the original open failure.
                original.add_note(f"Session cleanup also failed: {cleanup}")
            raise

    def _enqueue(
        self, event: CANFrame | DataFrame | TxEvent | TxTimeout | bytes
    ) -> None:
        if len(self._events) >= self.queue_limit:
            raise BufferError("CAN event queue is full; session stopped")
        self._events.append(event)

    def _pump(self) -> None:
        try:
            while not self._stop.is_set():
                with self.client.io_lock, self._lock:
                    packets = self.client.poll_events(25)
                    for payload in packets:
                        if len(payload) < 6:
                            raise ValueError("Truncated channel event")
                        destination, source, opcode = struct.unpack_from("<3H", payload)
                        if (destination, source, opcode) == (0, self.route.target, 9):
                            self._enqueue(self._decode_rx(payload))
                        elif (destination, source, opcode) == (
                            0,
                            self.route.target,
                            0x0A,
                        ):
                            event = decode_tx_event(payload, self.route.target)
                            submission = self._pending.get(event.sequence)
                            # 0x106 proves matching loopback notification, not ECU delivery.
                            if (
                                submission
                                and submission.correlates(event)
                                and event.status == 0x106
                            ):
                                del self._pending[event.sequence]
                            self._enqueue(event)
                        else:
                            self._enqueue(payload)
                    now = time.monotonic()
                    for sequence, submission in tuple(self._pending.items()):
                        if now >= submission.deadline:
                            self._enqueue(TxTimeout(submission))
                            del self._pending[sequence]
                # Fake transports may return immediately; avoid a busy-spin.
                self._stop.wait(0.001)
        except Exception as error:  # noqa: BLE001 - surface worker failures to the owner.
            with self._lock:
                self._error = error
                self._ready = False
            self._stop.set()

    def _check(self) -> None:
        if self._error is not None:
            raise RuntimeError(
                "CAN receive worker failed; close session"
            ) from self._error
        if not self._ready or self._stop.is_set():
            raise RuntimeError("CAN session is not ready")

    def submit_frame(
        self, can_id: int, data: bytes, *, timeout_ms: int = 1000
    ) -> Submission:
        if not 1 <= timeout_ms <= 10000:
            raise ValueError("Write timeout must be 1..10000 ms")
        raw = can_data(can_id, data, bool(self.flags))
        return self._submit(raw, self.flags, timeout_ms)

    def _submit(self, raw: bytes, flags: int, timeout_ms: int) -> Submission:
        # Same order as worker: transport lock, then session lock. Protect insertion
        # until the ack and already-buffered event can be correlated together.
        with self.client.io_lock, self._lock:
            self._check()
            if len(self._pending) >= self.pending_limit:
                raise BufferError("CAN pending submission queue is full")
            sequence = self.client.sequence % 255 + 1
            # shortcut: forbid sequence reuse per session; reopen after <=255 writes
            # until physical evidence establishes safe late-event eviction.
            if sequence in self._used_sequences:
                raise BufferError("CAN write sequence would be reused; close session")
            self._used_sequences.add(sequence)
            body = struct.pack("<IIHH", flags, timeout_ms, len(raw), 0) + raw
            try:
                reply = self._command(
                    self.route.target, 8, body, count=1, accepted_statuses=(0, 0x101)
                )
            except Exception:
                self._ready = False
                self._stop.set()
                raise
            submission = Submission(
                self.route.target,
                sequence,
                1,
                struct.unpack_from("<I", reply, 12)[0],
                time.monotonic() + timeout_ms / 1000,
            )
            self._pending[sequence] = submission
            return submission

    def events(self) -> tuple[CANFrame | DataFrame | TxEvent | TxTimeout | bytes, ...]:
        """Drain retained notifications; errors remain observable after draining."""
        with self._lock:
            result = tuple(self._events)
            self._events.clear()
            if not result and self._error is not None:
                raise RuntimeError(
                    "CAN receive worker failed; close session"
                ) from self._error
            return result

    def get_value(self, parameter: int) -> int:
        if not 0 <= parameter <= 0xFFFFFFFF:
            raise ValueError("Invalid parameter ID")
        with self.client.io_lock, self._lock:
            self._check()
            reply = self._command(self.route.target, 0x0C, struct.pack("<I", parameter))
            if len(reply) < 28:
                raise ValueError("GetValue reply lacks value at +24")
            return struct.unpack_from("<I", reply, 24)[0]

    def set_value(self, parameter: int, value: int) -> None:
        """Low-level firmware parameter pair; device rejects unsupported IDs/values."""
        if not 0 <= parameter <= 0xFFFFFFFF or not 0 <= value <= 0xFFFFFFFF:
            raise ValueError("Invalid parameter/value")
        with self.client.io_lock, self._lock:
            self._check()
            self._command(self.route.target, 0x0B, struct.pack("<II", parameter, value))

    def start_message_filter(
        self, mask: bytes, pattern: bytes, *, block: bool = False
    ) -> int:
        if self.filter_mode == 2:
            raise ValueError(
                "Firmware ISO requires its configured flow-control peer filter"
            )
        limit = 255 if isinstance(self, (KLineSession, ByteSession)) else 4
        if (
            not isinstance(mask, bytes)
            or not isinstance(pattern, bytes)
            or len(mask) != len(pattern)
            or not 1 <= len(mask) <= limit
            or (limit == 4 and len(mask) != 4)
        ):
            raise ValueError("Invalid message-filter mask/pattern sizes")
        mode = int(block)
        with self.client.io_lock, self._lock:
            self._check()
            if len(self._extra_filters) >= 10:
                raise BufferError("Host message-filter bound exhausted")
            self._extra_filter_modes.add(mode)
            body = (
                struct.pack("<IHBB", mode, self.flags & 0x100, mode + 1, len(mask))
                + mask
                + pattern
            )
            reply = self._command(self.route.target, 0x0D, body)
            if len(reply) < 24:
                raise ValueError("Filter reply lacks hardware ID")
            hardware_id = struct.unpack_from("<I", reply, 20)[0]
            if (mode, hardware_id) in self._extra_filters or (
                mode == self.filter_mode and hardware_id == self._filter
            ):
                raise ProtocolError("Device reused an active filter ID")
            self._extra_filters.add((mode, hardware_id))
            return hardware_id

    def stop_message_filter(self, hardware_id: int, *, block: bool = False) -> None:
        mode = int(block)
        with self.client.io_lock, self._lock:
            self._check()
            if (mode, hardware_id) not in self._extra_filters:
                raise ValueError("Filter ID is not owned by this API")
            self._command(
                self.route.target, 0x0E, struct.pack("<II", mode, hardware_id)
            )
            self._extra_filters.remove((mode, hardware_id))

    def start_periodic(self, data: bytes, interval_ms: int, *, flags: int = 0) -> int:
        if isinstance(self, FirmwareISOSession):
            if not isinstance(data, bytes) or not 1 <= len(data) <= (
                6 if self.peer.tx_address is not None else 7
            ):
                raise ValueError("Firmware ISO periodic requires a single-frame PDU")
            if flags:
                raise ValueError("Unsupported firmware ISO periodic flags")
            address = (
                bytes([self.peer.tx_address])
                if self.peer.tx_address is not None
                else b""
            )
            data = self.peer.tx_id.to_bytes(4, "big") + address + data
            flags = (self.flags & 0x100) | (0x80 if address else 0)
        elif isinstance(self, ByteSession):
            assert isinstance(self.route, ProtocolRoute)
            if self.route.protocol == 0x800A:
                raise ValueError(
                    "Original UART echo channel does not support periodics"
                )
            self._validate_data(data, flags)
        elif isinstance(self, KLineSession):
            if not isinstance(data, bytes) or not 1 <= len(data) <= 12:
                raise ValueError("K-line periodic requires 1..12 bytes")
            if flags not in (0, 0x200):
                raise ValueError("Unsupported periodic TxFlags")
        else:
            if not isinstance(data, bytes) or not 4 <= len(data) <= 12:
                raise ValueError("CAN periodic requires ID4 and up to eight bytes")
            can_data(int.from_bytes(data[:4], "big"), data[4:], bool(flags & 0x100))
            if flags not in (0, 0x100):
                raise ValueError("Unsupported CAN periodic TxFlags")
        if not 5 <= interval_ms <= 65535:
            raise ValueError("Periodic interval must be 5..65535 milliseconds")
        with self.client.io_lock, self._lock:
            self._check()
            if len(self._periodics) >= 10:
                raise BufferError("Only ten firmware periodics permitted")
            self._periodic_attempt = True
            reply = self._command(
                self.periodic_target,
                0x0D,
                struct.pack("<IIIB", 4, interval_ms, flags, len(data)) + data,
            )
            if len(reply) < 24:
                raise ValueError("Periodic reply lacks hardware ID")
            hardware_id = struct.unpack_from("<I", reply, 20)[0]
            if hardware_id in self._periodics:
                raise ProtocolError("Device reused an active periodic ID")
            self._periodics.add(hardware_id)
            return hardware_id

    def stop_periodic(self, hardware_id: int) -> None:
        with self.client.io_lock, self._lock:
            self._check()
            if hardware_id not in self._periodics:
                raise ValueError("Periodic ID is not owned by this session")
            self._command(
                self.periodic_target, 0x0E, struct.pack("<II", 4, hardware_id)
            )
            self._periodics.remove(hardware_id)

    def clear_periodics(self) -> None:
        with self.client.io_lock, self._lock:
            self._check()
            self._command(self.periodic_target, 0x10, struct.pack("<I", 4))
            self._periodics.clear()

    def clear_tx(self) -> None:
        with self.client.io_lock, self._lock:
            self._check()
            self._command(self.route.target, 0x11, struct.pack("<I", 2))
            self._pending.clear()

    def clear_rx(self) -> None:
        with self.client.io_lock, self._lock:
            self._check()
            self._command(self.route.target, 0x11, struct.pack("<I", 3))
            self._events = deque(
                event
                for event in self._events
                if not isinstance(event, (CANFrame, DataFrame))
            )
            self.client.events = deque(
                packet
                for packet in self.client.events
                if len(packet) < 6
                or struct.unpack_from("<3H", packet) != (0, self.route.target, 9)
            )

    def close(self) -> None:
        self._stop.set()
        if self._worker is not None and self._worker.ident is not None:
            self._worker.join(1)
            if self._worker.is_alive():
                raise TimeoutError(
                    "RX worker did not stop; transport must be closed by owner"
                )
        self._ready = False
        steps: list[tuple[int, int, bytes]] = []
        for mode in sorted(self._extra_filter_modes):
            steps.append((self.route.target, 0x10, struct.pack("<I", mode)))
        if self._functional_attempt:
            steps.append((self.route.target, 0x10, struct.pack("<I", 3)))
        if self._repeat_attempt:
            steps.append((self.route.target, 0x10, struct.pack("<I", 5)))
        if self._periodic_attempt:
            steps.append((self.periodic_target, 0x10, struct.pack("<I", 4)))
        if (
            self._filter is not None
            and self.filter_mode not in self._extra_filter_modes
        ):
            steps.append(
                (
                    self.route.target,
                    0x0E,
                    struct.pack("<II", self.filter_mode, self._filter),
                )
            )
        elif self._filter_attempt and self.filter_mode not in self._extra_filter_modes:
            steps.append((self.route.target, 0x10, struct.pack("<I", self.filter_mode)))
        if self._pins:
            steps.append(
                (
                    self.route.target,
                    0x12,
                    struct.pack("<III", 0, self.route.pin1, self.route.pin2),
                )
            )
        if self._connected:
            steps.append((self.route.target, 7, b""))
        if self._device:
            steps.append((1, 5, b""))
        errors = []
        for target, opcode, body in steps:
            try:
                self._command(target, opcode, body, cleanup=True)
            except Exception as error:  # noqa: BLE001 - attempt every remaining cleanup step.
                errors.append(error)
        self._device = self._connected = self._pins = self._filter_attempt = False
        self._filter = None
        self._pending.clear()
        self._extra_filters.clear()
        self._extra_filter_modes.clear()
        self._periodics.clear()
        self._repeats.clear()
        self._repeat_attempt = False
        self._periodic_attempt = False
        self._finished = True
        self._cleanup_failed = self._cleanup_failed or bool(errors)
        if not self._cleanup_failed:
            with self.client.io_lock:
                if self.client.channel_owner is self:
                    self.client.channel_owner = None
        if errors:
            raise ExceptionGroup("CAN channel cleanup failed", errors)


class ISOTPExchange:
    """Bounded host ISO-TP over explicitly injected raw CAN channels.

    This adapter requires a correlated raw0x106 loopback for every submitted
    frame. It does not reinterpret that notification as ECU delivery or firmware
    ISO completion. No channel is opened by construction or exchange.
    """

    def __init__(
        self,
        channels: dict[str, tuple[CANSession, Peer]],
        *,
        timeout: float = 5.0,
        frame_timeout: float = 1.0,
        cancelled: Callable[[], bool] | None = None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        event_limit: int = 4096,
    ):
        if not channels or len(channels) > 64:
            raise ValueError("ISO exchange requires 1..64 configured ECUs")
        if not math.isfinite(timeout) or not 0 < timeout <= 60:
            raise ValueError("ISO exchange timeout must be finite and in (0, 60]")
        if not math.isfinite(frame_timeout) or not 0.001 <= frame_timeout <= 10:
            raise ValueError("ISO frame timeout must be finite and in [0.001, 10]")
        if not 1 <= event_limit <= 65536:
            raise ValueError("Invalid ISO event budget")
        for ecu, (channel, peer) in channels.items():
            validate_ecu(ecu)
            if (
                channel.receive_id != peer.rx_id
                or bool(channel.flags & 0x100) != peer.extended_id
            ):
                raise ValueError("ISO peer does not match raw channel filter/ID format")
            if channel.route.target >> 8 not in (5, 21):
                raise ValueError("Host ISO exchange requires a raw CAN channel")
        self.channels = dict(channels)
        self.timeout, self.frame_timeout = timeout, frame_timeout
        self.cancelled = cancelled or (lambda: False)
        self.clock, self.sleep, self.event_limit = clock, sleep, event_limit
        self._exchange_lock = threading.Lock()

    def exchange(self, ecu: str, request: bytes) -> bytes:
        """Return one reassembled PDU only after all emitted frames have loopback.

        The application layer validates services/replies. On any exchange failure
        the selected channel is closed; its transport still belongs to the owner.
        """
        validate_ecu(ecu)
        if ecu not in self.channels:
            raise ValueError("ECU has no explicitly configured raw CAN peer")
        if not isinstance(request, bytes) or not 1 <= len(request) <= 4095:
            raise ValueError("ISO request must contain 1..4095 bytes")
        if not self._exchange_lock.acquire(blocking=False):
            raise RuntimeError("ISO exchange is already active")
        channel, peer = self.channels[ecu]
        sender = Sender(peer, timeout=self.frame_timeout)
        receiver = Receiver(peer, timeout=self.frame_timeout)
        try:
            return self._run(channel, peer, sender, receiver, request)
        except Exception as original:
            try:
                channel.close()
            except Exception as cleanup:  # noqa: BLE001 - preserve exchange failure.
                original.add_note(f"ISO channel cleanup also failed: {cleanup}")
            raise
        finally:
            sender.reset()
            receiver.reset()
            self._exchange_lock.release()

    def _run(
        self,
        channel: CANSession,
        peer: Peer,
        sender: Sender,
        receiver: Receiver,
        request: bytes,
    ) -> bytes:
        started = self.clock()
        if not math.isfinite(started):
            raise ValueError("ISO clock must be finite and monotonic")
        previous = started
        deadline = started + self.timeout
        outgoing = deque([sender.start(request, started)])
        pending: Submission | None = None
        response_pdu: bytes | None = None
        observed = 0
        submitted_request = False
        last_cf_loopback: float | None = None
        pending_is_cf = False
        while True:
            now = self.clock()
            if not math.isfinite(now) or now < previous:
                raise ValueError("ISO clock must be finite and monotonic")
            previous = now
            if self.cancelled():
                raise InterruptedError("ISO exchange cancelled")
            if now >= deadline:
                raise TimeoutError("ISO exchange response timeout")
            if pending is not None and now >= pending.deadline:
                raise TimeoutError("ISO raw frame loopback timeout")
            sender.tick(now)
            receiver.tick(now)
            for event in channel.events():
                observed += 1
                if observed > self.event_limit:
                    raise BufferError("ISO exchange event budget exhausted")
                if isinstance(event, TxTimeout):
                    if pending is not None and event.submission == pending:
                        raise TimeoutError("ISO raw frame loopback timeout")
                elif isinstance(event, TxEvent):
                    if pending is not None and pending.correlates(event):
                        if event.status != 0x106:
                            raise ProtocolError(
                                f"Unproven ISO TX event status {event.status:#x}"
                            )
                        if pending_is_cf:
                            # USB ACK can precede the actual device send; space
                            # the next CF from its observed loopback instead.
                            last_cf_loopback = self.clock()
                        pending = None
                        pending_is_cf = False
                elif isinstance(event, CANFrame):
                    # Raw status bits beyond the ID-format bit have unproven ISO
                    # semantics; never pass a loopback/error indication as ECU RX.
                    if event.status & ~0x100:
                        raise ProtocolError("Unsupported raw CAN receive status")
                    raw = peer.input(
                        event.can_id, event.data, bool(event.status & 0x100)
                    )
                    if raw is None:
                        continue
                    if not submitted_request:
                        raise ProtocolError(
                            "Stale ECU event preceded request submission"
                        )
                    if raw[0] >> 4 == 3:
                        sender.flow(
                            event.can_id, event.data, now, extended_id=peer.extended_id
                        )
                    else:
                        if sender.state != "idle":
                            raise ProtocolError(
                                "ECU response preceded complete request submission"
                            )
                        pdu, flow = receiver.feed(
                            event.can_id, event.data, now, extended_id=peer.extended_id
                        )
                        if flow is not None:
                            if outgoing:
                                raise BufferError(
                                    "ISO flow-control queue is already occupied"
                                )
                            outgoing.append(flow)
                        if pdu is not None:
                            if response_pdu is not None:
                                raise ProtocolError("Multiple ECU response PDUs")
                            response_pdu = pdu
                else:
                    raise ProtocolError(
                        "Unclassified raw channel event during ISO exchange"
                    )
            if pending is None:
                if response_pdu is not None and not outgoing and sender.state == "idle":
                    return response_pdu
                if outgoing:
                    frame = outgoing.popleft()
                elif (
                    last_cf_loopback is None or now >= last_cf_loopback + sender.spacing
                ):
                    frame = sender.poll(now)
                else:
                    frame = None
                if frame is not None:
                    milliseconds = max(
                        1,
                        min(10000, int(min(self.frame_timeout, deadline - now) * 1000)),
                    )
                    pending = channel.submit_frame(
                        peer.tx_id, frame, timeout_ms=milliseconds
                    )
                    submitted_request = True
                    pending_is_cf = frame[int(peer.tx_address is not None)] >> 4 == 2
            self.sleep(min(0.001, max(0, deadline - now)))


@dataclass(frozen=True)
class ProtocolRoute(CANRoute):
    protocol: int


def protocol_routes(board_reply: bytes, protocol: int) -> tuple[ProtocolRoute, ...]:
    """Advertised ISO/K-line routes, default pins first; caller selects explicitly."""
    can_routes(board_reply)
    protocol = {0x8001: 2, 0x8002: 3, 0x8003: 4, 0x8004: 5, 0x8005: 6}.get(
        protocol, protocol
    )
    if protocol == 5:
        return tuple(
            ProtocolRoute(r.slot, r.board_type, r.target, r.resource, r.pin1, r.pin2, 5)
            for r in can_routes(board_reply)
        )
    if protocol not in (2, 3, 4, 6, 0x800A):
        raise ValueError("Protocol absent from original JLR requirement table")
    result = []
    for index in range(8):
        board_type = board_reply[20 + index * 20]
        slot = 1 << index
        rows: list[tuple[int, int, int, int]] = []
        if protocol == 2 and board_type in (3, 5, 9):
            rows.append((2, 3, 2, 10))
        elif protocol == 0x800A and board_type in (1, 3, 5, 8, 9, 10, 11):
            rows.append((13, 4 if board_type == 8 else 2, 7, 0))
        elif protocol == 6 and 1 <= board_type <= 11:
            rows.append((6, 1, 6, 14))
            if board_type in (5, 7, 8, 11):
                resource = {5: 4, 7: 5, 8: 3, 11: 3}[board_type]
                rows.append((22, resource, 3, 11))
                if board_type in (8, 11):
                    rows.append((22, resource, 12, 13))
        elif protocol in (3, 4) and board_type in (1, 3, 5, 6, 7, 8, 9, 10, 11):
            resource = 4 if board_type in (7, 8) else 2
            rows.extend(((protocol, resource, 7, 15), (protocol, resource, 7, 0)))
            for pin in {5: (3, 8), 7: (11,), 8: (3, 6, 8, 9, 12, 13)}.get(
                board_type, ()
            ):
                rows.append((protocol, resource, pin, 0))
            if board_type in (1, 3, 5, 6, 9):
                resource = {5: 5, 6: 3}.get(board_type, 4)
                rows.append((protocol + 22, resource, 15, 0))
        result.extend(
            ProtocolRoute(
                slot, board_type, address << 8 | slot, resource, pin1, pin2, protocol
            )
            for address, resource, pin1, pin2 in rows
        )
    return tuple(result)


@dataclass(frozen=True)
class DataFrame:
    status: int
    timestamp: int
    data: bytes
    extra_data: bytes = b""


def decode_data_event(payload: bytes, target: int) -> DataFrame:
    """Generic channel9 body, before protocol-specific host postprocessing."""
    if len(payload) < 24 or struct.unpack_from("<3H", payload) != (0, target, 9):
        raise ValueError("Not a complete data RX event for this channel")
    status, timestamp, wire_size, size = struct.unpack_from("<IIHH", payload, 12)
    actual = len(payload) - 24
    if size > 0x1020 or actual < size or actual > 0x1020:
        raise ValueError("Invalid data RX size")
    if wire_size not in (0, actual) or (wire_size == 0 and actual != size):
        raise ValueError("Data RX wire/data byte counts disagree")
    return DataFrame(status, timestamp, payload[24 : 24 + size], payload[24 + size :])


def repeat_body(
    data: bytes,
    mask: bytes,
    pattern: bytes,
    interval_ms: int,
    *,
    matches: int = 1,
    flags: int = 0,
) -> bytes:
    """Literal DLL repeat offsets, including its surprising overlapping copies.

    Original stack gaps are zeroed. This is wire reconstruction, not a claim
    that unequal TX/filter lengths form a useful physical repeat operation.
    """
    if any(
        not isinstance(value, bytes) or not 1 <= len(value) <= 12
        for value in (data, mask, pattern)
    ) or len(mask) != len(pattern):
        raise ValueError(
            "Repeat requires TX/mask/pattern 1..12 bytes and equal mask/pattern sizes"
        )
    if (
        not 5 <= interval_ms <= 65535
        or not 1 <= matches <= 255
        or flags not in (0, 0x200)
    ):
        raise ValueError("Invalid repeat interval/count/flags")
    size = len(data) + len(mask) + len(pattern)
    raw = bytearray(max(size, 3 * len(mask)))
    raw[: len(data)] = data
    # Assembly 1000d6fa and 1000d711 uses filter lengths, not TX length.
    raw[len(mask) : 2 * len(mask)] = mask
    raw[len(mask) + len(pattern) : len(mask) + 2 * len(pattern)] = pattern
    return (
        struct.pack("<IIIBBB", 5, interval_ms, flags, len(data), len(mask), matches)
        + raw[:size]
    )


class KLineSession(CANSession):
    """ISO9141/ISO14230 lifecycle, firmware byte transport, explicit initialization.

    Caller owns headers/checksum policy and ECU interpretation. No automatic init
    or periodic request occurs on open. RX carries original status/timestamp.
    """

    @staticmethod
    def routes(board_reply: bytes) -> tuple[ProtocolRoute, ...]:
        return protocol_routes(board_reply, 3) + protocol_routes(board_reply, 4)

    def __init__(
        self,
        client: JLRClient,
        board_reply: bytes,
        route: ProtocolRoute,
        baud: int = 10400,
        *,
        queue_limit: int = 256,
        pending_limit: int = 32,
        connect_flags: int = 0,
    ):
        if connect_flags & ~0x10000200:
            raise ValueError("Unsupported K-line ConnectFlags")
        if route.protocol not in (3, 4):
            raise ValueError("K-line requires ISO9141 or ISO14230 route")
        super().__init__(
            client,
            board_reply,
            route,
            baud,
            0,
            queue_limit=queue_limit,
            pending_limit=pending_limit,
        )
        self.flags = connect_flags | (0x1000 if route.pin2 == 0 else 0)
        self._checksum_mode = 0

    def _configure_open(self) -> None:
        self._command(self.route.target, 0x0B, struct.pack("<II", 0x47, 1))

    def _filter_body(self) -> bytes:
        # One zero mask byte is an explicit pass-all byte filter.
        return struct.pack("<IHBB", 0, 0, 1, 1) + b"\0\0"

    def _decode_rx(self, payload: bytes) -> DataFrame:
        event = decode_data_event(payload, self.route.target)
        if not event.status and not self.flags & 0x200:
            if len(event.extra_data) != 1:
                raise ProtocolError("K-line RX lacks checksum byte")
            checksum = sum(event.data) & (0x7F if self._checksum_mode == 1 else 0xFF)
            if checksum != event.extra_data[0]:
                if self.flags & 0x10000000:
                    return DataFrame(
                        event.status | 0x40000000,
                        event.timestamp,
                        event.data,
                        event.extra_data,
                    )
                raise ProtocolError("K-line RX checksum mismatch")
        return event

    def submit_frame(
        self, can_id: int, data: bytes, *, timeout_ms: int = 1000
    ) -> Submission:
        raise TypeError("Use submit_data for K-line bytes")

    def submit_data(
        self, data: bytes, *, flags: int = 0, timeout_ms: int = 1000
    ) -> Submission:
        if not isinstance(data, bytes) or not 1 <= len(data) <= 0x1020:
            raise ValueError("K-line data must contain 1..4128 bytes")
        if flags not in (0, 0x200) or not 1 <= timeout_ms <= 10000:
            raise ValueError("Unsupported K-line flags or timeout")
        return self._submit(data, flags, timeout_ms)

    def _config_parameter(self, parameter: int) -> int:
        mapping = {
            1: 4,
            7: 7,
            9: 0x47,
            10: 8,
            12: 9,
            14: 11,
            15: 12,
            16: 13,
            17: 0x50,
            19: 16,
            20: 17,
            21: 18,
            22: 19,
            32: 31,
            33: 32,
            0x10008: 0x31,
            0x10000008: 0x51,
        }
        assert isinstance(self.route, ProtocolRoute)
        mapping[0x19 if self.route.protocol == 3 else 0x12] = (
            10 if self.route.protocol == 3 else 15
        )
        if parameter not in mapping:
            raise ValueError("Unsupported K-line J2534 configuration parameter")
        return mapping[parameter]

    def get_config(self, parameter: int) -> int:
        return self.get_value(self._config_parameter(parameter))

    def set_config(self, parameter: int, value: int) -> None:
        if not 0 <= value <= 0xFFFFFFFF:
            raise ValueError("Invalid configuration value")
        if parameter == 0x20 and value not in (0, 1):
            raise ValueError("Checksum mode requires 0 or 1")
        self.set_value(self._config_parameter(parameter), value)
        if parameter == 0x20:
            self._checksum_mode = value

    def five_baud_init(self, address: int = 0x33) -> bytes:
        """Return two keyword bytes; short/sync/error replies fail explicitly."""
        if not 0 <= address <= 255:
            raise ValueError("Invalid 5-baud address")
        with self.client.io_lock, self._lock:
            self._check()
            reply = self._command(
                self.route.target,
                0x11,
                struct.pack("<IB", 0, address),
                timeout=10,
                accepted_statuses=(0, 0x208, 0x209),
            )
            if len(reply) < 24:
                raise ValueError("5-baud reply lacks byte count")
            count = struct.unpack_from("<I", reply, 20)[0]
            if count > 128 or len(reply) != 24 + count:
                raise ValueError("Invalid 5-baud byte count")
            if struct.unpack_from("<I", reply, 12)[0] or count < 4:
                raise ProtocolError("5-baud initialization failed before both keywords")
            if reply[25] != 0x55:
                raise ProtocolError("Invalid 5-baud sync byte")
            return reply[26:28]

    def fast_init(
        self, message: bytes, *, expect_reply: bool = True
    ) -> DataFrame | None:
        if not isinstance(message, bytes) or not 1 <= len(message) <= 4128:
            raise ValueError("Fast init requires 1..4128 bytes")
        body = (
            struct.pack("<IIIIHH", 1, int(expect_reply), 0, 8000, len(message), 0)
            + message
        )
        with self.client.io_lock, self._lock:
            self._check()
            reply = self._command(self.route.target, 0x11, body, timeout=10)
            if not expect_reply:
                return None
            if len(reply) < 32:
                raise ValueError("Fast init reply lacks message body")
            packet = struct.pack("<6H", 0, self.route.target, 9, 0, 0, 0) + reply[20:]
            event = self._decode_rx(packet)
            if event.status:
                raise ProtocolError("Fast init response has receive error")
            return event

    def start_repeat(
        self,
        data: bytes,
        mask: bytes,
        pattern: bytes,
        interval_ms: int,
        *,
        matches: int = 1,
        flags: int = 0,
    ) -> int:
        body = repeat_body(
            data, mask, pattern, interval_ms, matches=matches, flags=flags
        )
        with self.client.io_lock, self._lock:
            self._check()
            if len(self._repeats) >= 10:
                raise BufferError("Host repeat-message bound exhausted")
            self._repeat_attempt = True
            reply = self._command(self.route.target, 0x0D, body)
            if len(reply) < 24:
                raise ValueError("Repeat reply lacks hardware ID")
            hardware_id = struct.unpack_from("<I", reply, 20)[0]
            if hardware_id in self._repeats:
                raise ProtocolError("Device reused an active repeat ID")
            self._repeats.add(hardware_id)
            return hardware_id

    def query_repeat(self, hardware_id: int) -> bool:
        with self.client.io_lock, self._lock:
            self._check()
            if hardware_id not in self._repeats:
                raise ValueError("Repeat ID is not owned by this session")
            # The original leaves the middle DWORD uninitialized. Emit zero.
            reply = self._command(
                self.route.target, 0x11, struct.pack("<III", 5, 0, hardware_id)
            )
            if len(reply) < 21:
                raise ValueError("Repeat query lacks active byte")
            return bool(reply[20])

    def stop_repeat(self, hardware_id: int) -> None:
        with self.client.io_lock, self._lock:
            self._check()
            if hardware_id not in self._repeats:
                raise ValueError("Repeat ID is not owned by this session")
            self._command(self.route.target, 0x0E, struct.pack("<II", 5, hardware_id))
            self._repeats.remove(hardware_id)

    def clear_repeats(self) -> None:
        with self.client.io_lock, self._lock:
            self._check()
            self._command(self.route.target, 0x10, struct.pack("<I", 5))
            self._repeats.clear()


class FirmwareISOSession(CANSession):
    """Firmware segments TX/FC; host reconstructs RX9 segments without emitting FC."""

    filter_mode = 2

    @staticmethod
    def routes(board_reply: bytes) -> tuple[ProtocolRoute, ...]:
        return protocol_routes(board_reply, 6)

    def __init__(
        self,
        client: JLRClient,
        board_reply: bytes,
        route: ProtocolRoute,
        baud: int,
        peer: Peer,
        *,
        queue_limit: int = 256,
    ):
        if route.protocol != 6:
            raise ValueError("Firmware ISO requires protocol 6")
        self.peer = peer
        super().__init__(
            client,
            board_reply,
            route,
            baud,
            peer.rx_id,
            extended=peer.extended_id,
            queue_limit=queue_limit,
        )

    def _filter_body(self) -> bytes:
        peer = self.peer
        flags = self.flags | (0x80 if peer.rx_address is not None else 0)
        pattern = peer.rx_id.to_bytes(4, "big")
        flow = peer.tx_id.to_bytes(4, "big")
        if peer.rx_address is not None:
            assert peer.tx_address is not None
            pattern += bytes([peer.rx_address])
            flow += bytes([peer.tx_address])
        # Literal DLL copy: only mask.Data[0] goes to firmware, not all ID bytes.
        return (
            struct.pack("<II", 2, flags)
            + b"\xff"
            + pattern.ljust(5, b"\0")
            + flow.ljust(5, b"\0")
        )

    def submit_frame(
        self, can_id: int, data: bytes, *, timeout_ms: int = 1000
    ) -> Submission:
        raise TypeError("Use submit_pdu; firmware ISO must not receive host FC frames")

    def submit_pdu(self, data: bytes, *, timeout_ms: int = 1000) -> Submission:
        if not isinstance(data, bytes) or not 1 <= len(data) <= 4095:
            raise ValueError("ISO PDU must contain 1..4095 bytes")
        if not 1 <= timeout_ms <= 10000:
            raise ValueError("Write timeout must be 1..10000 ms")
        raw = self.peer.tx_id.to_bytes(4, "big")
        if self.peer.tx_address is not None:
            raw += bytes([self.peer.tx_address])
        flags = self.flags | (0x80 if self.peer.tx_address is not None else 0)
        result = self._submit(raw + data, flags, timeout_ms)
        # Native whole-PDU completion semantics differ from raw CAN loopback.
        # Keep TX events neutral; application reply is the exchange success gate.
        with self._lock:
            self._pending.pop(result.sequence, None)
        return result


class FirmwareISOExchange:
    """One whole-PDU Write8 followed by firmware-managed segment receive."""

    def __init__(
        self,
        channels: dict[str, FirmwareISOSession],
        *,
        timeout: float = 5,
        cancelled: Callable[[], bool] | None = None,
    ):
        if (
            not channels
            or len(channels) > 64
            or not math.isfinite(timeout)
            or not 0 < timeout <= 60
        ):
            raise ValueError("Invalid firmware ISO channels/timeout")
        for ecu in channels:
            validate_ecu(ecu)
        self.channels, self.timeout = dict(channels), timeout
        self.cancelled = cancelled or (lambda: False)
        self._exchange_lock = threading.Lock()

    def exchange(self, ecu: str, request: bytes) -> bytes:
        validate_ecu(ecu)
        if ecu not in self.channels:
            raise ValueError("ECU has no explicitly configured firmware ISO channel")
        if not self._exchange_lock.acquire(blocking=False):
            raise RuntimeError("Firmware ISO exchange already active")
        channel = self.channels[ecu]
        receiver = Receiver(channel.peer, timeout=self.timeout)
        try:
            if self.cancelled():
                raise InterruptedError("Firmware ISO exchange cancelled")
            if channel.events():
                raise ProtocolError("Stale firmware ISO events preceded request")
            deadline = time.monotonic() + self.timeout
            channel.submit_pdu(
                request, timeout_ms=min(10000, max(1, int(self.timeout * 1000)))
            )
            observed = 0
            response = None
            while time.monotonic() < deadline:
                if self.cancelled():
                    raise InterruptedError("Firmware ISO exchange cancelled")
                for event in channel.events():
                    observed += 1
                    if observed > 4096:
                        raise BufferError("Firmware ISO event budget exhausted")
                    if isinstance(event, CANFrame):
                        allowed = 0x100 | (
                            0x80 if channel.peer.rx_address is not None else 0
                        )
                        if event.status & ~allowed:
                            raise ProtocolError(
                                "Firmware ISO RX status indicates error"
                            )
                        pdu, _firmware_owned_fc = receiver.feed(
                            event.can_id,
                            event.data,
                            time.monotonic(),
                            extended_id=bool(event.status & 0x100),
                        )
                        if pdu is not None:
                            if response is not None:
                                raise ProtocolError("Multiple firmware ISO responses")
                            response = pdu
                    elif isinstance(event, TxEvent):
                        if event.status not in (0x106, 0x10A, 0x10C, 0x10E, 0x10F):
                            raise ProtocolError(
                                f"Firmware ISO TX/error status {event.status:#x}"
                            )
                    else:
                        raise ProtocolError("Unclassified firmware ISO event")
                if response is not None:
                    return response
                receiver.tick(time.monotonic())
                time.sleep(0.001)
            raise TimeoutError("Firmware ISO response timeout")
        except Exception as original:
            try:
                channel.close()
            except Exception as cleanup:  # noqa: BLE001 - preserve original failure.
                original.add_note(f"Firmware ISO cleanup also failed: {cleanup}")
            raise
        finally:
            receiver.reset()
            self._exchange_lock.release()


class KLineExchange:
    """Bounded byte exchange with explicitly injected ECU framing/correlation.

    encode/decode own vehicle headers and checksum policy; decode returns None
    for an unrelated complete message. Raw status is never silently discarded.
    """

    def __init__(
        self,
        channels: dict[
            str,
            tuple[
                KLineSession | ByteSession,
                Callable[[bytes], bytes],
                Callable[[bytes], bytes | None],
            ],
        ],
        *,
        timeout: float = 5,
        cancelled: Callable[[], bool] | None = None,
    ):
        if (
            not channels
            or len(channels) > 64
            or not math.isfinite(timeout)
            or not 0 < timeout <= 60
        ):
            raise ValueError("Invalid K-line channel map/timeout")
        for ecu in channels:
            validate_ecu(ecu)
        self.channels, self.timeout = dict(channels), timeout
        self.cancelled = cancelled or (lambda: False)
        self._exchange_lock = threading.Lock()

    def exchange(self, ecu: str, request: bytes) -> bytes:
        validate_ecu(ecu)
        if ecu not in self.channels:
            raise ValueError("ECU has no explicitly configured K-line channel")
        if not isinstance(request, bytes) or not 1 <= len(request) <= 4128:
            raise ValueError("K-line request must contain 1..4128 bytes")
        if not self._exchange_lock.acquire(blocking=False):
            raise RuntimeError("K-line exchange already active")
        channel, encode, decode = self.channels[ecu]
        try:
            if self.cancelled():
                raise InterruptedError("K-line exchange cancelled")
            if channel.events():
                raise ProtocolError("Stale K-line events preceded request")
            data = encode(request)
            submission = channel.submit_data(
                data, timeout_ms=max(1, min(10000, int(self.timeout * 1000)))
            )
            deadline = time.monotonic() + self.timeout
            observed = 0
            while time.monotonic() < deadline:
                if self.cancelled():
                    raise InterruptedError("K-line exchange cancelled")
                response = None
                for event in channel.events():
                    observed += 1
                    if observed > 4096:
                        raise BufferError("K-line event budget exhausted")
                    if isinstance(event, DataFrame):
                        if event.status:
                            raise ProtocolError(f"K-line RX status {event.status:#x}")
                        value = decode(event.data)
                        if value is not None:
                            if not isinstance(value, bytes) or not value:
                                raise ProtocolError(
                                    "K-line decoder returned invalid PDU"
                                )
                            if response is not None:
                                raise ProtocolError("Multiple K-line response PDUs")
                            response = value
                    elif isinstance(event, TxEvent):
                        if event.status not in (0x106, 0x10A):
                            raise ProtocolError(
                                f"K-line TX/error status {event.status:#x}"
                            )
                    elif isinstance(event, TxTimeout):
                        raise TimeoutError("K-line submission timeout")
                    else:
                        raise ProtocolError("Unclassified K-line event")
                if response is not None:
                    with channel._lock:
                        channel._pending.pop(submission.sequence, None)
                    return response
                time.sleep(0.001)
            raise TimeoutError("K-line response timeout")
        except Exception as original:
            try:
                channel.close()
            except Exception as cleanup:  # noqa: BLE001 - preserve exchange failure.
                original.add_note(f"K-line cleanup also failed: {cleanup}")
            raise
        finally:
            self._exchange_lock.release()


def kwp_message(
    target: int, source: int, pdu: bytes, *, functional: bool = False
) -> bytes:
    """Build ISO14230 addressed data; firmware owns the TX checksum byte."""
    if not 0 <= target <= 255 or not 0 <= source <= 255:
        raise ValueError("KWP addresses must be bytes")
    if not isinstance(pdu, bytes) or not 1 <= len(pdu) <= 255:
        raise ValueError("KWP PDU must contain 1..255 bytes")
    format_byte = (0xC0 if functional else 0x80) | (len(pdu) if len(pdu) < 64 else 0)
    header = bytes([format_byte, target, source])
    return header + (bytes([len(pdu)]) if len(pdu) >= 64 else b"") + pdu


def kwp_payload(message: bytes, *, target: int, source: int) -> bytes | None:
    """Validate addressed ISO14230 data after KLineSession checked/stripped CS."""
    if not isinstance(message, bytes) or len(message) < 4:
        raise ProtocolError("Truncated addressed KWP message")
    if message[0] >> 6 not in (2, 3):
        raise ProtocolError("KWP decoder requires explicit addressed header")
    size = message[0] & 0x3F
    offset = 3
    if size == 0:
        size = message[3]
        offset = 4
    if size == 0 or len(message) != offset + size:
        raise ProtocolError("KWP data length disagrees with header")
    if not 0 <= target <= 255 or not 0 <= source <= 255:
        raise ValueError("KWP addresses must be bytes")
    if message[1:3] != bytes([target, source]):
        return None
    return message[offset:]


class ByteSession(CANSession):
    """Remaining original JLR PWM/UART-echo byte channels, without CAN coercion."""

    @staticmethod
    def routes(board_reply: bytes) -> tuple[ProtocolRoute, ...]:
        return protocol_routes(board_reply, 2) + protocol_routes(board_reply, 0x800A)

    def __init__(
        self,
        client: JLRClient,
        board_reply: bytes,
        route: ProtocolRoute,
        baud: int,
        *,
        connect_flags: int = 0,
        queue_limit: int = 256,
    ):
        if route.protocol not in (2, 0x800A):
            raise ValueError("Byte channel requires advertised PWM or UART echo route")
        if not 5 <= baud <= 500000 or connect_flags & ~0x10000000:
            raise ValueError("Invalid byte-channel baud/ConnectFlags")
        super().__init__(client, board_reply, route, baud, 0, queue_limit=queue_limit)
        self.flags = connect_flags
        self.node_address = 0xF0

    def _filter_body(self) -> bytes:
        return struct.pack("<IHBB", 0, 0, 1, 1) + b"\0\0"

    def _decode_rx(self, payload: bytes) -> DataFrame:
        return decode_data_event(payload, self.route.target)

    def submit_frame(
        self, can_id: int, data: bytes, *, timeout_ms: int = 1000
    ) -> Submission:
        raise TypeError("Use submit_data for native byte channels")

    def submit_data(
        self, data: bytes, *, flags: int = 0, timeout_ms: int = 1000
    ) -> Submission:
        self._validate_data(data, flags)
        if not 1 <= timeout_ms <= 10000:
            raise ValueError("Invalid byte-channel timeout")
        return self._submit(data, flags, timeout_ms)

    def _validate_data(self, data: bytes, flags: int) -> None:
        assert isinstance(self.route, ProtocolRoute)
        lower, upper = (3, 10) if self.route.protocol == 2 else (4, 256)
        if not isinstance(data, bytes) or not lower <= len(data) <= upper:
            raise ValueError(
                f"Native byte-channel data must contain {lower}..{upper} bytes"
            )
        if flags != 0:
            raise ValueError("Invalid byte-channel TxFlags")
        if self.route.protocol == 2 and data[2] != self.node_address:
            raise ValueError(
                "PWM message source byte differs from configured node address"
            )

    def set_node_address(self, value: int) -> None:
        assert isinstance(self.route, ProtocolRoute)
        if self.route.protocol != 2 or not 0 <= value <= 255:
            raise ValueError("PWM node address must be a byte")
        self.set_value(5, value)
        self.node_address = value

    def update_functional_lookup(
        self, addresses: bytes, *, remove: bool = False
    ) -> None:
        assert isinstance(self.route, ProtocolRoute)
        if self.route.protocol != 2:
            raise ValueError("Functional lookup table requires PWM")
        if not isinstance(addresses, bytes) or not 1 <= len(addresses) <= 256:
            raise ValueError("Functional lookup addresses must contain 1..256 bytes")
        with self.client.io_lock, self._lock:
            self._check()
            self._functional_attempt = True
            for address in addresses:
                self._command(
                    self.route.target,
                    0x0E if remove else 0x0D,
                    struct.pack("<II", 3, address),
                )

    def clear_functional_lookup(self) -> None:
        assert isinstance(self.route, ProtocolRoute)
        if self.route.protocol != 2:
            raise ValueError("Functional lookup table requires PWM")
        with self.client.io_lock, self._lock:
            self._check()
            self._command(self.route.target, 0x10, struct.pack("<I", 3))


@dataclass(frozen=True)
class WireCommand:
    target: int
    opcode: int
    body: bytes


def voltage_routes(board_reply: bytes, *, ground: bool = False) -> tuple[CANRoute, ...]:
    """Reported output capabilities only; enumeration never enables any output."""
    can_routes(board_reply)
    pins = (
        {
            1: (1, 9, 15),
            3: (15,),
            5: (12, 15),
            6: (15,),
            7: (15,),
            8: (15,),
            9: (15,),
            10: (1, 9, 15),
            11: (15,),
        }
        if ground
        else {1: (12,), 3: (13,), 4: (6, 9, 12, 14), 5: (13,), 9: (13,), 10: (12,)}
    )
    resources = (
        {1: 5, 3: 5, 5: 6, 6: 4, 7: 6, 8: 5, 9: 5, 10: 5, 11: 4}
        if ground
        else {1: 6, 3: 6, 4: 4, 5: 7, 9: 6, 10: 6}
    )
    result = []
    for index in range(8):
        kind = board_reply[20 + index * 20]
        slot = 1 << index
        for pin in pins.get(kind, ()):
            result.append(
                CANRoute(
                    slot,
                    kind,
                    ((0x81 if ground else 0x80) << 8) | slot,
                    resources[kind],
                    pin,
                    0,
                )
            )
    return tuple(result)


def voltage_commands(
    board_reply: bytes, route: CANRoute, millivolts: int | None, *, ground: bool = False
) -> tuple[WireCommand, ...]:
    """Pure command plan for simulator/review. No command is sent by this function.

    None disables this already-owned route. Caller must model device/pin/resource
    ownership before executing the plan; a board report alone cannot prove it.
    """
    if route not in voltage_routes(board_reply, ground=ground):
        raise ValueError("Output route is not advertised by supplied board reply")
    if ground:
        if millivolts not in (None, 0):
            raise ValueError("Ground route accepts zero or disabled only")
        return (
            WireCommand(
                route.target,
                0x12,
                struct.pack("<III", int(millivolts is not None), route.pin1, 0),
            ),
        )
    if millivolts is not None and not 5000 <= millivolts <= 20000:
        raise ValueError("Programming voltage must be 5000..20000 mV")
    pin = WireCommand(
        route.target,
        0x12,
        struct.pack("<III", int(millivolts is not None), route.pin1, 0),
    )
    level = WireCommand(1, 0x0B, struct.pack("<II", 1, millivolts or 0))
    return (pin, level) if millivolts is None else (level, pin)
