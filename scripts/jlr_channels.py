"""Evidence-backed, injected-transport raw CAN lifecycle. PHYSICAL_UNCONFIRMED.

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
    """Default CAN only; reject unknown boards rather than guessing pin overrides."""
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
    transport and must close it even if this session's close raises. No firmware
    ISO channel, host ISO sender, or physical completion promise is exposed.
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
        if route not in can_routes(board_reply):
            raise ValueError("Route is not advertised by supplied Board109 reply")
        if not 1 <= baud <= 0xFFFFFFFF:
            raise ValueError("Invalid CAN baud")
        if not 1 <= queue_limit <= 1024 or not 1 <= pending_limit <= 255:
            raise ValueError("Invalid queue bounds")
        can_data(receive_id, b"", extended)
        self.client, self.route, self.baud = client, route, baud
        self.receive_id, self.flags = receive_id, 0x100 if extended else 0
        self.queue_limit, self.pending_limit = queue_limit, pending_limit
        self._events: deque[CANFrame | TxEvent | TxTimeout | bytes] = deque()
        self._pending: dict[int, Submission] = {}
        self._used_sequences: set[int] = set()
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._worker: threading.Thread | None = None
        self._error: Exception | None = None
        self._device = self._connected = self._pins = self._filter_attempt = False
        self._filter: int | None = None
        self._ready = False
        self._finished = False
        self._cleanup_failed = False

    def _command(self, target: int, opcode: int, body: bytes = b"", **kwargs) -> bytes:
        return self.client.transact(target, opcode, body, timeout=0.5, **kwargs)

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
            self._command(self.route.target, 0x12, struct.pack("<III", 1, 6, 14))
            body = struct.pack("<IHBB", 0, self.flags, 1, 4)
            body += b"\xff" * 4 + self.receive_id.to_bytes(4, "big")
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

    def _enqueue(self, event: CANFrame | TxEvent | TxTimeout | bytes) -> None:
        if len(self._events) >= self.queue_limit:
            raise BufferError("CAN event queue is full; session stopped")
        self._events.append(event)

    def _pump(self) -> None:
        try:
            while not self._stop.is_set():
                packets = self.client.poll_events(25)
                with self._lock:
                    for payload in packets:
                        if len(payload) < 6:
                            raise ValueError("Truncated channel event")
                        destination, source, opcode = struct.unpack_from("<3H", payload)
                        if (destination, source, opcode) == (0, self.route.target, 9):
                            self._enqueue(decode_can_event(payload, self.route.target))
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
            body = struct.pack("<IIHH", self.flags, timeout_ms, len(raw), 0) + raw
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

    def events(self) -> tuple[CANFrame | TxEvent | TxTimeout | bytes, ...]:
        """Drain retained notifications; errors remain observable after draining."""
        with self._lock:
            result = tuple(self._events)
            self._events.clear()
            if not result and self._error is not None:
                raise RuntimeError(
                    "CAN receive worker failed; close session"
                ) from self._error
            return result

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
        if self._filter is not None:
            steps.append((self.route.target, 0x0E, struct.pack("<II", 0, self._filter)))
        elif self._filter_attempt:
            steps.append((self.route.target, 0x10, struct.pack("<I", 0)))
        if self._pins:
            steps.append((self.route.target, 0x12, struct.pack("<III", 0, 6, 14)))
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
            if channel.route.target >> 8 != 5:
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
