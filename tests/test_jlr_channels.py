import struct
import threading
import time
import unittest
from builtins import ExceptionGroup
from collections import deque
from itertools import pairwise
from unittest.mock import patch

from scripts.diagnostics import Session as DiagnosticSession
from scripts.isotp import Peer, ProtocolError, Receiver, Sender
from scripts.jlr import JLRClient, request
from scripts.jlr_channels import (
    CANFrame,
    CANRoute,
    CANSession,
    ISOTPExchange,
    Submission,
    TxEvent,
    TxTimeout,
    can_data,
    can_routes,
    decode_can_event,
    decode_tx_event,
)
from scripts.mongoose_protocol import decode_frames, encode_frame


def board_reply(board_type=1, slot=0):
    result = bytearray(struct.pack("<6HII", 0, 1, 0x8109, 1, 0, 0, 0, 0) + bytes(160))
    result[20 + slot * 20] = board_type
    return bytes(result)


def rx(target=0x0501, status=0, data=b"\x07\xe8", can_id=0x7E8):
    raw = can_id.to_bytes(4, "big") + data
    return struct.pack("<6HIIHH", 0, target, 9, 0, 0, 0, status, 123, 0, len(raw)) + raw


def tx(sequence, count=1, status=0x106, target=0x0501):
    return struct.pack("<6HII", 0, target, 0x0A, sequence, count, 0, status, 321)


class FakeTransport:
    def __init__(self, fail_at=None, fail_cleanup=False, ack=0):
        self.sent = []
        self.chunks = deque()
        self.lock = threading.Lock()
        self.fail_at = fail_at
        self.fail_cleanup = fail_cleanup
        self.ack = ack
        self.inject_tx = False

    def write(self, frame):
        payload = decode_frames(frame)[0]
        with self.lock:
            self.sent.append(payload)
            target, _, opcode, sequence = struct.unpack_from("<4H", payload)
            if len(self.sent) == self.fail_at:
                raise TimeoutError("synthetic lost reply")
            status = self.ack if opcode == 8 else 0
            if self.fail_cleanup and opcode in (0x0E, 7, 5):
                status = 0x205
            reply = struct.pack(
                "<6HII", 0, target, opcode | 0x8000, sequence, 0, 0, status, 0
            )
            if opcode == 0x0D:
                reply += struct.pack("<I", 0)  # Hardware filter zero is valid.
            chunk = encode_frame(reply)
            if opcode == 8 and self.inject_tx:
                chunk += encode_frame(tx(sequence))
            self.chunks.append(chunk)

    def read(self, timeout_ms):
        with self.lock:
            return self.chunks.popleft() if self.chunks else b""

    def inject(self, payload):
        with self.lock:
            self.chunks.append(encode_frame(payload))


def wait_events(session, wanted, seconds=1):
    events = []
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        events.extend(session.events())
        if wanted(events):
            return events
        time.sleep(0.002)
    raise AssertionError(f"Events did not arrive: {events}")


class ChannelTests(unittest.TestCase):
    def session(self, transport=None, **kwargs):
        transport = transport or FakeTransport()
        boards = board_reply()
        client = JLRClient(transport)
        session = CANSession(
            client, boards, can_routes(boards)[0], 500000, 0x7E8, **kwargs
        )
        self.addCleanup(session.close)
        return session, transport

    def test_capabilities_are_strict_and_slot_mask_derived(self):
        for slot in range(8):
            for board_type in range(1, 12):
                route = can_routes(board_reply(board_type, slot))[0]
                self.assertEqual(
                    route, CANRoute(1 << slot, board_type, 0x0500 | 1 << slot, 1, 6, 14)
                )
        self.assertEqual(can_routes(board_reply(255)), ())
        for bad in (b"", bytes(180), board_reply()[:-1], board_reply() + b"x"):
            with self.assertRaises(ValueError):
                can_routes(bad)
        boards = board_reply()
        with self.assertRaises(ValueError):
            CANSession(
                JLRClient(FakeTransport()),
                boards,
                CANRoute(1, 1, 5, 1, 6, 14),
                500000,
                0x7E8,
            )

    def test_lifecycle_wire_and_idempotent_cleanup(self):
        session, transport = self.session()
        self.assertEqual(transport.sent, [])
        session.open()
        self.assertEqual(
            [struct.unpack_from("<H", p, 4)[0] for p in transport.sent],
            [3, 6, 0x12, 0x0D],
        )
        self.assertEqual(transport.sent[1][12:], struct.pack("<II", 0, 500000))
        self.assertEqual(
            transport.sent[3][12:],
            struct.pack("<IHBB", 0, 0, 1, 4) + b"\xff" * 4 + b"\x00\x00\x07\xe8",
        )
        session.close()
        self.assertEqual(
            [struct.unpack_from("<H", p, 4)[0] for p in transport.sent[4:]],
            [0x0E, 0x12, 7, 5],
        )
        self.assertEqual(transport.sent[4][12:], bytes(8))
        session.close()
        self.assertEqual(len(transport.sent), 8)
        with self.assertRaises(RuntimeError):
            session.open()

    def test_cleanup_after_each_ambiguous_open_failure(self):
        expected = {1: [5], 2: [7, 5], 3: [0x12, 7, 5], 4: [0x10, 0x12, 7, 5]}
        for failure in range(1, 5):
            transport = FakeTransport(fail_at=failure)
            session, _ = self.session(transport)
            with self.assertRaises(TimeoutError):
                session.open()
            self.assertEqual(
                [struct.unpack_from("<H", p, 4)[0] for p in transport.sent[failure:]],
                expected[failure],
            )

    def test_worker_start_failure_still_closes_protocol_channel(self):
        session, transport = self.session()
        with (
            patch(
                "scripts.jlr_channels.threading.Thread.start",
                side_effect=RuntimeError("synthetic thread limit"),
            ),
            self.assertRaisesRegex(RuntimeError, "synthetic thread limit"),
        ):
            session.open()
        self.assertEqual(
            [struct.unpack_from("<H", p, 4)[0] for p in transport.sent[-4:]],
            [0x0E, 0x12, 7, 5],
        )
        self.assertIsNone(session.client.channel_owner)

    def test_cleanup_ignores_cancel_and_attempts_remaining_steps(self):
        session, transport = self.session()
        session.open()
        session.client.cancel = threading.Event()
        session.client.cancel.set()
        transport.fail_cleanup = True
        with self.assertRaises(ExceptionGroup) as raised:
            session.close()
        self.assertEqual(len(raised.exception.exceptions), 3)
        self.assertEqual(
            [struct.unpack_from("<H", p, 4)[0] for p in transport.sent[-4:]],
            [0x0E, 0x12, 7, 5],
        )
        self.assertIs(session.client.channel_owner, session)
        session.close()
        self.assertIs(session.client.channel_owner, session)

    def test_background_rx_and_tx_with_interleaved_ack(self):
        session, transport = self.session()
        transport.inject_tx = True
        session.open()
        transport.inject(rx())
        submission = session.submit_frame(0x7E0, b"\x02\x01\x0c")
        events = wait_events(
            session, lambda events: any(isinstance(e, TxEvent) for e in events)
        )
        self.assertTrue(any(isinstance(e, CANFrame) for e in events))
        event = next(e for e in events if isinstance(e, TxEvent))
        self.assertTrue(submission.correlates(event))
        self.assertFalse(session._pending)
        write = next(
            p for p in transport.sent if struct.unpack_from("<H", p, 4)[0] == 8
        )
        self.assertEqual(struct.unpack_from("<H", write, 8)[0], 1)
        self.assertEqual(
            write[12:],
            struct.pack("<IIHH", 0, 1000, 7, 0) + b"\x00\x00\x07\xe0\x02\x01\x0c",
        )

    def test_pending_ack_and_wrong_count_are_not_completion(self):
        session, transport = self.session(FakeTransport(ack=0x101), pending_limit=1)
        session.open()
        submission = session.submit_frame(0x7E0, b"", timeout_ms=20)
        self.assertEqual(submission.ack_status, 0x101)
        transport.inject(tx(submission.sequence, count=2))
        events = wait_events(
            session, lambda events: any(isinstance(e, TxTimeout) for e in events)
        )
        self.assertTrue(any(isinstance(e, TxEvent) for e in events))
        self.assertTrue(
            any(isinstance(e, TxTimeout) and e.submission == submission for e in events)
        )
        session.client.sequence = submission.sequence - 1
        with self.assertRaises(BufferError):
            session.submit_frame(0x7E0, b"")

    def test_queue_bounds_and_worker_failure_are_visible(self):
        session, transport = self.session(queue_limit=1)
        session.open()
        transport.inject(rx())
        transport.inject(rx())
        deadline = time.monotonic() + 1
        while session._error is None and time.monotonic() < deadline:
            time.sleep(0.002)
        self.assertIsInstance(session._error, BufferError)
        self.assertEqual(len(session.events()), 1)
        with self.assertRaises(RuntimeError):
            session.events()
        with self.assertRaises(RuntimeError):
            session.submit_frame(0x7E0, b"")

    def test_pending_limit_and_device_exclusivity(self):
        session, _ = self.session(pending_limit=1)
        session.open()
        session.submit_frame(0x7E0, b"")
        with self.assertRaises(BufferError):
            session.submit_frame(0x7E0, b"")
        other = CANSession(
            session.client, board_reply(), can_routes(board_reply())[0], 500000, 0x7E8
        )
        with self.assertRaises(RuntimeError):
            other.open()

    def test_cancel_stops_receiver_and_cleanup_still_runs(self):
        session, transport = self.session()
        session.client.cancel = threading.Event()
        session.open()
        session.client.cancel.set()
        deadline = time.monotonic() + 1
        while session._error is None and time.monotonic() < deadline:
            time.sleep(0.002)
        self.assertIsInstance(session._error, InterruptedError)
        session.close()
        self.assertEqual(struct.unpack_from("<H", transport.sent[-1], 4)[0], 5)

    def test_write_failure_stops_further_submissions(self):
        session, transport = self.session(FakeTransport(ack=0x205))
        session.open()
        with self.assertRaises(OSError):
            session.submit_frame(0x7E0, b"")
        sent = len(transport.sent)
        with self.assertRaises(RuntimeError):
            session.submit_frame(0x7E0, b"")
        self.assertEqual(len(transport.sent), sent)
        session.close()
        self.assertEqual(struct.unpack_from("<H", transport.sent[-1], 4)[0], 5)

    def test_malformed_background_event_is_not_silently_dropped(self):
        session, transport = self.session()
        session.open()
        transport.inject(rx()[:-1])
        deadline = time.monotonic() + 1
        while session._error is None and time.monotonic() < deadline:
            time.sleep(0.002)
        with self.assertRaises(RuntimeError) as raised:
            session.events()
        self.assertIsInstance(raised.exception.__cause__, ValueError)

    def test_event_validation_and_unknown_tx_suffix(self):
        self.assertEqual(
            decode_can_event(rx(), 0x0501), CANFrame(0, 123, 0x7E8, b"\x07\xe8")
        )
        for payload in (
            rx()[:-1],
            rx() + b"x",
            rx(target=5),
            rx(can_id=0x800),
            bytes(28),
        ):
            with self.assertRaises(ValueError):
                decode_can_event(payload, 0x0501)
        self.assertEqual(decode_tx_event(tx(12) + b"opaque", 0x0501).tail, b"opaque")
        for payload in (tx(1)[:19], tx(1, target=5)):
            with self.assertRaises(ValueError):
                decode_tx_event(payload, 0x0501)
        for can_id, data in ((-1, b""), (0x800, b""), (1, bytes(9))):
            with self.assertRaises(ValueError):
                can_data(can_id, data)
        self.assertEqual(len(can_data(0x1FFFFFFF, bytes(8), True)), 12)
        submission = Submission(0x0501, 1, 1, 0, 1)
        self.assertFalse(submission.correlates(decode_tx_event(tx(1, count=2), 0x0501)))

    def test_client_bounds_count_and_cancellation_before_io(self):
        self.assertEqual(
            struct.unpack_from(
                "<H", decode_frames(request(0x501, 8, 1, count=1))[0], 8
            )[0],
            1,
        )
        transport = FakeTransport()
        client = JLRClient(transport, threading.Event())
        for timeout in (-1, float("nan"), float("inf"), 11):
            with self.assertRaises(ValueError):
                client.transact(1, 3, timeout=timeout)
        with self.assertRaises(TimeoutError):
            client.transact(1, 3, timeout=0)
        assert client.cancel is not None
        client.cancel.set()
        with self.assertRaises(InterruptedError):
            client.transact(1, 3)
        self.assertEqual(transport.sent, [])
        client.transact(1, 5, cleanup=True)


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


class FakeISOChannel(CANSession):
    """Two real host state machines connected by authored in-memory CAN frames."""

    def __init__(self, peer, response, clock, *, loopback=True, tx_status=0x106):
        super().__init__(
            JLRClient(FakeTransport()),
            board_reply(),
            can_routes(board_reply())[0],
            500000,
            peer.rx_id,
            extended=peer.extended_id,
        )
        self.peer, self.response, self.clock = peer, response, clock
        remote = Peer(
            peer.rx_id, peer.tx_id, peer.extended_id, peer.rx_address, peer.tx_address
        )
        self.remote_receiver = Receiver(remote, blocksize=2, stmin=5)
        self.remote_sender = Sender(remote)
        self.loopback, self.tx_status = loopback, tx_status
        self.sent_frames = []
        self.received_requests = []
        self.iso_events = deque()
        self.closed = False
        self.write_failure = False
        self.write_delay = 0.0
        self.withhold_response = False
        self.fail_flow = False
        self.suppress_flow_loopback = False
        self.sequence = 0

    def submit_frame(self, can_id, data, *, timeout_ms=1000):
        is_flow = data[int(self.peer.tx_address is not None)] >> 4 == 3
        if self.write_failure or (self.fail_flow and is_flow):
            raise OSError("synthetic raw submit failure")
        self.clock.sleep(self.write_delay)
        self.sent_frames.append((self.clock(), can_id, data))
        self.sequence += 1
        submission = Submission(
            self.route.target, self.sequence, 1, 0, self.clock() + timeout_ms / 1000
        )
        if self.loopback and not (is_flow and self.suppress_flow_loopback):
            self.iso_events.append(
                TxEvent(self.route.target, self.sequence, 1, self.tx_status, 0, b"")
            )
        raw = self.remote_receiver.peer.input(can_id, data, self.peer.extended_id)
        assert raw is not None
        if raw[0] >> 4 == 3:
            self.remote_sender.flow(
                can_id, data, self.clock(), extended_id=self.peer.extended_id
            )
        else:
            request_pdu, flow = self.remote_receiver.feed(
                can_id, data, self.clock(), extended_id=self.peer.extended_id
            )
            if flow is not None:
                self.iso_events.append(self.frame(flow))
            if request_pdu is not None:
                self.received_requests.append(request_pdu)
                if not self.withhold_response:
                    self.iso_events.append(
                        self.frame(
                            self.remote_sender.start(self.response, self.clock())
                        )
                    )
        return submission

    def frame(self, data):
        return CANFrame(0x100 if self.peer.extended_id else 0, 0, self.peer.rx_id, data)

    def events(self):
        if self.remote_sender.state == "send":
            frame = self.remote_sender.poll(self.clock())
            if frame is not None:
                self.iso_events.append(self.frame(frame))
        result = tuple(self.iso_events)
        self.iso_events.clear()
        return result

    def close(self):
        self.closed = True


class WallClock:
    def __call__(self):
        return time.monotonic()

    def sleep(self, seconds):
        time.sleep(seconds)


class ISOUSBTransport(FakeTransport):
    """Synthetic ECU frames transported through real SLP/USB-client code."""

    def __init__(self, peer, response):
        super().__init__()
        self.ecu = FakeISOChannel(peer, response, WallClock())
        self.sequences = {}

    def write(self, frame):
        super().write(frame)
        payload = decode_frames(frame)[0]
        if struct.unpack_from("<H", payload, 4)[0] == 8:
            size = struct.unpack_from("<H", payload, 20)[0]
            raw = payload[24 : 24 + size]
            submission = self.ecu.submit_frame(int.from_bytes(raw[:4], "big"), raw[4:])
            self.sequences[submission.sequence] = struct.unpack_from("<H", payload, 6)[
                0
            ]

    def read(self, timeout_ms):
        chunk = super().read(timeout_ms)
        if chunk:
            return chunk
        chunks = []
        for event in self.ecu.events():
            if isinstance(event, TxEvent):
                payload = tx(self.sequences[event.sequence], status=event.status)
            else:
                assert isinstance(event, CANFrame)
                payload = rx(status=event.status, data=event.data, can_id=event.can_id)
            chunks.append(encode_frame(payload))
        return b"".join(chunks)


class ISOExchangeTests(unittest.TestCase):
    def setup_exchange(
        self,
        *,
        peer=None,
        response=b"\x41\x0c\x12\x34",
        loopback=True,
        tx_status=0x106,
        timeout=0.1,
        frame_timeout=0.03,
        event_limit=4096,
    ):
        clock = FakeClock()
        peer = peer or Peer(0x7E0, 0x7E8)
        channel = FakeISOChannel(
            peer, response, clock, loopback=loopback, tx_status=tx_status
        )
        exchange = ISOTPExchange(
            {"engine": (channel, peer)},
            timeout=timeout,
            frame_timeout=frame_timeout,
            clock=clock,
            sleep=clock.sleep,
            event_limit=event_limit,
        )
        return exchange, channel, clock

    def test_diagnostic_session_through_real_raw_session_and_slp_codec(self):
        peer = Peer(0x7E0, 0x7E8)
        vin = b"JTDBR32E720123456"
        transport = ISOUSBTransport(peer, b"\x49\x02\x01" + vin)
        boards = board_reply()
        channel = CANSession(
            JLRClient(transport), boards, can_routes(boards)[0], 500000, peer.rx_id
        )
        exchange = ISOTPExchange({"engine": (channel, peer)}, timeout=1)
        try:
            channel.open()
            self.assertEqual(
                DiagnosticSession(exchange.exchange).read("engine", b"\x09\x02"),
                b"\x01" + vin,
            )
            self.assertTrue(any(p[4:6] == b"\x08\x00" for p in transport.sent))
        finally:
            channel.close()
        self.assertEqual(struct.unpack_from("<H", transport.sent[-1], 4)[0], 5)

    def test_diagnostic_session_through_actual_iso_pump(self):
        exchange, channel, _ = self.setup_exchange()
        self.assertEqual(
            DiagnosticSession(exchange.exchange).read("engine", b"\x01\x0c"),
            b"\x12\x34",
        )
        self.assertEqual(channel.received_requests, [b"\x01\x0c"])
        self.assertEqual(channel.sent_frames[0][2], b"\x02\x01\x0c")
        self.assertFalse(channel.closed)

    def test_multiframe_both_directions_with_addressing_and_stmin(self):
        for extended in (False, True):
            for addressing in (False, True):
                with self.subTest(extended=extended, addressing=addressing):
                    peer = Peer(
                        0x18DA10F1 if extended else 0x7E0,
                        0x18DAF110 if extended else 0x7E8,
                        extended,
                        0x10 if addressing else None,
                        0xF1 if addressing else None,
                    )
                    expected = bytes(range(50))
                    exchange, channel, _ = self.setup_exchange(
                        peer=peer, response=expected, timeout=2
                    )
                    request_pdu = bytes(range(40))
                    self.assertEqual(exchange.exchange("engine", request_pdu), expected)
                    self.assertEqual(channel.received_requests, [request_pdu])
                    pci_offset = int(addressing)
                    consecutive = [
                        t
                        for t, _, data in channel.sent_frames
                        if data[pci_offset] >> 4 == 2
                    ]
                    self.assertGreater(len(consecutive), 2)
                    self.assertTrue(
                        all(b - a >= 0.005 - 1e-9 for a, b in pairwise(consecutive))
                    )
                    self.assertTrue(
                        any(
                            data[pci_offset] >> 4 == 3
                            for _, _, data in channel.sent_frames
                        )
                    )
                    self.assertFalse(channel.closed)

    def test_stmin_is_anchored_after_blocking_raw_submission(self):
        exchange, channel, _ = self.setup_exchange(timeout=2)
        channel.write_delay = 0.01
        self.assertEqual(
            exchange.exchange("engine", bytes(range(40))), b"\x41\x0c\x12\x34"
        )
        consecutive = [t for t, _, data in channel.sent_frames if data[0] >> 4 == 2]
        self.assertGreater(len(consecutive), 2)
        self.assertTrue(all(b - a >= 0.005 - 1e-9 for a, b in pairwise(consecutive)))

    def test_stmin_waits_after_deferred_device_send_loopback(self):
        class DeferredWireChannel(FakeISOChannel):
            def __init__(self, *args):
                super().__init__(*args)
                self.deferred = None
                self.delayed_cf = False

            def submit_frame(self, can_id, data, *, timeout_ms=1000):
                assert self.deferred is None
                delay = 0.0
                if data[0] >> 4 == 2 and not self.delayed_cf:
                    delay, self.delayed_cf = 0.01, True
                self.deferred = (self.clock() + delay, can_id, data, timeout_ms)
                # USB ACK precedes both the physical send and its loopback.
                return Submission(
                    self.route.target,
                    self.sequence + 1,
                    1,
                    0,
                    self.clock() + timeout_ms / 1000,
                )

            def events(self):
                if self.deferred is not None and self.clock() >= self.deferred[0]:
                    _, can_id, data, timeout_ms = self.deferred
                    self.deferred = None
                    super().submit_frame(can_id, data, timeout_ms=timeout_ms)
                return super().events()

        clock = FakeClock()
        peer = Peer(0x7E0, 0x7E8)
        channel = DeferredWireChannel(peer, b"\x41\x0c\x12\x34", clock)
        exchange = ISOTPExchange(
            {"engine": (channel, peer)}, timeout=2, clock=clock, sleep=clock.sleep
        )
        self.assertEqual(
            exchange.exchange("engine", bytes(range(40))), b"\x41\x0c\x12\x34"
        )
        consecutive = [t for t, _, data in channel.sent_frames if data[0] >> 4 == 2]
        self.assertGreater(len(consecutive), 2)
        self.assertTrue(
            all(b - a >= 0.005 - 1e-9 for a, b in pairwise(consecutive)), consecutive
        )

    def test_ecu_response_without_tx_loopback_is_never_success(self):
        exchange, channel, _ = self.setup_exchange(loopback=False)
        with self.assertRaisesRegex(TimeoutError, "loopback"):
            exchange.exchange("engine", b"\x01\x0c")
        self.assertEqual(channel.received_requests, [b"\x01\x0c"])
        self.assertTrue(channel.closed)

    def test_response_flow_control_also_requires_loopback_and_handles_submit_failure(
        self,
    ):
        exchange, channel, _ = self.setup_exchange(response=bytes(range(50)))
        channel.suppress_flow_loopback = True
        with self.assertRaisesRegex(TimeoutError, "loopback"):
            exchange.exchange("engine", b"\x01\x0c")
        self.assertTrue(channel.closed)
        exchange, channel, _ = self.setup_exchange(response=bytes(range(50)))
        channel.fail_flow = True
        with self.assertRaises(OSError):
            exchange.exchange("engine", b"\x01\x0c")
        self.assertTrue(channel.closed)

    def test_malformed_consecutive_frame_and_nonmonotonic_clock_abort(self):
        exchange, channel, _ = self.setup_exchange()
        actual_events = channel.events

        def malformed_events():
            return tuple(
                CANFrame(e.status, e.timestamp, e.can_id, b"\x21\x01")
                if isinstance(e, CANFrame)
                else e
                for e in actual_events()
            )

        with (
            patch.object(channel, "events", side_effect=malformed_events),
            self.assertRaises(ProtocolError),
        ):
            exchange.exchange("engine", b"\x01\x0c")
        self.assertTrue(channel.closed)
        exchange, channel, _ = self.setup_exchange()
        times = iter([1.0, 0.5])
        exchange.clock = lambda: next(times)
        with self.assertRaisesRegex(ValueError, "monotonic"):
            exchange.exchange("engine", b"\x01\x0c")
        self.assertTrue(channel.closed)
        self.assertEqual(channel.sent_frames, [])

    def test_unknown_matching_tx_status_aborts_instead_of_guessing(self):
        exchange, channel, _ = self.setup_exchange(tx_status=0x10A)
        with self.assertRaisesRegex(ProtocolError, "Unproven"):
            exchange.exchange("engine", b"\x01\x0c")
        self.assertTrue(channel.closed)

    def test_idle_deadline_and_cancel_cleanup(self):
        exchange, channel, clock = self.setup_exchange()
        channel.withhold_response = True
        with self.assertRaisesRegex(TimeoutError, "response"):
            exchange.exchange("engine", b"\x01\x0c")
        self.assertTrue(channel.closed)
        self.assertGreaterEqual(clock(), 0.1)
        exchange, channel, _ = self.setup_exchange()
        exchange.cancelled = lambda: True
        with self.assertRaises(InterruptedError):
            exchange.exchange("engine", b"\x01\x0c")
        self.assertEqual(channel.sent_frames, [])
        self.assertTrue(channel.closed)

    def test_submit_failure_and_stale_or_malformed_rx_close_channel(self):
        exchange, channel, _ = self.setup_exchange()
        channel.write_failure = True
        with self.assertRaises(OSError):
            exchange.exchange("engine", b"\x01\x0c")
        self.assertTrue(channel.closed)
        for stale in (channel.frame(b"\x04\x41\x0c\x12\x34"), b"unknown"):
            exchange, channel, _ = self.setup_exchange()
            channel.iso_events.append(stale)
            with self.assertRaises(ProtocolError):
                exchange.exchange("engine", b"\x01\x0c")
            self.assertTrue(channel.closed)
            self.assertEqual(channel.sent_frames, [])

    def test_event_budget_and_invalid_configuration(self):
        exchange, channel, _ = self.setup_exchange(event_limit=1)
        with self.assertRaises(BufferError):
            exchange.exchange("engine", b"\x01\x0c")
        self.assertTrue(channel.closed)
        exchange, channel, _ = self.setup_exchange()
        with self.assertRaises(ValueError):
            ISOTPExchange({"engine": (channel, Peer(0x7E0, 0x7E9))})
        with self.assertRaises(ValueError):
            ISOTPExchange({"engine": (channel, Peer(0x7E0, 0x7E8, True))})
        channel.route = CANRoute(1, 1, 0x0601, 1, 6, 14)
        with self.assertRaises(ValueError):
            ISOTPExchange({"engine": (channel, channel.peer)})
        self.assertEqual(channel.sent_frames, [])

    def test_wrong_ecu_invalid_request_and_concurrent_exchange_do_no_io(self):
        exchange, channel, _ = self.setup_exchange()
        for ecu, invalid_request in (
            ("other", b"\x01\x0c"),
            ("engine", b""),
            ("engine", bytes(4096)),
        ):
            with self.assertRaises(ValueError):
                exchange.exchange(ecu, invalid_request)
        exchange._exchange_lock.acquire()
        try:
            with self.assertRaises(RuntimeError):
                exchange.exchange("engine", b"\x01\x0c")
        finally:
            exchange._exchange_lock.release()
        self.assertEqual(channel.sent_frames, [])
        self.assertFalse(channel.closed)


if __name__ == "__main__":
    unittest.main()


class ProtocolTransport(FakeTransport):
    """Original-format replies and unsolicited RX, entirely synthetic USB."""

    def __init__(
        self, *, iso_response=None, bad_init=False, disconnected=False, **kwargs
    ):
        super().__init__(**kwargs)
        self.iso_response = iso_response
        self.bad_init = bad_init
        self.disconnected = disconnected

    def write(self, frame):
        payload = decode_frames(frame)[0]
        target, _, opcode, _sequence = struct.unpack_from("<4H", payload)
        super().write(frame)
        with self.lock:
            if opcode == 0x0C:
                base = decode_frames(self.chunks.pop())[0]
                self.chunks.append(
                    encode_frame(base + bytes(4) + struct.pack("<I", 12345))
                )
            elif opcode == 0x11:
                base = decode_frames(self.chunks.pop())[0]
                mode = struct.unpack_from("<I", payload, 12)[0]
                if mode == 0:
                    data = b"\x33\x55\x08\x08"
                    base += struct.pack("<I", 1 if self.bad_init else len(data)) + data
                elif mode == 1:
                    data = b"\x83\xf1\x10\xc1\xe9\x8f"
                    base += (
                        struct.pack("<IIHH", 0, 88, len(data) + 1, len(data))
                        + data
                        + bytes([sum(data) & 0xFF])
                    )
                self.chunks.append(encode_frame(base))
            elif opcode == 8 and self.iso_response is not None:
                peer = Peer(tx_id=0x7E8, rx_id=0x7E0)
                sender = Sender(peer)
                packets = [sender.start(self.iso_response, time.monotonic())]
                if sender.state != "idle":
                    sender.flow(0x7E0, b"\x30\0\0", time.monotonic())
                    while sender.state != "idle":
                        packet = sender.poll(time.monotonic())
                        if packet is not None:
                            packets.append(packet)
                for packet in packets:
                    self.chunks.append(encode_frame(rx(target=target, data=packet)))

    def read(self, timeout_ms):
        if self.disconnected:
            raise OSError("Synthetic USB hot unplug")
        return super().read(timeout_ms)


class NativeProtocolTests(unittest.TestCase):
    def kline(self, protocol=3, transport=None):
        from scripts.jlr_channels import KLineSession, protocol_routes

        transport = transport or ProtocolTransport()
        boards = board_reply()
        session = KLineSession(
            JLRClient(transport), boards, protocol_routes(boards, protocol)[0]
        )
        return session, transport

    def iso(self, data=b"\x62\xf1\x90VIN"):
        from scripts.jlr_channels import (
            FirmwareISOExchange,
            FirmwareISOSession,
            protocol_routes,
        )

        boards = board_reply()
        transport = ProtocolTransport(iso_response=data)
        session = FirmwareISOSession(
            JLRClient(transport),
            boards,
            protocol_routes(boards, 6)[0],
            500000,
            Peer(tx_id=0x7E0, rx_id=0x7E8),
        )
        return session, transport, FirmwareISOExchange({"engine": session})

    def test_routes_are_board_and_slot_derived(self):
        from scripts.jlr_channels import protocol_routes

        for protocol in (3, 4, 6):
            route = protocol_routes(board_reply(1, 7), protocol)[0]
            self.assertEqual(route.target, protocol << 8 | 128)
        self.assertFalse(protocol_routes(board_reply(2), 3))
        self.assertEqual(protocol_routes(board_reply(8), 4)[0].resource, 4)
        with self.assertRaises(ValueError):
            protocol_routes(bytes(180), 6)

    def test_kline_lifecycle_values_init_and_bytes(self):
        from scripts.jlr_channels import DataFrame

        session, transport = self.kline()
        session.open()
        try:
            self.assertEqual(session.five_baud_init(), b"\x08\x08")
            session.set_value(4, 10400)
            self.assertEqual(session.get_value(4), 12345)
            submission = session.submit_data(b"\x68\x6a\xf1\x01\x00")
            self.assertEqual(submission.target, 0x301)
            data = b"\x48\x6b\x10\x41\x00"
            packet = (
                struct.pack(
                    "<6HIIHH", 0, 0x301, 9, 0, 0, 0, 0, 9, len(data) + 1, len(data)
                )
                + data
                + bytes([sum(data) & 0xFF])
            )
            transport.inject(packet)
            events = wait_events(
                session, lambda e: any(isinstance(x, DataFrame) for x in e)
            )
            self.assertIn(DataFrame(0, 9, data, bytes([sum(data) & 0xFF])), events)
        finally:
            session.close()
        pin = [p for p in transport.sent if struct.unpack_from("<H", p, 4)[0] == 0x12]
        self.assertEqual(pin[0][12:], struct.pack("<III", 1, 7, 15))
        self.assertEqual(pin[-1][12:], struct.pack("<III", 0, 7, 15))

    def test_fast_init_exact_body_and_protocol_rejection(self):
        session, transport = self.kline(4)
        session.open()
        try:
            event = session.fast_init(b"\xc1\x33\xf1\x81")
            self.assertIsNotNone(event)
            packet = next(p for p in transport.sent if p[4:6] == b"\x11\0")
            self.assertEqual(
                packet[12:],
                struct.pack("<IIIIHH", 1, 1, 0, 8000, 4, 0) + b"\xc1\x33\xf1\x81",
            )
        finally:
            session.close()
        session, _ = self.kline(3)
        session.open()
        try:
            self.assertIsNotNone(session.fast_init(b"x"))
        finally:
            session.close()

    def test_malformed_five_baud_reply_rejected(self):
        session, _ = self.kline(transport=ProtocolTransport(bad_init=True))
        session.open()
        try:
            with self.assertRaises(ValueError):
                session.five_baud_init()
        finally:
            session.close()

    def test_periodic_wire_and_ambiguous_cleanup(self):
        session, transport = self.kline()
        session.open()
        try:
            hardware_id = session.start_periodic(b"\x3e", 1000)
            self.assertEqual(hardware_id, 0)
            start = transport.sent[-1]
            self.assertEqual(start[12:], struct.pack("<IIIB", 4, 1000, 0, 1) + b"\x3e")
            with self.assertRaises(ProtocolError):
                session.start_periodic(b"\x3e", 1000)
            session.stop_periodic(0)
            with self.assertRaises(ValueError):
                session.stop_periodic(0)
        finally:
            session.close()
        self.assertIn(
            struct.pack("<I", 4),
            [p[12:] for p in transport.sent if p[4:6] == b"\x10\0"],
        )

    def test_firmware_iso_single_whole_pdu_and_no_double_fc(self):
        for size in (3, 50, 4095):
            with self.subTest(size=size):
                data = bytes(i % 256 for i in range(size))
                session, transport, exchange = self.iso(data)
                session.open()
                try:
                    self.assertEqual(exchange.exchange("engine", b"\x22\xf1\x90"), data)
                finally:
                    session.close()
                writes = [p for p in transport.sent if p[4:6] == b"\x08\0"]
                self.assertEqual(len(writes), 1)
                self.assertEqual(writes[0][24:], b"\0\0\x07\xe0\x22\xf1\x90")
                stop = next(p for p in transport.sent if p[4:6] == b"\x0e\0")
                self.assertEqual(stop[12:], struct.pack("<II", 2, 0))

    def test_firmware_iso_filter_literal_packing_and_long_write(self):
        session, transport, _ = self.iso()
        session.open()
        try:
            packet = next(p for p in transport.sent if p[4:6] == b"\x0d\0")
            self.assertEqual(
                packet[12:],
                struct.pack("<II", 2, 0) + b"\xff" + b"\0\0\x07\xe8\0\0\0\x07\xe0\0",
            )
            data = b"\x22" * 4095
            session.submit_pdu(data)
            self.assertEqual(transport.sent[-1][24:], b"\0\0\x07\xe0" + data)
            with self.assertRaises(TypeError):
                session.submit_frame(0x7E0, b"\x30\0\0")
        finally:
            session.close()

    def test_firmware_cancel_closes_and_releases(self):
        from scripts.jlr_channels import FirmwareISOExchange

        session, transport, _ = self.iso()
        session.open()
        exchange = FirmwareISOExchange({"engine": session}, cancelled=lambda: True)
        with self.assertRaises(InterruptedError):
            exchange.exchange("engine", b"\x22\xf1\x90")
        self.assertIsNone(session.client.channel_owner)
        self.assertFalse(any(p[4:6] == b"\x08\0" for p in transport.sent))

    def test_kline_and_iso_partial_open_failure_cleanup(self):
        for protocol in (3, 4, 6):
            for fail_at in range(1, 5):
                with self.subTest(protocol=protocol, fail_at=fail_at):
                    transport = ProtocolTransport(fail_at=fail_at)
                    if protocol in (3, 4):
                        session, _ = self.kline(protocol, transport)
                    else:
                        from scripts.jlr_channels import (
                            FirmwareISOSession,
                            protocol_routes,
                        )

                        boards = board_reply()
                        session = FirmwareISOSession(
                            JLRClient(transport),
                            boards,
                            protocol_routes(boards, 6)[0],
                            500000,
                            Peer(tx_id=0x7E0, rx_id=0x7E8),
                        )
                    with self.assertRaises(TimeoutError):
                        session.open()
                    self.assertIsNone(session.client.channel_owner)
                    self.assertEqual(transport.sent[-1][4:6], b"\x05\0")

    def test_decode_data_event_rejects_size_and_preserves_status(self):
        from scripts.jlr_channels import decode_data_event

        packet = (
            struct.pack("<6HIIHH", 0, 0x301, 9, 0, 0, 0, 0x40000000, 99, 0, 1) + b"x"
        )
        self.assertEqual(decode_data_event(packet, 0x301).status, 0x40000000)
        with self.assertRaises(ValueError):
            decode_data_event(packet[:-1], 0x301)


class NativeFailureTests(unittest.TestCase):
    kline = NativeProtocolTests.kline
    iso = NativeProtocolTests.iso

    def test_kline_exchange_injected_framing(self):
        from scripts.jlr_channels import KLineExchange

        class ReplyTransport(ProtocolTransport):
            def write(self, frame):
                payload = decode_frames(frame)[0]
                super().write(frame)
                if payload[4:6] == b"\x08\0":
                    response = b"\x48\x6b\x10\x41\x00"
                    self.inject(
                        struct.pack(
                            "<6HIIHH",
                            0,
                            0x301,
                            9,
                            0,
                            0,
                            0,
                            0,
                            99,
                            len(response) + 1,
                            len(response),
                        )
                        + response
                        + bytes([sum(response) & 0xFF])
                    )

        session, transport = self.kline(transport=ReplyTransport())
        exchange = KLineExchange(
            {
                "engine": (
                    session,
                    lambda p: b"\x68\x6a\xf1" + p,
                    lambda p: p[3:] if p[:3] == b"\x48\x6b\x10" else None,
                )
            }
        )
        session.open()
        try:
            self.assertEqual(exchange.exchange("engine", b"\x01\0"), b"\x41\0")
            self.assertEqual(transport.sent[-1][24:], b"\x68\x6a\xf1\x01\0")
        finally:
            session.close()

    def test_firmware_timeout_closes(self):
        from scripts.jlr_channels import FirmwareISOExchange

        session, transport, _ = self.iso()
        transport.iso_response = None
        session.open()
        with self.assertRaises(TimeoutError):
            FirmwareISOExchange({"engine": session}, timeout=0.01).exchange(
                "engine", b"x"
            )
        self.assertIsNone(session.client.channel_owner)

    def test_kline_timeout_and_cancel_close(self):
        from scripts.jlr_channels import KLineExchange

        for cancel in (False, True):
            session, _ = self.kline()
            session.open()
            exchange = KLineExchange(
                {"engine": (session, lambda x: x, lambda x: x)},
                timeout=0.01,
                cancelled=lambda cancel=cancel: cancel,
            )
            with self.assertRaises(InterruptedError if cancel else TimeoutError):
                exchange.exchange("engine", b"x")
            self.assertIsNone(session.client.channel_owner)

    def test_hotplug_error_stops_worker_and_preserves_cleanup_failure(self):
        session, transport = self.kline()
        session.open()
        transport.disconnected = True
        deadline = time.monotonic() + 1
        while session._error is None and time.monotonic() < deadline:
            time.sleep(0.001)
        with self.assertRaises(RuntimeError):
            session.submit_data(b"x")
        with self.assertRaises(RuntimeError):
            session.events()
        with self.assertRaises(ExceptionGroup):
            session.close()
        self.assertIs(session.client.channel_owner, session)

    def test_partial_bulk_reassembly_new_native_paths(self):
        class FragmentTransport(ProtocolTransport):
            def read(self, timeout_ms):
                chunk = super().read(timeout_ms)
                if len(chunk) > 3:
                    with self.lock:
                        self.chunks.appendleft(chunk[3:])
                    return chunk[:3]
                return chunk

        session, _ = self.kline(transport=FragmentTransport())
        session.open()
        try:
            self.assertEqual(session.five_baud_init(), b"\x08\x08")
        finally:
            session.close()


class NativeControlTests(unittest.TestCase):
    kline = NativeProtocolTests.kline
    iso = NativeProtocolTests.iso

    def test_kwp_short_long_and_address_correlation(self):
        from scripts.jlr_channels import kwp_message, kwp_payload

        for length in (1, 63, 64, 255):
            data = b"\x22" * length
            for functional in (False, True):
                message = kwp_message(0x33, 0xF1, data, functional=functional)
                self.assertEqual(kwp_payload(message, target=0x33, source=0xF1), data)
                self.assertIsNone(kwp_payload(message, target=0x10, source=0xF1))
                with self.assertRaises(ProtocolError):
                    kwp_payload(message[:-1], target=0x33, source=0xF1)
        with self.assertRaises(ValueError):
            kwp_message(256, 0, b"x")

    def test_config_translation_and_host_checksum_mode(self):
        session, transport = self.kline()
        session.open()
        try:
            session.set_config(0x19, 12)
            self.assertEqual(transport.sent[-1][12:], struct.pack("<II", 10, 12))
            self.assertEqual(session.get_config(9), 12345)
            self.assertEqual(transport.sent[-1][12:], struct.pack("<I", 0x47))
            session.set_config(0x20, 1)
            packet = (
                struct.pack("<6HIIHH", 0, 0x301, 9, 0, 0, 0, 0, 9, 2, 1) + b"\xf0\x70"
            )
            self.assertEqual(session._decode_rx(packet).data, b"\xf0")
            with self.assertRaises(ProtocolError):
                session._decode_rx(packet[:-1] + b"\xf0")
            with self.assertRaises(ValueError):
                session.set_config(3, 1)
            with self.assertRaises(ValueError):
                session.set_config(0x20, 2)
        finally:
            session.close()

    def test_repeat_literal_offsets_and_bounds(self):
        from scripts.jlr_channels import repeat_body

        body = repeat_body(b"ABC", b"\xff" * 3, b"XYZ", 100, matches=2)
        self.assertEqual(
            body,
            struct.pack("<IIIBBB", 5, 100, 0, 3, 3, 2) + b"ABC" + b"\xff" * 3 + b"XYZ",
        )
        # Unequal TX/filter copies overlap exactly like the observed instructions;
        # only the declared prefix is sent and no original stack bytes are copied.
        self.assertEqual(repeat_body(b"ABCDE", b"x", b"y", 100)[15:], b"AxyDE\0\0")
        self.assertEqual(len(repeat_body(b"A", b"xx", b"yy", 100)), 20)
        with self.assertRaises(ValueError):
            repeat_body(b"A", b"x", b"yy", 100)

    def test_repeat_lifecycle_and_query(self):
        class RepeatTransport(ProtocolTransport):
            def write(self, frame):
                payload = decode_frames(frame)[0]
                super().write(frame)
                if payload[4:6] == b"\x11\0" and payload[12:16] == struct.pack("<I", 5):
                    with self.lock:
                        reply = decode_frames(self.chunks.pop())[0]
                        self.chunks.append(encode_frame(reply + b"\x01"))

        session, transport = self.kline(transport=RepeatTransport())
        session.open()
        try:
            hardware_id = session.start_repeat(b"ABC", b"\xff" * 3, b"XYZ", 100)
            self.assertTrue(session.query_repeat(hardware_id))
            self.assertEqual(
                transport.sent[-1][12:], struct.pack("<III", 5, 0, hardware_id)
            )
            session.stop_repeat(hardware_id)
            with self.assertRaises(ValueError):
                session.query_repeat(hardware_id)
        finally:
            session.close()
        self.assertIn(
            struct.pack("<I", 5),
            [p[12:] for p in transport.sent if p[4:6] == b"\x10\0"],
        )

    def test_block_filter_wire_and_cleanup(self):
        session, transport = self.kline()
        session.open()
        try:
            hardware_id = session.start_message_filter(b"\xff", b"\x10", block=True)
            self.assertEqual(
                transport.sent[-1][12:], struct.pack("<IHBB", 1, 0, 2, 1) + b"\xff\x10"
            )
            session.stop_message_filter(hardware_id, block=True)
            with self.assertRaises(ValueError):
                session.stop_message_filter(hardware_id, block=True)
        finally:
            session.close()

    def test_kline_only_and_alternate_iso_pins(self):
        from scripts.jlr_channels import (
            FirmwareISOSession,
            KLineSession,
            protocol_routes,
        )

        boards = board_reply(8)
        routes = protocol_routes(boards, 4)
        route = next(r for r in routes if (r.pin1, r.pin2) == (13, 0))
        transport = ProtocolTransport()
        session = KLineSession(JLRClient(transport), boards, route)
        session.open()
        try:
            self.assertEqual(session.flags, 0x1000)
            self.assertEqual(transport.sent[1][12:], struct.pack("<II", 0x1000, 10400))
        finally:
            session.close()
        route = next(
            r for r in protocol_routes(boards, 6) if (r.pin1, r.pin2) == (12, 13)
        )
        session = FirmwareISOSession(
            JLRClient(ProtocolTransport()),
            boards,
            route,
            500000,
            Peer(tx_id=0x7E0, rx_id=0x7E8),
        )
        self.assertEqual(session.route.target, 0x1601)


class NativeExtendedTests(unittest.TestCase):
    kline = NativeProtocolTests.kline

    def test_firmware_iso_29bit_extended_addressing(self):
        from scripts.jlr_channels import (
            FirmwareISOExchange,
            FirmwareISOSession,
            protocol_routes,
        )

        tx_id, rx_id = 0x18DA10F1, 0x18DAF110
        peer = Peer(
            tx_id=tx_id, rx_id=rx_id, extended_id=True, tx_address=0x10, rx_address=0xF1
        )

        class ExtendedTransport(ProtocolTransport):
            def write(self, frame):
                payload = decode_frames(frame)[0]
                super().write(frame)
                if payload[4:6] == b"\x08\0":
                    data = rx_id.to_bytes(4, "big") + b"\xf1\x03\x62\xf1\x90"
                    self.inject(
                        struct.pack(
                            "<6HIIHH", 0, 0x601, 9, 0, 0, 0, 0x180, 99, 0, len(data)
                        )
                        + data
                    )

        boards = board_reply()
        transport = ExtendedTransport()
        session = FirmwareISOSession(
            JLRClient(transport), boards, protocol_routes(boards, 6)[0], 500000, peer
        )
        session.open()
        try:
            self.assertEqual(
                FirmwareISOExchange({"engine": session}).exchange(
                    "engine", b"\x22\xf1\x90"
                ),
                b"\x62\xf1\x90",
            )
            write = next(p for p in transport.sent if p[4:6] == b"\x08\0")
            self.assertEqual(struct.unpack_from("<I", write, 12)[0], 0x180)
            self.assertEqual(write[24:], tx_id.to_bytes(4, "big") + b"\x10\x22\xf1\x90")
        finally:
            session.close()

    def test_ambiguous_scheduled_start_clears_correct_group(self):
        for group in (4, 5):
            session, transport = self.kline(transport=ProtocolTransport(fail_at=6))
            session.open()
            try:
                with self.assertRaises(TimeoutError):
                    if group == 4:
                        session.start_periodic(b"\x3e", 100)
                    else:
                        session.start_repeat(b"A", b"\xff", b"B", 100)
            finally:
                session.close()
            self.assertIn(
                struct.pack("<I", group),
                [p[12:] for p in transport.sent if p[4:6] == b"\x10\0"],
            )

    def test_additional_pass_filter_cleanup_does_not_stop_cleared_primary(self):
        class FilterTransport(ProtocolTransport):
            def __init__(self):
                super().__init__()
                self.next_filter_id = 0

            def write(self, frame):
                payload = decode_frames(frame)[0]
                super().write(frame)
                if payload[4:6] == b"\x0d\0":
                    with self.lock:
                        reply = decode_frames(self.chunks.pop())[0]
                        self.chunks.append(
                            encode_frame(
                                reply[:20] + struct.pack("<I", self.next_filter_id)
                            )
                        )
                        self.next_filter_id += 1

        session, transport = self.kline(transport=FilterTransport())
        session.open()
        self.assertEqual(session.start_message_filter(b"\xff", b"\x10"), 1)
        session.close()
        self.assertTrue(
            any(p[4:6] == b"\x10\0" and p[12:] == bytes(4) for p in transport.sent)
        )
        self.assertFalse(any(p[4:6] == b"\x0e\0" for p in transport.sent))


class KLineFlagTests(unittest.TestCase):
    def test_disabled_checksum_and_sniff_mode_preserve_native_data(self):
        from scripts.jlr_channels import KLineSession, protocol_routes

        boards = board_reply()
        route = protocol_routes(boards, 3)[0]
        session = KLineSession(
            JLRClient(ProtocolTransport()), boards, route, connect_flags=0x200
        )
        raw = struct.pack("<6HIIHH", 0, route.target, 9, 0, 0, 0, 0, 9, 1, 1) + b"A"
        self.assertEqual(session._decode_rx(raw).data, b"A")
        sniff = KLineSession(
            JLRClient(ProtocolTransport()), boards, route, connect_flags=0x10000000
        )
        raw = struct.pack("<6HIIHH", 0, route.target, 9, 0, 0, 0, 0, 9, 2, 1) + b"A\0"
        self.assertEqual(sniff._decode_rx(raw).status, 0x40000000)
        with self.assertRaises(ValueError):
            KLineSession(
                JLRClient(ProtocolTransport()), boards, route, connect_flags=0x800
            )

    def test_periodic_native_twelve_byte_bound(self):
        session, _ = NativeProtocolTests().kline()
        with self.assertRaises(ValueError):
            session.start_periodic(b"x" * 13, 100)


class RemainingFamilyTests(unittest.TestCase):
    def byte_session(self, protocol):
        from scripts.jlr_channels import ByteSession, protocol_routes

        boards = board_reply(3)
        transport = ProtocolTransport()
        session = ByteSession(
            JLRClient(transport),
            boards,
            protocol_routes(boards, protocol)[0],
            41600 if protocol == 2 else 10400,
        )
        return session, transport

    def test_pwm_and_uart_echo_native_byte_lifecycle(self):
        from scripts.jlr_channels import DataFrame

        for protocol in (2, 0x800A):
            session, transport = self.byte_session(protocol)
            session.open()
            try:
                data = b"\x61\x6a\xf0\x01" if protocol == 2 else b"\x03\x01\x01\0"
                submission = session.submit_data(data)
                self.assertEqual(submission.target, 0x201 if protocol == 2 else 0xD01)
                self.assertEqual(transport.sent[-1][24:], data)
                payload = (
                    struct.pack(
                        "<6HIIHH",
                        0,
                        session.route.target,
                        9,
                        0,
                        0,
                        0,
                        0,
                        10,
                        len(data),
                        len(data),
                    )
                    + data
                )
                transport.inject(payload)
                events = wait_events(
                    session, lambda e: any(isinstance(v, DataFrame) for v in e)
                )
                self.assertIn(DataFrame(0, 10, data), events)
                if protocol == 2:
                    session.start_periodic(data, 100)
                    session.set_node_address(0xF1)
                    with self.assertRaises(ValueError):
                        session.submit_data(data)
                    session.submit_data(data[:2] + b"\xf1" + data[3:])
                else:
                    with self.assertRaises(ValueError):
                        session.start_periodic(data, 100)
                with self.assertRaises(ValueError):
                    session.submit_data(b"x")
            finally:
                session.close()

    def test_all_supported_protocol_routes_and_aliases(self):
        from scripts.jlr_channels import protocol_routes

        boards = board_reply(3)
        for base, alias in (
            (2, 0x8001),
            (3, 0x8002),
            (4, 0x8003),
            (5, 0x8004),
            (6, 0x8005),
        ):
            self.assertEqual(
                protocol_routes(boards, base), protocol_routes(boards, alias)
            )
        for original_rejected in (
            1,
            7,
            0x8006,
            0x8007,
            0x8008,
            0x8009,
            0x800C,
            0x800D,
            0x8011,
        ):
            with self.assertRaises(ValueError):
                protocol_routes(boards, original_rejected)
        self.assertFalse(protocol_routes(board_reply(2), 2))
        self.assertEqual(len(can_routes(board_reply(8))), 3)

    def test_firmware_iso_periodic_is_whole_single_frame_pdu_on_native_route(self):
        session, transport, _ = NativeProtocolTests().iso()
        session.open()
        try:
            hardware_id = session.start_periodic(b"\x3e\0", 100)
            packet = transport.sent[-1]
            self.assertEqual(struct.unpack_from("<H", packet)[0], 0x601)
            self.assertEqual(
                packet[12:],
                struct.pack("<IIIB", 4, 100, 0, 6) + b"\0\0\x07\xe0\x3e\0",
            )
            session.stop_periodic(hardware_id)
            self.assertEqual(struct.unpack_from("<H", transport.sent[-1])[0], 0x601)
            with self.assertRaises(ValueError):
                session.start_periodic(bytes(8), 100)
        finally:
            session.close()


class ControlOrderingTests(unittest.TestCase):
    def test_clear_rx_preserves_transmit_observations_and_drops_buffered_rx(self):
        from scripts.jlr_channels import DataFrame

        session, _ = NativeProtocolTests().kline()
        session.open()
        try:
            with session.client.io_lock, session._lock:
                event = TxEvent(session.route.target, 2, 1, 0x106, 10, b"")
                session._events.extend((DataFrame(0, 9, b"x"), event))
                raw_rx = (
                    struct.pack(
                        "<6HIIHH", 0, session.route.target, 9, 0, 0, 0, 0, 9, 2, 1
                    )
                    + b"x"
                    + bytes([ord("x")])
                )
                session.client.events.append(raw_rx)
                session.client.events.append(tx(2, target=session.route.target))
                session.clear_rx()
                self.assertEqual(tuple(session._events), (event,))
                self.assertEqual(len(session.client.events), 1)
                self.assertEqual(session.client.events[0][4:6], b"\x0a\0")
        finally:
            session.close()

    def test_failed_control_stops_further_submissions(self):
        session, _ = NativeProtocolTests().kline(transport=ProtocolTransport(fail_at=6))
        session.open()
        try:
            with self.assertRaises(TimeoutError):
                session.set_value(4, 10400)
            with self.assertRaises(RuntimeError):
                session.submit_data(b"x")
        finally:
            session.close()


class VoltagePlanTests(unittest.TestCase):
    def test_output_plans_are_pure_and_capability_bound(self):
        from scripts.jlr_channels import voltage_commands, voltage_routes

        boards = board_reply(3)
        route = voltage_routes(boards)[0]
        self.assertEqual((route.target, route.pin1), (0x8001, 13))
        on = voltage_commands(boards, route, 12000)
        self.assertEqual(
            (on[0].target, on[0].opcode, on[0].body),
            (1, 0x0B, struct.pack("<II", 1, 12000)),
        )
        self.assertEqual(on[1].body, struct.pack("<III", 1, 13, 0))
        off = voltage_commands(boards, route, None)
        self.assertEqual(off[0].body, struct.pack("<III", 0, 13, 0))
        self.assertEqual(off[1].body, struct.pack("<II", 1, 0))
        with self.assertRaises(ValueError):
            voltage_commands(boards, route, 20001)
        with self.assertRaises(ValueError):
            voltage_commands(board_reply(2), route, 12000)
        ground = voltage_routes(boards, ground=True)[0]
        self.assertEqual(
            voltage_commands(boards, ground, 0, ground=True)[0].body,
            struct.pack("<III", 1, 15, 0),
        )


class NativeIgnoredStatusTests(unittest.TestCase):
    def test_original_iso_ignored_status_does_not_abort_valid_response(self):
        from scripts.jlr_channels import (
            FirmwareISOExchange,
            FirmwareISOSession,
            protocol_routes,
        )

        class StatusTransport(ProtocolTransport):
            def write(self, frame):
                payload = decode_frames(frame)[0]
                super().write(frame)
                if payload[4:6] == b"\x08\0":
                    sequence = struct.unpack_from("<H", payload, 6)[0]
                    self.inject(tx(sequence, status=0x10C, target=0x601))

        boards = board_reply()
        transport = StatusTransport(iso_response=b"\x62\xf1\x90")
        session = FirmwareISOSession(
            JLRClient(transport),
            boards,
            protocol_routes(boards, 6)[0],
            500000,
            Peer(tx_id=0x7E0, rx_id=0x7E8),
        )
        session.open()
        try:
            self.assertEqual(
                FirmwareISOExchange({"engine": session}).exchange(
                    "engine", b"\x22\xf1\x90"
                ),
                b"\x62\xf1\x90",
            )
        finally:
            session.close()


class NativeRouteTrustTests(unittest.TestCase):
    def test_protocol_tag_cannot_be_swapped_onto_another_advertised_target(self):
        from dataclasses import replace

        from scripts.jlr_channels import ByteSession, KLineSession, protocol_routes

        boards = board_reply(3)
        transport = ProtocolTransport()
        with self.assertRaises(ValueError):
            ByteSession(
                JLRClient(transport),
                boards,
                replace(protocol_routes(boards, 2)[0], protocol=0x800A),
                10400,
            )
        with self.assertRaises(ValueError):
            KLineSession(
                JLRClient(transport),
                boards,
                replace(protocol_routes(boards, 3)[0], protocol=4),
            )
        self.assertFalse(transport.sent)


class PWMFunctionalLookupTests(unittest.TestCase):
    def test_original_functional_lookup_add_remove_clear_and_failure_cleanup(self):
        session, transport = RemainingFamilyTests().byte_session(2)
        session.open()
        try:
            session.update_functional_lookup(b"\x10\x20")
            self.assertEqual(
                [p[12:] for p in transport.sent[-2:]],
                [struct.pack("<II", 3, 0x10), struct.pack("<II", 3, 0x20)],
            )
            session.update_functional_lookup(b"\x10", remove=True)
            self.assertEqual(transport.sent[-1][4:6], b"\x0e\0")
            session.clear_functional_lookup()
            self.assertEqual(transport.sent[-1][12:], struct.pack("<I", 3))
        finally:
            session.close()
        session, transport = RemainingFamilyTests().byte_session(2)
        session.open()
        transport.fail_at = 5
        try:
            with self.assertRaises(TimeoutError):
                session.update_functional_lookup(b"\x10")
        finally:
            session.close()
        self.assertIn(
            struct.pack("<I", 3),
            [p[12:] for p in transport.sent if p[4:6] == b"\x10\0"],
        )
