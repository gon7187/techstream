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
