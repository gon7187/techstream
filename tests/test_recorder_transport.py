"""Authored byte-stream peers; no device or vendor executable is used."""

import struct
import unittest
from collections.abc import Callable
from typing import cast
from unittest.mock import patch

from scripts.drive_recorder import (
    NativeTransferAcknowledgement,
    NativeTransferFrame,
    NativeVimClient,
    NativeVimReply,
    RecorderCancelled,
    RecorderError,
    UnsupportedRecorderOperation,
    decode_vim_transfer,
    encode_vim_transfer,
)
from scripts.recorder_transport import RecorderTransport

CAPABILITIES = frozenset({"denso-vim-control"})


class Clock:
    def __init__(self):
        self.now = 100.0

    def __call__(self):
        return self.now


class Peer:
    def __init__(self, response=b"reply", *, read_size=517, write_size=517):
        self.clock = Clock()
        self.response = response
        self.read_size, self.write_size = read_size, write_size
        self.incoming = bytearray()
        self.pending = bytearray()
        self.frames = []
        self.request_frames = []
        self.requests = []
        self.close_count = 0
        self.before_read: Callable[[], None] | None = None
        self.before_write: Callable[[], None] | None = None
        self.reply_ack = True
        self.reply_data = True
        self.corrupt = self.sequence_error = False
        self.read_count = self.write_count = 0

    def write(self, data, *, timeout):
        self.write_count += 1
        if self.before_write:
            self.before_write()
        count = min(len(data), self.write_size)
        self.pending.extend(data[:count])
        while len(self.pending) >= 4:
            size = struct.unpack_from("<H", self.pending, 2)[0] + 6
            if len(self.pending) < size:
                break
            raw = bytes(self.pending[:size])
            del self.pending[:size]
            frame = NativeTransferFrame.parse(raw)
            self.frames.append(raw)
            if frame.control == 3:
                continue
            if frame.control == 0x7F:
                self.incoming.extend(NativeTransferFrame(0x7F, b"\x06\x05").encode())
                continue
            self.request_frames.append(raw)
            if self.reply_ack:
                self.incoming.extend(NativeTransferAcknowledgement(state=3).encode())
            if frame.control in (0, 2):
                self.requests.append(decode_vim_transfer(tuple(self.request_frames)))
                self.request_frames.clear()
                if self.reply_data:
                    frames = list(encode_vim_transfer(self.response))
                    if self.corrupt:
                        bad = bytearray(frames[0])
                        bad[-2] ^= 1
                        self.incoming.extend(bad)
                    if self.sequence_error:
                        self.incoming.extend(frames[0])
                        self.incoming.extend(
                            NativeTransferFrame(0x89, b"wrong").encode()
                        )
                        frames = frames[1:]
                    self.incoming.extend(b"".join(frames))
        return count

    def read(self, size, *, timeout):
        self.read_count += 1
        if self.before_read:
            self.before_read()
        if not self.incoming:
            self.clock.now += timeout
            return b""
        count = min(size, self.read_size, len(self.incoming))
        result = bytes(self.incoming[:count])
        del self.incoming[:count]
        return result

    def close(self):
        self.close_count += 1


class RecorderTransportTests(unittest.TestCase):
    def transport(self, peer=None, **kwargs):
        peer = peer or Peer()
        return peer, RecorderTransport(
            peer, capabilities=CAPABILITIES, clock=peer.clock, **kwargs
        )

    def exchange(
        self,
        transport,
        peer,
        request=b"request",
        timeout: float = 30,
        cancelled=lambda: False,
    ):
        return transport(request, deadline=peer.clock() + timeout, cancelled=cancelled)

    def test_real_native_client_and_fragmented_stream(self):
        reply = NativeVimReply(0x81, 6, struct.pack("<I", 7)).encode()
        peer, transport = self.transport(Peer(reply, read_size=1, write_size=2))
        client = NativeVimClient(transport, capabilities=CAPABILITIES, clock=peer.clock)
        self.assertEqual(client.get_mode(), 7)
        self.assertEqual(peer.requests, [b"\x01"])
        self.assertEqual(NativeTransferFrame.parse(peer.frames[0]).payload, b"\x01")
        self.assertEqual(NativeTransferAcknowledgement.parse(peer.frames[-1]).state, 3)
        self.assertEqual(transport.report()["exchanges"], 1)
        self.assertEqual(transport.report()["command_retransmissions"], 0)

    def test_multiframe_in_both_directions_wraps_sequence(self):
        data = bytes(range(256)) * 270
        peer, transport = self.transport(Peer(data))
        self.assertEqual(self.exchange(transport, peer, data), data)
        self.assertEqual(peer.requests, [data])
        controls = [NativeTransferFrame.parse(raw).control for raw in peer.frames]
        self.assertIn(255, controls)
        self.assertGreater(controls.count(128), 1)

    def test_sequential_exchanges_and_context_close(self):
        peer, transport = self.transport()
        with transport:
            for request in (b"one", b"two"):
                self.assertEqual(self.exchange(transport, peer, request), b"reply")
        transport.close()
        self.assertEqual(peer.close_count, 1)
        self.assertEqual(transport.report()["state"], "closed")
        with self.assertRaises(ConnectionError):
            self.exchange(transport, peer)

    def test_explicit_capability_before_any_io(self):
        peer = Peer()
        with self.assertRaises(UnsupportedRecorderOperation):
            RecorderTransport(peer, capabilities=frozenset())
        self.assertEqual((peer.read_count, peer.write_count), (0, 0))

    def test_receiver_checksum_nak_and_valid_peer_retry(self):
        peer = Peer()
        peer.corrupt = True
        peer, transport = self.transport(peer)
        self.assertEqual(self.exchange(transport, peer), b"reply")
        acks = [
            NativeTransferAcknowledgement.parse(raw)
            for raw in peer.frames
            if NativeTransferFrame.parse(raw).control == 3
        ]
        self.assertEqual([ack.error for ack in acks], [0x900D0004, None])
        self.assertEqual(peer.requests, [b"request"])

    def test_receiver_sequence_nak_preserves_partial_response(self):
        data = b"a" * 1200
        peer = Peer(data)
        peer.sequence_error = True
        peer, transport = self.transport(peer)
        self.assertEqual(self.exchange(transport, peer), data)
        errors = [
            NativeTransferAcknowledgement.parse(raw).error
            for raw in peer.frames
            if NativeTransferFrame.parse(raw).control == 3
        ]
        self.assertIn(0x900D0005, errors)

    def test_receiver_bad_etx_nak_and_valid_retry(self):
        peer = Peer()
        peer.reply_ack = peer.reply_data = False
        valid = NativeTransferFrame(0, b"reply").encode()
        peer.incoming.extend(NativeTransferAcknowledgement(state=3).encode())
        peer.incoming.extend(valid[:-1] + b"\x04" + valid)
        peer, transport = self.transport(peer)
        self.assertEqual(self.exchange(transport, peer), b"reply")
        errors = [
            NativeTransferAcknowledgement.parse(raw).error
            for raw in peer.frames
            if NativeTransferFrame.parse(raw).control == 3
        ]
        self.assertEqual(errors, [0x900D0006, None])

    def test_truncated_header_and_payload_have_bounded_timeouts(self):
        ack = NativeTransferAcknowledgement(state=3).encode()
        for raw in (b"\x02", ack + NativeTransferFrame(0, b"reply").encode()[:-2]):
            peer = Peer()
            peer.reply_ack = peer.reply_data = False
            peer.incoming.extend(raw)
            peer, transport = self.transport(peer)
            with self.subTest(raw=raw), self.assertRaises(TimeoutError):
                self.exchange(transport, peer, timeout=0.2)
            self.assertEqual(transport.report()["state"], "fault")

    def test_malformed_ack_and_extra_ack_cannot_complete_exchange(self):
        for frames in (
            [NativeTransferFrame(3, b"\x06").encode()],
            [NativeTransferAcknowledgement(state=3).encode()] * 2,
        ):
            peer = Peer()
            peer.reply_ack = peer.reply_data = False
            peer.incoming.extend(b"".join(frames))
            peer, transport = self.transport(peer)
            with self.assertRaises(RecorderError):
                self.exchange(transport, peer)
            self.assertEqual(transport.report()["exchanges"], 0)

    def test_idle_read_timeouts_and_late_ack_do_not_repeat_data(self):
        peer, transport = self.transport()
        original = peer.read
        attempts = 0

        def delayed_read(size, *, timeout):
            nonlocal attempts
            attempts += 1
            if attempts <= 2:
                peer.clock.now += timeout
                raise TimeoutError("authored transient read timeout")
            return original(size, timeout=timeout)

        with patch.object(peer, "read", side_effect=delayed_read):
            self.assertEqual(self.exchange(transport, peer), b"reply")
        self.assertEqual(peer.requests, [b"request"])

    def test_lost_ack_times_out_without_repeating_command(self):
        peer = Peer()
        peer.reply_ack = peer.reply_data = False
        peer, transport = self.transport(peer)
        with self.assertRaisesRegex(TimeoutError, "acknowledgement"):
            self.exchange(transport, peer)
        self.assertEqual(peer.requests, [b"request"])
        self.assertEqual(transport.report()["state"], "fault")
        with self.assertRaisesRegex(RecorderError, "reconnection"):
            self.exchange(transport, peer)
        self.assertEqual(peer.requests, [b"request"])

    def test_lost_response_status_queries_are_not_command_retries(self):
        peer = Peer()
        peer.reply_data = False
        peer, transport = self.transport(peer, max_events=1000)
        with self.assertRaisesRegex(TimeoutError, "deadline"):
            self.exchange(transport, peer, timeout=3.5)
        controls = [NativeTransferFrame.parse(raw).control for raw in peer.frames]
        self.assertGreaterEqual(controls.count(0x7F), 2)
        self.assertEqual(peer.requests, [b"request"])

    def test_native_receive_timeout_with_no_keepalive_reply(self):
        peer, transport = self.transport()
        peer.reply_data = False

        def ignore_ping():
            if (
                len(peer.pending) >= 0
                and peer.frames
                and NativeTransferFrame.parse(peer.frames[-1]).control == 0x7F
            ):
                peer.incoming.clear()

        peer.before_read = ignore_ping
        with self.assertRaisesRegex(TimeoutError, "response"):
            self.exchange(transport, peer)

    def test_peer_nak_not_retried(self):
        peer = Peer()
        peer.reply_ack = peer.reply_data = False
        peer.incoming.extend(NativeTransferAcknowledgement(error=0x900D0004).encode())
        peer, transport = self.transport(peer)
        with self.assertRaisesRegex(RecorderError, "NAK"):
            self.exchange(transport, peer)
        self.assertEqual(peer.requests, [b"request"])

    def test_cancel_before_io_and_at_each_transfer_boundary(self):
        peer, transport = self.transport()
        with self.assertRaises(RecorderCancelled):
            self.exchange(transport, peer, cancelled=lambda: True)
        self.assertEqual(peer.write_count, 0)
        self.assertEqual(transport.report()["state"], "idle")
        for phase in ("shortwrite", "ack", "response", "reply_ack"):
            peer, transport = self.transport(
                Peer(b"a" * 1100, write_size=2 if phase == "shortwrite" else 517)
            )

            def cancelled(phase=phase, peer=peer):
                if phase == "shortwrite":
                    return peer.write_count > 0
                if phase == "ack":
                    return peer.read_count > 0
                if phase == "response":
                    return len(peer.incoming) < 500 and peer.read_count > 2
                return any(
                    NativeTransferFrame.parse(raw).control == 3 for raw in peer.frames
                )

            with self.subTest(phase=phase), self.assertRaises(RecorderCancelled):
                self.exchange(transport, peer, cancelled=cancelled)
            self.assertEqual(transport.report()["state"], "fault")

    def test_public_cancel_and_close_during_io(self):
        for method in ("cancel", "close"):
            peer, transport = self.transport()
            peer.before_read = getattr(transport, method)
            with (
                self.subTest(method=method),
                self.assertRaises((RecorderCancelled, ConnectionError)),
            ):
                self.exchange(transport, peer)

    def test_busy_guard_rejects_nested_exchange(self):
        peer, transport = self.transport()
        errors = []

        def nested():
            try:
                self.exchange(transport, peer)
            except RecorderError as exc:
                errors.append(str(exc))

        peer.before_write = nested
        self.assertEqual(self.exchange(transport, peer), b"reply")
        self.assertTrue(errors and all("busy" in error for error in errors))

    def test_hotplug_during_read_or_partial_write(self):
        for phase in ("read", "write"):
            peer, transport = self.transport(Peer(write_size=1))

            def unplug():
                raise ConnectionError("authored hotplug removal")

            if phase == "read":
                peer.before_read = unplug
            else:

                def partial_unplug(peer=peer):
                    if peer.write_count > 1:
                        unplug()

                peer.before_write = partial_unplug
            with self.subTest(phase=phase), self.assertRaises(ConnectionError):
                self.exchange(transport, peer)
            self.assertEqual(transport.report()["state"], "fault")

    def test_uncertain_write_timeout_is_never_retried(self):
        peer, transport = self.transport()
        with patch.object(
            peer, "write", side_effect=TimeoutError("uncertain accepted bytes")
        ) as write:
            with self.assertRaisesRegex(TimeoutError, "uncertain"):
                self.exchange(transport, peer)
            self.assertEqual(write.call_count, 1)
        with self.assertRaisesRegex(RecorderError, "reconnection"):
            self.exchange(transport, peer)
        self.assertEqual(peer.requests, [])

    def test_cancel_or_deadline_takes_precedence_over_simultaneous_io_error(self):
        for phase in ("read", "write"):
            for interrupted in ("cancel", "deadline"):
                peer, transport = self.transport()

                def fail(peer=peer, transport=transport, interrupted=interrupted):
                    if interrupted == "cancel":
                        transport.cancel()
                    else:
                        peer.clock.now += 100
                    raise OSError("simultaneous stream failure")

                setattr(peer, "before_" + phase, fail)
                expected = (
                    RecorderCancelled if interrupted == "cancel" else TimeoutError
                )
                with (
                    self.subTest(phase=phase, interrupted=interrupted),
                    self.assertRaises(expected) as error,
                ):
                    self.exchange(transport, peer)
                self.assertIsInstance(error.exception.__cause__, OSError)

    def test_constructor_rejects_invalid_host_limits(self):
        for options in (
            {"max_size": 0},
            {"max_size": True},
            {"max_size": 67108865},
            {"max_events": 0},
            {"io_timeout": 0},
            {"io_timeout": float("nan")},
        ):
            with self.subTest(options=options), self.assertRaises(RecorderError):
                self.transport(**options)

    def test_invalid_stream_contract_and_event_budget(self):
        for count in (0, -1, True, 999, None):
            peer, transport = self.transport()
            with (
                self.subTest(count=count),
                patch.object(peer, "write", return_value=count),
                self.assertRaises(RecorderError),
            ):
                self.exchange(transport, peer)
        peer, transport = self.transport()
        peer.read = lambda size, *, timeout: b"x" * (size + 1)
        with self.assertRaisesRegex(RecorderError, "byte bound"):
            self.exchange(transport, peer)
        peer, transport = self.transport(max_events=2)
        with self.assertRaisesRegex(RecorderError, "budget"):
            self.exchange(transport, peer)

    def test_invalid_framing_and_large_wire_length(self):
        for raw in (b"bad!", b"\x02\x00\x00\x02"):
            peer = Peer()
            peer.reply_ack = peer.reply_data = False
            peer.incoming.extend(raw)
            peer, transport = self.transport(peer)
            with self.subTest(raw=raw), self.assertRaises(RecorderError):
                self.exchange(transport, peer)

    def test_input_and_deadline_validation(self):
        peer, transport = self.transport(max_size=10)
        for request in (b"", "request", b"a" * 11):
            with self.subTest(request=request), self.assertRaises(RecorderError):
                self.exchange(transport, peer, cast(bytes, request))
        for deadline in (float("nan"), float("inf")):
            with self.assertRaises(RecorderError):
                transport(b"r", deadline=deadline, cancelled=lambda: False)
        with self.assertRaises(TimeoutError):
            self.exchange(transport, peer, timeout=0)
        self.assertEqual(peer.write_count, 0)


if __name__ == "__main__":
    unittest.main()
