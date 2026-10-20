import unittest

from scripts.isotp import Peer, ProtocolError, Receiver, Sender, stmin_seconds


class ISOTPTests(unittest.TestCase):
    def test_can_frame_format_is_part_of_peer_identity(self):
        peer = Peer(0x123, 0x456, extended_id=True)
        receiver = Receiver(peer)
        self.assertEqual(receiver.feed(0x456, b"\x01x", 0), (None, None))
        self.assertEqual(
            receiver.feed(0x456, b"\x01x", 0.1, extended_id=True), (b"x", None)
        )
        sender = Sender(peer)
        sender.start(b"a" * 20, 0)
        sender.flow(0x456, b"\x30\0\0", 0.1)
        self.assertEqual(sender.state, "flow")
        sender.flow(0x456, b"\x30\0\0", 0.2, extended_id=True)
        self.assertEqual(sender.state, "send")

    def test_roundtrip_boundaries_addressing_blocks_and_sequence_wrap(self):
        for length in (*range(1, 32), 111, 112, 113, 4095):
            for extended in (False, True):
                for block in (0, 1, 8):
                    with self.subTest(length=length, extended=extended, block=block):
                        a = Peer(
                            0x7E0,
                            0x7E8,
                            tx_address=0x10 if extended else None,
                            rx_address=0xF1 if extended else None,
                        )
                        b = Peer(
                            0x7E8,
                            0x7E0,
                            tx_address=a.rx_address,
                            rx_address=a.tx_address,
                        )
                        sender, receiver = (
                            Sender(a),
                            Receiver(b, blocksize=block, stmin=0xF1),
                        )
                        data = bytes(i % 256 for i in range(length))
                        now = 0.0
                        pdu, fc = receiver.feed(a.tx_id, sender.start(data, now), now)
                        for _ in range(10000):
                            if pdu is not None:
                                break
                            if fc is not None:
                                sender.flow(a.rx_id, fc, now)
                            now += 0.0002
                            frame = sender.poll(now)
                            if frame is None:
                                fc = None
                            else:
                                pdu, fc = receiver.feed(a.tx_id, frame, now)
                        self.assertEqual(pdu, data)
                        self.assertEqual(sender.state, "idle")
                        self.assertIsNone(receiver.deadline)

    def test_receiver_rejects_malformed_and_resets_on_wrong_sequence(self):
        peer = Peer(0x7E0, 0x7E8)
        for data in (
            b"",
            b"\0",
            b"\x08abcdefg",
            b"\x07a",
            b"\x10\0abcdef",
            b"\x10\x07abcdef",
            b"\x10\x14abc",
            b"\x30\0\0",
            b"123456789",
        ):
            with self.subTest(data=data), self.assertRaises(ProtocolError):
                Receiver(peer).feed(peer.rx_id, data, 0)
        receiver = Receiver(peer)
        receiver.feed(peer.rx_id, b"\x10\x14abcdef", 0)
        with self.assertRaises(ProtocolError):
            receiver.feed(peer.rx_id, b"\x22wrong!!", 0.1)
        self.assertFalse(receiver.buffer)
        with self.assertRaises(ProtocolError):
            receiver.feed(peer.rx_id, b"\x21abcdefg", 0.2)

    def test_unrelated_peer_timeout_and_restart(self):
        peer = Peer(0x7E0, 0x7E8)
        receiver = Receiver(peer)
        self.assertEqual(receiver.feed(0x123, b"", 0), (None, None))
        receiver.feed(peer.rx_id, b"\x10\x14abcdef", 0)
        with self.assertRaises(TimeoutError):
            receiver.tick(1)
        receiver.feed(peer.rx_id, b"\x10\x14abcdef", 1.1)
        self.assertEqual(receiver.feed(peer.rx_id, b"\x03xyz", 1.2), (b"xyz", None))
        receiver.feed(peer.rx_id, b"\x10\x14abcdef", 1.3)
        receiver.feed(peer.rx_id, b"\x10\x08ABCDEF", 1.4)
        self.assertEqual(receiver.feed(peer.rx_id, b"\x21GH", 1.5), (b"ABCDEFGH", None))

    def test_flow_errors_wait_limit_and_cancellation_reset(self):
        peer = Peer(0x7E0, 0x7E8)
        for fc in (b"\x32\0\0", b"\x33\0\0", b"\x30\0\x80", b"\x30\0\xf0", b"\x30\0"):
            sender = Sender(peer)
            sender.start(b"a" * 20, 0)
            with self.subTest(fc=fc), self.assertRaises(ProtocolError):
                sender.flow(peer.rx_id, fc, 0.1)
            self.assertEqual(sender.state, "idle")
        sender = Sender(peer, wait_limit=1)
        sender.start(b"a" * 20, 0)
        sender.flow(peer.rx_id, b"\x31\0\0", 0.1)
        with self.assertRaises(ProtocolError):
            sender.flow(peer.rx_id, b"\x31\0\0", 0.2)
        sender.start(b"a" * 20, 0.3)
        sender.reset()
        self.assertEqual(sender.state, "idle")

    def test_block_spacing_is_not_mistaken_for_lost_progress(self):
        peer = Peer(0x7E0, 0x7E8)
        sender = Sender(peer, timeout=0.01)
        sender.start(b"a" * 30, 0)
        sender.flow(peer.rx_id, b"\x30\x01\x7f", 0.001)
        self.assertIsNotNone(sender.poll(0.001))
        sender.flow(peer.rx_id, b"\x30\x01\x7f", 0.002)
        self.assertIsNone(sender.poll(0.02))
        self.assertIsNotNone(sender.poll(0.128))

    def test_advertised_receive_spacing_is_included_in_deadline(self):
        for block in (0, 1):
            peer = Peer(0x7E0, 0x7E8)
            receiver = Receiver(peer, timeout=0.01, stmin=0x7F, blocksize=block)
            receiver.feed(peer.rx_id, b"\x10\x14abcdef", 0)
            receiver.feed(peer.rx_id, b"\x21ghijklm", 0.001)
            self.assertEqual(
                receiver.feed(peer.rx_id, b"\x22nopqrst", 0.128),
                (b"abcdefghijklmnopqrst", None),
            )

    def test_configuration_and_timestamp_validation(self):
        peer = Peer(0x7E0, 0x7E8)
        for bad in (-1, 0x80, 0xF0, 0xFA, 256):
            with self.assertRaises(ProtocolError):
                stmin_seconds(bad)
        self.assertEqual(stmin_seconds(0xF9), 0.0009)
        with self.assertRaises(ValueError):
            Peer(0x800, 1)
        with self.assertRaises(ValueError):
            Sender(peer, timeout=0)
        with self.assertRaises(ValueError):
            Receiver(peer, blocksize=256)
        with self.assertRaises(ValueError):
            Sender(peer).start(b"a" * 4096, 0)
        receiver = Receiver(peer)
        receiver.tick(1)
        for bad in (0, float("nan"), float("inf")):
            with self.assertRaises(ValueError):
                receiver.tick(bad)


if __name__ == "__main__":
    unittest.main()
