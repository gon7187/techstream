import struct
import tempfile
import threading
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from scripts.jlr import JLRClient, encode_frame
from scripts.jlr_firmware import (
    FirmwareUpdater,
    begin_body,
    chunk_body,
    images_from_pe,
    load_image,
    parse_image,
    plan,
)


def image(role=0, size=117):
    data = bytearray(size)
    struct.pack_into("<III", data, 0, 108, 0x50001 + role, 0x123)
    struct.pack_into("<I", data, 76, 0x76543210 + role)
    data[108:] = bytes(index % 256 for index in range(size - 108))
    return parse_image(bytes(data))


def boards(*, slot=2, mode=1, fingerprint=0, role=0):
    data = bytearray(180)
    data[21] = mode
    offset = 20 + (slot.bit_length() - 1) * 20
    data[offset : offset + 4] = bytes([1, mode, 1, 1])
    struct.pack_into("<I", data, offset + (4 if role == 0 else 8), fingerprint)
    return bytes(data)


class FakeIO:
    """Parses actual outbound JLR frames and emits independently packed replies."""

    def __init__(self, firmware, *, slot=2, fault=None, chunks=(4, 5, 0)):
        self.firmware, self.slot, self.fault = firmware, slot, fault
        self.chunks = list(chunks)
        self.requests = []
        self.pending = b""
        self.closed = False
        self.updated = False
        self.received = b""

    def write(self, data):
        size, _ = struct.unpack_from("<HH", data)
        assert size == len(data) - 4
        target, pad, opcode, sequence, count, reserved = struct.unpack_from(
            "<6H", data, 4
        )
        assert (target, pad, count, reserved) == (1, 0, 0, 0)
        self.requests.append((opcode, data[16:]))
        if self.fault == len(self.requests):
            raise TimeoutError("injected uncertain write")
        extra = b""
        if opcode == 0x109:
            extra = boards(
                slot=self.slot,
                fingerprint=self.firmware.fingerprint if self.updated else 0,
                role=self.firmware.role,
            )[20:]
        elif opcode == 0x10A:
            body = data[16:]
            operation, ordinal, length = struct.unpack_from("<III", body)
            assert ordinal == self.slot.bit_length()
            if operation == 1:
                assert length == len(self.firmware.data)
                assert len(body) == 124
                self.received = body[12:-4]
                assert body[-4:] == bytes(4)
            else:
                assert operation == 2
                assert struct.unpack_from("<I", body, 12)[0] == 0x5A000000
                assert len(body[16:]) == length
                self.received += body[16:]
            size = self.chunks.pop(0)
            extra = struct.pack("<I", size)
            if size == 0:
                self.updated = True
        self.pending = encode_frame(
            struct.pack("<6HII", 0, target, opcode | 0x8000, sequence, 0, 0, 0, 0)
            + extra
        )

    def read(self, timeout):
        assert 1 <= timeout <= 50
        data, self.pending = self.pending, b""
        return data

    def close(self):
        self.closed = True


class FirmwareTests(unittest.TestCase):
    def test_native_header_and_byte_preservation(self):
        item = image()
        self.assertEqual(
            (item.role, item.version, item.fingerprint), (0, 0x123, 0x76543210)
        )
        self.assertEqual(item.data[108:], bytes(range(9)))
        for data in (
            b"",
            item.data[:108],
            b"x" + item.data[1:],
            item.data[:4] + b"xxxx" + item.data[8:],
        ):
            with self.assertRaises(ValueError):
                parse_image(data)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "firmware.bin"
            path.write_bytes(item.data)
            self.assertEqual(load_image(path), item)
            with self.assertRaises(ValueError):
                load_image("/dev/null")

    def test_native_plan_presence_fingerprint_roles_and_slots(self):
        boot, app = image(), image(1)
        self.assertEqual(
            [(r.slot, r.image.role) for r in plan(boards(), (app, boot))],
            [(2, 0), (2, 1)],
        )
        self.assertFalse(plan(boards(fingerprint=boot.fingerprint), (boot,)))
        self.assertEqual(
            len(plan(boards(fingerprint=boot.fingerprint), (boot,), force=True)), 1
        )
        with self.assertRaises(ValueError):
            plan(boards(), (boot, boot))
        unknown = bytearray(boards())
        unknown[40] = 255
        with self.assertRaises(ValueError):
            plan(bytes(unknown), (boot,))

    def test_exact_native_command_vectors(self):
        item = image()
        record = plan(boards(), (item,))[0]
        self.assertEqual(
            begin_body(record),
            bytes.fromhex("010000000200000075000000") + item.data[:108] + bytes(4),
        )
        self.assertEqual(
            chunk_body(128, b"abc"),
            bytes.fromhex("0200000008000000030000000000005a616263"),
        )
        for invalid in (
            replace(record, slot=0),
            replace(record, slot=3),
            replace(record, board_kind=12),
            replace(record, image=replace(item, sha256="forged")),
        ):
            with self.assertRaises(ValueError):
                begin_body(invalid)
        for slot, data in ((3, b"a"), (1, b""), (1, b"a" * 8193)):
            with self.assertRaises(ValueError):
                chunk_body(slot, data)

    def test_full_wire_execution_and_terminal_state(self):
        item = image()
        io = FakeIO(item)
        client = JLRClient(io)
        updater = FirmwareUpdater(client)
        self.assertEqual(len(updater.run((item,))), 1)
        self.assertEqual(updater.state, "verified")
        self.assertEqual(updater.acknowledged, len(item.data))
        self.assertEqual(io.received, item.data)
        self.assertEqual(
            [op for op, _ in io.requests], [0x109, 0x10C, 0x10A, 0x10A, 0x10A, 0x109]
        )
        self.assertTrue(io.closed)
        self.assertIsNone(client.channel_owner)
        with self.assertRaises(RuntimeError):
            updater.run((item,))

    def test_host_bounded_8192_chunk_fits_jlr_framing(self):
        item = image(size=108 + 8192)
        io = FakeIO(item, chunks=(8192, 0))
        updater = FirmwareUpdater(JLRClient(io))
        updater.run((item,))
        self.assertEqual(io.received, item.data)
        self.assertEqual(updater.state, "verified")

    def test_every_uncertain_write_boundary_fails_and_closes(self):
        for fault in range(1, 7):
            with self.subTest(fault=fault):
                item = image()
                io = FakeIO(item, fault=fault)
                updater = FirmwareUpdater(JLRClient(io))
                with self.assertRaises(TimeoutError):
                    updater.run((item,))
                self.assertEqual(updater.state, "uncertain")
                self.assertTrue(io.closed)
                self.assertEqual(len(io.requests), fault)

    def test_cancel_before_first_command_and_between_chunks(self):
        for after in (0, 3, 4):
            io = FakeIO(image())
            updater = FirmwareUpdater(
                JLRClient(io),
                cancelled=lambda io=io, after=after: len(io.requests) >= after,
            )
            with self.assertRaises(InterruptedError):
                updater.run((image(),))
            self.assertEqual(updater.state, "cancelled" if after == 0 else "uncertain")
            self.assertTrue(io.closed)
            self.assertEqual(len(io.requests), after)

    def test_cancel_predicate_interrupts_a_missing_reply_inside_client(self):
        cancelled = False

        class MissingReply(FakeIO):
            reads = 0

            def read(self, timeout):
                nonlocal cancelled
                self.reads += 1
                cancelled = True
                return b""

        io = MissingReply(image())
        original = threading.Event()
        client = JLRClient(io, cancel=original)
        updater = FirmwareUpdater(client, cancelled=lambda: cancelled)
        with self.assertRaises(InterruptedError):
            updater.run((image(),))
        self.assertEqual(io.reads, 1)
        self.assertEqual(updater.state, "uncertain")
        self.assertTrue(io.closed)
        self.assertIs(client.cancel, original)

    def test_cancellation_at_final_ack_is_not_reported_as_verified(self):
        io = FakeIO(image())
        updater = FirmwareUpdater(
            JLRClient(io), cancelled=lambda: len(io.requests) >= 6
        )
        with self.assertRaises(InterruptedError):
            updater.run((image(),))
        self.assertEqual(updater.state, "uncertain")
        self.assertTrue(io.closed)

    def test_no_progress_overrun_and_early_finish(self):
        for chunks in ((0,), (8193,), (10,), (4, 0), (4, 5, 1)):
            io = FakeIO(image(), chunks=chunks)
            updater = FirmwareUpdater(JLRClient(io))
            with self.assertRaises(ValueError):
                updater.run((image(),))
            self.assertEqual(updater.state, "uncertain")
            self.assertTrue(io.closed)

    def test_post_transfer_mismatch_is_not_success(self):
        class WrongIdentity(FakeIO):
            def write(self, data):
                super().write(data)
                if self.updated and self.requests[-1][0] == 0x109:
                    payload = bytearray(self.pending[4:])
                    payload[40] = 2
                    self.pending = encode_frame(bytes(payload))

        io = WrongIdentity(image())
        updater = FirmwareUpdater(JLRClient(io))
        with self.assertRaises(ValueError):
            updater.run((image(),))
        self.assertEqual(updater.state, "uncertain")

    def test_owner_and_master_reopen_requirement(self):
        io = FakeIO(image())
        client = JLRClient(io)
        client.channel_owner = object()
        updater = FirmwareUpdater(client)
        with self.assertRaises(RuntimeError):
            updater.run((image(),))
        self.assertFalse(io.requests)
        self.assertFalse(io.closed)
        application = FakeIO(image(1))
        with self.assertRaises(ValueError):
            FirmwareUpdater(JLRClient(application)).run((image(1),))
        self.assertEqual([op for op, _ in application.requests], [0x109])
        master = FakeIO(image(), slot=1)
        with self.assertRaises(ValueError):
            FirmwareUpdater(JLRClient(master)).run((image(),))
        self.assertEqual([op for op, _ in master.requests], [0x109])

    def test_master_reconnect_and_application_mode_switch(self):
        for role in (0, 1):
            item = image(role)
            io = FakeIO(item, slot=1)
            replacement = FakeIO(item, slot=1)
            if role == 0:
                replacement.updated = True
            else:
                replacement.chunks = [4, 5, 0]
            updater = FirmwareUpdater(
                JLRClient(io),
                reopen=lambda replacement=replacement: JLRClient(replacement),
            )
            updater.run((item,))
            self.assertEqual(updater.state, "verified")
            self.assertTrue(io.closed)
            self.assertTrue(replacement.closed)
            if role == 1:
                self.assertEqual(io.requests[-1][0], 0x102)
                self.assertEqual(replacement.requests[0][0], 0x109)
                self.assertEqual(replacement.received, item.data)

    def test_reopened_board_identity_change_prevents_transfer(self):
        item = image(1)
        initial = FakeIO(item)

        class ChangedBoard(FakeIO):
            def write(self, data):
                super().write(data)
                if self.requests[-1][0] == 0x109:
                    payload = bytearray(self.pending[4:])
                    payload[40] = 2
                    self.pending = encode_frame(bytes(payload))

        replacement = ChangedBoard(item)
        updater = FirmwareUpdater(
            JLRClient(initial), reopen=lambda: JLRClient(replacement)
        )
        with self.assertRaisesRegex(ValueError, "identity changed before"):
            updater.run((item,))
        self.assertEqual([op for op, _ in replacement.requests], [0x109])
        self.assertTrue(replacement.closed)
        self.assertEqual(updater.state, "uncertain")

    def test_native_current_master_application_enters_boot_even_with_empty_plan(self):
        item = image(1)

        class CurrentApplication(FakeIO):
            reset = False

            def write(self, data):
                super().write(data)
                if self.requests[-1][0] == 0x103:
                    self.reset = True
                if self.requests[-1][0] == 0x109:
                    payload = (
                        self.pending[4:20]
                        + boards(
                            slot=1,
                            mode=1 if self.reset else 2,
                            fingerprint=item.fingerprint,
                            role=1,
                        )[16:]
                    )
                    self.pending = encode_frame(payload)

        io = CurrentApplication(item, slot=1)
        updater = FirmwareUpdater(JLRClient(io))
        self.assertFalse(updater.run((item,)))
        self.assertEqual([op for op, _ in io.requests], [0x109, 0x103, 0x109])
        self.assertEqual(updater.state, "verified")

    def test_second_native_pass_updates_newly_exposed_board(self):
        item = image()

        class DynamicBoards(FakeIO):
            probes = 0
            first_image = b""

            def write(self, data):
                if struct.unpack_from("<H", data, 8)[0] == 0x109:
                    self.probes += 1
                    if self.probes == 4:
                        self.first_image = self.received
                        self.slot, self.updated = 4, False
                        self.chunks = [4, 5, 0]
                super().write(data)
                if self.probes == 1 and self.requests[-1][0] == 0x109:
                    payload = bytearray(self.pending[4:])
                    payload[21] = 0
                    self.pending = encode_frame(bytes(payload))

        io = DynamicBoards(item)
        updater = FirmwareUpdater(JLRClient(io))
        result = updater.run((item,))
        self.assertEqual([record.slot for record in result], [2, 4])
        self.assertEqual(io.first_image, item.data)
        self.assertEqual(io.received, item.data)
        self.assertEqual(updater.acknowledged, 2 * len(item.data))
        self.assertEqual(updater.state, "verified")

    def test_native_boot_reset_accepts_status_seven(self):
        class ResetIO(FakeIO):
            def write(self, data):
                super().write(data)
                payload = bytearray(self.pending[4:])
                if self.requests[-1][0] == 0x109 and not self.updated:
                    payload[21] = 0
                if self.requests[-1][0] == 0x103:
                    struct.pack_into("<I", payload, 12, 7)
                self.pending = encode_frame(bytes(payload))

        io = ResetIO(image())
        updater = FirmwareUpdater(JLRClient(io))
        updater.run((image(),))
        self.assertEqual(updater.state, "verified")
        self.assertIn((0x103, b""), io.requests)
        reset_index = io.requests.index((0x103, b""))
        self.assertEqual(io.requests[reset_index + 1][0], 0x109)

    def test_reopen_provider_cannot_close_another_owners_client(self):
        owned_io = FakeIO(image())
        owned_client = JLRClient(owned_io)
        owner = object()
        owned_client.channel_owner = owner
        initial = FakeIO(image(), slot=1)
        updater = FirmwareUpdater(JLRClient(initial), reopen=lambda: owned_client)
        with self.assertRaisesRegex(RuntimeError, "already has an owner"):
            updater.run((image(),))
        self.assertTrue(initial.closed)
        self.assertFalse(owned_io.closed)
        self.assertIs(owned_client.channel_owner, owner)
        self.assertEqual(updater.state, "uncertain")

    def test_cleanup_failure_never_success(self):
        class BrokenClose(FakeIO):
            def close(self):
                raise OSError("close failed")

        updater = FirmwareUpdater(JLRClient(BrokenClose(image())))
        with self.assertRaises(OSError):
            updater.run((image(),))
        self.assertEqual(updater.state, "uncertain")

    def test_malformed_reply_and_status_fail_closed(self):
        for corruption in ("short", "status"):

            class BadReply(FakeIO):
                def write(self, data, corruption=corruption):
                    super().write(data)
                    if self.requests[-1][0] == 0x10A:
                        payload = bytearray(self.pending[4:])
                        if corruption == "short":
                            payload = payload[:20]
                        else:
                            struct.pack_into("<I", payload, 12, 9)
                        self.pending = encode_frame(bytes(payload))

            updater = FirmwareUpdater(JLRClient(BadReply(image())))
            with self.assertRaises((ValueError, OSError)):
                updater.run((image(),))
            self.assertEqual(updater.state, "uncertain")

    def test_reopen_fault_and_primary_exception_survive_cleanup(self):
        def failed_reopen():
            raise OSError("reopen failed")

        io = FakeIO(image(), slot=1)
        updater = FirmwareUpdater(JLRClient(io), reopen=failed_reopen)
        with self.assertRaisesRegex(OSError, "reopen failed"):
            updater.run((image(),))
        self.assertEqual(updater.state, "uncertain")
        self.assertTrue(io.closed)

        class BrokenCleanup(FakeIO):
            def close(self):
                raise OSError("close failed")

        updater = FirmwareUpdater(JLRClient(BrokenCleanup(image(), fault=1)))
        with self.assertRaisesRegex(TimeoutError, "injected uncertain write") as error:
            updater.run((image(),))
        self.assertIn("cleanup also failed", error.exception.__notes__[0])

    def test_whole_operation_deadline_and_invalid_limits(self):
        for timeout in (0, -1, 601, float("nan"), float("inf")):
            with self.assertRaises(ValueError):
                FirmwareUpdater(JLRClient(FakeIO(image())), timeout=timeout)
        io = FakeIO(image())
        updater = FirmwareUpdater(JLRClient(io), timeout=1)
        with (
            patch("scripts.jlr_firmware.time.monotonic", side_effect=(0, 2)),
            self.assertRaisesRegex(TimeoutError, "deadline"),
        ):
            updater.run((image(),))
        self.assertFalse(io.requests)
        self.assertTrue(io.closed)

    def test_constructor_does_no_io(self):
        io = FakeIO(image())
        FirmwareUpdater(JLRClient(io))
        self.assertFalse(io.requests)
        self.assertFalse(io.closed)

    def test_synthetic_pe_resource_extraction(self):
        data = bytearray(0x600)
        data[:2] = b"MZ"
        struct.pack_into("<I", data, 60, 0x80)
        data[0x80:0x84] = b"PE\0\0"
        struct.pack_into("<H", data, 0x86, 1)
        struct.pack_into("<H", data, 0x94, 0xE0)
        struct.pack_into("<H", data, 0x98, 0x10B)
        struct.pack_into("<II", data, 0x108, 0x1000, 0x400)
        struct.pack_into("<III", data, 0x184, 0x1000, 0x400, 0x200)
        for off, entries in (
            (0, [(10, 0x80000020)]),
            (0x20, [(5005, 0x80000050), (5006, 0x80000070)]),
            (0x50, [(1033, 0x90)]),
            (0x70, [(1033, 0xA0)]),
        ):
            struct.pack_into("<H", data, 0x200 + off + 14, len(entries))
            for index, (key, value) in enumerate(entries):
                struct.pack_into("<II", data, 0x200 + off + 16 + index * 8, key, value)
        boot, app = image(), image(1)
        for off, destination, item in ((0x90, 0x300, app), (0xA0, 0x400, boot)):
            struct.pack_into(
                "<II", data, 0x200 + off, 0x1000 + destination - 0x200, len(item.data)
            )
            data[destination : destination + len(item.data)] = item.data
        self.assertEqual(images_from_pe(bytes(data)), (boot, app))
        struct.pack_into("<I", data, 0x214, 0x80000000)
        with self.assertRaises(ValueError):
            images_from_pe(bytes(data))

    def test_pe_parser_rejects_malformed_input(self):
        for data in (b"", b"MZ" + bytes(62), b"MZ" + bytes(200)):
            with self.assertRaises(ValueError):
                images_from_pe(data)


if __name__ == "__main__":
    unittest.main()
