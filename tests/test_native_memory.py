"""Authored virtual-pointer lifetime checks; no native host addresses are used."""

import hashlib
import json
import struct
import unittest
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import cast

from scripts.j2534_2026 import NativeMessage, PrimitiveResult
from scripts.native_memory import NativeMemoryArena
from scripts.script_libraries import NativeProcedureLibraries
from scripts.utility_ex import _DRIVER_SLOTS, UtilityExContext, UtilityExEngine

SHA = "79fc495c68eb099a7ebc0d1eefe0eafd80101ac0bc09a58d3f603ed556c84762"


class NativeMemoryTests(unittest.TestCase):
    def setUp(self):
        self.owner = object()
        self.arena = NativeMemoryArena(SHA, self.owner, limit=64)

    def test_allocate_interior_read_write_and_nonoverlap(self):
        first, second = self.arena.alloc(8), self.arena.alloc(8)
        self.assertGreater(second, first + 8)
        self.assertEqual(self.arena.read(first, 8), bytes(8))
        self.arena.write(first + 2, b"abcd")
        self.assertEqual(self.arena.read(first, 8), b"\0\0abcd\0\0")
        for address, size in ((first - 1, 1), (first + 7, 2), (0, 1), (0xFFFFFFFF, 2)):
            with self.subTest(address=address), self.assertRaises(ValueError):
                self.arena.read(address, size)
        with self.assertRaises(ValueError):
            self.arena.write(first + 7, b"ab")
        self.assertEqual(self.arena.read(second, 8), bytes(8))

    def test_realloc_preserves_data_zero_fills_and_invalidates_old_address(self):
        first = self.arena.alloc(4)
        self.arena.write(first, b"ABCD")
        grown = self.arena.realloc(first, 8)
        self.assertNotEqual(first, grown)
        self.assertEqual(self.arena.read(grown, 8), b"ABCD" + bytes(4))
        with self.assertRaises(ValueError):
            self.arena.read(first, 1)
        small = self.arena.realloc(grown, 2)
        self.assertEqual(self.arena.read(small, 2), b"AB")
        self.assertEqual(self.arena.realloc(small, 0), 0)
        self.arena.free(0)
        with self.assertRaises(ValueError):
            self.arena.free(small)

    def test_budget_failure_preserves_old_allocation(self):
        pointer = self.arena.alloc(40)
        self.arena.write(pointer, b"kept")
        with self.assertRaises(MemoryError):
            self.arena.realloc(pointer, 65)
        self.assertEqual(self.arena.read(pointer, 4), b"kept")
        with self.assertRaises(MemoryError):
            self.arena.alloc(25)
        self.arena.free(pointer)
        self.assertGreater(self.arena.alloc(64), pointer)

    def test_realloc_release_fault_rolls_back_new_backing(self):
        from unittest.mock import patch

        pointer = self.arena.alloc(40)
        self.arena.write(pointer, b"kept")
        with (
            patch.object(
                self.arena, "free", side_effect=MemoryError("Authored release fault")
            ),
            self.assertRaises(MemoryError),
        ):
            self.arena.realloc(pointer, 48)
        self.assertEqual(self.arena.read(pointer, 4), b"kept")
        self.arena.alloc(24)

    def test_borrow_is_live_fixed_size_and_pins_allocation(self):
        pointer = self.arena.alloc(8)
        with self.arena.borrow(pointer) as live:
            self.assertIs(type(live), bytearray)
            live[1:3] = b"xy"
            self.assertEqual(self.arena.read(pointer + 1, 2), b"xy")
            self.arena.write(pointer + 4, b"Z")
            self.assertEqual(live[4], ord("Z"))
            with self.arena.borrow(pointer) as second:
                self.assertIs(second, live)
            for operation in (
                lambda: self.arena.free(pointer),
                lambda: self.arena.realloc(pointer, 16),
                self.arena.close,
            ):
                with self.assertRaises(BufferError):
                    operation()
            with self.assertRaises(BufferError):
                live.append(0)
        self.arena.free(pointer)
        with self.assertRaises(ValueError), self.arena.borrow(pointer):
            self.fail("Freed pointer was borrowed")

    def test_source_owner_and_cross_arena_isolation(self):
        self.arena.assert_owner(SHA, self.owner)
        for source, owner in (("0" * 64, self.owner), (SHA, object())):
            with self.assertRaises(ValueError):
                self.arena.assert_owner(source, owner)
        other = NativeMemoryArena(SHA, object(), limit=64)
        pointer = self.arena.alloc(4)
        other_pointer = other.alloc(4)
        self.assertNotEqual(pointer, other_pointer)
        with self.assertRaises(ValueError):
            other.read(pointer, 1)

    def test_invalid_types_addresses_and_lengths(self):
        pointer = self.arena.alloc(4)
        for size in (0, -1, True, 1 << 32):
            with self.subTest(size=size), self.assertRaises(ValueError):
                self.arena.alloc(size)
        for address in (True, -1, 1 << 32):
            with self.subTest(address=address), self.assertRaises(ValueError):
                self.arena.read(address, 1)
        with self.assertRaises(ValueError):
            self.arena.realloc(pointer + 1, 4)
        with self.assertRaises(ValueError), self.arena.borrow(pointer + 1):
            self.fail("Interior bytearray borrow must not copy")
        with self.assertRaises(TypeError):
            self.arena.write(pointer, "secret")  # pyright: ignore[reportArgumentType]

    def test_escaped_python_view_cannot_corrupt_free_bookkeeping(self):
        pointer = self.arena.alloc(8)
        with self.arena.borrow(pointer) as data:
            view = memoryview(data)
            data[:] = b"private!"
        self.arena.free(pointer)
        self.assertEqual(bytes(view), bytes(8))
        view.release()
        self.assertGreater(self.arena.alloc(64), pointer)

    def test_address_and_block_budget_exhaustion(self):
        from unittest.mock import patch

        with (
            patch("scripts.native_memory._next_address", 0xFFFFFFF0),
            self.assertRaises(MemoryError),
        ):
            self.arena.alloc(32)
        arena = NativeMemoryArena(SHA, self.owner)
        for _ in range(4096):
            arena.alloc(1)
        with self.assertRaises(MemoryError):
            arena.alloc(1)
        arena.close()

    def test_cancellation_fault_and_close(self):
        stopped = False
        arena = NativeMemoryArena(SHA, self.owner, cancelled=lambda: stopped)
        pointer = arena.alloc(4)
        arena.write(pointer, b"safe")
        stopped = True
        for action in (
            lambda: arena.alloc(4),
            lambda: arena.realloc(pointer, 8),
            lambda: arena.write(pointer, b"lost"),
            lambda: arena.read(pointer, 4),
        ):
            with self.assertRaises(InterruptedError):
                action()
        # Releasing resources is still possible after cancellation.
        arena.free(pointer)
        arena.close()
        stopped = False
        with self.assertRaises(ValueError):
            arena.alloc(4)


class NativeReceiverProjectionTests(unittest.TestCase):
    def setUp(self):
        # Authored lifetime fixture only; no business operation is substituted.
        self.context = SimpleNamespace(module_sha256=SHA, native_memory=None)
        self.context.native_memory_owner = self.context
        self.arena = NativeMemoryArena(SHA, self.context)
        self.context.native_memory = self.arena
        self.worker = SimpleNamespace(running=False)
        self.binding = object.__new__(NativeProcedureLibraries)
        self.binding.caller_sha256 = (
            "d9fc5bb2f9d7bd583a9fbe317c3d45a2ed4eb60b210ea9623a8230f3baec1e8d"
        )
        self.binding.engine = cast(
            UtilityExEngine, SimpleNamespace(context=self.context, worker=self.worker)
        )

    def test_source_fixed_awd_initializer_and_nested_destructor(self):
        receiver = self.binding.create_awd04_receiver()
        self.assertEqual(receiver.buffer, bytes(0x30))
        nested = self.arena.alloc(12)
        self.arena.write(nested, b"native bytes")
        receiver.buffer[0x24:0x28] = nested.to_bytes(4, "little")
        with self.assertRaises(BufferError):
            self.arena.free(receiver.address)
        receiver.close()
        receiver.close()
        for address in (receiver.address, nested):
            with self.assertRaises(ValueError):
                self.arena.read(address, 1)
        with self.assertRaises(ValueError):
            _ = receiver.buffer

    def test_running_worker_retains_pin_until_explicit_safe_release(self):
        receiver = self.binding.create_awd04_receiver()
        self.worker.running = True
        with self.assertRaises(BufferError):
            receiver.close()
        with self.assertRaises(BufferError):
            self.arena.free(receiver.address)
        self.worker.running = False
        receiver.close()
        self.arena.close()

    def test_changed_source_owner_arena_and_corrupt_nested_pointer_fail_closed(self):
        receiver = self.binding.create_awd04_receiver()
        self.context.native_memory = NativeMemoryArena(SHA, self.context)
        with self.assertRaises(ValueError):
            _ = receiver.buffer
        self.context.native_memory = self.arena
        receiver.buffer[0x24:0x28] = receiver.address.to_bytes(4, "little")
        with self.assertRaises(ValueError):
            receiver.close()
        receiver.buffer[0x24:0x28] = bytes(4)
        receiver.close()
        self.binding.caller_sha256 = "0" * 64
        with self.assertRaises(LookupError):
            self.binding.create_awd04_receiver()
        wrong = NativeMemoryArena(SHA, object())
        self.context.native_memory = wrong
        with self.assertRaises(ValueError):
            self.binding.borrow_receiver(wrong, wrong.alloc(4))

    def test_cancellation_still_releases_owned_receiver_and_nested_allocation(self):
        stopped = False
        self.arena.cancelled = lambda: stopped
        receiver = self.binding.create_awd04_receiver()
        nested = self.arena.alloc(4)
        receiver.buffer[0x24:0x28] = nested.to_bytes(4, "little")
        stopped = True
        receiver.close()
        self.arena.close()

    def test_tpw_native_descriptor_masks_and_destructor(self):
        receiver = self.binding.create_tpw03_receiver()
        self.assertEqual(len(receiver.buffer), 0xC4)
        masks = (b"\xe0", *(b"\x0f\xff\xff\xff",) * 5, b"\xff" * 5, b"\xff" * 5)
        pointers = []
        for index, mask in enumerate(masks):
            offset = 0x24 + index * 0x14
            identifier = (6, 15, 16, 17, 18, 19, 54, 54)[index]
            self.assertEqual(receiver.buffer[offset], identifier)
            self.assertEqual(receiver.buffer[offset + 1], 2 if 1 <= index <= 5 else 0)
            pointer = int.from_bytes(receiver.buffer[offset + 4 : offset + 8], "little")
            pointers.append(pointer)
            self.assertEqual(self.arena.read(pointer, len(mask)), mask)
            self.assertEqual(
                receiver.buffer[offset + 8 : offset + 12],
                len(mask).to_bytes(4, "little"),
            )
            self.assertEqual(receiver.buffer[offset + 12 : offset + 20], bytes(8))
        self.assertEqual(len(set(pointers)), 8)
        receiver.close()
        for pointer in pointers:
            with self.assertRaises(ValueError):
                self.arena.read(pointer, 1)

    def test_tpw_allocation_fault_rolls_back_partial_masks(self):
        self.arena = NativeMemoryArena(SHA, self.context, limit=200)
        self.context.native_memory = self.arena
        with self.assertRaises(MemoryError):
            self.binding.create_tpw03_receiver()
        self.arena.alloc(200)

    @staticmethod
    def history_file(payload):
        # Literal native nibble alphabet, not hexadecimal text.
        alphabet = bytes(
            (
                0x20,
                0x24,
                0x28,
                0x2C,
                0x30,
                0x34,
                0x38,
                0x3C,
                0x40,
                0x44,
                0x48,
                0x4C,
                0x50,
                0x54,
                0x58,
                0x5C,
            )
        )
        encoded = bytes(
            c for value in payload for c in (alphabet[value >> 4], alphabet[value & 15])
        )
        return len(payload).to_bytes(4, "little") + encoded

    def test_4wd_source_file_decoder_metadata_and_pointer(self):
        payload = bytes(range(32)) + bytes(range(256))
        receiver = self.binding.create_4wd05_receiver(self.history_file(payload))
        self.assertEqual(receiver.buffer[8:24], payload[:16])
        self.assertEqual(receiver.buffer[0x1C:0x2C], payload[16:32])
        self.assertEqual(receiver.buffer[0x18:0x1C], (16).to_bytes(4, "little"))
        self.assertEqual(receiver.buffer[0x2C:0x30], (16).to_bytes(4, "little"))
        pointer = int.from_bytes(receiver.buffer[0x50:0x54], "little")
        self.assertEqual(receiver.buffer[0x54:0x56], (256).to_bytes(2, "little"))
        self.assertEqual(self.arena.read(pointer, 256), bytes(range(256)))
        receiver.close()
        with self.assertRaises(ValueError):
            self.arena.read(pointer, 1)
        with self.binding.create_4wd05_receiver(self.history_file(bytes(32))) as empty:
            self.assertEqual(empty.buffer, bytes(0x58))
        for data in (
            bytes(67),
            self.history_file(bytes(32)) + b"x",
            (65568).to_bytes(4, "little") + bytes(64),
        ):
            with self.assertRaises(ValueError):
                self.binding.create_4wd05_receiver(data)

    def test_exact_private_native_caller_method_and_initializer_bytes(self):
        root = Path(__file__).resolve().parents[1]
        path = (
            root
            / "artifacts/extracted/techstream-18-application/Techstream_Bin_Util_ImmoON/IT3UtilityTY.dll"
        )
        if not path.exists():
            self.skipTest("Optional original18 native caller unavailable")
        data = path.read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(), self.binding.caller_sha256)
        pe = struct.unpack_from("<I", data, 0x3C)[0]
        section = pe + 24 + struct.unpack_from("<H", data, pe + 20)[0]
        _, virtual, _, raw = struct.unpack_from("<IIII", data, section + 8)
        self.assertEqual((virtual, raw), (0x1000, 0x1000))
        packet = (
            root / "analysis/evidence/no-car-142/native-pointer-caller-bindings.json"
        )
        if packet.exists():
            for row in json.loads(packet.read_text())["rows"]:
                code = bytes.fromhex(row["instruction_hex"])
                start = row["method_rva"]
                self.assertEqual(data[start : start + len(code)], code)
        zeroing = bytes.fromhex("b90c00000033c08dbee8000000684dfe0000f3ab")
        self.assertEqual(data[0x9971E : 0x9971E + len(zeroing)], zeroing)
        self.assertEqual(data[0x99693:0x99699], bytes.fromhex("8b860c010000"))


class NativePointerWireIntegrationTests(unittest.TestCase):
    def binding(self, *, fault=False, cancel=False, profile="history", mode=20):
        root = Path(__file__).resolve().parents[1]
        caller = (
            root
            / "artifacts/extracted/techstream-18-application/Techstream_Bin_Util_ImmoON/IT3UtilityTY.dll"
        )
        target = (
            root
            / "artifacts/extracted/techstream-18-application/Techstream_Bin/UtilityEx2TY.dll"
        )
        if not caller.exists() or not target.exists():
            self.skipTest("Optional exact native caller/engine source pair unavailable")
        writes, events = [], []
        pending = []
        context = None

        def primitive(*args):
            return PrimitiveResult()

        def connect(protocol, flags, output):
            events.append(("connect", protocol, flags))
            output[:] = (42).to_bytes(4, "little")
            return PrimitiveResult()

        def filter_start(channel, kind, mask, pattern, flow, output):
            output[:] = (51 + kind).to_bytes(4, "little")
            return PrimitiveResult()

        def write(channel, messages, count, timeout):
            request = messages[0].data
            writes.append(request)
            body = request[4:]
            if body[:1] == b"\x10":
                reply = bytes((0x50, body[1]))
            elif body[:1] == b"\x2e":
                reply = b"\x6e" + body[1:3]
            elif profile == "AWD" and body == b"\x22\x01\x01":
                reply = b"\x62\x01\x01" + bytes(32)
            elif profile == "AWD" and body[:2] == b"\x22\x22":
                reply = (
                    b"\x62" + body[1:3] + (b"ab" if body[2] == 1 else b"cde")
                    if body[2] in (1, 2)
                    else b"\x7f\x22\x31"
                )
            elif profile == "replay" and body == b"\xab\x01":
                reply = b"\xeb\x01"
            elif profile == "replay" and body == b"\x22\x20\x02":
                reply = b"\x62\x20\x02" + bytes(16)
            elif profile == "TPW" and body[:1] == b"\xa8":
                descriptors = (
                    (
                        (6, b"\xe0"),
                        *((i, b"\0\0\x0f\xff\xff\xff") for i in range(15, 20)),
                        (54, b"\xff" * 5),
                    )
                    if body[1] == 1
                    else ((54, b"\xff" * 5),)
                )
                reply = (
                    b"\xe8"
                    + body[1:]
                    + b"".join(bytes((i, len(mask))) + mask for i, mask in descriptors)
                )
                pending.extend(((body, reply), (body, None)))
                return PrimitiveResult()
            elif profile == "TPW" and body[:1] == b"\x21":
                payload = (
                    b"\0"
                    if body[1] == 6
                    else bytes(range(1, 6))
                    if body[1] == 54
                    else b"abcd"
                )
                reply = b"\x61" + body[1:] + payload
            elif profile == "TPW" and body[:2] == b"\x3b\x36":
                reply = b"\x7b\x36"
            else:
                raise AssertionError(f"Unexpected native wire request {body.hex()}")
            pending.append((body, reply))
            return PrimitiveResult()

        def read(channel, messages, count, timeout):
            request, reply = pending.pop(0)
            if reply is None:
                return PrimitiveResult(9)
            if request[:1] == b"\x2e":
                if fault:
                    raise OSError("Authored raw SDK receive failure")
                if cancel:
                    assert context is not None
                    context._cancel.set()
            messages[0] = NativeMessage(6, b"\0\0\x07\xe8" + reply)
            return PrimitiveResult()

        def disconnect(channel):
            events.append(("disconnect", channel))
            return PrimitiveResult()

        class Host:
            tick = 0

            def get_parameter(self, key):
                return {
                    0x6F: mode,
                    0x70: 0x12,
                    0x74: 0x7E0,
                    0xD3: 0xFFFFFFFF,
                    0xDD: 0xFFFFFFFF,
                }.get(key, 0)

            def get_data_size(self, key):
                return 8 if key == 500 else 0

            def get_data(self, key):
                return (
                    (1).to_bytes(4, "little") + (500000).to_bytes(4, "little")
                    if key == 500
                    else b""
                )

            def set_parameter(self, key, value):
                return 0

            def write_parameters(self):
                return 0

            def ticks(self):
                self.tick += 1
                return self.tick

            def sleep(self, milliseconds):
                self.tick += milliseconds

        exports: dict[str, Callable[..., object]] = dict.fromkeys(
            _DRIVER_SLOTS.values(), primitive
        )
        exports.update(
            PassThruConnect=connect,
            PassThruStartMsgFilter=filter_start,
            PassThruWriteMsgs=write,
            PassThruReadMsgs=read,
            PassThruDisconnect=disconnect,
        )
        context = UtilityExContext(
            target.read_bytes(), Host(), None, None, driver_exports=exports
        )
        context.native_memory = NativeMemoryArena(
            SHA, context, cancelled=context.is_cancelled
        )
        return (
            NativeProcedureLibraries(caller.read_bytes(), UtilityExEngine(context)),
            writes,
            events,
        )

    def test_actual_native_file_receiver_to_engine_to_typed_sdk_wire(self):
        binding, writes, events = self.binding()
        payload = bytes(32) + bytes.fromhex("20020200616220030000")
        receiver = binding.create_4wd05_receiver(
            NativeReceiverProjectionTests.history_file(payload)
        )
        try:
            self.assertEqual(receiver.call_method(0x9A470), 15)
            self.assertEqual(binding.engine.worker.get_status(), 0)
            self.assertEqual(
                [value[4:] for value in writes],
                [
                    bytes.fromhex(value)
                    for value in ("1001", "1003", "2e20026162", "2e2003", "1001")
                ],
            )
            self.assertEqual(events[0], ("connect", 6, 0))
            self.assertEqual(events[-1], ("disconnect", 42))
        finally:
            binding.engine.worker.stop(1000)
            receiver.close()

    def test_actual_4wd_replay_action_consumes_same_file_history_pointer(self):
        binding, writes, events = self.binding(profile="replay")
        payload = bytes(32) + bytes.fromhex("20020200616220030000")
        receiver = binding.create_4wd05_receiver(
            NativeReceiverProjectionTests.history_file(payload)
        )
        receiver.buffer[0:2] = b"\x04\x01"
        receiver.buffer[4:8] = (8).to_bytes(4, "little")
        try:
            self.assertEqual(receiver.call_method(0x9A450), 15)
            self.assertEqual(binding.engine.worker.get_status(), 8008)
            requests = [value[4:] for value in writes]
            self.assertEqual(
                requests,
                [
                    bytes.fromhex(v)
                    for v in (
                        "1001",
                        "1003",
                        "2e2002" + "00" * 16,
                        "2e20026162",
                        "2e2003",
                        "ab01",
                        "222002",
                        "1001",
                    )
                ],
            )
            self.assertEqual(events[-1], ("disconnect", 42))
        finally:
            binding.engine.worker.stop(1000)
            receiver.close()

    def test_actual_awd_native_history_allocation_and_owned_cleanup(self):
        binding, writes, events = self.binding(profile="AWD")
        receiver = binding.create_awd04_receiver()
        memory = binding.engine.context.native_memory
        assert memory is not None
        try:
            self.assertEqual(receiver.call_method(0x99700), 15)
            self.assertEqual(binding.engine.worker.get_status(), 1023)
            pointer = int.from_bytes(receiver.buffer[0x24:0x28], "little")
            self.assertEqual(receiver.buffer[0x20:0x24], (13).to_bytes(4, "little"))
            self.assertEqual(
                memory.read(pointer, 13), bytes.fromhex("22010200616222020300636465")
            )
            requests = [value[4:] for value in writes]
            self.assertEqual(
                requests[:3], [bytes.fromhex(v) for v in ("1001", "1003", "220101")]
            )
            self.assertEqual(
                [value for value in requests if value[:2] == b"\x22\x22"],
                [bytes((0x22, 0x22, n if n < 10 else n + 6)) for n in range(1, 28)],
            )
            self.assertEqual(events[-1], ("disconnect", 42))
        finally:
            binding.engine.worker.stop(1000)
            receiver.close()
        with self.assertRaises(ValueError):
            memory.read(pointer, 1)

    def test_actual_tpw_nested_mask_support_read_and_write(self):
        binding, writes, events = self.binding(profile="TPW", mode=4)
        receiver = binding.create_tpw03_receiver()
        try:
            for action in (0, 1, 2):
                receiver.buffer[0x20:0x24] = action.to_bytes(4, "little")
                self.assertEqual(receiver.call_method(0x57EC0), 15)
                self.assertEqual(binding.engine.worker.get_status(), 0)
            self.assertEqual(receiver.buffer[0x1C:0x20], (5).to_bytes(4, "little"))
            self.assertEqual(
                [receiver.buffer[4 + 5 * i] for i in range(5)], [1, 2, 3, 4, 5]
            )
            requests = [value[4:] for value in writes]
            self.assertEqual(
                requests,
                [
                    bytes.fromhex(v)
                    for v in (
                        "a801",
                        "a803",
                        "2106",
                        "210f",
                        "2110",
                        "2111",
                        "2112",
                        "2113",
                        "2136",
                        "3b360102030405",
                    )
                ],
            )
            self.assertEqual(events[-1], ("disconnect", 42))
        finally:
            binding.engine.worker.stop(1000)
            receiver.close()

    def test_actual_native_malformed_nested_span_fails_before_history_wire(self):
        binding, writes, events = self.binding()
        payload = bytes(32) + bytes.fromhex("20020200616220030000")
        receiver = binding.create_4wd05_receiver(
            NativeReceiverProjectionTests.history_file(payload)
        )
        pointer = receiver.buffer[0x50:0x54]
        receiver.buffer[0x50:0x54] = (int.from_bytes(pointer, "little") + 1).to_bytes(
            4, "little"
        )
        try:
            self.assertEqual(receiver.call_method(0x9A470), 15)
            with self.assertRaises(ValueError):
                binding.engine.worker.get_status()
            self.assertFalse(any(value[4:5] == b"\x2e" for value in writes))
            self.assertEqual(events[-1], ("disconnect", 42))
        finally:
            binding.engine.worker.stop(1000)
            receiver.buffer[0x50:0x54] = pointer
            receiver.close()

    def test_actual_native_pointer_cancel_and_sdk_fault_are_not_success(self):
        for fault, cancel, error in (
            (True, False, OSError),
            (False, True, InterruptedError),
        ):
            with self.subTest(fault=fault, cancel=cancel):
                binding, writes, events = self.binding(fault=fault, cancel=cancel)
                payload = bytes(32) + bytes.fromhex("20020200616220030000")
                receiver = binding.create_4wd05_receiver(
                    NativeReceiverProjectionTests.history_file(payload)
                )
                try:
                    self.assertEqual(receiver.call_method(0x9A470), 15)
                    with self.assertRaises(error):
                        binding.engine.worker.get_status()
                    self.assertIn(bytes.fromhex("000007e02e20026162"), writes)
                    self.assertNotIn(bytes.fromhex("000007e02e2003"), writes)
                    self.assertEqual(events[-1], ("disconnect", 42))
                finally:
                    binding.engine.worker.stop(1000)
                    receiver.close()


if __name__ == "__main__":
    unittest.main()
