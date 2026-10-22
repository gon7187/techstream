"""Authored CSDF fixtures: no original Toyota program or DLL is required."""

import hashlib
import json
import struct
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.script_libraries import (
    _TY2_METHODS,
    CommunicationOptions,
    ExchangeResult,
    NativeProcedureLibraries,
    ScriptLibraries,
    SequenceError,
    pack_replies,
)
from scripts.script_vm import LibraryContext, ScriptObject, Step, evaluate


class LibraryTests(unittest.TestCase):
    def setUp(self):
        self.requests = []

        def exchange(ecu, request):
            self.requests.append((ecu, request))
            return b"\x61\x02\xaa\xbb"

        self.host = ScriptLibraries(exchange, ecu="engine", ecu_id=3)

    def call(self, library, identifier, values=(), *, argc=None, variables=None):
        context = LibraryContext(list(values), variables or [None] * 3, 0, 4096)
        self.host.libraries[library][identifier](
            context, len(values) if argc is None else argc
        )
        context.check()
        return context

    def test_all_observed_identifiers_are_bound(self):
        self.assertEqual(
            set(self.host.libraries[b"ScriptLibCommunication"]), set(range(1, 12))
        )
        self.assertEqual(set(self.host.libraries[b"ScriptLibLang"]), {1, 2})
        for name in (b"ScriptLibDebug", b"ScriptLibSystem", b"ScriptLibRMLib"):
            self.assertEqual(set(self.host.libraries[name]), {1})

    def test_send_stores_reply_and_returns_real_status(self):
        c = self.call(
            b"ScriptLibCommunication", 1, [(3, b"\x21\x02"), (4, b"\x01\x80")]
        )
        self.assertEqual(c.variables[1], (3, b"\x61\x02\xaa\xbb"))
        self.assertEqual(c.stack, [(1, b"\0")])
        self.assertEqual(self.requests, [("engine", b"\x21\x02")])

    def test_send_error_mapping_and_cleared_storage(self):
        for native, expected in ((0, 0), (8, 1), (9, 2), (10, 3), (99, 4), (0x3101, 5)):

            def exchange(ecu, request, native=native):
                raise SequenceError(native)

            self.host = ScriptLibraries(exchange, ecu="engine", ecu_id=3)
            c = self.call(b"ScriptLibCommunication", 1, [(3, b"x"), (4, b"\0\x80")])
            self.assertEqual(c.stack, [(1, bytes([expected]))])
            self.assertEqual(c.variables[0], (3, b""))

    def test_setters_return_previous_value(self):
        for identifier, new, old in ((7, 4, 2), (7, 1, 4), (10, 1, 0), (10, 2, 1)):
            c = self.call(b"ScriptLibCommunication", identifier, [(1, bytes([new]))])
            self.assertEqual(c.stack, [(1, bytes([old]))])
        self.assertFalse(self.host.address_type)

    def test_ecu_identity_and_support_bits(self):
        self.assertEqual(self.call(b"ScriptLibCommunication", 3).stack, [(1, b"\x03")])
        for pid, expected in ((1, 1), (2, 0), (8, 1), (9, 1), (0, 1)):
            c = self.call(
                b"ScriptLibCommunication", 2, [(1, bytes([pid])), (3, b"\x81")]
            )
            self.assertEqual(c.stack, [(1, bytes([expected]))])

    def test_native_length_and_extract_use_u8_arguments(self):
        self.assertEqual(
            self.call(b"ScriptLibLang", 2, [(3, bytes(256))]).stack, [(1, b"\0")]
        )
        self.assertEqual(
            self.call(
                b"ScriptLibLang", 1, [(3, b"abcdef"), (1, b"\x02"), (1, b"\x03")]
            ).stack,
            [(3, b"cde")],
        )
        self.assertEqual(
            self.call(b"ScriptLibLang", 1, [(3, b"abcdef"), (1, b"\x02")]).stack,
            [(3, b"cdef")],
        )
        self.assertEqual(
            self.call(
                b"ScriptLibLang", 1, [(3, b"abc"), (1, b"\x03"), (1, b"\x02")]
            ).stack,
            [(3, b"")],
        )

    def test_plural_reply_framing_and_zero_based_extract(self):
        self.host = ScriptLibraries(
            lambda e, r: b"unused",
            ecu="engine",
            ecu_id=3,
            plural_exchange=lambda e, r: (b"first", b"second"),
        )
        c = self.call(b"ScriptLibCommunication", 5, [(3, b"x"), (4, b"\0\x80")])
        self.assertEqual(c.variables[0], (3, pack_replies((b"first", b"second"))))
        c = self.call(b"ScriptLibCommunication", 6, [(1, b"\x01"), c.variables[0]])
        self.assertEqual(c.stack, [(3, b"second")])

    def test_support_tlvs_and_fillzero_cache(self):
        framed = pack_replies((b"\x61\0\x02\x02\x80\x40\x03\x01\xff",))
        c = self.call(b"ScriptLibCommunication", 8, [(1, b"\x02"), (3, framed)])
        self.assertEqual(c.stack, [(3, b"\x80\x40")])
        c = self.call(
            b"ScriptLibCommunication",
            4,
            [(1, b"\x02"), (3, b"\xaa\xbb"), (3, b"\x01\0\x01")],
        )
        self.assertEqual(c.stack, [(3, b"\xaa\0\xbb")])
        self.assertEqual(self.host.pid_data[2], b"\xaa\0\xbb")

    def test_did_ranges_respect_zero_low_byte_wildcard(self):
        self.host.did_ranges = ((0x1205, 0x12F0),)
        for did, expected in (
            (b"\x12\0", 1),
            (b"\x12\x04", 0),
            (b"\x12\x05", 1),
            (b"\x12\xf1", 0),
        ):
            c = self.call(b"ScriptLibCommunication", 11, [(3, did)])
            self.assertEqual(c.stack, [(1, bytes([expected]))])

    def test_record_reader_uses_one_based_length_prefixed_records(self):
        self.host.read_record = lambda name: b"\x03one\x03two"
        self.assertEqual(
            self.call(b"ScriptLibRMLib", 1, [(2, b"table"), (1, b"\x02")]).stack,
            [(3, b"two")],
        )
        self.assertEqual(
            self.call(b"ScriptLibRMLib", 1, [(2, b"table"), (1, b"\x03")]).stack,
            [(3, b"")],
        )

    def test_record_source_c_string_and_missing_file(self):
        names = []

        def read_record(name):
            names.append(name)
            raise FileNotFoundError(name)

        self.host.read_record = read_record
        c = self.call(b"ScriptLibRMLib", 1, [(2, b"table\0"), (1, b"\x01")])
        self.assertEqual(names, [b"table"])
        self.assertEqual(c.stack, [(3, b"")])

    def test_native_exchange_receives_exact_options_and_timeout_is_checked(self):
        calls = []

        def native(ecu, request, options):
            calls.append((ecu, request, options))
            return ExchangeResult(9, ())

        self.host.native_exchange = native
        c = self.call(b"ScriptLibCommunication", 5, [(3, b"x")])
        self.assertEqual(c.stack, [(1, b"\x02")])
        self.assertEqual(
            calls, [("engine", b"x", CommunicationOptions(2, False, True))]
        )
        self.host.deadline, self.host.clock = 10, lambda: 10
        with self.assertRaises(TimeoutError):
            self.call(b"ScriptLibCommunication", 3)

    def test_retained_state_is_bounded_before_hex_allocation(self):
        self.host.exchange = lambda ecu, request: bytes(9 * 1024 * 1024)
        with self.assertRaisesRegex(ValueError, "aggregate byte budget"):
            self.call(b"ScriptLibCommunication", 1, [(3, b"x")])
        self.assertEqual(self.host.log_messages, [])

    def test_cpu_scans_observe_cancellation(self):
        checks = 0

        def cancelled():
            nonlocal checks
            checks += 1
            return checks >= 3

        self.host.cancelled = cancelled
        table = b"\xe8\x01" + b"\x01\0" * 600
        with self.assertRaises(InterruptedError):
            self.call(
                b"ScriptLibCommunication",
                8,
                [(1, b"\xff"), (3, pack_replies((table,)))],
            )

    def test_cancellation_after_exchange_prevents_success(self):
        stopped = False

        def exchange(ecu, request):
            nonlocal stopped
            stopped = True
            return b"reply"

        self.host.exchange = exchange
        self.host.cancelled = lambda: stopped
        with self.assertRaises(InterruptedError):
            self.call(b"ScriptLibCommunication", 1, [(3, b"x")])
        self.assertEqual(self.host.log_messages, [])

    def test_support_tlv_may_cross_native_cursor_fence(self):
        # Authored example: selected last TLV extends one byte beyond the fence.
        c = self.call(
            b"ScriptLibCommunication",
            8,
            [(1, b"\x02"), (3, b"\x05\0\xe8\x01\x02\x02ab")],
        )
        self.assertEqual(c.stack, [(3, b"ab")])

    def test_debug_and_post_message_deliver_host_events(self):
        self.call(b"ScriptLibDebug", 1, [(3, b"a"), (1, b"b")])
        self.call(b"ScriptLibSystem", 1, [(1, b"\x07")])
        self.assertEqual(
            self.host.events[0]["values"],
            [{"tag": 3, "hex": "61"}, {"tag": 1, "hex": "62"}],
        )
        self.assertEqual(self.host.events[1]["wparam"], 7)

    def test_log_fillzero_changes_last_reply_and_preserves_tail(self):
        self.call(b"ScriptLibCommunication", 1, [(3, b"\x21\x02")])
        c = self.call(b"ScriptLibCommunication", 9, [(3, b"\x01\0\x01"), (1, b"\x21")])
        self.assertEqual(self.host.log_messages[-1]["response_hex"], "6102aa00bb")
        self.assertEqual(c.stack, [(1, b"\0")])

    def test_vm_dispatch_authored_program(self):
        s = ScriptObject(
            1,
            (),
            (b"ScriptLibCommunication",),
            (
                Step(0, 0x13, b"\x21\x02"),
                Step(0, 0x15, b"\0\x80"),
                Step(0, 0x40, b"\x01\0\x02"),
                Step(0, 0x44, b""),
            ),
        )
        self.assertEqual(evaluate(s, libraries=self.host.libraries), ((1, b"\0"),))

    def test_invalid_args_frames_dependencies_and_limits(self):
        with self.assertRaises(ValueError):
            self.call(b"ScriptLibCommunication", 1, [(3, b"x"), (1, b"\0")])
        with self.assertRaises(ValueError):
            self.call(b"ScriptLibLang", 1, [(3, b"abc")])
        for identifier, values in (
            (2, [(1, b"1"), (3, b"")]),
            (6, [(1, b"\0"), (3, b"\x03\0x")]),
            (8, [(1, b"1"), (3, b"\x03\0\x61\0x")]),
            (4, [(1, b"1"), (3, b"x"), (3, b"\x01\x01")]),
        ):
            with self.assertRaises(ValueError):
                self.call(b"ScriptLibCommunication", identifier, values)
        with self.assertRaises(RuntimeError):
            self.call(b"ScriptLibRMLib", 1, [(2, b"table"), (1, b"\1")])
        with self.assertRaises(RuntimeError):
            self.call(b"ScriptLibCommunication", 11, [(3, b"\x12\x34")])
        self.host.cancelled = lambda: True
        with self.assertRaises(InterruptedError):
            self.call(b"ScriptLibCommunication", 3)


class NativeMarshallingTests(unittest.TestCase):
    def setUp(self):
        # Only marshalling is mocked; this fixture claims no business completion.
        self.binding = object.__new__(NativeProcedureLibraries)
        self.binding.caller_sha256 = (
            "ecba533aeaa2ec2a014fa59a113d025a8efe90338767c2786b8a5a891ca0f599"
        )

    def test_all45_native_receiver_bodies_keep_pointer_and_exact_writes(self):
        self.assertEqual(len(_TY2_METHODS), 45)
        for method, (iat, offset) in _TY2_METHODS.items():
            with self.subTest(method=hex(method)):
                data = bytearray(b"\xaa" * max(8, (offset or 0) + 4))
                before = data[:]
                args = () if offset is None else (0xF1234567,)
                with patch.object(self.binding, "invoke_iat", return_value=15) as call:
                    self.assertEqual(self.binding.call_method(method, data, args), 15)
                self.assertEqual(call.call_args.args[0], iat)
                self.assertIs(call.call_args.args[1][0], data)
                if offset is not None:
                    before[offset : offset + 4] = b"\x67\x45\x23\xf1"
                self.assertEqual(data, before)

    def test_bad_source_method_arity_buffer_and_scalar_fail_before_engine(self):
        with patch.object(self.binding, "invoke_iat") as call:
            for method, data, args in (
                (0, bytearray(4), ()),
                (0x384B0, bytearray(4), ()),
                (0x384B0, bytearray(4), (True,)),
                (0x384B0, bytearray(4), (-1,)),
                (0x384B0, bytearray(4), (1 << 32,)),
                (0x1230, bytearray(4), (1,)),
                (0x39050, bytearray(3), ()),
                (0x39050, bytearray(4), (1,)),
            ):
                with (
                    self.subTest(method=method, args=args),
                    self.assertRaises((ValueError, LookupError)),
                ):
                    self.binding.call_method(method, data, args)
            call.assert_not_called()
            self.binding.caller_sha256 = "0" * 64
            with self.assertRaises(LookupError):
                self.binding.call_method(0x39050, bytearray(4))

    def test_native_fault_retains_prior_argument_write(self):
        for error in (
            InterruptedError("cancelled"),
            TimeoutError("deadline"),
            OSError("fault"),
        ):
            data = bytearray(8)
            with (
                patch.object(self.binding, "invoke_iat", side_effect=error),
                self.assertRaises(type(error)),
            ):
                self.binding.call_method(0x384B0, data, (7,))
            self.assertEqual(data, b"\x07" + bytes(7))

    def test_exact_private_image_confirms_each_receiver_instruction_body(self):
        root = Path(__file__).resolve().parents[1]
        path = (
            root
            / "artifacts/extracted/techstream-18-application/Techstream_Bin/IT3UtilityTY2.dll"
        )
        if not path.exists():
            self.skipTest("Optional exact private caller image unavailable")
        data = path.read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(), self.binding.caller_sha256)
        pe = struct.unpack_from("<I", data, 0x3C)[0]
        count, optional = (
            struct.unpack_from("<H", data, pe + 6)[0],
            struct.unpack_from("<H", data, pe + 20)[0],
        )
        sections = []
        for index in range(count):
            start = pe + 24 + optional + index * 40
            size, rva, raw_size, raw = struct.unpack_from("<IIII", data, start + 8)
            sections.append((rva, max(size, raw_size), raw))
        for method, (iat, offset) in _TY2_METHODS.items():
            base, _, raw = next(
                row for row in sections if row[0] <= method < row[0] + row[1]
            )
            if offset is None:
                expected = (
                    bytes.fromhex("81c1e800000051ff15")
                    + struct.pack("<I", 0x10000000 + iat)
                    + b"\xc3"
                )
            elif offset == 0:
                expected = (
                    bytes.fromhex("8d81e80000008b4c2404508908ff15")
                    + struct.pack("<I", 0x10000000 + iat)
                    + bytes.fromhex("c20400")
                )
            else:
                expected = (
                    bytes.fromhex("8b4424048981")
                    + struct.pack("<I", offset + 0xE8)
                    + bytes.fromhex("81c1e800000051ff15")
                    + struct.pack("<I", 0x10000000 + iat)
                    + bytes.fromhex("c20400")
                )
            self.assertEqual(
                data[raw + method - base : raw + method - base + len(expected)],
                expected,
                hex(method),
            )
        packet = root / "analysis/evidence/no-car-83/it3-import-source-bindings.json"
        if packet.exists():
            known = {
                row["iat_rva"]
                for row in json.loads(packet.read_text())["rows"]
                if row["source_sha256"] == self.binding.caller_sha256
            }
            self.assertTrue({iat for iat, _ in _TY2_METHODS.values()} <= known)


if __name__ == "__main__":
    unittest.main()
