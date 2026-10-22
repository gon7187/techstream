"""Authored native-layout fixtures; no OEM files or hardware required."""

import math
import struct
import unittest
from dataclasses import dataclass, replace
from typing import Any, cast
from unittest.mock import patch

from scripts.data_monitor import (
    MonitorDefinitions,
    MonitorRange,
    MonitorSignalMetadata,
    p4_setup_commands,
    pack_p4,
    selected_monitor_buffer,
    selected_p4_monitor,
)
from scripts.drive_recorder import (
    DRS_MAGIC,
    DrsFile,
    DrsTable,
    NativeCoreBuffer,
    NativeCoreString,
    NativeDisplayItem,
    NativeDmciCommand,
    NativeDmciError,
    NativeDmciList,
    NativeDrsError,
    NativeDrsExecutor,
    NativeMessage,
    NativeMonitorBuffer,
    NativeMonitorPacket,
    NativeMonitorPacketReader,
    NativeMonitorRecorder,
    NativeMonitorReply,
    NativeMonitorSignal,
    NativeReadExpectation,
    NativeRecorderCapture,
    NativeRecorderSeries,
    NativeRecorderState,
    NativeSystemTime,
    NativeTransferAcknowledgement,
    NativeTransferFrame,
    NativeTransferSession,
    NativeTriggerComparison,
    NativeTriggerCondition,
    NativeTriggerInfo,
    NativeTriggerParameters,
    NativeTriggerWindow,
    NativeVehicleEntry,
    NativeVehicleSelection,
    NativeVehicleSelector,
    NativeVehicleSession,
    NativeVimClient,
    NativeVimError,
    NativeVimFiles,
    NativeVimReply,
    OnboardRecorderService,
    RecorderCancelled,
    RecorderController,
    RecorderError,
    RecorderPaths,
    UnsupportedRecorderOperation,
    build_native_drs,
    convert_native_trigger_value,
    decode_command,
    decode_vim_command,
    decode_vim_transfer,
    encode_command,
    encode_native_mode21,
    encode_vim_command,
    encode_vim_transfer,
    evaluate_native_comparisons,
    native_mode_exchange_tables,
    native_monitor_buffer,
    native_trigger_sign_value,
    selected_car_info_frames,
    selected_car_info_plan,
    selected_check_mode_frames,
    selected_check_mode_plan,
    selected_session_tables,
    selected_vehicle_context,
    selected_vehicle_vin,
)
from scripts.snapshot import (
    MonitorBuffer,
    decode_signal_item,
    decode_signal_table,
    monitor_packets,
    monitor_samples,
)
from scripts.snapshot import (
    TableFile as SnapshotTableFile,
)
from scripts.snapshot import (
    parse as parse_snapshot,
)
from scripts.toyota_session import Cancelled, SessionError


class NativeDrsTests(unittest.TestCase):
    def test_literal_native_envelope(self):
        data = bytes.fromhex("01000080020003000a00000000020600000000000000")
        parsed = DrsFile.parse(data)
        self.assertEqual((parsed.header_word_1, parsed.header_word_2), (2, 3))
        self.assertEqual(
            parsed.tables, (DrsTable(0x200, bytes.fromhex("0600000000000000")),)
        )
        self.assertEqual(parsed.encode(), data)
        self.assertEqual(
            decode_command(parsed.tables[0]), {"protocol_id": 6, "flags": 0}
        )

    def test_opaque_tables_duplicates_and_order_survive(self):
        doc = DrsFile(0xFFFF, 0, (DrsTable(0xF001, b"\0\xff"), DrsTable(0xF001, b"")))
        self.assertEqual(DrsFile.parse(doc.encode()), doc)
        self.assertEqual(doc.report()["format"], "native-drs")

    def test_every_prefix_is_rejected(self):
        data = DrsFile(0, 0, (DrsTable(0x200, b"12345678"),)).encode()
        # A header alone is a valid empty file; other proper prefixes truncate a table.
        for size in list(range(8)) + list(range(9, len(data))):
            with self.subTest(size=size), self.assertRaises(RecorderError):
                DrsFile.parse(data[:size])

    def test_bad_magic_length_limit_and_unsigned_fields(self):
        for data in (
            struct.pack("<IHH", 0x80000002, 0, 0),
            struct.pack("<IHHIH", DRS_MAGIC, 0, 0, 1, 3),
        ):
            with self.assertRaises(RecorderError):
                DrsFile.parse(data)
        with self.assertRaises(RecorderError):
            DrsFile.parse(DrsFile(0, 0, ()).encode(), max_size=7)
        for value in (-1, 65536, True):
            with self.assertRaises(RecorderError):
                DrsTable(value)

    def test_all_supported_typed_commands_roundtrip(self):
        msg = NativeMessage(6, 0, 0x100, 123, 0, b"\x00\x00\x07\xe0\x21\x01")
        cases = [
            (0x200, {"protocol_id": 6, "flags": 0}),
            (0x203, {"timeout": 500, "message": msg}),
            (0x214, {"message": msg}),
            (0x206, {"filter_type": 3, "messages": (msg, msg, msg)}),
            (0x211, {"parameters": ((1, 10400), (2, 500000))}),
            (3, {"frames": ((0, 8), (255, 4096))}),
            (0x213, {"data": b"\x33", "value_after_data": 0}),
            (
                0x202,
                {
                    "words": (1, 2, 3, 4, 5, 6, 7),
                    "mask_data": b"pattern",
                    "pattern_data": b"flow",
                },
            ),
        ]
        for table_id, fields in cases:
            with self.subTest(table=table_id):
                record = encode_command(table_id, fields)
                self.assertEqual(decode_command(record), fields)
                self.assertEqual(
                    encode_command(table_id, decode_command(record)), record
                )
        self.assertEqual(msg.encode()[:24], struct.pack("<6I", 6, 0, 256, 123, 6, 0))

    def test_empty_records_and_incomplete_layouts(self):
        for table_id in (0x11, 0x12, 0x21, 0x22, 0x23, 0x24, 0x27, 0x201):
            self.assertEqual(decode_command(encode_command(table_id, {})), {})
            with self.assertRaises(RecorderError):
                decode_command(DrsTable(table_id, b"x"))
        for table_id in (0xFFFF,):
            with self.assertRaises(UnsupportedRecorderOperation):
                decode_command(DrsTable(table_id))

    def test_native_read_mask_pattern_layout_and_matching(self):
        expectation = NativeReadExpectation(
            100, (6, 0, 0, 0, 0, 0), b"\xf0\xff", b"\x60\x01"
        )
        data = expectation.encode()
        self.assertEqual(data[:28], struct.pack("<7I", 100, 6, 0, 0, 0, 0, 0))
        self.assertEqual(NativeReadExpectation.parse(data), expectation)
        self.assertEqual(
            decode_command(DrsTable(0x202, data))["mask_data"], b"\xf0\xff"
        )
        self.assertTrue(expectation.matches(NativeMessage(6, 0, 0, 0, 0, b"\x6a\x01")))
        self.assertFalse(expectation.matches(NativeMessage(6, 0, 0, 0, 0, b"\x6a\x02")))
        self.assertFalse(expectation.matches(NativeMessage(6, 1, 0, 0, 0, b"\x6a\x01")))
        self.assertFalse(expectation.matches(NativeMessage(6, 0, 0, 0, 0, b"\x6a")))
        self.assertFalse(expectation.matches(NativeMessage(6, 0, 0, 0, 0, b"")))
        with self.assertRaises(RecorderError):
            NativeReadExpectation.parse(data[:-1])

    def test_shared_native_system_information_in_drs(self):
        system = {
            "identifier": 3,
            "strings": [
                {"core": [1, 0], "data_hex": "4100"},
                {"core": [1, 0], "data_hex": "4200"},
            ],
            "value_raw": 7,
        }
        table = encode_command(0x8100, {"system": system})
        self.assertEqual(decode_command(table), {"system": system})
        self.assertEqual(
            table.payload, bytes.fromhex("03000000010000000200410001000000020042000700")
        )
        for length in range(len(table.payload)):
            with self.assertRaises(RecorderError):
                decode_command(DrsTable(0x8100, table.payload[:length]))

    def test_native_write_start_end_child_table_envelope(self):
        connect = encode_command(0x200, {"protocol_id": 6, "flags": 0})
        container = encode_command(0x21, {"children": (connect,)})
        self.assertEqual(container.payload, connect.encode())
        self.assertEqual(decode_command(container), {"children": (connect,)})
        for length in range(1, len(container.payload)):
            with self.assertRaises(RecorderError):
                decode_command(DrsTable(0x21, container.payload[:length]))
        calls = []

        class Backend:
            def invoke(self, operation, fields, **context):
                calls.append(operation)

        controller = RecorderController(
            Backend(), capabilities=frozenset({"native-drs-execution"})
        )
        unknown = encode_command(0x21, {"children": (DrsTable(0xF001, b"x"),)})
        with self.assertRaises(UnsupportedRecorderOperation):
            controller.execute(DrsFile(2, 0, (connect, unknown)))
        self.assertEqual(calls, [])
        nested = container
        for _ in range(66):
            nested = encode_command(0x21, {"children": (nested,)})
        with self.assertRaises(RecorderError):
            controller.execute(DrsFile(2, 0, (nested,)))
        self.assertEqual(calls, [])

    def test_parser_bound_options_are_validated(self):
        data = DrsFile(2, 0, ()).encode()
        for bounds in (
            {"max_size": -1},
            {"max_size": True},
            {"max_tables": -1},
            {"max_tables": True},
        ):
            with self.assertRaises(RecorderError):
                DrsFile.parse(data, **bounds)
        self.assertEqual(DrsFile.parse(data, max_tables=0).tables, ())

    def test_bad_dynamic_sizes_and_fields(self):
        for table in (
            DrsTable(3, struct.pack("<I", 0xFFFFFFFF)),
            DrsTable(0x213, struct.pack("<I", 0xFFFFFFFF)),
            DrsTable(0x203, b"\0" * 8),
        ):
            with self.assertRaises(RecorderError):
                decode_command(table)
        for table_id, fields in (
            (0x200, {}),
            (0x200, {"protocol_id": True, "flags": 0}),
            (3, {"frames": ((0, 65536),)}),
            (0x206, {"messages": ()}),
            (0x213, {"data": "33"}),
        ):
            with self.assertRaises(RecorderError):
                encode_command(table_id, fields)

    def test_native_trigger_fields_and_session_buffer(self):
        info = NativeTriggerInfo((5, 0), 2, 100, 50)
        self.assertEqual(info.encode(), bytes.fromhex("05000000020064003200"))
        self.assertEqual(NativeTriggerInfo.parse(info.encode()), info)
        condition = NativeTriggerCondition((1, 0), 0x1234, 2, 3500, 100, 1)
        self.assertEqual(NativeTriggerCondition.parse(condition.encode()), condition)
        for parser, data in (
            (NativeTriggerInfo.parse, info.encode()),
            (NativeTriggerCondition.parse, condition.encode()),
        ):
            with self.assertRaises(RecorderError):
                parser(data[:-1])
            with self.assertRaises(RecorderError):
                parser(data + b"\0")
        for table_id in (0x28, 0x29):
            fields = {
                "value_before_buffer": 7,
                "core_words": (2, 0),
                "data": b"\x10\x01",
            }
            table = encode_command(table_id, fields)
            self.assertEqual(
                table.payload, bytes.fromhex("0700000002000000020000001001")
            )
            self.assertEqual(decode_command(table), fields)

    def test_trigger_parameter_file_execution(self):
        condition = NativeTriggerCondition((1, 0), 0x1234, 2, 3500, 100, 1)
        params = NativeTriggerParameters(
            (1, 0), 3, 2, (1, 0), (condition,), (1, 0), ((1, 0, 0x1234),)
        )
        self.assertEqual(NativeTriggerParameters.parse(params.encode()), params)
        words_only = NativeTriggerParameters(
            (1, 0), 1, 2, (1, 0), (), (1, 0), ((1, 0, 0x1234),)
        )
        self.assertEqual(
            words_only.encode(),
            bytes.fromhex("0100000001000200010000000000000001000000010000003412"),
        )
        tables = (
            encode_command(5, {"trigger": NativeTriggerInfo((1, 0), 2, 100, 50)}),
            encode_command(6, {"trigger": params}),
        )
        doc = DrsFile.parse(DrsFile(2, 0, tables).encode())
        backend = FakeBackend()
        controller = RecorderController(
            backend, capabilities=frozenset({"native-drs-execution"})
        )
        controller.execute(doc)
        self.assertEqual(
            [call[0] for call in backend.calls], ["trigger_info", "trigger_parameters"]
        )
        self.assertEqual(backend.calls[1][1]["trigger"], params)
        for data in (
            params.encode()[:-1],
            params.encode() + b"\0",
            bytes.fromhex("010000000300020001000000ffffffff"),
        ):
            with self.assertRaises(RecorderError):
                NativeTriggerParameters.parse(data)

    def test_message_capacity_and_table_count_bound(self):
        with self.assertRaises(RecorderError):
            NativeMessage(6, 0, 0, 0, 0, b"x" * 4129)
        data = DrsFile(2, 0, (DrsTable(0x201), DrsTable(0x201))).encode()
        with self.assertRaises(RecorderError):
            DrsFile.parse(data, max_tables=1)

    def test_native_ini(self):
        text = "[VERSION]\nFileVersion=1.0.0\n[DriveRecord]\nSettingFolder=\\InternalCF\\Data\\DriveRecord\nOutputFolder=\\InternalCF\\Data\\DriveRecord\nMaxFile=20\n"
        result = RecorderPaths.parse(text.encode("utf-16"))
        self.assertEqual(result.max_file, 20)
        self.assertEqual(result.setting_folder, "\\InternalCF\\Data\\DriveRecord")
        for data in (
            b"garbage",
            b"[DriveRecord]\nMaxFile=0",
            text.replace("MaxFile=20", "MaxFile=0").encode(),
        ):
            with self.assertRaises(RecorderError):
                RecorderPaths.parse(data)


class FakeBackend:
    def __init__(self):
        self.calls = []
        self.fail = False
        self.after = lambda: None

    def invoke(self, operation, fields, *, deadline, cancelled):
        self.calls.append((operation, fields))
        if self.fail:
            raise OSError("adapter disconnected")
        self.after()
        return {"native_operation": operation}


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.backend = FakeBackend()
        self.clock = [100.0]
        self.controller = RecorderController(
            self.backend,
            capabilities=frozenset({"native-drs-execution"}),
            clock=lambda: self.clock[0],
        )
        self.settings = DrsFile(
            0,
            0,
            (encode_command(0x200, {"protocol_id": 6, "flags": 0}), DrsTable(0x201)),
        )

    def test_native_file_drives_injected_backend(self):
        parsed = DrsFile.parse(self.settings.encode())
        self.assertEqual(len(self.controller.execute(parsed)), 2)
        self.assertEqual(
            [call[0] for call in self.backend.calls], ["connect", "disconnect"]
        )
        self.assertEqual(self.controller.state, "idle")
        self.assertEqual(self.controller.report()["physical"], "PHYSICAL_UNCONFIRMED")

    def test_jlr_has_no_implied_onboard_recorder(self):
        controller = RecorderController(
            self.backend, capabilities=frozenset({"J2534", "JLR"})
        )
        with self.assertRaises(UnsupportedRecorderOperation):
            controller.execute(self.settings)
        self.assertFalse(self.backend.calls)

    def test_preflight_prevents_partial_actions(self):
        settings = DrsFile(0, 0, self.settings.tables + (DrsTable(0xFFFF),))
        with self.assertRaises(UnsupportedRecorderOperation):
            self.controller.execute(settings)
        self.assertFalse(self.backend.calls)
        self.assertEqual(self.controller.state, "idle")

    def test_failure_latches_fault_until_explicit_recovery(self):
        self.backend.fail = True
        with self.assertRaises(OSError):
            self.controller.execute(self.settings)
        self.assertEqual(self.controller.state, "fault")
        with self.assertRaises(RecorderError):
            self.controller.execute(self.settings)
        self.controller.recover()
        self.assertEqual(self.controller.state, "idle")

    def test_cancel_before_and_after_backend(self):
        with self.assertRaises(RecorderCancelled):
            self.controller.execute(self.settings, cancelled=lambda: True)
        self.assertFalse(self.backend.calls)
        self.controller.recover()
        cancelled = [False]
        self.backend.after = lambda: cancelled.__setitem__(0, True)
        with self.assertRaises(RecorderCancelled):
            self.controller.execute(self.settings, cancelled=lambda: cancelled[0])
        self.assertEqual(len(self.backend.calls), 1)
        self.assertEqual(self.controller.state, "cancelled")

    def test_deadlines_and_invalid_timeout(self):
        for value in (0, -1, float("inf"), float("nan")):
            with self.assertRaises(RecorderError):
                self.controller.execute(self.settings, timeout=value)
        self.backend.after = lambda: self.clock.__setitem__(0, 111.0)
        with self.assertRaises(TimeoutError):
            self.controller.execute(self.settings, timeout=10)
        self.assertEqual(self.controller.state, "fault")
        self.assertEqual(len(self.backend.calls), 1)


class NativeVimPacketTests(unittest.TestCase):
    def test_original_compact_command_encoding_boundaries(self):
        cases = (
            (1, "01"),
            (2, "02"),
            (0x70, "70"),
            (0x7F, "7f00"),
            (0xFF, "ff00"),
            (0xFF7F, "7fff00"),
            (0xFFFFFF7F, "7fffffff"),
        )
        for command, literal in cases:
            with self.subTest(command=command):
                raw = bytes.fromhex(literal)
                self.assertEqual(encode_vim_command(command), raw)
                self.assertEqual(
                    decode_vim_command(raw + b"payload"), (command, b"payload")
                )
                for size in range(len(raw)):
                    with self.assertRaises(RecorderError):
                        decode_vim_command(raw[:size])
        with self.assertRaises(RecorderError):
            encode_vim_command(0x1234)

    def test_native_mode_packets_and_negative_reply(self):
        requests = []
        mode = [4]

        def exchange(request, *, deadline, cancelled):
            requests.append(request)
            command, payload = decode_vim_command(request)
            if command == 1:
                self.assertEqual(payload, b"")
                return NativeVimReply(
                    command | 0x80, 6, struct.pack("<I", mode[0])
                ).encode()
            if command == 2:
                mode[0] = struct.unpack("<I", payload)[0]
                return NativeVimReply(command | 0x80, 6, b"\0" * 4).encode()
            return NativeVimReply(command | 0x80, 0x15, b"", 0x901F0001).encode()

        client = NativeVimClient(
            exchange, capabilities=frozenset({"denso-vim-control"})
        )
        self.assertEqual(client.get_mode(), 4)
        self.assertEqual(client.change_mode(7), 0)
        self.assertEqual(client.get_mode(), 7)
        self.assertEqual(requests[:2], [b"\x01", b"\x02\x07\x00\x00\x00"])
        with self.assertRaises(NativeVimError) as error:
            client.command_execute(b"native-payload")
        self.assertEqual(error.exception.reply.error, 0x901F0001)
        self.assertEqual(requests[-1], b"\x70native-payload")
        for raw in (b"", b"\x01", b"\x01\x15", b"\x01\x15\x01\x00\x00\x00trailing"):
            with self.assertRaises(RecorderError):
                NativeVimReply.parse(raw)

    def test_native_system_and_local_time_packets(self):
        value = NativeSystemTime(2026, 10, 2, 20, 12, 34, 56, 789)
        requests = []
        status = [0]

        def exchange(request, *, deadline, cancelled):
            command, payload = decode_vim_command(request)
            requests.append(request)
            if command in (4, 6):
                self.assertEqual(payload, b"")
                result = struct.pack("<I", status[0]) + value.encode()
            else:
                self.assertEqual(payload, value.encode())
                result = struct.pack("<II", status[0], 1)
            return NativeVimReply(command | 0x80, 6, result).encode()

        client = NativeVimClient(
            exchange, capabilities=frozenset({"denso-vim-control"})
        )
        for local in (False, True):
            self.assertEqual(client.get_time(local=local), value)
            self.assertTrue(client.set_time(value, local=local))
        self.assertEqual([x[0] for x in requests], [4, 5, 6, 7])
        status[0] = 5
        with self.assertRaises(RecorderError):
            client.get_time()
        with self.assertRaises(RecorderError):
            client.set_time(value)
        with self.assertRaises(RecorderError):
            NativeSystemTime.parse(value.encode()[:-1])

    def test_post_io_cancel_and_deadline_cover_fault_paths(self):
        for case in ("nak", "malformed", "exception"):
            for timeout_case in (False, True):
                flag = [False]
                now = [0.0]

                def exchange(
                    request,
                    *,
                    deadline,
                    cancelled,
                    case=case,
                    timeout_case=timeout_case,
                    now=now,
                    flag=flag,
                ):
                    if timeout_case:
                        now[0] = deadline
                    else:
                        flag[0] = True
                    if case == "exception":
                        raise OSError("disconnected")
                    return (
                        b""
                        if case == "malformed"
                        else NativeVimReply(0x81, 0x15, b"", 77).encode()
                    )

                client = NativeVimClient(
                    exchange,
                    capabilities=frozenset({"denso-vim-control"}),
                    clock=lambda now=now: now[0],
                )
                with self.assertRaises(
                    TimeoutError if timeout_case else RecorderCancelled
                ) as error:
                    client.get_mode(cancelled=lambda flag=flag: flag[0])
                self.assertIsNotNone(error.exception.__cause__)

    def test_native_client_capability_cancel_deadline(self):
        calls = []
        now = [10.0]

        def exchange(request, *, deadline, cancelled):
            calls.append(request)
            now[0] = deadline
            return NativeVimReply(0x81, 6, b"\0" * 4).encode()

        client = NativeVimClient(
            exchange, capabilities=frozenset({"JLR"}), clock=lambda: now[0]
        )
        with self.assertRaises(UnsupportedRecorderOperation):
            client.get_mode()
        self.assertFalse(calls)
        client.capabilities = frozenset({"denso-vim-control"})
        with self.assertRaises(RecorderCancelled):
            client.get_mode(cancelled=lambda: True)
        self.assertFalse(calls)
        with self.assertRaises(TimeoutError):
            client.get_mode()


class NativeVimFileTests(unittest.TestCase):
    def setUp(self):
        self.contents = bytearray(b"original-recording")
        self.offset = 0
        self.calls = []
        self.closed = []
        self.fail_read = False
        self.fail_close = False
        self.zero_write = False
        self.cancel_flag = False
        self.cancel_after_read = False
        self.corrupt_count = False
        self.find_index = 0
        self.client = NativeVimClient(
            self.exchange,
            capabilities=frozenset({"denso-vim-control", "denso-vim-files"}),
        )
        self.files = NativeVimFiles(self.client)

    def exchange(self, request, *, deadline, cancelled):
        command, payload = decode_vim_command(request)
        self.calls.append(request)
        if command == 0x21:
            count, version, revision, size = struct.unpack_from("<IHHH", payload)
            self.assertEqual((count, version, revision), (size, 1, 0))
            path = payload[10 : 10 + size].decode("utf-16le")
            self.assertTrue(path.endswith("\0"))
            access, share, creation, flags, template = struct.unpack_from(
                "<5I", payload, 10 + size
            )
            self.assertEqual((share, flags, template), (0, 0x80, 0))
            self.offset = 0
            if creation == 2:
                self.assertEqual(access, 0x40000000)
                self.contents.clear()
            else:
                self.assertEqual((creation, access), (3, 0x80000000))
            result = struct.pack("<I", 19)
        elif command == 0x23:
            handle, size = struct.unpack("<II", payload)
            self.assertEqual(handle, 19)
            if self.fail_read:
                raise OSError("read disconnected")
            data = bytes(self.contents[self.offset : self.offset + size])
            self.offset += len(data)
            result = (
                struct.pack(
                    "<BIHHI", 1, len(data) + int(self.corrupt_count), 1, 0, len(data)
                )
                + data
            )
            if self.cancel_after_read:
                self.cancel_flag = True
        elif command == 0x24:
            handle, count, version, revision, length = struct.unpack_from(
                "<IIHHI", payload
            )
            self.assertEqual(
                (handle, count, version, revision, length),
                (19, len(payload) - 16, 1, 0, len(payload) - 16),
            )
            # Exercise a valid partial native write, not just one full append.
            written = 0 if self.zero_write else min(length, 3)
            self.contents.extend(payload[16 : 16 + written])
            result = struct.pack("<BI", 1, written)
        elif command == 0x2E:
            handle, low, high, origin = struct.unpack("<4I", payload)
            self.assertEqual(handle, 19)
            signed_offset = low | (high << 32)
            if high & 0x80000000:
                signed_offset -= 1 << 64
            self.offset = signed_offset + (
                0 if origin == 0 else self.offset if origin == 1 else len(self.contents)
            )
            result = struct.pack("<Q", self.offset)
        elif command in (0x26, 0x27):
            if command == 0x26:
                length, version, revision, duplicate = struct.unpack_from(
                    "<4H", payload
                )
                self.assertEqual((length, version, revision), (duplicate, 1, 0))
                self.assertTrue(payload[8:].decode("utf-16le").endswith("*.dm\0"))
                self.find_index = 0
            else:
                self.assertEqual(payload, struct.pack("<I", 19))
                self.find_index += 1
            has_entry = self.find_index < 2
            name = (
                (f"trip-{self.find_index:02}.dm\0").encode("utf-16le")
                if has_entry
                else b""
            )
            status = struct.pack("<I", 19) if command == 0x26 else bytes([has_entry])
            result = (
                status
                + struct.pack("<9I", 0x20, 1, 2, 3, 4, 5, 6, 1, 123)
                + struct.pack("<4H", len(name), 1, 0, len(name))
                + name
            )
        elif command == 0x28:
            self.closed.append(struct.unpack("<I", payload)[0])
            result = b"\x01"
        elif command == 0x22:
            self.closed.append(struct.unpack("<I", payload)[0])
            result = bytes([not self.fail_close])
        else:
            raise AssertionError(f"Unexpected native file command {command:#x}")
        return NativeVimReply(command | 0x80, 6, result).encode()

    def test_native_download_and_upload_settings(self):
        self.assertEqual(
            self.files.download("\\InternalCF\\Data\\trip.dm", chunk_size=4),
            b"original-recording",
        )
        self.assertEqual(self.calls[1], bytes.fromhex("231300000004000000"))
        self.assertEqual(self.closed, [19])
        settings = DrsFile(
            2, 0, (encode_command(0x200, {"protocol_id": 6, "flags": 0}),)
        )
        self.assertEqual(
            self.files.upload_settings("trip.drs", settings, chunk_size=7),
            len(settings.encode()),
        )
        self.assertEqual(bytes(self.contents), settings.encode())
        self.assertEqual(self.closed, [19, 19])

    def test_native_list_and_seek(self):
        entries = self.files.list_files("\\InternalCF\\Data\\*.dm")
        self.assertEqual(
            [entry["name"] for entry in entries], ["trip-00.dm", "trip-01.dm"]
        )
        self.assertEqual(entries[0]["size"], (1 << 32) + 123)
        self.assertEqual(self.calls[-1], bytes.fromhex("2813000000"))
        handle = self.files.open("trip.dm")
        self.assertEqual(self.files.seek(handle, 8), 8)
        self.assertEqual(self.files.seek(handle, -3, 1), 5)
        self.assertEqual(self.files.read(handle, 4), b"nal-")
        self.files.close(handle)
        with self.assertRaises(RecorderError):
            self.files.list_files("*.dm", max_entries=1)
        self.assertEqual(self.calls[-1], bytes.fromhex("2813000000"))

    def test_acquisition_cancel_and_deadline_close_new_handle(self):
        original = self.client.exchange
        now = [0.0]
        self.client.clock = lambda: now[0]
        for timeout_case in (False, True):
            for upload in (False, True):
                self.cancel_flag = False
                self.calls.clear()
                self.closed.clear()
                now[0] = 0.0

                def exchange(
                    request, *, deadline, cancelled, timeout_case=timeout_case
                ):
                    reply = original(request, deadline=deadline, cancelled=cancelled)
                    if decode_vim_command(request)[0] == 0x21:
                        if timeout_case:
                            now[0] = deadline
                        else:
                            self.cancel_flag = True
                    return reply

                self.client.exchange = exchange
                with self.assertRaises(
                    TimeoutError if timeout_case else RecorderCancelled
                ):
                    if upload:
                        self.files.upload_settings(
                            "trip.drs",
                            DrsFile(2, 0, ()),
                            cancelled=lambda: self.cancel_flag,
                        )
                    else:
                        self.files.download(
                            "trip.dm", cancelled=lambda: self.cancel_flag
                        )
                self.assertEqual(self.closed, [19])
                self.assertEqual(
                    [decode_vim_command(x)[0] for x in self.calls], [0x21, 0x22]
                )

    def test_find_acquisition_malformed_body_and_cancel_close_search(self):
        original = self.client.exchange
        for malformed in (False, True):
            self.cancel_flag = False
            self.calls.clear()

            def exchange(request, *, deadline, cancelled, malformed=malformed):
                response = original(request, deadline=deadline, cancelled=cancelled)
                if decode_vim_command(request)[0] == 0x26:
                    if malformed:
                        return NativeVimReply(
                            0xA6, 6, struct.pack("<I", 19) + b"bad"
                        ).encode()
                    self.cancel_flag = True
                return response

            self.client.exchange = exchange
            with self.assertRaises(RecorderError):
                self.files.list_files("*.dm", cancelled=lambda: self.cancel_flag)
            self.assertEqual(
                [decode_vim_command(x)[0] for x in self.calls], [0x26, 0x28]
            )

    def test_size_failure_and_cancel_close_handle(self):
        with self.assertRaises(RecorderError):
            self.files.download("trip.dm", max_size=3, chunk_size=4)
        self.assertEqual(self.closed, [19])
        self.closed.clear()
        self.cancel_after_read = True
        with self.assertRaises(RecorderCancelled):
            self.files.download("trip.dm", cancelled=lambda: self.cancel_flag)
        self.assertEqual(self.closed, [19])

    def test_fault_cleanup_preserves_primary_and_short_write_progress(self):
        self.fail_read = self.fail_close = True
        with self.assertRaises(OSError) as error:
            self.files.download("trip.dm")
        self.assertIn("cleanup also failed", error.exception.__notes__[0])
        self.assertEqual(self.closed, [19])
        self.fail_close = False
        self.zero_write = True
        with self.assertRaises(RecorderError):
            self.files.upload_settings("trip.drs", DrsFile(2, 0, ()))
        self.assertEqual(self.closed, [19, 19])

    def test_corrupt_native_counts_and_capability(self):
        self.corrupt_count = True
        with self.assertRaises(RecorderError):
            self.files.download("trip.dm")
        self.assertEqual(self.closed, [19])
        self.client.capabilities = frozenset({"denso-vim-control"})
        before = len(self.calls)
        with self.assertRaises(UnsupportedRecorderOperation):
            self.files.download("trip.dm")
        self.assertEqual(len(self.calls), before)


class NativeTriggerComparisonTests(unittest.TestCase):
    def test_native_raw_signal_and_trigger_unit_conversion(self):
        name = NativeCoreString((1, 0), b"")
        signal = NativeMonitorSignal(
            (1, 0, 0, 7),
            (name, name, name),
            (0, 0),
            1,
            (2, 3, 7),
            0,
            (0, 0),
            (1, 0),
            (),
            (0, 0, 0),
        )
        condition = NativeTriggerCondition((1, 0), 1, 5, 0, 2, 3)
        # signed8(-3)*3/2 truncates=-4; offset7 ->3; triggerunits3*2/3 ->2.
        self.assertEqual(convert_native_trigger_value(0xFD, signal, condition), 2)
        condition = NativeTriggerCondition((1, 0), 1, 5, 0, 2, 0)
        with self.assertRaises(RecorderError):
            convert_native_trigger_value(1, signal, condition)

    def test_native_unsigned_twos_complement_and_sign_magnitude(self):
        self.assertEqual(native_trigger_sign_value(0xFF, 0, 8), 255)
        self.assertEqual(native_trigger_sign_value(0xFF, 1, 8), -1)
        self.assertEqual(native_trigger_sign_value(0xFF, 3, 8), -127)
        self.assertEqual(native_trigger_sign_value(0x80, 3, 8), 0)
        self.assertEqual(native_trigger_sign_value(0x7F, 1, 8), 127)
        self.assertEqual(native_trigger_sign_value(0xFFFFFFFF, 1, 32), -1)
        self.assertEqual(native_trigger_sign_value(0xFFFFFFFF, 2, 32), 0xFFFFFFFF)
        with self.assertRaises(RecorderError):
            native_trigger_sign_value(0, 1, 33)

    def test_recovered_condition_numbers_and_sliding_state(self):
        for condition, matches in (
            (3, (False, True, False)),
            (5, (True, False, False)),
            (6, (False, False, True)),
            (99, (False, False, False)),
        ):
            state = NativeTriggerComparison(condition, 10)
            self.assertEqual(tuple(state.evaluate(x) for x in (9, 10, 11)), matches)
            self.assertEqual(state.phase, 1 if matches[-1] else 2)
        state = NativeTriggerComparison(6, 0, True, 0)
        self.assertFalse(state.evaluate(10))
        self.assertTrue(state.evaluate(11))
        self.assertFalse(state.evaluate(9))
        self.assertEqual(state.reference, 9)

    def test_native_all_any_and_updates_even_when_first_decides(self):
        first = NativeTriggerComparison(3, 1)
        second = NativeTriggerComparison(6, 0, True)
        self.assertTrue(evaluate_native_comparisons((first, second), (1, 2), 2))
        self.assertEqual(second.reference, 2)
        self.assertFalse(evaluate_native_comparisons((first, second), (0, 3), 1))
        self.assertEqual(second.reference, 3)
        self.assertTrue(evaluate_native_comparisons((first,), (1,), 99))
        self.assertFalse(evaluate_native_comparisons((), (), 1))
        with self.assertRaises(RecorderError):
            first.evaluate(1 << 31)
        with self.assertRaises(RecorderError):
            evaluate_native_comparisons((first,), (), 1)


class NativeTransferTests(unittest.TestCase):
    def test_native_session_send_ack_receive_and_keepalive(self):
        session = NativeTransferSession(clock=lambda: 100.0)
        data = encode_vim_command(1, b"x" * 600)
        first = session.start(data)
        self.assertEqual(NativeTransferFrame.parse(first).control, 1)
        next_frames = session.receive(NativeTransferAcknowledgement(state=3).encode())
        self.assertEqual(NativeTransferFrame.parse(next_frames[0]).control, 2)
        self.assertEqual(
            session.receive(NativeTransferAcknowledgement(state=3).encode()), ()
        )
        self.assertEqual(session.state, 5)
        self.assertEqual(session.poll(), (NativeTransferFrame(0x7F, b"").encode(),))
        response = NativeVimReply(0x81, 6, b"r" * 1100).encode()
        for frame in encode_vim_transfer(response):
            self.assertEqual(
                session.receive(frame),
                (NativeTransferAcknowledgement(state=3).encode(),),
            )
        self.assertEqual(session.take_response(), response)
        self.assertEqual(session.state, 1)

    def test_native_session_sequence_nak_deadline_and_cancel(self):
        now = [10.0]
        session = NativeTransferSession(max_size=10, clock=lambda: now[0])
        session.start(b"x")
        now[0] = 12.0
        self.assertEqual(session.poll(), ())
        now[0] = 12.01
        with self.assertRaises(TimeoutError):
            session.poll()
        session.cancel()
        session.start(b"x")
        with self.assertRaises(RecorderError):
            session.receive(NativeTransferAcknowledgement(error=77).encode())
        session.cancel()
        session.start(b"x")
        session.receive(NativeTransferAcknowledgement(state=3).encode())
        with self.assertRaises(RecorderError):
            session.receive(NativeTransferFrame(2, b"x").encode())
        session.receive(NativeTransferFrame(1, b"123").encode())
        self.assertEqual(
            session.receive(NativeTransferFrame(0x81, b"x").encode()),
            (NativeTransferAcknowledgement(error=0x900D0005).encode(),),
        )
        with self.assertRaises(RecorderError):
            session.receive(NativeTransferFrame(2, b"12345678").encode())
        with self.assertRaises(RecorderError):
            session.take_response()
        session.cancel()
        self.assertEqual(session.state, 0)

    def test_native_receiver_emits_nak_and_preserves_partial_for_valid_retry(self):
        session = NativeTransferSession()
        session.start(b"x")
        session.receive(NativeTransferAcknowledgement(state=3).encode())
        session.receive(NativeTransferFrame(1, b"first").encode())
        corrupt = bytearray(NativeTransferFrame(0x80, b"second").encode())
        corrupt[-2] ^= 1
        result = session.receive(bytes(corrupt))
        self.assertEqual(
            NativeTransferAcknowledgement.parse(result[0]).error, 0x900D0004
        )
        self.assertEqual(session.state, 3)
        session.receive(NativeTransferFrame(0x80, b"second").encode())
        session.receive(NativeTransferFrame(2, b"last").encode())
        self.assertEqual(session.take_response(), b"firstsecondlast")

    def test_transfer_ack_and_nak_exact_bytes(self):
        ack = NativeTransferAcknowledgement(state=3)
        self.assertEqual(ack.encode(), bytes.fromhex("0203020006030e03"))
        self.assertEqual(NativeTransferAcknowledgement.parse(ack.encode()), ack)
        nak = NativeTransferAcknowledgement(error=0x900D0004)
        self.assertEqual(NativeTransferAcknowledgement.parse(nak.encode()), nak)
        for data in (
            NativeTransferFrame(3, b"\x06").encode(),
            NativeTransferFrame(0, b"\x06\x03").encode(),
            NativeTransferFrame(3, b"\x15\0").encode(),
        ):
            with self.assertRaises(RecorderError):
                NativeTransferAcknowledgement.parse(data)

    def test_literal_single_and_native_segmentation_boundaries(self):
        self.assertEqual(
            encode_vim_transfer(b"\x01"), (bytes.fromhex("02000100010203"),)
        )
        for size in (0, 1, 510, 511, 512, 1022, 1023, 511 * 132):
            data = bytes(range(256)) * (size // 256) + bytes(range(size % 256))
            frames = encode_vim_transfer(data)
            self.assertEqual(decode_vim_transfer(frames), data)
            self.assertTrue(all(len(x) <= 517 for x in frames))
        frames = encode_vim_transfer(b"x" * 1023)
        self.assertEqual(
            [NativeTransferFrame.parse(x).control for x in frames], [1, 128, 2]
        )

    def test_corruption_truncation_limits_and_sequence(self):
        frame = encode_vim_transfer(b"abc")[0]
        for length in range(len(frame)):
            with self.assertRaises(RecorderError):
                NativeTransferFrame.parse(frame[:length])
        for index in range(len(frame)):
            corrupt = bytearray(frame)
            corrupt[index] ^= 1
            with self.assertRaises(RecorderError):
                NativeTransferFrame.parse(bytes(corrupt))
        frames = encode_vim_transfer(b"x" * 1023)
        for reordered in (frames[::-1], frames[1:], (frames[0], frames[2], frames[1])):
            with self.assertRaises(RecorderError):
                decode_vim_transfer(reordered)
        with self.assertRaises(RecorderError):
            decode_vim_transfer(frames, max_size=1022)
        with self.assertRaises(RecorderError):
            encode_vim_transfer(b"abc", max_size=2)


class NativeDmciTests(unittest.TestCase):
    def test_dmci_status_has_typed_error_without_mapping_host_failures(self):
        command = NativeDmciCommand(0x11E, (19,))

        def exchange(request, **kwargs):
            return NativeVimReply(0x2DFF, 6, struct.pack("<I", 0xA0050441)).encode()

        client = NativeVimClient(
            exchange, capabilities=frozenset({"denso-vim-control", "denso-vim-dmci"})
        )
        with self.assertRaises(NativeDmciError) as caught:
            client.dmci(command)
        self.assertEqual(caught.exception.status, 0xA0050441)
        self.assertIsInstance(caught.exception, RecorderError)
        self.assertEqual(str(caught.exception), "Native DMCI status: 0xa0050441")

        def failed_exchange(request, **kwargs):
            raise TimeoutError("authored host timeout")

        client = NativeVimClient(
            failed_exchange,
            capabilities=frozenset({"denso-vim-control", "denso-vim-dmci"}),
        )
        with self.assertRaisesRegex(TimeoutError, "authored host timeout"):
            client.dmci(command)

    def test_psa_additional_frame_mode21_literal_payload(self):
        payload = encode_native_mode21(((0x21, bytes.fromhex("aabb")),))
        self.assertEqual(payload.hex(), "0100000001000000210100000002000000aabb")
        command = NativeDmciCommand.from_neutral(0x117, (19, payload))
        restored = NativeDmciCommand.parse(command.table())
        self.assertEqual(restored, command)
        calls = []

        def exchange(request, **kwargs):
            calls.append(request)
            return NativeVimReply(0x27FF, 6, bytes(4)).encode()

        client = NativeVimClient(
            exchange, capabilities=frozenset({"denso-vim-control", "denso-vim-dmci"})
        )
        client.dmci(command)
        self.assertEqual(decode_vim_command(calls[0]), (0x277F, command.encode()))

    def test_alias_repeated_dmci_buffers_are_bounded_before_join(self):
        buffer = NativeCoreBuffer((1, 0), b"x" * 16)
        modes = NativeDmciList((1, 0), ((1, buffer),) * 4)
        pairs = NativeDmciList((1, 0), ())
        command = NativeDmciCommand(0x109, (1, 2, modes, 3, pairs, 1))
        with (
            patch("scripts.drive_recorder.MAX_RECORDER_BYTES", 64),
            self.assertRaisesRegex(RecorderError, "byte budget"),
        ):
            command.encode()
        with (
            patch("scripts.drive_recorder.MAX_RECORDER_BYTES", 16),
            self.assertRaisesRegex(RecorderError, "byte budget"),
        ):
            buffer.encode()

    def test_remaining_host_dmci_request_codecs_and_real_wire_ids(self):
        buffer = NativeCoreBuffer((1, 0), b"x")
        words = NativeDmciList((1, 0), ((7,), (8,)))
        ids = NativeDmciList((1, 0), ((0xF200, 3),))
        pairs = NativeDmciList((1, 0), ((7, 9),))
        commands = (
            (NativeDmciCommand(0x117, (19, buffer)), 0x277F),
            (NativeDmciCommand(0x118, (1, 2, 3, 4, 5, 6, 7, 8, 9)), 0x287F),
            (NativeDmciCommand(0x119, (1, 2, ids, 3, pairs, 4)), 0x297F),
            (NativeDmciCommand(0x11A, (19, buffer)), 0x2A7F),
            (NativeDmciCommand(0x11B, (19, buffer, buffer, 3, 4)), 0x2B7F),
            (
                NativeDmciCommand(
                    0x11C, (1, 2, buffer, 3, words, words, 4, pairs, 5, words)
                ),
                0x2C7F,
            ),
            (NativeDmciCommand(0x11E, (19,)), 0x2D7F),
        )
        expected = iter(commands)

        def exchange(request, **kwargs):
            command, wire = next(expected)
            actual, payload = decode_vim_command(request)
            self.assertEqual((actual, payload), (wire, command.encode()))
            return NativeVimReply(wire | 0x80, 6, bytes(4)).encode()

        client = NativeVimClient(
            exchange, capabilities=frozenset({"denso-vim-control", "denso-vim-dmci"})
        )
        for command, _ in commands:
            self.assertEqual(NativeDmciCommand.parse(command.table()), command)
            self.assertEqual(client.dmci(command), b"")
            for length in range(len(command.encode())):
                with self.assertRaises(RecorderError):
                    NativeDmciCommand.parse(
                        DrsTable(command.command_id, command.encode()[:length])
                    )
        with self.assertRaises(RecorderError):
            NativeDmciCommand(0x11D, ()).encode()

    def test_original_iso_setup_body_and_actual_wire_opcode(self):
        text = NativeCoreString((1, 0), b"ISO\0")
        params = NativeDmciList((1, 0), ((1, 500000),))
        command = NativeDmciCommand(0x100, (text, params, 1, 2, 3, 4))
        literal = bytes.fromhex(
            "01000000040049534f0001000000010000000100000020a1070001000000020000000300000004000000"
        )
        self.assertEqual(command.encode(), literal)
        self.assertEqual(NativeDmciCommand.parse(DrsTable(0x100, literal)), command)
        requests = []

        def exchange(request, *, deadline, cancelled):
            requests.append(request)
            return NativeVimReply(0x10FF, 6, bytes(4)).encode()

        client = NativeVimClient(
            exchange, capabilities=frozenset({"denso-vim-control", "denso-vim-dmci"})
        )
        self.assertEqual(client.dmci(command), b"")
        self.assertEqual(requests, [b"\x7f\x10" + literal])
        for length in range(len(literal)):
            with self.assertRaises(RecorderError):
                NativeDmciCommand.parse(DrsTable(0x100, literal[:length]))

    def test_get_monitor_data_complete_reply_and_packet_stream(self):
        empty = NativeCoreBuffer((1, 0), b"")
        raw = (
            struct.pack("<I", 1000)
            + bytes.fromhex("123456")
            + struct.pack("<I", 1100)
            + bytes.fromhex("789abc")
        )
        reply = NativeMonitorReply(
            0,
            NativeDmciList((1, 0), ((19, NativeCoreBuffer((1, 0), raw)),)),
            (empty, empty, empty, empty, empty),
            0,
        )
        self.assertEqual(NativeMonitorReply.parse(reply.encode()), reply)
        requests = []

        def exchange(request, *, deadline, cancelled):
            requests.append(request)
            return NativeVimReply(0x19FF, 6, reply.encode()).encode()

        client = NativeVimClient(
            exchange, capabilities=frozenset({"denso-vim-control", "denso-vim-dmci"})
        )
        self.assertEqual(client.get_monitor_data((19,)), reply)
        self.assertEqual(requests[0], bytes.fromhex("7f19010000000100000013000000"))
        reader = NativeMonitorPacketReader(((0, 1), (1, 2)), phase=0)
        self.assertEqual(reader.feed(raw[:6]), ())
        packets = reader.feed(raw[6:])
        self.assertEqual(
            packets,
            (
                NativeMonitorPacket(1000, bytes.fromhex("123456")),
                NativeMonitorPacket(1100, bytes.fromhex("789abc")),
            ),
        )
        reader.finish()
        with self.assertRaises(RecorderError):
            NativeMonitorReply.parse(reply.encode()[:-1])
        reader.feed(b"x")
        with self.assertRaises(RecorderError):
            reader.finish()

    def test_trigger_window_duration_percent_and_timestamp_wrap(self):
        window = NativeTriggerWindow(NativeTriggerInfo((1, 0), 0, 4, 25))
        self.assertEqual((window.pre_ms, window.post_ms), (1000, 3000))
        for stamp in (100, 600, 1200):
            window.feed(NativeMonitorPacket(stamp, b"a"))
        window.trigger(1200)
        window.feed(NativeMonitorPacket(4200, b"b"))
        self.assertTrue(window.complete)
        self.assertEqual(
            [p.timestamp_ms for p in window.packets], [100, 600, 1200, 4200]
        )
        wrap = NativeTriggerWindow(NativeTriggerInfo((1, 0), 0, 1, 0))
        wrap.feed(NativeMonitorPacket(0xFFFFFFF0, b"x"))
        wrap.trigger(0xFFFFFFF0)
        wrap.feed(NativeMonitorPacket(1000, b"y"))
        self.assertTrue(wrap.complete)

    def test_packet_and_window_aggregate_byte_bounds_and_duplicate_preflight(self):
        reader = NativeMonitorPacketReader(((0, 1),), phase=0, max_bytes=9)
        reader.feed(struct.pack("<IB", 1, 2))
        with self.assertRaisesRegex(RecorderError, "byte budget"):
            reader.feed(struct.pack("<IB", 2, 3))
        self.assertEqual(reader.bytes_read, 5)
        with self.assertRaisesRegex(RecorderError, "Duplicate"):
            NativeMonitorPacketReader(((0, 1), (0, 2)), phase=0)
        window = NativeTriggerWindow(
            NativeTriggerInfo((1, 0), 0, 100, 100), max_bytes=9
        )
        window.feed(NativeMonitorPacket(0, b"x"))
        with self.assertRaisesRegex(RecorderError, "byte budget"):
            window.feed(NativeMonitorPacket(1, b"y"))
        self.assertEqual(len(window.packets), 1)
        self.assertEqual(window.retained_bytes, 5)

    def test_all_100_through_116_commands_include_active_and_psa(self):
        active = NativeDmciCommand(0x10F, (19, NativeCoreBuffer((1, 0), b"x"), 4))
        psa = NativeDmciCommand(0x115, (1, 2, 3, 4, 5, 6, 7, 8, 9))
        self.assertEqual(NativeDmciCommand.parse(active.table()), active)
        self.assertEqual(psa.encode(), struct.pack("<4B5I", 1, 2, 3, 4, 5, 6, 7, 8, 9))
        self.assertEqual(NativeDmciCommand.parse(psa.table()), psa)

    def test_external_trigger_ahead_of_buffer_does_not_finish_early(self):
        window = NativeTriggerWindow(NativeTriggerInfo((1, 0), 0, 1, 0))
        window.trigger(2000)
        window.feed(NativeMonitorPacket(1000, b"x"))
        self.assertFalse(window.complete)
        window.feed(NativeMonitorPacket(2000, b"y"))
        self.assertFalse(window.complete)
        window.feed(NativeMonitorPacket(3000, b"z"))
        self.assertTrue(window.complete)

    def test_monitor_pack_pair_lists_and_command_tree(self):
        buffer = NativeCoreBuffer((1, 0), b"\x21\x01")
        modes = NativeDmciList((1, 0), ((0x21, buffer),))
        standards = NativeDmciList((1, 0), ((7, 8),))
        pack = NativeDmciCommand(0x109, (1, 2, modes, 3, standards, 4))
        self.assertEqual(NativeDmciCommand.parse(pack.table()), pack)
        self.assertEqual(pack.encode()[:8], bytes.fromhex("0100000002000000"))
        self.assertIn(
            bytes.fromhex("01000000010000002101000000020000002101"), pack.encode()
        )
        pair = NativeDmciCommand(
            0x10A,
            (1, 2, 3, NativeDmciList((1, 0), ((0x21, 0x01),)), 4, standards, 5, 6),
        )
        self.assertEqual(decode_command(pair.table()), {"dmci": pair})
        for command_id in (0x104, 0x106, 0x108, 0x10C, 0x10E):
            self.assertEqual(NativeDmciCommand(command_id, ()).encode(), b"")
        for command in (pack, pair):
            for length in range(len(command.encode())):
                with self.assertRaises(RecorderError):
                    NativeDmciCommand.parse(
                        DrsTable(command.command_id, command.encode()[:length])
                    )
        with self.assertRaises(RecorderError):
            NativeDmciCommand(0x101, (1,)).encode()


class NativeMonitorRecorderTests(unittest.TestCase):
    def setUp(self):
        name = NativeCoreString((1, 0), b"x")
        self.signal = NativeMonitorSignal(
            (7, 0, 0, 7),
            (name, name, name),
            (0, 0),
            0,
            (1, 1, 0),
            0,
            (0, 255),
            (1, 0),
            (),
            (0, 0, 0),
        )
        self.monitor = NativeMonitorBuffer(
            0,
            0,
            1,
            0,
            4096,
            encode_command(3, {"frames": ((0, 1),)}),
            encode_command(4, {"signals": (self.signal,)}),
            name,
            (1, 0),
            ((1, 0, 7),),
        )
        self.parameters = NativeTriggerParameters(
            (1, 0),
            1,
            2,
            (1, 0),
            (NativeTriggerCondition((1, 0), 7, 6, 3, 1, 1),),
            (1, 0),
            (),
        )
        self.info = NativeTriggerInfo((1, 0), 2, 2, 50)
        self.calls = []
        self.values = iter(((1000, 1), (2000, 4), (3000, 5)))
        self.cancel_flag = False
        self.cancel_read = self.fail_read = self.fail_stop = False
        self.client = NativeVimClient(
            self.exchange,
            capabilities=frozenset({"denso-vim-control", "denso-vim-dmci"}),
            clock=lambda: 0.0,
        )

    def settings(self):
        return DrsFile(
            2,
            0,
            (
                encode_command(2, {"monitor": self.monitor}),
                encode_command(5, {"trigger": self.info}),
                encode_command(6, {"trigger": self.parameters}),
                encode_command(
                    0x11, {"children": (NativeDmciCommand(0x10C, ()).table(),)}
                ),
                encode_command(
                    0x12, {"children": (NativeDmciCommand(0x10E, ()).table(),)}
                ),
            ),
        )

    def exchange(self, request, *, deadline, cancelled):
        command, payload = decode_vim_command(request)
        self.calls.append(command)
        if command == 0x197F:
            if self.fail_read:
                raise OSError("native monitor disconnected")
            stamp, value = next(self.values)
            empty = NativeCoreBuffer((1, 0), b"")
            reply = NativeMonitorReply(
                0,
                NativeDmciList(
                    (1, 0),
                    ((19, NativeCoreBuffer((1, 0), struct.pack("<IB", stamp, value))),),
                ),
                (empty, empty, empty, empty, empty),
                0,
            ).encode()
            if self.cancel_read:
                self.cancel_flag = True
        else:
            self.assertEqual(payload, b"")
            if command == 0x1A7F and self.fail_stop:
                raise OSError("native monitor stop failed")
            reply = bytes(4)
        return NativeVimReply(command | 0x80, 6, reply).encode()

    def test_nonfinite_clocks_and_deadline_overflow_fail_before_primitives(self):
        for value in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(clock=value):
                self.client.clock = lambda value=value: value
                legacy_backend = FakeBackend()
                legacy = RecorderController(
                    legacy_backend,
                    capabilities=frozenset({"native-drs-execution"}),
                    clock=self.client.clock,
                )
                for operation in (
                    lambda legacy=legacy: legacy.execute(
                        DrsFile(
                            2,
                            0,
                            (encode_command(0x200, {"protocol_id": 6, "flags": 0}),),
                        )
                    ),
                    lambda: self.client.get_mode(),
                    lambda: NativeVimFiles(self.client).list_files("*"),
                    lambda: NativeMonitorRecorder(
                        self.settings(), self.client, interface_id=19, phase=0
                    ).capture(),
                    lambda: NativeTransferSession(clock=self.client.clock),
                ):
                    with self.assertRaisesRegex(RecorderError, "clock must be finite"):
                        operation()
                series, storage = self.series()
                with self.assertRaisesRegex(RecorderError, "clock must be finite"):
                    series.run()
                self.assertEqual(len(storage.files), 1)
                self.assertEqual(self.calls, [])
                self.assertEqual(legacy_backend.calls, [])
        self.client.clock = lambda: 1e308
        with self.assertRaisesRegex(RecorderError, "deadline must be finite"):
            self.client.get_mode(timeout=1e308)
        self.assertEqual(self.calls, [])

    def test_transfer_rechecks_clock_before_start_receive_and_poll(self):
        for operation in ("start", "receive", "poll"):
            now = [0.0]
            session = NativeTransferSession(clock=lambda now=now: now[0])
            now[0] = float("nan")
            with (
                self.subTest(operation=operation),
                self.assertRaisesRegex(RecorderError, "clock must be finite"),
            ):
                if operation == "start":
                    session.start(b"authored")
                elif operation == "receive":
                    session.receive(NativeTransferFrame(0, b"authored").encode())
                else:
                    session.poll()
            self.assertEqual(session.state, 1)

    def test_clock_becomes_invalid_after_monitor_io_still_runs_full_cleanup(self):
        now = [0.0]
        self.client.clock = lambda: now[0]
        original = self.client.exchange

        def exchange(request, *, deadline, cancelled):
            result = original(request, deadline=deadline, cancelled=cancelled)
            if decode_vim_command(request)[0] == 0x197F:
                now[0] = float("nan")
            self.assertTrue(math.isfinite(deadline))
            return result

        self.client.exchange = exchange
        settings = self.settings()
        cleanup = encode_command(
            0x12,
            {
                "children": tuple(
                    NativeDmciCommand(i, ()).table() for i in (0x10E, 0x108, 0x104)
                )
            },
        )
        settings = replace(settings, tables=settings.tables[:-1] + (cleanup,))
        recorder = NativeMonitorRecorder(
            settings, self.client, interface_id=19, phase=0
        )
        with self.assertRaisesRegex(RecorderError, "clock must be finite"):
            recorder.capture()
        self.assertEqual(self.calls, [0x187F, 0x197F, 0x1A7F, 0x147F, 0x127F])
        self.assertEqual(recorder.state, "fault")

    def test_clock_becomes_invalid_after_file_handle_acquisition_closes_it(self):
        for acquire, close, operation in (
            (0x21, 0x22, "download"),
            (0x26, 0x28, "list_files"),
        ):
            with self.subTest(acquire=acquire):
                now, calls = [0.0], []

                def exchange(
                    request,
                    *,
                    deadline,
                    cancelled,
                    acquire=acquire,
                    close=close,
                    now=now,
                    calls=calls,
                ):
                    command, _ = decode_vim_command(request)
                    calls.append(command)
                    if command == acquire:
                        now[0] = float("nan")
                        body = struct.pack("<I", 19)
                    else:
                        self.assertEqual(command, close)
                        body = b"\x01"
                    self.assertTrue(math.isfinite(deadline))
                    return NativeVimReply(command | 0x80, 6, body).encode()

                client = NativeVimClient(
                    exchange,
                    capabilities=frozenset({"denso-vim-control", "denso-vim-files"}),
                    clock=lambda now=now: now[0],
                )
                with self.assertRaisesRegex(RecorderError, "clock must be finite"):
                    getattr(NativeVimFiles(client), operation)("authored")
                self.assertEqual(calls, [acquire, close])
                with self.assertRaisesRegex(RecorderError, "clock must be finite"):
                    client.get_mode()
                self.assertEqual(calls, [acquire, close])

    def test_invalid_clock_after_native_io_error_preserves_original_cause(self):
        now = [0.0]

        def exchange(request, **kwargs):
            now[0] = float("nan")
            raise OSError("authored I/O failure")

        client = NativeVimClient(
            exchange,
            capabilities=frozenset({"denso-vim-control"}),
            clock=lambda: now[0],
        )
        with self.assertRaisesRegex(RecorderError, "clock must be finite") as raised:
            client.get_mode()
        self.assertIsInstance(raised.exception.__cause__, OSError)

    def test_invalid_clock_after_connect_disconnects_owned_channel(self):
        settings = DrsFile(
            2,
            0,
            (
                encode_command(
                    0x21,
                    {
                        "children": (
                            encode_command(0x200, {"protocol_id": 6, "flags": 0}),
                        )
                    },
                ),
            ),
        )
        for initial in (float("nan"), float("inf"), float("-inf"), 0.0):
            with self.subTest(initial=initial):
                now, calls = [initial], []

                class Backend:
                    def invoke(
                        self, operation, fields, *, now=now, calls=calls, **kwargs
                    ):
                        calls.append(operation)
                        if operation == "connect":
                            now[0] = float("nan")
                            return 19
                        return None

                executor = NativeDrsExecutor(
                    settings, Backend(), clock=lambda now=now: now[0]
                )
                with self.assertRaisesRegex(RecorderError, "clock must be finite"):
                    executor.execute_group(0x21)
                self.assertEqual(
                    calls, ["connect", "disconnect"] if initial == 0.0 else []
                )
                self.assertIsNone(executor.channel)

    def test_series_successful_save_is_retained_when_clock_becomes_invalid(self):
        series, storage = self.series()
        now = [0.0]
        self.client.clock = lambda: now[0]
        storage.after = lambda: now.__setitem__(0, float("nan"))
        with self.assertRaisesRegex(RecorderError, "clock must be finite"):
            series.run()
        self.assertEqual(series.written, ["out\\run-02.dm"])
        self.assertIn(series.written[0], storage.files)
        self.assertEqual(self.calls[-1], 0x1A7F)

    def test_ring_header_and_complete_dm_budget_are_checked_before_acquisition(self):
        from scripts.drive_recorder import MAX_RECORDER_BYTES

        self.monitor = replace(self.monitor, allocation_size=MAX_RECORDER_BYTES - 37)
        with self.assertRaisesRegex(RecorderError, "ring allocation"):
            NativeMonitorRecorder(
                self.settings(), self.client, interface_id=19, phase=0
            )
        self.monitor = replace(self.monitor, allocation_size=MAX_RECORDER_BYTES - 38)
        with self.assertRaisesRegex(RecorderError, "DM file byte budget"):
            NativeMonitorRecorder(
                self.settings(), self.client, interface_id=19, phase=0
            )
        self.assertEqual(self.calls, [])
        self.monitor = replace(self.monitor, allocation_size=4096, value_after_count=1)
        series, storage = self.series()
        overhead = len(
            NativeRecorderCapture(0, ()).dm_bytes(
                self.monitor,
                series.metadata,
                series.system_information,
                phase=0,
                block_packets=1,
            )
        )
        self.monitor = replace(
            self.monitor, allocation_size=MAX_RECORDER_BYTES - overhead + 1
        )
        recorder = NativeMonitorRecorder(
            self.settings(), self.client, interface_id=19, phase=0
        )
        with self.assertRaisesRegex(RecorderError, "DM file byte budget"):
            NativeRecorderSeries(
                recorder,
                storage,
                series.paths,
                series.base_name,
                series.metadata,
                series.system_information,
                block_packets=1,
            )
        self.assertEqual(self.calls, [])

    def test_manual_button_tick_uses_native_preceding_packet_alignment(self):
        self.info = replace(self.info, trigger_type=0)
        self.monitor = replace(self.monitor, value_after_count=1)
        records = struct.pack("<IBIBIBIB", 1000, 1, 2000, 4, 3000, 5, 4000, 6)
        original = self.client.exchange

        def exchange(request, *, deadline, cancelled):
            command, _ = decode_vim_command(request)
            if command != 0x197F:
                return original(request, deadline=deadline, cancelled=cancelled)
            self.calls.append(command)
            empty = NativeCoreBuffer((1, 0), b"")
            reply = NativeMonitorReply(
                0,
                NativeDmciList((1, 0), ((19, NativeCoreBuffer((1, 0), records)),)),
                (empty, empty, empty, empty, empty),
                0,
            )
            return NativeVimReply(0x19FF, 6, reply.encode()).encode()

        self.client.exchange = exchange
        capture = NativeMonitorRecorder(
            self.settings(), self.client, interface_id=19, phase=0
        ).capture(trigger_event=lambda: 2000)
        self.assertEqual(capture.trigger_timestamp_ms, 2000)
        self.assertEqual(
            [packet.timestamp_ms for packet in capture.packets], [1000, 2000, 3000]
        )
        self.assertEqual(self.calls.count(0x197F), 1)

    def test_available_batch_is_fully_persisted_before_post_window_finishes(self):
        records = struct.pack(
            "<IBIBIBIBIB", 1000, 1, 2000, 4, 3000, 5, 4000, 6, 5000, 7
        )
        original = self.client.exchange

        def exchange(request, *, deadline, cancelled):
            if decode_vim_command(request)[0] != 0x197F:
                return original(request, deadline=deadline, cancelled=cancelled)
            self.calls.append(0x197F)
            empty = NativeCoreBuffer((1, 0), b"")
            reply = NativeMonitorReply(
                0,
                NativeDmciList((1, 0), ((19, NativeCoreBuffer((1, 0), records)),)),
                (empty, empty, empty, empty, empty),
                0,
            )
            return NativeVimReply(0x19FF, 6, reply.encode()).encode()

        self.client.exchange = exchange
        capture = NativeMonitorRecorder(
            self.settings(), self.client, interface_id=19, phase=0
        ).capture()
        self.assertEqual([p.timestamp_ms for p in capture.packets], [1000, 2000, 3000])
        assert capture.ring_images is not None
        # Mode0 includes producer bytes after the selected right boundary.
        self.assertEqual(capture.ring_images[0][38:63], records)
        self.assertEqual(self.calls, [0x187F, 0x197F, 0x1A7F])
        self.monitor = replace(self.monitor, allocation_size=20)
        recorder = NativeMonitorRecorder(
            self.settings(), self.client, interface_id=19, phase=0
        )
        with self.assertRaisesRegex(RecorderError, "free|space|capacity"):
            recorder.capture()
        self.assertEqual(recorder.state, "fault")
        self.assertEqual(self.calls[-1], 0x1A7F)

    def test_post_window_compares_the_last_available_packet(self):
        batches = iter(
            (
                struct.pack("<IBIBIBIB", 1000, 1, 2000, 4, 3000, 5, 2500, 6),
                struct.pack("<IB", 4000, 7),
            )
        )
        original = self.client.exchange

        def exchange(request, *, deadline, cancelled):
            if decode_vim_command(request)[0] != 0x197F:
                return original(request, deadline=deadline, cancelled=cancelled)
            self.calls.append(0x197F)
            empty = NativeCoreBuffer((1, 0), b"")
            reply = NativeMonitorReply(
                0,
                NativeDmciList(
                    (1, 0), ((19, NativeCoreBuffer((1, 0), next(batches))),)
                ),
                (empty, empty, empty, empty, empty),
                0,
            )
            return NativeVimReply(0x19FF, 6, reply.encode()).encode()

        self.client.exchange = exchange
        NativeMonitorRecorder(
            self.settings(), self.client, interface_id=19, phase=0
        ).capture()
        self.assertEqual(self.calls.count(0x197F), 2)

    def test_full_cleanup_attempts_remaining_commands_after_each_failure(self):
        settings = self.settings()
        cleanup = encode_command(
            0x12,
            {
                "children": tuple(
                    NativeDmciCommand(i, ()).table() for i in (0x10E, 0x108, 0x104)
                )
            },
        )
        settings = replace(settings, tables=settings.tables[:-1] + (cleanup,))
        original = self.client.exchange
        for fail_at in (0x187F, 0x197F, None):
            with self.subTest(primary=fail_at):
                self.calls.clear()
                self.values = iter(((1000, 1), (2000, 4), (3000, 5)))

                def exchange(request, *, deadline, cancelled, fail_at=fail_at):
                    command, _ = decode_vim_command(request)
                    if command in (fail_at, 0x1A7F, 0x147F):
                        self.calls.append(command)
                        raise OSError(f"failed {command:#x}")
                    return original(request, deadline=deadline, cancelled=cancelled)

                self.client.exchange = exchange
                recorder = NativeMonitorRecorder(
                    settings, self.client, interface_id=19, phase=0
                )
                with self.assertRaisesRegex(
                    OSError, f"failed {fail_at or 0x1A7F:#x}"
                ) as raised:
                    recorder.capture()
                self.assertEqual(self.calls[-3:], [0x1A7F, 0x147F, 0x127F])
                self.assertEqual(recorder.state, "fault")
                if fail_at is None:
                    self.assertIn("0x108", raised.exception.__notes__[0])
                else:
                    self.assertIn("stop also failed", raised.exception.__notes__[0])

    def test_manual_non_crossing_snapshot_returns_its_last_packet(self):
        self.info = replace(self.info, trigger_type=0)
        self.monitor = replace(self.monitor, value_after_count=1)
        capture = NativeMonitorRecorder(
            self.settings(), self.client, interface_id=19, phase=0
        ).capture(trigger_event=lambda: 2000)
        self.assertEqual(capture.trigger_timestamp_ms, 1000)
        self.assertEqual(
            [packet.timestamp_ms for packet in capture.packets], [1000, 2000]
        )
        self.assertEqual(self.calls.count(0x197F), 2)

    def test_manual_button_after_draining_prior_batch_is_one_shot(self):
        self.info = replace(self.info, trigger_type=0)
        self.monitor = replace(self.monitor, value_after_count=1)
        events = iter((None, 2000))
        observed = []

        def button():
            value = next(events)
            observed.append(value)
            return value

        capture = NativeMonitorRecorder(
            self.settings(), self.client, interface_id=19, phase=0
        ).capture(trigger_event=button)
        self.assertEqual(observed, [None, 2000])
        self.assertEqual(capture.trigger_timestamp_ms, 2000)
        self.assertEqual(
            [packet.timestamp_ms for packet in capture.packets], [1000, 2000, 3000]
        )

    def test_manual_button_without_predecessor_uses_crossing_packet(self):
        self.info = replace(self.info, trigger_type=0)
        self.monitor = replace(self.monitor, value_after_count=1)
        self.values = iter(((2000, 4), (3000, 5)))
        capture = NativeMonitorRecorder(
            self.settings(), self.client, interface_id=19, phase=0
        ).capture(trigger_event=lambda: 1500)
        self.assertEqual(capture.trigger_timestamp_ms, 2000)
        self.assertEqual(
            [packet.timestamp_ms for packet in capture.packets], [2000, 3000]
        )

    def test_native_ring_overwrite_keeps_source_selected_area(self):
        self.monitor = replace(self.monitor, allocation_size=10, value_after_count=1)
        capture = NativeMonitorRecorder(
            self.settings(), self.client, interface_id=19, phase=0
        ).capture()
        self.assertEqual(capture.trigger_timestamp_ms, 2000)
        self.assertEqual([packet.timestamp_ms for packet in capture.packets], [3000])
        metadata = MonitorBuffer(
            b"x", bytes(16), b"", b"", b"", b"", 0, (), (), b"", ()
        )
        result = capture.monitor_buffer(
            self.monitor, metadata, phase=0, block_packets=1
        )
        self.assertEqual(
            struct.unpack_from("<7I", result.ring_buffer, 10), (10, 5, 0, 0, 5, 5, 5)
        )
        self.assertEqual(
            [packet["timestamp_raw"] for packet in monitor_packets(result)], [3000]
        )

    def test_native_block2_window_uses_original_lookup_stride(self):
        self.monitor = replace(
            self.monitor, frame_count=2, allocation_size=30, value_after_count=1
        )
        capture = NativeMonitorRecorder(
            self.settings(), self.client, interface_id=19, phase=0
        ).capture()
        # Native lookup divides active packet count by block size, while its
        # timestamp probe retains single-packet indexing; preserve that quirk.
        self.assertEqual(
            [packet.timestamp_ms for packet in capture.packets], [1000, 2000]
        )
        self.assertEqual(capture.trigger_timestamp_ms, 2000)
        self.assertIsNotNone(capture.ring_images)
        assert capture.ring_images is not None
        self.assertEqual(struct.unpack_from("<H", capture.ring_images[1], 8)[0], 2)

    def test_sh3_indeterminate_interior_seek_fails_with_native_stop(self):
        self.values = iter(((1000, 1), (0xFFFFFFFF, 1), (3000, 4), (4000, 5)))
        recorder = NativeMonitorRecorder(
            self.settings(), self.client, interface_id=19, phase=0
        )
        with self.assertRaisesRegex(RecorderError, "Unknown SH3 native seek result"):
            recorder.capture()
        self.assertEqual(recorder.state, "fault")
        self.assertEqual(self.calls, [0x187F] + [0x197F] * 4 + [0x1A7F])

    def test_native_phase1_block2_first_frame_capture_and_gui_playback(self):
        self.monitor = replace(
            self.monitor,
            buffer_size=1,
            frame_count=2,
            allocation_size=30,
            value_after_count=1,
            frame_table=encode_command(3, {"frames": ((0, 1), (1, 1))}),
        )
        capture = NativeMonitorRecorder(
            self.settings(), self.client, interface_id=19, phase=1
        ).capture()
        self.assertEqual(capture.trigger_timestamp_ms, 2000)
        self.assertEqual([p.timestamp_ms for p in capture.packets], [1000, 2000])
        metadata = MonitorBuffer(
            b"capture", bytes(16), b"description", b"", b"", b"", 0, (), (7,), b"", ()
        )
        for mode in (0, 1):
            record = capture.monitor_buffer(
                replace(self.monitor, value_after_count=mode),
                metadata,
                phase=1,
                block_packets=2,
            )
            packets = monitor_packets(record)
            self.assertTrue(all(p["frames"] == [] for p in packets))
            samples = monitor_samples(record)
            self.assertEqual(len(samples), 1)
            self.assertEqual(samples[0]["timestamp_raw"], 2000)
            self.assertEqual(samples[0]["values"][0]["raw_bits"], 4)
        self.assertEqual(self.calls[-1], 0x1A7F)

    def test_phase1_block2_unsafe_layouts_fail_before_native_start(self):
        original = self.monitor
        for frames, identity in (
            (((0, 1),), (7, 0, 0, 7)),
            (((0, 1), (1, 2)), (7, 0, 0, 7)),
            (((0, 1), (1, 1)), (7, 1, 0, 7)),
            (((0, 1), (1, 1)), (7, 0, 0, 8)),
            (((0, 1), (1, 1)), (7, 0, 7, 0)),
        ):
            with self.subTest(frames=frames, identity=identity):
                signal = replace(self.signal, identity_words=identity)
                self.monitor = replace(
                    original,
                    buffer_size=1,
                    frame_count=2,
                    frame_table=encode_command(3, {"frames": frames}),
                    signal_table=encode_command(4, {"signals": (signal,)}),
                )
                with self.assertRaises(RecorderError):
                    NativeMonitorRecorder(
                        self.settings(), self.client, interface_id=19, phase=1
                    )
                self.assertEqual(self.calls, [])

    def test_native_zero_post_window_waits_for_following_packet(self):
        self.info = replace(self.info, duration=0, trigger_point=0)
        self.monitor = replace(self.monitor, value_after_count=1)
        capture = NativeMonitorRecorder(
            self.settings(), self.client, interface_id=19, phase=0
        ).capture()
        self.assertEqual(self.calls.count(0x197F), 3)
        self.assertEqual([packet.timestamp_ms for packet in capture.packets], [2000])

    def test_actual_native_packets_drive_trigger_and_pre_post_capture(self):
        recorder = NativeMonitorRecorder(
            self.settings(), self.client, interface_id=19, phase=0
        )
        capture = recorder.capture()
        self.assertEqual(capture.trigger_timestamp_ms, 2000)
        self.assertEqual(
            [packet.timestamp_ms for packet in capture.packets], [1000, 2000, 3000]
        )
        self.assertEqual(
            capture.packet_bytes(), struct.pack("<IBIBIB", 1000, 1, 2000, 4, 3000, 5)
        )
        self.assertEqual(self.calls, [0x187F, 0x197F, 0x197F, 0x197F, 0x1A7F])
        self.assertEqual(recorder.state, "complete")
        with self.assertRaises(RecorderError):
            recorder.capture()

    def series(self, *, free=0x200000, fail_write=False):
        class Storage:
            def __init__(self):
                self.files = {"out\\run-01.dm": b"existing"}
                self.after = lambda: None

            def exists(self, path, **kwargs):
                return path in self.files

            def free_bytes(self, folder, **kwargs):
                return free

            def write(self, path, data, **kwargs):
                if fail_write:
                    raise OSError("record storage failed")
                self.files[path] = data
                self.after()

        storage = Storage()
        recorder = NativeMonitorRecorder(
            self.settings(),
            self.client,
            interface_id=19,
            phase=0,
            recorder_state=NativeRecorderState(0, 0),
        )
        metadata = MonitorBuffer(
            b"capture", bytes(16), b"description", b"", b"", b"", 0, (), (7,), b"", ()
        )
        system = {
            "identifier": 3,
            "strings": [
                {"core": [1, 0], "data_hex": "4100"},
                {"core": [1, 0], "data_hex": "4200"},
            ],
            "value_raw": 7,
        }
        return NativeRecorderSeries(
            recorder,
            storage,
            RecorderPaths("s", "out", 3),
            "run",
            metadata,
            system,
            block_packets=1,
        ), storage

    def test_native_series_quantity_slots_and_complete_dm_output(self):
        self.info = NativeTriggerInfo((1, 0), 4, 2, 50)
        self.parameters = replace(self.parameters, record_quantity=2)
        self.values = iter(
            ((1000, 1), (2000, 4), (3000, 5), (4000, 1), (5000, 4), (6000, 5))
        )
        series, storage = self.series()
        paths = series.run(max_records=2)
        self.assertEqual(paths, ("out\\run-02.dm", "out\\run-03.dm"))
        for path in paths:
            parsed = parse_snapshot(storage.files[path])
            assert isinstance(parsed, SnapshotTableFile)
            self.assertEqual(
                (parsed.magic, parsed.version, parsed.revision), (0x80000002, 1, 0)
            )
            self.assertEqual([table.id for table in parsed.tables], [0x8100, 0x8101])
        self.assertEqual(series.state, "complete")
        self.assertEqual(self.calls.count(0x187F), 2)
        self.assertEqual(self.calls.count(0x1A7F), 2)

    def test_native_series_storage_and_budget_fail_before_acquisition(self):
        series, _ = self.series(free=0x1FFFFF)
        with self.assertRaises(NativeDrsError) as raised:
            series.run()
        self.assertEqual(raised.exception.code, 0xA01F010B)
        self.assertEqual(self.calls, [])
        self.info = NativeTriggerInfo((1, 0), 4, 2, 50)
        self.parameters = replace(self.parameters, record_quantity=2)
        series, _ = self.series()
        with self.assertRaises(RecorderError):
            series.run(max_records=1)
        self.assertEqual(self.calls, [])

    def test_successful_save_is_retained_when_post_write_cancel_arrives(self):
        self.info = NativeTriggerInfo((1, 0), 1, 2, 50)
        series, storage = self.series()
        storage.after = lambda: setattr(self, "cancel_flag", True)
        with self.assertRaises(RecorderCancelled):
            series.run(cancelled=lambda: self.cancel_flag)
        self.assertEqual(series.written, ["out\\run-02.dm"])
        self.assertIn(series.written[0], storage.files)
        self.assertEqual(series.recorder.recorder_state.reference_raw, 1)
        self.assertEqual(
            NativeRecorderState.parse(storage.files["s\\temp.dat"]).reference_raw, 1
        )
        self.assertEqual(series.state, "cancelled")

    def test_failed_native_save_does_not_persist_sliding_reference(self):
        self.info = NativeTriggerInfo((1, 0), 1, 2, 50)
        series, _ = self.series(fail_write=True)
        with self.assertRaisesRegex(OSError, "record storage failed"):
            series.run()
        self.assertEqual(series.recorder.recorder_state.reference_raw, 0)
        self.assertEqual(self.calls[-1], 0x1A7F)
        self.assertEqual(series.state, "fault")

    def test_native_phase_block_and_ring_capacity_bindings_preflight(self):
        self.assertEqual(
            (self.monitor.phase, self.monitor.block_packets, self.monitor.serial_mode),
            (0, 1, 0),
        )
        with self.assertRaisesRegex(RecorderError, "SetPhase"):
            NativeMonitorRecorder(
                self.settings(), self.client, interface_id=19, phase=1
            )
        original = self.monitor
        self.monitor = replace(self.monitor, allocation_size=4)
        with self.assertRaisesRegex(RecorderError, "ring capacity"):
            NativeMonitorRecorder(
                self.settings(), self.client, interface_id=19, phase=0
            )
        self.assertEqual(self.calls, [])
        self.monitor = replace(original, frame_count=3)
        with self.assertRaisesRegex(UnsupportedRecorderOperation, "block packet"):
            NativeMonitorRecorder(
                self.settings(), self.client, interface_id=19, phase=0
            )
        self.monitor = replace(original, value_after_count=2)
        with self.assertRaisesRegex(UnsupportedRecorderOperation, "serial mode"):
            NativeMonitorRecorder(
                self.settings(), self.client, interface_id=19, phase=0
            )
        self.monitor = original
        metadata = MonitorBuffer(
            b"x", bytes(16), b"", b"", b"", b"", 0, (), (), b"", ()
        )
        with self.assertRaisesRegex(RecorderError, "phase/block"):
            NativeRecorderCapture(0, ()).monitor_buffer(
                self.monitor, metadata, phase=0, block_packets=2
            )

    def vin_profile(
        self,
        *,
        alternate=False,
        mask_a=b"\x0f\x0f",
        context_phase=None,
        context_module="SelectCarTypVn10_DT.dll",
        retries=0,
        vin_category=1,
    ):
        import tempfile
        from pathlib import Path

        from scripts.demo import _ddb, create_demo
        from scripts.profiles import VehicleCatalog

        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = create_demo(Path(temporary.name) / "authored") / "Techstream_DB_NA"
        old = VehicleCatalog(root).management
        sections = {
            key: (value.count, value.payload) for key, value in old.sections.items()
        }
        variables = (
            b"\x09\x00",
            b"\x09\x02",
            b"\x21\x01",
            b"\x00\xff" if context_phase else b"\xff\xff",
            b"\x00\xff" if context_phase else mask_a,
            b"\x00\xff" if context_phase else b"\xf0\xf0",
            b"\x3e",
            b"\x61" if context_phase else bytes(2),
            b"\x22\x01",
        )
        directory, image = bytearray(), bytearray()
        for value in variables:
            directory += struct.pack("<IH", len(image), len(value))
            image += value
        sections[0] = (len(variables), bytes(directory + image))
        category = bytearray(sections[16][1])
        category[72] = context_phase or 6
        struct.pack_into("<H", category, 68, vin_category)
        sections[16] = (1, bytes(category))
        functions = (
            (0x85, 1, 1),
            (0x86, 2, 1),
            (0x103, 2, 1),
            (0x58, 5, 1),
            (0x67, 5, 1),
            (0x7F, 5, 1),
            *(
                (function, 3 if function == 40 else 4, 1 if function == 40 else 2)
                for function in (*range(40, 53), 54, 55, 56, 53, 57)
            ),
        )
        if alternate:
            functions += ((40, 6, 1),)
        if context_phase == 3:
            functions += tuple((function, 3, 1) for function in range(27, 40))
        sections[18] = (
            len(functions),
            b"".join(
                struct.pack("<8H", vin_category, f, settings, comm, 0, 1, 0, 0)
                for f, comm, settings in sorted(functions)
            ),
        )
        comm = (
            (1, 1, 4, 8),
            (2, 2, 4, 8),
            (3, 3, 5, 8),
            (4, 3, 6, 8),
            (5, 7, 4, 8),
            (6, 9, 4, 8),
        )
        sections[17] = (len(comm), b"".join(struct.pack("<4H", *row) for row in comm))
        settings = []
        for key, first, second in ((1, 11, 13), (2, 21, 23)):
            row = bytearray(16)
            struct.pack_into("<II", row, 0, first, second)
            struct.pack_into("<H", row, 10, key)
            row[14] = retries
            settings.append(bytes(row))
        sections[29] = (2, b"".join(settings))
        protocol = bytearray(28)
        struct.pack_into("<6H", protocol, 0, vin_category, 1, 0x33, 0x7DF, 0x7E0, 0xAB)
        protocol[24] = 0x12
        can = bytearray(28)
        struct.pack_into("<IIHHH", can, 0, 0x1234, 500000, 1, 0, 20)
        sections[13], sections[14] = (1, bytes(protocol)), (1, bytes(can))
        if context_phase:
            sections[19] = (
                1,
                context_module.encode("utf-16le").ljust(80, b"\0")
                + struct.pack("<3HBB", 0, 0, 0, 0x7D, 0),
            )
        (root / "Toyota.ddb").write_bytes(_ddb(1, sections))
        return VehicleCatalog(root).build_profile(vin_category)

    def automatic_vehicle_runtime(
        self,
        *,
        phase=3,
        source_build=18,
        section_updates=None,
        support=True,
        probe_status=0,
        module="SelectCarTypVn10_DT.dll",
        protocol_only=False,
        extra_category_master_id=None,
        p4_category=False,
    ):
        from scripts.demo import _ddb
        from scripts.frame_transport import DriverProperties, J2534Result
        from scripts.frame_transport import NativeMessage as WireMessage
        from scripts.native_communication import NativeCommunication
        from scripts.profiles import VehicleCatalog

        profile = self.vin_profile(context_phase=phase, context_module=module)
        sections = {
            key: (part.count, part.payload)
            for key, part in profile.catalog.management.sections.items()
        }
        sections[2] = (1, struct.pack("<HBB", 1, 0x12, 0))
        count, frames = sections[17]
        sections[17] = (count + 1, struct.pack("<4H", 0, 1, 4, 8) + frames)
        row = bytearray(32)
        struct.pack_into("<I7H", row, 0, 0x7FF, 1, 1, 1, 1, 1, 0, 1)
        row[18] = 0x12
        sections[59] = (1, bytes(row))
        if extra_category_master_id is not None:
            count, masters = sections[47]
            sections[47] = (
                count + 1,
                masters + struct.pack("<IHH", 12, 1, extra_category_master_id),
            )
        if p4_category:
            category = bytearray(sections[16][1])
            category[72] = 6
            sections[16] = (sections[16][0], bytes(category))
        for key, value in (section_updates or {}).items():
            if value is None:
                sections.pop(key, None)
            else:
                sections[key] = value
        if protocol_only:
            count, categories = sections[16]
            sections[16] = (count, bytes(40) + categories[40:])
        root = profile.catalog.root
        (root / "Toyota.ddb").write_bytes(_ddb(1, sections))
        catalog = VehicleCatalog(root)
        profile = (
            catalog.build_protocol_profile(1)
            if protocol_only
            else catalog.build_profile(1)
        )
        vin = b"AUTHOREDVIN123456"

        class Backend:
            def __init__(self):
                self.calls = []
                self.request = b""

            def invoke(self, operation, fields, **kwargs):
                self.calls.append((operation, fields))
                if operation == "connect":
                    return J2534Result(handle=41)
                if operation == "start_message_filter":
                    return J2534Result(handle=42)
                if operation == "write_messages":
                    self.request = fields["messages"][0].data[4:]
                    return J2534Result(
                        code=probe_status if self.request == b"\x3e" else 0, count=1
                    )
                if operation == "read_messages":
                    data = {
                        b"\x3e": b"\x7e\x00",
                        b"\x09\x00": b"\x49\x00\x40" if support else b"\x49\x00\x00",
                        b"\x09\x02": b"\x49\x02\x01" + vin,
                    }.get(self.request, b"\x61\xa5")
                    return J2534Result(
                        count=1,
                        messages=(WireMessage(6, 0, 0, 0, 0, b"\0\0\x07\xe8" + data),),
                    )
                return J2534Result()

        backend = Backend()
        communication = NativeCommunication.from_backend(
            profile,
            backend,
            "selected",
            first_request=b"\x09\x00",
            driver=DriverProperties(0, b"04.04", "authored-version-reply"),
            device_kind=8,
            bus_id=0x12,
            source_build=source_build,
            clock=lambda: 0.0,
        )
        return communication, backend, vin

    def test_automatic_protocol_candidate_requires_no_ecu_database(self):
        from unittest.mock import patch

        communication, backend, vin = self.automatic_vehicle_runtime(protocol_only=True)
        self.assertEqual(communication.profile.filename, "")
        self.assertFalse(hasattr(communication.profile, "database"))
        with patch.object(
            communication.profile.catalog,
            "read_system",
            side_effect=AssertionError("Protocol acquisition must not open ECUDB"),
        ):
            selector = NativeVehicleSelector(
                NativeVehicleSession(communication),
                info_ids=(5, 4, 1, 3),
                text_encoding="ascii",
            )
            selected = selector.select()
            self.assertEqual(selected.vin.data, vin + b"\0")
            self.assertEqual(selected.trailing_words, (1, 0))
            self.assertEqual(selector.answer(1, 1).trailing_words, (0, 10001))
        self.assertTrue(backend.calls)

    def test_automatic_vehicle_selector_joins_actual_protocol_probe_vin_and_options(
        self,
    ):
        communication, backend, vin = self.automatic_vehicle_runtime()
        selector = NativeVehicleSelector(
            communication, info_ids=(5, 4, 1, 3, 16, 17), text_encoding="ascii"
        )
        selected = selector.select()
        self.assertEqual(
            selected.trailing_words,
            (1, 0),
            (backend.calls, communication.connection_entries),
        )
        self.assertEqual(tuple(item.values for item in selected.options), ((1,), (2,)))
        self.assertEqual(selected.vin.data, vin + b"\0")
        self.assertEqual(tuple(item.values for item in selected.car_info), ((1,), (3,)))
        self.assertEqual(NativeVehicleSelection.parse(selected.encode()), selected)
        before = len(backend.calls)
        for bad in (True, 1.0, "1", -1, 65536):
            with self.assertRaises(RecorderError):
                selector.answer(1, cast(Any, bad))
        self.assertEqual(len(backend.calls), before)
        terminal = selector.answer(1, 1)
        self.assertEqual(terminal.trailing_words, (0, 10001))
        self.assertEqual(terminal.vin.data, b"\0")
        self.assertEqual(
            tuple(item.values for item in terminal.car_info), ((4,), (1,), (3,))
        )
        self.assertEqual(terminal.car_info[-1].text.data, b"2065\0")
        self.assertEqual(len(backend.calls), before)

    def manual_ordinary_runtime(
        self,
        *,
        module="SelectCarTypVn10_DT.dll",
        option=0,
        model=10001,
        extra_category_master_id=None,
        phase=3,
        p4_category=False,
        probe_status=0,
        source_build=18,
        option_records=None,
        section_updates=None,
    ):
        row = bytearray(52)
        struct.pack_into("<H", row, 0, 1)
        row[2] = 0x12
        struct.pack_into("<4H", row, 40, 1, 1, 1, 1)
        struct.pack_into("<HH", row, 48, option, model)
        updates = {41: (1, bytes(row))}
        updates.update(section_updates or {})
        if option_records is not None:
            updates[42] = (len(option_records) // 16, option_records)
        return self.automatic_vehicle_runtime(
            phase=phase,
            source_build=source_build,
            module=module,
            section_updates=updates,
            extra_category_master_id=extra_category_master_id,
            p4_category=p4_category,
            probe_status=probe_status,
        )

    def test_manual18_menu_and_fresh_selector_share_actual_native_session(self):
        communication, backend, _vin = self.manual_ordinary_runtime()
        session = NativeVehicleSession(communication)
        producer = NativeVehicleSelector(session, info_ids=(), text_encoding="ascii")

        menu = producer.select_categories((), bus_judge=0)
        self.assertEqual(menu.mode, 1)
        self.assertEqual(
            tuple(
                (item.level, tuple(choice.value for choice in item.choices))
                for item in menu.items
            ),
            ((1, (1,)), (2, (1,)), (3, (1,)), (4, (1,))),
        )
        self.assertEqual(session.category_ids, [(1, 1), (2, 1), (3, 1), (4, 1)])
        self.assertEqual((session.shared_category, session.shared_bus), (1, 0x12))
        self.assertEqual(backend.calls, [])

        consumer = NativeVehicleSelector(session, info_ids=(), text_encoding="ascii")
        selected = consumer.select()
        self.assertEqual(selected.trailing_words, (0, 10001))
        self.assertEqual(NativeVehicleSelection.parse(selected.encode()), selected)
        self.assertEqual((session.current_model, session.model_list), (10001, [10001]))
        self.assertEqual((session.shared_protocol, session.shared_option), (0, 0))

    def test_manual18_except_hv_uses_actual_null_send_and_mode2_postlude(self):
        communication, backend, _vin = self.manual_ordinary_runtime()
        session = NativeVehicleSession(communication)
        selector = NativeVehicleSelector(session, info_ids=(), text_encoding="ascii")

        menu = selector.select_categories((), bus_judge=1)
        self.assertEqual(menu.mode, 2)
        self.assertEqual((session.shared_category, session.shared_bus), (1, 0x12))
        self.assertTrue(backend.calls)
        selected = NativeVehicleSelector(
            session, info_ids=(), text_encoding="ascii"
        ).select()
        self.assertEqual(selected.trailing_words, (0, 0xFFFF))
        self.assertEqual(
            (session.current_model, session.model_list), (0xFFFF, [0xFFFF])
        )
        assert session.manual_parent_record is not None
        self.assertEqual(session.manual_parent_record[72], 3)

    def test_manual18_admission_errors_and_native_shortsort_ties(self):
        communication, backend, _vin = self.manual_ordinary_runtime(
            module="SelectCarVn10Std_DT.dll"
        )
        selector = NativeVehicleSelector(
            communication, info_ids=(), text_encoding="ascii"
        )
        with self.assertRaises(UnsupportedRecorderOperation):
            selector.select_categories((), bus_judge=0)
        self.assertEqual(backend.calls, [])

        communication, backend, _vin = self.manual_ordinary_runtime(source_build=12)
        with self.assertRaises(UnsupportedRecorderOperation):
            NativeVehicleSelector(
                communication, info_ids=(), text_encoding="ascii"
            ).select_categories((), bus_judge=0)
        self.assertEqual(backend.calls, [])

        communication, _backend, _vin = self.manual_ordinary_runtime()
        session = NativeVehicleSession(communication)
        NativeVehicleSelector(
            session, info_ids=(), text_encoding="ascii"
        ).select_categories((), bus_judge=0)
        assert session.manual_identity is not None
        session.manual_identity = (*session.manual_identity[:-1], 12)
        with self.assertRaises(UnsupportedRecorderOperation):
            NativeVehicleSelector(session, info_ids=(), text_encoding="ascii").select()

        with self.assertRaises(NativeDrsError) as raised:
            NativeVehicleSelector(
                *self.manual_ordinary_runtime()[:1], info_ids=(), text_encoding="ascii"
            ).select_categories(((5, 1),), bus_judge=0)
        self.assertEqual(raised.exception.code, 0xC0040001)

        for count, expected in (
            (3, [2, 3, 1]),
            (8, [2, 3, 4, 5, 6, 7, 8, 1]),
            (9, [5, 2, 3, 4, 1, 6, 7, 8, 9]),
        ):
            rows = []
            for identity in range(1, count + 1):
                raw = bytearray(52)
                struct.pack_into("<H", raw, 0, identity)
                raw[2] = 7
                rows.append({"raw_hex": raw.hex()})
            sorted_rows = NativeVehicleSelector._manual_variant_sort(tuple(rows))
            self.assertEqual(
                [
                    struct.unpack_from("<H", bytes.fromhex(row["raw_hex"]))[0]
                    for row in sorted_rows
                ],
                expected,
            )

    def test_manual18_mode0_and_duplicate_ids_leave_slot17_untouched(self):
        row = bytearray(52)
        struct.pack_into("<H", row, 0, 1)
        row[2] = 0x12
        struct.pack_into("<4H", row, 40, 1, 1, 1, 1)
        struct.pack_into("<HH", row, 48, 0, 10001)
        communication, _backend, _vin = self.automatic_vehicle_runtime(
            phase=3, section_updates={41: (2, bytes(row) * 2)}
        )
        session = NativeVehicleSession(communication)
        selector = NativeVehicleSelector(session, info_ids=(), text_encoding="ascii")
        menu = selector.select_categories((), bus_judge=0)
        self.assertEqual(menu.mode, 0)
        self.assertEqual(session.category_ids, [])
        self.assertEqual(session.category_mode, 0)

        communication, _backend, _vin = self.manual_ordinary_runtime()
        session = NativeVehicleSession(communication)
        menu = NativeVehicleSelector(
            session, info_ids=(), text_encoding="ascii"
        ).select_categories(((1, 0), (1, 1)), bus_judge=0)
        self.assertEqual(menu.mode, 1)
        self.assertEqual(session.category_ids[0], (1, 1))

    def test_manual18_rejects_nonempty_multi_owner_cancel_and_dispose(self):
        communication, backend, _vin = self.manual_ordinary_runtime()
        session = NativeVehicleSession(communication)
        NativeVehicleSelector(
            session, info_ids=(), text_encoding="ascii"
        ).select_categories((), bus_judge=0)
        session.option_groups.append(object())
        selector = NativeVehicleSelector(session, info_ids=(), text_encoding="ascii")
        with self.assertRaises(UnsupportedRecorderOperation):
            selector.select()
        self.assertEqual(backend.calls, [])

        communication, backend, _vin = self.manual_ordinary_runtime()
        session = NativeVehicleSession(communication)
        selector = NativeVehicleSelector(session, info_ids=(), text_encoding="ascii")
        communication.cancelled = lambda: True
        with self.assertRaises(Cancelled):
            selector.select_categories((), bus_judge=0)
        self.assertEqual(backend.calls, [])
        communication.cancelled = lambda: False
        session.dispose()
        with self.assertRaises(SessionError):
            NativeVehicleSelector(
                session, info_ids=(), text_encoding="ascii"
            ).select_categories((), bus_judge=0)

    def test_manual18_option42_terminal_answer_survives_fresh_selector(self):
        communication, _backend, _vin = self.manual_ordinary_runtime(option=1, model=0)
        session = NativeVehicleSession(communication)
        NativeVehicleSelector(
            session, info_ids=(), text_encoding="ascii"
        ).select_categories((), bus_judge=0)
        pending = NativeVehicleSelector(
            session, info_ids=(), text_encoding="ascii"
        ).select()
        self.assertTrue(pending.options)
        self.assertEqual(pending.trailing_words[0], 1)
        terminal = NativeVehicleSelector(
            session, info_ids=(), text_encoding="ascii"
        ).answer(1, pending.options[0].values[0])
        self.assertEqual(terminal.trailing_words[0], 0)
        self.assertEqual(session.shared_option, 0)

    def test_manual18_formatter_keeps_select_names_out_of_car_info(self):
        communication, _backend, _vin = self.manual_ordinary_runtime(
            extra_category_master_id=5, phase=4, p4_category=True
        )
        session = NativeVehicleSession(communication)
        NativeVehicleSelector(
            session, info_ids=(), text_encoding="ascii"
        ).select_categories((), bus_judge=0)
        category_id = 5
        selected = NativeVehicleSelector(
            session, info_ids=(4, category_id), text_encoding="ascii"
        ).select()
        self.assertEqual(
            tuple(entry.values for entry in selected.select_names), ((category_id, 1),)
        )
        self.assertEqual(tuple(entry.values for entry in selected.car_info), ((4,),))
        self.assertEqual(NativeVehicleSelection.parse(selected.encode()), selected)
        self._assert_selected_metadata_capture(communication.profile, selected)

    def test_manual18_option42_zero_model_resume_preserves_shared_option(self):
        option_records = b"".join(
            struct.pack("<I6H", 12, 1, group, 1, model, next_group, 0)
            for group, model, next_group in ((1, 0, 0), (0, 10001, 0))
        )
        communication, _backend, _vin = self.manual_ordinary_runtime(
            option=1, model=0, option_records=option_records
        )
        session = NativeVehicleSession(communication)
        NativeVehicleSelector(
            session, info_ids=(), text_encoding="ascii"
        ).select_categories((), bus_judge=0)
        NativeVehicleSelector(session, info_ids=(), text_encoding="ascii").select()
        resumed = NativeVehicleSelector(
            session, info_ids=(), text_encoding="ascii"
        ).answer(1, 1)
        self.assertEqual(resumed.trailing_words, (0, 0xFFFF))
        self.assertEqual(session.shared_option, 1)
        self.assertEqual(
            (session.current_model, session.model_list), (0xFFFF, [0xFFFF])
        )

    def test_manual18_option42_resume_commits_terminal_provider_state(self):
        initial = bytearray(52)
        struct.pack_into("<H", initial, 0, 1)
        initial[2] = 0x12
        struct.pack_into("<I", initial, 36, 3)
        struct.pack_into("<4H", initial, 40, 0, 0, 1, 0)
        struct.pack_into("<HH", initial, 48, 1, 0)
        terminal = bytearray(initial)
        struct.pack_into("<I", terminal, 36, 0x3FF)
        struct.pack_into("<4H", terminal, 40, 0, 0, 2, 0)
        struct.pack_into("<HH", terminal, 48, 0, 10001)
        option_records = b"".join(
            struct.pack("<I6H", 12, 1, group, 1, model, next_group, 0)
            for group, model, next_group in ((1, 0, 0), (0, 10001, 0))
        )
        protocol_rows = struct.pack("<HBB", 1, 0x12, 0) * 2
        communication, backend, _vin = self.manual_ordinary_runtime(
            option=1,
            model=0,
            option_records=option_records,
            section_updates={
                41: (2, bytes(initial + terminal)),
                2: (2, protocol_rows),
                59: (0, b""),
            },
        )
        session = NativeVehicleSession(communication)
        NativeVehicleSelector(
            session, info_ids=(), text_encoding="ascii"
        ).select_categories(((3, 1),), bus_judge=0)
        pending = NativeVehicleSelector(
            session, info_ids=(), text_encoding="ascii"
        ).select()
        self.assertEqual(pending.trailing_words, (1, 0))
        selected = NativeVehicleSelector(
            session, info_ids=(), text_encoding="ascii"
        ).answer(1, pending.options[0].values[0])
        self.assertEqual(selected.trailing_words, (0, 10001))
        self.assertEqual(
            (session.shared_category, session.shared_bus, session.shared_protocol),
            (1, 0x12, 3),
        )
        self.assertEqual(session.shared_option, 0)
        self.assertEqual((session.current_model, session.model_list), (10001, [10001]))
        assert session.manual_parent_record is not None
        self.assertEqual(session.manual_parent_record[72], 3)
        self.assertTrue(backend.calls)

    def test_manual18_resume_model_zero_skips_terminal_formatter(self):
        initial = bytearray(52)
        struct.pack_into("<H", initial, 0, 1)
        initial[2] = 0x12
        struct.pack_into("<I", initial, 36, 3)
        struct.pack_into("<4H", initial, 40, 0, 0, 1, 0)
        struct.pack_into("<HH", initial, 48, 1, 0)
        terminal = bytearray(initial)
        struct.pack_into("<I", terminal, 36, 0x3FF)
        struct.pack_into("<4H", terminal, 40, 0, 0, 2, 0)
        option_records = b"".join(
            struct.pack("<I6H", 12, 1, group, 1, model, next_group, 0)
            for group, model, next_group in ((1, 0, 0), (0, 10001, 0))
        )
        protocol_rows = struct.pack("<HBB", 1, 0x12, 0) * 2
        communication, _backend, _vin = self.manual_ordinary_runtime(
            option=1,
            model=0,
            option_records=option_records,
            section_updates={
                41: (2, bytes(initial + terminal)),
                2: (2, protocol_rows),
                43: None,
                59: (0, b""),
            },
        )
        session = NativeVehicleSession(communication)
        NativeVehicleSelector(
            session, info_ids=(), text_encoding="ascii"
        ).select_categories(((3, 1),), bus_judge=0)
        pending = NativeVehicleSelector(
            session, info_ids=(), text_encoding="ascii"
        ).select()
        resumed = NativeVehicleSelector(
            session, info_ids=(4, 1, 3), text_encoding="ascii"
        ).answer(1, pending.options[0].values[0])
        self.assertEqual(resumed.trailing_words, (1, 0))
        self.assertEqual(resumed.car_info, ())

    def test_manual18_resume_propagates_missing_db102_query_error(self):
        option_records = b"".join(
            struct.pack("<I6H", 12, 1, group, 1, model, next_group, 0)
            for group, model, next_group in ((1, 0, 0), (0, 10001, 0))
        )
        communication, _backend, _vin = self.manual_ordinary_runtime(
            option=1,
            model=0,
            option_records=option_records,
            section_updates={2: None},
        )
        session = NativeVehicleSession(communication)
        NativeVehicleSelector(
            session, info_ids=(), text_encoding="ascii"
        ).select_categories((), bus_judge=0)
        NativeVehicleSelector(session, info_ids=(), text_encoding="ascii").select()
        with self.assertRaises(NativeDrsError) as caught:
            NativeVehicleSelector(session, info_ids=(), text_encoding="ascii").answer(
                1, 1
            )
        self.assertEqual(caught.exception.code, 0xA0030107)
        self.assertEqual(session.shared_option, 1)

    def test_manual18_option42_next_group_and_terminal_cross_fresh_selectors(self):
        option_records = b"".join(
            struct.pack("<I6H", 12, 1, group, 1, model, next_group, 0)
            for group, model, next_group in ((1, 0, 2), (2, 10001, 0))
        )
        communication, _backend, _vin = self.manual_ordinary_runtime(
            option=1, model=0, option_records=option_records
        )
        session = NativeVehicleSession(communication)
        NativeVehicleSelector(
            session, info_ids=(), text_encoding="ascii"
        ).select_categories((), bus_judge=0)
        pending = NativeVehicleSelector(
            session, info_ids=(), text_encoding="ascii"
        ).select()
        next_group = NativeVehicleSelector(
            session, info_ids=(), text_encoding="ascii"
        ).answer(1, pending.options[0].values[0])
        self.assertEqual(next_group.trailing_words[0], 2)
        self.assertEqual(next_group.select_names, ())
        terminal = NativeVehicleSelector(
            session, info_ids=(), text_encoding="ascii"
        ).answer(2, next_group.options[0].values[0])
        self.assertEqual(terminal.trailing_words, (0, 10001))
        self.assertEqual(session.shared_option, 0)

    def test_automatic_selected_producer_uses_six_regional_protocol_providers(self):
        row = bytearray(32)
        struct.pack_into("<I7H", row, 0, 0x7FF, 1, 1, 1, 1, 0, 10001, 1)
        row[18] = 0x12
        for build, phase, module in (
            (build, phase, module)
            for build in (12, 18)
            for phase in (3, 4)
            for module in (
                "SelectCarVn10Brd_DT.dll",
                "SelectCarVn10Std_DT.dll",
                "SelectCarTypVn10_DT.dll",
            )
        ):
            with self.subTest(build=build, phase=phase, module=module):
                communication, backend, vin = self.automatic_vehicle_runtime(
                    source_build=build,
                    phase=phase,
                    module=module,
                    section_updates={59: (1, bytes(row))},
                )
                selector = NativeVehicleSelector(
                    communication,
                    info_ids=(5, 1, 2, 3, 4, 16, 17),
                    text_encoding="ascii",
                )
                selected = selector.select()
                self.assertEqual(selected.trailing_words, (0, 10001))
                self.assertEqual(selected.vin.data, vin + b"\0")
                self.assertEqual(
                    tuple(item.values for item in selected.select_names), ((5, 1),)
                )
                self.assertEqual(
                    tuple(item.values for item in selected.car_info),
                    ((1,), (2,), (3,), (4,)),
                )
                self.assertEqual(
                    selected.car_info[0].text.data,
                    b"\xa5" * (3 if phase == 3 else 7) + b"\0",
                )
                self.assertEqual(selected.car_info[2].text.data, b"2065\0")
                writes = [
                    fields["messages"][0].data[4:]
                    for operation, fields in backend.calls
                    if operation == "write_messages"
                ]
                self.assertEqual(writes.count(b"\x3e"), 1)

    def test_automatic_vehicle_fallback_uses_raw129_and_native_setup_without_extra_probe(
        self,
    ):
        row = bytearray(52)
        struct.pack_into("<H", row, 0, 1)
        row[2] = 0x12
        struct.pack_into("<I6H", row, 36, 0x3FF, 1, 1, 1, 1, 0, 10001)
        for phase in (3, 4):
            with self.subTest(phase=phase):
                communication, backend, _ = self.automatic_vehicle_runtime(
                    phase=phase,
                    support=False,
                    section_updates={41: (1, bytes(row)), 59: None},
                )
                selector = NativeVehicleSelector(
                    communication, info_ids=(4, 1, 3), text_encoding="ascii"
                )
                selected = selector.select()
                self.assertEqual(selected.trailing_words, (0, 10001))
                self.assertEqual(selected.vin.data, b"\0")
                writes = [
                    fields["messages"][0].data[4:]
                    for operation, fields in backend.calls
                    if operation == "write_messages"
                ]
                self.assertEqual(writes.count(b"\x3e"), 1)
                self.assertNotIn(b"\x09\x02", writes)
                self.assertEqual(selected.car_info[-1].text.data, b"2065\0")

    def test_automatic_vin_multiple_rows_and_division_priority_preserve_native_count(
        self,
    ):
        rows = []
        for level, model in ((1, 10001), (2, 10002)):
            row = bytearray(32)
            struct.pack_into("<I7H", row, 0, 0x7FF, level, 1, 1, 1, 0, model, 1)
            row[18] = 0x12
            rows.append(bytes(row))
        for division, expected in ((0, 0), (5, 10002), (6, 10001)):
            with self.subTest(division=division):
                communication, _, _ = self.automatic_vehicle_runtime(
                    section_updates={59: (2, b"".join(rows))}
                )
                selector = NativeVehicleSelector(
                    communication,
                    info_ids=(4,),
                    text_encoding="ascii",
                    division=division,
                )
                selected = selector.select()
                self.assertEqual(selected.trailing_words, (0, expected))
                self.assertEqual(len(selected.car_info), int(bool(expected)))

    def test_automatic_vin_hidden_registration_name_and_answer_filter_are_distinct(
        self,
    ):
        vehicle_set = "UNREG".encode("utf-16le").ljust(18, b"\0") + struct.pack(
            "<H", 10001
        )
        communication, backend, _ = self.automatic_vehicle_runtime(
            section_updates={82: (1, vehicle_set)}
        )
        selector = NativeVehicleSelector(
            communication, info_ids=(4,), text_encoding="ascii"
        )
        pending = selector.select()
        self.assertEqual(selector.hidden_name, "UNREG")
        self.assertEqual(tuple(row.values for row in pending.options), ((1,), (2,)))
        before = len(backend.calls)
        with self.assertRaises(NativeDrsError) as caught:
            selector.answer(1, 1)
        self.assertEqual(caught.exception.code, 0xC0040102)
        self.assertEqual(selector.answer(1, 2).trailing_words, (0, 10002))
        self.assertEqual(len(backend.calls), before)

    def test_automatic_vin_priority_empty_is_completed_without_diagnostic_fallback(
        self,
    ):
        row = bytearray(32)
        struct.pack_into("<I7H", row, 0, 0x7FF, 4, 1, 1, 1, 0, 10001, 1)
        row[18] = 0x12
        communication, backend, vin = self.automatic_vehicle_runtime(
            section_updates={59: (1, bytes(row))}
        )
        selector = NativeVehicleSelector(
            communication, info_ids=(1, 3, 4), text_encoding="ascii", division=5
        )
        selected = selector.select()
        self.assertEqual(selected.trailing_words, (0, 0))
        self.assertEqual(selected.vin.data, vin + b"\0")
        self.assertEqual(
            tuple(item.text.data for item in selected.car_info), (b"\0", b"1900\0")
        )
        writes = [
            fields["messages"][0].data[4:]
            for operation, fields in backend.calls
            if operation == "write_messages"
        ]
        self.assertNotIn(b"\x21\x01", writes)

    def test_automatic_option_next_group_and_protocol_resume_use_fresh_response_lists(
        self,
    ):
        for next_group in (0, 2):
            with self.subTest(next_group=next_group):
                options = b"".join(
                    (
                        struct.pack("<I6H", 16, 1, 0, 7, 10001, 0, 0),
                        struct.pack("<I6H", 16, 1, 1, 1, 0, next_group, 0),
                        struct.pack("<I6H", 16, 1, 2, 3, 10001, 0, 0),
                    )
                )
                communication, backend, _ = self.automatic_vehicle_runtime(
                    section_updates={42: (3, options)}
                )
                selector = NativeVehicleSelector(
                    communication, info_ids=(4, 1, 3), text_encoding="ascii"
                )
                self.assertEqual(selector.select().trailing_words, (1, 0))
                before = len(backend.calls)
                selected = selector.answer(1, 1)
                if next_group:
                    self.assertEqual(selected.trailing_words, (2, 0))
                    self.assertEqual(selected.car_info, ())
                    self.assertEqual(
                        tuple(row.values for row in selected.options), ((3,),)
                    )
                    self.assertEqual(selector.answer(2, 3).trailing_words, (0, 10001))
                else:
                    self.assertEqual(selected.trailing_words, (0, 65535))
                self.assertEqual(len(backend.calls), before)

    def test_automatic_failed_probe_records_native_negative_and_stops_before_vin(self):
        communication, backend, _ = self.automatic_vehicle_runtime(probe_status=5)
        selector = NativeVehicleSelector(
            communication, info_ids=(4,), text_encoding="ascii"
        )
        self.assertEqual(selector.select().trailing_words, (0, 65535))
        (entry,) = communication.connection_entries
        self.assertEqual(
            (entry.supported, entry.protocol, entry.request, entry.reply),
            (0, 3, b"", b""),
        )
        writes = [
            fields["messages"][0].data[4:]
            for operation, fields in backend.calls
            if operation == "write_messages"
        ]
        self.assertEqual(writes, [b"\x3e"])

    def test_automatic_pending_answer_rechecks_source_cancellation_and_deadline(self):
        from scripts.demo import _ddb
        from scripts.diagnostic_db import read_database
        from scripts.toyota_session import Cancelled, SessionError

        for failure in ("source", "cancel", "deadline"):
            with self.subTest(failure=failure):
                communication, backend, _ = self.automatic_vehicle_runtime()
                selector = NativeVehicleSelector(
                    communication, info_ids=(4,), text_encoding="ascii"
                )
                selector.select()
                before = len(backend.calls)
                expected = SessionError
                if failure == "source":
                    catalog = communication.profile.catalog
                    sections = {
                        key: (part.count, part.payload)
                        for key, part in catalog.management.sections.items()
                    }
                    count, rows = sections[42]
                    sections[42] = (count, rows[:-2] + b"\x01\x00")
                    path = catalog.root / "Toyota.ddb"
                    path.write_bytes(_ddb(1, sections))
                    catalog.management = read_database(path)
                elif failure == "cancel":
                    communication.cancelled = lambda: True
                    expected = Cancelled
                else:
                    communication.clock = lambda owner=communication: owner.deadline
                with self.assertRaises(expected):
                    selector.answer(1, 1)
                self.assertEqual(len(backend.calls), before)

    def test_automatic_vehicle_budget_stops_before_materializing_all_entries(self):
        communication, _, _ = self.automatic_vehicle_runtime()
        selector = NativeVehicleSelector(
            communication, info_ids=(5,) * 1000, text_encoding="ascii"
        )
        with (
            patch("scripts.drive_recorder.MAX_RECORDER_BYTES", 128),
            patch.object(selector, "_text", wraps=selector._text) as text,
            self.assertRaisesRegex(RecorderError, "byte budget"),
        ):
            selector.select()
        self.assertLess(text.call_count, 10)

    def test_native_vehicle_session_reuses_actual_positive_and_negative_vin_observations(
        self,
    ):
        from scripts.toyota_session import SessionError

        row = bytearray(52)
        struct.pack_into("<H", row, 0, 1)
        row[2] = 0x12
        struct.pack_into("<I6H", row, 36, 0x3FF, 1, 1, 1, 1, 0, 10001)
        for support in (True, False):
            with self.subTest(support=support):
                communication, backend, vin = self.automatic_vehicle_runtime(
                    support=support, section_updates={41: (1, bytes(row))}
                )
                session = NativeVehicleSession(communication)
                for _ in range(2):
                    selector = NativeVehicleSelector(
                        session, info_ids=(1, 3), text_encoding="ascii"
                    )
                    output = selector.select()
                    self.assertEqual(output.car_info[-1].text.data, b"2065\0")
                (entry,) = session.vin_entries
                self.assertEqual(
                    (entry.category, entry.data), (1, vin if support else bytes(17))
                )
                writes = [
                    fields["messages"][0].data[4:]
                    for operation, fields in backend.calls
                    if operation == "write_messages"
                ]
                self.assertEqual(writes.count(b"\x09\x00"), 1)
                self.assertEqual(writes.count(b"\x09\x02"), int(support))
                self.assertEqual(writes.count(b"\x21\x01"), 1)
                before = len(backend.calls)
                session.dispose()
                with self.assertRaisesRegex(SessionError, "disposed"):
                    NativeVehicleSelector(session, info_ids=(), text_encoding="ascii")
                self.assertEqual(len(backend.calls), before)

    def test_selected_context_diagnostics_use_native_protocol_state_and_channel(self):
        from scripts.native_communication import NativeCommunication

        @dataclass(frozen=True)
        class Reply:
            code: int = 0
            data: bytes = b"\x61\xa5"

        for source_build, phase, module in (
            (build, phase, module)
            for build in (12, 18)
            for phase in (3, 4, 6, 20, 21)
            for module in (
                "SelectCarVn10Brd_DT.dll",
                "SelectCarVn10Std_DT.dll",
                "SelectCarTypVn10_DT.dll",
            )
        ):
            profile = replace(
                self.vin_profile(context_phase=phase, context_module=module),
                vehicle_name_key=10001,
            )
            calls = []

            class Operations:
                def send(self, request, calls=calls, **kwargs):
                    calls.append(("send", request, kwargs))
                    return 0

                def receive(self, calls=calls, **kwargs):
                    calls.append(("receive", kwargs))
                    return Reply()

                def close(self):
                    return 0

            communication = NativeCommunication(
                profile,
                Operations(),
                "authoredECU",
                bus_id=0x12,
                source_build=source_build,
                clock=lambda: 0.0,
            )
            context = selected_vehicle_context(
                profile,
                decision_row=0,
                answers=(1,),
                info_ids=(1, 2, 3, 16, 17, 3),
                vin=b"",
                text_encoding="ascii",
                source_build=source_build,
                communication=communication,
            )
            expected = {
                3: (b"\xa5" * 3, b"\xb5\xa5\xa5", b"2065", b"10", b"165", b"2065"),
                4: (b"\xa5" * 7, b"\xa5" * 6, b"2065", b"165", b"165", b"2065"),
                6: (b"",) * 6,
                20: (b"", b"", b"1900", b"", b"", b"1900"),
                21: (b"", b"", b"1900", b"", b"", b"1900"),
            }[phase]
            unsupported = phase == 6 or (
                phase == 21 and module == "SelectCarVn10Std_DT.dll"
            )
            if unsupported:
                expected = (b"",) * 6
            self.assertEqual(
                tuple(entry.text.data for entry in context.car_info),
                tuple(expected[index] + b"\0" for index in (0, 1, 2, 5)),
            )
            self.assertEqual(
                tuple(entry.values for entry in context.car_info),
                ((1,), (2,), (3,), (3,)),
            )
            self.assertEqual(NativeVehicleSelection.parse(context.encode()), context)
            if unsupported:
                self.assertEqual(calls, [])
            else:
                self.assertEqual(calls[0][1], None)
                self.assertEqual(calls[0][2]["initialization_mode"], 0)
                self.assertEqual(calls[0][2]["timeout"], 1000)
                self.assertEqual(len(calls), 3 if phase in (3, 4) else 1)

    def test_selected_context_diagnostic_probe_failure_is_native_empty_first_field(
        self,
    ):
        from scripts.native_communication import NativeCommunication

        profile = replace(self.vin_profile(context_phase=4), vehicle_name_key=10001)
        calls = []

        class Operations:
            def send(self, request, **kwargs):
                calls.append(request)
                return 0xA0040201

            def receive(self, **kwargs):
                raise AssertionError("Failed native probe must not receive")

            def close(self):
                return 0

        communication = NativeCommunication(
            profile, Operations(), "authoredECU", bus_id=0x12, clock=lambda: 0.0
        )
        context = selected_vehicle_context(
            profile,
            decision_row=0,
            answers=(1,),
            info_ids=(1, 3, 2),
            vin=b"",
            text_encoding="ascii",
            source_build=18,
            communication=communication,
        )
        self.assertEqual(
            tuple(entry.text.data for entry in context.car_info),
            (b"\0", b"1900\0", b"\0"),
        )
        self.assertEqual(calls, [None])

    def test_selected_context_native12_work_area_overflow_is_not_native18_clipping(
        self,
    ):
        from scripts.native_communication import NativeCommunication

        @dataclass(frozen=True)
        class Reply:
            code: int = 0
            data: bytes = b"\x61" + b"A" * 20

        class Operations:
            def send(self, request, **kwargs):
                return 0

            def receive(self, **kwargs):
                return Reply()

            def close(self):
                return 0

        for build in (12, 18):
            profile = replace(self.vin_profile(context_phase=3), vehicle_name_key=10001)
            communication = NativeCommunication(
                profile,
                Operations(),
                "authoredECU",
                bus_id=0x12,
                source_build=build,
                clock=lambda: 0.0,
            )
            kwargs: dict[str, Any] = {
                "decision_row": 0,
                "answers": (1,),
                "info_ids": (1,),
                "vin": b"",
                "text_encoding": "ascii",
                "source_build": build,
                "communication": communication,
            }
            if build == 12:
                with self.assertRaisesRegex(
                    UnsupportedRecorderOperation, "Native12.*stack"
                ):
                    selected_vehicle_context(profile, **kwargs)
            else:
                value = selected_vehicle_context(profile, **kwargs)
                self.assertEqual(value.car_info[0].text.data, b"AAA\0")

    def test_selected_context_negative_empty_cache_keeps_native_constructor_fields(
        self,
    ):
        from scripts.native_communication import NativeCommunication

        @dataclass(frozen=True)
        class Reply:
            code: int = 0x91010009
            data: bytes = b""

        class Operations:
            def send(self, request, **kwargs):
                return 0

            def receive(self, **kwargs):
                return Reply()

            def close(self):
                return 0

        profile = replace(self.vin_profile(context_phase=3), vehicle_name_key=10001)
        communication = NativeCommunication(
            profile, Operations(), "authoredECU", bus_id=0x12, clock=lambda: 0.0
        )
        value = selected_vehicle_context(
            profile,
            decision_row=0,
            answers=(1,),
            info_ids=(1, 2, 3, 16, 17),
            vin=b"",
            text_encoding="ascii",
            source_build=18,
            communication=communication,
        )
        self.assertEqual(
            tuple(entry.text.data for entry in value.car_info),
            (b"\0", b"0\0", b"1900\0"),
        )
        self.assertEqual(communication.calls, 3)

    def test_selected_vehicle_vin_uses_actual_support_and_direct_observation(self):
        from scripts.monitor_support import MonitorSupportCache

        profile = self.vin_profile()
        vin = b"AUTHOREDVIN123456"
        calls = []

        def exchange(query):
            calls.append(query.request)
            return (
                b"\x49\x00\x40"
                if query.request == b"\x09\x00"
                else b"\x49\x02\x01" + vin
            )

        cache = MonitorSupportCache(profile, exchange, "authoredECU", clock=lambda: 0.0)
        self.assertEqual(selected_vehicle_vin(profile, cache, bus_id=0x12), vin)
        self.assertEqual(calls, [b"\x09\x00", b"\x09\x02"])
        absent = MonitorSupportCache(
            profile, lambda query: b"\x49\x00\x00", "authoredECU", clock=lambda: 0.0
        )
        self.assertIsNone(selected_vehicle_vin(profile, absent, bus_id=0x12))
        short = MonitorSupportCache(
            profile,
            lambda query: (
                b"\x49\x00\x40"
                if query.request == b"\x09\x00"
                else b"\x49\x02\x01short"
            ),
            "authoredECU",
            clock=lambda: 0.0,
        )
        with self.assertRaises(NativeDrsError) as caught:
            selected_vehicle_vin(profile, short, bus_id=0x12)
        self.assertEqual(caught.exception.code, 0xA0040202)

    def test_selected_vehicle_vin_reassembles_native_four_byte_segments(self):
        from scripts.monitor_support import MonitorSupportCache

        profile = self.vin_profile()
        vin = b"AUTHOREDVIN123456"
        data = b"\0\0\0" + vin
        for truncated in (False, True):
            responses = [
                (0, b"\x49\x02" + bytes([index // 4]) + data[index : index + 4])
                for index in range(0, len(data), 4)
            ]
            if truncated:
                responses.pop()
            replies = iter((*responses, (0x91010009, b"")))

            class Stream:
                def send(self, operation):
                    return 0

                def receive(self, operation, replies=replies):
                    return next(replies)

            cache = MonitorSupportCache(
                profile,
                lambda query: b"\x49\x00\x00\x40",
                "authoredECU",
                stream=Stream(),
                clock=lambda: 0.0,
            )
            if truncated:
                with self.assertRaises(NativeDrsError) as caught:
                    selected_vehicle_vin(profile, cache, bus_id=0x11)
                self.assertEqual(caught.exception.code, 0xA0040202)
            else:
                self.assertEqual(selected_vehicle_vin(profile, cache, bus_id=0x11), vin)

    def test_selected_vehicle_vin_segment_failures_stop_or_drain_as_native(self):
        from scripts.monitor_support import MonitorSupportCache

        profile = self.vin_profile()
        for observations, expected in (
            (((0, b"\x49\x02short"[:6]),), 0xA0040201),
            (((0, b"\x7f"), (0, b"discard"), (0x91010009, b"")), 0xA0040202),
            (((0x90020323, b""),), 0x90020323),
            (((0x91010009, b""),), 0xA0040202),
        ):
            replies = iter(observations)
            received = []

            class Stream:
                def send(self, operation):
                    return 0

                def receive(self, operation, replies=replies, received=received):
                    value = next(replies)
                    received.append(value)
                    return value

            cache = MonitorSupportCache(
                profile,
                lambda query: b"\x49\x00\x00\x40",
                "authoredECU",
                stream=Stream(),
                clock=lambda: 0.0,
            )
            with (
                self.subTest(expected=hex(expected)),
                self.assertRaises(NativeDrsError) as caught,
            ):
                selected_vehicle_vin(profile, cache, bus_id=0x11)
            self.assertEqual(caught.exception.code, expected)
            self.assertEqual(tuple(received), observations)

    def test_selected_vehicle_vin_retry_cursor_packet_count_and_status_precedence(self):
        from scripts.monitor_support import MonitorSupportCache

        def segments(*values):
            return tuple((0, b"\x49\x02\x01" + value) for value in values)

        cases = (
            (
                segments(b"abcd", b"efgh")
                + ((0x91010008, b""),)
                + segments(b"ijkl", b"mnop", b"qrst")
                + ((0x91010009, b""),),
                b"lmnopqrst" + bytes(8),
                1,
            ),
            (((0x91010008, b""),) * 2, 0xA0040202, 2),
            (
                segments(b"abcd", b"efgh", b"ijkl", b"mnop", b"qrst")
                + ((0x91010008, b""), (0x91010009, b"")),
                0x91010009,
                1,
            ),
        )
        for observations, expected, sends in cases:
            profile = self.vin_profile(retries=1)
            replies = iter(observations)
            sent = []

            class Stream:
                def send(self, operation, sent=sent):
                    sent.append(operation.query.request)
                    return 0

                def receive(self, operation, replies=replies):
                    return next(replies)

            cache = MonitorSupportCache(
                profile,
                lambda query: b"\x49\x00\x00\x40",
                "authoredECU",
                stream=Stream(),
                clock=lambda: 0.0,
            )
            if isinstance(expected, bytes):
                self.assertEqual(
                    selected_vehicle_vin(profile, cache, bus_id=0x11), expected
                )
            else:
                with self.assertRaises(NativeDrsError) as caught:
                    selected_vehicle_vin(profile, cache, bus_id=0x11)
                self.assertEqual(caught.exception.code, expected)
            self.assertEqual(sent, [b"\x09\x02"] * sends)
            self.assertEqual(list(replies), [])

    def test_selected_vehicle_vin_keeps_shared_budget_and_cancellation(self):
        from scripts.monitor_support import MonitorSupportCache
        from scripts.toyota_session import Cancelled, Limits, SessionError

        profile = self.vin_profile()
        cancelled = False
        calls = []

        class Stream:
            def send(self, operation):
                nonlocal cancelled
                calls.append("send")
                cancelled = True
                return 0

            def receive(self, operation):
                raise AssertionError("Cancelled acquisition must stop before receive")

        cache = MonitorSupportCache(
            profile,
            lambda query: b"\x49\x00\x00\x40",
            "authoredECU",
            stream=Stream(),
            cancelled=lambda: cancelled,
            clock=lambda: 0.0,
        )
        with self.assertRaises(Cancelled):
            selected_vehicle_vin(profile, cache, bus_id=0x11)
        self.assertEqual(calls, ["send"])
        cancelled = False
        limited = MonitorSupportCache(
            profile,
            lambda query: b"\x49\x00\x00\x40",
            "authoredECU",
            stream=Stream(),
            limits=Limits(exchanges=1),
            clock=lambda: 0.0,
        )
        with self.assertRaisesRegex(SessionError, "budget"):
            selected_vehicle_vin(profile, limited, bus_id=0x11)
        self.assertEqual(calls, ["send"])

    def test_selected_vehicle_vin_runs_shared_native_communication_primitives(self):
        from scripts.native_communication import NativeCommunication

        profile = self.vin_profile()
        vin = b"AUTHOREDVIN123456"
        replies = iter((b"\x49\x00\x40", b"\x49\x02\x01" + vin))
        calls = []

        @dataclass(frozen=True)
        class Reply:
            code: int
            data: bytes

        class Operations:
            def send(self, request, **kwargs):
                calls.append(("send", request, kwargs))
                return 0

            def receive(self, **kwargs):
                calls.append(("receive", kwargs))
                return Reply(0, next(replies))

            def close(self):
                return 0

        communication = NativeCommunication(
            profile, Operations(), "authoredECU", bus_id=0x12, clock=lambda: 0.0
        )
        self.assertEqual(
            selected_vehicle_vin(profile, communication.cache, bus_id=0x12), vin
        )
        self.assertEqual([call[0] for call in calls], ["send", "receive"] * 2)
        self.assertEqual(
            [calls[index][1] for index in (0, 2)], [b"\x09\x00", b"\x09\x02"]
        )
        self.assertEqual([calls[index][2]["timeout"] for index in (0, 2)], [11, 11])
        self.assertEqual([calls[index][1]["timeout"] for index in (1, 3)], [13, 13])
        self.assertEqual(communication.calls, 4)

    def test_selected_vehicle_vin_native18_special_category_uses_extended103(self):
        from scripts.native_communication import NativeCommunication

        profile = self.vin_profile(vin_category=0x18D)
        vin = b"AUTHOREDVIN123456"
        for source_build in (12, 18):
            for payload in (b"\x49\x02\x01" + vin, b"\x49\x02\x01short"):
                with self.subTest(source_build=source_build, payload=payload):
                    calls = []
                    replies = iter(
                        (payload, payload)
                        if source_build == 18
                        else (b"\x49\x00\x40", payload)
                    )

                    @dataclass(frozen=True)
                    class Reply:
                        code: int
                        data: bytes

                    class Operations:
                        def send(self, request, calls=calls, **kwargs):
                            calls.append((request, kwargs))
                            return 0

                        def receive(self, replies=replies, **kwargs):
                            return Reply(0, next(replies))

                        def close(self):
                            return 0

                    communication = NativeCommunication(
                        profile,
                        Operations(),
                        "authoredECU",
                        bus_id=0x12,
                        source_build=source_build,
                        clock=lambda: 0.0,
                    )
                    if len(payload) < 20:
                        with self.assertRaises(NativeDrsError) as caught:
                            selected_vehicle_vin(
                                profile, communication.cache, bus_id=0x12
                            )
                        self.assertEqual(caught.exception.code, 0xA0040202)
                    else:
                        self.assertEqual(
                            selected_vehicle_vin(
                                profile, communication.cache, bus_id=0x12
                            ),
                            vin,
                        )
                    if source_build == 18 and len(payload) >= 20:
                        self.assertEqual(
                            selected_vehicle_vin(
                                profile, communication.cache, bus_id=0x12
                            ),
                            vin,
                        )
                    self.assertEqual(
                        [call[0] for call in calls],
                        [b"\x09\x02"] * (2 if len(payload) >= 20 else 1)
                        if source_build == 18
                        else [b"\x09\x00", b"\x09\x02"],
                    )
                    self.assertEqual(calls[-1][1]["no_session"], source_build == 18)
                    self.assertEqual(
                        calls[-1][1]["initialization_mode"],
                        2 if source_build == 18 else 1,
                    )
                    self.assertFalse(communication.no_init)
                    self.assertFalse(communication.no_session)

    def test_selected_vin_cache_multi_receive_and_mask_merge(self):
        from scripts.monitor_support import MonitorSupportCache

        profile = self.vin_profile()
        calls = []
        replies = iter(((0, b"\x49\x02a"), (0, b"\x49\x02b"), (0x91010009, b"")))

        class Stream:
            def send(self, operation):
                calls.append(("send", operation))
                return 0

            def receive(self, operation):
                calls.append(("receive", operation))
                return next(replies)

        def transaction(query):
            calls.append(("transaction", query))
            return b"\x49\x00\x40" if query.request == b"\x09\x00" else b"\x61\xa5"

        cache = MonitorSupportCache(
            profile,
            transaction,
            "authoredECU",
            stream=Stream(),
            bus_id=0x12,
            clock=lambda: 0.0,
        )
        result = selected_car_info_frames(profile, cache, bus_id=0x12)
        self.assertEqual(result.settings_words, (21, 23))
        self.assertEqual(result.ignored_initial_status, 0)
        self.assertEqual(
            result.initial[0].responses,
            ((b"\xff" * 3, b"\x49\x02a"), (b"\xff" * 3, b"\x49\x02b")),
        )
        self.assertEqual(result.checks[0].responses, ((b"\xff\xff", b"\x61\xa5"),))
        self.assertEqual(len(result.checks), 1)
        self.assertEqual(
            [kind for kind, _ in calls],
            ["transaction", "send", "receive", "receive", "receive", "transaction"],
        )
        self.assertTrue(
            all(
                value.query.native_parameter == 0x12
                if kind in ("send", "receive")
                else value.native_parameter == 0x12
                for kind, value in calls
            )
        )

    def test_vin_failed_frame_tries_next_and_native_negative_cache_is_retained(self):
        from scripts.monitor_support import MonitorSupportCache
        from scripts.toyota import ToyotaCodecError

        profile = self.vin_profile(alternate=True)
        calls = []

        def transaction(query):
            calls.append(query.request)
            if query.request == b"\x09\x00":
                raise ToyotaCodecError("initial timeout", 0x91010009)
            if query.request == b"\x21\x01":
                raise ToyotaCodecError("native no data", 0x90020323)
            return b"\x62\xa5"

        cache = MonitorSupportCache(
            profile, transaction, "authoredECU", clock=lambda: 0.0
        )
        result = selected_car_info_frames(profile, cache, bus_id=0x12)
        self.assertEqual(calls, [b"\x09\x00", b"\x21\x01", b"\x22\x01"])
        self.assertEqual(len(result.checks), 1)
        self.assertEqual(result.checks[0].request, b"\x22\x01")
        self.assertEqual(result.checks[0].responses, ((b"\xff\xff", b"\x62\xa5"),))
        self.assertEqual(result.settings_words, (11, 13))

    def test_vin_short_mask_uses_native_first_element_fallback(self):
        from scripts.monitor_support import MonitorSupportCache
        from scripts.toyota import ToyotaCodecError

        def transaction(query):
            if query.request == b"\x09\x00":
                raise ToyotaCodecError("initial timeout", 0x91010009)
            return b"\x61\xa5"

        profile = self.vin_profile(mask_a=b"\x0f")
        cache = MonitorSupportCache(
            profile, transaction, "authoredECU", clock=lambda: 0.0
        )
        result = selected_car_info_frames(profile, cache, bus_id=0x12)
        self.assertEqual(result.checks[0].responses, ((b"\xff\xff", b"\x61\xa5"),))
        profile = self.vin_profile(mask_a=b"")
        cache = MonitorSupportCache(
            profile, transaction, "authoredECU", clock=lambda: 0.0
        )
        with self.assertRaisesRegex(UnsupportedRecorderOperation, "empty-mask"):
            selected_car_info_frames(profile, cache, bus_id=0x12)

    def test_vin_absent_function_status_differs_from_malformed_metadata(self):
        from scripts.monitor_support import MonitorSupportCache

        profile = self.vin_profile()
        management = profile.catalog.management
        section = management.sections[18]
        rows = tuple(
            row for row in section.rows(16) if struct.unpack_from("<H", row, 2)[0] != 40
        )
        profile.catalog.management = replace(
            management,
            sections={
                **management.sections,
                18: replace(section, count=len(rows), payload=b"".join(rows)),
            },
        )
        cache = MonitorSupportCache(
            profile, lambda query: b"\x49\x00\x00", "authoredECU", clock=lambda: 0.0
        )
        with self.assertRaises(NativeDrsError) as raised:
            selected_car_info_frames(profile, cache, bus_id=0x12)
        self.assertEqual(raised.exception.code, 0xC0040101)
        profile = self.vin_profile()
        management = profile.catalog.management
        profile.catalog.management = replace(
            management,
            sections={
                **management.sections,
                17: replace(management.sections[17], count=0, payload=b"\0"),
            },
        )
        cache = MonitorSupportCache(
            profile, lambda query: b"", "authoredECU", clock=lambda: 0.0
        )
        with self.assertRaisesRegex(
            RecorderError, "Malformed selected VIN"
        ) as malformed:
            selected_car_info_frames(profile, cache, bus_id=0x12)
        self.assertNotIsInstance(malformed.exception, NativeDrsError)

    def test_selected_vin_plan_runs_actual_group27_primitives(self):
        from scripts.frame_transport import DriverProperties
        from scripts.monitor_support import MonitorSupportCache

        profile = self.vin_profile()

        def transaction(query):
            # A native initial85 error is ignored; normal checks still compile.
            if query.request == b"\x09\x00":
                from scripts.toyota import ToyotaCodecError

                raise ToyotaCodecError("authored initial timeout", 0x91010009)
            return b"\x61\xa5"

        cache = MonitorSupportCache(
            profile, transaction, "authoredECU", clock=lambda: 0.0
        )
        records = selected_car_info_plan(
            profile,
            cache,
            bus_id=0x12,
            driver=DriverProperties(0, b"04.04", "authoredReadVersion"),
            diagnostic_mode=bytes(16),
        )
        self.assertEqual(
            [r.table_id for r in records],
            [
                0x200,
                0x211,
                0x206,
                0x206,
                0x203,
                0x202,
                0x203,
                0x202,
                0x203,
                0x202,
                0x201,
            ],
        )
        expected = NativeReadExpectation.parse(records[7].payload)
        self.assertEqual(
            (expected.mask_data, expected.pattern_data),
            (bytes(4) + b"\xff\xff", bytes(4) + b"\x61\xa5"),
        )
        calls = []
        replies = iter((bytes(6), bytes(4) + b"\x61\xa5", bytes(6)))

        class Backend:
            def invoke(self, operation, fields, **kwargs):
                calls.append(operation)
                if operation == "connect":
                    return 19
                if operation == "read_messages":
                    return NativeMessage(6, 0, 0, 0, 0, next(replies))
                return None

        settings = DrsFile.parse(
            DrsFile(2, 0, (encode_command(0x27, {"children": records}),)).encode()
        )
        executor = NativeDrsExecutor(settings, Backend(), clock=lambda: 0.0)
        executor.execute_group(0x27)
        self.assertEqual(calls[0], "connect")
        self.assertEqual(calls[-1], "disconnect")
        self.assertEqual(calls.count("read_messages"), 3)

    def test_selected_vin_multi_plan_roundtrips_and_executes_all_checks(self):
        from scripts.frame_transport import DriverProperties
        from scripts.monitor_support import MonitorSupportCache

        profile = self.vin_profile()
        observed = iter(((0, b"\x49\x02a"), (0, b"\x49\x02b"), (0x91010009, b"")))

        class Stream:
            def send(self, operation):
                return 0

            def receive(self, operation):
                return next(observed)

        def transaction(query):
            return b"\x49\x00\x40" if query.request == b"\x09\x00" else b"\x61\xa5"

        cache = MonitorSupportCache(
            profile, transaction, "authoredECU", stream=Stream(), clock=lambda: 0.0
        )
        records = selected_car_info_plan(
            profile,
            cache,
            bus_id=0x12,
            driver=DriverProperties(0, b"04.04", "authoredReadVersion"),
            diagnostic_mode=bytes(16),
        )
        self.assertEqual(sum(r.table_id == 0x202 for r in records), 5)
        replies = iter(
            (
                bytes(7),
                bytes(4) + b"\x49\x02a",
                bytes(4) + b"\x49\x02b",
                bytes(4) + b"\x61\xa5",
                bytes(7),
            )
        )
        calls = []

        class Backend:
            def invoke(self, operation, fields, **kwargs):
                calls.append(operation)
                if operation == "connect":
                    return 19
                if operation == "read_messages":
                    return NativeMessage(6, 0, 0, 0, 0, next(replies))
                return None

        settings = DrsFile.parse(
            DrsFile(2, 0, (encode_command(0x27, {"children": records}),)).encode()
        )
        NativeDrsExecutor(settings, Backend(), clock=lambda: 0.0).execute_group(0x27)
        self.assertEqual(calls.count("write_messages"), 3)  # empty init is skipped.
        self.assertEqual(calls.count("read_messages"), 5)
        self.assertEqual(calls[-1], "disconnect")

    def test_vin_ignored_multi_status_and_host_cancellation_are_distinct(self):
        from scripts.monitor_support import MonitorSupportCache
        from scripts.toyota_session import Cancelled

        profile = self.vin_profile()
        calls = []

        class Stream:
            def send(self, operation):
                calls.append("send")
                return 0

            def receive(self, operation):
                calls.append("receive")
                return (0x90020323, b"")

        def transaction(query):
            return b"\x49\x00\x40" if query.request == b"\x09\x00" else b"\x61\xa5"

        cache = MonitorSupportCache(
            profile, transaction, "authoredECU", stream=Stream(), clock=lambda: 0.0
        )
        result = selected_car_info_frames(profile, cache, bus_id=0x12)
        self.assertEqual(
            (result.initial, result.ignored_initial_status), ((), 0x90020323)
        )
        self.assertEqual(len(result.checks), 1)
        self.assertEqual(calls, ["send", "receive"])

        def cancelled_query(query):
            raise Cancelled("authored cancellation")

        cache = MonitorSupportCache(
            profile, cancelled_query, "authoredECU", clock=lambda: 0.0
        )
        with self.assertRaises(Cancelled):
            selected_car_info_frames(profile, cache, bus_id=0x12)
        self.assertEqual(self.calls, [])

    def test_selected_check_mode_plan_emits_actual_protocol_groups(self):
        import tempfile
        from pathlib import Path

        from scripts.demo import create_demo
        from scripts.diagnostic_db import Section
        from scripts.frame_transport import DriverProperties
        from scripts.profiles import VehicleCatalog

        with tempfile.TemporaryDirectory() as tmp:
            root = create_demo(Path(tmp) / "authored")
            profile = VehicleCatalog(root / "Techstream_DB_NA").build_profile(1)
            category = bytearray(profile.category_record)
            category[72] = 6
            profile = replace(profile, category_record=bytes(category))
            management = profile.catalog.management
            functions = b"".join(
                struct.pack("<8H", 1, function, 1, key, 0, 1, 0, 0)
                for function, key in ((3, 1), (5, 2), (0x58, 3), (0x67, 1), (0x7F, 2))
            )
            comm = struct.pack("<12H", 1, 1, 2, 3, 2, 2, 3, 1, 3, 3, 0, 0)
            protocol = bytearray(28)
            struct.pack_into("<6H", protocol, 0, 1, 1, 0x33, 0x7DF, 0x7E0, 0xAB)
            protocol[24] = 0x12
            can = bytearray(28)
            struct.pack_into("<IIHHH", can, 0, 0x1234, 500000, 1, 0, 20)
            profile.catalog.management = replace(
                management,
                sections={
                    **management.sections,
                    18: Section(18, 0, 5, False, functions),
                    17: Section(17, 0, 3, False, comm),
                    13: Section(13, 0, 1, False, bytes(protocol)),
                    14: Section(14, 0, 1, False, bytes(can)),
                },
            )
            plan = selected_check_mode_plan(
                profile,
                bus_id=0x12,
                driver=DriverProperties(0, b"04.04", "authoredReadVersion"),
                diagnostic_mode=bytes(16),
            )
        self.assertEqual(
            [t.table_id for t in plan.diagnostic_setup],
            [0x200, 0x211, 0x206, 0x206, 0x203, 0x202],
        )
        self.assertEqual(
            [t.table_id for t in plan.diagnostic_end], [0x203, 0x202, 0x201]
        )
        change = decode_command(plan.change_mode[0])["message"]
        assert isinstance(change, NativeMessage)
        self.assertEqual(change.data, b"\0\0\x07\xe0\x21\0")
        self.assertEqual(change.extra_data_index, 6)
        self.assertEqual(
            NativeReadExpectation.parse(plan.change_mode[1].payload).mask_data,
            bytes(4) + b"\xff",
        )
        self.assertEqual(plan.sessions, ())
        replies = iter((0, 0, 0x22, 0x22, 0))
        calls = []

        class Backend:
            def invoke(self, operation, fields, **kwargs):
                calls.append(operation)
                if operation == "connect":
                    return 19
                if operation == "read_messages":
                    return NativeMessage(
                        6, 0, 0, 0, 0, bytes(4) + bytes((next(replies),)) + bytes(3)
                    )
                return None

        settings = DrsFile(
            2,
            0,
            tuple(
                encode_command(identity, {"children": children})
                for identity, children in (
                    (0x21, plan.diagnostic_setup),
                    (0x22, plan.diagnostic_end),
                    (0x23, plan.change_mode),
                    (0x24, plan.confirm_mode),
                )
            ),
        )
        executor = NativeDrsExecutor(
            DrsFile.parse(settings.encode()), Backend(), clock=lambda: 0.0
        )
        self.assertEqual(executor.check_mode(wait=lambda _: None), 1)
        self.assertEqual(calls[0], "connect")
        self.assertEqual(calls[-1], "disconnect")
        self.assertEqual(calls.count("read_messages"), 5)
        self.assertIsNone(executor.channel)

    def test_selected_p5_session_records_use_native_address_branch(self):
        import tempfile
        from pathlib import Path

        from scripts.demo import create_demo
        from scripts.diagnostic_db import Section
        from scripts.profiles import VehicleCatalog

        with tempfile.TemporaryDirectory() as tmp:
            root = create_demo(Path(tmp) / "authored")
            profile = VehicleCatalog(root / "Techstream_DB_NA").build_profile(1)
            category = bytearray(profile.category_record)
            category[72] = 20
            profile = replace(profile, category_record=bytes(category))
            management = profile.catalog.management
            rows = b"".join(
                struct.pack("<8H", 1, function, 1, key, 0, 1, 0, 0)
                for function, key in ((0xD1, 1), (0xD1, 2), (0xD2, 2))
            )
            protocol = bytearray(28)
            struct.pack_into("<H", protocol, 0, 1)
            struct.pack_into("<H", protocol, 8, 0x9876)
            protocol[24] = 7
            profile.catalog.management = replace(
                management,
                sections={
                    **management.sections,
                    18: Section(18, 0, 3, False, rows),
                    13: Section(13, 0, 1, False, bytes(protocol)),
                },
            )
            mode = bytearray(16)
            struct.pack_into("<I", mode, 8, 0xDEADBEEF)
            tables = selected_session_tables(
                profile, diagnostic_mode=bytes(mode), bus_id=0
            )
            self.assertEqual([table.table_id for table in tables], [0x28, 0x29])
            self.assertEqual(
                [decode_command(table)["data"] for table in tables],
                [b"\x21\0", b"\x30\0"],
            )
            self.assertEqual(
                [decode_command(table)["value_before_buffer"] for table in tables],
                [0xDEADBEEF] * 2,
            )
            fallback = selected_session_tables(
                profile, diagnostic_mode=bytes(16), bus_id=7
            )
            self.assertEqual(decode_command(fallback[0])["value_before_buffer"], 0x9876)
            with self.assertRaises(NativeDrsError) as error:
                selected_session_tables(profile, diagnostic_mode=bytes(16), bus_id=0)
            self.assertEqual(error.exception.code, 0xC0040602)
            category[72] = 6
            profile = replace(profile, category_record=bytes(category))
            self.assertEqual(
                selected_session_tables(profile, diagnostic_mode=b"", bus_id=0), ()
            )

    def test_selected_database_check_mode_frame_producers(self):
        import tempfile
        from pathlib import Path

        from scripts.demo import create_demo
        from scripts.diagnostic_db import Section
        from scripts.profiles import VehicleCatalog

        with tempfile.TemporaryDirectory() as tmp:
            root = create_demo(Path(tmp) / "authored")
            profile = VehicleCatalog(root / "Techstream_DB_NA").build_profile(1)
            management = profile.catalog.management
            rows = b"".join(
                struct.pack("<8H", 1, function, 1, key, 0, 1, 0, 0)
                for function, key in ((3, 1), (4, 2), (5, 1), (5, 2))
            )
            comm = struct.pack("<8H", 1, 1, 2, 3, 2, 2, 3, 1)
            settings = bytearray(management.sections[29].payload)
            struct.pack_into("<II", settings, 0, 0x11223344, 0x55667788)
            profile.catalog.management = replace(
                management,
                sections={
                    **management.sections,
                    18: Section(18, 0, 4, False, rows),
                    17: Section(17, 0, 2, False, comm),
                    29: Section(29, 0, 1, False, bytes(settings)),
                },
            )
            result = selected_check_mode_frames(profile)
            self.assertEqual(result.change.request, b"\x21\x00")
            self.assertEqual(result.change.receive_mask, b"\xff")
            self.assertEqual(result.change.receive_check, b"\x22\x00\x00\x00")
            self.assertEqual(result.change.settings_words, (0x11223344, 0x55667788))
            outgoing = NativeMessage(
                6, 0, 128, 999, 0, b"\xaa\xbb" + result.change.request
            )
            write, read = native_mode_exchange_tables(result.change, outgoing)
            self.assertEqual(decode_command(write)["timeout"], 0x11223344)
            expected = NativeReadExpectation.parse(read.payload)
            self.assertEqual(expected.initial_header_words, (6, 0, 128, 0, 0, 0))
            self.assertEqual(expected.mask_data, b"\0\0\xff")
            self.assertEqual(expected.pattern_data, b"\0\0\x22\0\0\0")
            self.assertEqual(expected.timeout, 0x55667788)

            class Backend:
                def invoke(self, operation, fields, **kwargs):
                    if operation == "connect":
                        return 19
                    if operation == "read_messages":
                        return NativeMessage(6, 0, 0, 0, 0, b"\x99\x88\x22\x01")
                    return None

            executor = NativeDrsExecutor(
                DrsFile(
                    2,
                    0,
                    (
                        encode_command(
                            0x21,
                            {
                                "children": (
                                    encode_command(
                                        0x200, {"protocol_id": 6, "flags": 128}
                                    ),
                                )
                            },
                        ),
                        encode_command(0x23, {"children": (write, read)}),
                    ),
                ),
                Backend(),
                clock=lambda: 0.0,
            )
            executor.execute_group(0x21)
            received = executor.execute_group(0x23)[-1]
            assert isinstance(received, NativeMessage)
            self.assertEqual(received.data, b"\x99\x88\x22\x01")
            executor.close()

            self.assertEqual(
                [frame.receive_mask for frame in result.confirm],
                [b"\x30\x00", b"\x22\x00\x00\x00"],
            )
            self.assertEqual(
                [frame.receive_check for frame in result.confirm],
                [frame.receive_mask for frame in result.confirm],
            )
            self.assertEqual(
                selected_check_mode_frames(profile, level=0).change.request, b"\x30\x00"
            )
            with self.assertRaises(NativeDrsError) as error:
                selected_check_mode_frames(profile, level=2)
            self.assertEqual(error.exception.code, 0xC0040C01)
            profile.catalog.management = replace(
                profile.catalog.management,
                sections={
                    **profile.catalog.management.sections,
                    18: Section(18, 0, 5, False, rows[:16] + rows),
                },
            )
            with self.assertRaises(NativeDrsError) as error:
                selected_check_mode_frames(profile)
            self.assertEqual(error.exception.code, 0xC0040102)

    def test_selected_database_metadata_to_native_capture_and_playback(self):
        import tempfile
        from pathlib import Path

        from scripts.demo import _ddb, create_demo
        from scripts.diagnostic_db import read_database
        from scripts.profiles import VehicleCatalog

        with tempfile.TemporaryDirectory() as tmp:
            root = create_demo(Path(tmp) / "authored")
            database_path = root / "Techstream_DB_NA" / "Toyota.ddb"
            database = read_database(database_path)
            sections = {
                key: (value.count, value.payload)
                for key, value in database.sections.items()
            }
            category = bytearray(sections[16][1])
            category[72] = 6
            sections[16] = (1, bytes(category))
            sections[19] = (
                1,
                "SelectCarTypVn10_DT.dll".encode("utf-16le").ljust(80, b"\0")
                + struct.pack("<3HBB", 0, 0, 0, 0x7D, 0),
            )
            database_path.write_bytes(_ddb(1, sections))
            profile = VehicleCatalog(root / "Techstream_DB_NA").build_profile(
                1, vehicle_name_key=10001
            )
            selection = selected_vehicle_context(
                profile,
                decision_row=0,
                answers=(1,),
                info_ids=(4,),
                vin=b"",
                text_encoding="ascii",
                source_build=18,
            )
            self.assertEqual(selection.car_info[0].text.data, b"Demo Model\0")
            self._assert_selected_metadata_capture(profile, selection)

    def test_automatic_vehicle_metadata_to_native_drs_capture_and_dm_playback(self):
        communication, _, _ = self.automatic_vehicle_runtime(phase=4)
        selector = NativeVehicleSelector(
            NativeVehicleSession(communication),
            info_ids=(4, 1, 3),
            text_encoding="ascii",
        )
        selector.select()
        selection = selector.answer(1, 1)
        assert selector.communication is not None
        profile = selector.catalog.build_profile(
            selector.communication.profile.category,
            exception_ids=selector.communication.profile.exception_ids,
            vehicle_name_key=selection.trailing_words[1],
        )
        self._assert_selected_metadata_capture(profile, selection)

    def _assert_selected_metadata_capture(self, profile, selection):
        observed = {key: False for key in (22, 12, 25, 11, 26, 29, 27, 28, 35)}
        observed[22] = True
        plan = selected_p4_monitor(
            profile,
            (1,),
            {12: b"\xff\xff"},
            observed,
            interface_id=19,
            excluded=0,
            max_request=10,
            max_reply=10,
            standard_values=(),
        )
        plan = replace(
            plan,
            signals=(
                replace(plan.signals[0], extended=(0x11223344, 0x55667788, 0x99AABBCC)),
            ),
        )
        self.monitor = selected_monitor_buffer(
            plan,
            phase=0,
            allocation_size=4096,
            name=b"selected\0",
            text_encoding="ascii",
        )
        self.parameters = replace(
            self.parameters,
            conditions=(
                replace(self.parameters.conditions[0], pid_id=1, parameter_value=12),
            ),
        )
        setup = tuple(
            NativeDmciCommand.from_neutral(item.command_id, item.values)
            for item in (*plan.commands.setup, *plan.commands.start)
        )
        stop = tuple(
            NativeDmciCommand.from_neutral(item.command_id, item.values)
            for item in plan.commands.stop
        )
        system = {
            "identifier": 1,
            "strings": [{"core": [1, 0], "data_hex": "00"}] * 2,
            "value_raw": 0,
        }
        settings = build_native_drs(
            selection,
            system,
            self.monitor,
            self.info,
            self.parameters,
            setup=setup,
            stop=stop,
        )
        parsed_settings = DrsFile.parse(settings.encode())
        self.assertEqual(
            decode_command(parsed_settings.tables[0])["selection"], selection
        )
        self.assertEqual(self.monitor.serial_mode, 1)
        signals = decode_command(self.monitor.signal_table)["signals"]
        assert isinstance(signals, tuple)
        signal = signals[0]
        assert isinstance(signal, NativeMonitorSignal)
        self.assertEqual(signal.scaling_words, (4, 1, 0))
        self.assertEqual(signal.strings[0].data, b"Engine speed\0")
        self.assertEqual(signal.trailing_words, plan.signals[0].extended)

        def exchange(request, *, deadline, cancelled):
            command, payload = decode_vim_command(request)
            self.calls.append(command)
            if command == 0x197F:
                stamp, value = next(self.values)
                empty = NativeCoreBuffer((1, 0), b"")
                reply = NativeMonitorReply(
                    0,
                    NativeDmciList(
                        (1, 0),
                        (
                            (
                                19,
                                NativeCoreBuffer(
                                    (1, 0),
                                    struct.pack("<I", stamp)
                                    + struct.pack(">H", value * 4),
                                ),
                            ),
                        ),
                    ),
                    (empty, empty, empty, empty, empty),
                    0,
                ).encode()
            else:
                if command == 0x157F:
                    self.assertEqual(payload, setup[0].encode())
                reply = bytes(4)
            return NativeVimReply(command | 0x80, 6, reply).encode()

        self.client.exchange = exchange
        capture = NativeMonitorRecorder(
            parsed_settings, self.client, interface_id=19, phase=0
        ).capture()
        self.assertEqual(capture.trigger_timestamp_ms, 2000)
        metadata = MonitorBuffer(
            b"selected", bytes(16), b"", b"", b"", b"", 0, (), (1,), b"", ()
        )
        result = capture.monitor_buffer(
            self.monitor, metadata, phase=0, block_packets=1
        )
        self.assertEqual(
            [p["timestamp_raw"] for p in monitor_packets(result)], [1000, 2000, 3000]
        )
        self.assertEqual(self.calls, [0x157F, 0x187F, 0x197F, 0x197F, 0x197F, 0x1A7F])

    def test_selected_p4_producer_to_native_drs_and_actual_acquisition(self):
        definitions = MonitorDefinitions(
            (7,), (MonitorRange(0, 7, 7, 0x10, 0, 0, 0),), (), "authored"
        )
        packing = pack_p4(
            definitions,
            {0x10: b"\xff"},
            capabilities=0x20,
            category_flags=6,
            excluded=0,
            max_request=64,
            max_reply=64,
        )
        plan = p4_setup_commands(
            packing,
            interface_id=19,
            buffer_468=0,
            total_length=1,
            standard_values=(),
            attribute_2_23=False,
        )
        setup = tuple(
            NativeDmciCommand.from_neutral(command.command_id, command.values)
            for command in (*plan.setup, *plan.start)
        )
        stop = tuple(
            NativeDmciCommand.from_neutral(command.command_id, command.values)
            for command in plan.stop
        )
        system = {
            "identifier": 3,
            "strings": [
                {"core": [1, 0], "data_hex": "41"},
                {"core": [1, 0], "data_hex": "42"},
            ],
            "value_raw": 7,
        }
        selection = NativeVehicleSelection(
            (1, 0),
            NativeCoreString((1, 0), b""),
            ((1, 0), (1, 0), (1, 0)),
            (),
            (),
            (),
            (0, 0),
        )
        settings = build_native_drs(
            selection,
            system,
            self.monitor,
            self.info,
            self.parameters,
            setup=setup,
            stop=stop,
        )
        self.assertEqual(
            [table.table_id for table in settings.tables],
            [1, 0x8100, 0x11, 0x12, 2, 5, 6],
        )
        settings = DrsFile.parse(settings.encode())
        original = self.client.exchange

        def exchange(request, *, deadline, cancelled):
            command, payload = decode_vim_command(request)
            if command == 0x167F:
                self.calls.append(command)
                self.assertEqual(payload, setup[0].encode())
                return NativeVimReply(command | 0x80, 6, bytes(4)).encode()
            return original(request, deadline=deadline, cancelled=cancelled)

        self.client.exchange = exchange
        capture = NativeMonitorRecorder(
            settings, self.client, interface_id=19, phase=0
        ).capture()
        self.assertEqual(capture.trigger_timestamp_ms, 2000)
        self.assertEqual(self.calls, [0x167F, 0x187F, 0x197F, 0x197F, 0x197F, 0x1A7F])

    def test_check_car_protocol_group_precedes_native_monitor_start(self):
        commands = (
            encode_command(0x200, {"protocol_id": 6, "flags": 0}),
            encode_command(
                0x203, {"timeout": 10, "message": NativeMessage(6, 0, 0, 0, 0, b"\x22")}
            ),
            encode_command(0x201, {}),
        )
        settings = replace(
            self.settings(),
            tables=self.settings().tables
            + (encode_command(0x27, {"children": commands}),),
        )
        test = self

        class Backend:
            def invoke(self, operation, fields, **kwargs):
                test.calls.append(operation)
                return 19 if operation == "connect" else None

        protocol = NativeDrsExecutor(settings, Backend(), clock=lambda: 0.0)
        recorder = NativeMonitorRecorder(
            settings, self.client, interface_id=19, phase=0, protocol=protocol
        )
        recorder.capture()
        self.assertEqual(
            self.calls[:4], ["connect", "write_messages", "disconnect", 0x187F]
        )
        self.assertEqual(self.calls[-1], 0x1A7F)
        self.calls.clear()
        with self.assertRaises(UnsupportedRecorderOperation):
            NativeMonitorRecorder(
                settings, self.client, interface_id=19, phase=0
            ).capture()
        self.assertEqual(self.calls, [])

    def test_capture_lease_rejects_same_and_shared_client_reentry(self):
        recorder = NativeMonitorRecorder(
            self.settings(), self.client, interface_id=19, phase=0
        )
        other = NativeMonitorRecorder(
            self.settings(), self.client, interface_id=19, phase=0
        )
        original = self.client.exchange

        def exchange(request, *, deadline, cancelled):
            if decode_vim_command(request)[0] == 0x187F:
                with self.assertRaisesRegex(RecorderError, "busy"):
                    other.capture()
                with self.assertRaisesRegex(RecorderError, "busy"):
                    recorder.capture()
            return original(request, deadline=deadline, cancelled=cancelled)

        self.client.exchange = exchange
        recorder.capture()
        self.assertEqual(recorder.state, "complete")
        self.assertEqual(other.state, "idle")
        self.assertFalse(self.client._capture_lock.locked())

    def test_stop_keyboard_interrupt_latches_fault_and_preserves_primary(self):
        original = self.client.exchange

        def exchange(request, *, deadline, cancelled):
            if decode_vim_command(request)[0] == 0x1A7F:
                raise KeyboardInterrupt()
            return original(request, deadline=deadline, cancelled=cancelled)

        self.client.exchange = exchange
        recorder = NativeMonitorRecorder(
            self.settings(), self.client, interface_id=19, phase=0
        )
        with self.assertRaises(KeyboardInterrupt):
            recorder.capture()
        self.assertEqual(recorder.state, "fault")
        self.assertFalse(self.client._capture_lock.locked())
        self.fail_read = True
        recorder = NativeMonitorRecorder(
            self.settings(), self.client, interface_id=19, phase=0
        )
        with self.assertRaises(OSError) as raised:
            recorder.capture()
        self.assertIn("stop also failed", raised.exception.__notes__[0])
        self.assertFalse(self.client._capture_lock.locked())

    def test_actual_dm_export_failure_restores_reference_before_save(self):
        self.info = NativeTriggerInfo((1, 0), 1, 2, 50)
        series, storage = self.series()
        with (
            patch.object(
                NativeRecorderCapture,
                "dm_bytes",
                side_effect=RecorderError("export failed"),
            ),
            self.assertRaisesRegex(RecorderError, "export failed"),
        ):
            series.run()
        self.assertEqual(series.recorder.recorder_state.reference_raw, 0)
        self.assertEqual(series.written, [])
        self.assertEqual(len(storage.files), 1)

    def test_persisted_raw_reference_initializes_sliding_trigger(self):
        self.info = NativeTriggerInfo((1, 0), 1, 2, 50)
        recorder = NativeMonitorRecorder(
            self.settings(),
            self.client,
            interface_id=19,
            phase=0,
            recorder_state=NativeRecorderState(0, 0),
        )
        capture = recorder.capture(
            trigger_event=lambda: self.fail("parameter trigger polled manual event")
        )
        self.assertEqual(capture.trigger_timestamp_ms, 1000)
        self.assertEqual(recorder.recorder_state.reference_raw, 1)
        self.assertEqual(self.calls, [0x187F, 0x197F, 0x197F, 0x1A7F])

    def test_capture_exports_native_dm_subbuffers_for_playback(self):
        recorder = NativeMonitorRecorder(
            self.settings(), self.client, interface_id=19, phase=0
        )
        capture = recorder.capture()
        metadata = MonitorBuffer(
            b"capture",
            bytes(16),
            b"description",
            b"",
            b"",
            b"",
            0,
            (),
            (7,),
            b"comment",
            (),
        )
        result = capture.monitor_buffer(
            self.monitor, metadata, phase=0, block_packets=1
        )
        capacity, available, start, read, write, written, size = struct.unpack_from(
            "<7I", result.ring_buffer, 10
        )
        self.assertEqual(
            (capacity, available, start, read, write, written, size),
            (4096, 4081, 0, 0, 15, 15, 4096),
        )
        compact = capture.monitor_buffer(
            replace(self.monitor, value_after_count=1),
            metadata,
            phase=0,
            block_packets=1,
        )
        self.assertEqual(
            struct.unpack_from("<7I", compact.ring_buffer, 10),
            (4096, 4081, 0, 0, 15, 15, 15),
        )
        self.assertEqual(monitor_packets(compact), monitor_packets(result))
        self.assertEqual(result.marker, 2000)
        self.assertEqual(result.comment, b"comment")
        self.assertEqual(
            [packet["timestamp_raw"] for packet in monitor_packets(result)],
            [1000, 2000, 3000],
        )
        signal = decode_signal_item(
            bytes.fromhex(decode_signal_table(result.signal_table)["items_hex"][0])
        ).to_dict()
        self.assertEqual(signal["version"], 4)
        self.assertEqual(signal["pid"], 7)

    def test_cancel_and_fault_always_stop_preserving_primary(self):
        self.cancel_read = True
        recorder = NativeMonitorRecorder(
            self.settings(), self.client, interface_id=19, phase=0
        )
        with self.assertRaises(RecorderCancelled):
            recorder.capture(cancelled=lambda: self.cancel_flag)
        self.assertEqual(self.calls[-1], 0x1A7F)
        self.assertEqual(recorder.state, "cancelled")
        self.cancel_flag = self.cancel_read = False
        self.fail_read = self.fail_stop = True
        recorder = NativeMonitorRecorder(
            self.settings(), self.client, interface_id=19, phase=0
        )
        with self.assertRaises(OSError) as error:
            recorder.capture()
        self.assertIn("stop also failed", error.exception.__notes__[0])
        self.assertEqual(recorder.state, "fault")


class NativeMonitorSignalTests(unittest.TestCase):
    def test_native_vehicle_selection_complete_lists(self):
        text = NativeCoreString((1, 0), b"VIN\0")
        names = NativeVehicleEntry((1, 0), (2, 3), text)
        car = NativeVehicleEntry((1, 0), (4,), text)
        option = NativeVehicleEntry((1, 0), (5,), text)
        selection = NativeVehicleSelection(
            (1, 0), text, ((1, 0), (1, 0), (1, 0)), (names,), (car,), (option,), (6, 7)
        )
        table = encode_command(1, {"selection": selection})
        self.assertEqual(
            table.payload[:14], bytes.fromhex("0100000001000000040056494e00")
        )
        self.assertEqual(table.payload[-4:], bytes.fromhex("06000700"))
        self.assertEqual(decode_command(table), {"selection": selection})
        for length in range(len(table.payload)):
            with self.subTest(length=length), self.assertRaises(RecorderError):
                decode_command(DrsTable(1, table.payload[:length]))
        with self.assertRaises(RecorderError):
            decode_command(DrsTable(1, table.payload + b"x"))

    def test_constructor_default_signal_slots_preserve_zero_length_strings(self):
        item = MonitorSignalMetadata(
            0, 0, 0, 0, "", b"", "", 0, 0, 0, 1, 1, 0, 0, 1, 0, (), (0, 1, 0)
        )
        monitor = native_monitor_buffer(
            7,
            (item, item),
            ((0, 1),),
            (0,),
            default_signal_slots=(1,),
            phase=0,
            allocation_size=4096,
            name=b"x",
            text_encoding="ascii",
        )
        signals = decode_command(monitor.signal_table)["signals"]
        assert isinstance(signals, tuple)
        self.assertEqual(tuple(x.data for x in signals[0].strings), (b"\0",) * 3)
        self.assertEqual(tuple(x.data for x in signals[1].strings), (b"",) * 3)
        for slots in ((-1,), (2,), (1, 1), (True,)):
            with self.subTest(slots=slots), self.assertRaises(RecorderError):
                native_monitor_buffer(
                    7,
                    (item, item),
                    ((0, 1),),
                    (0,),
                    default_signal_slots=slots,
                    phase=0,
                    allocation_size=4096,
                    name=b"x",
                    text_encoding="ascii",
                )
        with self.assertRaises(RecorderError):
            native_monitor_buffer(
                7,
                (replace(item, multiplier=2),),
                ((0, 1),),
                (0,),
                default_signal_slots=(0,),
                phase=0,
                allocation_size=4096,
                name=b"x",
                text_encoding="ascii",
            )

    def test_unassigned_short_name_retains_constructor_length(self):
        item = MonitorSignalMetadata(
            42, 0, 0, 7, "signal", b"", "unit", 0, 0, 0, 1, 1, 0, 0, 1, 0, (), (0, 1, 0)
        )
        monitor = native_monitor_buffer(
            7,
            (item,),
            ((0, 1),),
            (42,),
            phase=0,
            allocation_size=4096,
            name=b"x",
            text_encoding="ascii",
            unassigned_short_name_slots=(0,),
        )
        signals = decode_command(monitor.signal_table)["signals"]
        assert isinstance(signals, tuple)
        self.assertEqual(
            tuple(x.data for x in signals[0].strings), (b"signal\0", b"", b"unit\0")
        )
        for slots, candidate in (
            ((1,), item),
            ((0, 0), item),
            ((0,), replace(item, short_name=b"assigned")),
        ):
            with self.subTest(slots=slots), self.assertRaises(RecorderError):
                native_monitor_buffer(
                    7,
                    (candidate,),
                    ((0, 1),),
                    (42,),
                    phase=0,
                    allocation_size=4096,
                    name=b"x",
                    text_encoding="ascii",
                    unassigned_short_name_slots=slots,
                )

    def test_selected_terminal_vehicle_context_uses_native_info_ids(self):
        import tempfile
        from pathlib import Path

        from scripts.demo import _ddb, create_demo
        from scripts.diagnostic_db import read_database
        from scripts.profiles import VehicleCatalog

        with tempfile.TemporaryDirectory() as tmp:
            root = create_demo(Path(tmp) / "authored") / "Techstream_DB_NA"
            path = root / "Toyota.ddb"
            db = read_database(path)
            sections = {
                key: (value.count, value.payload) for key, value in db.sections.items()
            }
            categories = b"".join(
                row[:6] + struct.pack("<H", 10 + struct.unpack_from("<H", row, 4)[0])
                for row in db.sections[47].rows(8)
            )
            dll = "SelectCarTypVn10_DT.dll".encode("utf-16le").ljust(80, b"\0")
            sections[47] = (4, categories)
            sections[19] = (1, dll + struct.pack("<3HBB", 0, 0, 0, 0x7D, 0))
            path.write_bytes(_ddb(1, sections))
            catalog = VehicleCatalog(root)
            profile = catalog.build_profile(1, vehicle_name_key=10001)
            original_names = sections[43]
            sections[43] = (
                original_names[0] * 2,
                b"".join(row * 2 for row in db.sections[43].rows(12)),
            )
            path.write_bytes(_ddb(1, sections))
            duplicate_profile = VehicleCatalog(root).build_profile(
                1, vehicle_name_key=10001
            )
            duplicate_context = selected_vehicle_context(
                duplicate_profile,
                decision_row=0,
                answers=(1,),
                info_ids=(4,),
                vin=b"",
                text_encoding="ascii",
                source_build=18,
            )
            self.assertEqual(duplicate_context.car_info[0].text.data, b"\0")
            sections[43] = original_names
            original_options = sections[42]
            selected_option = next(
                row
                for row in db.sections[42].rows(16)
                if struct.unpack_from("<3H", row, 4) == (1, 1, 1)
            )
            foreign_option = bytearray(selected_option)
            struct.pack_into("<H", foreign_option, 4, 65535)
            sections[42] = (
                original_options[0] + 2,
                original_options[1] + bytes(foreign_option) + selected_option,
            )
            path.write_bytes(_ddb(1, sections))
            staged_profile = VehicleCatalog(root).build_profile(
                1, vehicle_name_key=10001
            )
            staged_context = selected_vehicle_context(
                staged_profile,
                decision_row=0,
                answers=(1,),
                info_ids=(4,),
                vin=b"",
                text_encoding="ascii",
                source_build=18,
            )
            self.assertEqual(staged_context.trailing_words, (0, 10001))
            sections[42] = original_options
            path.write_bytes(_ddb(1, sections))
            context = selected_vehicle_context(
                profile,
                decision_row=0,
                answers=(1,),
                info_ids=(12, 4, 11),
                vin=b"AUTHORED",
                text_encoding="ascii",
                source_build=18,
            )
            self.assertEqual(
                [entry.values for entry in context.select_names], [(12, 1), (11, 1)]
            )
            self.assertEqual([entry.values for entry in context.car_info], [(4,)])
            self.assertEqual(context.trailing_words, (0, 10001))
            self.assertEqual(context.vin.data, b"AUTHORED\0")
            self.assertEqual(NativeVehicleSelection.parse(context.encode()), context)
            self.assertEqual(
                [entry.text.data for entry in context.select_names],
                [b"Demo Model\0", b"Synthetic\0"],
            )
            for build in (12, 18):
                for module in (
                    "SelectCarVn10Brd_DT.dll",
                    "SelectCarVn10Std_DT.dll",
                    "SelectCarTypVn10_DT.dll",
                ):
                    sections[19] = (
                        1,
                        module.encode("utf-16le").ljust(80, b"\0")
                        + struct.pack("<3HBB", 0, 0, 0, 0x7D, 0),
                    )
                    sections[67] = (1, struct.pack("<IHH", 7, 10001, 0))
                    path.write_bytes(_ddb(1, sections))
                    regional = VehicleCatalog(root).build_profile(
                        1, vehicle_name_key=10001
                    )
                    ids = (11, 4, 18) if "Brd" in module else (11, 4)
                    value = selected_vehicle_context(
                        regional,
                        decision_row=0,
                        answers=(1,),
                        info_ids=ids,
                        vin=b"",
                        text_encoding="ascii",
                        source_build=build,
                    )
                    self.assertEqual(value.select_names[0].values, (11, 1))
                    self.assertEqual(
                        [entry.values for entry in value.car_info],
                        [(4,)],
                    )
                    ordered = selected_vehicle_context(
                        regional,
                        decision_row=0,
                        answers=(1,),
                        info_ids=(11, 65500, 4, 65500, 12, 65500),
                        vin=b"",
                        text_encoding="ascii",
                        source_build=build,
                    )
                    self.assertEqual(
                        [entry.values for entry in ordered.select_names],
                        [(11, 1), (65500, 1), (65500, 1), (12, 1), (65500, 1)],
                    )
                    self.assertEqual(
                        [entry.text.data for entry in ordered.select_names],
                        [b"Synthetic\0"] * 3 + [b"Demo Model\0"] * 2,
                    )
                    with self.assertRaises(NativeDrsError) as missing:
                        selected_vehicle_context(
                            regional,
                            decision_row=0,
                            answers=(1,),
                            info_ids=(65500,),
                            vin=b"",
                            text_encoding="ascii",
                            source_build=build,
                        )
                    self.assertEqual(missing.exception.code, 0xC0040001)
            with (
                patch("scripts.drive_recorder.MAX_RECORDER_BYTES", 80),
                self.assertRaisesRegex(RecorderError, "byte budget"),
            ):
                selected_vehicle_context(
                    profile,
                    decision_row=0,
                    answers=(1,),
                    info_ids=(11, 11, 11),
                    vin=b"",
                    text_encoding="ascii",
                    source_build=18,
                )
            native_row = bytearray(sections[41][1])
            struct.pack_into("<H", native_row, 40, 0)
            sections[41] = (2, bytes(native_row))
            path.write_bytes(_ddb(1, sections))
            zero_profile = VehicleCatalog(root).build_profile(1, vehicle_name_key=10001)
            zero = selected_vehicle_context(
                zero_profile,
                decision_row=0,
                answers=(1,),
                info_ids=(11,),
                vin=b"",
                text_encoding="ascii",
                source_build=18,
            )
            self.assertEqual(zero.select_names[0].values, (1, 0))
            self.assertEqual(zero.select_names[0].text.data, b"\0")
            catalog.vehicle_definitions[0]["raw_hex"] = bytes(native_row[:52]).hex()
            with self.assertRaisesRegex(RecorderError, "differs from its source"):
                selected_vehicle_context(
                    profile,
                    decision_row=0,
                    answers=(1,),
                    info_ids=(11,),
                    vin=b"",
                    text_encoding="ascii",
                    source_build=18,
                )
            catalog.vehicle_definitions[0]["raw_hex"] = (
                db.sections[41].rows(52)[0].hex()
            )
            for bad in (
                {"info_ids": (1,)},
                {"answers": ()},
                {"answers": (True,)},
                {"answers": (1.0,)},
                {"answers": ("1",)},
                {"answers": (-1,)},
                {"answers": (65536,)},
                {"source_build": 12.0},
                {"answers": (2,)},
                {"source_build": 13},
            ):
                kwargs: dict[str, Any] = {
                    "decision_row": 0,
                    "answers": (1,),
                    "info_ids": (11,),
                    "vin": b"",
                    "text_encoding": "ascii",
                    "source_build": 18,
                }
                kwargs.update(bad)
                with self.subTest(bad=bad), self.assertRaises(RecorderError):
                    selected_vehicle_context(profile, **kwargs)

    def test_native_monitor_buffer_nested_tables(self):
        monitor = NativeMonitorBuffer(
            7,
            4096,
            1,
            9,
            8192,
            encode_command(3, {"frames": ((0, 8),)}),
            encode_command(4, {"signals": ()}),
            NativeCoreString((1, 0), b"trip\0"),
            (1, 0),
            ((1, 0, 42),),
        )
        table = encode_command(2, {"monitor": monitor})
        self.assertEqual(table.payload[:18], struct.pack("<IIHII", 7, 4096, 1, 9, 8192))
        self.assertEqual(decode_command(table), {"monitor": monitor})
        empty = replace(monitor, selected_ids=())
        self.assertEqual(len(table.payload) - len(empty.encode()), 2)
        self.assertEqual(table.payload[-2:], bytes.fromhex("2a00"))
        for length in range(len(table.payload)):
            with self.subTest(length=length), self.assertRaises(RecorderError):
                decode_command(DrsTable(2, table.payload[:length]))
        with self.assertRaises(RecorderError):
            decode_command(DrsTable(2, table.payload + b"x"))

    def test_direct_drs_signal_layout_and_every_truncation(self):
        label = NativeCoreString((1, 0), b"X\0")
        display = NativeDisplayItem((2, 0), 12, label, (2, 8), 1)
        signal = NativeMonitorSignal(
            (1, 2, 3, 4),
            (label, label, label),
            (5, 6),
            1,
            (7, 8, 9),
            2,
            (10, 11),
            (1, 0),
            (display,),
            (13, 14, 15),
        )
        table = encode_command(4, {"signals": (signal,)})
        self.assertEqual(table.payload[:12], bytes.fromhex("010000000100020003000400"))
        self.assertEqual(table.payload[-12:], struct.pack("<3I", 13, 14, 15))
        self.assertEqual(decode_command(table), {"signals": (signal,)})
        for length in range(len(table.payload)):
            with self.subTest(length=length), self.assertRaises(RecorderError):
                decode_command(DrsTable(4, table.payload[:length]))
        with self.assertRaises(RecorderError):
            decode_command(DrsTable(4, table.payload + b"x"))
        with self.assertRaises(RecorderError):
            NativeDisplayItem((1, 0), 1, label, (0, 1), 2).encode()
        with self.assertRaisesRegex(UnsupportedRecorderOperation, "core version"):
            replace(display, core_words=(3, 0)).encode()
        future = bytearray(table.payload)
        # Signal display-list core starts after fixed fields and three strings;
        # target the display item's own core, not its containing list.
        display_offset = table.payload.index(display.encode())
        struct.pack_into("<H", future, display_offset, 3)
        with self.assertRaisesRegex(UnsupportedRecorderOperation, "core version"):
            decode_command(DrsTable(4, bytes(future)))


class OnboardServiceTests(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self.result = 0
        self.now = 0.0
        self.advance = False
        outer = self

        class Backend:
            def check(self, *args, **context):
                outer.calls.append(("check", args, context["deadline"]))
                return outer.result

            def execute(self, *args, **context):
                outer.calls.append(("execute", args, context["deadline"]))
                if outer.advance:
                    outer.now += 40
                return outer.result

            def cancel(self, **context):
                outer.calls.append(("cancel", (), context["deadline"]))
                return outer.result

        self.service = OnboardRecorderService(
            Backend(), "\\InternalCF", clock=lambda: self.now
        )

    def test_service_nonfinite_clock_preflight_and_active_ownership(self):
        for value in (float("nan"), float("inf"), float("-inf")):
            self.now = value
            with self.assertRaisesRegex(RecorderError, "clock must be finite"):
                self.service.update(switch_enabled=True)
            self.assertEqual(self.calls, [])
        self.now = 0.0
        original = self.service.backend.execute

        def execute(*args, **kwargs):
            result = original(*args, **kwargs)
            self.now = float("nan")
            return result

        with (
            patch.object(self.service.backend, "execute", execute),
            self.assertRaisesRegex(RecorderError, "clock must be finite"),
        ):
            self.service.update(switch_enabled=True)
        self.assertTrue(self.service.active)
        self.now = 0.0
        self.service.shutdown()
        self.assertFalse(self.service.active)
        self.assertEqual(self.calls[-1][0], "cancel")

    def test_switch_usb_and_shutdown_native_transitions(self):
        self.service.update(switch_enabled=True)
        self.assertTrue(self.service.active)
        self.assertEqual([x[0] for x in self.calls], ["check", "execute"])
        self.service.update(usb_connected=True)
        self.assertFalse(self.service.active)
        self.service.update(switch_enabled=True)
        self.assertEqual(len(self.calls), 3)
        self.service.update(usb_connected=False)
        self.assertTrue(self.service.active)
        self.service.shutdown()
        self.service.shutdown()
        self.assertEqual(
            [x[0] for x in self.calls],
            ["check", "execute", "cancel", "check", "execute", "cancel"],
        )
        with self.assertRaises(RecorderError):
            self.service.update()

    def test_check_failure_does_not_start_and_cancel_fault_preserves_active(self):
        self.result = 5
        self.service.update(switch_enabled=True)
        self.assertFalse(self.service.active)
        self.assertEqual(len(self.calls), 1)
        self.result = 0
        self.service.update()
        self.result = 9
        with self.assertRaises(RecorderError):
            self.service.update(switch_enabled=False)
        self.assertTrue(self.service.active)
        self.assertIsNotNone(self.service.fault)
        self.result = 0
        self.service.shutdown()
        self.assertFalse(self.service.active)

    def test_deadline_cancel_and_successful_start_timeout_state(self):
        with self.assertRaises(RecorderCancelled):
            self.service.update(switch_enabled=True, cancelled=lambda: True)
        self.assertEqual(self.calls, [])
        self.advance = True
        with self.assertRaises(TimeoutError):
            self.service.update()
        self.assertTrue(self.service.active)
        self.service.shutdown()
        with self.assertRaises(RecorderError):
            OnboardRecorderService(self.service.backend, "x").update(timeout=0)


class NativeDrsExecutorTests(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self.cancelled = False
        self.responses = []
        self.after = lambda: None
        test = self

        class Backend:
            def invoke(self, operation, fields, *, deadline, cancelled):
                test.calls.append((operation, fields))
                test.after()
                if operation == "connect":
                    return 19
                if operation == "read_messages":
                    return test.responses.pop(0)
                return None

        self.backend = Backend()
        self.message = NativeMessage(6, 0, 0, 0, 0, b"\x62\xf1")
        expectation = NativeReadExpectation(100, (6, 0, 0, 0, 0, 0), b"\xff", b"\x62")
        children = (
            encode_command(0x200, {"protocol_id": 6, "flags": 0}),
            DrsTable(0x202, expectation.encode()),
            encode_command(0x203, {"timeout": 10, "message": self.message}),
            encode_command(0x201, {}),
        )
        self.settings = DrsFile(0, 0, (encode_command(0x27, {"children": children}),))

    def test_channel_mask_read_status_and_native_order(self):
        self.responses = [NativeMessage(6, 1, 0, 0, 0, b""), self.message]
        executor = NativeDrsExecutor(self.settings, self.backend)
        results = executor.execute_group(0x27)
        self.assertEqual(results[1], self.message)
        self.assertEqual(
            [x[0] for x in self.calls],
            [
                "connect",
                "read_messages",
                "read_messages",
                "write_messages",
                "disconnect",
            ],
        )
        self.assertEqual(self.calls[1][1]["channel_id"], 19)
        self.assertIsNone(executor.channel)
        self.assertEqual(executor.execute_group(0x21), ())

    def test_mismatch_disconnects_and_has_native_error(self):
        self.responses = [NativeMessage(6, 0, 0, 0, 0, b"\x63")]
        executor = NativeDrsExecutor(self.settings, self.backend)
        with self.assertRaises(NativeDrsError) as raised:
            executor.execute_group(0x27)
        self.assertEqual(raised.exception.code, 0xA11F0201)
        self.assertEqual(self.calls[-1][0], "disconnect")
        self.assertEqual(executor.state, "fault")

    def test_cancellation_during_connect_closes_acquired_channel(self):
        self.after = lambda: setattr(self, "cancelled", True)
        executor = NativeDrsExecutor(self.settings, self.backend)
        with self.assertRaises(RecorderCancelled):
            executor.execute_group(0x27, cancelled=lambda: self.cancelled)
        self.assertEqual([x[0] for x in self.calls], ["connect", "disconnect"])
        self.assertIsNone(executor.channel)

    def test_conditional_mode_initial_and_changed_paths(self):
        check = self.settings.tables[0]
        children = decode_command(check)["children"]
        assert isinstance(children, tuple)
        settings = DrsFile(
            0,
            0,
            (
                encode_command(0x21, {"children": (children[0],)}),
                encode_command(0x24, {"children": (children[1],)}),
                encode_command(0x23, {"children": (children[2],)}),
                encode_command(0x22, {"children": (children[3],)}),
            ),
        )
        self.responses = [self.message]
        executor = NativeDrsExecutor(settings, self.backend)
        self.assertEqual(executor.check_mode(wait=lambda _: None), 0)
        self.assertEqual(
            [x[0] for x in self.calls], ["connect", "read_messages", "disconnect"]
        )
        self.calls.clear()
        self.responses = [NativeMessage(6, 0, 0, 0, 0, b"\x63"), self.message]
        waits = []
        self.assertEqual(executor.check_mode(wait=waits.append), 1)
        self.assertEqual(waits, [1.0])
        self.assertEqual(
            [x[0] for x in self.calls],
            [
                "connect",
                "read_messages",
                "write_messages",
                "read_messages",
                "disconnect",
            ],
        )

    def test_conditional_mode_seven_attempt_limit_and_cleanup(self):
        children = decode_command(self.settings.tables[0])["children"]
        assert isinstance(children, tuple)
        settings = DrsFile(
            0,
            0,
            tuple(
                encode_command(group, {"children": (child,)})
                for group, child in (
                    (0x21, children[0]),
                    (0x24, children[1]),
                    (0x23, children[2]),
                    (0x22, children[3]),
                )
            ),
        )
        self.responses = [NativeMessage(6, 0, 0, 0, 0, b"\x63")] * 8
        with self.assertRaises(NativeDrsError) as raised:
            NativeDrsExecutor(settings, self.backend).check_mode(wait=lambda _: None)
        self.assertEqual(raised.exception.code, 0xA11F0203)
        self.assertEqual(sum(x[0] == "write_messages" for x in self.calls), 7)
        self.assertEqual(self.calls[-1][0], "disconnect")

    def test_native_temp_state_and_absent_confirm_initial_fallback(self):
        state = NativeRecorderState.parse(bytes.fromhex("ffffffff01000000"))
        self.assertEqual(state.encode(), bytes.fromhex("ffffffff01000000"))
        with self.assertRaises(RecorderError):
            NativeRecorderState.parse(state.encode() + b"x")
        children = decode_command(self.settings.tables[0])["children"]
        assert isinstance(children, tuple)
        settings = DrsFile(
            0,
            0,
            (
                encode_command(0x21, {"children": (children[0],)}),
                encode_command(0x22, {"children": (children[3],)}),
                encode_command(0x23, {"children": (children[2],)}),
            ),
        )
        executor = NativeDrsExecutor(settings, self.backend, recorder_state=state)
        self.assertEqual(executor.check_mode(wait=lambda _: None), 0)
        self.assertEqual(executor.recorder_state.check_mode, 0)
        self.assertEqual([x[0] for x in self.calls], ["connect", "disconnect"])
        self.calls.clear()
        with self.assertRaises(NativeDrsError) as raised:
            executor.check_mode(wait=lambda _: None)
        self.assertEqual(raised.exception.code, 0x901F0105)
        self.assertEqual(
            [x[0] for x in self.calls], ["connect", "write_messages", "disconnect"]
        )

    def test_executor_reentry_cannot_steal_channel_or_reset_state(self):
        self.responses = [self.message]
        executor = NativeDrsExecutor(self.settings, self.backend)

        def reenter():
            self.assertEqual(executor.state, "executing")
            with self.assertRaisesRegex(RecorderError, "busy"):
                executor.execute_group(0x22)
            with self.assertRaisesRegex(RecorderError, "busy"):
                executor.close()

        self.after = reenter
        executor.execute_group(0x27)
        self.assertIsNone(executor.channel)
        self.assertEqual(executor.state, "idle")
        self.assertFalse(executor._execution_lock.locked())

    def test_entire_group_preflight_precedes_connect(self):
        children = (
            encode_command(0x200, {"protocol_id": 6, "flags": 0}),
            DrsTable(0x202, b""),
        )
        settings = DrsFile(0, 0, (encode_command(0x27, {"children": children}),))
        with self.assertRaises(RecorderError):
            NativeDrsExecutor(settings, self.backend).execute_group(0x27)
        self.assertEqual(self.calls, [])


if __name__ == "__main__":
    unittest.main()
