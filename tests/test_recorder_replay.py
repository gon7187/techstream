import json
import os
import struct
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from scripts.drive_recorder import (
    DrsFile,
    DrsTable,
    NativeCoreBuffer,
    NativeDmciList,
    NativeMonitorBuffer,
    NativeMonitorReply,
    NativeReadExpectation,
    NativeTriggerInfo,
    NativeVimReply,
    decode_command,
    encode_command,
)
from scripts.recorder_replay import (
    RecorderRecording,
    create_recorder_examples,
    replay_recorder,
    save_recorder_dm,
)
from scripts.snapshot import TableFile, parse, playback


class RecorderReplayTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for name, raw in create_recorder_examples().items():
            (self.root / name).write_bytes(raw)
        self.settings = self.root / "recorder-settings.drs"
        self.recording = self.root / "recorder-recording.json"
        self.document = json.loads(self.recording.read_bytes())

    def run_document(self, document=None, **options):
        if document is not None:
            self.recording.write_text(json.dumps(document))
        return replay_recorder(self.settings, self.recording, **options)

    def test_export_accepts_native_dm_larger_than_recording_budget(self):
        settings = DrsFile.parse(self.settings.read_bytes())
        monitor = decode_command(
            next(table for table in settings.tables if table.table_id == 2)
        )["monitor"]
        assert isinstance(monitor, NativeMonitorBuffer)
        monitor = replace(monitor, allocation_size=16 * 1024 * 1024)
        tables = tuple(
            encode_command(2, {"monitor": monitor}) if table.table_id == 2 else table
            for table in settings.tables
        )
        self.settings.write_bytes(replace(settings, tables=tables).encode())
        report = self.run_document()
        self.assertEqual(report["status"], "completed", report.get("error"))
        self.assertTrue(report["result"]["dm_export_available"])
        target = self.root / "large-native.dm"
        save_recorder_dm(target, report, sources=(self.settings, self.recording))
        self.assertGreater(target.stat().st_size, 16 * 1024 * 1024)
        self.assertIsInstance(parse(target.read_bytes()), TableFile)

    def test_actual_c9_threshold_capture_and_guarded_native_dm(self):
        report = self.run_document()
        self.assertEqual(report["status"], "completed", report)
        self.assertEqual(report["result"]["trigger_timestamp_raw"], 2000)
        self.assertEqual(
            [row["timestamp_raw"] for row in report["result"]["packets"]],
            [1000, 2000, 3000],
        )
        self.assertEqual(report["remaining_events"], 0)
        target = self.root / "capture.dm"
        save_recorder_dm(target, report, sources=(self.settings, self.recording))
        container = parse(target.read_bytes())
        assert isinstance(container, TableFile)
        self.assertEqual([table.id for table in container.tables], [0x8100, 0x8101])
        decoded = playback(container)
        self.assertEqual(
            [row["timestamp_raw"] for row in decoded["samples"]], [1000, 2000, 3000]
        )
        for source in (self.settings, self.recording):
            before = source.read_bytes()
            for kind in ("same", "symlink", "hardlink"):
                alias = (
                    source if kind == "same" else self.root / f"{source.name}-{kind}"
                )
                if kind == "symlink":
                    alias.symlink_to(source)
                if kind == "hardlink":
                    os.link(source, alias)
                with self.assertRaises(ValueError):
                    save_recorder_dm(
                        alias, report, sources=(self.settings, self.recording)
                    )
                self.assertEqual(source.read_bytes(), before)
        with self.assertRaises(OSError):
            save_recorder_dm(self.root, report, sources=(self.settings, self.recording))
        self.assertEqual(
            self.settings.read_bytes(),
            create_recorder_examples()["recorder-settings.drs"],
        )

    def test_context_and_duplicate_keys_fail_before_execution(self):
        for key, value in (
            ("phase", True),
            ("interface_id", -1),
            ("trigger_events", [False]),
            ("capabilities", []),
            ("limits", {"seconds": float("nan"), "max_polls": 3}),
            ("monitor_metadata_hex", "00"),
        ):
            with self.subTest(key=key):
                document = json.loads(json.dumps(self.document))
                document["context"][key] = value
                with self.assertRaises(ValueError):
                    RecorderRecording(document)
        self.recording.write_text('{"schema":1,"schema":2}')
        with self.assertRaises(ValueError):
            self.run_document()
        pipe = self.root / "pipe"
        os.mkfifo(pipe)
        with self.assertRaises(ValueError):
            replay_recorder(pipe, self.recording)

    def test_manual_tick_uses_native_batch_marker_and_following_snapshot(self):
        settings = DrsFile.parse(self.settings.read_bytes())
        self.settings.write_bytes(
            replace(
                settings,
                tables=tuple(
                    encode_command(5, {"trigger": NativeTriggerInfo((1, 0), 0, 2, 50)})
                    if table.table_id == 5
                    else table
                    for table in settings.tables
                ),
            ).encode()
        )
        for batches, marker, selected in (
            (((1000, 2000, 3000, 4000),), 2000, [1000, 2000, 3000]),
            (((1000,), (2000,)), 1000, [1000, 2000]),
        ):
            with self.subTest(batches=batches):
                document = json.loads(json.dumps(self.document))
                document["context"]["trigger_events"] = [2000]
                reads = []
                for stamps in batches:
                    event = json.loads(json.dumps(document["events"][1]))
                    empty = NativeCoreBuffer((1, 0), b"")
                    payload = NativeMonitorReply(
                        0,
                        NativeDmciList(
                            (1, 0),
                            (
                                (
                                    19,
                                    NativeCoreBuffer(
                                        (1, 0),
                                        b"".join(
                                            struct.pack("<IB", stamp, stamp // 1000)
                                            for stamp in stamps
                                        ),
                                    ),
                                ),
                            ),
                        ),
                        (empty, empty, empty, empty, empty),
                        0,
                    ).encode()
                    event["transaction"]["response"] = (
                        NativeVimReply(0x19FF, 6, payload).encode().hex()
                    )
                    reads.append(event)
                document["events"] = (
                    document["events"][:1] + reads + document["events"][-1:]
                )
                report = self.run_document(document)
                self.assertEqual(report["status"], "completed", report.get("error"))
                self.assertEqual(report["result"]["trigger_timestamp_raw"], marker)
                self.assertEqual(
                    [row["timestamp_raw"] for row in report["result"]["packets"]],
                    selected,
                )
                self.assertEqual(report["remaining_events"], 0)
                self.assertEqual(report["remaining_trigger_events"], 0)
                self.assertEqual(len(report["events"]), len(batches) + 2)
                native = parse(bytes.fromhex(report["result"]["native_dm_hex"]))
                assert isinstance(native, TableFile)
                # Native serial mode zero exports the full ring image, including
                # packets beyond the separately selected trigger window.
                self.assertEqual(
                    [row["timestamp_raw"] for row in playback(native)["samples"]],
                    [stamp for batch in batches for stamp in batch],
                )

    def test_cancel_consumes_actual_stop_and_repeat_succeeds(self):
        # A cancellation recording ends its data acquisition after the first poll.
        document = self.document
        document["events"] = document["events"][:2] + document["events"][-1:]
        document["context"]["trigger_events"] = []
        actual = []

        def construct(document):
            recording = RecorderRecording(document)
            actual.append(recording)
            return recording

        with patch("scripts.recorder_replay.RecorderRecording", side_effect=construct):
            report = self.run_document(
                document, cancelled=lambda: bool(actual) and actual[0].position >= 2
            )
        self.assertEqual(report["status"], "cancelled", report)
        self.assertEqual(
            report["events"][-1]["transaction"]["request"],
            document["events"][-1]["transaction"]["request"],
        )
        self.assertEqual(report["remaining_events"], 0)
        self.recording.write_bytes(
            create_recorder_examples()["recorder-recording.json"]
        )
        self.assertEqual(self.run_document()["status"], "completed")

    def test_heterogeneous_native_primitives_share_order_and_cleanup(self):
        settings = DrsFile.parse(self.settings.read_bytes())
        group = encode_command(
            0x27, {"children": (encode_command(0x200, {"protocol_id": 6, "flags": 0}),)}
        )
        self.settings.write_bytes(
            DrsFile(
                settings.header_word_1,
                settings.header_word_2,
                (*settings.tables, group),
            ).encode()
        )
        document = self.document
        document["context"]["capabilities"].append("native-drs-execution")
        document["events"][:0] = [
            {
                "kind": "j2534",
                "operation": "connect",
                "fields": {"protocol_id": 6, "flags": 0},
                "result": 19,
            },
            {
                "kind": "j2534",
                "operation": "disconnect",
                "fields": {"channel_id": 19},
                "result": None,
            },
        ]
        report = self.run_document(document)
        self.assertEqual(report["status"], "completed", report)
        self.assertEqual(
            [row["kind"] for row in report["events"][:3]], ["j2534", "j2534", "vim"]
        )
        document["events"][1], document["events"][2] = (
            document["events"][2],
            document["events"][1],
        )
        report = self.run_document(document)
        self.assertEqual(report["status"], "failed")
        self.assertIn("chronological", report["error"]["message"])

    def test_large_native_vim_reply_and_typed_read_result(self):
        settings = DrsFile.parse(self.settings.read_bytes())
        monitor = decode_command(
            next(table for table in settings.tables if table.table_id == 2)
        )["monitor"]
        assert isinstance(monitor, NativeMonitorBuffer)
        enlarged_settings = replace(
            settings,
            tables=tuple(
                encode_command(
                    2, {"monitor": replace(monitor, allocation_size=128 * 1024)}
                )
                if table.table_id == 2
                else table
                for table in settings.tables
            ),
        ).encode()
        document = self.document
        raw = b"".join(
            struct.pack("<IB", (index + 1) * 1000, min(255, index * 3 + 1))
            for index in range(14000)
        )
        empty = NativeCoreBuffer((1, 0), b"")
        payload = NativeMonitorReply(
            0,
            NativeDmciList((1, 0), ((19, NativeCoreBuffer((1, 0), raw)),)),
            (empty, empty, empty, empty, empty),
            0,
        ).encode()
        document["events"][1]["transaction"]["response"] = (
            NativeVimReply(0x19FF, 6, payload).encode().hex()
        )
        document["events"] = document["events"][:2] + document["events"][-1:]
        overflow = self.run_document(document)
        self.assertEqual(overflow["status"], "failed")
        self.assertIn("unread free space", overflow["error"]["message"])
        self.assertEqual(overflow["remaining_events"], 0)
        self.settings.write_bytes(enlarged_settings)
        report = self.run_document(document)
        self.assertEqual(report["status"], "completed", report)
        self.assertEqual(len(report["result"]["packets"]), 3)
        self.assertGreater(
            len(bytes.fromhex(report["events"][1]["transaction"]["response"])), 65535
        )
        settings = DrsFile.parse(self.settings.read_bytes())
        expectation = NativeReadExpectation(100, (6, 0, 0, 0, 0, 0), b"\xff", b"\x62")
        read = DrsTable(0x202, expectation.encode())
        group = encode_command(
            0x27,
            {"children": (encode_command(0x200, {"protocol_id": 6, "flags": 0}), read)},
        )
        self.settings.write_bytes(DrsFile(2, 0, (*settings.tables, group)).encode())
        document["context"]["capabilities"].append("native-drs-execution")
        fields = {
            "words": [expectation.timeout, *expectation.initial_header_words],
            "mask_data": expectation.mask_data.hex(),
            "pattern_data": expectation.pattern_data.hex(),
            "channel_id": 19,
        }
        message = {
            "protocol_id": 6,
            "rx_status": 0,
            "tx_flags": 0,
            "timestamp": 5,
            "extra_data_index": 0,
            "data_hex": "62f1",
        }
        document["events"][:0] = [
            {
                "kind": "j2534",
                "operation": "connect",
                "fields": {"protocol_id": 6, "flags": 0},
                "result": 19,
            },
            {
                "kind": "j2534",
                "operation": "read_messages",
                "fields": fields,
                "result": message,
            },
            {
                "kind": "j2534",
                "operation": "disconnect",
                "fields": {"channel_id": 19},
                "result": None,
            },
        ]
        report = self.run_document(document)
        self.assertEqual(report["status"], "completed", report)
        document["events"][1]["result"]["data_hex"] = "63"
        report = self.run_document(document)
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["events"][-1]["operation"], "disconnect")
        self.assertEqual(report["remaining_events"], 3)

    def test_native_check_mode_state_survives_reference_commit(self):
        settings = DrsFile.parse(self.settings.read_bytes())
        expectation = NativeReadExpectation(100, (6, 0, 0, 0, 0, 0), b"\xff", b"\x62")
        tables = tuple(
            encode_command(5, {"trigger": NativeTriggerInfo((1, 0), 7, 2, 50)})
            if table.table_id == 5
            else table
            for table in settings.tables
        )
        groups = (
            encode_command(
                0x21,
                {"children": (encode_command(0x200, {"protocol_id": 6, "flags": 0}),)},
            ),
            encode_command(
                0x24, {"children": (DrsTable(0x202, expectation.encode()),)}
            ),
        )
        self.settings.write_bytes(DrsFile(2, 0, (*tables, *groups)).encode())
        document = self.document
        document["context"]["capabilities"].append("native-drs-execution")
        document["context"]["recorder_state_hex"] = struct.pack(
            "<II", 0xFFFFFFFF, 1
        ).hex()
        document["events"][:0] = [
            {
                "kind": "j2534",
                "operation": "connect",
                "fields": {"protocol_id": 6, "flags": 0},
                "result": 19,
            },
            {
                "kind": "j2534",
                "operation": "read_messages",
                "fields": {
                    "words": [100, 6, 0, 0, 0, 0, 0],
                    "mask_data": "ff",
                    "pattern_data": "62",
                    "channel_id": 19,
                },
                "result": {
                    "protocol_id": 6,
                    "rx_status": 0,
                    "tx_flags": 0,
                    "timestamp": 0,
                    "extra_data_index": 0,
                    "data_hex": "62",
                },
            },
            {
                "kind": "j2534",
                "operation": "disconnect",
                "fields": {"channel_id": 19},
                "result": None,
            },
        ]
        report = self.run_document(document)
        self.assertEqual(report["status"], "completed", report)
        self.assertEqual(
            struct.unpack("<II", bytes.fromhex(report["result"]["recorder_state_hex"]))[
                1
            ],
            0,
        )

    def test_leftovers_and_missing_trigger_are_failures_without_fabricated_events(self):
        document = self.document
        document["context"].pop("monitor_metadata_hex")
        document["context"]["trigger_events"].append(None)
        report = self.run_document(document)
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["result"]["state"], "complete")
        self.assertEqual(len(report["result"]["packets"]), 3)
        self.assertFalse(report["result"]["dm_export_available"])
        self.assertEqual(report["remaining_trigger_events"], 1)
        document["context"]["trigger_events"] = []
        settings = DrsFile.parse(self.settings.read_bytes())

        tables = tuple(
            encode_command(5, {"trigger": NativeTriggerInfo((1, 0), 0, 2, 50)})
            if table.table_id == 5
            else table
            for table in settings.tables
        )
        self.settings.write_bytes(
            DrsFile(settings.header_word_1, settings.header_word_2, tables).encode()
        )
        report = self.run_document(document)
        self.assertEqual(report["status"], "failed")
        self.assertEqual(len(report["events"]), 1)
        self.assertGreater(report["remaining_events"], 0)


if __name__ == "__main__":
    unittest.main()
