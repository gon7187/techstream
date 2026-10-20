"""Authored raw SDK recordings through real selected producers and DM parser."""

import copy
import hashlib
import json
import struct
import tempfile
import unittest
from pathlib import Path
from typing import Any

from test_monitor_variable import authored_profile

from scripts.demo import _ddb
from scripts.frame_transport import J2534Result, NativeMessage
from scripts.monitor_replay import (
    SCHEMA,
    MonitorRecording,
    MonitorReplay,
    load_monitor_recording,
    monitor_module_ids,
    sdk_value,
)
from scripts.snapshot import TableFile, encode_system_information, parse


def authored_document(root: Path, *, mode="normal", build=18):
    profile = authored_profile(root / "fixture")
    source = profile.catalog.root
    sections = {
        i: (s.count, s.payload) for i, s in profile.catalog.management.sections.items()
    }
    requests = (b"\2\12\0", b"\x13", b"\x10\x01", b"\x3e")
    offset, entries = 0, []
    for request in requests:
        entries.append(struct.pack("<IH", offset, len(request)))
        offset += len(request)
    sections[0] = (4, b"".join(entries + list(requests)))
    sections[17] = (
        4,
        struct.pack("<16H", 9, 1, 0, 0, 10, 2, 0, 0, 11, 3, 0, 0, 12, 4, 0, 0),
    )
    sections[18] = (
        3,
        b"".join(
            struct.pack("<8H", 1, fn, 1, frame, 0, count, 0, 0)
            for fn, frame, count in ((0x13, 10, 1), (0x67, 11, 0), (0x7F, 12, 0))
        ),
    )
    (source / "Toyota.ddb").write_bytes(_ddb(1, sections))
    if mode == "a8":
        from test_monitor_packet_a8 import profile as a8_profile

        a8 = a8_profile()
        category = bytearray(a8.category_record)
        category[: len("DemoEngine.ddb".encode("utf-16le"))] = "DemoEngine.ddb".encode(
            "utf-16le"
        )
        sections = {
            i: (item.count, item.payload)
            for i, item in a8.catalog.management.sections.items()
        }
        sections[16] = (1, bytes(category))
        (source / "Toyota.ddb").write_bytes(_ddb(1, sections))
        (source / "DemoEngine.ddb").write_bytes(
            _ddb(
                2,
                {
                    i: (item.count, item.payload)
                    for i, item in a8.database.sections.items()
                },
            )
        )
    if mode == "osc":
        instrument = bytearray(profile.category_record)
        instrument[:40] = bytes(40)
        encoded = "Instrument.ddb".encode("utf-16le")
        instrument[: len(encoded)] = encoded
        struct.pack_into("<H", instrument, 68, 999)
        sections[16] = (2, sections[16][1] + bytes(instrument))
        (source / "Toyota.ddb").write_bytes(_ddb(1, sections))
        instrument_sections = {
            i: (item.count, item.payload)
            for i, item in profile.database.sections.items()
        }
        rows = []
        for index in range(4):
            row = bytearray(profile.database.sections[10].payload[:84])
            struct.pack_into("<HH", row, 56, index + 1, 0)
            struct.pack_into("<HH", row, 62, index * 8, index * 8 + 7)
            row[79] = index + 1
            rows.append(bytes(row))
        instrument_sections[10] = (4, b"".join(rows))
        (source / "Instrument.ddb").write_bytes(_ddb(2, instrument_sections))
    if build == 12:
        from scripts.diagnostic_db import parse_database

        management_path = source / "Toyota.ddb"
        database = parse_database(management_path.read_bytes())
        sections = {
            i: (item.count, item.payload) for i, item in database.sections.items()
        }
        protocol = bytearray(sections[13][1][:24])
        protocol[22] = sections[13][1][24]
        sections[13] = (1, bytes(protocol))
        management_path.write_bytes(_ddb(1, sections))
        for path in source.glob("*.ddb"):
            database = parse_database(path.read_bytes())
            if database.kind == 2 and 14 in database.sections:
                ecu_sections = {
                    i: (item.count, item.payload)
                    for i, item in database.sections.items()
                }
                ecu_sections[14] = (0, b"")
                path.write_bytes(_ddb(2, ecu_sections))
            data = bytearray(path.read_bytes())
            struct.pack_into("<I", data, 28, 0x0100030C)
            path.write_bytes(data)
    context = {
        "source_build": build,
        "mode": mode if mode in ("dual", "variable") else "normal",
        "category": 1,
        "selected_ids": [4],
        "vehicle_name_key": None,
        "exception_ids": [],
        "source_files": {
            p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in source.glob("*.ddb")
        },
        "ecu": "engine",
        "bus_id": 0x12,
        "diagnostic_mode_hex": "00" * 16,
        "controller_flags": 4,
        "driver": {
            "version_status": 0,
            "api_version_hex": b"04.04".hex(),
            "source": "authored",
        },
        "device_kind": 8,
        "native_variant": "dual" if mode == "dual" else "normal",
        "initial_request_hex": "13",
        "observed_functions": {
            str(key): key == 11
            for key in (22, 10, 8, 9, 12, 25, 11, 26, 29, 27, 28, 35)
        },
        "selection": {
            "communication_protocol": 0x12,
            "attribute_3_31": False,
            "excluded": 0,
            "standard_values": [],
            "parameter_6": 1,
            "active_alias_pid": 0,
            "dynamic_requested": False,
            "routine_ids": [],
            "native_ecu": 1,
        },
        "metadata": {
            "phase": 0,
            "allocation_size": 4096,
            "name_hex": b"authored".hex(),
            "text_encoding": "utf-8",
            "system_information_hex": encode_system_information(
                {
                    "identifier": 1,
                    "strings": [
                        {"core": [1, 0], "data_hex": ""},
                        {"core": [1, 0], "data_hex": ""},
                    ],
                    "value_raw": 0,
                }
            ).hex(),
        },
        "limits": {"seconds": 30, "exchanges": 256},
        "packet_count": 1,
        "dual": {
            "retry_limit": 1,
            "send_timeout": 1000,
            "receive_timeout": 200,
            "map_values": [0, 0, 0],
        }
        if mode == "dual"
        else None,
        "oscilloscope": None,
        "variable": {"command_kind": 7, "command_ecu": 1, "standard_values": []}
        if mode == "variable"
        else None,
    }
    if mode == "a8":
        context.update(
            category=42,
            selected_ids=[17],
            controller_flags=9,
            initial_request_hex="a1010cff",
        )
        context["selection"]["native_ecu"] = 42
        context["observed_functions"] = {
            key: key == "8" for key in context["observed_functions"]
        }
    if mode == "osc":
        context["oscilloscope"] = {
            "selected_ids": [1, 2, 3, 4],
            "measure_time_range": None,
            "forward_time_range": None,
        }
    context["module_ids"] = dict(
        monitor_module_ids(
            build,
            "DM_ActVariable_DT.dll" if mode == "variable" else "DataMonitorPhase4.dll",
            mode == "dual",
        )
    )
    if mode in ("variable4", "variable4null"):
        context["mode"] = "variable"
        context["device_kind"] = 4
        context["variable"] = {
            "command_kind": 7,
            "command_ecu": 1,
            "standard_values": [],
            "init_mode": None,
            "parameter_c0": None,
        }
        context["vim"] = {
            "capabilities": ["denso-vim-control", "denso-vim-dmci"],
            "module_variant": "VS_x86",
        }
        context["module_ids"] = dict(
            monitor_module_ids(build, "DM_ActVariable_DT.dll", vim_variant="VS_x86")
        )
    if mode == "variable4null":
        add_primary(source, context, 2)
        context["variable"].update(command_kind=0x42, command_ecu=2)
    document = {
        "schema": SCHEMA,
        "source": "authored_synthetic",
        "context": context,
        "events": [
            {
                "kind": "sdk",
                "operation": "disconnect",
                "request": {},
                "result": sdk_value(J2534Result()),
                "elapsed_ms": 0,
                "tick": 1234,
            }
        ],
    }
    return source, document


class AuthoredCapture(MonitorRecording):
    """Fixture author only; the tested execution rereads its literal JSON output."""

    def __init__(self, document, *, commands=()):
        document = copy.deepcopy(document)
        if commands:
            document["events"] = [
                {
                    "kind": "host",
                    "operation": "enqueue",
                    "request": command,
                    "result": None,
                    "elapsed_ms": 0,
                    "tick": 1234,
                }
                for command in commands
            ]
        super().__init__(document)
        self.host_commands = list(commands)
        self.captured = []
        self.request = b""
        self.support_reads = 0
        self.sdk_reads = 0

    def next_host_command(self):
        if not self.host_commands:
            return None
        request = self.host_commands.pop(0)
        self.host_commands_left -= 1
        self.captured.append(
            {
                "kind": "host",
                "operation": "enqueue",
                "request": request,
                "result": None,
                "elapsed_ms": 0,
                "tick": 1234,
            }
        )
        return request

    def consume(self, kind, operation, request):
        if kind == "vim":
            from scripts.drive_recorder import (
                DMCI_WIRE_COMMANDS,
                NativeCoreBuffer,
                NativeDmciList,
                NativeMonitorReply,
                NativeVimReply,
                decode_vim_command,
            )

            wire, _ = decode_vim_command(request["data"])
            empty = NativeCoreBuffer((1, 0), b"")
            response = (
                NativeMonitorReply(
                    0,
                    NativeDmciList(
                        (1, 0),
                        (
                            (
                                self.context["category"],
                                NativeCoreBuffer(
                                    (1, 0), struct.pack("<I", 1234) + b"AB"
                                ),
                            ),
                        ),
                    ),
                    (empty, empty, empty, empty, empty),
                    0,
                ).encode()
                if wire == DMCI_WIRE_COMMANDS[0x10D]
                else bytes(4)
                + (struct.pack("<I", 1) if wire == DMCI_WIRE_COMMANDS[0x114] else b"")
            )
            result = NativeVimReply(wire | 0x80, 6, response).encode()
            encoded = sdk_value(result)
        elif kind == "osc":
            from scripts.monitor_instruments import OscRead

            result = OscRead(0, b"ABCD", 1000) if operation == "read_buffer" else 0
            encoded = sdk_value(result)
        elif kind == "support":
            if operation == "exchange":
                result = 0, b"\x61\x0cAB"
            elif operation == "send":
                result = 0, b""
            else:
                self.support_reads += 1
                result = (
                    (0, b"\x53\0\x09\x02\xff\xff")
                    if self.support_reads == 1
                    else (0x91010009, b"")
                )
            encoded = {"status": result[0], "data": result[1].hex()}
        else:
            if operation == "connect":
                result = J2534Result(handle=7)
            elif operation == "start_message_filter":
                result = J2534Result(handle=9)
            elif operation == "write_messages":
                self.request = request["messages"][0].data[4:]
                self.sdk_reads = 0
                result = J2534Result(count=1)
            elif operation == "read_messages":
                self.sdk_reads += 1
                if self.request[:1] in (b"\x13", b"\xa3") and self.sdk_reads > 1:
                    result = J2534Result(code=9)
                else:
                    if self.request == b"\x10\x01":
                        payload = b"\x50\x01"
                    elif self.request == b"\x13":
                        payload = b"\x53\0\x09\x02\xff\xff"
                    elif self.request[:1] == b"\xa1":
                        payload = b"\xe1" + self.request[1:]
                    elif self.request[:1] == b"\xa2":
                        payload = b"\xe2\x01AB"
                    elif self.request[:1] == b"\xa3":
                        payload = b"\xe3"
                    elif self.request[:1] == b"\x30":
                        payload = b"\x70" + self.request[1:2]
                    elif self.request[:1] == b"\x08":
                        payload = b"\x48" + self.request[1:2]
                    else:
                        payload = b"\x41" + self.request[1:2] + b"AB"
                    result = J2534Result(
                        count=1,
                        messages=(
                            NativeMessage(6, 0, 0, 1234, 0, b"\0\0\x07\xe8" + payload),
                        ),
                    )
            else:
                result = J2534Result()
            encoded = sdk_value(result)
        self.tick = 1234
        self.captured.append(
            {
                "kind": kind,
                "operation": operation,
                "request": sdk_value(request),
                "result": encoded,
                "elapsed_ms": 0,
                "tick": 1234,
            }
        )
        return result

    def assert_complete(self):
        pass


def capture_document(root: Path, *, mode="normal", build=18, commands=()):
    source, document = authored_document(root, mode=mode, build=build)
    author = AuthoredCapture(document, commands=commands)
    MonitorReplay(author, source).run()
    document["events"] = author.captured
    return source, document


class MonitorReplayTests(unittest.TestCase):
    def test_variable_native_host_queue_actual_results(self):
        commands = (
            {
                "command_id": 11,
                "signal_id": 4,
                "value": 0x1234,
                "auxiliary": 0,
                "initial_repeat": None,
            },
            {"command_id": 96, "signal_id": 0x1234},
            {"command_id": 12, "initialize": False},
        )
        for build in (12, 18):
            for mode in ("variable", "variable4", "variable4null"):
                with (
                    self.subTest(build=build, mode=mode),
                    tempfile.TemporaryDirectory() as directory,
                ):
                    source, document = capture_document(
                        Path(directory), build=build, mode=mode, commands=commands
                    )
                    host = [
                        event for event in document["events"] if event["kind"] == "host"
                    ]
                    self.assertEqual(
                        [event["request"] for event in host], list(commands)
                    )
                    self.assertTrue(all(event["result"] is None for event in host))
                    replay = MonitorReplay(
                        MonitorRecording.loads(json.dumps(document).encode()), source
                    )
                    report = replay.run()
                    self.assertEqual(
                        [item["command_id"] for item in report["result"]["commands"]],
                        [11, 96, 12],
                    )
                    self.assertTrue(
                        all(
                            item["completed"] and item["status"] == 0
                            for item in report["result"]["commands"]
                        )
                    )
                    self.assertTrue(report["result"]["playback"]["samples"])
                    self.assertIsInstance(parse(replay.outputs["monitor"]), TableFile)

    def test_host_queue_strict_schema_and_chronological_order(self):
        with tempfile.TemporaryDirectory() as directory:
            source, document = capture_document(
                Path(directory),
                mode="variable4",
                commands=({"command_id": 12, "initialize": False},),
            )
            index = next(
                i
                for i, event in enumerate(document["events"])
                if event["kind"] == "host"
            )
            for mutation in (
                "result",
                "boolean",
                "unknown",
                "secret",
                "order",
                "extra",
            ):
                bad = copy.deepcopy(document)
                host = bad["events"][index]
                if mutation == "result":
                    host["result"] = {"status": 0}
                elif mutation == "boolean":
                    host["request"]["initialize"] = 1
                elif mutation == "unknown":
                    host["request"]["command_id"] = 13
                elif mutation == "secret":
                    host["request"]["secret-password"] = "DO-NOT-PRINT"
                elif mutation == "order":
                    bad["events"].insert(0, bad["events"].pop(index))
                else:
                    bad["events"].append(copy.deepcopy(host))
                with (
                    self.subTest(mutation=mutation),
                    self.assertRaises(ValueError) as raised,
                ):
                    replay = MonitorReplay(
                        MonitorRecording.loads(json.dumps(bad).encode()), source
                    )
                    replay.run()
                self.assertNotIn("DO-NOT-PRINT", str(raised.exception))
                self.assertNotIn("secret-password", str(raised.exception))

    def test_host_queue_native_fault_completes_actual_command_and_capture(self):
        from scripts.drive_recorder import (
            DMCI_WIRE_COMMANDS,
            NativeVimReply,
            decode_vim_command,
        )

        with tempfile.TemporaryDirectory() as directory:
            source, document = authored_document(Path(directory), mode="variable4")

            class FaultCapture(AuthoredCapture):
                def consume(self, kind, operation, request):
                    if (
                        kind == "vim"
                        and decode_vim_command(request["data"])[0]
                        == DMCI_WIRE_COMMANDS[0x10F]
                    ):
                        wire, _ = decode_vim_command(request["data"])
                        result = NativeVimReply(
                            wire | 0x80, 6, struct.pack("<I", 0xC0040601)
                        ).encode()
                        self.captured.append(
                            {
                                "kind": kind,
                                "operation": operation,
                                "request": sdk_value(request),
                                "result": sdk_value(result),
                                "elapsed_ms": 0,
                                "tick": 1234,
                            }
                        )
                        return result
                    return super().consume(kind, operation, request)

            commands = (
                {
                    "command_id": 11,
                    "signal_id": 4,
                    "value": 1,
                    "auxiliary": 0,
                    "initial_repeat": None,
                },
            )
            author = FaultCapture(document, commands=commands)
            first = MonitorReplay(author, source).run()
            document["events"] = author.captured
            replay = MonitorReplay(
                MonitorRecording.loads(json.dumps(document).encode()), source
            )
            report = replay.run()
            self.assertEqual(report["result"]["commands"], first["result"]["commands"])
            self.assertTrue(report["result"]["commands"][0]["completed"])
            self.assertNotEqual(report["result"]["commands"][0]["status"], 0)
            self.assertEqual(
                report["result"]["commands"][0]["error_type"], "MonitorError"
            )
            self.assertTrue(report["result"]["playback"]["samples"])

    def test_host_queue_budget_and_cancellation_release_real_resources(self):
        for failure in ("budget", "cancel"):
            with (
                self.subTest(failure=failure),
                tempfile.TemporaryDirectory() as directory,
            ):
                source, document = authored_document(Path(directory), mode="variable4")
                author = AuthoredCapture(
                    document,
                    commands=({"command_id": 12, "initialize": False},)
                    * (257 if failure == "budget" else 2),
                )
                if failure == "cancel":
                    author.cancelled = lambda author=author: any(
                        event["kind"] == "host" for event in author.captured
                    )
                with self.assertRaises(Exception) as first:
                    MonitorReplay(author, source).run()
                document["events"] = author.captured
                recording = MonitorRecording.loads(json.dumps(document).encode())
                if failure == "cancel":
                    threshold = next(
                        i + 1
                        for i, event in enumerate(author.captured)
                        if event["kind"] == "host"
                    )
                    recording.cancelled = (
                        lambda recording=recording, threshold=threshold: (
                            recording.position >= threshold
                        )
                    )
                replay = MonitorReplay(recording, source)
                with self.assertRaises(type(first.exception)):
                    replay.run()
                recording.assert_complete()
                self.assertEqual(replay.outputs, {})

    def test_actual_normal_dual_variable_factories_and_native_dm(self):
        for mode in ("normal", "dual", "variable", "a8", "osc"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source, document = capture_document(root, mode=mode)
                recording_path = root / "recording.json"
                recording_path.write_text(json.dumps(document))
                replay = load_monitor_recording(recording_path, source)
                report = replay.run()
                self.assertEqual(report["status"], "completed")
                self.assertEqual(report["physical_status"], "PHYSICAL_UNCONFIRMED")
                samples = report["result"]["playback"]["samples"]
                self.assertEqual(samples[0]["values"][0]["raw_bits"], 0x4142)
                self.assertEqual(report["result"]["outputs"][0]["id"], "monitor")
                if mode == "osc":
                    osc = report["result"]["outputs"][1]
                    self.assertEqual(osc["id"], "oscilloscope")
                    self.assertTrue(osc["playback"]["samples"])
                    replay.save_dm(root / "osc.dm", stream="oscilloscope")
                    self.assertEqual(
                        (root / "osc.dm").read_bytes(), replay.outputs["oscilloscope"]
                    )
                assert replay.dm_bytes is not None
                self.assertIsInstance(parse(replay.dm_bytes), TableFile)
                destination = root / "result.dm"
                replay.save_dm(destination)
                self.assertEqual(destination.read_bytes(), replay.dm_bytes)
                with self.assertRaisesRegex(ValueError, "single-use"):
                    replay.run()
                with self.assertRaisesRegex(ValueError, "overwrite"):
                    replay.save_dm(recording_path)
                alias = root / "alias.dm"
                alias.hardlink_to(source / "Toyota.ddb")
                with self.assertRaisesRegex(ValueError, "overwrite"):
                    replay.save_dm(alias)

    def test_device4_variable_raw_vim_and_native_dm(self):
        for build in (12, 18):
            with self.subTest(build=build), tempfile.TemporaryDirectory() as directory:
                source, document = capture_document(
                    Path(directory), mode="variable4", build=build
                )
                self.assertTrue(
                    any(event["kind"] == "vim" for event in document["events"])
                )
                replay = MonitorReplay(
                    MonitorRecording.loads(json.dumps(document).encode()), source
                )
                report = replay.run()
                self.assertEqual(
                    report["result"]["playback"]["samples"][0]["values"][0]["raw_bits"],
                    0x4142,
                )

    def test_legacy_run_and_run87_real_factories(self):
        from scripts.drive_recorder import DrsFile

        for build in (12, 18):
            for phase, command, device in (
                (3, 9, 4),
                (3, 9, 8),
                (7, 56, 8),
                (3, 87, 8),
                (3, 87, 4),
            ):
                with (
                    self.subTest(
                        build=build, phase=phase, command=command, device=device
                    ),
                    tempfile.TemporaryDirectory() as directory,
                ):
                    source, document = capture_legacy_document(
                        Path(directory),
                        build=build,
                        phase=phase,
                        command=command,
                        device=device,
                    )
                    replay = MonitorReplay(
                        MonitorRecording.loads(json.dumps(document).encode()), source
                    )
                    result = replay.run()["result"]
                    if command == 87:
                        self.assertFalse(result["dm_export_available"])
                        raw = replay.outputs["recording"]
                        self.assertEqual(DrsFile.parse(raw).encode(), raw)
                        self.assertEqual(
                            result["outputs"][0]["native_settings"],
                            DrsFile.parse(raw).report(),
                        )
                        self.assertNotIn("playback", result)
                        replay.save_output(
                            Path(directory) / "actual.drs", stream="recording"
                        )
                        self.assertEqual(
                            (Path(directory) / "actual.drs").read_bytes(), raw
                        )
                        with self.assertRaisesRegex(ValueError, "overwrite"):
                            replay.save_output(
                                source / "Toyota.ddb", stream="recording"
                            )
                        with self.assertRaises(ValueError):
                            replay.save_dm(
                                Path(directory) / "wrong.dm", stream="recording"
                            )
                    else:
                        self.assertTrue(result["playback"]["samples"])

    def test_legacy_native_unsupported_no_fabricated_traffic(self):
        for build in (12, 18):
            for command, device, expected in ((56, 4, 0xC0051302), (87, 8, 0x90050405)):
                with (
                    self.subTest(build=build, command=command),
                    tempfile.TemporaryDirectory() as directory,
                ):
                    source, document, author = capture_legacy_document(
                        Path(directory),
                        build=build,
                        phase=7,
                        command=command,
                        device=device,
                        capture=False,
                    )
                    with self.assertRaises(Exception) as first:
                        MonitorReplay(author, source).run()
                    self.assertEqual(getattr(first.exception, "code", None), expected)
                    document["events"] = author.captured
                    replay = MonitorReplay(
                        MonitorRecording.loads(json.dumps(document).encode()), source
                    )
                    with self.assertRaises(type(first.exception)) as second:
                        replay.run()
                    self.assertEqual(getattr(second.exception, "code", None), expected)
                    replay.recording.assert_complete()
                    self.assertEqual(replay.outputs, {})

    def test_variable4_actual_fault_and_cancellation_cleanup(self):
        from scripts.drive_recorder import NativeVimReply, decode_vim_command

        for failure in ("native", "cancel"):
            with (
                self.subTest(failure=failure),
                tempfile.TemporaryDirectory() as directory,
            ):
                source, document = authored_document(Path(directory), mode="variable4")

                class FailedCapture(AuthoredCapture):
                    def consume(self, kind, operation, request, failure=failure):
                        if (
                            failure == "native"
                            and kind == "vim"
                            and not any(
                                event["kind"] == "vim" for event in self.captured
                            )
                        ):
                            wire, _ = decode_vim_command(request["data"])
                            result = NativeVimReply(
                                wire | 0x80, 6, struct.pack("<I", 0xC0040601)
                            ).encode()
                            self.captured.append(
                                {
                                    "kind": kind,
                                    "operation": operation,
                                    "request": sdk_value(request),
                                    "result": sdk_value(result),
                                    "elapsed_ms": 0,
                                    "tick": 1234,
                                }
                            )
                            return result
                        return super().consume(kind, operation, request)

                author = FailedCapture(document)
                if failure == "cancel":
                    author.cancelled = lambda author=author: any(
                        event["kind"] == "vim" for event in author.captured
                    )
                with self.assertRaises(Exception) as first:
                    MonitorReplay(author, source).run()
                document["events"] = author.captured
                replay_recording = MonitorRecording.loads(json.dumps(document).encode())
                if failure == "cancel":
                    threshold = next(
                        index + 1
                        for index, event in enumerate(author.captured)
                        if event["kind"] == "vim"
                    )
                    replay_recording.cancelled = (
                        lambda replay_recording=replay_recording, threshold=threshold: (
                            replay_recording.position >= threshold
                        )
                    )
                replay = MonitorReplay(replay_recording, source)
                with self.assertRaises(type(first.exception)):
                    replay.run()
                replay_recording.assert_complete()
                self.assertEqual(replay.outputs, {})

    def test_primary_retains_actual_selected_vehicle_context(self):
        with tempfile.TemporaryDirectory() as directory:
            source, document = authored_document(Path(directory), mode="variable4null")
            document["context"]["vehicle_name_key"] = 10001
            replay = MonitorReplay(MonitorRecording(document), source)
            assert replay.primary_profile is not None
            self.assertEqual(replay.primary_profile.vehicle_name_key, 10001)
            author = AuthoredCapture(document)
            MonitorReplay(author, source).run()
            document["events"] = author.captured
            self.assertEqual(
                MonitorReplay(
                    MonitorRecording.loads(json.dumps(document).encode()), source
                ).run()["status"],
                "completed",
            )

    def test_variable4_management_only_null_primary(self):
        for build in (12, 18):
            with self.subTest(build=build), tempfile.TemporaryDirectory() as directory:
                source, document = capture_document(
                    Path(directory), mode="variable4null", build=build
                )
                replay = MonitorReplay(
                    MonitorRecording.loads(json.dumps(document).encode()), source
                )
                report = replay.run()
                self.assertEqual(
                    report["result"]["playback"]["samples"][0]["values"][0]["pid"], "4"
                )
                self.assertEqual(len(report["result"]["outputs"]), 1)

    def test_vim_raw_stream_controls_and_explicit_module_variant(self):
        with tempfile.TemporaryDirectory() as directory:
            source, document = capture_document(Path(directory), mode="variable4")
            for mutation in ("truncated", "extra", "secret", "variant", "module"):
                bad = copy.deepcopy(document)
                if mutation == "truncated":
                    bad["events"].pop()
                elif mutation == "extra":
                    bad["events"].append(bad["events"][-1])
                elif mutation == "secret":
                    event = next(e for e in bad["events"] if e["kind"] == "vim")
                    event["request"]["data"] = {"bytes": b"DO-NOT-PRINT".hex()}
                elif mutation == "variant":
                    bad["context"]["vim"]["module_variant"] = "XP_x86"
                else:
                    del bad["context"]["module_ids"]["ComTol32.dll"]
                with (
                    self.subTest(mutation=mutation),
                    self.assertRaises(ValueError) as raised,
                ):
                    MonitorReplay(
                        MonitorRecording.loads(json.dumps(bad).encode()), source
                    ).run()
                self.assertNotIn("DO-NOT-PRINT", str(raised.exception))
                self.assertNotIn(b"DO-NOT-PRINT".hex(), str(raised.exception))
            malformed = copy.deepcopy(document)
            event = next(e for e in malformed["events"] if e["kind"] == "vim")
            event["request"]["data"] = {"bytes": "zz"}
            with self.assertRaises(ValueError):
                MonitorRecording.loads(json.dumps(malformed).encode())

    def test_variable4_cleanup_preserves_primary_host_exception(self):
        from scripts.drive_recorder import DMCI_WIRE_COMMANDS, decode_vim_command

        with tempfile.TemporaryDirectory() as directory:
            source, document = authored_document(Path(directory), mode="variable4")
            primary, secondary = (
                TimeoutError("primary sentinel"),
                RuntimeError("cleanup sentinel"),
            )

            class FailedCapture(AuthoredCapture):
                failed = False

                def vim_exchange(self, request, deadline, cancelled):
                    wire, _ = decode_vim_command(request)
                    if wire == DMCI_WIRE_COMMANDS[0x10D]:
                        self.failed = True
                        raise primary
                    if self.failed:
                        raise secondary
                    return super().vim_exchange(
                        request, deadline=deadline, cancelled=cancelled
                    )

            replay = MonitorReplay(FailedCapture(document), source)
            with self.assertRaises(TimeoutError) as raised:
                replay.run()
            self.assertIs(raised.exception, primary)
            self.assertEqual(replay.outputs, {})

    def test_legacy_management_primary_preserves_native_empty_path(self):
        for build in (12, 18):
            with self.subTest(build=build), tempfile.TemporaryDirectory() as directory:
                source, document, author = capture_legacy_document(
                    Path(directory), build=build, capture=False
                )
                add_primary(source, document["context"], 43)
                document["context"]["legacy"]["command_ecu"] = 43
                author.context = copy.deepcopy(document["context"])
                with self.assertRaises(Exception) as first:
                    MonitorReplay(author, source).run()
                self.assertEqual(getattr(first.exception, "code", None), 0xC0050001)
                document["events"] = author.captured
                replay = MonitorReplay(
                    MonitorRecording.loads(json.dumps(document).encode()), source
                )
                with self.assertRaises(type(first.exception)) as second:
                    replay.run()
                self.assertEqual(getattr(second.exception, "code", None), 0xC0050001)
                replay.recording.assert_complete()
                self.assertEqual(replay.outputs, {})

    def test_legacy_null_primary_exports_actual_selected_slot(self):
        for build in (12, 18):
            for phase, device in ((3, 4), (7, 8)):
                with (
                    self.subTest(build=build, phase=phase),
                    tempfile.TemporaryDirectory() as directory,
                ):
                    source, document, author = capture_legacy_document(
                        Path(directory),
                        build=build,
                        phase=phase,
                        device=device,
                        command=56,
                        capture=False,
                    )
                    add_primary(source, document["context"], 43)
                    document["context"]["legacy"]["command_ecu"] = 43
                    author.context = copy.deepcopy(document["context"])
                    MonitorReplay(author, source).run()
                    document["events"] = author.captured
                    replay = MonitorReplay(
                        MonitorRecording.loads(json.dumps(document).encode()), source
                    )
                    report = replay.run()
                    self.assertTrue(report["result"]["playback"]["samples"])
                    self.assertEqual(len(report["result"]["outputs"]), 1)
                    self.assertIsInstance(parse(replay.outputs["monitor"]), TableFile)

    def test_legacy_cancel_releases_actual_recorded_resources(self):
        from scripts.toyota_session import Cancelled

        for command in (9, 87):
            with (
                self.subTest(command=command),
                tempfile.TemporaryDirectory() as directory,
            ):
                source, document, author = capture_legacy_document(
                    Path(directory), command=command, capture=False
                )
                author.cancelled = lambda author=author: bool(author.captured)
                with self.assertRaises(Cancelled):
                    MonitorReplay(author, source).run()
                document["events"] = author.captured
                recording = MonitorRecording.loads(json.dumps(document).encode())
                recording.cancelled = lambda recording=recording: (
                    recording.position >= 1
                )
                replay = MonitorReplay(recording, source)
                with self.assertRaises(Cancelled):
                    replay.run()
                recording.assert_complete()
                self.assertEqual(replay.outputs, {})

    def test_native12_all_recorded_factories(self):
        for mode in ("normal", "dual", "variable", "a8", "osc"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                source, document = capture_document(
                    Path(directory), mode=mode, build=12
                )
                replay = MonitorReplay(
                    MonitorRecording.loads(json.dumps(document).encode()), source
                )
                result = replay.run()
                self.assertEqual(result["status"], "completed")
                self.assertEqual(
                    result["result"]["playback"]["samples"][0]["values"][0]["raw_bits"],
                    0x4142,
                )

    def test_order_truncation_extra_and_secret_safe_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            source, document = capture_document(Path(directory))
            for mutation in ("truncated", "extra", "secret"):
                value = copy.deepcopy(document)
                if mutation == "truncated":
                    value["events"].pop()
                elif mutation == "extra":
                    value["events"].append(value["events"][-1])
                else:
                    value["events"][0]["request"]["secret-password"] = "DO-NOT-PRINT"
                with (
                    self.subTest(mutation=mutation),
                    self.assertRaises(ValueError) as raised,
                ):
                    MonitorReplay(
                        MonitorRecording.loads(json.dumps(value).encode()), source
                    ).run()
                self.assertNotIn("DO-NOT-PRINT", str(raised.exception))
                self.assertNotIn("secret-password", str(raised.exception))

    def test_source_pins_and_untrusted_schema(self):
        with tempfile.TemporaryDirectory() as directory:
            source, document = capture_document(Path(directory))
            for key, value in (
                ("source_files", {"../secret": "0" * 64}),
                ("selected_ids", [True]),
                ("source_build", True),
                ("packet_count", 100001),
            ):
                bad = copy.deepcopy(document)
                bad["context"][key] = value
                with self.subTest(key=key), self.assertRaises(ValueError):
                    MonitorReplay(MonitorRecording(bad), source)
            (source / "DemoEngine.ddb").write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "identity"):
                MonitorReplay(MonitorRecording(document), source)

    def test_strict_duplicate_nonfinite_bytes_and_depth_budgets(self):
        for raw in (
            b'{"secret":"DO-NOT-PRINT","secret":1}',
            b'{"schema":NaN}',
            b"[" * 1200,
        ):
            with self.subTest(raw=raw[:10]), self.assertRaises(ValueError) as raised:
                MonitorRecording.loads(raw)
            self.assertNotIn("DO-NOT-PRINT", str(raised.exception))
        with self.assertRaises(ValueError):
            MonitorRecording.loads(b" " * (16 * 1024 * 1024 + 1))
        with tempfile.TemporaryDirectory() as directory:
            _, document = authored_document(Path(directory))
            document["events"][0]["result"]["data"] = {"bytes": "zz"}
            with self.assertRaises(ValueError):
                MonitorRecording(document)

    def test_cancel_and_native_driver_fault(self):
        with tempfile.TemporaryDirectory() as directory:
            source, document = capture_document(Path(directory))
            recording = MonitorRecording(document, cancelled=lambda: True)
            with self.assertRaises(InterruptedError):
                MonitorReplay(recording, source).run()
            fault = copy.deepcopy(document)
            event = next(
                event
                for event in fault["events"]
                if event["kind"] == "sdk" and event["operation"] == "connect"
            )
            event["result"] = sdk_value(J2534Result(code=7))
            replay = MonitorReplay(MonitorRecording(fault), source)
            with self.assertRaises(ValueError):
                replay.run()
            self.assertIsNone(replay.dm_bytes)

    def test_changed_source_after_load_and_unpinned_instrument(self):
        with tempfile.TemporaryDirectory() as directory:
            source, document = capture_document(Path(directory), mode="osc")
            bad = copy.deepcopy(document)
            del bad["context"]["source_files"]["Instrument.ddb"]
            recording = MonitorRecording(bad)
            with self.assertRaisesRegex(ValueError, "oscillator database"):
                MonitorReplay(recording, source)
            self.assertEqual(recording.position, 0)
            replay = MonitorReplay(MonitorRecording(document), source)
            (source / "Instrument.ddb").write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "source changed"):
                replay.run()
            self.assertEqual(replay.recording.position, 0)
            self.assertEqual(replay.outputs, {})

    def test_host_exception_identity_deadline_and_recorded_cancel_boundary(self):
        with tempfile.TemporaryDirectory() as directory:
            source, document = capture_document(Path(directory))
            sentinel = RuntimeError("authored host failure")

            def cancelled():
                raise sentinel

            with self.assertRaises(RuntimeError) as raised:
                MonitorReplay(MonitorRecording(document, cancelled), source).run()
            self.assertIs(raised.exception, sentinel)
            slow = copy.deepcopy(document)
            slow["events"][0]["elapsed_ms"] = 31000
            replay = MonitorReplay(MonitorRecording(slow), source)
            with self.assertRaisesRegex(RuntimeError, "deadline"):
                replay.run()
            self.assertIsNone(replay.dm_bytes)
            recorded_cancel = copy.deepcopy(document)
            event = next(
                event
                for event in recorded_cancel["events"]
                if event["kind"] == "sdk" and event["operation"] == "write_messages"
            )
            event["result"]["host_boundary"] = "cancelled_after"
            replay = MonitorReplay(MonitorRecording(recorded_cancel), source)
            with self.assertRaises(InterruptedError):
                replay.run()
            self.assertIsNone(replay.dm_bytes)

    def test_literal_byte_types_and_sdk_deadline_guard(self):
        with tempfile.TemporaryDirectory() as directory:
            _, document = authored_document(Path(directory))
            recording = MonitorRecording(document)
            with self.assertRaises(TimeoutError):
                recording.invoke("disconnect", {}, deadline=0, cancelled=lambda: False)
            self.assertEqual(recording.position, 0)

            document["events"][0]["request"] = {"token": {"bytes": "4142"}}
            recording = MonitorRecording(document)
            with self.assertRaisesRegex(ValueError, "mismatch"):
                recording.invoke(
                    "disconnect", {"token": "4142"}, deadline=1, cancelled=lambda: False
                )
            self.assertEqual(recording.position, 0)

    def test_module_identity_and_loaded_context_mutation_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            source, document = capture_document(Path(directory))
            bad = copy.deepcopy(document)
            bad["context"]["module_ids"]["DataMonitorPhase4.dll"] = "0" * 64
            with self.assertRaisesRegex(ValueError, "module source identity"):
                MonitorReplay(MonitorRecording(bad), source)
            replay = MonitorReplay(MonitorRecording(document), source)
            replay.context["module_ids"] = {}
            with self.assertRaisesRegex(ValueError, "context changed"):
                replay.run()
            self.assertEqual(replay.recording.position, 0)
            self.assertEqual(replay.outputs, {})

    def test_native_host_wait_advances_clock_and_enforces_deadline(self):
        with tempfile.TemporaryDirectory() as directory:
            source, document = authored_document(Path(directory))
            replay = MonitorReplay(MonitorRecording(document), source)
            operations = replay._operations()
            operations._wait_ms(125, 1)
            self.assertAlmostEqual(replay.recording.clock(), 0.125)
            self.assertEqual(replay.recording.position, 0)
            with self.assertRaises(TimeoutError):
                operations._wait_ms(1000, 0.2)
            self.assertLessEqual(replay.recording.clock(), 0.2)
            self.assertEqual(replay.recording.position, 0)
            for seconds in (True, -1, float("inf"), 3601):
                with self.subTest(seconds=seconds), self.assertRaises(ValueError):
                    replay.recording.wait(seconds)

    def test_cancelled_combined_capture_consumes_actual_release_events(self):
        with tempfile.TemporaryDirectory() as directory:
            source, document = authored_document(Path(directory), mode="osc")
            author = AuthoredCapture(document)
            author.cancelled = lambda: any(
                event["kind"] == "sdk" and event["operation"] == "read_messages"
                for event in author.captured
            )
            with self.assertRaises(InterruptedError) as authored_failure:
                MonitorReplay(author, source).run()
            document["events"] = author.captured
            cancel_after = next(
                index + 1
                for index, event in enumerate(author.captured)
                if event["kind"] == "sdk" and event["operation"] == "read_messages"
            )
            recording = MonitorRecording(document)
            recording.cancelled = lambda: recording.position >= cancel_after
            replay = MonitorReplay(recording, source)
            with self.assertRaises(type(authored_failure.exception)):
                replay.run()
            recording.assert_complete()
            self.assertIsNone(replay.dm_bytes)
            self.assertTrue(
                any(
                    event["kind"] == "osc"
                    and event["operation"] == "command"
                    and event["request"] == {"command": 1}
                    for event in author.captured[cancel_after:]
                )
            )
            self.assertEqual(author.captured[-1]["operation"], "disconnect")

    def test_dual_disconnect_failure_preserves_primary_host_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            source, document = authored_document(Path(directory), mode="dual")
            recording = AuthoredCapture(document)
            invoke = recording.invoke
            primary = TimeoutError("authored primary read failure")
            cleanup = RuntimeError("authored secondary disconnect failure")
            calls = []

            def primitive(operation, fields, *, deadline, cancelled):
                calls.append(operation)
                if operation == "read_messages":
                    raise primary
                if operation == "disconnect":
                    raise cleanup
                return invoke(operation, fields, deadline=deadline, cancelled=cancelled)

            recording.invoke = primitive
            replay = MonitorReplay(recording, source)
            with self.assertRaises(TimeoutError) as raised:
                replay.run()
            self.assertIs(raised.exception, primary)
            self.assertIn("disconnect", calls)
            self.assertTrue(any("RuntimeError" in note for note in primary.__notes__))
            self.assertIsNone(replay.dm_bytes)

    def test_explicit_ordered_profile_selection_bounds(self):
        with tempfile.TemporaryDirectory() as directory:
            source, document = authored_document(Path(directory))
            for field, value in (
                ("exception_ids", ""),
                ("exception_ids", [1] * 257),
                ("exception_ids", [True]),
                ("vehicle_name_key", 10001.0),
                ("vehicle_name_key", True),
            ):
                bad = copy.deepcopy(document)
                bad["context"][field] = value
                with (
                    self.subTest(field=field, value=str(value)[:20]),
                    self.assertRaises(ValueError),
                ):
                    MonitorReplay(MonitorRecording(bad), source)
            document["context"]["exception_ids"] = [2, 1, 2]
            replay = MonitorReplay(MonitorRecording(document), source)
            self.assertEqual(replay.profile.exception_ids, (2, 1, 2))


def capture_legacy_document(
    root: Path, *, build=18, phase=3, command=9, device=8, capture=True
) -> Any:
    from test_monitor_legacy import SelectedSupportIntegration

    from scripts.demo import _language
    from scripts.drive_recorder import (
        NativeCoreString,
        NativeTriggerInfo,
        NativeTriggerParameters,
        NativeVehicleSelection,
    )

    fixture = SelectedSupportIntegration()
    backend = fixture.run_backend()
    comm = fixture.run_communication(
        phase, build, backend, recording_protocol=command == 87
    )
    from scripts.profiles import VehicleProfile

    assert isinstance(comm.profile, VehicleProfile)
    source = root / "legacy"
    source.mkdir()
    sections = {
        key: (item.count, item.payload)
        for key, item in comm.profile.catalog.management.sections.items()
    }
    count, rows = sections[16]
    records = []
    for offset in range(0, len(rows), 76):
        row = bytearray(rows[offset : offset + 76])
        row[:40] = bytes(40)
        name = "DemoEngine.ddb".encode("utf-16le")
        row[: len(name)] = name
        records.append(bytes(row))
    sections[16] = (count, b"".join(records))
    for name, raw in (
        ("Toyota.ddb", _ddb(1, sections)),
        (
            "DemoEngine.ddb",
            _ddb(
                2,
                {
                    key: (item.count, item.payload)
                    for key, item in comm.profile.database.sections.items()
                },
            ),
        ),
        ("M_English.ddb", _language(list(comm.profile.catalog.language.strings))),
    ):
        raw = bytearray(raw)
        struct.pack_into("<I", raw, 28, comm.profile.catalog.management.version)
        (source / name).write_bytes(raw)
    # Reuse only the literal schema envelope, then replace all selected source inputs.
    _, template = authored_document(root / "template", build=build)
    ctx = template["context"]
    ctx.update(
        mode="legacy",
        category=42,
        selected_ids=[17],
        source_files={
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in source.glob("*.ddb")
        },
        bus_id=0x11,
        controller_flags=phase,
        initial_request_hex="2100",
        device_kind=device,
    )
    ctx["observed_functions"] = {
        str(key): value
        for key, value in fixture.observed(11 if phase == 3 else 26).items()
    }
    ctx["selection"].update(
        communication_protocol=0x11, attribute_3_31=None, native_ecu=42
    )
    ctx["module_ids"] = dict(
        monitor_module_ids(
            build,
            "DataMonitorPhase3.dll" if phase == 3 else "DataMonitorDKIso9141.dll",
            vim_variant="VS_x86" if device == 4 and command != 87 else None,
            recording=command == 87,
        )
    )
    selection = NativeVehicleSelection(
        (1, 0),
        NativeCoreString((1, 0), b"\0"),
        ((1, 0), (1, 0), (1, 0)),
        (),
        (),
        (),
        (0, 0),
    )
    ctx["legacy"] = {
        "command_id": command,
        "command_ecu": 42,
        "enable_mode": 0x10 if command == 87 else 65535,
        "shared_interface": 3,
        "init_mode": 1,
        "parameter_c0": 77,
        "standard_values": [],
        "vehicle_selection_hex": selection.encode().hex() if command == 87 else None,
        "trigger_info_hex": NativeTriggerInfo((1, 0), 1, 1, 0).encode().hex()
        if command == 87
        else None,
        "trigger_parameters_hex": NativeTriggerParameters(
            (1, 0), 1, 0, (1, 0), (), (1, 0), ()
        )
        .encode()
        .hex()
        if command == 87
        else None,
    }
    if device == 4 and command != 87:
        ctx["vim"] = {
            "capabilities": ["denso-vim-control", "denso-vim-dmci"],
            "module_variant": "VS_x86",
        }

    class LegacyCapture(AuthoredCapture):
        def consume(self, kind, operation, request):
            if kind != "sdk":
                return super().consume(kind, operation, request)
            result = backend.invoke(
                operation, request, deadline=30, cancelled=lambda: False
            )
            self.captured.append(
                {
                    "kind": kind,
                    "operation": operation,
                    "request": sdk_value(request),
                    "result": sdk_value(result),
                    "elapsed_ms": 0,
                    "tick": 1234,
                }
            )
            return result

    author = LegacyCapture(template)
    if not capture:
        return source, template, author
    MonitorReplay(author, source).run()
    template["events"] = author.captured
    return source, template


def add_primary(source, context, category):
    from scripts.diagnostic_db import parse_database
    from scripts.support import SCHEMAS, VERSION_SCHEMAS, word

    database = parse_database((source / "Toyota.ddb").read_bytes())
    sections = {
        key: (item.count, item.payload) for key, item in database.sections.items()
    }
    for slot, width, key_at in (
        (13, 24 if context["source_build"] == 12 else 28, 0),
        (16, 76, 68),
        (18, 16, 0),
    ):
        count, raw = sections[slot]
        rows = []
        for at in range(0, len(raw), width):
            row = bytearray(raw[at : at + width])
            if struct.unpack_from("<H", row, key_at)[0] != context["category"]:
                continue
            struct.pack_into("<H", row, key_at, category)
            if slot == 16:
                row[:40] = bytes(40)
            rows.append(bytes(row))
        schema = VERSION_SCHEMAS.get((database.version, 1, slot), SCHEMAS[(1, slot)])
        combined = [raw[at : at + width] for at in range(0, len(raw), width)] + rows
        combined.sort(
            key=lambda row: (word(row, schema.exception_offset), schema.key(row))
        )
        sections[slot] = (count + len(rows), b"".join(combined))
    raw = bytearray(_ddb(1, sections))
    struct.pack_into("<I", raw, 28, database.version)
    (source / "Toyota.ddb").write_bytes(raw)
    context["source_files"]["Toyota.ddb"] = hashlib.sha256(raw).hexdigest()
    context["primary"] = {
        "category": category,
        "ecu": "primary",
        "bus_id": context["bus_id"],
        "diagnostic_mode_hex": context["diagnostic_mode_hex"],
        "initial_request_hex": context["initial_request_hex"],
    }


if __name__ == "__main__":
    unittest.main()
