"""Strict recorded VIM/J2534 execution for imported native recorder settings."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import struct
import tempfile
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from scripts.drive_recorder import (
    DrsFile,
    NativeCoreBuffer,
    NativeCoreString,
    NativeDmciCommand,
    NativeDmciList,
    NativeDrsError,
    NativeDrsExecutor,
    NativeMessage,
    NativeMonitorBuffer,
    NativeMonitorRecorder,
    NativeMonitorReply,
    NativeMonitorSignal,
    NativeRecorderState,
    NativeTriggerCondition,
    NativeTriggerInfo,
    NativeTriggerParameters,
    NativeVimClient,
    NativeVimError,
    NativeVimReply,
    RecorderCancelled,
    decode_vim_command,
    encode_command,
)
from scripts.local_files import read_regular
from scripts.native_replay import MAX_FILE, NativeReplay, _hex, _object
from scripts.snapshot import (
    DM_MAGIC,
    MonitorBuffer,
    TableFile,
    decode_frame_table,
    decode_monitor_buffer,
    decode_ring_buffer,
    decode_system_information,
    dumps,
    encode_monitor_buffer,
    encode_system_information,
    monitor_samples,
)
from scripts.snapshot import (
    MAX_BYTES as MAX_SNAPSHOT_BYTES,
)
from scripts.snapshot import parse as parse_snapshot
from scripts.toyota_session import NativeStatus

SCHEMA = "techstream-native-recorder-v1"
CAPABILITIES = frozenset({"denso-vim-control", "denso-vim-dmci"})


def _uint(value: Any) -> int:
    if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
        raise ValueError("Native recorder value must be uint32")
    return value


def _message(value: Any) -> NativeMessage:
    if not isinstance(value, dict) or set(value) != {
        "protocol_id",
        "rx_status",
        "tx_flags",
        "timestamp",
        "extra_data_index",
        "data_hex",
    }:
        raise ValueError("Explicit complete native message required")
    return NativeMessage(
        _uint(value["protocol_id"]),
        _uint(value["rx_status"]),
        _uint(value["tx_flags"]),
        _uint(value["timestamp"]),
        _uint(value["extra_data_index"]),
        _hex(value["data_hex"]),
    )


def _fields(operation: str, value: Any) -> dict:
    schemas = {
        "connect": {"protocol_id", "flags"},
        "disconnect": {"channel_id"},
        "read_messages": {"words", "mask_data", "pattern_data", "channel_id"},
        "write_messages": {"timeout", "message", "channel_id"},
        "start_message_filter": {"filter_type", "messages", "channel_id"},
        "set_config": {"parameters", "channel_id"},
        "five_baud_init": {"data", "value_after_data", "channel_id"},
        "fast_init": {"message", "channel_id"},
    }
    if (
        not isinstance(operation, str)
        or operation not in schemas
        or not isinstance(value, dict)
        or set(value) != schemas[operation]
    ):
        raise ValueError("Unexpected recorder primitive fields/operation")
    result = {}
    for key, child in value.items():
        if key in ("mask_data", "pattern_data", "data"):
            result[key] = _hex(
                child,
                max_bytes=4128 if key in ("mask_data", "pattern_data") else 0xFFFF,
            )
        elif key == "message":
            result[key] = _message(child)
        elif key == "messages":
            if not isinstance(child, list) or len(child) != 3:
                raise ValueError("Native filter requires three messages")
            result[key] = tuple(map(_message, child))
        elif key == "words":
            if not isinstance(child, list) or len(child) != 7:
                raise ValueError("Native read requires seven words")
            result[key] = tuple(map(_uint, child))
        elif key == "parameters":
            if (
                not isinstance(child, list)
                or len(child) > 65535
                or any(not isinstance(pair, list) or len(pair) != 2 for pair in child)
            ):
                raise ValueError("Native config requires uint32 pairs")
            result[key] = tuple(tuple(map(_uint, pair)) for pair in child)
        else:
            result[key] = _uint(child)
    return result


def _result(operation: str, value: Any) -> object:
    if operation == "connect":
        return _uint(value)
    if operation == "read_messages":
        return _message(value)
    if value is not None:
        raise ValueError("Native primitive returns no value")
    return None


class RecorderRecording:
    """One chronological cursor shared by VIM bytes and typed J2534 primitives."""

    def __init__(self, document: dict):
        if (
            not isinstance(document, dict)
            or set(document) != {"schema", "source", "context", "events"}
            or document["schema"] != SCHEMA
        ):
            raise ValueError("Unexpected recorder schema/fields")
        context = document["context"]
        required = {"capabilities", "interface_id", "phase", "trigger_events", "limits"}
        if (
            not isinstance(context, dict)
            or not required <= set(context)
            or not set(context)
            <= required
            | {"monitor_metadata_hex", "recorder_state_hex", "system_information_hex"}
        ):
            raise ValueError("Explicit complete recorder context required")
        capabilities = context["capabilities"]
        if (
            not isinstance(capabilities, list)
            or any(not isinstance(flag, str) for flag in capabilities)
            or len(set(capabilities)) != len(capabilities)
            or not CAPABILITIES
            <= set(capabilities)
            <= CAPABILITIES | {"native-drs-execution"}
        ):
            raise ValueError("Explicit native VIM control/DMCI capabilities required")
        _uint(context["interface_id"])
        if type(context["phase"]) is not int or context["phase"] not in (0, 1):
            raise ValueError("Native recorder phase must be explicitly 0 or 1")
        limits = context["limits"]
        if (
            not isinstance(limits, dict)
            or set(limits) != {"seconds", "max_polls"}
            or type(limits["seconds"]) not in (int, float)
            or not math.isfinite(limits["seconds"])
            or not 0 < limits["seconds"] <= 3600
            or type(limits["max_polls"]) is not int
            or not 1 <= limits["max_polls"] <= 100000
        ):
            raise ValueError("Explicit bounded recorder limits required")
        triggers = context["trigger_events"]
        if not isinstance(triggers, list) or len(triggers) > limits["max_polls"]:
            raise ValueError("Explicit per-poll trigger events required")
        for value in triggers:
            if value is not None:
                _uint(value)
        self.system_information = (
            decode_system_information(
                _hex(context["system_information_hex"], max_bytes=MAX_FILE)
            )
            if "system_information_hex" in context
            else None
        )
        self.recorder_state = (
            NativeRecorderState.parse(_hex(context["recorder_state_hex"]))
            if "recorder_state_hex" in context
            else None
        )
        self.metadata = (
            decode_monitor_buffer(
                _hex(context["monitor_metadata_hex"], max_bytes=MAX_FILE)
            )
            if "monitor_metadata_hex" in context
            else None
        )
        if self.metadata is not None:
            if (
                decode_ring_buffer(self.metadata.ring_buffer)["phase"]
                != context["phase"]
            ):
                raise ValueError(
                    "Observed monitor metadata phase differs from recording"
                )
            decode_frame_table(self.metadata.frame_table)
        self.events, self.position, self.trigger_position, self.trace = (
            document["events"],
            0,
            0,
            [],
        )
        if not isinstance(self.events, list) or not 1 <= len(self.events) <= 100000:
            raise ValueError("Invalid recorder event count")
        pdus = []
        self.primitives = {}
        for index, event in enumerate(self.events):
            if not isinstance(event, dict):
                raise TypeError("Recorder event must be an object")
            if event.get("kind") == "vim" and set(event) == {"kind", "transaction"}:
                pdus.append(event["transaction"])
            elif event.get("kind") == "j2534" and set(event) in (
                {"kind", "operation", "fields", "result"},
                {"kind", "operation", "fields", "error"},
            ):
                if "native-drs-execution" not in capabilities:
                    raise ValueError("Recorded primitive execution capability required")
                operation = event["operation"]
                fields = _fields(operation, event["fields"])
                if "error" in event:
                    error = event["error"]
                    if not isinstance(error, dict) or set(error) != {"code"}:
                        raise ValueError(
                            "Recorded primitive error requires native code"
                        )
                    code = _uint(error["code"])
                    if code == 0:
                        raise ValueError("Recorded native error code must be nonzero")
                    result = NativeDrsError(code)
                else:
                    result = _result(operation, event["result"])
                self.primitives[index] = (operation, fields, result)
            else:
                raise ValueError("Unexpected recorder event fields/kind")
        self.replay = NativeReplay(
            {
                "schema": "techstream-native-exchange-v1",
                "source": document["source"],
                "ecus": ["vim"],
                "support": {},
                "transactions": pdus,
            },
            max_pdu_bytes=MAX_FILE,
        )
        self.context, self.source = context, document["source"]

    @staticmethod
    def check(deadline: float, cancelled: Callable[[], bool]) -> None:
        if cancelled():
            raise RecorderCancelled("Recorded recorder operation cancelled")
        if time.monotonic() >= deadline:
            raise TimeoutError("Recorded recorder operation deadline exceeded")

    def next(self, kind: str) -> dict:
        if (
            self.position >= len(self.events)
            or self.events[self.position]["kind"] != kind
        ):
            raise ValueError(
                f"Recorder chronological {kind} mismatch at event {self.position}"
            )
        return self.events[self.position]

    def consume(self, event: dict) -> None:
        self.trace.append({"index": self.position, **event})
        self.position += 1

    def __call__(
        self, request: bytes, *, deadline: float, cancelled: Callable[[], bool]
    ) -> bytes:
        self.check(deadline, cancelled)
        event = self.next("vim")
        before = self.replay.position
        try:
            return self.replay.exchange("vim", request)
        finally:
            if self.replay.position != before:
                self.consume(event)

    def invoke(
        self,
        operation: str,
        fields: Mapping[str, object],
        *,
        deadline: float,
        cancelled: Callable[[], bool],
    ) -> object:
        self.check(deadline, cancelled)
        event = self.next("j2534")
        expected, arguments, result = self.primitives[self.position]
        if operation != expected or dict(fields) != arguments:
            raise ValueError(
                f"Recorder primitive mismatch at event {self.position}: {operation}"
            )
        self.consume(event)
        if isinstance(result, NativeDrsError):
            raise result
        return result

    def trigger(self) -> int | None:
        values = self.context["trigger_events"]
        if self.trigger_position >= len(values):
            raise ValueError("Recorded trigger events exhausted")
        value = values[self.trigger_position]
        self.trigger_position += 1
        return value

    def complete(self) -> None:
        self.replay.assert_complete()
        if self.position != len(self.events) or self.trigger_position != len(
            self.context["trigger_events"]
        ):
            raise ValueError("Recorder events remain unconsumed")


def replay_recorder(
    settings_path: str | Path,
    recording_path: str | Path,
    *,
    timeout: float = 30,
    max_polls: int = 100000,
    cancelled: Callable[[], bool] | None = None,
) -> dict:
    """Run actual native engines against a complete chronological recording."""
    if (
        type(timeout) not in (int, float)
        or not math.isfinite(timeout)
        or not 0 < timeout <= 3600
        or type(max_polls) is not int
        or not 1 <= max_polls <= 100000
    ):
        raise ValueError("Invalid recorder execution bounds")
    raw, settings_raw = (
        read_regular(recording_path, limit=MAX_FILE),
        read_regular(settings_path, limit=MAX_FILE),
    )
    if len(raw) + len(settings_raw) > MAX_FILE:
        raise ValueError("Recorder inputs exceed aggregate 16 MiB")
    try:
        document = json.loads(raw, object_pairs_hook=_object)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise ValueError("Invalid recorder recording JSON") from error
    recording = RecorderRecording(document)
    settings = DrsFile.parse(settings_raw)
    context = recording.context
    client = NativeVimClient(recording, capabilities=frozenset(context["capabilities"]))
    executor = NativeDrsExecutor(
        settings, recording, recorder_state=recording.recorder_state
    )
    recorder = NativeMonitorRecorder(
        settings,
        client,
        interface_id=context["interface_id"],
        phase=context["phase"],
        protocol=executor,
    )
    if (
        recording.metadata is not None
        and decode_ring_buffer(recording.metadata.ring_buffer)["block_packets"]
        != recorder.monitor.block_packets
    ):
        raise ValueError("Observed monitor block size differs from native settings")
    report = {
        "workflow": "recorder_replay",
        "source": recording.source,
        "physical_status": "PHYSICAL_UNCONFIRMED",
        "source_paths": [
            str(Path(settings_path).resolve()),
            str(Path(recording_path).resolve()),
        ],
        "settings_sha256": hashlib.sha256(settings_raw).hexdigest(),
        "recording_sha256": hashlib.sha256(raw).hexdigest(),
        "context": context,
        "status": "running",
        "result": {},
    }
    try:
        capture = recorder.capture(
            timeout=min(timeout, context["limits"]["seconds"]),
            max_polls=min(max_polls, context["limits"]["max_polls"]),
            cancelled=cancelled or (lambda: False),
            trigger_event=recording.trigger,
        )
        samples = []
        selected_signals = recorder.signals[:256]
        preview_count = min(
            len(capture.packets), 10000, 100000 // max(1, len(selected_signals))
        )
        for index, packet in enumerate(capture.packets[:preview_count]):
            values = []
            for signal in selected_signals:
                value = recorder.reader.raw_value(packet, signal)
                values.append(
                    {
                        "pid": signal.identity_words[0],
                        "name": f"Сигнал {signal.identity_words[0]} · исходное значение",
                        "unit": "raw",
                        "raw": value,
                        "value": value,
                        "display": str(value),
                    }
                )
            samples.append(
                {"index": index, "timestamp_raw": packet.timestamp_ms, "values": values}
            )
        report["result"] = {
            "trigger_timestamp_raw": capture.trigger_timestamp_ms,
            "packets": [
                {
                    "timestamp_raw": packet.timestamp_ms,
                    "payload_hex": packet.payload.hex(),
                }
                for packet in capture.packets
            ],
            "packet_stream_hex": capture.packet_bytes().hex(),
            "playback": {"timestamp_units": "native-raw-unknown", "samples": samples},
            "preview_limited": preview_count < len(capture.packets)
            or len(selected_signals) < len(recorder.signals),
            "dm_export_available": recording.metadata is not None
            and recording.system_information is not None,
        }
        if recording.metadata is not None:
            monitor = capture.monitor_buffer(
                recorder.monitor,
                recording.metadata,
                phase=context["phase"],
                block_packets=decode_ring_buffer(recording.metadata.ring_buffer)[
                    "block_packets"
                ],
                standard_values=tuple(
                    tuple(pair)
                    for pair in decode_frame_table(recording.metadata.frame_table)[
                        "standard_values"
                    ]
                ),
            )
            if len(capture.packets) * max(1, len(recorder.signals)) <= 100000:
                report["result"]["playback"] = {
                    "timestamp_units": "native-raw-unknown",
                    "samples": monitor_samples(monitor),
                }
            if recording.system_information is not None:
                report["result"]["native_dm_hex"] = capture.dm_bytes(
                    recorder.monitor,
                    recording.metadata,
                    recording.system_information,
                    phase=context["phase"],
                    block_packets=decode_ring_buffer(recording.metadata.ring_buffer)[
                        "block_packets"
                    ],
                    standard_values=tuple(
                        tuple(pair)
                        for pair in decode_frame_table(recording.metadata.frame_table)[
                            "standard_values"
                        ]
                    ),
                ).hex()
        recording.complete()
        report["status"] = "completed"
    except Exception as error:  # noqa: BLE001 - retain failure and cleanup evidence.
        report["status"] = (
            "cancelled"
            if isinstance(error, (RecorderCancelled, InterruptedError))
            else "failed"
        )
        report["error"] = {
            "type": type(error).__name__,
            "message": str(error),
            "notes": list(getattr(error, "__notes__", ())),
        }
        if isinstance(error, (NativeDrsError, NativeStatus)):
            report["error"]["native_status"] = error.code
        elif isinstance(error, NativeVimError):
            report["error"].update(
                native_status=error.reply.error, native_control=error.reply.control
            )
    report["result"]["state"] = recorder.state
    report["result"]["recorder_state_hex"] = executor.recorder_state.encode().hex()
    report["events"] = recording.trace
    report["remaining_events"] = len(recording.events) - recording.position
    report["remaining_trigger_events"] = (
        len(context["trigger_events"]) - recording.trigger_position
    )
    report["summary"] = {
        "completed": "Запись регистратора воспроизведена",
        "failed": "Регистратор не завершил запись",
        "cancelled": "Воспроизведение регистратора отменено",
    }[report["status"]]
    if report.get("error"):
        report["summary"] += f": {report['error']['message']}"
    return report


def create_recorder_examples() -> dict[str, bytes]:
    """Authored native threshold capture, using real typed native serializers."""
    name = NativeCoreString((1, 0), b"Synthetic signal")
    signal = NativeMonitorSignal(
        (7, 0, 0, 7),
        (name, name, NativeCoreString((1, 0), b"count")),
        (2, 0),
        0,
        (1, 1, 0),
        0,
        (0, 255),
        (1, 0),
        (),
        (0, 0, 0),
    )
    monitor = NativeMonitorBuffer(
        0,
        0,
        1,
        0,
        4096,
        encode_command(3, {"frames": ((0, 1),)}),
        encode_command(4, {"signals": (signal,)}),
        name,
        (1, 0),
        ((1, 0, 7),),
    )
    info = NativeTriggerInfo((1, 0), 2, 2, 50)
    parameters = NativeTriggerParameters(
        (1, 0),
        1,
        2,
        (1, 0),
        (NativeTriggerCondition((1, 0), 7, 6, 3, 1, 1),),
        (1, 0),
        (),
    )
    settings = DrsFile(
        2,
        0,
        (
            encode_command(2, {"monitor": monitor}),
            encode_command(5, {"trigger": info}),
            encode_command(6, {"trigger": parameters}),
            encode_command(0x11, {"children": (NativeDmciCommand(0x10C, ()).table(),)}),
            encode_command(0x12, {"children": (NativeDmciCommand(0x10E, ()).table(),)}),
        ),
    )
    # Capture the actual native client's requests rather than reimplementing DMCI.
    transactions = []
    values = iter(((1000, 1), (2000, 4), (3000, 5)))

    def exchange(
        request: bytes, *, deadline: float, cancelled: Callable[[], bool]
    ) -> bytes:
        command, _payload = decode_vim_command(request)
        if command == 0x197F:
            stamp, value = next(values)
            empty = NativeCoreBuffer((1, 0), b"")
            payload = NativeMonitorReply(
                0,
                NativeDmciList(
                    (1, 0),
                    ((19, NativeCoreBuffer((1, 0), struct.pack("<IB", stamp, value))),),
                ),
                (empty, empty, empty, empty, empty),
                0,
            ).encode()
        else:
            payload = bytes(4)
        response = NativeVimReply(command | 0x80, 6, payload).encode()
        transactions.append(
            {"ecu": "vim", "request": request.hex(), "response": response.hex()}
        )
        return response

    client = NativeVimClient(exchange, capabilities=CAPABILITIES)
    capture = NativeMonitorRecorder(
        settings, client, interface_id=19, phase=0
    ).capture()
    metadata = MonitorBuffer(
        b"Authored recorder",
        bytes(16),
        b"Synthetic metadata",
        b"",
        b"",
        b"",
        0,
        (),
        (7,),
        b"Authored only",
        (),
    )
    observed = capture.monitor_buffer(monitor, metadata, phase=0, block_packets=1)
    document = {
        "schema": SCHEMA,
        "source": "authored_synthetic",
        "context": {
            "capabilities": sorted(CAPABILITIES),
            "interface_id": 19,
            "phase": 0,
            "trigger_events": [],
            "limits": {"seconds": 30, "max_polls": 100000},
            "monitor_metadata_hex": encode_monitor_buffer(observed).hex(),
            "system_information_hex": encode_system_information(
                {
                    "identifier": 42,
                    "strings": [
                        {"core": [1, 0], "data_hex": b"Authored ECU".hex()},
                        {"core": [1, 0], "data_hex": b"Authored CALID".hex()},
                    ],
                    "value_raw": 0,
                }
            ).hex(),
        },
        "events": [{"kind": "vim", "transaction": row} for row in transactions],
    }
    return {
        "recorder-settings.drs": settings.encode(),
        "recorder-recording.json": (json.dumps(document, indent=2) + "\n").encode(),
    }


def save_recorder_dm(
    destination: Path, report: dict, *, sources: tuple[Path, ...]
) -> None:
    """Write only a completed captured DM; protect every recording/settings source."""
    if report.get("status") != "completed" or not report.get("result", {}).get(
        "dm_export_available"
    ):
        raise ValueError(
            "A completed capture with explicit monitor metadata is required"
        )
    value = report["result"]["native_dm_hex"]
    if (
        not isinstance(value, str)
        or len(value) > MAX_SNAPSHOT_BYTES * 2
        or len(value) % 2
        or re.fullmatch("[0-9a-fA-F]*", value) is None
    ):
        raise ValueError(
            "Captured DM must be hexadecimal within the 32 MiB snapshot limit"
        )
    raw = bytes.fromhex(value)
    parsed = parse_snapshot(raw)
    if (
        not isinstance(parsed, TableFile)
        or parsed.magic != DM_MAGIC
        or dumps(parsed) != raw
    ):
        raise ValueError("Captured native DM validation failed")
    recorded_sources = report.get("source_paths", [])
    if (
        not isinstance(recorded_sources, list)
        or len(recorded_sources) != 2
        or any(not isinstance(path, str) for path in recorded_sources)
    ):
        raise ValueError("Capture report must retain both original source paths")
    for original in (*sources, *(Path(path) for path in recorded_sources)):
        original.stat()
        if destination.resolve() == original.resolve() or (
            destination.exists() and destination.samefile(original)
        ):
            raise ValueError("Capture destination must differ from every source file")
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=destination.parent, prefix=f".{destination.name}.", delete=False
        ) as output:
            temporary = Path(output.name)
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, destination)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
