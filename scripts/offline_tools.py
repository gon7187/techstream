"""Local native-file tools and authored, executable diagnostic examples.

Every example runs the real parser or execution engine against authored bytes
and injected in-memory I/O. No device discovery or device opening occurs here.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import sys
import tempfile
import threading
import zlib
from collections import deque
from collections.abc import Callable, Mapping
from pathlib import Path

from scripts import calibration, communication_log, snapshot
from scripts.calibration_catalog import CalibrationCatalog, inspect_module_bytes
from scripts.demo_calibration import create_calibration_examples
from scripts.diagnostics import Session
from scripts.drive_recorder import (
    DrsFile,
    NativeMessage,
    RecorderController,
    encode_command,
)
from scripts.isotp import Peer
from scripts.jlr import JLRClient
from scripts.jlr_channels import (
    FirmwareISOExchange,
    FirmwareISOSession,
    protocol_routes,
)
from scripts.local_files import read_regular
from scripts.mongoose_protocol import decode_frames, encode_frame
from scripts.native_replay import NativeReplay
from scripts.plot import sample_chart
from scripts.programming import (
    Programmer,
    ProgramPlan,
    SimulatorBackend,
    reprostd_download_request,
    reprostd_transfer,
)
from scripts.programming_replay import create_programming_examples
from scripts.programming_replay import inspect_recording as inspect_programming
from scripts.recorder_replay import RecorderRecording, create_recorder_examples
from scripts.replay import Replay
from scripts.script_libraries import ScriptLibraries
from scripts.script_vm import (
    MAX_SIZE,
    ScriptObject,
    Step,
    evaluate,
    parse_object,
    parse_utility_xml,
)
from scripts.service_replay import ServiceReplay, create_demo_service_capture
from scripts.session_cli import save_report
from scripts.toyota import CommandFrame
from scripts.toyota_session import ActiveTest, CommandSpec, ToyotaSession
from scripts.utility import UtilityRuntime

WORKFLOWS = {
    "toyota": {
        "title": "Диагностика Toyota",
        "description": "Коды неисправностей, чтение параметра и запуск с остановкой теста на учебной записи.",
    },
    "utility": {
        "title": "Сервисная процедура",
        "description": "Исполнение учебной процедуры XML с библиотечной функцией и обменом с моделью ЭБУ.",
    },
    "script": {
        "title": "Диагностический сценарий",
        "description": "Исполнение учебного сценария CSDF с библиотеками связи и обработки ответа.",
    },
    "snapshot": {
        "title": "Запись параметров",
        "description": "Сохранение, повторное открытие и воспроизведение учебного снимка DM.",
    },
    "programming": {
        "title": "Передача калибровки",
        "description": "Передача учебных блоков в память симулятора и отдельная проверка восстановленного протокола передачи.",
    },
    "recorder": {
        "title": "Задание рекордера",
        "description": "Чтение команд DRS и исполнение подключения, настройки и отправки в модели адаптера.",
    },
    "transport": {
        "title": "Обмен через адаптер",
        "description": "Кодирование USB-пакетов и запрос ISO 15765 через модель Mongoose JLR.",
    },
    "monitors": {
        "title": "Мониторы OBD",
        "description": "Чтение поддерживаемых мониторов и оценка результата Mode 06 по учебной записи.",
    },
    "log": {
        "title": "Журнал обмена",
        "description": "Запись и повторное открытие учебного журнала в исходном бинарном формате RMViewer.",
    },
}


def _check(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(f"Offline workflow check failed: {message}")


def _cancel(cancelled: Callable[[], bool]) -> None:
    if cancelled():
        raise InterruptedError("Offline operation cancelled")


class _Exchange:
    """An exact ordered authored example, including receive-only continuations."""

    def __init__(self, steps: list[tuple[bytes, bytes]], cancelled: Callable[[], bool]):
        self.steps = deque(steps)
        self.cancelled = cancelled
        self.calls: list[dict] = []

    def __call__(self, ecu: str, request: bytes) -> bytes:
        _cancel(self.cancelled)
        if not self.steps or self.steps[0][0] != request or ecu != "synthetic-ECU":
            raise ValueError("Unexpected authored exchange")
        _, response = self.steps.popleft()
        self.calls.append(
            {"request_hex": request.hex(), "response_hex": response.hex()}
        )
        return response

    def complete(self) -> None:
        _check(not self.steps, "unconsumed authored exchanges")


def _toyota(cancelled: Callable[[], bool]) -> dict:
    replay = _Exchange(
        [
            (b"\x18", bytes.fromhex("5801020000")),
            (b"\x21\x12", b"\x61\x05"),
            (b"\x30\x01", b"\x70"),
            (b"\x30\x00", b"\x70"),
        ],
        cancelled,
    )
    commands = {
        key: CommandSpec(CommandFrame(request), payload_offset=offset)
        for key, request, offset in (
            ("dtc", b"\x18", 0),
            ("data", b"\x21\0", 1),
            ("start", b"\x30\x01", 0),
            ("stop", b"\x30\0", 0),
        )
    }
    session = ToyotaSession(replay, "synthetic-ECU", commands, cancelled=cancelled)
    codes = session.dtcs("dtc")
    freeze, physical = bytearray(84), bytearray(24)
    struct.pack_into("<HHH", freeze, 60, 7, 0, 7)
    freeze[76] = 2
    struct.pack_into("<iiiH", physical, 0, 2, 1, -4, 7)
    value = session.data_list(
        "data", 0x12, 1, freeze=bytes(freeze), physical=bytes(physical)
    )
    session.start_active_test(ActiveTest(("start",), ("stop",)))
    session.stop_active_test()
    replay.complete()
    _check(
        codes == [0x0102] and isinstance(value, dict) and value["value"] == 6,
        "Toyota result",
    )
    return {"codes": codes, "measurement": value, "session": session.report()}


UTILITY_XML = (
    b"demo"
    + """<UTILITY><FUNCTION><NAME>Authored procedure</NAME><FUNCID>demo</FUNCID>
<STORAGE><DATA DATAID="INT01"/><DATA DATAID="INT02"/><DATA DATAID="BYTE01" LENGTH="1"/></STORAGE>
<BLOCK ID="B1" TYPE="G002"><TITLE>Authored procedure</TITLE><FASTACTION>
<CALLFUNC NAME="GetEcuId" OUT="INT01">"INT02"</CALLFUNC>
<ACTION MODE="COMM" NEXT="C1"/></FASTACTION><COMM COMMID="C1">
<EVENT TYPE="SEND"><FRAME>$22,$01</FRAME></EVENT>
<EVENT TYPE="SUCCESS" MODE="BLOCK" NEXT="END"><FRAME>$62,*</FRAME>
<AFTER><RECEIVE OUT="BYTE01" POS="2" SIZE="1"/></AFTER></EVENT>
</COMM></BLOCK></FUNCTION></UTILITY>""".encode("utf-16")
)


def _utility(cancelled: Callable[[], bool]) -> dict:
    from scripts.utility_bindings import UtilityBindings

    replay = _Exchange([(b"\x22\x01", b"\x62\xa5")], cancelled)
    session = ToyotaSession(replay, "synthetic-ECU", {}, cancelled=cancelled)
    bindings = UtilityBindings(session, operations={}, ecu_id=42, protocol=6)
    runtime = UtilityRuntime(
        parse_utility_xml(UTILITY_XML),
        exchange=replay,
        library=bindings,
        ecu="synthetic-ECU",
        cancelled=cancelled,
    )
    report = runtime.run("demo")
    replay.complete()
    _check(
        report["status"] == "completed" and report["storage"]["INT02"] == 42,
        "utility by-reference result",
    )
    _check(report["storage"]["BYTE01"] == "a5", "utility response extraction")
    return report


def _script(cancelled: Callable[[], bool]) -> dict:
    script = ScriptObject(
        1,
        (),
        (b"ScriptLibCommunication", b"ScriptLibLang"),
        (
            Step(0, 0x40, b"\x03\0\0"),
            Step(0, 0x13, b"\x21\x02"),
            Step(0, 0x15, b"\0\x80"),
            Step(0, 0x40, b"\x01\0\x02"),
            Step(0, 0x15, b"\0\x80"),
            Step(0, 0x40, b"\x02\x01\x01"),
            Step(0, 0x44, b""),
        ),
    )
    replay = _Exchange([(b"\x21\x02", bytes.fromhex("6102aabb"))], cancelled)
    bindings = ScriptLibraries(
        replay, ecu="synthetic-ECU", ecu_id=3, cancelled=cancelled
    )
    result = evaluate(script, libraries=bindings.libraries, cancelled=cancelled)
    replay.complete()
    _check(result == ((1, b"\x03"), (1, b"\0"), (1, b"\x04")), "CSDF stack result")
    return {
        "stack": [{"tag": tag, "data_hex": value.hex()} for tag, value in result],
        "exchanges": replay.calls,
    }


def example_snapshot() -> bytes:
    """Two authored samples in the recovered DM layout, with one scaled signal."""
    indexes, lengths = [0] * 256, [0] * 256
    indexes[0], lengths[5] = 5, 1
    frames = struct.pack("<HHI256H256H", 1, 0, 1, *indexes, *lengths)
    signal = snapshot.SignalItem(
        1,
        0,
        42,
        5,
        0,
        7,
        b"Synthetic signal",
        b"Example",
        b"unit",
        2,
        0,
        0,
        2,
        1,
        -4,
        0,
        0,
        255,
        (),
        None,
    )
    item = snapshot.encode_signal_item(signal)
    signals = struct.pack("<HHII", 1, 0, 1, len(item)) + item
    samples = struct.pack("<IBIB", 100, 5, 120, 9)
    ring = (
        struct.pack(
            "<HHIH7I", 1, 0, 0, 1, len(samples), 0, 0, 0, 0, len(samples), len(samples)
        )
        + samples
    )
    monitor = snapshot.MonitorBuffer(
        b"synthetic-ECU",
        bytes(16),
        b"Authored capture",
        frames,
        signals,
        ring,
        100,
        (snapshot.Flag(120, b"Authored event"),),
        (42,),
        b"",
        (),
    )
    return snapshot.dumps(
        snapshot.TableFile(
            snapshot.DM_MAGIC,
            1,
            0,
            (snapshot.Table(0x8101, snapshot.encode_monitor_buffer(monitor)),),
        )
    )


def _snapshot(cancelled: Callable[[], bool]) -> dict:
    _cancel(cancelled)
    raw = example_snapshot()
    parsed = snapshot.parse(raw)
    _check(snapshot.dumps(parsed) == raw, "DM byte preservation")
    report = snapshot.playback(parsed)
    _check(
        [row["values"][0]["value"] for row in report["samples"]] == [6, 14],
        "DM scaled samples",
    )
    _check("<svg" in sample_chart(report["samples"], "42"), "DM plot rendering")
    return report


def example_tse() -> bytes:
    """Create a native TSE from authored header, ECU and monitor records."""
    source = snapshot.parse(example_snapshot())
    assert isinstance(source, snapshot.TableFile)
    monitor = snapshot.decode_monitor_buffer(source.tables[0].payload)
    captures = tuple(
        snapshot.TSEDataList(monitor, (), 1, (), bytes(90), bytes(80)) for _ in range(2)
    )
    data = snapshot.encode_tse_datalist_section(
        snapshot.TSEDataListSection(0xFFFFFFFF, 0xFFFFFF05, 0x1021, captures)
    )
    header = snapshot.create_tse_header(
        snapshot.TSEHeader(
            "TSE", 1, 0x102C, 0, 0, 0, 0, b"", b"", (42,), (0x2714,), b""
        )
    )
    label = b"Synthetic ECU"
    ecu = (
        struct.pack("<HHH", 42, 0, len(label))
        + label
        + struct.pack("<IIH", 0, 42, len(label))
        + label
        + bytes(83)
    )
    fragments = {
        "ECUInfo": struct.pack("<IIHH", 0xFFFFFFFF, 0xFFFFFF04, 0x1005, 1),
        "EcuData0042": ecu,
        "DataList0042": data,
    }
    result = snapshot.assemble_tse(
        header,
        tuple(
            fragments.get(entry["tag"], b"")
            for entry in header.metadata["index_entries"]
        ),
    )
    return snapshot.dumps(result)


def _programming(cancelled: Callable[[], bool]) -> dict:
    plan = ProgramPlan("synthetic-ECU", "authored-old", "authored-new", (b"AB", b"CD"))
    backend = SimulatorBackend(plan.ecu, plan.current_id)
    report = Programmer(backend).run(plan, cancelled=cancelled)
    _check(
        report["state"] == "completed" and backend.current_id == plan.target_id,
        "host programming simulation",
    )
    replay = _Exchange(
        [
            (reprostd_download_request(0x1000, 4), b"\x74\x10\x04"),
            (b"\x36\x01AB", b"\x76\x01"),
            (b"\x36\x02CD", b"\x76\x02"),
            (b"\x37", b"\x77"),
        ],
        cancelled,
    )
    fragment = reprostd_transfer(replay, plan.ecu, 0x1000, b"ABCD", cancelled=cancelled)
    replay.complete()
    _check(
        fragment["state"] == "fragment_completed"
        and not fragment["programming_completed"],
        "native transfer fragment",
    )
    return {"host_simulation": report, "native_transfer_fragment": fragment}


class _RecorderSimulator:
    """A stateful host model; it does not emulate the unresolved VIM wire ABI."""

    def __init__(self):
        self.connected = False
        self.baud = 0
        self.messages: list[str] = []
        self.operations: list[str] = []

    def invoke(
        self,
        operation: str,
        fields: Mapping[str, object],
        *,
        deadline: float,
        cancelled: Callable[[], bool],
    ) -> object:
        _cancel(cancelled)
        if operation == "connect":
            _check(
                not self.connected and fields == {"protocol_id": 6, "flags": 0},
                "recorder connect",
            )
            self.connected = True
        elif operation == "set_config":
            _check(
                self.connected and fields["parameters"] == ((2, 500000),),
                "recorder configuration",
            )
            self.baud = 500000
        elif operation == "write_messages":
            message = fields["message"]
            _check(
                self.connected
                and self.baud == 500000
                and isinstance(message, NativeMessage),
                "recorder send state",
            )
            if not isinstance(message, NativeMessage):
                raise ValueError("Expected native recorder message")
            self.messages.append(message.data.hex())
        elif operation == "disconnect":
            _check(self.connected, "recorder disconnect")
            self.connected = False
        else:
            raise ValueError(f"Unsupported authored recorder operation: {operation}")
        self.operations.append(operation)
        return {"state": "connected" if self.connected else "disconnected"}


def example_recorder() -> bytes:
    message = NativeMessage(6, 0, 0x100, 0, 0, b"\0\0\x07\xe0\x21\x01")
    return DrsFile(
        2,
        0,
        (
            encode_command(0x200, {"protocol_id": 6, "flags": 0}),
            encode_command(0x211, {"parameters": ((2, 500000),)}),
            encode_command(0x203, {"timeout": 500, "message": message}),
            encode_command(0x201, {}),
        ),
    ).encode()


def _recorder(cancelled: Callable[[], bool]) -> dict:
    raw = example_recorder()
    parsed = DrsFile.parse(raw)
    _check(parsed.encode() == raw, "DRS byte preservation")
    backend = _RecorderSimulator()
    controller = RecorderController(
        backend, capabilities=frozenset({"native-drs-execution"})
    )
    controller.execute(parsed, cancelled=cancelled)
    _check(
        not backend.connected and backend.messages == ["000007e02101"], "DRS sequence"
    )
    return {
        "operations": backend.operations,
        "messages_hex": backend.messages,
        "controller": controller.report(),
        "provider": "authored-host-model",
    }


class _SyntheticUSB:
    """Authored SLP replies delivered through the real client receive worker."""

    def __init__(self):
        self.queue: deque[bytes] = deque()
        self.writes: list[bytes] = []
        self.idle = threading.Event()

    def write(self, frame: bytes) -> None:
        payload = decode_frames(frame)[0]
        self.writes.append(payload)
        target, _, opcode, sequence = struct.unpack_from("<4H", payload)
        response = struct.pack(
            "<6HII", 0, target, opcode | 0x8000, sequence, 0, 0, 0, 0
        )
        self.queue.append(
            encode_frame(response + (bytes(4) if opcode == 0x0D else b""))
        )
        if opcode == 8:
            data = bytes.fromhex("000007e80362f190")
            event = (
                struct.pack("<6HIIHH", 0, target, 9, 0, 0, 0, 0, 123, 0, len(data))
                + data
            )
            self.queue.append(encode_frame(event))

    def read(self, timeout_ms: int) -> bytes:
        if not self.queue:
            self.idle.wait(min(timeout_ms / 1000, 0.001))
        return self.queue.popleft() if self.queue else b""


def _transport(cancelled: Callable[[], bool]) -> dict:
    transport = _SyntheticUSB()
    board = struct.pack("<6HII", 0, 1, 0x8109, 1, 0, 0, 0, 0) + b"\x01" + bytes(159)
    channel = FirmwareISOSession(
        JLRClient(transport),
        board,
        protocol_routes(board, 6)[0],
        500000,
        Peer(tx_id=0x7E0, rx_id=0x7E8),
    )
    channel.open()
    try:
        result = FirmwareISOExchange(
            {"synthetic-ECU": channel}, cancelled=cancelled
        ).exchange("synthetic-ECU", b"\x22\xf1\x90")
    finally:
        channel.close()
    writes = [
        payload
        for payload in transport.writes
        if struct.unpack_from("<H", payload, 4)[0] == 8
    ]
    _check(result == b"\x62\xf1\x90" and len(writes) == 1, "firmware ISO exchange")
    return {
        "request_hex": "22f190",
        "response_hex": result.hex(),
        "write_count": len(writes),
        "usb_packets": len(transport.writes),
        "provider": "authored-USB-model",
    }


def _monitors(cancelled: Callable[[], bool]) -> dict:
    replay = Replay(
        {
            "schema": "techstream-native-replay-v1",
            "source": "authored_synthetic",
            "ecus": ["synthetic-ECU"],
            "transactions": [
                {"ecu": "synthetic-ECU", "request": "0600", "response": "460080000000"},
                {
                    "ecu": "synthetic-ECU",
                    "request": "0601",
                    "response": "4601010a03e8000007d0",
                },
            ],
        }
    )
    report = Session(replay.exchange, cancelled=cancelled).monitors("synthetic-ECU")
    replay.assert_complete()
    _check(
        report["status"] == "ok" and len(report["results"]) == 1, "OBD monitor result"
    )
    return report


def example_log() -> bytes:
    ticks = iter((100, 101, 120))
    queue = communication_log.CommunicationLog(
        ticks=lambda: next(ticks),
        local_time=lambda: (2026, 10, 2, 20, 12, 30, 0, 0),
    )
    queue.clear()
    queue.put_log(communication_log.LogMessage(1, 4, b"\x22", b"\xf1\x90", field2c=102))
    queue.put_log(communication_log.LogMessage(2, 4, b"\x62", b"\xf1\x90", field2c=105))
    queue.set_end_log_time()
    return communication_log.dumps(queue.export())


def _log(cancelled: Callable[[], bool]) -> dict:
    _cancel(cancelled)
    raw = example_log()
    parsed = communication_log.parse(raw)
    _check(communication_log.dumps(parsed) == raw, "native log preservation")
    rows = list(communication_log.replay(parsed))
    _check([row["elapsed_ms"] for row in rows] == [0, 20, 2, 5], "native tick replay")
    return _log_report(parsed)


def _log_report(parsed: communication_log.CommunicationLogFile) -> dict:
    return {
        **parsed.to_dict(),
        "events": [
            {
                **{key: value for key, value in event.items() if key != "payload"},
                "payload_hex": event["payload"].hex(),
            }
            for event in communication_log.replay(parsed)
        ],
    }


def example_native_exchange() -> dict:
    """Captured-PDU fixture for the authored demo vehicle, including support."""
    return {
        "schema": "techstream-native-exchange-v1",
        "source": "authored_synthetic",
        "ecus": ["engine"],
        "support": {"engine": {"pid_lengths": {"0c": 2}, "did_lengths": None}},
        "transactions": [
            {"ecu": "engine", "request": "210c", "response": "610c80"},
            {"ecu": "engine", "request": "010c", "response": "410c1f40"},
        ],
    }


_RUNNERS = {
    "toyota": _toyota,
    "utility": _utility,
    "script": _script,
    "snapshot": _snapshot,
    "programming": _programming,
    "recorder": _recorder,
    "transport": _transport,
    "monitors": _monitors,
    "log": _log,
}


def run_example(key: str, cancelled: Callable[[], bool] | None = None) -> dict:
    if key not in _RUNNERS:
        raise ValueError("Unknown offline example")
    stop = cancelled if cancelled is not None else lambda: False
    _cancel(stop)
    result = _RUNNERS[key](stop)
    _cancel(stop)
    return {
        "workflow": key,
        "source": "authored_synthetic",
        "physical_status": "PHYSICAL_UNCONFIRMED",
        "summary": WORKFLOWS[key]["title"] + ": учебный сценарий выполнен",
        "result": result,
    }


def inspect_path(
    path: str | Path, *, buffer_index: int = 0, encoding: str | None = None
) -> dict:
    if type(buffer_index) is not int or buffer_index < 0:
        raise ValueError("Monitor buffer index must be a nonnegative integer")
    source = Path(path)
    raw = read_regular(source, limit=snapshot.MAX_BYTES)
    if len(raw) > MAX_SIZE and not (
        raw.startswith(b"\x9aS\xdb\x12")
        or int.from_bytes(raw[:4], "little")
        in (snapshot.DM_MAGIC, snapshot.DRS_MAGIC, communication_log.MAGIC)
    ):
        raise ValueError("Non-snapshot input exceeds the 16 MiB limit")
    if len(raw) >= 4 and int.from_bytes(raw[:4], "little") == communication_log.MAGIC:
        result = _log_report(communication_log.parse(raw))
    elif len(raw) >= 4 and int.from_bytes(raw[:4], "little") == snapshot.DRS_MAGIC:
        result = DrsFile.parse(raw).report()
    elif (
        len(raw) >= 4 and int.from_bytes(raw[:4], "little") == snapshot.DM_MAGIC
    ) or raw.startswith(b"\x9aS\xdb\x12"):
        parsed = snapshot.parse(raw)
        result = parsed.to_dict()
        if isinstance(parsed, snapshot.TSEFile):
            if encoding is not None:
                from scripts.tse_reports import report_views

                result["report_views"] = report_views(parsed, encoding=encoding)
                result["report_encoding"] = encoding
            supported = parsed.metadata["supported_feature_ids"]
            monitors = (
                snapshot.tse_monitors(parsed)
                if any(
                    fid in supported for fid in (0x2714, 0x2715, 0x2717, 0x2726, 0x2728)
                )
                else []
            )
            buffers = [
                {
                    "index": index,
                    "title": f"{item['family']} · ECU {item['ecu_id_raw']} · {item['record_index'] + 1}",
                    "family": item["family"],
                    "ecu_id_raw": item["ecu_id_raw"],
                    "record_index": item["record_index"],
                }
                for index, item in enumerate(monitors)
            ]
        else:
            buffers = [
                {"index": index, "title": f"DM · {index + 1}", "family": "DM"}
                for index, _ in enumerate(
                    table for table in parsed.tables if table.id == 0x8101
                )
            ]
        result["available_buffers"] = buffers
        result["playback_index"] = buffer_index if buffers else None
        if buffers:
            result["playback"] = snapshot.playback(parsed, buffer_index)
        elif buffer_index:
            raise ValueError("Native monitor buffer does not exist")
    elif raw.startswith((calibration.SIGNATURE, b"S0", b"S1", b"S2", b"S3")):
        result = calibration.inspect_calibration(raw)
    elif source.suffix.lower() == ".dll":
        result = {
            "format": "static-pe-metadata",
            **inspect_module_bytes(raw, source.name),
        }
    elif source.suffix.lower() in (".ini", ".csv"):
        catalog = CalibrationCatalog.from_tables(
            {source.name: raw}, encoded=source.suffix.lower() == ".ini"
        )
        result = {
            "format": "native-calibration-catalog",
            "keys": list(catalog.keys),
            "catalog": catalog.report(),
        }
    elif source.suffix.lower() == ".xml":
        try:
            result = {"format": "utility-xml", **parse_utility_xml(raw).inspect()}
        except ValueError:
            from scripts.tse_reports import parse_all_dtc_xml, view_all_dtc_xml

            view = view_all_dtc_xml(parse_all_dtc_xml(raw))
            if not {"AllDiag", "array-ECUInfo"} & view["stored_fields"].keys():
                raise ValueError("Unrecognized XML report schema") from None
            result = {"format": "all-dtc-xml", **view}
    elif source.suffix.lower() == ".bin":
        result = {"format": "csdf", **parse_object(raw).inspect()}
    elif source.suffix.lower() == ".json":
        from scripts.native_replay import _object

        try:
            document = json.loads(raw, object_pairs_hook=_object)
        except (ValueError, UnicodeError, RecursionError) as error:
            raise ValueError("Invalid native recording JSON") from error
        if not isinstance(document, dict):
            raise ValueError("Native recording object required")
        schema = document.get("schema")
        if schema == "techstream-programming-replay-v1":
            result = {
                **inspect_programming(raw),
                "format": "native-programming-recording",
            }
        elif schema == "techstream-service-replay-v1":
            service = ServiceReplay.from_bytes(raw)
            result = {
                "format": "native-service-recording",
                "source": document["provenance"],
                "workflow": document["workflow"]["kind"],
                "events": len(document["steps"]),
                "port_contracts": sorted(document["port_sources"]),
                "capture_sha256": service.capture_sha256,
            }
        elif schema == "techstream-native-recorder-v1":
            recording = RecorderRecording(document)
            result = {
                "format": "native-recorder-recording",
                "source": recording.source,
                "events": len(recording.events),
                "phase": recording.context["phase"],
                "capabilities": recording.context["capabilities"],
                "trigger_events": len(recording.context["trigger_events"]),
                "has_monitor_metadata": recording.metadata is not None,
            }
        else:
            replay = NativeReplay.loads(raw)
            result = {
                "format": "native-exchange-recording",
                "source": replay.source,
                "ecus": list(replay.ecus),
                "transactions": replay.remaining,
                "support": {
                    ecu: {
                        "pid_lengths": {f"{key:02x}": size for key, size in pid.items()}
                        if pid is not None
                        else None,
                        "did_lengths": {f"{key:02x}": size for key, size in did.items()}
                        if did is not None
                        else None,
                    }
                    for ecu in replay.ecus
                    for pid, did in (replay.observations(ecu),)
                },
            }
    else:
        raise ValueError(
            "Unsupported local format; expected DM, DRS, TSE, native log, CUW, SREC, utility XML, CSDF .bin or native exchange JSON"
        )
    if buffer_index and "available_buffers" not in result:
        raise ValueError("Monitor selection requires a DM or TSE recording")
    return {
        "source": "local_file_unverified",
        "physical_status": "PHYSICAL_UNCONFIRMED",
        "path": str(source.resolve()),
        "size": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "summary": f"{source.name} · {result['format']}",
        "result": result,
    }


def copy_native(source: str | Path, destination: str | Path) -> None:
    """Preserve every byte, including unknown records; never replace the source."""
    source, destination = Path(source), Path(destination)
    if source.resolve() == destination.resolve() or (
        destination.exists() and source.samefile(destination)
    ):
        raise ValueError("Native copy destination must differ from its source")
    original = read_regular(source, limit=snapshot.MAX_BYTES)
    if (
        len(original) >= 4
        and int.from_bytes(original[:4], "little") == communication_log.MAGIC
    ):
        raw = communication_log.dumps(communication_log.parse(original))
    else:
        raw = snapshot.dumps(snapshot.parse(original))
    _check(
        read_regular(source, limit=snapshot.MAX_BYTES) == raw,
        "native roundtrip lost source bytes",
    )
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=destination.parent, prefix=f".{destination.name}.", delete=False
        ) as target:
            temporary = Path(target.name)
            target.write(raw)
            target.flush()
            os.fsync(target.fileno())
        os.replace(temporary, destination)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def example_calibration() -> bytes:
    def record(header: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">H", len(header))
            + header
            + struct.pack(">II", len(data), zlib.crc32(data))
            + data
        )

    tail = (
        record(b"authored-metadata", b"[Format]\nVersion=1\n")
        + b"\x01"
        + record(b"authored-image", b"ABCD")
    )
    raw = (
        calibration.SIGNATURE
        + b"\x01"
        + bytes(4)
        + struct.pack(">I", 22 + len(tail))
        + tail
    )
    return raw[:14] + struct.pack(">I", zlib.crc32(raw[18:])) + raw[18:]


def create_examples(destination: str | Path) -> dict[str, Path]:
    directory = Path(destination)
    directory.mkdir(parents=True, exist_ok=False)
    files = {
        "capture.dm": example_snapshot(),
        "capture.tse": example_tse(),
        "all-dtc.xml": b"""<AllDiag><array-ECUInfo><ECUInfo>
<ECUId>7</ECUId><ECUName>Authored ECU</ECUName><array-DTCInfo><DTCInfo>
<DTCDispValue>P0123</DTCDispValue><DTCName>Authored fault</DTCName>
<StatusGridName>Authored saved status</StatusGridName>
</DTCInfo></array-DTCInfo></ECUInfo></array-ECUInfo></AllDiag>""",
        "settings.drs": example_recorder(),
        "calibration.cuw": example_calibration(),
        "procedure.xml": UTILITY_XML,
        "communication.clog": example_log(),
        "native-exchange.json": (
            json.dumps(example_native_exchange(), indent=2) + "\n"
        ).encode(),
    }
    files.update(create_calibration_examples())
    files.update(create_recorder_examples())
    files.update(create_programming_examples())
    files.update(
        (f"service-{kind}.json", create_demo_service_capture(kind))
        for kind in (
            "tis-check",
            "tis-save",
            "euro-online",
            "euro-save",
            "euro-key",
            "rks",
            "notice",
        )
    )
    result = {}
    for name, raw in files.items():
        path = directory / name
        path.write_bytes(raw)
        result[name] = path
    return result


def verify_workflows() -> None:
    from scripts.programming_replay import load_programming_files
    from scripts.recorder_replay import replay_recorder, save_recorder_dm

    for key in WORKFLOWS:
        report = run_example(key)
        _check(json.loads(json.dumps(report)) == report, f"{key} report roundtrip")
    with tempfile.TemporaryDirectory(prefix="techstream-offline-") as temporary:
        directory = Path(temporary)
        files = create_examples(directory / "inputs")
        for name, path in files.items():
            report = inspect_path(path)
            save_report(directory / f"{name}.json", report, source=path)
        copy = directory / "copy.dm"
        copy_native(files["capture.dm"], copy)
        _check(
            copy.read_bytes() == files["capture.dm"].read_bytes(),
            "source-preserving native export",
        )
        session, _ = load_programming_files(
            files["authored.cuw"],
            files["authored-programming.json"],
            {"DEMOP5DEMO.ini": files["DEMOP5DEMO.ini"]},
            {"SyntheticProgramming.dll": files["SyntheticProgramming.dll"]},
        )
        programming = session.run()
        _check(
            programming["state"] == "writer_completed"
            and programming["events_remaining"] == 0
            and programming["programming_completed"] is False,
            "imported native programming execution",
        )
        recorder = replay_recorder(
            files["recorder-settings.drs"], files["recorder-recording.json"]
        )
        _check(
            recorder["status"] == "completed"
            and recorder["remaining_events"] == 0
            and recorder["remaining_trigger_events"] == 0,
            "imported native recorder execution",
        )
        recorded = directory / "recorded.dm"
        save_recorder_dm(
            destination=recorded,
            report=recorder,
            sources=(files["recorder-settings.drs"], files["recorder-recording.json"]),
        )
        _check(
            bool(inspect_path(recorded)["result"]["playback"]["samples"]),
            "native recorder export and playback",
        )
        for name, path in files.items():
            if name.startswith("service-"):
                service = ServiceReplay.load(path).run()
                _check(
                    service["state"] == "complete"
                    and service["consumed_steps"] == service["total_steps"],
                    f"{name} native service execution",
                )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    example = commands.add_parser("example")
    example.add_argument("name", choices=tuple(WORKFLOWS))
    example.add_argument("--output", type=Path)
    inspect = commands.add_parser("inspect")
    inspect.add_argument("path", type=Path)
    inspect.add_argument("--buffer-index", type=int, default=0)
    inspect.add_argument(
        "--encoding", help="Explicit text encoding for saved TSE reports"
    )
    inspect.add_argument("--output", type=Path)
    fixtures = commands.add_parser("create-examples")
    fixtures.add_argument("directory", type=Path)
    copy = commands.add_parser("copy-native")
    copy.add_argument("source", type=Path)
    copy.add_argument("destination", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "create-examples":
            report = {
                key: str(path) for key, path in create_examples(args.directory).items()
            }
        elif args.command == "copy-native":
            copy_native(args.source, args.destination)
            report = {"destination": str(args.destination), "preserved": True}
        else:
            report = (
                run_example(args.name)
                if args.command == "example"
                else inspect_path(
                    args.path, buffer_index=args.buffer_index, encoding=args.encoding
                )
            )
            if args.output:
                save_report(
                    args.output,
                    report,
                    source=args.path if args.command == "inspect" else None,
                )
                return 0
        print(json.dumps(report, ensure_ascii=False, indent=2))
    except (OSError, ValueError, RuntimeError, ImportError) as exc:
        print(f"offline tools: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
