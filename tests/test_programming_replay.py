import hashlib
import io
import json
import os
import struct
import tempfile
import unittest
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType, SimpleNamespace
from typing import Any, cast
from unittest.mock import patch

from scripts.programming_replay import (
    ProgrammingTrace,
    create_programming_examples,
    inspect_recording,
    load_programming_files,
    load_programming_recording_stream,
    load_programming_replay,
)


@dataclass(frozen=True)
class AuthoredCanCIDReplayFixture:
    calibration: bytes
    catalog_sources: dict[str, bytes]
    module_bytes: dict[str, bytes]
    events_by_root: tuple[tuple[dict[str, Any], ...], ...]
    captured_identifiers_by_root: tuple[tuple[bytes, ...], ...]
    typed_outputs: tuple[dict[str, Any], ...]
    captured_tail_events: tuple[dict[str, Any], ...]
    trace_setup: dict[str, Any]


def make_authored_control_recorder(
    case: unittest.TestCase,
    *,
    source: bytes,
    catalog_sources: Mapping[str, bytes],
    module_files: Mapping[str, bytes],
    primitive_reply: Callable[[dict[str, Any], float | None], Any],
):
    """Create one source-bound CONTROL recording root and its live J2534 pair.

    The callback supplies actual SDK primitive replies and authored host observations;
    it never supplies getter results or other native business outcomes.
    """
    from scripts.j2534_2026 import (
        DriverMetadata2026,
        NativeMessage,
        PrimitiveResult,
    )
    from scripts.programming_2026_common import NativeRuntime2026
    from scripts.programming_replay import _native_request
    from tests.private_evidence import read_private_bytes

    if type(source) is not bytes or not isinstance(catalog_sources, Mapping):
        raise TypeError("Exact source and catalog inputs are required")
    if any(
        type(name) is not str or type(data) is not bytes
        for name, data in catalog_sources.items()
    ):
        raise TypeError("Exact authored catalog bytes are required")
    if any(
        type(name) is not str or type(data) is not bytes
        for name, data in module_files.items()
    ):
        raise TypeError("Exact authored module bytes are required")
    if not callable(primitive_reply):
        raise TypeError("Authored primitive reply callback is required")

    context = {
        "schema": "techstream-programming-replay-v1",
        "source": "recorded_unverified",
        "calibration_sha256": hashlib.sha256(source).hexdigest(),
        "operation": "get_cid",
        "node": 1,
        "observations": {
            "current_cids": [],
            "tester_info_hex": bytes(32).hex(),
            "system_time": [2026, 10, 22, 22, 1, 2, 3, 4],
            "timeout_seconds": 30,
            "cid_mode": 2,
            "host": {"driver_recording": "j2534_2026"},
        },
        "events": [],
    }
    modules = dict(module_files)
    modules.setdefault(
        "TCUWJ2534DeviceIF.dll",
        read_private_bytes(Path("runtime/no-car-21/recovered/TCUWJ2534DeviceIF.dll")),
    )
    root = load_programming_replay(
        source, json.dumps(context).encode(), catalog_sources, modules
    )
    case.addCleanup(root.trace.close)
    rows: list[dict[str, Any]] = []
    root.trace.rows = rows
    original_consume = root.trace.consume
    sdk_operations = frozenset(
        {
            "close_handle",
            "call_symbol",
            "create_mutex",
            "free_library",
            "get_symbol",
            "get_system_time",
            "lock",
            "load_library",
            "passthru_close",
            "passthru_connect",
            "passthru_disconnect",
            "passthru_ioctl",
            "passthru_load_library",
            "passthru_logical_connect",
            "passthru_logical_disconnect",
            "passthru_next_device",
            "passthru_open",
            "passthru_queue",
            "passthru_read",
            "passthru_read_buffer",
            "passthru_read_version",
            "passthru_save_log",
            "passthru_scan_devices",
            "passthru_start_filter",
            "passthru_start_periodic",
            "passthru_status",
            "passthru_stop_filter",
            "passthru_stop_periodic",
            "passthru_unload_library",
            "passthru_voltage",
            "passthru_write",
            "local_time_ms",
            "release_mutex",
            "set_communication_log_mode",
            "unlock",
            "wait",
            "wait_handle",
        }
    )

    def encode(value: Any) -> dict[str, Any]:
        if value is None:
            return {"type": "none", "value": None}
        if type(value) is bool:
            return {"type": "bool", "value": value}
        if type(value) is int:
            return {"type": "int", "value": value}
        if type(value) is str:
            return {"type": "text", "value": value}
        if type(value) is bytes:
            return {"type": "bytes", "value": value.hex()}
        if isinstance(value, NativeMessage):
            return {
                "type": "mapping",
                "value": {
                    "_native_type": {"type": "text", "value": "PASSTHRU_MSG_2026"},
                    **{key: encode(item) for key, item in vars(value).items()},
                },
            }
        if type(value) is tuple:
            return {"type": "tuple", "value": [encode(item) for item in value]}
        if type(value) is dict:
            return {
                "type": "mapping",
                "value": {key: encode(item) for key, item in value.items()},
            }
        raise TypeError(f"Unsupported authored recorder value: {type(value)!r}")

    def authoring_consume(kind: str, request: dict[str, Any], remaining=None):
        response = primitive_reply(request, remaining)
        if kind == "action" and request.get("operation") in sdk_operations:
            if type(response) is PrimitiveResult:
                result = encode({"status": response.status, "value": response.value})
            elif request.get("operation") == "set_communication_log_mode":
                result = encode(response)
            else:
                raise TypeError("Actual J2534 SDK replies must be PrimitiveResult")
        else:
            if isinstance(response, PrimitiveResult):
                raise TypeError("Host observations must be their raw typed values")
            result = encode(response)
        rows.append(
            {
                "kind": kind,
                "request": _native_request(request),
                "result": result,
                "elapsed_ms": 1,
            }
        )
        return original_consume(kind, request, remaining)

    root.trace.consume = authoring_consume
    runtime = NativeRuntime2026(
        root.trace.action,
        clock=root.trace.clock,
        cancelled=root.trace.cancelled,
        local_seconds_of_day=root.trace.native_local_seconds_of_day,
        local_milliseconds_of_day=root.trace.native_local_milliseconds_of_day,
    )
    root.bind_runtime2026(runtime)
    pair = root.trace.interface_pair
    if pair is None:
        raise AssertionError("Source recorder must issue its paired J2534 interfaces")
    for view in (pair.engine, pair.control):
        view.set_current_driver(DriverMetadata2026("Authored", "authored.dll"))
    return root, runtime, pair, rows


def _run_authored_suzuki_raw_control(case, calibration, catalog, module_files):
    """Run the selected Suzuki writer through an actual raw CONTROL helper lease."""
    import tempfile
    import threading

    from scripts.cuw_2026 import CUWEngine2026, identity_2026
    from scripts.cuw_persistence import (
        CUWPersistence,
        RecoveryCalibration,
        ReproInfoState,
    )
    from scripts.j2534_2026 import DriverMetadata2026, NativeMessage, PrimitiveResult
    from scripts.programming_2026_common import (
        ControlCommPhase2026,
        NativeFrontendParameters2026,
        NativeRuntime2026,
    )
    from scripts.programming_replay import _native_request
    from tests.private_evidence import read_private_bytes
    from tests.test_programming_2026_vendor import TypedDriver

    recording = {
        "schema": "techstream-programming-replay-v1",
        "source": "recorded_unverified",
        "calibration_sha256": hashlib.sha256(calibration).hexdigest(),
        "operation": "write",
        "node": 1,
        "observations": {
            "current_cids": [],
            "tester_info_hex": bytes(32).hex(),
            "system_time": [2026, 10, 22, 22, 1, 2, 3, 4],
            "timeout_seconds": 30,
            "cid_mode": 2,
            "host": {"cpu_index": 0, "driver_recording": "j2534_2026"},
        },
        "events": [],
    }
    raw_modules = {
        **module_files,
        "TCUWJ2534DeviceIF.dll": read_private_bytes(
            Path("runtime/no-car-21/recovered/TCUWJ2534DeviceIF.dll")
        ),
    }
    raw = load_programming_replay(
        calibration, json.dumps(recording).encode(), catalog, raw_modules
    )
    case.addCleanup(raw.trace.close)
    raw.trace.rows = []
    raw.trace.position = 0
    raw.trace.elapsed = 0.0
    driver = TypedDriver.__new__(TypedDriver)
    driver.replies = {
        b"\x2e\xcf\x80\x01": [b"\x6e\xcf\x80"],
        b"\x31\x01\xda\x00": [b"\x71\x01\xda\x00\x01"],
        b"\x31\x03\xda\x00": [b"\x71\x03\xda\x00\x06"],
        b"\x31\x01\xd9\x15": [b"\x71\x01\xd9\x15\x01"],
        b"\x31\x01\xda\x01": [b"\x71\x01\xda\x01\x01"],
    }
    driver.pending = []
    driver.events = []
    driver.fault = None
    driver.now = 0.0
    local_ms = 1000
    callback_authority: list[dict[str, Any]] = []
    runtime = None
    controller = None
    engine = None

    def typed(value):
        if value is None:
            return {"type": "none", "value": None}
        if type(value) is bool:
            return {"type": "bool", "value": value}
        if type(value) is int:
            return {"type": "int", "value": value}
        if type(value) is bytes:
            return {"type": "bytes", "value": value.hex()}
        if isinstance(value, NativeMessage):
            return {
                "type": "mapping",
                "value": {
                    "_native_type": {
                        "type": "text",
                        "value": "PASSTHRU_MSG_2026",
                    },
                    **{key: typed(item) for key, item in vars(value).items()},
                },
            }
        if type(value) is tuple:
            return {"type": "tuple", "value": [typed(item) for item in value]}
        if type(value) is dict:
            return {
                "type": "mapping",
                "value": {key: typed(item) for key, item in value.items()},
            }
        raise TypeError(f"Unsupported captured raw CONTROL value: {type(value)!r}")

    def consume(kind, request, remaining=None):
        nonlocal local_ms
        if kind != "action":
            raise ValueError(f"Unexpected raw CONTROL chronology kind: {kind}")
        operation = request["operation"]
        if operation == "notify_igoffon_wait":
            if runtime is None or controller is None:
                raise AssertionError("Selected callback owners must be bound")
            scope = runtime._device_calls.suzuki_wait_scope
            stage = scope.stage if scope is not None else None
            target = scope.target if scope is not None else None
            callback_authority.append(
                {
                    "scope_active": scope is not None,
                    "target_active": target is not None,
                    "target_type": (
                        type(target).__name__ if target is not None else None
                    ),
                    "stage_target_matches": (
                        stage is not None and stage._control_target2026 is target
                    ),
                    "stage_owners_match": (
                        stage is not None
                        and stage._engine2026 is engine
                        and stage._controller2026 is controller
                    ),
                    "export": scope.export if scope is not None else None,
                    "lease_active": (
                        scope is not None
                        and scope.helper_lease is not None
                        and controller._native_control_export_lease2026
                        is scope.helper_lease
                    ),
                    "entry_active": (
                        controller._native_control_helper_entry2026 is not None
                    ),
                    "thread_matches": (
                        scope is not None and scope.thread == threading.get_ident()
                    ),
                    "context_matches": (
                        scope is not None
                        and stage is not None
                        and scope.runner_context.container is stage.container
                    ),
                    "module": (
                        target.module_binding.module_name
                        if target is not None
                        else None
                    ),
                }
            )
        if operation.startswith("passthru_") or operation in (
            "create_mutex",
            "load_library",
            "get_symbol",
        ):
            result = (
                PrimitiveResult(value=2000)
                if operation == "get_timeout"
                else driver(request, remaining or 1.0)
            )
            value = {"status": result.status, "value": result.value}
            encoded = typed(value)
            returned = value
        else:
            if operation == "get_local_milliseconds_of_day":
                returned = local_ms
                local_ms += 1000
            elif operation == "get_local_seconds_of_day":
                returned = 1
            elif operation == "set_communication_log_mode":
                returned = 0
            elif operation == "load_library":
                returned = 2
            elif operation == "get_symbol":
                returned = 3
            else:
                returned = None
            encoded = typed(returned)
        captured = cast(list[dict[str, Any]], raw.trace.rows)
        captured.append(
            {
                "kind": "action",
                "request": _native_request(request),
                "result": encoded,
                "elapsed_ms": 1,
            }
        )
        raw.trace.position += 1
        raw.trace.elapsed += 0.001
        return returned

    raw.trace.consume = consume
    runtime = NativeRuntime2026(
        raw.trace.action,
        clock=raw.trace.clock,
        cancelled=raw.trace.cancelled,
        local_seconds_of_day=raw.trace.native_local_seconds_of_day,
        local_milliseconds_of_day=raw.trace.native_local_milliseconds_of_day,
        native_cancelled=lambda: False,
    )
    raw.bind_runtime2026(runtime)
    pair = raw.trace.interface_pair
    if pair is None:
        raise AssertionError("Raw paired provider was not issued")
    for view in (pair.engine, pair.control):
        view.set_current_driver(DriverMetadata2026("Authored", "authored.dll"))
    pair.engine.open()
    pair.engine.connect(6)

    frontend = NativeFrontendParameters2026.from_sources(catalog, encoded=True)
    engine = CUWEngine2026(module_files["CUW.dll"], general_parameters=frontend.general)
    case.addCleanup(engine.close)
    engine.configure(struct.pack("<IIddII", 1, 0, 1, 2, 0, 0))
    engine.bind_frontend_parameters(frontend)
    engine.load_cuw(calibration)
    engine.bind_interface_pair(pair)
    persistence_dir = tempfile.TemporaryDirectory()
    case.addCleanup(persistence_dir.cleanup)
    engine.bind_persistence(
        CUWPersistence(
            Path(persistence_dir.name),
            ReproInfoState(
                (
                    RecoveryCalibration(
                        "authored.cuw", calibration, blank_ecu_flags=(False,)
                    ),
                ),
                multi_calibration_file_num=1,
                loaded=False,
            ),
        )
    )
    controller = ControlCommPhase2026(
        identity_2026(
            module_files["TCUWControlCommPhase.dll"], "TCUWControlCommPhase.dll"
        ),
        runtime,
    )
    case.addCleanup(lambda: controller._close_control_pool2026(engine))
    raw.bind_controller2026(controller)
    raw.bind_engine2026(engine)
    with engine.controller_execution(controller, 2):
        result = controller.execute(engine, raw)
    rows = raw.trace.rows
    if not isinstance(rows, list):
        raise TypeError("Captured raw events must remain an owned list")
    ProgrammingTrace.validate(rows)
    return result, callback_authority, rows, driver, engine, controller, raw, runtime


def capture_authored_cancid_replay_fixture(
    case: unittest.TestCase,
    *,
    calibration: bytes | None = None,
    catalog_sources: Mapping[str, bytes] | None = None,
    raw_reply_payloads_by_root: tuple[tuple[bytes, ...], tuple[bytes, ...]]
    | None = None,
    tail_capture: Callable[[Any, Any], None] | None = None,
    tail_driver: Callable[[dict[str, Any], float], Any] | None = None,
) -> AuthoredCanCIDReplayFixture:
    """Capture two actual acquisitions; strictly replay the first source root."""
    if (tail_capture is None) is not (tail_driver is None):
        raise ValueError("Tail body and primitive reply callback are a required pair")
    if tail_capture is not None and (
        not callable(tail_capture) or not callable(tail_driver)
    ):
        raise TypeError("Callable actual tail body and primitive reply required")
    from scripts.calibration_2026 import native2026_metadata
    from scripts.j2534_2026 import (
        DriverMetadata2026,
        J2534Device2026,
        J2534InterfacePair2026,
        NativeMessage,
        PrimitiveResult,
    )
    from scripts.programming_2026_common import (
        ControlCommPhase2026,
        NativeFrontendParameters2026,
        NativeRuntime2026,
        _control_getter_output2026,
    )
    from scripts.programming_2026_legacy import (
        bind_can_cid_context,
        decode_can_cids2026,
        run_can_cid,
    )
    from scripts.programming_replay import _native_request
    from tests.private_evidence import read_private_bytes
    from tests.test_calibration_2026 import cuw, srecord
    from tests.test_cuw_engine_worker import encoded_table
    from tests.test_programming_2026_common import (
        RawControlStageMachineTests,
        make_raw_control_fixture2026,
    )

    if calibration is None:
        calibration = cuw(
            "[Format]\nVersion=105\n[Vehicle]\nNumberOfNode=1\n"
            "ContactType=P5-Unified\nKindOfECU=149\n[Node01]\n"
            "RequiredSpecReproVer=02\nDiagID=0200\nNumberOfCalibration=2\n"
            "[CPU11]\nCPUImageName=image0.vbf\nCPUType=311\n"
            "NumberOfTargets=1\n01_TargetCalibration=PLAIN_OLD\n"
            "[CPU12]\nCPUImageName=image1.vbf\nCPUType=312\n"
            "NumberOfTargets=1\n01_TargetCalibration=OLD_GROUP\n",
            (
                b"\n".join((srecord(1, 0, b"xPLAIN_OLD"), srecord(7, 0))),
                b"\n".join((srecord(1, 0, b"xOLD_GROUP"), srecord(7, 0))),
            ),
        )
    elif type(calibration) is not bytes:
        raise TypeError("Exact authored calibration bytes required")
    parameter_values = {
        "GetCANIDFunctionNameForGetCID": "GetCanIDsFromParamForGetCID",
        "CanIDForGetCID": "0200/0208",
        "ReceiveTimeoutBeforeGetCID": "123",
    }
    table_headers = (
        "ParamFileKeySystemProtocolMicon",
        "DLLFileNameForPrepareWrite",
        "DLLFileNameForFlashWrite",
        "DLLFileNameForGetCID",
        "DLLFileNameForChangeToReprogGatewayMode",
        "EnableDLLVersionInformation",
        "GetCANIDFunctionNameForFlashWrite",
        "AlternateDLLFileNamesForGetCID",
        *parameter_values,
    )
    keys = ("149P5-Unified311", "149P5-Unified312")
    default_catalog_sources = {
        "Parameter.ini": encoded_table(
            (
                "ParamFileKeySystemProtocolMicon",
                "M16CTypeFlag",
                "FORESTTypeFlag",
                "PasswordAddress",
                "ByteOrder",
                "FlagToDoIGOFFONAtCPUTypeChange",
                "FlagToChangeToReprogGWModeForCentralGW",
            ),
            (
                ("149P5-Unified", "0", "0", "00", "1", "0", "0"),
                (keys[0], "1", "0", "00", "1", "0", "0"),
                (keys[1], "0", "1", "01", "1", "0", "0"),
            ),
        ),
        "CanIDTable.ini": encoded_table(
            ("RequestCANID", "CalibrationType"), (("0200", "17"),)
        ),
        "LogicalAddressTable.ini": encoded_table(
            ("LogicalAddress", "CalibrationType"), (("0103", "18"),)
        ),
    }
    module_bytes = {
        name: read_private_bytes(Path("runtime/no-car-21/recovered") / name)
        for name in (
            "TCUWCanCIDGetter.dll",
            "TCUWSilPrepareWriter.dll",
            "TCUWSilFlashWriter.dll",
        )
    }
    for key in keys:
        default_catalog_sources[key + ".ini"] = encoded_table(
            table_headers,
            (
                (
                    key,
                    "TCUWSilPrepareWriter.dll",
                    "TCUWSilFlashWriter.dll",
                    "TCUWCanCIDGetter.dll",
                    "",
                    "0\n0\n0\n0",
                    "",
                    "",
                    *parameter_values.values(),
                ),
            ),
        )
    default_catalog_sources["149P5-Unified.ini"] = encoded_table(
        table_headers,
        (
            (
                "149P5-Unified",
                "TCUWSilPrepareWriter.dll",
                "TCUWSilFlashWriter.dll",
                "TCUWCanCIDGetter.dll",
                "",
                "0\n0\n0\n0",
                "",
                "",
                *parameter_values.values(),
            ),
        ),
    )
    if catalog_sources is None:
        selected_catalog_sources = default_catalog_sources
    else:
        if not isinstance(catalog_sources, Mapping) or any(
            type(name) is not str or type(data) is not bytes
            for name, data in catalog_sources.items()
        ):
            raise TypeError("Exact authored catalog source bytes required")
        selected_catalog_sources = dict(catalog_sources)
    if raw_reply_payloads_by_root is None:
        payloads_by_root = (
            (b"\x49\0\x10\0\0\0", b"\x49\x04\x01" + b"PLAIN_OLD\0".ljust(16, b" ")),
            (b"\x49\0\x10\0\0\0", b"\x49\x04\x01" + b"OLD_GROUP\0".ljust(16, b" ")),
        )
    else:
        if (
            type(raw_reply_payloads_by_root) is not tuple
            or len(raw_reply_payloads_by_root) != 2
            or any(
                type(root_payloads) is not tuple
                or not root_payloads
                or any(
                    type(payload) is not bytes or len(payload) > 4096
                    for payload in root_payloads
                )
                for root_payloads in raw_reply_payloads_by_root
            )
        ):
            raise TypeError("Two raw CanCID reply-payload sequences required")
        payloads_by_root = raw_reply_payloads_by_root

    recorder = RawControlStageMachineTests()
    case.addCleanup(recorder.doCleanups)
    _engine, _controller, recorder_session = make_raw_control_fixture2026(
        recorder,
        source=calibration,
        catalog=selected_catalog_sources,
        module_files=module_bytes,
        operation="get_cid",
    )
    source_metadata = native2026_metadata(
        recorder_session.container, node=1, cpu_index=0
    )
    binding, module, *_ = recorder_session._dispatch()
    if module.native_identity is None:
        raise AssertionError("Authenticated CanCID module identity required")
    reads: list[NativeMessage] = []
    rows: list[dict[str, Any]] = []
    payload_iter = iter(payloads_by_root[0])
    response_headers_by_request: dict[bytes, bytes] = {}
    delivered_raw_replies: list[tuple[bytes, bytes]] = []
    tail_active = False
    tail_clock_ticks = 0

    def capture_local_clock(operation: str) -> int:
        nonlocal tail_clock_ticks
        value = 1000 + tail_clock_ticks * 1000
        tail_clock_ticks += 1
        if tail_active:
            event = {"operation": operation}
            rows.append(
                {
                    "kind": "action",
                    "request": _native_request(event),
                    "result": {"type": "int", "value": value},
                    "elapsed_ms": 1,
                }
            )
        return value

    def encode(value: Any) -> dict[str, Any]:
        if value is None:
            return {"type": "none", "value": None}
        if type(value) is bool:
            return {"type": "bool", "value": value}
        if type(value) is int:
            return {"type": "int", "value": value}
        if type(value) is bytes:
            return {"type": "bytes", "value": value.hex()}
        if isinstance(value, NativeMessage):
            return {
                "type": "mapping",
                "value": {
                    "_native_type": {"type": "text", "value": "PASSTHRU_MSG_2026"},
                    **{key: encode(item) for key, item in vars(value).items()},
                },
            }
        if type(value) is tuple:
            return {"type": "tuple", "value": [encode(item) for item in value]}
        if type(value) is dict:
            return {
                "type": "mapping",
                "value": {key: encode(item) for key, item in value.items()},
            }
        raise TypeError(f"Unsupported captured J2534 result: {type(value)!r}")

    def capture_driver(event: dict[str, Any], _remaining: float) -> PrimitiveResult:
        if tail_active:
            if tail_driver is None:
                raise AssertionError("Tail primitive reply callback disappeared")
            result = tail_driver(event, _remaining)
            if type(result) is not PrimitiveResult:
                raise TypeError("Actual tail provider must return PrimitiveResult")
        else:
            result = None
        operation = event["operation"]
        if result is not None:
            pass
        elif operation == "passthru_write":
            message = event["messages"][0]
            response_header = response_headers_by_request.get(message.data[:4])
            if response_header is None:
                raise AssertionError("Actual selected CanCID response address required")
            payload = next(payload_iter)
            delivered_raw_replies.append((response_header, payload))
            reads.extend(
                (
                    NativeMessage(6, message.data[:4], rx_status=9),
                    NativeMessage(6, response_header + payload),
                )
            )
            result = PrimitiveResult(value=1)
        elif operation == "passthru_read":
            result = PrimitiveResult(value=(reads.pop(0),))
        elif operation in ("passthru_open", "passthru_connect"):
            result = PrimitiveResult(value=17)
        elif operation == "passthru_start_filter":
            result = PrimitiveResult(value=101)
        elif operation == "create_mutex":
            result = PrimitiveResult(value=1)
        elif operation == "wait_handle":
            result = PrimitiveResult(value=0)
        elif operation == "load_library":
            result = PrimitiveResult(value=2)
        elif operation == "get_symbol":
            result = PrimitiveResult(value=3)
        else:
            result = PrimitiveResult()
        rows.append(
            {
                "kind": "action",
                "request": _native_request(event),
                "result": encode({"status": result.status, "value": result.value}),
                "elapsed_ms": 1,
            }
        )
        return result

    class CapturedNativeRuntime2026(NativeRuntime2026):
        """Record notifications and log-mode host calls, retaining J2534 action."""

        def _provider(self, operation: str, cleanup: bool = False, **kwargs):
            if tail_active and (
                operation.startswith("notify_")
                or operation == "set_communication_log_mode"
            ):
                host_driver = tail_driver
                if host_driver is None:
                    raise AssertionError("Tail host reply callback disappeared")

                def capture_host_reply(event: dict[str, Any], remaining: float):
                    result = host_driver(event, remaining)
                    if type(result) is not PrimitiveResult:
                        raise TypeError(
                            "Actual tail host reply must be PrimitiveResult"
                        )
                    if result.status:
                        rows.append(
                            {
                                "kind": "action",
                                "request": _native_request(event),
                                "result": {
                                    "type": "error",
                                    "value": {
                                        "domain": "j2534_2026",
                                        "code": result.status,
                                        "detail": result.status,
                                    },
                                },
                                "elapsed_ms": 1,
                            }
                        )
                        raise ValueError(
                            "Native host callback returned a failure status"
                        )
                    rows.append(
                        {
                            "kind": "action",
                            "request": _native_request(event),
                            "result": encode(result.value),
                            "elapsed_ms": 1,
                        }
                    )
                    return result.value

                return capture_host_reply
            return super()._provider(operation, cleanup, **kwargs)

    def capture_runtime() -> CapturedNativeRuntime2026:
        return CapturedNativeRuntime2026(
            device.primitive,
            clock=clock,
            native_cancelled=lambda: False,
            local_seconds_of_day=lambda: (
                capture_local_clock("get_local_seconds_of_day") // 1000
            ),
            local_milliseconds_of_day=lambda: capture_local_clock(
                "get_local_milliseconds_of_day"
            ),
        )

    clock = lambda: 0
    device = J2534Device2026(capture_driver, clock=clock, background_workers=False)
    peer = J2534Device2026(capture_driver, clock=clock, background_workers=False)
    direct_pair = J2534InterfacePair2026(peer, device)
    for view in (direct_pair.engine, direct_pair.control):
        view.set_current_driver(DriverMetadata2026("Authored", "authored.dll"))
    device.have_ownership()
    initial_ownership_rows = tuple(rows)

    events_by_root = []
    captured_identifiers_by_root = []
    raw_transport_by_root: list[tuple[tuple[bytes, bytes], ...]] = []
    for root_index in range(2):
        rows.clear()
        if root_index == 0:
            rows.extend(initial_ownership_rows)
        reads.clear()
        payload_iter = iter(payloads_by_root[root_index])
        delivered_raw_replies.clear()
        cid_context = bind_can_cid_context(
            recorder_session.container,
            recorder_session.node,
            (),
            binding,
            module.native_identity,
            {},
            {},
        )
        response_headers_by_request = {
            address.headers()[0]: address.headers()[1]
            for address in cid_context.addresses
        }
        if len(response_headers_by_request) != len(cid_context.addresses):
            raise AssertionError("Selected CanCID request addresses must be unique")
        result = run_can_cid(
            cid_context,
            capture_runtime(),
        )
        if result["native_success"] is not True:
            raise AssertionError("Captured actual CanCID body did not succeed")
        if tuple(payload_iter):
            raise AssertionError("Captured CanCID body left raw reply payloads unused")
        raw_replies = tuple(delivered_raw_replies)
        transport_cids = tuple(
            cid.encode("latin-1")
            for response_header, payload in raw_replies
            if payload[:2] == b"\x49\x04"
            for cid in decode_can_cids2026(response_header + payload)
        )
        if result["cids"] != transport_cids:
            raise AssertionError("CanCID output differs from raw transport replies")
        captured_identifiers_by_root.append(tuple(result["cids"]))
        raw_transport_by_root.append(raw_replies)
        events_by_root.append(tuple(rows))
    captured_tail_events: tuple[dict[str, Any], ...] = ()
    try:
        if tail_capture is not None:
            tail_active = True
            tail_start = len(rows)
            tail_runtime = capture_runtime()
            if (
                tail_runtime.action != device.primitive
                or direct_pair.control is not device
            ):
                raise AssertionError(
                    "Tail must retain the exact captured provider and pair"
                )
            tail_result = tail_capture(direct_pair, tail_runtime)
            if tail_result is not None:
                raise TypeError(
                    "Tail callback may execute native work but return no outcome"
                )
            captured_tail_events = tuple(rows[tail_start:])
    finally:
        device.close()
        peer.close()

    typed_outputs = []
    replay = RawControlStageMachineTests()
    case.addCleanup(replay.doCleanups)
    from scripts.cuw_2026 import CUWEngine2026, identity_2026
    from scripts.programming_replay import load_programming_replay
    from tests.private_evidence import read_private_bytes

    events = (
        replay.event("get_local_milliseconds_of_day", 1000),
        *events_by_root[0],
        replay.event("get_local_milliseconds_of_day", 2000),
    )
    context = {
        "schema": "techstream-programming-replay-v1",
        "source": "recorded_unverified",
        "calibration_sha256": hashlib.sha256(calibration).hexdigest(),
        "operation": "get_cid",
        "node": 1,
        "observations": {
            "current_cids": [],
            "tester_info_hex": bytes(32).hex(),
            "system_time": [2026, 10, 22, 22, 1, 2, 3, 4],
            "timeout_seconds": 30,
            "cid_mode": 2,
            "host": {"driver_recording": "j2534_2026"},
        },
        "events": list(events),
    }

    session = load_programming_replay(
        calibration,
        json.dumps(context).encode(),
        selected_catalog_sources,
        {
            **module_bytes,
            "TCUWJ2534DeviceIF.dll": read_private_bytes(
                Path("runtime/no-car-21/recovered/TCUWJ2534DeviceIF.dll")
            ),
        },
    )
    case.addCleanup(session.trace.close)
    runtime = NativeRuntime2026(
        session.trace.action,
        clock=session.trace.clock,
        cancelled=session.trace.cancelled,
        local_seconds_of_day=session.trace.native_local_seconds_of_day,
        local_milliseconds_of_day=session.trace.native_local_milliseconds_of_day,
    )
    frontend = NativeFrontendParameters2026.from_sources(
        selected_catalog_sources, encoded=True
    )
    engine = CUWEngine2026(
        read_private_bytes(Path("runtime/no-car-21/recovered/CUW.dll")),
        general_parameters=frontend.general,
    )
    engine.bind_frontend_parameters(frontend)
    engine.configure(struct.pack("<IIddII", 2, 0, 1, 2, 0, 0))
    engine.load_cuw(calibration)
    case.addCleanup(engine.close)
    controller = ControlCommPhase2026(
        identity_2026(
            read_private_bytes(
                Path("runtime/no-car-21/recovered/TCUWControlCommPhase.dll")
            ),
            "TCUWControlCommPhase.dll",
        ),
        runtime,
    )
    session.bind_runtime2026(runtime)
    if session.trace.interface_pair is None:
        raise AssertionError("Paired strict replay did not issue an interface pair")
    for view in (
        session.trace.interface_pair.engine,
        session.trace.interface_pair.control,
    ):
        view.set_current_driver(DriverMetadata2026("Authored", "authored.dll"))
    engine.bind_interface_pair(session.trace.interface_pair)
    with engine.controller_execution(controller, 0):
        result = controller.execute(engine, session)
        context = controller.native_control_context2026(engine)
        output = _control_getter_output2026(context)
        if output is None:
            pool = controller._control_parameter_pool2026
            filenames = (
                tuple(slot.filename for slot in pool._state.slots)
                if pool is not None
                else ()
            )
            raise AssertionError(
                f"Captured CanCID trace did not issue typed output: {result!r}; "
                f"cursor={session.trace.position}; "
                f"next={[row['request']['operation'] for row in session.trace.rows[session.trace.position : session.trace.position + 4]]}; "
                f"native_error={engine.dh_state._primary_error}; "
                f"pool_filenames={filenames!r}"
            )
        typed_outputs.append(
            {
                "identifiers": output.identifiers,
                "raw_al": output.raw_al,
                "getter_mode": output.getter_mode,
                "module_names": tuple(
                    target.module_binding.module_name
                    for target in output.getter_targets
                ),
                "query_records34": output.query_records34,
                "communication_addresses": output.communication_addresses,
                "hardware": output.hardware,
            }
        )
        if result["identifiers"] != output.identifiers or output.identifiers != tuple(
            cid.encode("latin-1")
            for response_header, payload in raw_transport_by_root[0]
            if payload[:2] == b"\x49\x04"
            for cid in decode_can_cids2026(response_header + payload)
        ):
            raise AssertionError("Replay identifiers differ from typed output")

    return AuthoredCanCIDReplayFixture(
        calibration,
        selected_catalog_sources,
        module_bytes,
        (events_by_root[0], events_by_root[1]),
        (captured_identifiers_by_root[0], captured_identifiers_by_root[1]),
        (typed_outputs[0],),
        captured_tail_events,
        {
            "operation": "get_cid",
            "contact": source_metadata.vehicle.get("contacttype", ""),
            "cpus": 2,
            "getter": "TCUWCanCIDGetter.dll",
            "selector": "GetCanIDsFromParamForGetCID",
            "parameter_values": {
                "GetCANIDFunctionNameForGetCID": "GetCanIDsFromParamForGetCID",
                "CanIDForGetCID": "0200/0208",
                "ReceiveTimeoutBeforeGetCID": "123",
            },
            "paired": True,
            "source_names": tuple(
                cpu.values.get("cpuimagename", "") for cpu in source_metadata.cpus
            ),
            "local_clock_ms": (1000, 2000),
            "capture_order": (0, 1),
        },
    )


class AuthoredDHTail:
    """Capture a real whole-file DH writer tail on the fixture's same J2534 pair."""

    def __init__(self):
        from tests.private_evidence import read_private_bytes
        from tests.test_calibration_2026 import cuw, srecord
        from tests.test_cuw_engine_worker import encoded_table

        self.source = cuw(
            "[Format]\nVersion=105\n[Vehicle]\nNumberOfNode=1\n"
            "ContactType=P5-Unified\nKindOfECU=149\n[Node01]\n"
            "RequiredSpecReproVer=02\nDiagID=0200\nNumberOfCalibration=1\n"
            "[CPU11]\nCPUImageName=whole.vbf\nCPUType=311\n"
            "NumberOfTargetHardwares=1\n01_TargetHardware=\n"
            "NumberOfTargets=1\n01_TargetCalibration=OLD_GROUP\n",
            (b"\n".join((srecord(1, 0, b"xOLD_GROUP"), srecord(7, 0))),),
        )
        key = "149P5-Unified"
        values = {
            "ParamFileKeySystemProtocolMicon": key,
            "DLLFileNameForFlashWrite": "TCUWCanDHFlashWriter.dll",
            "DLLFileNameForPrepareWrite": "TCUWCanDHPrepareWriter.dll",
            "GetCANIDFunctionNameForFlashWrite": "GetCanIDsFromParamForPrepareWrite",
            "CanIDForPrepareWrite": "0700/0708",
            "StartAddress": "00000000",
            "FlagToNonChangeReprogGWModeProcess": "1",
            "PrepareRetryFlag": "1",
            "IGOffRetriableFlag": "1",
            "EnableDLLVersionInformation": "0\n0\n0\n0",
        }
        self.catalog = {
            key + ".ini": encoded_table(tuple(values), (tuple(values.values()),)),
            "Parameter.ini": encoded_table(
                (
                    "ParamFileKeySystemProtocolMicon",
                    "M16CTypeFlag",
                    "FORESTTypeFlag",
                    "PasswordAddress",
                    "ByteOrder",
                    "FlagToDoIGOFFONAtCPUTypeChange",
                    "FlagToChangeToReprogGWModeForCentralGW",
                ),
                (
                    (key, "0", "0", "00", "1", "0", "0"),
                    ("149P5-Unified311", "1", "0", "00", "1", "0", "0"),
                ),
            ),
        }
        self.modules = {
            name: read_private_bytes(Path("runtime/no-car-21/recovered") / name)
            for name in (
                "TCUWCanDHFlashWriter.dll",
                "TCUWCanDHPrepareWriter.dll",
                "TCUWDHUtils.dll",
                "SecretInfo.dll",
                "CUW.dll",
            )
        }
        self.pending: list[Any] = []
        self.pdus: list[str] = []
        self.result: dict[str, Any] | None = None
        self.pair: Any = None

    def driver(self, event: dict[str, Any], _remaining: float):
        from scripts.j2534_2026 import NativeMessage, PrimitiveResult

        operation = event["operation"]
        if operation.startswith("notify_"):
            return PrimitiveResult()
        if operation == "passthru_write":
            pdu = event["messages"][0].data[4:]
            self.pdus.append(pdu.hex())
            if pdu.startswith(b"\x34"):
                return PrimitiveResult(status=24)
            if pdu != bytes.fromhex("22fd10"):
                raise AssertionError(f"Unexpected actual DH PDU {pdu.hex()}")
            self.pending.append(
                NativeMessage(6, bytes.fromhex("00000708") + bytes.fromhex("62fd10"))
            )
            return PrimitiveResult(value=1)
        if operation == "passthru_read":
            return PrimitiveResult(value=(self.pending.pop(0),))
        if operation in ("passthru_open", "passthru_connect"):
            return PrimitiveResult(value=17)
        if operation == "passthru_start_filter":
            return PrimitiveResult(value=101)
        if operation == "wait_handle":
            return PrimitiveResult(value=0)
        return PrimitiveResult()

    def capture(self, pair: Any, runtime: Any) -> None:
        import hashlib
        import struct
        import tempfile

        from scripts.calibration import CalibrationContainer
        from scripts.calibration_2026 import parse_cuw_2026
        from scripts.calibration_catalog import inspect_module_bytes
        from scripts.cuw_2026 import CUWEngine2026
        from scripts.cuw_persistence import (
            CUWPersistence,
            RecoveryCalibration,
            ReproInfoState,
        )
        from scripts.native_modules import identify_native_module
        from scripts.programming_2026_common import (
            NativeGeneralParameters2026,
            bind_native_parameter2026,
        )
        from scripts.programming_2026_dh import bind_native_context, execute_context

        self.pair = pair
        if (
            pair.control.interface_pair is not pair
            or pair.engine.provider is not pair.control.provider
        ):
            raise AssertionError("DH tail must use the CanCID pair and provider")
        general = NativeGeneralParameters2026.from_sources(self.catalog, encoded=True)
        engine = CUWEngine2026(self.modules["CUW.dll"], general_parameters=general)
        persistence_dir = None
        try:
            engine.configure(struct.pack("<IIddII", 1, 0, 1, 2, 0, 0))
            engine.load_cuw(self.source)
            persistence_dir = tempfile.TemporaryDirectory(dir=Path(__file__).parent)
            engine.bind_persistence(
                CUWPersistence(
                    Path(persistence_dir.name),
                    ReproInfoState(
                        (
                            RecoveryCalibration(
                                "whole.cuw", self.source, blank_ecu_flags=(False,)
                            ),
                        ),
                        multi_calibration_file_num=1,
                        loaded=False,
                    ),
                )
            )
            container = parse_cuw_2026(self.source)
            if not isinstance(container, CalibrationContainer):
                raise TypeError("DH calibration source did not parse")
            selected = bind_native_parameter2026(
                container,
                self.catalog,
                "write",
                metadata_state=engine.native_metadata,
                encoded=True,
            )
            writer = "TCUWCanDHFlashWriter.dll"
            identity = identify_native_module(
                hashlib.sha256(self.modules[writer]).hexdigest(), writer
            )
            context = bind_native_context(
                container,
                1,
                (),
                selected,
                identity,
                {
                    "selected_module": self.modules[writer],
                    "dh_utils_module": self.modules["TCUWDHUtils.dll"],
                    "secret_info_module": self.modules["SecretInfo.dll"],
                    "cuw_module": self.modules["CUW.dll"],
                },
                {
                    "cpu_index": 0,
                    "dh_state": engine.dh_state,
                    "module_version": inspect_module_bytes(
                        self.modules[writer], writer
                    )["version"],
                },
            )
            if not pair.control.opened:
                pair.control.open()
            if not pair.control.connecting:
                pair.control.connect(6)
            self.result = execute_context(context, runtime)
            if (
                self.result["native_return"] is not False
                or self.result.get("native_passthru_error") != 24
            ):
                raise AssertionError(
                    f"Actual DH writer did not report status 24: {self.result}"
                )
        finally:
            engine.close()
            if persistence_dir is not None:
                persistence_dir.cleanup()


def authored_classic_can40_inputs() -> tuple[
    bytes, Mapping[str, bytes], tuple[tuple[bytes, ...], tuple[bytes, ...]]
]:
    from tests.test_calibration_2026 import cuw, srecord
    from tests.test_cuw_engine_worker import encoded_table

    def assert_equal(actual: object, expected: object) -> None:
        if actual != expected:
            raise AssertionError(f"Authored classic CAN input mismatch: {actual!r}")

    def classic_source() -> bytes:
        source_text = (
            "[Format]\nVersion=40\n[Vehicle]\nContactType=CAN\n"
            "KindOfECU=149\nNumberOfCalibration=2\n"
        )
        for index, (new_cid, target) in enumerate(
            (
                ("PLAIN_NEW", "NO_PLAIN_MATCH"),
                ("PLAIN_FOREST_NEW", "NO_OTHER_MATCH"),
            ),
            1,
        ):
            source_text += (
                f"[CPU{index:02}]\nCPUImageName=plain{index}.bin\n"
                f"CPUType={310 + index}\nNewCID={new_cid}\n"
                "NumberOfTargetHardwares=1\n01_TargetHardware=\n"
                f"NumberOfTargets=1\n01_TargetCalibration={target}\n"
            )
        file_payloads = tuple(
            b"\n".join((srecord(1, 0, value), srecord(7, 0)))
            for value in (b"\x11\x22\x33\x44", b"\x01\x02\x03\x04")
        )
        return cuw(source_text, file_payloads)

    calibration = classic_source()
    assert_equal(
        hashlib.sha256(calibration).hexdigest(),
        "699a07351b446defe869a120aab0481a0498ef0caeee1b95f310724ccc277556",
    )
    common = {
        "PasswordAddress": "00",
        "ByteOrder": "1",
        "FlagToHoldSFormatRecords": "0",
        "FlagToChangeProtocolAtSuccessGetCID": "0",
        "FlagToDoIGOFFONAtCPUTypeChange": "0",
        "FlagToChangeToReprogGWModeForCentralGW": "0",
        "FlagToUseCIDGetterAndFlashWriterDLL": "0",
        "WaitTimeForIGOFFON": "0",
        "WaitTimeAfterBatteryDisconnected": "0",
        "WaitTimeAfterBatteryConnected": "0",
        "BatteryVoltageUpperThreshold": "16000",
        "KindOfECUNames": "Authored CAN\nAuthored CAN\nAuthored CAN\nAuthored CAN",
    }
    parameter_headers = (
        "ParamFileKeySystemProtocolMicon",
        "M16CTypeFlag",
        "FORESTTypeFlag",
        *common,
    )
    catalog_sources = {
        "Parameter.ini": encoded_table(
            parameter_headers,
            tuple(
                (key, m16c, forest, *common.values())
                for key, m16c, forest in (
                    ("149CAN311", "1", "0"),
                    ("149CAN312", "0", "1"),
                    ("P5-Unified", "0", "0"),
                )
            ),
        ),
        "CanIDTable.ini": encoded_table(
            ("RequestCANID", "CalibrationType"), (("0200", "17"),)
        ),
        "LogicalAddressTable.ini": encoded_table(
            ("LogicalAddress", "CalibrationType"), (("0103", "18"),)
        ),
    }
    profile = {
        "DLLFileNameForGetCID": "TCUWCanCIDGetter.dll",
        "DLLFileNameForPrepareWrite": "TCUWCanDHPrepareWriter.dll",
        "DLLFileNameForFlashWrite": "TCUWCanDHFlashWriter.dll",
        "DLLFileNameForChangeToReprogGatewayMode": "",
        "EnableDLLVersionInformation": "0\n0\n0\n0",
        "GetCANIDFunctionNameForGetCID": "GetCanIDsFromParamForGetCID",
        "CanIDForGetCID": "0200/0208",
        "ReceiveTimeoutBeforeGetCID": "123",
        "GetCANIDFunctionNameForPrepareWrite": "GetCanIDsFromParamForPrepareWrite",
        "GetCANIDFunctionNameForFlashWrite": "GetCanIDsFromParamForPrepareWrite",
        "CanIDForPrepareWrite": "0200/0208",
        "AlternateDLLFileNamesForGetCID": "",
        "StartAddress": "00000000",
        "FlagToNonChangeReprogGWModeProcess": "1",
        "PrepareRetryFlag": "1",
        "IGOffRetriableFlag": "1",
    }
    profile_headers = (
        "ParamFileKeySystemProtocolMicon",
        *profile,
    )
    for key in ("149CAN311", "149CAN312"):
        catalog_sources[key + ".ini"] = encoded_table(
            profile_headers, ((key, *profile.values()),)
        )
    catalog_hashes = {
        "Parameter.ini": "5878a20c88505851c89e4f37811a4a0942518168aba82ed5bb58597a65d24af5",
        "CanIDTable.ini": "315d719007e06ab32377df35e856ab79dfcdaa820b4d713369bdf2654972caf3",
        "LogicalAddressTable.ini": "09983797fc3cd8e4988fbca32973808a30d8669658b4c4b1c97ccdb8582727dc",
        "149CAN311.ini": "731711c3555b1012025903ec560414f81a3d7870911320ebdc1a3bf0809e80d1",
        "149CAN312.ini": "0f97224ea1ecd5547adc4d3a7d978720dc136894789e5ee7eeded98fb8b01e1d",
    }
    for name, data in catalog_sources.items():
        assert_equal(hashlib.sha256(data).hexdigest(), catalog_hashes[name])
    payloads_by_root = (
        (
            bytes.fromhex("490010000000"),
            bytes.fromhex(
                "490402504c41494e5f4f4c4400202020202020554e52454c415445445f4f4c44002020"
            ),
        ),
        (
            bytes.fromhex("490010000000"),
            bytes.fromhex(
                "4904024f4c445f47524f555000202020202020464f524553545f4e4557002020202020"
            ),
        ),
    )
    assert_equal(
        payloads_by_root[0][1],
        bytes.fromhex(
            "490402504c41494e5f4f4c4400202020202020554e52454c415445445f4f4c44002020"
        ),
    )
    assert_equal(
        payloads_by_root[1][1],
        bytes.fromhex(
            "4904024f4c445f47524f555000202020202020464f524553545f4e4557002020202020"
        ),
    )

    return calibration, MappingProxyType(catalog_sources), payloads_by_root


class ProgrammingReplayTests(unittest.TestCase):
    def setUp(self):
        self.files = create_programming_examples()
        self.document = json.loads(self.files["authored-programming.json"])
        self.first_exchange = next(
            i
            for i, row in enumerate(self.document["events"])
            if row["kind"] == "exchange"
        )

    def test_authored_cancid_fixture_replays_first_of_two_real_getters(self):
        fixture = capture_authored_cancid_replay_fixture(self)
        self.assertEqual(len(fixture.events_by_root), 2)
        self.assertIsNot(fixture.events_by_root[0], fixture.events_by_root[1])
        self.assertIn("TCUWCanCIDGetter.dll", fixture.module_bytes)
        self.assertEqual(fixture.trace_setup["local_clock_ms"], (1000, 2000))
        self.assertEqual(fixture.trace_setup["capture_order"], (0, 1))
        self.assertEqual(len(fixture.typed_outputs), 1)
        output = fixture.typed_outputs[0]
        for index, events in enumerate(fixture.events_by_root):
            operations = tuple(row["request"]["operation"] for row in events)
            self.assertIn("passthru_open", operations)
            self.assertIn("passthru_connect", operations)
            self.assertIn("passthru_write", operations)
            self.assertIn("passthru_read", operations)
            expected = b"PLAIN_OLD" if index == 0 else b"OLD_GROUP"
            if index == 0:
                self.assertEqual(output["identifiers"], (expected,))
            self.assertTrue(output["raw_al"])
            self.assertEqual(output["getter_mode"], 0)
            self.assertEqual(output["module_names"], ("TCUWCanCIDGetter.dll",))
            self.assertTrue(
                all(len(record) == 12 for record in output["query_records34"])
            )

    def test_authored_no_file_bin_cancid_source_uses_actual_parser_and_body(self):
        from scripts.calibration_2026 import (
            native2026_cid_rebuild_allowed,
            native2026_metadata,
            parse_cuw_2026,
        )
        from tests.test_calibration_2026 import cuw

        calibration = cuw(
            "[Format]\nVersion=40\n[Vehicle]\nContactType=P5-Unified\n"
            "KindOfECU=149\nNumberOfCalibration=2\nDiagID=0200\n"
            "RequiredSpecReproVer=02\n[CPU01]\nCPUImageName=source.bin\n"
            "CPUType=312\nNewCID=NEW_PLAIN\nNumberOfTargets=1\n"
            "01_TargetCalibration=NOT_RECEIVED\n[CPU02]\n"
            "CPUImageName=source2.bin\nCPUType=311\nNewCID=NEW_GROUP\n"
            "NumberOfTargets=1\n01_TargetCalibration=OLD_GROUP\n",
            (b"", b""),
        )
        self.assertEqual(
            hashlib.sha256(calibration).hexdigest(),
            "875cfc80ead03f5923555983c5dd582b4930288c4403ae7803d7470bcf7e1316",
        )
        container = parse_cuw_2026(calibration)
        first_cpu = native2026_metadata(container, node=1, cpu_index=0)
        second_cpu = native2026_metadata(container, node=1, cpu_index=1)
        self.assertTrue(native2026_cid_rebuild_allowed(first_cpu))
        self.assertEqual(first_cpu.cpu.files, ())
        self.assertEqual(second_cpu.cpu.files, ())
        self.assertEqual(first_cpu.cpu.values["cpuimagename"], "source.bin")
        self.assertEqual(second_cpu.cpu.values["cpuimagename"], "source2.bin")
        self.assertEqual(first_cpu.cpu.values["cputype"], "312")
        self.assertEqual(second_cpu.cpu.values["cputype"], "311")
        self.assertEqual(first_cpu.cpu.values["newcid"], "NEW_PLAIN")
        self.assertEqual(second_cpu.cpu.values["newcid"], "NEW_GROUP")
        self.assertEqual(first_cpu.cpu.values["01_targetcalibration"], "NOT_RECEIVED")
        self.assertEqual(second_cpu.cpu.values["01_targetcalibration"], "OLD_GROUP")

        fixture = capture_authored_cancid_replay_fixture(self, calibration=calibration)
        self.assertEqual(fixture.calibration, calibration)
        self.assertEqual(
            fixture.trace_setup["source_names"], ("source.bin", "source2.bin")
        )
        self.assertEqual(len(fixture.events_by_root), 2)
        self.assertEqual(fixture.typed_outputs[0]["identifiers"], (b"PLAIN_OLD",))

    def test_authored_classic_can40_sources_drive_two_real_cancid_acquisitions(self):
        calibration, catalog_sources, payloads_by_root = authored_classic_can40_inputs()
        fixture = capture_authored_cancid_replay_fixture(
            self,
            calibration=calibration,
            catalog_sources=catalog_sources,
            raw_reply_payloads_by_root=cast(
                tuple[tuple[bytes, ...], tuple[bytes, ...]], payloads_by_root
            ),
        )

        self.assertEqual(fixture.calibration, calibration)
        self.assertEqual(fixture.catalog_sources, catalog_sources)
        self.assertEqual(fixture.trace_setup["contact"], "CAN")
        self.assertEqual(
            fixture.captured_identifiers_by_root,
            (
                (b"PLAIN_OLD", b"UNRELATED_OLD"),
                (b"OLD_GROUP", b"FOREST_NEW"),
            ),
        )
        self.assertEqual(
            fixture.typed_outputs[0]["identifiers"],
            (b"PLAIN_OLD", b"UNRELATED_OLD"),
        )
        self.assertEqual(fixture.trace_setup["capture_order"], (0, 1))

    def test_actual_dh_writer_tail_uses_same_cancid_pair_and_records_fault(self):
        tail = AuthoredDHTail()
        fixture = capture_authored_cancid_replay_fixture(
            self, tail_capture=tail.capture, tail_driver=tail.driver
        )
        self.assertEqual(len(fixture.events_by_root), 2)
        self.assertIs(tail.pair.control, tail.pair.engine.interface_pair.control)
        self.assertIs(tail.pair.control.provider, tail.pair.engine.provider)
        self.assertIsNotNone(tail.result)
        assert tail.result is not None
        self.assertIs(tail.result["native_return"], False)
        self.assertEqual(tail.result["native_passthru_error"], 24)
        self.assertTrue(any(pdu.startswith("34") for pdu in tail.pdus))
        operations = tuple(
            row["request"]["operation"] for row in fixture.captured_tail_events
        )
        self.assertIn("passthru_open", operations)
        self.assertIn("passthru_connect", operations)
        self.assertIn("notify_programming_active", operations)
        self.assertIn("passthru_write", operations)
        host_rows = tuple(
            row
            for row in fixture.captured_tail_events
            if row["request"]["operation"].startswith("notify_")
        )
        self.assertTrue(host_rows)
        self.assertTrue(
            all(row["result"] == {"type": "none", "value": None} for row in host_rows)
        )

    def test_selected_suzuki_usb_callback_publishes_before_provider_fault(self):
        import hashlib
        import tempfile
        import zlib

        from scripts.calibration_2026 import parse_cuw_2026
        from scripts.cuw_2026 import CUWEngine2026, identity_2026
        from scripts.cuw_persistence import (
            CUWPersistence,
            RecoveryCalibration,
            ReproInfoState,
        )
        from scripts.native_modules import identify_native_module
        from scripts.programming_2026_common import (
            ControlCommPhase2026,
            NativeFrontendParameters2026,
            NativeRuntime2026,
            bind_native_parameter2026,
        )
        from scripts.programming_2026_suzuki_fhi import (
            bind_native_context,
            execute_context,
        )
        from scripts.programming_replay import _native_request
        from tests.private_evidence import read_private_bytes
        from tests.test_cuw_engine_worker import encoded_table

        def encode(value: Any) -> dict[str, Any]:
            if value is None:
                return {"type": "none", "value": None}
            if type(value) is bool:
                return {"type": "bool", "value": value}
            if type(value) is int:
                return {"type": "int", "value": value}
            if type(value) is bytes:
                return {"type": "bytes", "value": value.hex()}
            if type(value) is tuple:
                return {"type": "tuple", "value": [encode(item) for item in value]}
            raise TypeError(
                f"Unsupported captured Suzuki callback value: {type(value)!r}"
            )

        def record(header: bytes, data: bytes) -> bytes:
            return (
                struct.pack(">H", len(header))
                + header
                + struct.pack(">II", len(data), zlib.crc32(data))
                + data
            )

        metadata = (
            b"[Format]\nVersion=10\n[Vehicle]\nKindOfECU=31\n"
            b"ContactType=SUZUKI\nNumberOfCalibration=1\n"
            b"ByteNumberOfTransmitting=00000003\nCANIDTx_Func_USDT=07DF\n"
            b"CANIDTx_Phys_USDT=07E01234\nCANIDRx_Phys_USDT=07E85678\n"
            b"[CPU01]\nCPUImageName=authored.vbf\nStartAddress=0100001000\n"
            b"SizeOfUncompressedDownloadData=00000008\nSizeOfDownloadData=00000004\n"
        )
        payload = b"DATAextra"
        body = (
            record(b"authored.att", metadata)
            + b"\x01"
            + record(b"authored.bin", payload)
        )
        calibration = (
            b"\0CALIBRATION\0\x68" + bytes(4) + struct.pack(">I", 22 + len(body)) + body
        )
        calibration = (
            calibration[:14]
            + struct.pack(">I", zlib.crc32(calibration[18:]))
            + calibration[18:]
        )
        module_name = "TCUWCanSuzukiUSBReproUDSFlashWriter.dll"
        utility_name = "TCUWCanSuzukiUDSUtils.dll"
        source_catalog = {
            "31SUZUKI.ini": encoded_table(
                (
                    "ParamFileKeySystemProtocolMicon",
                    "DLLFileNameForFlashWrite",
                    "GetCANIDFunctionNameForFlashWrite",
                    "WaitTimeForIGOFFON",
                    "AlternateWaitTimeForIGOFFON",
                    "CpuLoopBetweenPrepareAndWriteFlag",
                    "EnableDLLVersionInformation",
                ),
                (
                    (
                        "31SUZUKI",
                        module_name,
                        "GetCanIDsFromCalibrationFileForSUZUKI",
                        "5",
                        "12",
                        "0",
                        "0\n0\n0\n0",
                    ),
                ),
            ),
            "Parameter.ini": encoded_table(
                (
                    "ParamFileKeySystemProtocolMicon",
                    "M16CTypeFlag",
                    "FORESTTypeFlag",
                    "PasswordAddress",
                    "ByteOrder",
                    "FlagToDoIGOFFONAtCPUTypeChange",
                    "FlagToChangeToReprogGWModeForCentralGW",
                    "WaitTimeForIGOFFON",
                    "WaitTimeAfterBatteryDisconnected",
                    "WaitTimeAfterBatteryConnected",
                    "BatteryVoltageUpperThreshold",
                ),
                (("31SUZUKI", "0", "0", "00", "1", "0", "0", "5", "6", "7", "12.5"),),
            ),
            "CanIDTable.ini": encoded_table(
                ("RequestCANID", "ResponseCANID"), (("07E0", "07E8"),)
            ),
            "LogicalAddressTable.ini": encoded_table(
                ("LogicalAddress",), (("SUZUKI",),)
            ),
        }
        image_root = Path("runtime/no-car-21/recovered")
        module_files = {
            name: read_private_bytes(image_root / name)
            for name in (
                module_name,
                utility_name,
                "CUW.dll",
                "TCUWControlCommPhase.dll",
            )
        }
        container = parse_cuw_2026(calibration)
        frontend = NativeFrontendParameters2026.from_sources(
            source_catalog, encoded=True
        )

        direct_engine = CUWEngine2026(
            module_files["CUW.dll"], general_parameters=frontend.general
        )
        self.addCleanup(direct_engine.close)
        direct_engine.configure(struct.pack("<IIddII", 1, 0, 1, 2, 0, 0))
        direct_engine.bind_frontend_parameters(frontend)
        direct_engine.load_cuw(calibration)
        direct_persistence = tempfile.TemporaryDirectory()
        self.addCleanup(direct_persistence.cleanup)
        direct_engine.bind_persistence(
            CUWPersistence(
                Path(direct_persistence.name),
                ReproInfoState(
                    (
                        RecoveryCalibration(
                            "authored.cuw", calibration, blank_ecu_flags=(False,)
                        ),
                    ),
                    multi_calibration_file_num=1,
                    loaded=False,
                ),
            )
        )
        binding = bind_native_parameter2026(
            container,
            source_catalog,
            "write",
            node=1,
            cpu_index=0,
            metadata_state=direct_engine.native_metadata,
            encoded=True,
        )
        identity = identify_native_module(
            hashlib.sha256(module_files[module_name]).hexdigest(), module_name
        )
        native_context = bind_native_context(
            container,
            1,
            (),
            binding,
            identity,
            {
                "selected_module": module_files[module_name],
                "utils_module": module_files[utility_name],
                "cuw_module": module_files["CUW.dll"],
            },
            {"cpu_index": 0, "suzuki_state": direct_engine.suzuki_state},
        )
        captured_rows: list[dict[str, Any]] = []
        nested_action_rows: list[dict[str, Any]] = []
        nested_action_capture = False
        last_request = b""

        def capture_action(event: dict[str, Any], _remaining: float):
            nonlocal last_request
            operation = event["operation"]
            if operation == "start_flow_control_filter":
                result: Any = 8
            elif operation == "get_timeout":
                result = 2000
            elif operation == "write_messages":
                last_request = event["data"][4:]
                result = 1
            elif operation == "read_specified_can_message":
                replies = {
                    b"\x2e\xcf\x80\x01": b"\x6e\xcf\x80",
                    b"\x31\x01\xda\x00": b"\x71\x01\xda\x00\x01",
                    b"\x31\x03\xda\x00": b"\x71\x03\xda\x00\x06",
                    b"\x31\x01\xd9\x15": b"\x71\x01\xd9\x15\x01",
                    b"\x31\x01\xda\x01": b"\x71\x01\xda\x01\x01",
                }
                result = bytes.fromhex("000007e8") + replies[last_request]
            else:
                result = None
            row = {
                "kind": "action",
                "request": _native_request(event),
                "result": encode(result),
                "elapsed_ms": 1,
            }
            (nested_action_rows if nested_action_capture else captured_rows).append(row)
            return result

        capture_runtime = NativeRuntime2026(
            capture_action, native_cancelled=lambda: False
        )
        captured_result = execute_context(native_context, capture_runtime)
        self.assertTrue(captured_result["native_return"])
        self.assertEqual(direct_engine.native_wait_time_for_igoffon2026(1), 0)
        self.assertIn(
            "notify_igoffon_wait",
            [row["request"]["operation"] for row in captured_rows],
        )
        callback_row = next(
            row
            for row in captured_rows
            if row["request"]["operation"] == "notify_igoffon_wait"
        )
        self.assertEqual(callback_row["request"]["value"], 12)
        callback_row["result"] = {
            "type": "error",
            "value": {
                "domain": "j2534_2026",
                "code": 5,
                "detail": 5,
            },
        }
        recording = {
            "schema": "techstream-programming-replay-v1",
            "source": "recorded_unverified",
            "calibration_sha256": hashlib.sha256(calibration).hexdigest(),
            "operation": "write",
            "node": 1,
            "observations": {
                "current_cids": [],
                "tester_info_hex": bytes(32).hex(),
                "system_time": [2026, 10, 22, 22, 1, 2, 3, 4],
                "timeout_seconds": 30,
                "cid_mode": 2,
                "host": {"cpu_index": 0},
            },
            "events": [
                {
                    "kind": "action",
                    "request": {"operation": "get_local_milliseconds_of_day"},
                    "result": {"type": "int", "value": 1000},
                    "elapsed_ms": 1,
                },
                *captured_rows,
                {
                    "kind": "action",
                    "request": {"operation": "get_local_milliseconds_of_day"},
                    "result": {"type": "int", "value": 2000},
                    "elapsed_ms": 1,
                },
            ],
        }
        session = load_programming_replay(
            calibration, json.dumps(recording).encode(), source_catalog, module_files
        )
        self.addCleanup(session.trace.close)
        runtime = None
        trace_action = session.trace.action
        reentry_started = False
        reentry_result = None
        reentry_error = None
        reentry_wait_value = None

        def replay_action(event: dict[str, Any], remaining: float):
            nonlocal nested_action_capture
            nonlocal reentry_started, reentry_result, reentry_error
            nonlocal reentry_wait_value
            scope = (
                getattr(runtime._device_calls, "suzuki_wait_scope", None)
                if runtime is not None
                else None
            )
            if scope is not None and not reentry_started:
                reentry_started = True
                nested_action_capture = True
                try:
                    reentry_result = execute_context(scope.runner_context, runtime)
                except ValueError as exc:
                    reentry_error = exc
                finally:
                    nested_action_capture = False
                reentry_wait_value = engine.native_wait_time_for_igoffon2026(1)
            if nested_action_capture:
                return capture_action(event, remaining)
            return trace_action(event, remaining)

        session.trace.action = replay_action
        runtime = NativeRuntime2026(
            session.trace.action,
            clock=session.trace.clock,
            cancelled=session.trace.cancelled,
            local_seconds_of_day=session.trace.native_local_seconds_of_day,
            local_milliseconds_of_day=session.trace.native_local_milliseconds_of_day,
        )
        controller = ControlCommPhase2026(
            identity_2026(
                module_files["TCUWControlCommPhase.dll"], "TCUWControlCommPhase.dll"
            ),
            runtime,
        )
        engine = CUWEngine2026(
            module_files["CUW.dll"], general_parameters=frontend.general
        )
        self.addCleanup(engine.close)
        engine.configure(struct.pack("<IIddII", 1, 0, 1, 2, 0, 0))
        engine.bind_frontend_parameters(frontend)
        engine.load_cuw(calibration)
        persistence_dir = tempfile.TemporaryDirectory()
        self.addCleanup(persistence_dir.cleanup)
        engine.bind_persistence(
            CUWPersistence(
                Path(persistence_dir.name),
                ReproInfoState(
                    (
                        RecoveryCalibration(
                            "authored.cuw", calibration, blank_ecu_flags=(False,)
                        ),
                    ),
                    multi_calibration_file_num=1,
                    loaded=False,
                ),
            )
        )
        session.bind_controller2026(controller)
        session.bind_engine2026(engine)
        with engine.controller_execution(controller, 0):
            result = session.run_bound2026(runtime)
        self.assertTrue(reentry_started)
        self.assertIn(
            "start_flow_control_filter",
            [row["request"]["operation"] for row in nested_action_rows],
        )
        self.assertIsInstance(reentry_result, dict)
        assert reentry_result is not None
        self.assertEqual(reentry_result["error"], "ValueError")
        self.assertIsNone(reentry_error)
        self.assertEqual(reentry_wait_value, 0)
        self.assertEqual(result["module"], module_name)
        self.assertIs(result["native_return"], False)
        self.assertEqual(engine.native_wait_time_for_igoffon2026(1), 12)
        self.assertEqual(engine.native_wait_time_for_igoffon2026(2), 0)
        self.assertEqual(engine.native_wait_time_for_igoffon2026(3), 0)
        self.assertEqual(session.trace.position, len(captured_rows) + 2)

        (
            raw_result,
            raw_callback_authority,
            raw_events,
            raw_driver,
            raw_engine,
            raw_controller,
            raw_session,
            raw_runtime,
        ) = _run_authored_suzuki_raw_control(
            self, calibration, source_catalog, module_files
        )
        self.assertEqual(raw_result["native_phase"], 2)
        self.assertIs(raw_result["native_return"], True)
        self.assertEqual(raw_result["exports"][0]["state"], "writer_completed")
        self.assertEqual(raw_result["exports"][0]["module"], module_name)
        self.assertEqual(
            raw_callback_authority,
            [
                {
                    "scope_active": True,
                    "target_active": True,
                    "target_type": "NativeControlExportTarget2026",
                    "stage_target_matches": True,
                    "stage_owners_match": True,
                    "export": "StartFlashWrite",
                    "lease_active": True,
                    "entry_active": True,
                    "thread_matches": True,
                    "context_matches": True,
                    "module": module_name,
                }
            ],
        )
        self.assertEqual(raw_engine.native_wait_time_for_igoffon2026(1), 12)
        self.assertEqual(raw_controller._native_control_export_lease2026, None)
        self.assertIsNone(raw_controller._native_control_helper_entry2026)
        self.assertIsNone(raw_session._control_target2026)
        self.assertIsNone(raw_session._control_export2026)
        self.assertIsNone(raw_runtime._device_calls.suzuki_wait_scope)
        self.assertEqual(len(raw_events), 35)
        self.assertEqual(raw_session.trace.position, len(raw_events))
        self.assertTrue(
            any(
                row["request"]["operation"] == "notify_igoffon_wait"
                for row in raw_events
            )
        )
        self.assertTrue(
            any(
                event["operation"] == "passthru_write"
                and event["messages"][0].data[4:] == b"\x2e\xcf\x80\x01"
                for event in raw_driver.events
            )
        )
        self.assertEqual(raw_driver.pending, [])

    def test_same_json_stream_is_validated_before_execution_and_spooled(self):
        class SmallReads(io.BytesIO):
            def read(self, size=-1):
                return super().read(min(size, 7))

        raw = self.files["authored-programming.json"]
        source = SmallReads(raw)
        session = load_programming_recording_stream(
            self.files["authored.cuw"],
            source,
            {"DEMOP5DEMO.ini": self.files["DEMOP5DEMO.ini"]},
            {"SyntheticProgramming.dll": self.files["SyntheticProgramming.dll"]},
        )
        rows = session.trace.rows
        try:
            self.assertNotIsInstance(rows, tuple)
            self.assertEqual(session.trace.position, 0)
            self.assertEqual(
                session.input_hashes["context"], hashlib.sha256(raw).hexdigest()
            )
            self.assertEqual(session.run()["state"], "writer_completed")
            self.assertFalse(source.closed)
        finally:
            session.trace.close()
        for broken in (
            raw + b"{}",
            raw[:-1],
            raw.replace(b'"events":', b'"events":[],"events":'),
        ):
            with self.assertRaises(ValueError):
                load_programming_recording_stream(
                    self.files["authored.cuw"],
                    SmallReads(broken),
                    {"DEMOP5DEMO.ini": self.files["DEMOP5DEMO.ini"]},
                    {
                        "SyntheticProgramming.dll": self.files[
                            "SyntheticProgramming.dll"
                        ]
                    },
                )

    def load(
        self,
        document=None,
        *,
        cuw=None,
        module=None,
        cancelled=lambda: False,
        attachments=None,
    ):
        return load_programming_replay(
            cuw or self.files["authored.cuw"],
            json.dumps(self.document if document is None else document).encode(),
            {"DEMOP5DEMO.ini": self.files["DEMOP5DEMO.ini"]},
            {
                "SyntheticProgramming.dll": self.files["SyntheticProgramming.dll"]
                if module is None
                else module
            },
            attachments=attachments,
            cancelled=cancelled,
        )

    def test_vbf_resume_root_is_fresh_and_uses_prepared_source_view(self):
        from scripts.programming_replay import ProgrammingReplay

        session = self.load()
        session.used = True
        runtime, controller, engine, job = (object() for _ in range(4))
        session._runtime2026 = runtime
        session._controller2026 = controller
        session._engine2026 = engine
        session.context["observations"]["host"].update(
            stage="stale-stage",
            native2026={"export": "stale-export", "stage": "stale-stage", "keep": 1},
        )
        container = SimpleNamespace(digest="a" * 64)
        request = SimpleNamespace(
            previous_session=session,
            container=container,
            source_sha256=container.digest,
            node=3,
            cpu_index=2,
            received_identifiers=(b"CID\x00", b"\xff"),
        )
        trace_position = session.trace.position
        from scripts import cuw_engine_threads

        with (
            patch.object(
                cuw_engine_threads,
                "validate_vbf_process_before2026",
                return_value=request,
                create=True,
            ) as validate,
            patch.object(
                session,
                "selected_identity",
                side_effect=AssertionError(
                    "root construction must not select a module"
                ),
            ) as select_identity,
        ):
            following = session._next_vbf_prepare2026(job, request)

        validate.assert_called_once_with(request, job, states=("prepared",))
        select_identity.assert_not_called()
        self.assertIs(type(following), ProgrammingReplay)
        self.assertIs(following.container, container)
        self.assertEqual(following.context["operation"], "prepare")
        self.assertEqual(following.context["node"], 3)
        self.assertEqual(following.context["calibration_sha256"], "a" * 64)
        self.assertEqual(
            following.context["observations"]["current_cids"], ("CID\x00", "\xff")
        )
        host = following.context["observations"]["host"]
        self.assertEqual(host["cpu_index"], 2)
        self.assertEqual(host["native2026"], {"keep": 1, "cpu_index": 2})
        self.assertNotIn("export", host["native2026"])
        self.assertNotIn("stage", host)
        self.assertNotIn("export", host)
        self.assertEqual(following.input_hashes["calibration"], "a" * 64)
        for name in (
            "catalog",
            "modules",
            "attachments",
            "trace",
            "_catalog_sources",
            "_module_files",
        ):
            self.assertIs(getattr(following, name), getattr(session, name))
        self.assertIs(following._runtime2026, runtime)
        self.assertIs(following._controller2026, controller)
        self.assertIs(following._engine2026, engine)
        self.assertFalse(following.used)
        for name in (
            "_selection2026",
            "_executed_selection2026",
            "_control_target2026",
            "_control_export2026",
            "_retained_export2026",
            "_alternate_parent2026",
        ):
            self.assertIsNone(getattr(following, name))
        host["native2026"]["keep"] = 2
        self.assertEqual(
            session.context["observations"]["host"]["native2026"]["keep"], 1
        )
        self.assertEqual(session.trace.position, trace_position)

    def test_vbf_resume_root_rejects_a_different_previous_root(self):
        session = self.load()
        session.used = True
        request = SimpleNamespace(previous_session=object())
        from scripts import cuw_engine_threads

        with (
            patch.object(
                cuw_engine_threads,
                "validate_vbf_process_before2026",
                return_value=request,
                create=True,
            ),
            self.assertRaisesRegex(ValueError, "previous raw root"),
        ):
            session._next_vbf_prepare2026(object(), request)

    def test_next_getter_root_rejects_noncontinuations_before_source_access(self):
        session = self.load()
        trace_position = session.trace.position
        with self.assertRaisesRegex(TypeError, "Exact native getter continuation"):
            session._next_cid_root_34cb0_2026(cast(Any, object()))
        self.assertEqual(session.trace.position, trace_position)
        self.assertFalse(session.used)

    def test_next_getter_root_rejects_continuation_with_foreign_job_type(self):
        from scripts.cuw_engine_worker import _NativeGetterContinuation2026

        session = self.load()
        entry = object.__new__(_NativeGetterContinuation2026)
        object.__setattr__(entry, "job", object())
        trace_position = session.trace.position
        with self.assertRaisesRegex(TypeError, "Exact native getter job"):
            session._next_cid_root_34cb0_2026(entry)
        self.assertEqual(session.trace.position, trace_position)
        self.assertFalse(session.used)

    def test_next_getter_root_rejects_continuation_with_foreign_worker_type(self):
        from scripts.cuw_engine_threads import EngineThreadJob2026
        from scripts.cuw_engine_worker import _NativeGetterContinuation2026

        session = self.load()
        entry = object.__new__(_NativeGetterContinuation2026)
        object.__setattr__(entry, "job", object.__new__(EngineThreadJob2026))
        object.__setattr__(entry, "worker", object())
        trace_position = session.trace.position
        with self.assertRaisesRegex(TypeError, "Exact native getter worker"):
            session._next_cid_root_34cb0_2026(entry)
        self.assertEqual(session.trace.position, trace_position)
        self.assertFalse(session.used)

    def test_constructed_getter_continuation_reaches_rejecting_validator_before_clone(
        self,
    ):
        from scripts.cuw_engine_threads import _TOKEN, EngineThreadJob2026
        from scripts.cuw_engine_worker import (
            EngineWorker2026,
            _NativeGetterContinuation2026,
        )
        from scripts.programming_replay import ProgrammingReplay

        session = self.load()
        entry = object.__new__(_NativeGetterContinuation2026)
        job = EngineThreadJob2026(SimpleNamespace(worker=None), None, _token=_TOKEN)
        object.__setattr__(entry, "job", job)
        object.__setattr__(entry, "worker", object.__new__(EngineWorker2026))
        object.__setattr__(entry, "old_completion", object())
        object.__setattr__(entry, "old_lease", object())
        trace_position = session.trace.position

        with (
            patch.object(ProgrammingReplay, "__init__", autospec=True) as clone,
            self.assertRaisesRegex(ValueError, "stale or foreign"),
        ):
            session._next_cid_root_34cb0_2026(entry)
        clone.assert_not_called()
        self.assertEqual(session.trace.position, trace_position)
        self.assertFalse(session.used)

    def test_fresh_clone_actual_import_metadata_writer_and_identity(self):
        from scripts.calibration_catalog import inspect_module_bytes

        module = self.files["SyntheticProgramming.dll"]
        inspected = inspect_module_bytes(module, "SyntheticProgramming.dll")
        self.assertEqual(inspected["version"], "1.0.0007.0")
        self.assertEqual(inspected["exports"], ["StartFlashWrite"])
        self.assertEqual(struct.unpack_from("<I", module, 0xA8)[0], 0)
        self.assertEqual(struct.unpack_from("<I", module, 0x19C)[0] & 0x20000000, 0)
        session = self.load()
        result = session.run()
        self.assertEqual(result["state"], "writer_completed")
        self.assertEqual(result["source_identity"]["kind"], "authored_fixture")
        self.assertEqual(result["events_remaining"], 0)
        self.assertFalse(result["programming_completed"])
        self.assertEqual(
            result["input_hashes"]["calibration"],
            hashlib.sha256(self.files["authored.cuw"]).hexdigest(),
        )
        with self.assertRaises(ValueError):
            session.run()

    def test_request_digest_compares_actual_bytes_without_replacing_payload(self):
        payload = b"authored actual calibration bytes"
        descriptor = {
            "type": "bytes_sha256",
            "length": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
        }
        row = {
            "kind": "action",
            "request": {"operation": "write_messages", "data": descriptor},
            "result": {"type": "int", "value": 1},
            "elapsed_ms": 0,
        }
        trace = ProgrammingTrace.validate([row])
        self.assertEqual(
            trace.action({"operation": "write_messages", "data": payload}, 1), 1
        )
        for wrong in (payload + b"x", bytes(len(payload)), descriptor):
            trace = ProgrammingTrace.validate([row])
            with self.assertRaises(ValueError):
                trace.action({"operation": "write_messages", "data": wrong}, 1)
            self.assertEqual(trace.position, 0)
        broken = json.loads(json.dumps(row))
        broken["request"]["data"]["sha256"] = "unknown"
        with self.assertRaises(ValueError):
            ProgrammingTrace.validate([broken])

    def test_native_progress_float_requests_are_finite_and_chronological(self):
        row = {
            "kind": "action",
            "request": {"operation": "progress", "percent": 12.5},
            "result": {"type": "none", "value": None},
            "elapsed_ms": 0,
        }
        trace = ProgrammingTrace.validate([row])
        self.assertIsNone(trace.action({"operation": "progress", "percent": 12.5}, 1))
        trace.assert_complete()
        for invalid in (float("nan"), float("inf"), 1e13):
            row["request"]["percent"] = invalid
            with self.assertRaises(ValueError):
                ProgrammingTrace.validate([row])

    def test_explicit_native2026_error_domains_and_cleanup_metadata(self):
        from scripts.programming_2026_common import (
            NativeJ2534Exception2026,
            NativePassThruException2026,
        )
        from scripts.programming_replay import _report

        for domain, code, detail in (("cpass2026", 73, None), ("j2534_2026", 1, 99)):
            fault = {"domain": domain, "code": code}
            if detail is not None:
                fault["detail"] = detail
            trace = ProgrammingTrace.validate(
                [
                    {
                        "kind": "action",
                        "request": {"operation": "get_timeout"},
                        "result": {"type": "error", "value": fault},
                        "elapsed_ms": 0,
                    }
                ]
            )
            expected = (
                NativePassThruException2026
                if detail is None
                else NativeJ2534Exception2026
            )
            with self.assertRaises(expected) as caught:
                trace.action({"operation": "get_timeout"}, 1)
            self.assertEqual(caught.exception.error, code)
            if detail is not None:
                assert isinstance(caught.exception, NativeJ2534Exception2026)
                self.assertEqual(caught.exception.j2534_error, detail)
        result = _report(
            {
                "native_error_code": 3,
                "native_error_domain": "CPassThruException",
                "cleanup_error_details": [
                    {
                        "phase": "stop_filter",
                        "native_error_domain": "CJ2534Exception",
                        "native_error_code": 99,
                        "error_chain": ["private key material"],
                    }
                ],
            }
        )
        details = result["cleanup_error_details"]
        assert isinstance(details, list)
        self.assertEqual(details[0]["native_error_code"], 99)
        self.assertNotIn("private key material", json.dumps(result))
        auxiliary = _report(
            {
                "native_results": [
                    {
                        "assembly": "AUTHORED12345",
                        "assembly_valid": False,
                        "assembly_error": {
                            "native_error_code": 92,
                            "error_chain": ["private"],
                        },
                        "history": ["private"],
                    }
                ]
            }
        )
        self.assertIn('"native_error_code": 92', json.dumps(auxiliary))
        self.assertNotIn("private", json.dumps(auxiliary))
        ansi = _report(
            {"identifiers": (b"\xff ", b"ASCII", b"ASCII"), "native_success": True}
        )
        self.assertEqual(ansi["identifiers"], ["ASCII", "ASCII"])
        self.assertEqual(
            ansi["identifier_bytes_hex"], ["ff20", "4153434949", "4153434949"]
        )
        records = ansi["identifier_records"]
        assert isinstance(records, list)
        self.assertEqual(records[0], {"bytes_hex": "ff20", "ascii": None})

    def test_native_error_reports_and_engine_binding_are_bounded(self):
        from scripts.programming_replay import _report

        self.assertEqual(
            _report(
                {
                    "native_error_code": 73,
                    "error_type": "NativeIDError",
                    "response": b"secret",
                }
            ),
            {"native_error_code": 73, "error_type": "NativeIDError"},
        )
        self.assertEqual(
            _report({"native_error": -(1 << 31) - 1, "error_type": "secret material"}),
            {},
        )
        session = self.load()
        with self.assertRaises(TypeError):
            session.bind_engine2026(object())
        self.assertEqual(session.trace.position, 0)
        self.assertFalse(session.used)

    def test_all_dh_writer_modules_reach_the_strict_native_binder(self):
        from scripts.programming_replay import BoundModule

        class BinderReached(Exception):
            pass

        for name in (
            "TCUWCanDHFlashWriter.dll",
            "TCUWCanDHGatewayFlashWriter.dll",
            "TCUWCanDH19PFSURegGatewayFlashWriter.dll",
            "TCUWCanDHMultiROMFlashWriter.dll",
        ):
            with self.subTest(module=name):
                session = self.load()
                module = BoundModule(name, "0" * 64, 2026, name[:-4], ())
                with (
                    patch(
                        "scripts.programming_2026_dh.bind_native_context",
                        side_effect=BinderReached,
                    ) as binder,
                    self.assertRaises(BinderReached),
                ):
                    session._runner2026(SimpleNamespace(operation="write"), module, ())
                binder.assert_called_once()
                self.assertEqual(session.trace.position, 0)

    def test_sil_controller_state_cannot_be_supplied_by_json(self):
        from scripts.programming_replay import BoundModule

        for key, value in (
            ("use_new_password", False),
            ("reset_requested", False),
            ("prepare_status", 0),
            ("received_cid_count", 0),
        ):
            with self.subTest(key=key):
                session = self.load()
                session.context["observations"]["host"]["native2026"] = {key: value}
                module = BoundModule(
                    "TCUWSilFlashWriter.dll", "0" * 64, 2026, "TCUWSilFlashWriter", ()
                )
                with self.assertRaisesRegex(ValueError, "SIL state must originate"):
                    session._runner2026(SimpleNamespace(operation="write"), module, ())
                self.assertEqual(session.trace.position, 0)

    def test_alternate_getter_requires_actual_native_cid_selection(self):
        session = self.load()
        with self.assertRaisesRegex(ValueError, "actual CID phase"):
            session.next_alternate_getter2026()
        with self.assertRaisesRegex(ValueError, "engine and controller required"):
            session.selected_binding2026()
        self.assertEqual(session.trace.position, 0)

    def test_ethernet_writer_requires_retained_engine_rks_identity(self):
        from scripts.programming_replay import BoundModule

        module = BoundModule(
            "TCUWEthernetReprostdFlashWriter.dll",
            "0" * 64,
            2026,
            "TCUWEthernetReprostdFlashWriter",
            (),
        )
        session = self.load()
        with self.assertRaisesRegex(ValueError, "Actual loaded RKS engine state"):
            session._runner2026(SimpleNamespace(operation="write"), module, ())
        session.context["observations"]["host"]["native2026"] = {
            "rks_software_identity": {"software_id": "CAPTURED"}
        }
        with self.assertRaisesRegex(ValueError, "must originate from engine"):
            session._runner2026(SimpleNamespace(operation="write"), module, ())
        self.assertEqual(session.trace.position, 0)

    def test_gateway_phase_cannot_reuse_an_ordinary_preparation_or_probe(self):
        from scripts.programming_replay import BoundModule

        document = json.loads(json.dumps(self.document))
        document["operation"] = "change_gateway"
        session = self.load(document)
        self.assertEqual(
            inspect_recording(json.dumps(document).encode())["operation"],
            "change_gateway",
        )
        for build, exports in (
            (18, ("ChangeToReprogGatewayMode",)),
            (2026, ("StartPrepareWrite", "IsFinishReprogramming")),
        ):
            with self.subTest(build=build):
                module = BoundModule(
                    "Candidate.dll", "0" * 64, build, "Candidate", exports
                )
                with self.assertRaisesRegex(ValueError, "actual gateway-mode export"):
                    session._runner(None, module, (), {}, {}, {})
        self.assertEqual(session.trace.position, 0)

    def test_ordinary_legacy_prepare_cannot_select_gateway_through_host_flag(self):
        session = self.load()
        session.context["operation"] = "prepare"
        session.context["observations"]["host"]["legacy"] = {"stage": "gateway"}
        with self.assertRaisesRegex(ValueError, "distinct gateway operation"):
            session._legacy_runner(None, SimpleNamespace(), 30)

    def test_raw_catalog_presence_does_not_parse_native_profile(self):
        session = self.load()
        session._catalog_sources = {"8P4A.ini": b"malformed native profile"}
        self.assertTrue(session.has_catalog_source2026("8P4A.ini"))
        self.assertFalse(session.has_catalog_source2026("missing.ini"))
        for name in ("../8P4A.ini", "", "x" * 261):
            with self.assertRaises(ValueError):
                session.has_catalog_source2026(name)
        self.assertEqual(session.trace.position, 0)

    def test_native_gateway_cached_byte_preserves_full_unsigned_domain(self):
        from scripts.programming_replay import _report

        for value in (0, 1, 2, 3, 255):
            self.assertEqual(_report({"gateway_kind": value})["gateway_kind"], value)
        for value in (-1, 256, True, "3"):
            self.assertNotIn("gateway_kind", _report({"gateway_kind": value}))

    def test_nested_online_clock_requires_bounded_captured_elapsed(self):
        trace = ProgrammingTrace(())
        trace.absorb_online_elapsed(0.125)
        self.assertEqual(trace.clock(), 0.125)
        for value in (True, -1, 601, float("nan"), float("inf"), "0.1"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                trace.absorb_online_elapsed(value)  # pyright: ignore[reportArgumentType]
            self.assertEqual(trace.clock(), 0.125)
        self.assertEqual(trace.position, 0)

    def test_online_attachment_descriptor_cannot_supply_a_successful_key(self):
        from scripts.programming_2026_common import NativeRuntime2026

        session = self.load()
        runtime = NativeRuntime2026(session.trace.action)
        for descriptor in (
            {"key": "SUCCESS"},
            {"configuration": "missing", "recording": "missing"},
        ):
            with self.subTest(descriptor=descriptor), self.assertRaises(ValueError):
                session._bind_online2026(runtime, {"online2026": descriptor})
        self.assertEqual(session.trace.position, 0)

    def test_recording_inspection_is_structural_and_omits_observations(self):
        raw = self.files["authored-programming.json"]
        report = inspect_recording(raw)
        self.assertEqual(report["operation"], "write")
        self.assertEqual(report["events"], 37)
        self.assertFalse(report["source_identity_validated"])
        self.assertNotIn("AUTHORED-OLD", json.dumps(report))
        for invalid in (b"{}", b"[]", b'{"schema":1,"schema":2}'):
            with (
                self.subTest(invalid=invalid),
                self.assertRaises((TypeError, ValueError)),
            ):
                inspect_recording(invalid)
        changed = json.loads(raw)
        changed["events"][0]["result"] = {"type": "bool", "value": 1}
        with self.assertRaises(ValueError):
            inspect_recording(json.dumps(changed).encode())

    def test_nested_native_results_and_recovery_error_detail(self):
        from scripts.programming import NativeRecoveryTransportError

        for operation, maximum in (
            ("get_local_seconds_of_day", 86399),
            ("get_local_milliseconds_of_day", 86399999),
        ):
            row = {
                "kind": "action",
                "request": {"operation": operation},
                "result": {"type": "int", "value": maximum + 1},
                "elapsed_ms": 0,
            }
            with self.assertRaises(ValueError):
                ProgrammingTrace.validate([row])
            row["result"]["value"] = maximum
            trace = ProgrammingTrace.validate([row])
            callback = (
                trace.native_local_seconds_of_day
                if operation == "get_local_seconds_of_day"
                else trace.native_local_milliseconds_of_day
            )
            self.assertEqual(callback(), maximum)

        for tag, expected in (("tuple", (1, 2)), ("sequence", [1, 2])):
            trace = ProgrammingTrace.validate(
                [
                    {
                        "kind": "action",
                        "request": {"operation": "observed_native_values"},
                        "result": {
                            "type": tag,
                            "value": [
                                {"type": "int", "value": 1},
                                {"type": "int", "value": 2},
                            ],
                        },
                        "elapsed_ms": 0,
                    }
                ]
            )
            self.assertEqual(
                trace.action({"operation": "observed_native_values"}, 1), expected
            )

        result = {
            "type": "mapping",
            "value": {
                "data": {"type": "bytes", "value": "55aa"},
                "rx_status": {"type": "int", "value": 0},
            },
        }
        request = {"operation": "FAST_INIT"}
        trace = ProgrammingTrace.validate(
            [
                {
                    "kind": "action",
                    "request": request,
                    "result": result,
                    "elapsed_ms": 0,
                },
                {
                    "kind": "action",
                    "request": {"operation": "reconnect"},
                    "result": {
                        "type": "error",
                        "value": {
                            "domain": "native",
                            "code": 9,
                            "detail": 16,
                        },
                    },
                    "elapsed_ms": 0,
                },
            ]
        )
        self.assertEqual(
            trace.action(request, 1), {"data": b"\x55\xaa", "rx_status": 0}
        )
        with self.assertRaises(NativeRecoveryTransportError) as caught:
            trace.action({"operation": "reconnect"}, 1)
        self.assertEqual((caught.exception.code, caught.exception.detail), (9, 16))
        result["value"]["rx_status"]["value"] = True
        with self.assertRaises(ValueError):
            ProgrammingTrace.validate(
                [
                    {
                        "kind": "action",
                        "request": request,
                        "result": result,
                        "elapsed_ms": 0,
                    }
                ]
            )

    def test_unknown_and_spoofed_module_or_source_rejected_before_events(self):
        for raw in (b"MZ" + bytes(200), self.files["SyntheticProgramming.dll"] + b"x"):
            with self.subTest(module=len(raw)), self.assertRaises(ValueError):
                self.load(module=raw)
        self.document["source"] = "recorded_unverified"
        with self.assertRaises(ValueError):
            self.load()
        self.document["source"] = "authored_synthetic"
        self.document["calibration_sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            self.load()

    def test_chronology_pending_receive_and_trailing_records(self):
        changed = json.loads(json.dumps(self.document))
        changed["events"][self.first_exchange]["request"]["payload_hex"] = "22f181"
        result = self.load(changed).run()
        self.assertEqual(result["state"], "recovery_required")
        self.assertEqual(result["events_consumed"], self.first_exchange)
        changed = json.loads(json.dumps(self.document))
        changed["events"].append(changed["events"][-1])
        result = self.load(changed).run()
        self.assertEqual(result["state"], "recovery_required")
        self.assertEqual(result["events_remaining"], 1)
        changed = json.loads(json.dumps(self.document))
        original = changed["events"][self.first_exchange]["result"]["value"]
        changed["events"][self.first_exchange]["result"]["value"] = "7f2e78"
        changed["events"].insert(
            self.first_exchange + 1,
            {
                "kind": "action",
                "request": {"operation": "set_timeout", "milliseconds": 1000},
                "result": {"type": "none", "value": None},
                "elapsed_ms": 0,
            },
        )
        changed["events"].insert(
            self.first_exchange + 2,
            {
                "kind": "receive",
                "request": {"ecu": "0700", "payload_hex": ""},
                "result": {"type": "bytes", "value": original},
                "elapsed_ms": 0,
            },
        )
        self.assertEqual(self.load(changed).run()["state"], "writer_completed")

    def test_each_captured_io_fault_remains_uncertain_and_never_resumes(self):
        for index in range(len(self.document["events"])):
            changed = json.loads(json.dumps(self.document))
            changed["events"][index]["result"] = {
                "type": "error",
                "value": {"domain": "host", "code": 1},
            }
            session = self.load(changed)
            with self.subTest(event=index):
                result = session.run()
                self.assertEqual(result["state"], "recovery_required")
                self.assertFalse(result["automatic_retry"])
                self.assertFalse(result["resume_authorized"])
                with self.assertRaises(ValueError):
                    session.run()

    def test_cancellation_and_callback_elapsed_deadline(self):
        session = self.load(cancelled=lambda: True)
        self.assertEqual(session.run()["events_consumed"], 0)
        changed = json.loads(json.dumps(self.document))
        changed["events"][0]["elapsed_ms"] = 31000
        result = self.load(changed).run()
        self.assertEqual(result["state"], "recovery_required")
        self.assertEqual(result["events_consumed"], 1)

    def test_every_callback_cancellation_and_deadline_including_final_cleanup(self):
        for index in range(len(self.document["events"])):
            holder = {}
            session = self.load(
                cancelled=lambda index=index, holder=holder: bool(
                    holder and holder["session"].trace.position >= index + 1
                )
            )
            holder["session"] = session
            with self.subTest(event=index, fault="cancel"):
                self.assertEqual(session.run()["state"], "recovery_required")
            changed = json.loads(json.dumps(self.document))
            changed["events"][index]["elapsed_ms"] += 31000
            with self.subTest(event=index, fault="deadline"):
                self.assertEqual(self.load(changed).run()["state"], "recovery_required")

    def test_schema_types_unknown_fields_duplicate_keys_and_path_aliases(self):
        malformed = json.loads(json.dumps(self.document))
        malformed["events"][self.first_exchange]["result"] = {
            "type": "none",
            "value": None,
        }
        with self.assertRaises(ValueError):
            self.load(malformed)
        malformed = json.loads(json.dumps(self.document))
        malformed["events"][self.first_exchange]["request"]["payload_hex"] = ""
        with self.assertRaises(ValueError):
            self.load(malformed)
        malformed = json.loads(json.dumps(self.document))
        malformed["input_path"] = "/etc/passwd"
        with self.assertRaises(ValueError):
            self.load(malformed)
        with self.assertRaises(ValueError):
            self.load(attachments={"../key": b"secret"})
        with self.assertRaises(ValueError):
            load_programming_replay(
                self.files["authored.cuw"], b'{"schema":1,"schema":2}', {}, {}
            )
        with self.assertRaises(ValueError):
            ProgrammingTrace.validate(
                [
                    {
                        "kind": "receive",
                        "request": {"ecu": "x", "payload_hex": "22"},
                        "result": {"type": "bytes", "value": "62"},
                        "elapsed_ms": 0,
                    }
                ]
            )

    def test_secrets_hidden_and_atomic_export_preserves_every_selected_source(self):
        secret = b"SECRET-AUTHORIZATION-MATERIAL"
        session = self.load(attachments={"authorized.bin": secret})
        report = session.run()
        self.assertNotIn(secret.decode(), repr(session))
        self.assertNotIn(secret.decode(), json.dumps(report))
        self.assertNotIn("history", json.dumps(report))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inputs = []
            for name, data in {**self.files, "authorized.bin": secret}.items():
                path = root / name
                path.write_bytes(data)
                inputs.append(path)
            for source in inputs:
                before = source.read_bytes()
                with self.assertRaises(ValueError):
                    session.export_result(source, input_paths=inputs)
                self.assertEqual(source.read_bytes(), before)
            hard = root / "hard.json"
            os.link(inputs[-1], hard)
            with self.assertRaises(ValueError):
                session.export_result(hard, input_paths=inputs)
            link = root / "link.json"
            link.symlink_to(inputs[0])
            with self.assertRaises(ValueError):
                session.export_result(link, input_paths=inputs)
            output = root / "result.json"
            session.export_result(output, input_paths=inputs)
            self.assertEqual(
                json.loads(output.read_bytes())["state"], "writer_completed"
            )
            self.assertFalse(tuple(root.glob(".programming-*")))
            imported, all_paths = load_programming_files(
                root / "authored.cuw",
                root / "authored-programming.json",
                {"DEMOP5DEMO.ini": root / "DEMOP5DEMO.ini"},
                {"SyntheticProgramming.dll": root / "SyntheticProgramming.dll"},
                attachment_paths={"authorized.bin": root / "authorized.bin"},
            )
            self.assertEqual(len(all_paths), 5)
            self.assertEqual(imported.run()["state"], "writer_completed")


class RecordedDeviceTests(unittest.TestCase):
    @staticmethod
    def tagged(value):
        if value is None:
            return {"type": "none", "value": None}
        if type(value) is int:
            return {"type": "int", "value": value}
        if isinstance(value, bytes):
            return {"type": "bytes", "value": value.hex()}
        if isinstance(value, str):
            return {"type": "text", "value": value}
        if isinstance(value, tuple):
            return {
                "type": "tuple",
                "value": [RecordedDeviceTests.tagged(v) for v in value],
            }
        return {
            "type": "mapping",
            "value": {k: RecordedDeviceTests.tagged(v) for k, v in value.items()},
        }

    @classmethod
    def row(cls, request, status=0, value=None):
        return {
            "kind": "action",
            "request": request,
            "result": cls.tagged({"status": status, "value": value}),
            "elapsed_ms": 1,
        }

    def test_retained_device_state_and_cleanup_after_host_cancel(self):
        from scripts.programming_2026_common import NativeRuntime2026

        stopped = [False]
        trace = ProgrammingTrace.validate(
            [
                self.row(
                    {"operation": "passthru_open", "name": None, "version": 0}, value=41
                ),
                self.row({"operation": "passthru_close", "device": 41}),
            ],
            cancelled=lambda: stopped[0],
        )
        device = trace.bind_recorded_device2026(timeout=30, max_calls=20)
        runtime = NativeRuntime2026(
            trace.action, clock=trace.clock, cancelled=trace.cancelled, max_calls=20
        )
        runtime.bind_recorded_device2026(trace, device)
        self.assertIs(runtime.recorded_device2026(), device)
        device.open()
        self.assertTrue(device.opened)
        stopped[0] = True
        trace.cleanup_primitive({"operation": "disconnect"}, 5)
        self.assertFalse(device.opened)
        self.assertEqual(trace.position, 2)
        with self.assertRaises(ValueError):
            trace.bind_recorded_device2026(timeout=30, max_calls=21)

    def test_distinct_native_views_share_exact_provider_and_release_once(self):
        from scripts.programming_replay import native_device_action2026

        trace = ProgrammingTrace.validate(
            [
                self.row(
                    {"operation": "passthru_open", "name": None, "version": 0}, value=41
                ),
                self.row({"operation": "passthru_close", "device": 41}),
            ]
        )
        control = trace.bind_recorded_device2026(timeout=30, max_calls=20)
        pair = trace.interface_pair
        self.assertIsNotNone(pair)
        assert pair is not None
        self.assertIs(control, pair.control)
        self.assertIs(trace.engine_device, pair.engine)
        self.assertIs(pair.engine.provider, control.provider)
        self.assertIs(pair.engine.clock, control.clock)
        self.assertIs(pair.engine.cancelled, control.cancelled)
        from scripts.j2534_2026 import DriverMetadata2026

        pair.engine.set_driver(DriverMetadata2026("authored", "offline.dll"))
        control.set_driver(DriverMetadata2026("authored", "offline.dll"))
        pair.engine.open()
        self.assertTrue(pair.engine.opened)
        self.assertFalse(control.opened)
        pair.import_into(control, pair.export_from(pair.engine))
        self.assertTrue(control.opened)
        native_device_action2026(control, {"operation": "disconnect"}, 5, cleanup=True)
        pair.engine.close()
        self.assertFalse(control.opened)
        self.assertFalse(pair.engine.opened)
        self.assertEqual(trace.position, 2)

    def test_driver_failure_preserves_unopened_device(self):
        from scripts.j2534_2026 import NativeJ2534Error2026

        trace = ProgrammingTrace.validate(
            [
                self.row(
                    {"operation": "passthru_open", "name": None, "version": 0}, status=7
                )
            ]
        )
        device = trace.bind_recorded_device2026(timeout=30, max_calls=20)
        with self.assertRaises(NativeJ2534Error2026):
            device.open()
        self.assertFalse(device.opened)
        self.assertEqual(trace.position, 1)

    def test_message_bytes_digest_and_explicit_typed_read_batch(self):
        from scripts.j2534_2026 import NativeMessage, NativeReadBatch2026

        message = {
            "_native_type": "PASSTHRU_MSG_2026",
            "protocol_id": 6,
            "data": b"\x00\x00\x01\x08\x62",
            "rx_status": 0,
            "tx_flags": 0,
            "timestamp": 13,
            "extra_data_index": 0,
        }
        request = {
            "operation": "passthru_write_msgs",
            "message": {
                **message,
                "data": {
                    "type": "bytes_sha256",
                    "length": 5,
                    "sha256": hashlib.sha256(message["data"]).hexdigest(),
                },
            },
        }
        trace = ProgrammingTrace.validate(
            [
                self.row(
                    request,
                    value={
                        "_native_type": "READ_BATCH_2026",
                        "messages": (message,),
                        "count": 1,
                    },
                )
            ]
        )
        result = trace.driver_primitive(
            {
                "operation": "passthru_write_msgs",
                "message": NativeMessage(6, message["data"], timestamp=13),
            },
            30,
        )
        self.assertIsInstance(result.value, NativeReadBatch2026)
        self.assertEqual(result.value.messages[0].data, message["data"])
        changed = ProgrammingTrace.validate([self.row(request)])
        with self.assertRaises(ValueError):
            changed.driver_primitive(
                {
                    "operation": "passthru_write_msgs",
                    "message": NativeMessage(6, b"wrong", timestamp=13),
                },
                30,
            )
        self.assertEqual(changed.position, 0)

    def test_no_default_driver_success_and_no_unknown_native_objects(self):
        for value in (
            None,
            {"value": 3},
            {"status": 0, "value": {"_native_type": "arbitrary"}},
        ):
            trace = ProgrammingTrace.validate(
                [
                    {
                        "kind": "action",
                        "request": {"operation": "passthru_open"},
                        "result": self.tagged(value),
                        "elapsed_ms": 0,
                    }
                ]
            )
            with self.subTest(value=value), self.assertRaises(ValueError):
                trace.driver_primitive({"operation": "passthru_open"}, 30)


def make_authentic_sbr_replay_fixture(
    case,
    *,
    data: bytes = b"DATA",
    cpu_count: int = 1,
    cpu_type_second: str = "283",
    block_response: bytes = bytes.fromhex("7420000a"),
    events_override=None,
    capture_progress: bool = True,
):
    """Build real SBR family outputs into one raw CONTROL chronology."""
    import csv
    import hashlib
    import io
    from pathlib import Path

    from scripts.calibration import CalibrationContainer
    from scripts.calibration_2026 import parse_cuw_2026
    from scripts.j2534_2026 import J2534Device2026, PrimitiveResult
    from scripts.native_modules import identify_native_module
    from scripts.programming_2026_common import (
        NativeRuntime2026,
        bind_native_parameter2026,
    )
    from scripts.programming_2026_vendor import bind_native_context, run_native
    from tests.private_evidence import read_private_bytes
    from tests.test_calibration_2026 import cuw
    from tests.test_cuw_engine_worker import encoded_table
    from tests.test_programming_2026_common import make_raw_control_fixture2026
    from tests.test_programming_2026_vendor import (
        TypedDriver,
    )
    from tests.test_programming_2026_vendor import (
        context as vendor_context,
    )

    prepare_name = "TCUWCanSBRPrepareWriter.dll"
    writer_name = "TCUWCanSBRFlashWriter.dll"
    utility_name = "TCUWSBRUtils.dll"
    original = vendor_context(prepare_name)
    catalog_name, original_table = next(
        iter(original.selection.catalog_sources.items())
    )
    source_rows = list(csv.reader(io.StringIO(original_table.decode())))
    fields = source_rows[0]
    row = dict(zip(fields, source_rows[1], strict=True))
    if cpu_count not in (1, 2):
        raise ValueError("The authored SBR replay fixture supports one or two CPUs")
    row.update(
        DLLFileNameForFlashWrite=writer_name,
        DLLFileNameForChangeToReprogGatewayMode="",
        GetCANIDFunctionNameForFlashWrite="GetCanIDsFromParamForPrepareWrite",
        CanIDForFlashWrite="07E0/07E8",
        CanIDForPrepareWrite=(
            "07E0/07E8\n07E1/07E9" if cpu_count == 2 else "07E0/07E8"
        ),
        EnableDLLVersionInformation="0\n0\n0\n0",
        CpuLoopBetweenPrepareAndWriteFlag="0",
    )
    for name in (
        "DLLFileNameForFlashWrite",
        "DLLFileNameForChangeToReprogGatewayMode",
        "GetCANIDFunctionNameForFlashWrite",
        "CanIDForFlashWrite",
        "CanIDForPrepareWrite",
        "EnableDLLVersionInformation",
    ):
        if name not in fields:
            fields.append(name)
    values = tuple(row[name] for name in fields)
    plain_table = io.StringIO(newline="")
    plain_writer = csv.writer(plain_table, lineterminator="\r\n")
    plain_writer.writerow(fields)
    plain_writer.writerow(values)
    raw_catalog = {catalog_name: plain_table.getvalue().encode()}
    catalog = {catalog_name: encoded_table(tuple(fields), (values,))}
    if cpu_count == 2:
        second_row = dict(row)
        second_row["ParamFileKeySystemProtocolMicon"] = (
            row["ParamFileKeySystemProtocolMicon"][:-3] + cpu_type_second
        )
        second_row["CanIDForFlashWrite"] = "07E1/07E9"
        second_row["CanIDForPrepareWrite"] = "07E1/07E9"
        second_values = tuple(second_row[name] for name in fields)
        second_catalog_name = catalog_name[: -len("282.ini")] + cpu_type_second + ".ini"
        second_table = io.StringIO(newline="")
        second_writer = csv.writer(second_table, lineterminator="\r\n")
        second_writer.writerow(fields)
        second_writer.writerow(second_values)
        raw_catalog[second_catalog_name] = second_table.getvalue().encode()
        catalog[second_catalog_name] = encoded_table(tuple(fields), (second_values,))
    general_fields = (
        "ParamFileKeySystemProtocolMicon",
        "M16CTypeFlag",
        "FlagToChangeToReprogGWModeForCentralGW",
        "FORESTTypeFlag",
        "PasswordAddress",
        "ByteOrder",
        "FlagToDoIGOFFONAtCPUTypeChange",
    )
    general_rows = [
        (row["ParamFileKeySystemProtocolMicon"], "0", "0", "0", "00", "1", "0")
    ]
    if cpu_count == 2:
        general_rows.append(
            (
                second_row["ParamFileKeySystemProtocolMicon"],
                "0",
                "0",
                "0",
                "00",
                "1",
                "0",
            )
        )
    catalog["Parameter.ini"] = encoded_table(general_fields, tuple(general_rows))
    cpu_sections = [
        (
            "[CPU01]\nCPUType=282\nNumberOfFiles=1\n[File1001]\n"
            "ALFID=44\nEraseBlock=1\nDownloadAddress=00001000\n"
            f"DownloadMemsize={len(data):08X}\n"
        )
    ]
    if cpu_count == 2:
        cpu_sections.append(
            f"[CPU02]\nCPUType={cpu_type_second}\nNumberOfFiles=1\n"
            "[File2001]\nALFID=44\nEraseBlock=1\n"
            "DownloadAddress=00002000\n"
            f"DownloadMemsize={len(data):08X}\n"
        )
    source = cuw(
        "[Format]\nVersion=9\n[Vehicle]\n"
        f"NumberOfCalibration={cpu_count}\n"
        "ContactType=P5-CAN\nKindOfECU=106\n" + "".join(cpu_sections),
        (data,) * cpu_count,
    )
    container = parse_cuw_2026(source)
    if not isinstance(container, CalibrationContainer):
        raise TypeError("Authored SBR fixture must remain a CUW container")
    image_root = Path("runtime/no-car-21/recovered")
    module_bytes = {
        name: read_private_bytes(image_root / name)
        for name in (prepare_name, writer_name, utility_name)
    }

    class CapturingDriver(TypedDriver):
        def __init__(self, replies):
            self.rows = []
            self.replies = {
                request: list(values) for request, values in replies.items()
            }
            self.pending = []
            self.events = []
            self.fault = None
            self.now = 0.0
            self.timeout = 100
            self.device = J2534Device2026(
                cast(Any, self), clock=lambda: self.now, background_workers=False
            )

        def __call__(self, event, remaining):
            if event["operation"] in (
                "calculate_sbr_key",
                "calculate_sbr_gateway_key",
                "progress",
                "notify_progress_count",
                "notify_progress_percent",
            ):
                result = (
                    bytes(4)
                    if event["operation"] == "calculate_sbr_key"
                    else bytes(256)
                    if event["operation"] == "calculate_sbr_gateway_key"
                    else None
                )
                self.rows.append((event, result, False))
                return result
            result = super().__call__(event, remaining)
            self.rows.append((event, result, True))
            return result

    def tag(value):
        from scripts.j2534_2026 import NativeMessage, NativeReadBatch2026

        if isinstance(value, PrimitiveResult):
            value = {"status": value.status, "value": value.value}
        if value is None:
            return {"type": "none", "value": None}
        if type(value) is bool:
            return {"type": "bool", "value": value}
        if type(value) is int:
            return {"type": "int", "value": value}
        if isinstance(value, bytes):
            return {"type": "bytes", "value": value.hex()}
        if isinstance(value, str):
            return {"type": "text", "value": value}
        if isinstance(value, (tuple, list)):
            kind = "tuple" if isinstance(value, tuple) else "sequence"
            return {"type": kind, "value": [tag(item) for item in value]}
        if isinstance(value, dict):
            return {
                "type": "mapping",
                "value": {key: tag(item) for key, item in value.items()},
            }
        if type(value) is NativeMessage:
            return {
                "type": "mapping",
                "value": {
                    "_native_type": {"type": "text", "value": "PASSTHRU_MSG_2026"},
                    **{key: tag(item) for key, item in vars(value).items()},
                },
            }
        if type(value) is NativeReadBatch2026:
            return {
                "type": "mapping",
                "value": {
                    "_native_type": {"type": "text", "value": "READ_BATCH_2026"},
                    "messages": tag(value.messages),
                    "count": tag(value.count),
                },
            }
        raise TypeError(f"Unsupported captured primitive value {type(value)!r}")

    if (
        not isinstance(block_response, bytes)
        or len(block_response) != 4
        or block_response[:2] != bytes.fromhex("7420")
    ):
        raise ValueError("SBR block response must be a four-byte 74 20 response")
    block_width = int.from_bytes(block_response[2:], "big") - 6
    if block_width < 1:
        raise ValueError("SBR max block length must leave room for one data byte")
    replies = {
        b"\x27\x33": [b"\x67\x33" + bytes(range(16))],
        b"\x27\x34" + bytes(256): [b"\x67\x34"],
        b"\x31\x01\x02\0": [b"\x71\x01\x02\0"],
        b"\x31\x01\x02\x01": [b"\x71\x01\x02\x01"],
        b"\x22\xf1\0": [b"\x62\xf1\0\xe0\0\0"],
        b"\x27\x01": [b"\x67\x01" + bytes(4)],
        b"\x10\x02": [b"\x50\x02"],
        b"\x37": [b"\x77"] * cpu_count,
    }
    for cpu_index in range(cpu_count):
        address = 0x1000 + cpu_index * 0x1000
        cpu_area = bytes.fromhex("440000") + address.to_bytes(2, "big")
        cpu_area += len(data).to_bytes(4, "big")
        replies[bytes.fromhex("3101ff00") + cpu_area] = [bytes.fromhex("7101ff00")]
        replies[bytes.fromhex("3404") + cpu_area] = [block_response]
        replies[bytes.fromhex("3101ff01") + cpu_area] = [bytes.fromhex("7101ff0101")]
        for sequence, offset in enumerate(range(0, len(data), block_width), 1):
            chunk = data[offset : offset + block_width]
            request = (
                bytes((0x36, sequence & 0xFF))
                + (address + offset).to_bytes(4, "big")
                + chunk
            )
            replies[request] = [bytes((0x76, sequence & 0xFF))]
    driver = CapturingDriver(replies)
    driver.device.open()
    driver.device.connect(6)
    direct_device_action = driver.device.primitive

    def direct_action(event, remaining):
        if event["operation"] in (
            "switch_connection",
            "switch_connection_with_version",
            "start_periodic",
            "stop_periodic",
            "connect",
            "start_sync_periodic",
            "set_local_time_to_previous_send_time",
            "is_sending_sync_periodic",
            "disconnect",
            "stop_sync_periodic",
            "stop_sync_periodic_message",
            "get_protocol_id",
            "get_send_timeout",
            "set_send_timeout",
            "set_history_enabled",
            "get_system_time",
            "local_time_ms",
            "get_timeout",
            "set_timeout",
            "write_messages",
            "read_specified_can_messages",
            "read_messages_result",
            "read_after_indication_result",
            "read_messages",
            "read_after_indication",
            "queue_messages",
            "write_tcp",
            "read_tcp",
            "logical_connect",
            "logical_disconnect",
            "logical_connect_udp_discovery",
            "logical_disconnect_udp_discovery",
            "start_sync_periodic_0500",
            "five_baud_init",
            "fast_init",
            "read_specified_can_message",
            "start_flow_control_filter",
            "stop_filter",
            "control_io",
            "wait",
            "lock",
            "unlock",
            "ioctl",
            "wrap_read_messages",
        ):
            return direct_device_action(event, remaining)
        if event["operation"] == "get_local_milliseconds_of_day":
            result = 1500
        elif event["operation"] == "get_local_seconds_of_day":
            result = 1
        elif event["operation"] == "calculate_sbr_key":
            result = bytes(4)
        elif event["operation"] == "calculate_sbr_gateway_key":
            result = bytes(256)
        elif event["operation"] == "progress" or event["operation"] in (
            "notify_progress_count",
            "notify_progress_percent",
        ):
            result = None
        elif event["operation"] == "set_communication_log_mode":
            result = 0
        else:
            raise AssertionError(f"Unexpected authored family primitive: {event}")
        driver.rows.append((event, result, False))
        return result

    def local_ms():
        driver.rows.append(
            ({"operation": "get_local_milliseconds_of_day"}, 1500, False)
        )
        return 1500

    def local_seconds():
        driver.rows.append(({"operation": "get_local_seconds_of_day"}, 1, False))
        return 1

    runtime = NativeRuntime2026(
        direct_action,
        timeout=1800,
        clock=lambda: driver.now,
        native_cancelled=lambda: False,
        local_seconds_of_day=local_seconds,
        local_milliseconds_of_day=local_ms,
    )

    def family_context(name, operation):
        selection = bind_native_parameter2026(
            container, raw_catalog, operation, encoded=False, node=1
        )
        identity = identify_native_module(
            hashlib.sha256(module_bytes[name]).hexdigest(), name
        )
        return bind_native_context(
            container, 1, (), selection, identity, {}, {"cpu_index": 0}
        )

    direct_events = []
    prepare_ctx = family_context(prepare_name, "prepare")
    prepare_result = run_native(
        prepare_ctx,
        runtime,
        key_provider=lambda secret_type, seed, aes, encrypt: runtime.call(
            "calculate_sbr_key",
            secret_type=secret_type,
            seed=seed,
            aes=aes,
            encrypt=encrypt,
        ),
        gateway_key_provider=lambda seed: runtime.call(
            "calculate_sbr_gateway_key", seed=seed
        ),
    )
    assert prepare_result["state"] == "prepare_completed"
    prepare_count = len(driver.rows)
    driver.rows.append(
        (
            {"operation": "set_communication_log_mode", "mode": 2},
            0,
            False,
        )
    )
    writer_ctx = family_context(writer_name, "write")
    writer_result = run_native(
        writer_ctx,
        runtime,
        notify=lambda field, value: (
            runtime.call("progress", field=field, value=value)
            if field in ("writing", "next_cpu")
            else None
        ),
    )
    assert writer_result["state"] == "writer_completed"
    driver.rows.append(
        (
            {"operation": "set_communication_log_mode", "mode": 0},
            0,
            False,
        )
    )
    direct_events.extend(driver.rows[:prepare_count])
    direct_events.append(driver.rows[prepare_count])
    direct_events.extend(driver.rows[prepare_count + 1 :])
    event_rows = []
    from scripts.programming_replay import _native_request

    for request, output, is_driver in direct_events:
        if is_driver and isinstance(output, PrimitiveResult):
            output_value = {"status": output.status, "value": output.value}
        elif is_driver:
            output_value = {"status": 0, "value": output}
        else:
            output_value = output
        event_rows.append(
            {
                "kind": "action",
                "request": _native_request(request),
                "result": tag(output_value),
                "elapsed_ms": max(
                    1,
                    request.get("milliseconds", 1)
                    if request["operation"] == "wait"
                    else 1,
                ),
            }
        )

    if cpu_count == 2:
        for mode in (2, 0):
            event_rows.append(
                {
                    "kind": "action",
                    "request": {
                        "operation": "set_communication_log_mode",
                        "mode": mode,
                    },
                    "result": {"type": "int", "value": 0},
                    "elapsed_ms": 1,
                }
            )
    events = (
        {
            "kind": "action",
            "request": {"operation": "get_local_milliseconds_of_day"},
            "result": {"type": "int", "value": 1000},
            "elapsed_ms": 1,
        },
        *event_rows,
        {
            "kind": "action",
            "request": {"operation": "get_local_milliseconds_of_day"},
            "result": {"type": "int", "value": 2000},
            "elapsed_ms": 1,
        },
    )
    engine, control, session = make_raw_control_fixture2026(
        case,
        source=source,
        catalog=catalog,
        module_files=module_bytes,
        operation="prepare",
        events=events if events_override is None else events_override,
        paired=True,
    )

    class ProgrammingTraceCapture:
        """Capture native order using only already-authored primitive inputs."""

        def __init__(self):
            self.actions = []
            self.recorded_consume = session.trace.consume

        def __call__(self, kind, request, remaining=None):
            if kind == "action" and request.get("operation") in (
                "notify_progress_count",
                "notify_progress_percent",
            ):
                self.actions.append(dict(request))
                rows = session.trace.rows
                if type(rows) is not list:
                    raise TypeError("Mutable source trace capture rows required")
                rows.insert(
                    session.trace.position,
                    {
                        "kind": "action",
                        "request": _native_request(request),
                        "result": {"type": "none", "value": None},
                        "elapsed_ms": 0,
                    },
                )
            if kind == "action":
                rows = session.trace.rows
                if type(rows) is not list:
                    raise TypeError("Mutable source trace capture rows required")
                position = session.trace.position
                expected = (
                    rows[position].get("request") if position < len(rows) else None
                )
                normalized = _native_request(request)
                if expected != normalized:
                    match = next(
                        (
                            index
                            for index in range(position + 1, len(rows))
                            if rows[index].get("kind") == "action"
                            and rows[index].get("request") == normalized
                        ),
                        None,
                    )
                    if match is not None:
                        rows[position], rows[match] = rows[match], rows[position]
            return self.recorded_consume(kind, request, remaining)

    from scripts.programming_replay import _native_request

    canonical_actions = []
    if capture_progress:
        session.trace.rows = list(session.trace.rows)
        trace_capture = ProgrammingTraceCapture()
        canonical_actions = trace_capture.actions
        session.trace.consume = trace_capture
    return (
        engine,
        control,
        session,
        driver,
        control.runtime,
        canonical_actions,
        row["ParamFileKeySystemProtocolMicon"],
    )


class ControlStagedReplayTests(unittest.TestCase):
    def setUp(self):
        helper = ProgrammingReplayTests()
        helper.setUp()
        self.helper = helper
        self.session = helper.load()

    def _load_private_dh_retry_proof(self):
        import importlib.util

        from tests.private_evidence import require_private

        relative_paths = (
            "runtime/no-car-119/verify_failed_dh_retry.py",
            "runtime/no-car-119/verify_failed_sonar_retry.py",
            "runtime/no-car-119/dh_retry_fixture.py",
            "runtime/no-car-119/sonar_retry_fixture.py",
            "runtime/no-car-21/recovered/CUW.dll",
            "runtime/no-car-21/recovered/TCUWCanDHFlashWriter.dll",
            "runtime/no-car-21/recovered/TCUWCanDHPrepareWriter.dll",
            "runtime/no-car-21/recovered/TCUWControlCommPhase.dll",
            "runtime/no-car-21/recovered/TCUWJ2534DeviceIF.dll",
            "runtime/no-car-21/recovered/TCUWDHUtils.dll",
            "runtime/no-car-21/recovered/SecretInfo.dll",
        )
        require_private(*relative_paths)
        repo_root = Path(__file__).resolve().parents[1]
        proof_path = repo_root / relative_paths[0]
        spec = importlib.util.spec_from_file_location("dh_retry_raw_proof", proof_path)
        if spec is None or spec.loader is None:
            raise AssertionError("Private DH retry proof loader is unavailable")
        proof = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(proof)
        return proof

    def test_dh_retry_proof_skips_when_private_source_is_absent(self):
        from tests import private_evidence

        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(private_evidence, "_REPO_ROOT", Path(directory)),
            self.assertRaises(unittest.SkipTest),
        ):
            self._load_private_dh_retry_proof()

    def test_private_stage_rejects_forged_or_unbound_target(self):
        from scripts.programming_2026_common import NativeControlExportTarget2026

        with self.assertRaisesRegex(ValueError, "exact replay owners"):
            self.session._next_control_export2026(object(), "StartFlashWrite")
        with self.assertRaisesRegex(ValueError, "exact replay owners"):
            self.session._next_control_export2026(
                object.__new__(NativeControlExportTarget2026), "StartFlashWrite"
            )
        self.assertEqual(self.session.trace.position, 0)
        self.assertFalse(self.session.used)

    def test_private_stage_rejects_unknown_export(self):
        with self.assertRaisesRegex(ValueError, "exact replay owners"):
            self.session._next_control_export2026(object(), "caller_selected_stage")
        self.assertEqual(self.session.trace.position, 0)

    def test_control_root_binding_requires_live_raw_driver_owners(self):
        with self.assertRaisesRegex(ValueError, "exact native owners"):
            self.session._bind_control_root2026(object(), object(), object())
        self.assertIsNone(self.session._engine2026)
        self.assertIsNone(self.session._controller2026)
        self.assertIsNone(self.session._runtime2026)
        self.assertEqual(self.session.trace.position, 0)

    def test_public_clone_cannot_receive_private_target_authority(self):
        from scripts.programming_replay import ProgrammingReplay

        with self.assertRaises(TypeError):
            cast(Any, self.session.next_session2026)(
                "write", node=1, cpu_index=0, _control_target2026=object()
            )
        forged = ProgrammingReplay(
            self.session.container,
            dict(self.session.context),
            self.session.catalog,
            self.session.modules,
            self.session.attachments,
            self.session.trace,
            dict(self.session.input_hashes),
            _control_target2026=object(),
            _control_export2026="StartFlashWrite",
        )
        with self.assertRaisesRegex(ValueError, "Private CONTROL replay lineage"):
            forged._validate_control_stage2026()

    def test_recording_cannot_supply_a_stage_override(self):
        document = dict(self.helper.document)
        document["stage"] = "write"
        with self.assertRaises(ValueError):
            self.helper.load(document)

    def test_control_return_receipt_requires_explicit_native_boolean(self):
        from scripts.programming_replay import ProgrammingReplay

        read_return = ProgrammingReplay._explicit_control_native_return2026
        self.assertIs(read_return({"native_return": True}), True)
        self.assertIs(read_return({"native_return": False}), False)
        self.assertIs(read_return({"native_result": {"returned": True}}), True)
        self.assertIsNone(
            read_return({"native_return": None, "native_result": {"returned": True}})
        )
        self.assertIsNone(
            read_return({"state": "writer_completed", "native_success": True})
        )
        self.assertIsNone(read_return({"identifiers": (b"CID",)}))

    def test_dh_binding_rejects_caller_supplied_export_override(self):
        proof = self._load_private_dh_retry_proof()
        from scripts import programming_2026_dh as dh2026

        with proof.factory.canonical(authoring=True) as (
            _engine,
            _control,
            session,
            _cancel,
        ):
            selection, module, *_ = session._dispatch2026()
            with self.assertRaisesRegex(ValueError, "undeclared overrides"):
                dh2026.bind_native_context(
                    session.container,
                    session.node,
                    (),
                    selection,
                    module.native_identity,
                    {"selected_module": session._module_files[module.name]},
                    {"export": "PrepareRetry"},
                )

    def test_actual_dh_retry_uses_private_export_on_fresh_strict_trace(self):
        proof = self._load_private_dh_retry_proof()
        authored_rows, captured = proof.exercise(1, author=True)
        rows, strict = proof.exercise(1, events=authored_rows)

        self.assertEqual(rows, authored_rows)
        self.assertEqual(captured["events"], 97)
        self.assertFalse(captured["exact_final_trace"])
        self.assertEqual(captured["native_prepare_retry_exports"], 1)
        self.assertEqual(strict["events"], 97)
        self.assertTrue(strict["exact_final_trace"])
        self.assertEqual(strict["native_prepare_retry_exports"], 1)
        self.assertTrue(strict["source_retry_decision"])

    def test_authentic_sbr_two_cpu_shared_execute_frozen_strict_replay(self):
        import copy

        capture_engine, capture_control, capture_session, *_ = (
            make_authentic_sbr_replay_fixture(self, cpu_count=2)
        )
        with capture_engine.controller_execution(capture_control, 1):
            capture_session._bind_control_prelude2026(
                capture_engine, capture_control, capture_control.runtime
            )
            device = capture_engine.engine_runtime_device()
            device.open()
            device.connect(6)
            capture_result = capture_control.execute(capture_engine, capture_session)
        self.assertTrue(capture_result["native_return"])
        self.assertEqual(
            tuple(report["entrypoint"] for report in capture_result["exports"]),
            ("StartPrepareWrite", "StartFlashWrite", "StartFlashWrite"),
        )
        self.assertEqual(capture_result["exports"][1]["transferred"], 8)
        self.assertEqual(capture_result["exports"][1]["next_cpu_index"], 2)
        self.assertEqual(capture_result["exports"][2]["transferred"], 0)
        self.assertTrue(capture_result["exports"][2]["native_skipped_completed"])
        self.assertEqual(capture_result["exports"][2]["next_cpu_index"], 1)
        self.assertEqual(capture_engine.comm_phase, 2)
        self.assertEqual(
            capture_session.trace.position, len(capture_session.trace.rows)
        )
        captured_events = tuple(copy.deepcopy(capture_session.trace.rows))
        captured_wire = json.dumps(captured_events)
        self.assertEqual(captured_wire.count("36010000100044415441"), 1)
        self.assertEqual(captured_wire.count("36010000200044415441"), 1)
        self.assertIn("000007e0", captured_wire)
        self.assertIn("000007e1", captured_wire)
        self.assertEqual(
            [
                event["request"]["mode"]
                for event in captured_events
                if event.get("request", {}).get("operation")
                == "set_communication_log_mode"
            ],
            [2, 0, 2, 0],
        )
        self.assertEqual(
            [
                action["cpu_index"]
                for action in (
                    event["request"]
                    for event in captured_events
                    if event.get("request", {}).get("operation")
                    == "notify_progress_count"
                )
            ],
            [0, 1],
        )

        engine, control, session, *_ = make_authentic_sbr_replay_fixture(
            self,
            cpu_count=2,
            events_override=captured_events,
            capture_progress=False,
        )
        with engine.controller_execution(control, 1):
            session._bind_control_prelude2026(engine, control, control.runtime)
            device = engine.engine_runtime_device()
            device.open()
            device.connect(6)
            result = control.execute(engine, session)
        self.assertTrue(result["native_return"])
        self.assertEqual(session.trace.position, len(captured_events))
        self.assertEqual(
            tuple(report["entrypoint"] for report in result["exports"]),
            ("StartPrepareWrite", "StartFlashWrite", "StartFlashWrite"),
        )
        self.assertEqual(result["exports"][1]["transferred"], 8)
        self.assertEqual(result["exports"][2]["transferred"], 0)
        self.assertTrue(result["exports"][2]["native_skipped_completed"])
        self.assertEqual(engine.comm_phase, 2)
        self.assertIsNone(control._native_control_raw_execution2026)

    def test_authentic_sbr_prepare_empty_gateway_write_shared_execute(self):
        import copy

        from scripts.programming_replay import _native_request
        from tests.test_cuw_engine_worker import encoded_table

        (
            capture_engine,
            capture_control,
            capture_session,
            _capture_driver,
            _capture_runtime,
            canonical_actions,
            parameter_key,
        ) = make_authentic_sbr_replay_fixture(self)
        with capture_engine.controller_execution(capture_control, 1):
            from types import MappingProxyType

            held_metadata = capture_control.native_control_context2026(
                capture_engine
            )._capture.metadata
            self.assertTrue(held_metadata.parser_parameters_validated)
            original_sources = capture_session._catalog_sources
            unrelated_sources = dict(original_sources)
            unrelated_sources["Parameter.ini"] = encoded_table(
                (
                    "ParamFileKeySystemProtocolMicon",
                    "M16CTypeFlag",
                    "FlagToChangeToReprogGWModeForCentralGW",
                    "FORESTTypeFlag",
                    "PasswordAddress",
                    "ByteOrder",
                    "FlagToDoIGOFFONAtCPUTypeChange",
                ),
                (
                    (
                        parameter_key,
                        "0",
                        "0",
                        "0",
                        "00",
                        "1",
                        "1",
                    ),
                ),
            )
            capture_session._catalog_sources = MappingProxyType(unrelated_sources)
            with self.assertRaisesRegex(ValueError, "General source differs"):
                capture_session._bind_control_prelude2026(
                    capture_engine, capture_control, capture_control.runtime
                )
            capture_session._catalog_sources = original_sources
            capture_session._bind_control_prelude2026(
                capture_engine, capture_control, capture_control.runtime
            )
            self.assertIsNone(capture_control._native_control_raw_execution2026)
            capture_session.context["observations"]["current_cids"] = [
                "ROOT-JSON-MUST-NOT-WIN"
            ]
            engine_device = capture_engine.engine_runtime_device()
            engine_device.open()
            engine_device.connect(6)
            capture_result = capture_control.execute(capture_engine, capture_session)
        self.assertTrue(capture_result["native_return"])
        self.assertEqual(
            capture_session.trace.position, len(capture_session.trace.rows)
        )
        captured_events = tuple(copy.deepcopy(capture_session.trace.rows))

        (
            engine,
            control,
            session,
            _driver,
            _runtime,
            strict_actions,
            _parameter_key,
        ) = make_authentic_sbr_replay_fixture(
            self, events_override=captured_events, capture_progress=False
        )
        self.assertEqual(strict_actions, [])
        requests = tuple(
            event["request"]
            for event in captured_events
            if event["request"].get("operation")
            in ("notify_progress_count", "notify_progress_percent")
        )
        self.assertEqual(
            requests,
            tuple(_native_request(event) for event in canonical_actions),
        )
        with engine.controller_execution(control, 1):
            session._bind_control_prelude2026(engine, control, control.runtime)
            session.context["observations"]["current_cids"] = ["ROOT-JSON-MUST-NOT-WIN"]
            engine_device = engine.engine_runtime_device()
            engine_device.open()
            engine_device.connect(6)
            result = control.execute(engine, session)
        self.assertEqual(
            tuple(report["native_return"] for report in result["exports"]),
            (True, True),
        )
        self.assertEqual(
            tuple(report["entrypoint"] for report in result["exports"]),
            ("StartPrepareWrite", "StartFlashWrite"),
        )
        self.assertEqual(engine.comm_phase, 2)
        self.assertTrue(result["native_return"])
        self.assertEqual(session.trace.position, len(session.trace.rows))
        self.assertTrue(session.used)
        self.assertEqual(
            tuple(canonical_actions),
            (
                {
                    "operation": "notify_progress_count",
                    "cpu_index": 0,
                    "transferred_bytes": 0,
                },
                {
                    "operation": "notify_progress_percent",
                    "cpu_index": 0,
                    "progress": 100,
                },
            ),
        )
        self.assertEqual(session.trace.position, len(captured_events))
        wire = json.dumps(session.trace.rows)
        self.assertIn("1063", wire)
        self.assertIn("360100001000", wire)
        self.assertIn("44415441", wire)
        self.assertFalse(engine.worker.control_state.failed)
        self.assertIsNone(control._native_control_helper_entry2026)
        self.assertIsNone(control._native_control_raw_execution2026)


if __name__ == "__main__":
    unittest.main()
