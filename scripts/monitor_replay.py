"""Bounded raw SDK observations through selected native monitor producers.

Recordings contain primitive outcomes, never monitor plans or decoded samples.
Nothing in this module opens an adapter or executes an imported application.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import math
import os
import re
import tempfile
from collections.abc import Callable, Mapping
from functools import cache
from pathlib import Path
from types import MappingProxyType
from typing import Any

from scripts.data_monitor import (
    MonitorError,
    SelectedMonitorSession,
    select_provider,
    selected_dual_target,
    selected_monitor_buffer,
    selected_normal_monitor_from_cache,
    selected_normal_monitor_worker,
    selected_p4_connection,
    selected_p5_can_connection,
)
from scripts.drive_recorder import NativeMonitorPacket, NativeRecorderCapture
from scripts.frame_transport import (
    DriverProperties,
    J2534Result,
    NativeFrameOperations,
    NativeMessage,
    runtime_frame_plan,
)
from scripts.local_files import read_regular
from scripts.monitor_support import MonitorSupportCache
from scripts.native_replay import MAX_FILE, _hex, _object
from scripts.profiles import VehicleCatalog
from scripts.snapshot import (
    MonitorBuffer,
    decode_monitor_buffer,
    decode_system_information,
    dumps,
    encode_monitor_buffer,
    monitor_samples,
    parse,
)
from scripts.toyota_session import Limits, NativeStatus

SCHEMA = "techstream-native-monitor-v1"
MAX_EVENTS = 100000
SDK_OPERATIONS = frozenset(
    {
        "connect",
        "disconnect",
        "ioctl",
        "start_message_filter",
        "stop_message_filter",
        "write_messages",
        "read_messages",
        "start_periodic_message",
        "stop_periodic_message",
    }
)


@cache
def monitor_module_ids(
    build: int,
    provider: str,
    dual: bool = False,
    *,
    vim_variant: str | None = None,
    recording: bool = False,
) -> Mapping[str, str]:
    """Canonical static module identities; no imported code is loaded/executed."""
    from scripts.native_inventory import load_manifest

    if type(build) is not int or build not in (12, 18):
        raise ValueError("Explicit monitor module source build required")
    required = {
        "KgpDataMonitorCtrl.dll",
        "DataListIF.dll",
        "DatMonCommon.dll",
        "CommandCommon.dll",
        "KGP_CommFrameCtrl.dll",
        provider,
    }
    if provider == "DM_ActVariable_DT.dll":
        required.add("DataMonitorPhase4.dll")
    if dual:
        required.add("DataMonitorDual_DT.dll")
    if recording:
        required.update(("FileManagerIT3.dll", "CommandDataLib.dll"))
    if vim_variant is not None:
        if vim_variant not in ("VS_x86", "VS_x64"):
            raise ValueError("Unsupported native VIM module source profile")
        required.update(("ComTol32.dll", "CommandDataLib.dll"))
    result = {}
    for module in load_manifest()["universe"]:
        for alias in module["aliases"]:
            name = Path(alias["path"]).name
            if (
                alias["build"] == str(build)
                and name in required
                and Path(alias["path"]).parent.name
                == (
                    f"Techstream_Bin_{vim_variant}"
                    if name == "ComTol32.dll"
                    else "Techstream_Bin"
                )
            ):
                if name in result and result[name] != module["sha256"]:
                    raise ValueError("Ambiguous canonical monitor module identity")
                result[name] = module["sha256"]
    if set(result) != required:
        raise ValueError("Canonical monitor module closure is incomplete")
    return MappingProxyType(result)


def _fields(value: Any, names: set[str]) -> dict:
    if not isinstance(value, dict) or set(value) != names:
        raise ValueError("Unexpected monitor recording fields")
    return value


def _uint(value: Any, maximum: int = 0xFFFFFFFF) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError("Invalid unsigned monitor observation")
    return value


def _host_command(value: Any) -> dict:
    if not isinstance(value, dict):
        raise TypeError("Literal native host command required")
    command = _uint(value.get("command_id"), 255)
    if command == 11:
        _fields(
            value, {"command_id", "signal_id", "value", "auxiliary", "initial_repeat"}
        )
        _uint(value["signal_id"], 65535)
        _uint(value["value"])
        _uint(value["auxiliary"])
        if value["initial_repeat"] is not None:
            _uint(value["initial_repeat"], 65535)
    elif command == 96:
        _fields(value, {"command_id", "signal_id"})
        _uint(value["signal_id"], 65535)
    elif command == 12:
        _fields(value, {"command_id", "initialize"})
        if type(value["initialize"]) is not bool:
            raise ValueError("Native active stop requires literal boolean")
    else:
        raise ValueError("Unsupported native host command")
    return value


def sdk_value(value: Any, depth: int = 0) -> Any:
    """Canonical literal SDK argument representation, with bytes kept distinct."""
    if depth > 12:
        raise ValueError("Monitor SDK nesting budget exceeded")
    if isinstance(value, bytes):
        return {"bytes": value.hex()}
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return sdk_value(dataclasses.asdict(value), depth + 1)
    if isinstance(value, Mapping) and len(value) <= 128:
        if any(not isinstance(key, str) or len(key) > 128 for key in value):
            raise ValueError("Invalid monitor SDK keys")
        return {key: sdk_value(child, depth + 1) for key, child in value.items()}
    if isinstance(value, (tuple, list)) and len(value) <= 4096:
        return [sdk_value(child, depth + 1) for child in value]
    if value is None or type(value) in (bool, int):
        if type(value) is int:
            _uint(value)
        return value
    if isinstance(value, str) and len(value) <= 4096:
        return value
    raise ValueError("Invalid bounded monitor SDK value")


def _literal(value: Any, depth: int = 0) -> Any:
    if depth > 12:
        raise ValueError("Monitor SDK nesting budget exceeded")
    if isinstance(value, dict):
        if set(value) == {"bytes"}:
            return _hex(value["bytes"])
        if len(value) > 128 or any(
            not isinstance(key, str) or len(key) > 128 for key in value
        ):
            raise ValueError("Invalid monitor SDK keys")
        return {key: _literal(child, depth + 1) for key, child in value.items()}
    if isinstance(value, list):
        if len(value) > 4096:
            raise ValueError("Monitor SDK collection budget exceeded")
        return tuple(_literal(child, depth + 1) for child in value)
    sdk_value(value)
    return value


def _sdk_result(value: Any) -> J2534Result:
    from scripts.frame_transport import NativeConfig

    fields = _fields(value, {field.name for field in dataclasses.fields(J2534Result)})
    fields = _literal(fields)
    messages = tuple(
        NativeMessage(
            **_fields(message, {f.name for f in dataclasses.fields(NativeMessage)})
        )
        for message in fields["messages"]
    )
    configs = tuple(
        NativeConfig(**_fields(config, {"parameter", "value"}))
        for config in fields["configs"]
    )
    return J2534Result(**{**fields, "messages": messages, "configs": configs})


class MonitorRecording:
    """One cursor for support PDUs, raw SDK calls and oscillator primitives."""

    def __init__(self, document: dict, cancelled: Callable[[], bool] = lambda: False):
        _fields(document, {"schema", "source", "context", "events"})
        if document["schema"] != SCHEMA or document["source"] not in (
            "authored_synthetic",
            "recorded_unverified",
        ):
            raise ValueError("Unsupported monitor recording schema/source")
        events = document["events"]
        if not isinstance(events, list) or len(events) > MAX_EVENTS:
            raise ValueError("Invalid bounded monitor event count")
        retained = 0
        checked = []
        for event in events:
            _fields(
                event, {"kind", "operation", "request", "result", "elapsed_ms", "tick"}
            )
            if event["kind"] not in ("sdk", "support", "osc", "vim", "host"):
                raise ValueError("Unknown monitor primitive kind")
            allowed = {
                "sdk": SDK_OPERATIONS,
                "vim": {"exchange"},
                "host": {"enqueue"},
                "support": {"exchange", "send", "receive"},
                "osc": {"command", "set_parameter", "read_buffer"},
            }[event["kind"]]
            if event["operation"] not in allowed:
                raise ValueError("Unknown monitor primitive operation")
            _uint(event["elapsed_ms"], 3600000)
            _uint(event["tick"])
            if event["kind"] == "host":
                request = _host_command(event["request"])
            elif event["kind"] == "vim":
                wire_request = _fields(event["request"], {"data"})
                request = {
                    "data": _hex(
                        _fields(wire_request["data"], {"bytes"})["bytes"],
                        max_bytes=MAX_FILE,
                    )
                }
            else:
                request = _literal(event["request"])
            if not isinstance(request, dict):
                raise TypeError("Explicit monitor primitive request required")
            if event["kind"] == "host":
                if event["result"] is not None:
                    raise ValueError("Host input cannot supply a business result")
                result = None
            elif event["kind"] == "vim":
                _fields(request, {"data"})
                if not isinstance(request["data"], bytes):
                    raise TypeError("Literal VIM request bytes required")
                result = _hex(
                    _fields(event["result"], {"bytes"})["bytes"], max_bytes=MAX_FILE
                )
            elif event["kind"] == "sdk":
                result = _sdk_result(event["result"])
            elif event["kind"] == "support":
                result = _fields(event["result"], {"status", "data"})
                result = (_uint(result["status"]), _hex(result["data"]))
            elif event["operation"] == "read_buffer":
                from scripts.monitor_instruments import OscRead

                result = OscRead(
                    **_literal(
                        _fields(
                            event["result"],
                            {"status", "data", "timestamp", "opaque", "remaining"},
                        )
                    )
                )
            else:
                result = _uint(event["result"])
            retained += len(json.dumps(event, ensure_ascii=True))
            if retained > MAX_FILE:
                raise ValueError("Monitor aggregate event budget exceeded")
            checked.append(
                (
                    event["kind"],
                    event["operation"],
                    json.dumps(
                        sdk_value(request), sort_keys=True, separators=(",", ":")
                    ),
                    result,
                    event["elapsed_ms"],
                    event["tick"],
                )
            )
        self.events = tuple(checked)
        self.host_commands_left = sum(event[0] == "host" for event in checked)
        self.context = json.loads(json.dumps(document["context"]))
        self.source, self.cancelled = document["source"], cancelled
        self.position, self.elapsed, self.tick = 0, 0.0, 0

    @classmethod
    def loads(
        cls, raw: bytes, cancelled: Callable[[], bool] = lambda: False
    ) -> MonitorRecording:
        if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_FILE:
            raise ValueError("Monitor recording exceeds bounded byte budget")
        try:
            document = json.loads(
                raw,
                object_pairs_hook=_object,
                parse_constant=lambda _: (_ for _ in ()).throw(
                    ValueError("Nonfinite JSON")
                ),
            )
        except (ValueError, UnicodeError, RecursionError) as error:
            raise ValueError("Malformed monitor recording JSON") from error
        return cls(document, cancelled)

    def clock(self) -> float:
        return self.elapsed

    def ticks(self) -> int:
        return self.tick

    def wait(self, seconds: float) -> None:
        """Advance the ported host wait without sleeping or inventing SDK data."""
        if (
            type(seconds) not in (int, float)
            or not math.isfinite(seconds)
            or not 0 <= seconds <= 3600
        ):
            raise ValueError("Invalid bounded monitor host wait")
        self.elapsed += seconds

    def consume(self, kind: str, operation: str, request: Any) -> Any:
        # Concrete runtimes own cancellation; recorded cleanup must remain callable.
        if self.position == len(self.events):
            raise ValueError("Monitor recording exhausted")
        expected_kind, expected_op, expected, result, elapsed, tick = self.events[
            self.position
        ]
        if (
            kind,
            operation,
            json.dumps(sdk_value(request), sort_keys=True, separators=(",", ":")),
        ) != (
            expected_kind,
            expected_op,
            expected,
        ):
            # Never expose recorded bytes, keys, paths or raw requests in errors.
            raise ValueError(f"Monitor primitive mismatch at event {self.position}")
        self.position += 1
        if kind == "host":
            self.host_commands_left -= 1
        self.elapsed += elapsed / 1000
        self.tick = tick
        return result

    def invoke(self, operation, fields, *, deadline, cancelled) -> J2534Result:
        if cancelled():
            raise InterruptedError("Monitor SDK cancelled")
        if not math.isfinite(deadline) or self.clock() >= deadline:
            raise TimeoutError("Monitor SDK deadline exceeded")
        return self.consume("sdk", operation, fields)

    def vim_exchange(
        self, request: bytes, *, deadline: float, cancelled: Callable[[], bool]
    ) -> bytes:
        if cancelled():
            raise InterruptedError("Monitor VIM cancelled")
        if not math.isfinite(deadline) or self.clock() >= deadline:
            raise TimeoutError("Monitor VIM deadline exceeded")
        return self.consume("vim", "exchange", {"data": request})

    @staticmethod
    def _query(query) -> dict:
        return {
            "ecu": query.ecu,
            "request": query.request,
            "native_parameter": query.native_parameter,
            "extended": query.extended,
            "capacity": query.capacity,
        }

    def exchange(self, query) -> bytes:
        status, data = self.consume("support", "exchange", self._query(query))
        if status:
            raise NativeStatus(status, data)
        return data

    def send(self, call) -> int:
        request = {
            "query": self._query(call.query),
            **{key: value for key, value in vars(call).items() if key != "query"},
        }
        status, data = self.consume("support", "send", request)
        if data:
            raise ValueError("Support send cannot return receive bytes")
        return status

    def receive(self, call) -> tuple[int, bytes]:
        request = {
            "query": self._query(call.query),
            **{key: value for key, value in vars(call).items() if key != "query"},
        }
        return self.consume("support", "receive", request)

    def command(self, command: int, *, deadline: float) -> int:
        return self.consume("osc", "command", {"command": command})

    def set_parameter(self, parameter: int, data: bytes, *, deadline: float) -> int:
        return self.consume(
            "osc", "set_parameter", {"parameter": parameter, "data": data}
        )

    def read_buffer(self, maximum: int, *, deadline: float):
        return self.consume("osc", "read_buffer", {"maximum": maximum})

    def assert_complete(self) -> None:
        if self.position != len(self.events):
            raise ValueError("Monitor recording contains unconsumed events")

    def next_host_command(self) -> dict | None:
        if self.position == len(self.events) or self.events[self.position][0] != "host":
            return None
        request = json.loads(self.events[self.position][2])
        self.consume("host", "enqueue", request)
        return request


class MonitorReplay:
    """Selected imported databases and deterministic primitive recording owner."""

    def __init__(
        self,
        recording: MonitorRecording,
        source_root: Path,
        *,
        path: Path | None = None,
    ):
        self.recording = recording
        context = _fields(
            recording.context,
            {
                "source_build",
                "mode",
                "category",
                "selected_ids",
                "vehicle_name_key",
                "exception_ids",
                "source_files",
                "module_ids",
                "ecu",
                "bus_id",
                "diagnostic_mode_hex",
                "controller_flags",
                "driver",
                "device_kind",
                "native_variant",
                "initial_request_hex",
                "observed_functions",
                "selection",
                "metadata",
                "limits",
                "packet_count",
                "dual",
                "oscilloscope",
                "variable",
            }
            | (set(recording.context) & {"vim", "legacy", "primary"}),
        )
        if type(context["source_build"]) is not int or context["source_build"] not in (
            12,
            18,
        ):
            raise ValueError("Explicit source build12/18 required")
        if context["mode"] not in ("normal", "dual", "variable", "legacy"):
            raise ValueError("Unsupported native monitor mode")
        if context.get("vim") is not None:
            vim = _fields(context["vim"], {"capabilities", "module_variant"})
            capabilities = vim["capabilities"]
            if (
                not isinstance(capabilities, list)
                or len(capabilities) != 2
                or any(not isinstance(flag, str) for flag in capabilities)
                or set(capabilities) != {"denso-vim-control", "denso-vim-dmci"}
            ):
                raise ValueError(
                    "Explicit native VIM control/DMCI observations required"
                )
        exceptions = context["exception_ids"]
        # Host work limit for repeated correspondence scans, not a native ceiling.
        if (
            not isinstance(exceptions, list)
            or len(exceptions) > 256
            or any(type(key) is not int or not 1 <= key <= 65535 for key in exceptions)
        ):
            raise ValueError("Monitor exceptions require at most256 ordered uint16 IDs")
        if context["vehicle_name_key"] is not None:
            _uint(context["vehicle_name_key"], 65535)
        root = source_root.resolve(strict=True)
        files = context["source_files"]
        if not isinstance(files, dict) or not 3 <= len(files) <= 64:
            raise ValueError("Pinned imported source files required")
        sources = []
        for name, digest in files.items():
            if (
                not isinstance(name, str)
                or Path(name).is_absolute()
                or "\\" in name
                or ".." in Path(name).parts
            ):
                raise ValueError("Invalid relative monitor source path")
            source = root / name
            if source.is_symlink() or not source.resolve(strict=True).is_relative_to(
                root
            ):
                raise ValueError("Monitor source escapes selected root")
            if (
                not isinstance(digest, str)
                or re.fullmatch("[0-9a-f]{64}", digest) is None
                or hashlib.sha256(read_regular(source, limit=MAX_FILE * 8)).hexdigest()
                != digest
            ):
                raise ValueError("Monitor source identity mismatch")
            sources.append(source)
        catalog = VehicleCatalog(root)
        profile = catalog.build_profile(
            _uint(context["category"], 65535),
            vehicle_name_key=context["vehicle_name_key"],
            exception_ids=tuple(context["exception_ids"]),
        )
        if not {"Toyota.ddb", "M_English.ddb", profile.filename} <= set(files):
            raise ValueError("Selected monitor databases lack explicit SHA pins")
        selection = _fields(
            context["selection"],
            {
                "communication_protocol",
                "attribute_3_31",
                "excluded",
                "standard_values",
                "parameter_6",
                "active_alias_pid",
                "dynamic_requested",
                "routine_ids",
                "native_ecu",
            },
        )
        self.primary_profile = None
        if context.get("primary") is not None:
            if context["mode"] not in ("legacy", "variable"):
                raise ValueError("Management-only primary requires its native runtime")
            primary = _fields(
                context["primary"],
                {
                    "category",
                    "ecu",
                    "bus_id",
                    "diagnostic_mode_hex",
                    "initial_request_hex",
                },
            )
            self.primary_profile = catalog.build_protocol_profile(
                _uint(primary["category"], 65535), exception_ids=tuple(exceptions)
            )
            self.primary_profile = dataclasses.replace(
                self.primary_profile, vehicle_name_key=context["vehicle_name_key"]
            )
            _uint(primary["bus_id"], 65535)
            if (
                not isinstance(primary["ecu"], str)
                or re.fullmatch("[A-Za-z0-9_.:-]{1,64}", primary["ecu"]) is None
                or len(_hex(primary["diagnostic_mode_hex"], max_bytes=16)) != 16
            ):
                raise ValueError("Invalid explicit primary communication observation")
            _hex(primary["initial_request_hex"])
        provider_profile = self.primary_profile or profile
        provider = (
            "DM_ActVariable_DT.dll"
            if context["mode"] == "variable"
            else select_provider(
                provider_profile.category_record[72],
                context["primary"]["bus_id"]
                if self.primary_profile is not None
                else selection["communication_protocol"],
                selection["attribute_3_31"],
            )
        )
        if context["module_ids"] != monitor_module_ids(
            context["source_build"],
            provider,
            context["mode"] == "dual",
            vim_variant=context["vim"]["module_variant"]
            if context.get("vim") is not None
            else None,
            recording=context["mode"] == "legacy"
            and context.get("legacy", {}).get("command_id") == 87,
        ):
            raise ValueError("Monitor module source identity/build mismatch")
        self.instrument_profile = None
        if context["oscilloscope"] is not None:
            self.instrument_profile = catalog.build_profile(999)
            if self.instrument_profile.filename not in files:
                raise ValueError(
                    "Selected oscillator database lacks an explicit SHA pin"
                )
        ids = context["selected_ids"]
        if (
            not isinstance(ids, list)
            or not 1 <= len(ids) <= 4096
            or any(type(key) is not int or not 0 <= key <= 65535 for key in ids)
            or len(set(ids)) != len(ids)
        ):
            raise ValueError("Invalid explicit monitor signal IDs")
        observed = context["observed_functions"]
        if not isinstance(observed, dict) or any(
            not isinstance(key, str)
            or re.fullmatch("[0-9]{1,5}", key) is None
            or type(value) is not bool
            for key, value in observed.items()
        ):
            raise ValueError("Explicit native function observations required")
        self.observed = {int(key): value for key, value in observed.items()}
        if len(self.observed) != len(observed) or any(
            key > 65535 for key in self.observed
        ):
            raise ValueError("Duplicate or oversized native function IDs")
        driver = _fields(
            context["driver"], {"version_status", "api_version_hex", "source"}
        )
        self.driver = DriverProperties(
            _uint(driver["version_status"]),
            _hex(driver["api_version_hex"], max_bytes=80),
            driver["source"],
        )
        limits = _fields(context["limits"], {"seconds", "exchanges"})
        if (
            type(limits["seconds"]) not in (int, float)
            or not math.isfinite(limits["seconds"])
            or not 0 < limits["seconds"] <= 3600
        ):
            raise ValueError("Invalid monitor deadline budget")
        self.limits = Limits(
            seconds=limits["seconds"], exchanges=_uint(limits["exchanges"], 65535)
        )
        if not self.limits.exchanges or not 1 <= _uint(context["packet_count"], 65535):
            raise ValueError("Positive monitor event/packet budgets required")
        if context["packet_count"] * len(ids) > 100000:
            raise ValueError("Monitor playback cell budget exceeded")
        if (
            not isinstance(context["ecu"], str)
            or re.fullmatch("[A-Za-z0-9_.:-]{1,64}", context["ecu"]) is None
        ):
            raise ValueError("Explicit bounded ECU label required")
        _uint(context["bus_id"], 65535)
        _uint(context["controller_flags"], 255)
        _uint(context["device_kind"])
        if context["native_variant"] not in ("normal", "psa", "dual", "multi"):
            raise ValueError("Unsupported monitor lower class")
        self.diagnostic_mode = _hex(context["diagnostic_mode_hex"], max_bytes=16)
        if len(self.diagnostic_mode) != 16:
            raise ValueError("Explicit16-byte diagnostic observation required")
        self._context_seal = json.dumps(context, sort_keys=True, separators=(",", ":"))
        self.context, self.profile = context, profile
        self.monitor_session = SelectedMonitorSession(
            profile,
            source_build=context["source_build"],
            shared_interface=context.get("legacy", {}).get("shared_interface")
            if context["mode"] == "legacy"
            else None,
        )
        self.sources = tuple(([path] if path else []) + sources)
        self._source_hashes = {
            source: hashlib.sha256(read_regular(source, limit=MAX_FILE * 8)).hexdigest()
            for source in self.sources
        }
        self.output_formats: dict[str, str] = {}
        self.outputs: dict[str, bytes] = {}
        self.dm_bytes: bytes | None = None
        self.used = False

    def _operations(self, variant=None) -> NativeFrameOperations:
        ctx, rec = self.context, self.recording
        variant = variant or ctx["native_variant"]
        frame = runtime_frame_plan(
            self.profile,
            _hex(ctx["initial_request_hex"]),
            native_build=ctx["source_build"],
            native_variant=variant,
            bus_id=ctx["bus_id"],
            driver=self.driver,
            diagnostic_mode=self.diagnostic_mode,
        )
        return NativeFrameOperations(
            self.profile,
            frame,
            rec,
            native_build=ctx["source_build"],
            native_variant=variant,
            bus_id=ctx["bus_id"],
            driver=self.driver,
            device_kind=ctx["device_kind"],
            diagnostic_mode=self.diagnostic_mode,
            clock=rec.clock,
            cancelled=rec.cancelled,
            wait=rec.wait,
        )

    def run(self) -> dict:
        if self.used:
            raise ValueError("Monitor recording session is single-use")
        self.used = True
        self._check_sources()
        ctx, rec, profile = self.context, self.recording, self.profile
        if ctx["mode"] != "variable" and ctx["variable"] is not None:
            raise ValueError("Unexpected variable configuration")
        if rec.cancelled():
            raise InterruptedError("Monitor recording cancelled")
        if ctx["mode"] == "variable":
            return self._run_variable()
        if ctx["mode"] == "legacy":
            return self._run_legacy()
        connection = (
            selected_p5_can_connection(
                profile,
                bus_id=ctx["bus_id"],
                diagnostic_mode=self.diagnostic_mode,
                controller_category_flags=ctx["controller_flags"],
                source_build=ctx["source_build"],
            ).connection
            if profile.category_record[72] & 31 == 20
            else selected_p4_connection(
                profile,
                bus_id=ctx["bus_id"],
                diagnostic_mode=self.diagnostic_mode,
                controller_category_flags=ctx["controller_flags"],
            )
        )
        cache = MonitorSupportCache(
            profile,
            rec.exchange,
            ctx["ecu"],
            source_build=ctx["source_build"],
            stream=rec,
            bus_id=ctx["bus_id"],
            limits=self.limits,
            clock=rec.clock,
            cancelled=rec.cancelled,
        )
        selection = _fields(
            ctx["selection"],
            {
                "communication_protocol",
                "attribute_3_31",
                "excluded",
                "standard_values",
                "parameter_6",
                "active_alias_pid",
                "dynamic_requested",
                "routine_ids",
                "native_ecu",
            },
        )
        plan = selected_normal_monitor_from_cache(
            cache,
            ctx["selected_ids"],
            self.observed,
            interface_id=connection.address.request_id,
            max_request=connection.maximum_request,
            max_reply=connection.maximum_reply,
            **{
                **selection,
                "standard_values": tuple(
                    tuple(pair) for pair in selection["standard_values"]
                ),
            },
        )
        from scripts.data_monitor import SelectedP4Monitor
        from scripts.monitor_p5 import SelectedP5Monitor
        from scripts.monitor_packet_a8 import SelectedPacketA8Monitor

        if not isinstance(
            plan, (SelectedP4Monitor, SelectedP5Monitor, SelectedPacketA8Monitor)
        ):
            raise TypeError("Normal recording selected a variable provider")
        operations = self._operations()
        oscillator = None
        if ctx["oscilloscope"] is not None:
            from scripts.monitor_poll import NormalOscilloscopeSelection

            osc = _fields(
                ctx["oscilloscope"],
                {"selected_ids", "measure_time_range", "forward_time_range"},
            )
            instrument_profile = self.instrument_profile
            if instrument_profile is None:
                raise ValueError("Selected oscillator source is absent")
            oscillator = NormalOscilloscopeSelection(
                instrument_profile,
                tuple(osc["selected_ids"]),
                rec,
                osc["measure_time_range"],
                osc["forward_time_range"],
            )
        if ctx["mode"] == "dual":
            from scripts.monitor_dual import (
                DualMonitorRuntime,
                NativeDualControl,
                NativeDualPrimitives,
                NativeDualTransport,
                selected_dual_cache,
            )

            if (
                not isinstance(plan, (SelectedP4Monitor, SelectedP5Monitor))
                or oscillator is not None
            ):
                raise ValueError("Dual recording requires its actual selected plan")
            dual = _fields(
                ctx["dual"],
                {"retry_limit", "send_timeout", "receive_timeout", "map_values"},
            )
            target = selected_dual_target(
                profile,
                plan,
                ecu=ctx["ecu"],
                bus_id=ctx["bus_id"],
                diagnostic_mode=self.diagnostic_mode,
                controller_category_flags=ctx["controller_flags"],
                source_build=ctx["source_build"],
                **{**dual, "map_values": tuple(dual["map_values"])},
            )
            control = NativeDualControl(
                (target,),
                {target.ecu: profile},
                NativeDualPrimitives(rec),
                driver=self.driver,
                source_build=ctx["source_build"],
                source_identity=profile.database.sha256,
                connected_device=ctx["device_kind"],
                diagnostic_mode=self.diagnostic_mode,
                clock=rec.clock,
            )
            transport = NativeDualTransport(
                control, operations, {target.ecu: operations.plan}
            )
            worker = DualMonitorRuntime(
                (target,),
                transport,
                version=ctx["source_build"],
                tick_ms=rec.ticks,
                driver_control=control,
                clock=rec.clock,
                cancelled=rec.cancelled,
                command_cache=selected_dual_cache({target.request_id: profile})
                if isinstance(plan, SelectedP5Monitor)
                else None,
            )
            worker.configure(target.request_id, plan.commands)
            primary = None
            try:
                packets = worker.run_packets(ctx["packet_count"])
                capture = NativeRecorderCapture(
                    0,
                    tuple(
                        NativeMonitorPacket(packet.timestamp_raw, packet.payload)
                        for packet in packets
                    ),
                )
            except BaseException as error:
                primary = error
                raise
            finally:
                try:
                    worker.close()
                except BaseException as cleanup:
                    if primary is None:
                        raise
                    primary.add_note(
                        f"Dual monitor cleanup failed: {type(cleanup).__name__}"
                    )
        else:
            if ctx["dual"] is not None:
                raise ValueError("Normal monitor cannot consume Dual configuration")
            worker = selected_normal_monitor_worker(
                operations,
                plan,
                connection,
                oscilloscope=oscillator,
                monitor_session=self.monitor_session,
                limits=self.limits,
                clock=rec.clock,
                ticks=rec.ticks,
                cancelled=rec.cancelled,
            )
            capture = worker.run(ctx["packet_count"])
        rec.assert_complete()
        metadata = _fields(
            ctx["metadata"],
            {
                "phase",
                "allocation_size",
                "name_hex",
                "text_encoding",
                "system_information_hex",
            },
        )
        name = _hex(metadata["name_hex"], max_bytes=256)
        settings = selected_monitor_buffer(
            plan,
            phase=metadata["phase"],
            allocation_size=metadata["allocation_size"],
            name=name,
            text_encoding=metadata["text_encoding"],
        )
        display = MonitorBuffer(
            name,
            bytes(16),
            b"",
            b"",
            b"",
            b"",
            0,
            (),
            tuple(ctx["selected_ids"]),
            b"",
            (),
        )
        saved = capture.monitor_buffer(
            settings, display, phase=metadata["phase"], block_packets=1
        )
        saved = decode_monitor_buffer(encode_monitor_buffer(saved))
        raw = capture.dm_bytes(
            settings,
            display,
            decode_system_information(_hex(metadata["system_information_hex"])),
            phase=metadata["phase"],
            block_packets=1,
        )
        if dumps(parse(raw)) != raw:
            raise ValueError("Native monitor DM reparse failed")
        self._check_sources()
        outputs = {"monitor": raw}
        report = {
            "workflow": "monitor_replay",
            "source": rec.source,
            "status": "completed",
            "summary": "Native monitor recording completed",
            "physical_status": "PHYSICAL_UNCONFIRMED",
            "source_paths": [str(path) for path in self.sources],
            "result": {
                "worker": type(worker).__name__,
                "events": rec.position,
                "dm_export_available": True,
                "native_dm_hex": raw.hex(),
                "playback": {
                    "samples": monitor_samples(
                        saved, encoding=metadata["text_encoding"]
                    ),
                    "timestamp_units": "native-raw-unknown",
                },
            },
        }
        report["result"]["outputs"] = [
            {
                "id": "monitor",
                "format": "dm",
                "category": profile.category,
                "native_dm_hex": raw.hex(),
                "playback": report["result"]["playback"],
            }
        ]
        if oscillator is not None:
            from scripts.monitor_instruments import selected_instrument_monitor
            from scripts.monitor_j2534 import DirectJ2534Worker

            if not isinstance(worker, DirectJ2534Worker) or worker.oscilloscope is None:
                raise ValueError(
                    "Selected oscillator did not create its actual consumer"
                )
            instrument = selected_instrument_monitor(
                oscillator.profile, oscillator.selected_ids
            )
            instrument_settings = instrument.monitor_buffer(
                allocation_size=metadata["allocation_size"],
                name=b"oscilloscope",
                text_encoding=metadata["text_encoding"],
            )
            instrument_display = MonitorBuffer(
                b"oscilloscope",
                bytes(16),
                b"",
                b"",
                b"",
                b"",
                0,
                (),
                oscillator.selected_ids,
                b"",
                (),
            )
            instrument_capture = worker.oscilloscope.capture()
            instrument_raw = instrument_capture.dm_bytes(
                instrument_settings,
                instrument_display,
                decode_system_information(_hex(metadata["system_information_hex"])),
                phase=0,
                block_packets=1,
            )
            instrument_saved = instrument_capture.monitor_buffer(
                instrument_settings, instrument_display, phase=0, block_packets=1
            )
            if dumps(parse(instrument_raw)) != instrument_raw:
                raise ValueError("Native oscillator DM reparse failed")
            outputs["oscilloscope"] = instrument_raw
            report["result"]["outputs"].append(
                {
                    "id": "oscilloscope",
                    "format": "dm",
                    "category": 999,
                    "native_dm_hex": instrument_raw.hex(),
                    "playback": {
                        "timestamp_units": "native-raw-unknown",
                        "samples": monitor_samples(
                            instrument_saved, encoding=metadata["text_encoding"]
                        ),
                    },
                }
            )
        self.dm_bytes, self.outputs = raw, outputs
        return report

    def _run_variable(self) -> dict:
        from scripts.data_monitor import (
            selected_legacy_check_target,
            selected_variable_monitor_runtime,
        )
        from scripts.native_communication import (
            NativeCommunication,
            NativeFrameController,
        )

        ctx, rec = self.context, self.recording
        if ctx["dual"] is not None or ctx["oscilloscope"] is not None:
            raise ValueError(
                "Variable recording cannot consume Dual/oscillator configuration"
            )
        selection = _fields(
            ctx["variable"],
            {"command_kind", "command_ecu", "standard_values"}
            | (set(ctx["variable"]) & {"init_mode", "parameter_c0"}),
        )
        metadata = _fields(
            ctx["metadata"],
            {
                "phase",
                "allocation_size",
                "name_hex",
                "text_encoding",
                "system_information_hex",
            },
        )
        name = _hex(metadata["name_hex"], max_bytes=256)
        communication = NativeCommunication(
            self.profile,
            NativeFrameController(self._operations()),
            ctx["ecu"],
            bus_id=ctx["bus_id"],
            source_build=ctx["source_build"],
            limits=self.limits,
            cancelled=rec.cancelled,
            clock=rec.clock,
        )
        target = selected_legacy_check_target(
            communication,
            ctx["selected_ids"],
            self.observed,
            monitor_session=self.monitor_session,
        )
        runtime = selected_variable_monitor_runtime(
            (target,),
            self._vim_client() if ctx["device_kind"] == 4 else self._operations(),
            connected_device=ctx["device_kind"],
            controller_communication=self._primary_communication(),
            init_mode=selection.get("init_mode"),
            parameter_c0=selection.get("parameter_c0"),
            command_kind=selection["command_kind"],
            command_ecu=selection["command_ecu"],
            allocation=metadata["allocation_size"],
            standard_values=(
                tuple(tuple(pair) for pair in selection["standard_values"]),
            ),
            names=(name,),
            monitor_session=self.monitor_session,
            text_encoding=metadata["text_encoding"],
            phase=metadata["phase"],
            limits=self.limits,
            clock=rec.clock,
            ticks=rec.ticks,
            cancelled=rec.cancelled,
        )
        primary = None
        try:
            if rec.host_commands_left:
                from scripts.monitor_variable import (
                    VariableDmciWorker,
                    VariableMonitorSource,
                    selected_variable_active_operation,
                    selected_variable_system_operation,
                )
                from scripts.profiles import VehicleProfile

                runtime.start()
                assert runtime.worker is not None
                steps = 0
                while True:
                    if rec.cancelled():
                        runtime.step()
                    command = rec.next_host_command()
                    if command is not None:
                        selected = runtime.targets[0]
                        if not isinstance(selected.cache.profile, VehicleProfile):
                            raise TypeError(
                                "Host command requires its actual selected ECU database"
                            )
                        arguments = {
                            "source": VariableMonitorSource.for_build(
                                ctx["source_build"]
                            ),
                            "observed_bus_id": selected.cache.bus_id,
                            "controller_category_flags": selected.cache.profile.category_record[
                                72
                            ],
                        }
                        operation = None
                        if command["command_id"] == 11:
                            operation = selected_variable_active_operation(
                                selected.cache.profile,
                                command["signal_id"],
                                command["value"],
                                auxiliary=command["auxiliary"],
                                initial_repeat=command["initial_repeat"],
                                **arguments,
                            )
                        elif command["command_id"] == 96:
                            operation = selected_variable_system_operation(
                                selected.cache.profile,
                                command["signal_id"],
                                **arguments,
                            )
                        runtime.enqueue(
                            command["command_id"],
                            operation,
                            initialize=command.get("initialize", False),
                        )
                        continue
                    packets = (
                        runtime.worker.packets[0]
                        if isinstance(runtime.worker, VariableDmciWorker)
                        else runtime.worker.packets
                    )
                    if (
                        len(packets) >= ctx["packet_count"]
                        and not rec.host_commands_left
                        and all(result.completed for result in runtime.command_results)
                    ):
                        break
                    if steps >= self.limits.exchanges:
                        raise ValueError("Variable cooperative step budget exhausted")
                    runtime.step()
                    steps += 1
                captures = runtime.stop()
            else:
                captures = runtime.run((ctx["packet_count"],))
        except BaseException as error:
            primary = error
            raise
        finally:
            try:
                runtime.close()
            except BaseException as cleanup:
                if primary is None:
                    raise
                primary.add_note(f"Variable cleanup failed: {type(cleanup).__name__}")
        rec.assert_complete()
        display = MonitorBuffer(
            name,
            bytes(16),
            b"",
            b"",
            b"",
            b"",
            0,
            (),
            tuple(ctx["selected_ids"]),
            b"",
            (),
        )
        raw = runtime.dm_bytes(
            0,
            display,
            decode_system_information(_hex(metadata["system_information_hex"])),
        )
        saved = captures[0].monitor_buffer(
            runtime.targets[0].buffer,
            display,
            phase=metadata["phase"],
            block_packets=runtime.targets[0].buffer.block_packets,
        )
        if dumps(parse(raw)) != raw:
            raise ValueError("Native variable DM reparse failed")
        self._check_sources()
        report = {
            "workflow": "monitor_replay",
            "source": rec.source,
            "status": "completed",
            "summary": "Native variable monitor recording completed",
            "physical_status": "PHYSICAL_UNCONFIRMED",
            "source_paths": [str(path) for path in self.sources],
            "result": {
                "worker": type(runtime).__name__,
                "events": rec.position,
                "commands": [
                    {
                        "command_id": item.command,
                        "completed": item.completed,
                        "status": item.status,
                        "error_type": type(item.error).__name__
                        if item.error is not None
                        else None,
                    }
                    for item in runtime.command_results
                ],
                "dm_export_available": True,
                "native_dm_hex": raw.hex(),
                "playback": {
                    "samples": monitor_samples(
                        saved, encoding=metadata["text_encoding"]
                    ),
                    "timestamp_units": "native-raw-unknown",
                },
            },
        }
        report["result"]["outputs"] = [
            {
                "id": "monitor",
                "format": "dm",
                "category": self.profile.category,
                "native_dm_hex": raw.hex(),
                "playback": report["result"]["playback"],
            }
        ]
        self.dm_bytes, self.outputs = raw, {"monitor": raw}
        return report

    def _run_legacy(self) -> dict:
        from scripts.data_monitor import (
            complete_selected_legacy_recording,
            selected_legacy_monitor_runtime,
        )
        from scripts.drive_recorder import (
            DrsFile,
            NativeTriggerInfo,
            NativeTriggerParameters,
            NativeVehicleSelection,
        )
        from scripts.monitor_legacy import LegacyRunTarget
        from scripts.native_communication import (
            NativeCommunication,
            NativeFrameController,
        )

        ctx, rec = self.context, self.recording
        if (
            ctx["dual"] is not None
            or ctx["oscilloscope"] is not None
            or ctx["variable"] is not None
        ):
            raise ValueError(
                "Legacy runtime cannot consume another provider configuration"
            )
        legacy = _fields(
            ctx.get("legacy"),
            {
                "command_id",
                "command_ecu",
                "enable_mode",
                "shared_interface",
                "init_mode",
                "parameter_c0",
                "standard_values",
                "vehicle_selection_hex",
                "trigger_info_hex",
                "trigger_parameters_hex",
            },
        )
        metadata = _fields(
            ctx["metadata"],
            {
                "phase",
                "allocation_size",
                "name_hex",
                "text_encoding",
                "system_information_hex",
            },
        )
        name = _hex(metadata["name_hex"], max_bytes=256)
        system = decode_system_information(_hex(metadata["system_information_hex"]))
        communication = NativeCommunication(
            self.profile,
            NativeFrameController(self._operations()),
            ctx["ecu"],
            bus_id=ctx["bus_id"],
            source_build=ctx["source_build"],
            limits=self.limits,
            cancelled=rec.cancelled,
            clock=rec.clock,
        )
        target = LegacyRunTarget(
            communication,
            tuple(ctx["selected_ids"]),
            self.observed,
            allocation_size=metadata["allocation_size"],
            name=name,
            text_encoding=metadata["text_encoding"],
            standard_values=tuple(tuple(pair) for pair in legacy["standard_values"]),
        )
        recording = legacy["command_id"] == 87
        if not recording and any(
            legacy[key] is not None
            for key in (
                "vehicle_selection_hex",
                "trigger_info_hex",
                "trigger_parameters_hex",
            )
        ):
            raise ValueError("Native Run87 metadata supplied to another command")
        primary_communication = self._primary_communication()
        primary_target = (
            LegacyRunTarget(primary_communication, (), {}, allocation_size=0)
            if primary_communication is not None
            else None
        )
        controller, message = selected_legacy_monitor_runtime(
            (target,),
            primary=primary_target,
            command_id=legacy["command_id"],
            command_ecu=legacy["command_ecu"],
            connected_device=ctx["device_kind"],
            client=self._vim_client()
            if ctx["device_kind"] == 4 and not recording
            else None,
            phase=metadata["phase"],
            enable_mode=legacy["enable_mode"],
            shared_interface=legacy["shared_interface"],
            init_mode=legacy["init_mode"],
            parameter_c0=legacy["parameter_c0"],
            selection=NativeVehicleSelection.parse(
                _hex(legacy["vehicle_selection_hex"])
            )
            if recording
            else None,
            trigger=NativeTriggerInfo.parse(_hex(legacy["trigger_info_hex"]))
            if recording
            else None,
            parameters=NativeTriggerParameters.parse(
                _hex(legacy["trigger_parameters_hex"])
            )
            if recording
            else None,
            system_information=system if recording else None,
            monitor_session=self.monitor_session,
            limits=self.limits,
            clock=rec.clock,
            cancelled=rec.cancelled,
        )
        if recording:
            drs = complete_selected_legacy_recording(controller, message)
            raw = drs.encode()
            if DrsFile.parse(raw).encode() != raw:
                raise ValueError("Native Run87 DRS reparse failed")
            result = {
                "dm_export_available": False,
                "drs_export_available": True,
                "native_drs_hex": raw.hex(),
                "outputs": [
                    {
                        "id": "recording",
                        "format": "drs",
                        "native_drs_hex": raw.hex(),
                        "table_count": len(drs.tables),
                        "native_settings": drs.report(),
                    }
                ],
            }
            outputs, formats = {"recording": raw}, {"recording": "drs"}
        else:
            primary = None
            try:
                controller.run_one()
                if message.exception is not None:
                    raise message.exception
                if message.result is None:
                    raise ValueError("Selected native legacy command did not finish")
                if message.result.status:
                    raise MonitorError(
                        "Selected native legacy command failed", message.result.status
                    )
                slot = next(
                    index
                    for index, retained in enumerate(controller.targets)
                    if retained is target
                )
                for _ in range(self.limits.exchanges):
                    if (
                        len(controller.capture(slot).capture.packets)
                        >= ctx["packet_count"]
                    ):
                        break
                    controller.poll()
                else:
                    raise ValueError("Legacy capture packet budget exhausted")
                display = MonitorBuffer(
                    name,
                    bytes(16),
                    b"",
                    b"",
                    b"",
                    b"",
                    0,
                    (),
                    tuple(ctx["selected_ids"]),
                    b"",
                    (),
                )
                raw = controller.dm_bytes(slot, display, system)
                selected = controller.capture(slot)
                saved = selected.capture.monitor_buffer(
                    controller.buffers[slot],
                    display,
                    phase=metadata["phase"],
                    block_packets=controller.buffers[slot].block_packets,
                )
                if dumps(parse(raw)) != raw:
                    raise ValueError("Native legacy DM reparse failed")
                playback = {
                    "timestamp_units": "native-raw-unknown",
                    "samples": monitor_samples(
                        saved, encoding=metadata["text_encoding"]
                    ),
                }
                result = {
                    "dm_export_available": True,
                    "native_dm_hex": raw.hex(),
                    "playback": playback,
                    "outputs": [
                        {
                            "id": "monitor",
                            "format": "dm",
                            "native_dm_hex": raw.hex(),
                            "playback": playback,
                        }
                    ],
                }
                outputs, formats = {"monitor": raw}, {"monitor": "dm"}
            except BaseException as error:
                primary = error
                raise
            finally:
                cleanup_failure = None
                for close in (
                    controller.close,
                    communication.close,
                    *(
                        (primary_communication.close,)
                        if primary_communication is not None
                        else ()
                    ),
                ):
                    try:
                        status = close()
                        if status:
                            raise ValueError("Native legacy cleanup failed")
                    except BaseException as cleanup:  # noqa: BLE001 - release both owned resources
                        if primary is None:
                            if cleanup_failure is None:
                                cleanup_failure = cleanup
                        else:
                            primary.add_note(
                                f"Legacy cleanup also failed: {type(cleanup).__name__}"
                            )
                if primary is None and cleanup_failure is not None:
                    raise cleanup_failure
        rec.assert_complete()
        self._check_sources()
        self.outputs, self.output_formats = outputs, formats
        self.dm_bytes = outputs.get("monitor")
        return {
            "workflow": "monitor_replay",
            "source": rec.source,
            "status": "completed",
            "summary": "Native legacy monitor recording completed",
            "physical_status": "PHYSICAL_UNCONFIRMED",
            "source_paths": [str(path) for path in self.sources],
            "result": {
                "worker": type(controller).__name__,
                "events": rec.position,
                **result,
            },
        }

    def _check_sources(self) -> None:
        if (
            json.dumps(self.context, sort_keys=True, separators=(",", ":"))
            != self._context_seal
        ):
            raise ValueError("Monitor recording context changed after validation")
        for source, digest in self._source_hashes.items():
            if (
                source.is_symlink()
                or hashlib.sha256(read_regular(source, limit=MAX_FILE * 8)).hexdigest()
                != digest
            ):
                raise ValueError("Monitor source changed after loading")

    def _primary_communication(self):
        from scripts.native_communication import (
            NativeCommunication,
            NativeFrameController,
        )

        if self.primary_profile is None:
            return None
        observed, ctx, rec = self.context["primary"], self.context, self.recording
        communication = NativeCommunication.from_backend(
            self.primary_profile,
            rec,
            observed["ecu"],
            first_request=_hex(observed["initial_request_hex"]),
            driver=self.driver,
            device_kind=ctx["device_kind"],
            bus_id=observed["bus_id"],
            source_build=ctx["source_build"],
            diagnostic_mode=_hex(observed["diagnostic_mode_hex"], max_bytes=16),
            limits=self.limits,
            cancelled=rec.cancelled,
            clock=rec.clock,
        )
        if not isinstance(communication.operations, NativeFrameController):
            raise TypeError("Primary requires its concrete frame controller")
        communication.operations.operations.wait = rec.wait
        return communication

    def _vim_client(self):
        from scripts.drive_recorder import NativeVimClient

        observed = _fields(self.context.get("vim"), {"capabilities", "module_variant"})
        capabilities = observed["capabilities"]
        if (
            not isinstance(capabilities, list)
            or set(capabilities) != {"denso-vim-control", "denso-vim-dmci"}
            or len(capabilities) != 2
        ):
            raise ValueError("Explicit native VIM control/DMCI observations required")
        return NativeVimClient(
            self.recording.vim_exchange,
            capabilities=frozenset(capabilities),
            clock=self.recording.clock,
        )

    def save_dm(self, destination: str | Path, *, stream: str = "monitor") -> None:
        if self.output_formats.get(stream, "dm") != "dm":
            raise ValueError("Selected output is native DRS, not DM")
        self.save_output(destination, stream=stream)

    def save_output(self, destination: str | Path, *, stream: str = "monitor") -> None:
        if not self.outputs:
            raise ValueError("Completed native monitor output required")
        self._check_sources()
        if stream not in self.outputs:
            raise ValueError("Unknown native monitor output stream")
        destination = Path(destination)
        for source in self.sources:
            if (
                destination.resolve() == source.resolve()
                or destination.exists()
                and destination.samefile(source)
            ):
                raise ValueError("Monitor export would overwrite an input")
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(
                dir=destination.parent, prefix=f".{destination.name}.", delete=False
            ) as output:
                temporary = Path(output.name)
                output.write(self.outputs[stream])
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, destination)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)


def load_monitor_recording(
    path: str | Path,
    source_root: str | Path,
    *,
    cancelled: Callable[[], bool] = lambda: False,
) -> MonitorReplay:
    path = Path(path)
    return MonitorReplay(
        MonitorRecording.loads(read_regular(path, limit=MAX_FILE), cancelled),
        Path(source_root),
        path=path,
    )
