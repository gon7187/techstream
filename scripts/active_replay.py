"""Selected active-test workflows over captured native application PDUs."""

from __future__ import annotations

import copy
import hashlib
import json
import re
import struct
import tempfile
import threading
import time
from collections.abc import Callable
from functools import wraps
from pathlib import Path
from typing import Any

from scripts.active_tests import (
    ActiveTestCatalog,
    ActiveTestInitialization,
    SAFinalizer,
    SAKeyMaterial,
)
from scripts.data_monitor import MonitorReceive, RoutineMonitor, legacy_initialize
from scripts.demo import _ddb, _language, create_demo
from scripts.diagnostic_db import parse_database
from scripts.local_files import read_regular
from scripts.native_replay import MAX_FILE, NativeReplay
from scripts.profiles import VehicleCatalog, VehicleProfile
from scripts.support import correspondence_rows, word
from scripts.toyota import CommandFrame, VariableTable
from scripts.toyota_session import (
    Cancelled,
    CommandSpec,
    LegacyActiveQueue,
    P5ActiveQueue,
    ToyotaSession,
    active_arguments_p5,
    active_request_p3,
    active_request_psa,
    routine_arguments_p5,
)

SCHEMA = "techstream-active-workflow-v1"


def _serialized(method: Callable[..., Any]) -> Callable[..., Any]:
    @wraps(method)
    def call(self, *args, **kwargs):
        with self._lock:
            return method(self, *args, **kwargs)

    return call


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate active workflow field: {key}")
        result[key] = value
    return result


def _fields(value: Any, names: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != names:
        raise ValueError(f"Unexpected {label} fields")
    return value


def _uint(value: Any, maximum: int, label: str) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError(f"{label} must fit an unsigned native field")
    return value


def _hex(value: Any, limit: int = 65535) -> bytes:
    if (
        not isinstance(value, str)
        or len(value) > limit * 2
        or len(value) % 2
        or re.fullmatch("[0-9a-fA-F]*", value) is None
    ):
        raise ValueError("Expected bounded even hexadecimal bytes")
    return bytes.fromhex(value)


def _lengths(value: Any, width: int) -> dict[int, int]:
    if not isinstance(value, dict) or len(value) > 65536:
        raise ValueError("Explicit support length observations are required")
    result = {}
    for key, length in value.items():
        if (
            not isinstance(key, str)
            or re.fullmatch(f"[0-9a-f]{{{width}}}", key) is None
        ):
            raise ValueError("Support keys require canonical lowercase hexadecimal")
        result[int(key, 16)] = _uint(
            length, 255 if width == 2 else 65535, "Observed data length"
        )
    return result


def _ids(value: Any, maximum: int) -> frozenset[int]:
    if not isinstance(value, list) or len(value) > maximum + 1:
        raise ValueError("Explicit observed identifier list is required")
    checked = [_uint(item, maximum, "Observed identifier") for item in value]
    if len(set(checked)) != len(checked):
        raise ValueError("Duplicate observed identifier")
    return frozenset(checked)


def _bits(value: Any) -> dict[tuple[int, int, int], bool]:
    if not isinstance(value, list) or len(value) > 100000:
        raise ValueError("Explicit bit-range observations are required")
    result = {}
    for item in value:
        item = _fields(item, {"pid", "start", "end", "supported"}, "bit observation")
        key = tuple(
            _uint(item[name], 65535 if name != "pid" else 255, name)
            for name in ("pid", "start", "end")
        )
        if key[1] > key[2] or type(item["supported"]) is not bool or key in result:
            raise ValueError("Invalid or duplicate native bit-range observation")
        result[key] = item["supported"]
    return result


def _load_document(raw: bytes) -> dict[str, Any]:
    if not isinstance(raw, bytes) or len(raw) > MAX_FILE:
        raise ValueError("Active recording must be bytes within 16 MiB")
    try:
        value = json.loads(raw, object_pairs_hook=_object)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise ValueError(f"Invalid active workflow JSON: {error}") from error
    return _document_fields(value)


def _document_fields(value: Any) -> dict[str, Any]:
    optional = (
        {"driver_events"}
        if isinstance(value, dict) and "driver_events" in value
        else set()
    )
    return _fields(
        value, {"schema", "context", "native", "events"} | optional, "active workflow"
    )


class _DriverReplay:
    """Literal low-level calls, ordered relative to the diagnostic PDU stream."""

    def __init__(self, events: Any, replay: NativeReplay):
        if not isinstance(events, list) or len(events) > 100000:
            raise ValueError("Bounded native driver events are required")
        self.events: list[dict[str, Any]] = []
        self.replay, self.position = replay, 0
        self.observed: list[dict[str, Any]] = []
        size = 2
        for event in events:
            if not isinstance(event, dict):
                raise TypeError("Invalid native driver event")
            operation = event.get("operation")
            common = {"operation", "after_exchange", "ecu", "timeout", "status"}
            fields = (
                {"request", "protocol", "initialize"}
                if operation == "send"
                else {"buffer", "maximum", "argument_5", "flags", "data", "source_id"}
            )
            if operation not in ("send", "receive"):
                raise ValueError("Unknown native driver primitive")
            _fields(event, common | fields, "native driver event")
            for key in ("after_exchange", "timeout", "status"):
                _uint(event[key], 0xFFFFFFFF, key)
            if event["ecu"] not in replay.ecus:
                raise ValueError("Driver event ECU is not recorded")
            if operation == "send":
                _uint(event["protocol"], 65535, "Driver bus ID")
                if type(event["initialize"]) is not bool:
                    raise ValueError("Driver initialization flag must be boolean")
                if event["request"] is not None:
                    _hex(event["request"], 4096)
            else:
                if type(event["buffer"]) is not bool:
                    raise ValueError("Driver receive buffer flag must be boolean")
                _uint(event["maximum"], 4096, "Driver receive maximum")
                for key in ("argument_5", "flags", "source_id"):
                    _uint(event[key], 0xFFFFFFFF, key)
                data = _hex(event["data"], 4096)
                if len(data) > event["maximum"] or (data and not event["buffer"]):
                    raise ValueError(
                        "Driver receive evidence exceeds its supplied buffer"
                    )
            # All fields have scalar types and bounded strings before copying or
            # serialization. Direct callers get the same aggregate byte ceiling
            # as file callers; rejected nested objects are never deep-copied.
            size += len(json.dumps(event, separators=(",", ":")).encode()) + 1
            if size > MAX_FILE:
                raise ValueError("Native driver evidence exceeds16 MiB")
            self.events.append(dict(event))

    def _call(
        self, operation: str, ecu: str, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        if self.position >= len(self.events):
            raise ValueError("Missing recorded native driver primitive")
        event = self.events[self.position]
        expected = {
            "operation": operation,
            "ecu": ecu,
            "after_exchange": self.replay.position,
        } | arguments
        if any(
            event.get(key) != value or type(event.get(key)) is not type(value)
            for key, value in expected.items()
        ):
            raise ValueError("Native driver primitive replay mismatch")
        self.position += 1
        self.observed.append(copy.deepcopy(event))
        return event

    def send(
        self,
        ecu: str,
        request: bytes | None,
        *,
        timeout: int,
        protocol: int,
        initialize: bool,
    ) -> int:
        return self._call(
            "send",
            ecu,
            {
                "request": None if request is None else request.hex(),
                "timeout": timeout,
                "protocol": protocol,
                "initialize": initialize,
            },
        )["status"]

    def receive(
        self,
        ecu: str,
        *,
        buffer: bool,
        maximum: int,
        timeout: int,
        argument_5: int,
        flags: int,
    ) -> MonitorReceive:
        event = self._call(
            "receive",
            ecu,
            {
                "buffer": buffer,
                "maximum": maximum,
                "timeout": timeout,
                "argument_5": argument_5,
                "flags": flags,
            },
        )
        return MonitorReceive(
            _hex(event["data"], 4096), event["source_id"], event["status"]
        )

    def assert_complete(self) -> None:
        if self.position != len(self.events):
            raise ValueError("Unconsumed recorded native driver primitives")


def selected_routine_monitors(
    profile: VehicleProfile, signal_id: int
) -> tuple[RoutineMonitor, ...]:
    """Phase5 7f20 -> engine1c50 -> 2fb0 selected normal RID setup."""
    selected = profile.frame_records(0xD7)
    if not selected:
        raise ValueError("Selected routine status frame is absent")
    _uint(signal_id, 65535, "Selected routine signal")
    if profile.database.version not in (0x0100030C, 0x0100032F):
        raise ValueError("No recovered routine monitor layout for this version")
    template = selected[0].frame.request
    if len(template) != 4:
        raise ValueError("Selected normal routine status template must have four bytes")
    special = {0x9C42: (0x9C40, 0x9C41), 0x9C46: (0x9C44, 0x9C45)}
    if profile.database.version == 0x0100032F:
        special[0x9C49] = (0x9C47, 0x9C48)
    keys = special.get(signal_id, (signal_id,))
    routines, displays, statuses = (profile.records(slot) for slot in (71, 73, 72))
    section = profile.catalog.management.sections[0]
    variables = VariableTable(section.payload, section.count)
    shift = 2 if profile.database.version == 0x0100030C else 0

    def values(key: int) -> tuple[int, ...]:
        result = []
        for row in statuses:
            if word(row, 0) != key:
                continue
            pattern = variables.get(word(row, 2))
            value = 0
            for index, byte in enumerate(pattern):
                value |= byte << (((len(pattern) - index - 1) * 8) & 31)
            result.append(value & 65535)
        return tuple(result)

    result = []
    for index, key in enumerate(keys):
        row = next((row for row in routines if word(row, 30) == key), None)
        if row is None:
            raise ValueError("Selected native routine monitor child is absent")
        group = word(row, 54 - shift)
        selected = next((row for row in displays if word(row, 4) == group), None)
        if selected is None:
            raise ValueError("Native routine monitor button group is empty")
        size = len(variables.get(word(selected, 10)))
        abnormal = values(word(row, 48 - shift))
        normal = values(word(row, 46 - shift)) if len(keys) == 1 else ()
        stop = (
            tuple(value for value in abnormal if value == 3)
            if len(keys) > 1 and index == 0
            else ()
        )
        request = template[:2] + word(row, 28).to_bytes(2, "big")
        result.append(RoutineMonitor(request, size, normal, abnormal, stop))
    return tuple(result)


class ActiveReplay:
    """One observed selected context, chronological evidence and owned lifecycle.

    List and Init may themselves consume captured support/initial-value probes.
    Their results are cached so rendering a dialog does not repeat native I/O.
    """

    def __init__(
        self,
        document: dict[str, Any],
        profile: VehicleProfile,
        *,
        cancelled: Callable[[], bool] | None = None,
        sa_library: str | Path | None = None,
    ):
        self._lock = threading.RLock()
        self._closing = threading.Event()
        _document_fields(document)
        if document["schema"] != SCHEMA:
            raise ValueError("Unknown active workflow schema")
        context_optional = (
            {"routine_info"}
            if isinstance(document["context"], dict)
            and "routine_info" in document["context"]
            else set()
        )
        context = _fields(
            document["context"],
            {
                "ecu",
                "family",
                "init_family",
                "protocol",
                "bus_id",
                "version",
                "category",
                "management_sha256",
                "ecu_sha256",
                "pid_lengths",
                "did_lengths",
                "enabled_dids",
                "enabled_rids",
                "bit_ranges",
                "pid_support",
                "positions",
                "driver",
            }
            | context_optional,
            "active context",
        )
        self.profile, self.catalog = profile, ActiveTestCatalog(profile)
        for name, actual in (
            ("version", profile.database.version),
            ("category", profile.category),
            ("management_sha256", profile.catalog.management.sha256),
            ("ecu_sha256", profile.database.sha256),
        ):
            if type(context[name]) is not type(actual) or context[name] != actual:
                raise ValueError(f"Active recording selected-profile mismatch: {name}")
        self.family, self.init_family = context["family"], context["init_family"]
        if self.family not in (
            "p3",
            "dk",
            "p4",
            "old_body",
            "sa",
            "p5",
            "routine",
            "psa",
        ):
            raise ValueError("Unknown active workflow family")
        if self.init_family not in ("p3", "dk", "p4", "p5", "routine"):
            raise ValueError("An actual recovered Init family must be selected")
        if (
            self.family in ("p3", "dk", "p4", "p5", "routine")
            and self.family != self.init_family
        ):
            raise ValueError("Active List and Init families disagree")
        if self.family in ("old_body", "sa", "psa") and self.init_family not in (
            "p3",
            "dk",
            "p4",
        ):
            raise ValueError("Legacy active workflow requires legacy Init metadata")
        self.protocol = _uint(context["protocol"], 255, "Protocol")
        self.bus_id = _uint(context["bus_id"], 65535, "Observed bus ID")
        if not self.bus_id:
            # P4 load8e00 rejects GetBusId==0. Requiring a captured connected
            # bus for other families is conservative host preflight.
            raise ValueError(
                "Active workflow requires a nonzero observed connected bus"
            )
        protocol_record = profile.protocol_info(self.bus_id)
        if protocol_record is None:
            raise ValueError("Observed bus has no selected native ProtInfo record")
        self.protocol_record = protocol_record
        self.routine_info = context.get("routine_info")
        if "routine_info" in context and type(self.routine_info) is not bool:
            raise ValueError("Observed routine-info flag must be boolean")
        self.driver = context["driver"]
        phase = self.init_family if self.family in ("old_body", "sa") else self.family
        allowed = {
            "p3": ("j2534",),
            "p4": ("j2534", "dual"),
            "dk": ("j2534", "dk_iso9141", "dk_kwp", "fuel"),
            "p5": ("p5", "dual"),
            "routine": ("p5", "dual"),
            "psa": ("psa",),
        }
        if self.driver not in allowed[phase]:
            raise ValueError("Selected active family and native driver disagree")
        self.pid_lengths = _lengths(context["pid_lengths"], 2)
        self.did_lengths = _lengths(context["did_lengths"], 4)
        self.enabled_dids = _ids(context["enabled_dids"], 65535)
        self.enabled_rids = _ids(context["enabled_rids"], 65535)
        self.pid_support = _ids(context["pid_support"], 65535)
        self.bit_ranges = _bits(context["bit_ranges"])
        if not isinstance(context["positions"], dict):
            raise TypeError("Explicit initial-read position observations required")
        self.positions = {}
        for key, value in context["positions"].items():
            if not isinstance(key, str) or re.fullmatch("[0-9a-f]{2}", key) is None:
                raise ValueError("Position observations require byte PID keys")
            self.positions[int(key, 16)] = _hex(value, 256)
        self.replay = NativeReplay(document["native"])
        self._driver_replay = _DriverReplay(
            document.get("driver_events", []), self.replay
        )
        if document["native"]["support"]:
            raise ValueError(
                "Active support observations belong to the selected workflow context"
            )
        self.ecu = context["ecu"]
        if self.ecu not in self.replay.ecus:
            raise ValueError("Selected active ECU is absent from native recording")
        external_cancelled = cancelled or (lambda: False)
        self.cancelled = lambda: self._closing.is_set() or external_cancelled()
        self._tick = 0
        self.session = ToyotaSession(
            self.replay.exchange,
            self.ecu,
            {},
            cancelled=self.cancelled,
            clock=time.monotonic,
        )
        self._events = self._validate_events(document["events"])
        if (
            self.family == "routine"
            and any(event["action"] == "status" for event in self._events)
            and self.routine_info is None
        ):
            raise ValueError("Routine status requires an observed routine-info flag")
        if (
            self.driver in ("dk_kwp", "fuel")
            and self._events[-1]["initialize"]
            and not self._driver_replay.events
        ):
            raise ValueError(
                "Recorded NULL send/receive initialization primitives are required"
            )
        self._event_position = 0
        self._tests = None
        self._initialized: dict[tuple[str, int], ActiveTestInitialization] = {}
        self._support: dict[str, Any] = {}
        self._selected_templates: dict[int, str] = {}
        self._status_monitors: tuple[RoutineMonitor, ...] = ()
        self._closed = False
        self.source_path: Path | None = None
        self._legacy: LegacyActiveQueue | None = None
        self._active_init: ActiveTestInitialization | None = None
        self._queue: LegacyActiveQueue | P5ActiveQueue | None = None
        self._phase_state = "idle"
        self._observations: list[dict[str, Any]] = []
        self._sa = None
        if self.family == "sa":
            if sa_library is None:
                raise ValueError(
                    "SA workflow requires local verified key-material library"
                )
            self._sa = SAFinalizer(
                profile, self.session, SAKeyMaterial.from_library(str(sa_library))
            )

    @staticmethod
    def _validate_events(value: Any) -> tuple[dict[str, Any], ...]:
        if not isinstance(value, list) or not 1 <= len(value) <= 100000:
            raise ValueError("Bounded native lifecycle events are required")
        result = []
        for event in value:
            names = (
                {"action", "tick", "initialize"}
                if isinstance(event, dict) and event.get("action") == "stop"
                else {"action", "tick"}
            )
            event = _fields(event, names, "active lifecycle event")
            if event["action"] not in ("start", "step", "status", "stop"):
                raise ValueError("Unknown active lifecycle event")
            checked = {
                "action": event["action"],
                "tick": _uint(event["tick"], 0xFFFFFFFF, "Native tick"),
            }
            if event["action"] == "stop":
                if type(event["initialize"]) is not bool:
                    raise ValueError(
                        "Recorded stop initialization flag must be boolean"
                    )
                checked["initialize"] = event["initialize"]
            result.append(checked)
        if result[0]["action"] != "start" or any(
            item["action"] == "start" for item in result[1:]
        ):
            raise ValueError("A workflow owns exactly one native start")
        if result[-1]["action"] != "stop" or any(
            item["action"] == "stop" for item in result[:-1]
        ):
            raise ValueError("A workflow requires exactly one final recorded stop")
        return tuple(result)

    @classmethod
    def loads(
        cls,
        raw: bytes,
        profile: VehicleProfile,
        *,
        cancelled: Callable[[], bool] | None = None,
        sa_library: str | Path | None = None,
    ) -> ActiveReplay:
        return cls(
            _load_document(raw), profile, cancelled=cancelled, sa_library=sa_library
        )

    @classmethod
    def load(
        cls,
        path: str | Path,
        profile: VehicleProfile,
        *,
        cancelled: Callable[[], bool] | None = None,
        sa_library: str | Path | None = None,
    ) -> ActiveReplay:
        result = cls.loads(
            read_regular(path, limit=MAX_FILE),
            profile,
            cancelled=cancelled,
            sa_library=sa_library,
        )
        result.source_path = Path(path).resolve()
        return result

    def _frame(self, function: int) -> CommandSpec:
        selected = self.profile.frame_records(function)
        if not selected:
            raise ValueError(
                f"Active phase requires selected function {function:02x} frame"
            )
        # Phase5 D599/DE10/E35E/E5AB and RoutineInit2260 consume GetAt(0).
        # Initial-value CA/6B readers separately enforce their native count==1.
        self._selected_templates[function] = selected[0].provenance
        return CommandSpec(selected[0].frame, provenance=selected[0].provenance)

    def _probe(self, request: bytes, *, cleanup: bool = False) -> bytes:
        probe = ToyotaSession(
            self.replay.exchange,
            self.ecu,
            {
                "support": CommandSpec(
                    CommandFrame(request),
                    check="raw",
                    provenance="selected-active-support-probe",
                )
            },
            cancelled=(lambda: False) if cleanup else self.cancelled,
            clock=time.monotonic,
        )
        try:
            return probe.execute("support")
        finally:
            self.session.trace.extend(probe.trace)

    def _binding(self, family: str):
        if family not in self._support:

            def bits(pid: int, start: int, end: int) -> bool:
                key = (pid, start, end)
                if key not in self.bit_ranges:
                    raise ValueError(
                        f"Missing observed native bit range {pid:02x}:{start}:{end}"
                    )
                return self.bit_ranges[key]

            def routine_probe(rid: int, size: int) -> bool:
                probe = ToyotaSession(
                    self.replay.exchange,
                    self.ecu,
                    {"status": self._frame(0xD7)},
                    cancelled=self.cancelled,
                    clock=time.monotonic,
                )
                try:
                    return probe.routine_initial_status_p5(
                        "status",
                        rid,
                        size,
                        subaru=bool(self.profile.category_record[72] & 0xE0 == 0x20),
                    )
                finally:
                    self.session.trace.extend(probe.trace)

            self._support[family] = self.catalog.observed_support(
                family,
                protocol=self.protocol,
                pid_lengths=self.pid_lengths,
                did_lengths=self.did_lengths,
                enabled_dids=self.enabled_dids,
                enabled_rids=self.enabled_rids,
                check_bits=bits,
                exchange=self._probe,
                pid_support=lambda pid: pid in self.pid_support,
                routine_probe=routine_probe,
                sa_finalize=self._sa,
            )
        return self._support[family]

    @_serialized
    def available_tests(self) -> tuple[dict[str, Any], ...]:
        if self._closed:
            raise ValueError("Active replay is closed")
        if self._tests is None:
            family = "p4" if self.family == "psa" else self.family
            self._tests = self.catalog.list(family, support=self._binding(family))
        return tuple(item.report() for item in self._tests)

    @_serialized
    def initialize(
        self, signal_id: int, *, family: str | None = None
    ) -> dict[str, Any]:
        signal_id = _uint(signal_id, 65535, "Active signal")
        self.available_tests()
        selected_family = "p4" if self.family == "psa" and family == "psa" else family
        candidates = [
            item
            for item in self._tests or ()
            if item.signal_id == signal_id
            and (selected_family is None or item.family == selected_family)
        ]
        if not candidates:
            raise ValueError("Active test is absent from the observed native list")
        if len({item.family for item in candidates}) != 1:
            raise ValueError("An unambiguous selected active family is required")
        selected = candidates[0]
        init_family = "routine" if selected.routine else self.init_family
        key = (init_family, signal_id)
        if key not in self._initialized:
            self._initialized[key] = self.catalog.initialize(
                init_family,
                signal_id,
                support=self._binding(init_family),
                read_value=self.catalog.initial_value_reader(
                    self.session, positions=self.positions
                ),
            )
        return self._initial_report(self._initialized[key])

    def _argument_fields(self, initial: ActiveTestInitialization) -> dict[str, bool]:
        modern = initial.test.family in ("p5", "routine")
        output_mask = False
        if (
            modern
            and not initial.test.routine
            and self.profile.database.version == 0x0100032F
        ):
            rows = [
                row
                for row in self.profile.records(67)
                if word(row, 2) == word(initial.test.record, 52)
            ]
            output_mask = bool(rows and rows[0][10] == 1)
        return {
            "scalar": not initial.test.routine or any(initial.output_mask),
            "bytes": initial.test.routine and any(initial.output_mask),
            "buttons": bool(initial.routine_buttons),
            "auxiliary": not modern,
            "output_mask": output_mask,
        }

    def _initial_report(self, initial: ActiveTestInitialization) -> dict[str, Any]:
        return copy.deepcopy(initial.report()) | {
            "input_byte_count": sum(bool(mask) for mask in initial.output_mask),
            "button_byte_count": len(initial.button_mask),
            "argument_fields": self._argument_fields(initial),
        }

    def _arguments(
        self, initial: ActiveTestInitialization, arguments: Any
    ) -> dict[str, Any]:
        optional = (
            {"output_mask"}
            if isinstance(arguments, dict) and "output_mask" in arguments
            else set()
        )
        arguments = _fields(
            arguments,
            {"value", "auxiliary", "display_index", "input_hex", "button_index"}
            | optional,
            "entered active arguments",
        )
        value = arguments["value"]
        if type(value) is not int or not -0x80000000 <= value <= 0x7FFFFFFF:
            raise ValueError("Entered active value must fit signed32 native long")
        auxiliary = _uint(arguments["auxiliary"], 255, "Entered auxiliary value")
        output_mask = _uint(
            arguments.get("output_mask", 0), 0xFFFFFFFF, "Entered output mask"
        )
        if initial.test.family in ("p5", "routine") and auxiliary:
            raise ValueError(
                "Selected modern active phase has no legacy auxiliary byte"
            )
        if (initial.test.family != "p5" or initial.test.routine) and output_mask:
            raise ValueError(
                "Scalar output masks belong to ordinary P5 active controls"
            )
        if self.profile.database.version == 0x0100030C and output_mask:
            raise ValueError(
                "Version 12 active controls have no scalar output-mask override"
            )
        if output_mask and not self._argument_fields(initial)["output_mask"]:
            raise ValueError(
                "Selected active data-ID mode has no scalar output-mask override"
            )
        display_index, button_index = (
            arguments["display_index"],
            arguments["button_index"],
        )
        if display_index is not None:
            display_index = _uint(
                display_index, len(initial.displays) - 1, "Selected display"
            )
            display = initial.displays[display_index]
            if not display.enabled or not isinstance(display.press, int):
                raise ValueError(
                    "Selected active display is unavailable or has no scalar value"
                )
            value = display.press
        input_bytes = _hex(arguments["input_hex"], 65531)
        if input_bytes and not initial.test.routine:
            raise ValueError("Byte arguments belong to selected Routine controls")
        if input_bytes and len(input_bytes) != sum(
            bool(mask) for mask in initial.output_mask
        ):
            raise ValueError(
                "Routine byte argument count differs from selected output mask"
            )
        # Routine input bytes replace the scalar assembly branch. Fixed commands
        # without an output mask do not consume the scalar field either.
        uses_scalar = not initial.test.routine or (
            not input_bytes and any(initial.output_mask)
        )
        if uses_scalar and not initial.minimum <= value <= initial.maximum:
            raise ValueError("Entered active value is outside selected Init limits")
        buttons = b""
        if button_index is not None:
            button_index = _uint(
                button_index,
                len(initial.routine_buttons) - 1,
                "Selected routine button",
            )
            selected_button = initial.routine_buttons[button_index]
            if not isinstance(selected_button.press, bytes):
                raise ValueError("Routine button lacks native byte data")
            buttons = selected_button.press
        return {
            "value": value & 0xFFFFFFFF,
            "auxiliary": auxiliary,
            "input_bytes": input_bytes,
            "buttons": buttons,
            "output_mask": output_mask,
        }

    def _selected_initial(
        self, signal_id: int, family: str | None
    ) -> ActiveTestInitialization:
        report = self.initialize(signal_id, family=family)
        init_family = "routine" if report["routine"] else self.init_family
        return self._initialized[(init_family, signal_id)]

    def _p5_queue(
        self, initial: ActiveTestInitialization, arguments: dict[str, Any]
    ) -> P5ActiveQueue:
        row = initial.test.record
        if initial.test.routine:
            start, release = routine_arguments_p5(
                row,
                self._frame(0xD5).frame.request,
                self._frame(0xD6).frame.request,
                initial.command,
                initial.output_mask,
                arguments["value"],
                input_bytes=arguments["input_bytes"],
                button_mask=initial.button_mask,
                buttons=arguments["buttons"],
            )
            repeat = 0
        else:
            did = word(row, 52)
            if (
                self.profile.database.version == 0x0100032F
                and self.protocol & 0xE0 == 0x20
            ):
                # Phase5 D5FA..D769 scans all selected actions for this DID.
                data_length = max(
                    word(item, 42) // 8 + 1
                    for item in self.profile.records(68)
                    if word(item, 52) == did
                )
            else:
                if did not in self.did_lengths:
                    raise ValueError(f"Missing observed active DID length {did:04x}")
                data_length = self.did_lengths[did]
            rows = tuple(
                record for record in self.profile.records(67) if word(record, 2) == did
            )
            if initial.pattern is None:
                raise ValueError("Selected active pattern is absent")
            start, release, repeat = active_arguments_p5(
                row,
                rows,
                self._frame(0x9D).frame.request,
                self._frame(0x64).frame.request,
                arguments["value"],
                data_length,
                initial.pattern,
                output_mask=arguments["output_mask"],
            )
        queue = P5ActiveQueue(dual=self.driver == "dual")
        queue.enqueue(
            start[1:], release[1:], repeat_ms=repeat, routine=initial.test.routine
        )
        return queue

    def _legacy_queue(
        self, initial: ActiveTestInitialization, arguments: dict[str, Any]
    ) -> LegacyActiveQueue:
        if initial.pattern is None:
            raise ValueError("Selected active pattern is absent")
        row = initial.test.record
        support = self.positions.get(row[82])
        if self.family == "psa":
            request, repeat = active_request_psa(
                row,
                initial.pattern,
                self.protocol,
                arguments["value"],
                auxiliary=arguments["auxiliary"],
                support=support,
                comm_mode=self.profile.active_comm_mode(row),
            )
            queue = LegacyActiveQueue("psa")
            queue.enqueue(request, repeat_ms=repeat)
        else:
            request, repeat = active_request_p3(
                row,
                initial.pattern,
                self.protocol,
                arguments["value"],
                auxiliary=arguments["auxiliary"],
                support=support,
            )
            queue = LegacyActiveQueue(
                "dk" if self.driver == "dk_iso9141" else "ordinary"
            )
            queue.enqueue(request[1:], repeat_ms=repeat)
        return queue

    def _legacy_step(self, *, cleanup: bool = False) -> bytes | None:
        queue = self._legacy
        if queue is None:
            raise ValueError("No legacy active test owns this replay")
        if not cleanup and self.cancelled():
            raise Cancelled("Legacy active workflow cancelled")
        if queue.family == "dk" and queue.items[-1].state in (1, 2):
            return None
        if queue.family == "psa":
            current = queue.items[-1]
            if current.state == 2:
                return None
            if current.state == 1:
                if self._tick >= current.next_tick:
                    current.state = 0
                return None
        if not cleanup:
            return self.session.legacy_active_step(queue, self._tick)
        request = (
            queue.next_request(self._tick)
            if queue.family == "ordinary"
            else queue.send_frame(self._tick)
        )
        if request is None:
            return None
        reply = self._probe(request, cleanup=True)
        queue.accept(reply, self._tick)
        return reply

    def _stop(self, *, shutdown: bool = False) -> list[bytes]:
        if self.session.active is not None:
            replies = self.session.stop_active_test(now_ms=self._tick)
        elif self._legacy is not None:
            queue = self._legacy
            if queue.family == "dk":
                # DataListIF7620 signals local worker termination; no ECU PDU.
                replies = []
            else:
                before = len(queue.items)
                queue.stop(
                    initialize=self._events[-1]["initialize"] if not shutdown else False
                )
                if queue.family == "psa" and len(queue.items) == before:
                    self._legacy = None
                    self._phase_state = "stopped"
                    return []
                if queue.family == "ordinary" and shutdown:
                    queue.skip_to_last()
                reply = self._legacy_step(cleanup=True)
                if reply is None:
                    raise ValueError("Recorded stop tick precedes native stop timing")
                replies = [reply]
                state = queue.items[0 if queue.family == "ordinary" else -1].state
                if state != (5 if queue.family == "ordinary" else 2):
                    raise ValueError(
                        "Recorded stop reply did not reach native terminal state"
                    )
                if (
                    not shutdown
                    and self._events[-1]["initialize"]
                    and self.driver in ("dk_kwp", "fuel")
                ):
                    # The ECU release has completed. A subsequent driver-call
                    # evidence failure must not manufacture a second release PDU.
                    self._legacy = None
                    # DataListIF2bc70/2c530 uses literal NULL calls; it ignores both
                    # native status codes. Keep the observations, including errors.
                    send_timeout, receive_timeout = self._driver_timeouts()
                    legacy_initialize(
                        self._driver_replay,
                        self.ecu,
                        send_timeout=send_timeout,
                        receive_timeout=receive_timeout,
                        protocol=self.bus_id,
                    )
            self._legacy = None
        else:
            replies = []
        self._phase_state = "stopped"
        return replies

    def _driver_timeouts(self) -> tuple[int, int]:
        management = self.profile.catalog.management
        functions = [
            row
            for row in correspondence_rows(management, 18, self.profile.exception_ids)
            if word(row, 0) == self.profile.category and word(row, 2) == 0xA7
        ]
        key = word(functions[0], 4) if functions else 1
        settings = [
            row
            for row in correspondence_rows(management, 29, self.profile.exception_ids)
            if word(row, 10) == key
        ]
        return struct.unpack_from("<II", settings[0]) if settings else (1000, 200)

    @_serialized
    def run_test(
        self, signal_id: int, arguments: dict[str, Any], *, family: str | None = None
    ) -> dict[str, Any]:
        if self._closed or self._phase_state != "idle":
            raise ValueError("Active workflow has already run or is closed")
        initial = self._selected_initial(signal_id, family)
        if (
            initial.test.routine
            and any(event["action"] == "status" for event in self._events)
            and self.routine_info is None
        ):
            raise ValueError("Routine status requires an observed routine-info flag")
        entered = self._arguments(initial, arguments)
        if initial.test.routine and any(
            event["action"] == "status" for event in self._events
        ):
            self._status_monitors = self._routine_monitors(initial)
        if self.cancelled():
            raise Cancelled("Active workflow cancelled before start")
        modern = initial.test.family in ("p5", "routine")
        queue = (
            self._p5_queue(initial, entered)
            if modern
            else self._legacy_queue(initial, entered)
        )
        self._active_init = initial
        self._queue = queue
        try:
            for position, event in enumerate(self._events):
                self._event_position = position
                self._tick = event["tick"]
                action = event["action"]
                if action != "stop" and self.cancelled():
                    raise Cancelled("Active workflow cancelled")
                if action == "start":
                    self._phase_state = "running"
                    if isinstance(queue, P5ActiveQueue):
                        reply = self.session.start_p5_active(queue, self._tick)
                    else:
                        self._legacy = queue
                        reply = self._legacy_step()
                    replies = [] if reply is None else [reply]
                elif action == "step":
                    reply = (
                        self.session.p5_active_step(self._tick)
                        if modern
                        else self._legacy_step()
                    )
                    replies = [] if reply is None else [reply]
                elif action == "status":
                    replies = self._status(initial)
                else:
                    replies = self._stop()
                self._observations.append(
                    {
                        "action": action,
                        "tick": self._tick,
                        "replies_hex": [reply.hex() for reply in replies],
                        "state": self._phase_state,
                    }
                )
            self.replay.assert_complete()
            self._driver_replay.assert_complete()
            self._event_position = len(self._events)
            return self.report()
        except BaseException as original:
            self._phase_state = "failed"
            try:
                if self._legacy is not None or self.session.active is not None:
                    self._tick = self._events[-1]["tick"]
                    self._stop(shutdown=True)
                    self._phase_state = "failed-cleaned-up"
            except BaseException as cleanup:  # noqa: BLE001 -- preserve operation and cleanup failures
                raise BaseExceptionGroup(
                    "Active workflow and recorded cleanup failed", [original, cleanup]
                ) from None
            raise

    def _routine_monitors(
        self, initial: ActiveTestInitialization
    ) -> tuple[RoutineMonitor, ...]:
        self._frame(0xD7)  # Retain selected-template provenance in the report.
        return selected_routine_monitors(self.profile, initial.test.signal_id)

    def _status(self, initial: ActiveTestInitialization) -> list[bytes]:
        if initial.test.routine:
            replies = []
            states = []
            for monitor in self._status_monitors:
                reply = self._probe(monitor.request)
                normal = monitor.check_status(
                    reply, routine_info=bool(self.routine_info)
                )
                abnormal = monitor.check_status(
                    reply, routine_info=bool(self.routine_info), abnormal=True
                )
                stop = RoutineMonitor(
                    monitor.request, monitor.size, monitor.stop, (), ()
                ).check_status(reply, routine_info=bool(self.routine_info))
                states.append(
                    {
                        "rid": monitor.rid,
                        "normal": normal,
                        "abnormal": abnormal,
                        "stop_pattern": stop,
                        "size": monitor.size,
                        "routine_info": self.routine_info,
                    }
                )
                replies.append(reply)
            self._observations.append({"routine_status": states})
            self._phase_state = (
                "abnormal_pattern_matched"
                if any(state["abnormal"] for state in states)
                else "normal_pattern_matched"
                if all(state["normal"] for state in states)
                else "routine_status_unmatched"
            )
            return replies
        if not initial.current_value_supported:
            raise ValueError("Current active-test signal was not observed as available")
        modern = initial.test.family == "p5"
        row = next(
            (
                row
                for row in self.profile.records(62 if modern else 10)
                if word(row, 36 if modern else 56) == initial.current_value_pid
            ),
            None,
        )
        if row is None:
            raise ValueError("Selected active current-value record is absent")
        reader = self.catalog.initial_value_reader(
            self.session, positions=self.positions
        )
        value = reader(
            "p5-monitor" if modern else "p4" if self.init_family == "p4" else "p3", row
        )
        self._observations.append(
            {"current_value": value, "pid": initial.current_value_pid}
        )
        return []

    def close(self) -> None:
        self._closing.set()
        with self._lock:
            if not self._closed:
                if self._legacy is not None or self.session.active is not None:
                    self._tick = self._events[-1]["tick"]
                    self._stop(shutdown=True)
                self._closed = True

    @_serialized
    def report(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "source": self.replay.source,
            "physical_status": "PHYSICAL_UNCONFIRMED",
            "profile": self.profile.report(),
            "ecu": self.ecu,
            "family": self.family,
            "protocol": self.protocol,
            "driver": self.driver,
            "driver_selectors": [
                word(self.protocol_record, 6),
                word(self.protocol_record, 8),
            ],
            "state": self._phase_state,
            "semantic_status": "native-lifecycle-observed",
            "remaining_exchanges": self.replay.remaining,
            "remaining_driver_events": len(self._driver_replay.events)
            - self._driver_replay.position,
            "selected_templates": {
                f"{function:04x}": provenance
                for function, provenance in self._selected_templates.items()
            },
            "initialization": None
            if self._active_init is None
            else self._initial_report(self._active_init),
            "events": copy.deepcopy(self._observations),
            "driver_events": copy.deepcopy(self._driver_replay.observed),
            "session": self.session.report(),
            "native_queue": None
            if self._queue is None
            else [
                {
                    "request_hex": item.request.hex(),
                    "state": item.state,
                    "next_tick": item.next_tick,
                    "repeat_ms": item.repeat_ms,
                }
                for item in self._queue.items
            ],
        }

    @_serialized
    def write_report(self, destination: str | Path) -> None:
        # Exclusive creation also rejects source symlinks/hardlinks and devices.
        payload = json.dumps(self.report(), indent=2, ensure_ascii=False) + "\n"
        with Path(destination).open("x", encoding="utf-8") as stream:
            stream.write(payload)


def create_active_examples() -> dict[str, bytes]:
    """Authored demo resources and exact native workflows; no OEM artifacts.

    Returns relative paths and bytes, leaving overwrite/destination policy to
    the UI. All resources originate from the production synthetic demo builder.
    """
    with tempfile.TemporaryDirectory(prefix="techstream-active-example-") as temporary:
        root = create_demo(Path(temporary) / "resources")
        database_root = root / "Techstream_DB_NA"
        management = parse_database((database_root / "Toyota.ddb").read_bytes())
        ecu = parse_database((database_root / "DemoEngine.ddb").read_bytes())
        sections = {
            slot: (section.count, section.payload)
            for slot, section in management.sections.items()
        }
        variables = VariableTable(
            management.sections[0].payload, management.sections[0].count
        )
        payloads = [
            variables.get(index) for index in range(1, management.sections[0].count + 1)
        ]
        functions: list[bytes] = list(management.sections[18].rows(16))
        communications: list[bytes] = list(management.sections[17].rows(8))
        for index, (function, request) in enumerate(
            (
                (0x9D, b"\x2f\0\0\x03"),
                (0x64, b"\x2f\0\0\0"),
                (0xD5, b"\x31\x01\0\0"),
                (0xD6, b"\x31\x02\0\0"),
                (0xD7, b"\x31\x03\0\0"),
                (0xCA, b"\x22\0\0"),
                (0xEB, b"\x27\x01"),
                (0xEC, b"\x27\x02\0\0"),
            ),
            10,
        ):
            payloads.append(request)
            communications.append(struct.pack("<4H", index, len(payloads), 0, 0))
            functions.append(struct.pack("<8H", 1, function, 1, index, 0, 1, 0, 0))
        payloads.extend((b"\xa0", b"\x0f", b"\x01"))
        command_ref, output_ref, complete_ref = range(
            len(payloads) - 2, len(payloads) + 1
        )
        directory, storage = bytearray(), bytearray()
        for payload in payloads:
            directory.extend(struct.pack("<IH", len(storage), len(payload)))
            storage.extend(payload)
        sections[0] = (len(payloads), bytes(directory + storage))
        communications.sort(key=lambda row: word(row, 0))
        functions.sort(key=lambda row: (word(row, 0), word(row, 2), word(row, 10)))
        sections[17] = (
            len(communications),
            b"".join(communications),
        )
        sections[18] = (
            len(functions),
            b"".join(functions),
        )
        protocol = bytearray(28)
        struct.pack_into("<H", protocol, 0, 1)
        struct.pack_into("<HH", protocol, 6, 0x1234, 0x5678)
        protocol[24] = 1
        sections[13] = (1, bytes(protocol))
        management_bytes = _ddb(1, sections)
        selected = {
            slot: (section.count, section.payload)
            for slot, section in ecu.sections.items()
        }
        legacy = bytearray(92)
        legacy[:14] = b"Authored fan\0\0"
        struct.pack_into("<III", legacy, 20, 0, 255, 0)
        struct.pack_into("<I", legacy, 32, 18)
        struct.pack_into("<H", legacy, 56, 1)
        struct.pack_into("<HH", legacy, 62, 1, 1)
        struct.pack_into("<H", legacy, 74, 2)
        legacy[82], legacy[83] = 0x12, 1
        pattern = bytearray(24)
        struct.pack_into("<H", pattern, 0, 1)
        struct.pack_into("<H", pattern, 10, 1)
        struct.pack_into("<H", pattern, 2, 100)
        pattern[20] = 1
        active = bytearray(64)
        struct.pack_into("<III", active, 0, 0, 255, 0)
        struct.pack_into("<I", active, 12, 19)
        for offset, value in (
            (32, 2),
            (36, 1),
            (38, 1),
            (42, 7),
            (44, 1),
            (52, 0x1234),
        ):
            struct.pack_into("<H", active, offset, value)
        active[56], active[57], active[61] = 1, 1, 1
        data_id = bytearray(12)
        struct.pack_into("<HHHH", data_id, 2, 0x1234, 1, 0, 1)
        data_id[10] = 3
        routine = bytearray(64)
        struct.pack_into("<II", routine, 0, 255, 0)
        struct.pack_into("<I", routine, 8, 20)
        for offset, value in (
            (28, 0x4321),
            (30, 3),
            (34, 1),
            (36, 1),
            (40, command_ref),
            (42, output_ref),
            (46, 1),
            (54, 2),
            (56, 2),
        ):
            struct.pack_into("<H", routine, offset, value)
        routine[60] = 1
        status = struct.pack("<6H", 1, complete_ref, 1, 0, 0, 0)
        button = bytearray(20)
        struct.pack_into("<IHHHH", button, 0, 20, 2, 1, 0, complete_ref)
        selected.update(
            {
                11: (1, bytes(legacy)),
                12: (1, bytes(pattern)),
                33: (0, b""),
                62: (0, b""),
                67: (1, bytes(data_id)),
                68: (1, bytes(active)),
                71: (1, bytes(routine)),
                72: (1, status),
                73: (1, bytes(button)),
            }
        )
        ecu_bytes = _ddb(2, selected)
        base_catalog = VehicleCatalog(database_root)
        original_strings = [
            base_catalog.language.resolve(index) for index in range(1, 18)
        ]
        language_bytes = _language(
            original_strings
            + ["Authored legacy fan", "Authored P5 fan", "Authored routine"]
        )
        for region in ("NA", "EU", "JP"):
            folder = root / f"Techstream_DB_{region}"
            (folder / "Toyota.ddb").write_bytes(management_bytes)
            (folder / "DemoEngine.ddb").write_bytes(ecu_bytes)
            (folder / "M_English.ddb").write_bytes(language_bytes)
        profile = VehicleCatalog(database_root).build_profile(1)
        files = {
            str(path.relative_to(root)): path.read_bytes()
            for path in root.rglob("*")
            if path.is_file()
        }
        for family, signal, requests in (
            ("p3", 1, (("301205", "7000"), ("30", "70"))),
            ("p4", 1, (("301205", "7000"), ("30", "70"))),
            ("old_body", 1, (("301205", "7000"), ("30", "70"))),
            ("dk", 1, (("3d12", "7d"),)),
            ("sa", 1, (("2701", "67010000"), ("301205", "7000"), ("30", "70"))),
            ("psa", 1, (("301200", "701201"), ("301211", "701211"))),
            ("p5", 2, (("2f12340305", "6f1234"), ("2f123400", "6f1234"))),
            (
                "routine",
                3,
                (
                    ("31034321", "7103432101"),
                    ("31014321a5", "7101"),
                    ("31034321", "7103432101"),
                    ("31024321", "7102"),
                ),
            ),
        ):
            context = {
                "ecu": "authored-ecu",
                "family": family,
                "init_family": "p3" if family in ("old_body", "sa", "psa") else family,
                "protocol": 21
                if family in ("p5", "routine")
                else 7
                if family == "dk"
                else 0,
                "bus_id": 1,
                "version": profile.database.version,
                "category": 1,
                "management_sha256": profile.catalog.management.sha256,
                "ecu_sha256": profile.database.sha256,
                "pid_lengths": {},
                "did_lengths": {"1234": 1},
                "enabled_dids": [0x1234],
                "enabled_rids": [0x4321],
                "bit_ranges": [],
                "pid_support": [],
                "positions": {},
                "driver": "p5"
                if family in ("p5", "routine")
                else "dk_iso9141"
                if family == "dk"
                else "psa"
                if family == "psa"
                else "j2534",
            }
            document = {
                "schema": SCHEMA,
                "context": context,
                "native": {
                    "schema": "techstream-native-exchange-v1",
                    "source": "authored_synthetic",
                    "ecus": ["authored-ecu"],
                    "support": {},
                    "transactions": [
                        {"ecu": "authored-ecu", "request": request, "response": reply}
                        for request, reply in requests
                    ],
                },
                "events": [
                    {"action": "start", "tick": 100},
                    {"action": "stop", "tick": 200, "initialize": False},
                ],
            }
            if family == "routine":
                document["context"]["routine_info"] = False
                document["events"].insert(1, {"action": "status", "tick": 150})
            files[f"active-{family}.json"] = (
                json.dumps(document, indent=2) + "\n"
            ).encode()
        files["demo-manifest.json"] = (
            json.dumps(
                {
                    "format": "techstream-authored-active-demo-v1",
                    "synthetic": True,
                    "physical_status": "PHYSICAL_UNCONFIRMED",
                    "files": {
                        name: hashlib.sha256(data).hexdigest()
                        for name, data in files.items()
                        if name != "demo-manifest.json"
                    },
                },
                indent=2,
            )
            + "\n"
        ).encode()
        return files


def create_signed_active_examples() -> dict[str, bytes]:
    """Authored signed API fixtures and exact negative-value wire recordings."""
    files = create_active_examples()
    identities = {}
    for name, payload in list(files.items()):
        if not name.endswith(".ddb"):
            continue
        database = parse_database(payload)
        if database.kind != 2:
            continue
        sections = {
            slot: (section.count, section.payload)
            for slot, section in database.sections.items()
        }
        for slot, maximum, minimum in ((11, 24, 28), (68, 4, 8), (71, 0, 4)):
            count, body = sections[slot]
            row = bytearray(body)
            struct.pack_into("<I", row, maximum, 5)
            struct.pack_into("<I", row, minimum, 0xFFFFFFFB)
            sections[slot] = (count, bytes(row))
        updated = _ddb(2, sections)
        identities[database.sha256] = hashlib.sha256(updated).hexdigest()
        files[name] = updated
    for name, payload in list(files.items()):
        if not name.startswith("active-") or not name.endswith(".json"):
            continue
        document = json.loads(payload)
        document["context"]["ecu_sha256"] = identities[
            document["context"]["ecu_sha256"]
        ]
        files[name] = (json.dumps(document, indent=2) + "\n").encode()
    for family, position, request in (
        ("p3", 0, "3012ff"),
        ("p5", 0, "2f123403ff"),
        ("routine", 1, "31014321af"),
    ):
        document = json.loads(files[f"active-{family}.json"])
        document["native"]["transactions"][position]["request"] = request
        files[f"active-{family}-negative.json"] = (
            json.dumps(document, indent=2) + "\n"
        ).encode()
    manifest = json.loads(files["demo-manifest.json"])
    manifest["files"] = {
        name: hashlib.sha256(payload).hexdigest()
        for name, payload in files.items()
        if name != "demo-manifest.json"
    }
    files["demo-manifest.json"] = (json.dumps(manifest, indent=2) + "\n").encode()
    return files
