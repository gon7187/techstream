"""Execute imported native XML/CSDF with strict chronological offline evidence."""

from __future__ import annotations

import hashlib
import json
import math
import re
import struct
import threading
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from scripts.diagnostic_db import Language, parse_database
from scripts.local_files import read_regular
from scripts.native_replay import MAX_FILE, NativeReplay, _hex, _object
from scripts.profiles import VehicleProfile
from scripts.script_libraries import (
    CommunicationOptions,
    ExchangeResult,
    ScriptLibraries,
)
from scripts.script_vm import (
    UtilityResource,
    decode_utility_resource,
    evaluate,
    parse_object,
    parse_utility_xml,
    utility_resource_key,
)
from scripts.toyota_session import Cancelled, Limits, NativeStatus, ToyotaSession
from scripts.utility import UtilityRuntime
from scripts.utility_bindings import SupportCache, SupportRecord, UtilityBindings

SCHEMA = "techstream-native-procedure-v1"
MAX_EVENTS = 100000


def _read(path: str | Path) -> bytes:
    return read_regular(path, limit=MAX_FILE)


class _Inputs:
    """Bound each captured input before reading, retain hashes of parsed bytes."""

    def __init__(self) -> None:
        self.sources: list[dict[str, Any]] = []
        self.size = 0

    def read(self, path: str | Path) -> bytes:
        data = read_regular(path, limit=MAX_FILE - self.size)
        self.size += len(data)
        self.sources.append(
            {
                "path": str(Path(path).absolute()),
                "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        )
        return data


def _utility(data: bytes, key_data: bytes | None) -> UtilityResource:
    if data[4:6] == b"\xff\xfe":
        return parse_utility_xml(data)
    if key_data is None:
        raise ValueError("Encrypted utility requires an explicit verified key library")
    return decode_utility_resource(data, utility_resource_key(key_data))


def open_utility(path: str | Path, key_library: Path | None = None) -> UtilityResource:
    """Read a native four-byte/UTF16 envelope, or decrypt with a verified library."""
    inputs = _Inputs()
    data = inputs.read(path)
    return _utility(data, inputs.read(key_library) if key_library is not None else None)


def _uint(value: Any, maximum: int = 0xFFFFFFFF) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError("Expected bounded native unsigned integer")
    return value


def _decimal_map(value: Any) -> dict[int, int]:
    if not isinstance(value, dict) or len(value) > 65536:
        raise ValueError("Native context must be a decimal-keyed map")
    result = {}
    for key, number in value.items():
        if not isinstance(key, str) or re.fullmatch("0|[1-9][0-9]{0,9}", key) is None:
            raise ValueError("Native context keys must use canonical decimal spelling")
        result[_uint(int(key))] = _uint(number)
    return result


def _support(value: Any) -> SupportCache | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {"selected", "records"}:
        raise ValueError("Invalid explicit support cache")
    selected = value["selected"]
    rows = value["records"]
    if (
        not isinstance(selected, list)
        or len(selected) != 3
        or not isinstance(rows, list)
        or len(rows) > 65536
    ):
        raise ValueError("Invalid support cache dimensions")
    records = {}
    for row in rows:
        if not isinstance(row, dict) or set(row) != {
            "key",
            "offsets",
            "support",
            "received",
        }:
            raise ValueError("Invalid support cache record")
        key = row["key"]
        if not isinstance(key, list) or len(key) != 4 or tuple(key) in records:
            raise ValueError("Invalid/duplicate support cache key")
        records[tuple(_uint(x) for x in key)] = SupportRecord(
            tuple(row["offsets"]), _hex(row["support"]), _hex(row["received"])
        )
    return SupportCache(
        records, selected=(_uint(selected[0]), _uint(selected[1]), _uint(selected[2]))
    )


class ProcedureRecording:
    """NativeReplay validates bytes; this index enforces driver/PDU chronology."""

    def __init__(
        self,
        path: str | Path,
        cancelled: Callable[[], bool],
        *,
        raw: bytes | None = None,
    ):
        if raw is None:
            raw = _read(path)
        if type(raw) is not bytes or len(raw) > MAX_FILE:
            raise ValueError("Procedure recording bytes exceed input limit/type")
        try:
            doc = json.loads(raw, object_pairs_hook=_object)
        except (ValueError, UnicodeError, RecursionError) as error:
            raise ValueError("Invalid procedure recording JSON") from error
        if (
            not isinstance(doc, dict)
            or set(doc) != {"schema", "source", "ecu", "context", "events"}
            or doc["schema"] != SCHEMA
        ):
            raise ValueError("Unexpected procedure recording schema/fields")
        if doc["source"] not in ("authored_synthetic", "recorded_unverified"):
            raise ValueError("Procedure recording provenance is required")
        context = doc["context"]
        if not isinstance(context, dict) or set(context) != {
            "broker",
            "script_ecu_id",
            "support",
            "initial_variables",
            "did_ranges",
            "language",
            "limits",
        }:
            raise ValueError("Explicit complete procedure context required")
        limits = context["limits"]
        if not isinstance(limits, dict) or set(limits) != {
            "seconds",
            "steps",
            "exchanges",
        }:
            raise ValueError("Explicit procedure limits required")
        seconds = limits["seconds"]
        if (
            type(seconds) not in (int, float)
            or not math.isfinite(seconds)
            or not 0 < seconds <= 3600
        ):
            raise ValueError("Invalid procedure deadline")
        if not 1 <= _uint(limits["steps"], 1000000) or not 1 <= _uint(
            limits["exchanges"], MAX_EVENTS
        ):
            raise ValueError("Invalid procedure execution bounds")
        self._cleanup_thread: int | None = None
        self._cleanup_deadline = 0.0
        self.deadline = time.monotonic() + seconds
        self.cancelled, self.context, self.ecu, self.source = (
            cancelled,
            context,
            doc["ecu"],
            doc["source"],
        )
        self.broker = (
            _decimal_map(context["broker"]) if context["broker"] is not None else None
        )
        self.support = _support(context["support"])
        self.events, self.position = doc["events"], 0
        if not isinstance(self.events, list) or len(self.events) > MAX_EVENTS:
            raise ValueError("Invalid procedure event count")
        pdus = []
        for event in self.events:
            if not isinstance(event, dict):
                raise TypeError("Invalid procedure event")
            if event.get("kind") == "pdu" and set(event) == {
                "kind",
                "transaction",
                "options",
            }:
                pdus.append(event["transaction"])
                options = event["options"]
                if options is not None:
                    if not isinstance(options, dict) or set(options) != {
                        "retry_count",
                        "address_type",
                        "plural",
                        "sequence_code",
                        "response_count",
                    }:
                        raise ValueError(
                            "Explicit ScriptLib communication options required"
                        )
                    _uint(options["retry_count"], 255)
                    _uint(options["sequence_code"], 65535)
                    _uint(options["response_count"], 256)
                    if (
                        type(options["address_type"]) is not bool
                        or type(options["plural"]) is not bool
                    ):
                        raise ValueError("ScriptLib options require exact booleans")
            elif event.get("kind") == "driver" and set(event) == {
                "kind",
                "operation",
                "arguments",
                "result",
            }:
                self._validate_driver(event)
            else:
                raise ValueError("Unsupported procedure event fields/kind")
        # Zero-PDU programs consume no synthetic transaction. NativeReplay
        # validates every actual transaction before execution.
        if len(pdus) > limits["exchanges"]:
            raise ValueError("Recorded PDUs exceed total procedure exchange bound")
        self.replay = (
            NativeReplay(
                {
                    "schema": "techstream-native-exchange-v1",
                    "source": self.source,
                    "ecus": [self.ecu],
                    "support": {},
                    "transactions": pdus,
                },
                lambda: (
                    self.cancelled() and threading.get_ident() != self._cleanup_thread
                ),
            )
            if pdus
            else None
        )
        if self.replay is None and (
            not isinstance(self.ecu, str)
            or re.fullmatch("[A-Za-z0-9_.:-]{1,64}", self.ecu) is None
        ):
            raise ValueError("Invalid explicit native ECU label")
        self.trace: list[dict] = []
        self._trace_bytes = 0
        self._lock = threading.RLock()

    @staticmethod
    def _validate_driver(event: dict) -> None:
        operation, arguments, result = (
            event["operation"],
            event["arguments"],
            event["result"],
        )
        if not isinstance(arguments, list):
            raise TypeError("Driver arguments must be an array")
        if operation == "initialize":
            if len(arguments) != 2 or type(arguments[1]) is not bool:
                raise ValueError(
                    "Initialize requires broker snapshot and refresh boolean"
                )
            _decimal_map(arguments[0])
            _uint(result)
        elif operation == "finalize":
            if arguments:
                raise ValueError("Finalize has no arguments")
            _uint(result)
        elif operation == "configure":
            if (
                len(arguments) != 2
                or not isinstance(arguments[0], str)
                or not arguments[0]
            ):
                raise ValueError("Configure requires name and uint32")
            _uint(arguments[1])
            if result is not None:
                raise ValueError("Configure returns no value")
        elif operation in ("keepalive", "abort"):
            if (
                (
                    operation == "keepalive"
                    and (len(arguments) != 1 or type(arguments[0]) is not bool)
                )
                or (operation == "abort" and arguments)
                or result is not None
            ):
                raise ValueError("Invalid driver boolean/no-value event")
        else:
            raise ValueError("Unknown driver operation")

    def check(self) -> None:
        if threading.get_ident() == self._cleanup_thread:
            if time.monotonic() >= self._cleanup_deadline:
                raise TimeoutError("Native procedure cleanup deadline exceeded")
            return
        if self.cancelled():
            raise InterruptedError("Native procedure cancelled")
        if time.monotonic() >= self.deadline:
            raise TimeoutError("Native procedure deadline exceeded")

    def surface(self, event: dict) -> None:
        with self._lock:
            size = len(json.dumps(event, separators=(",", ":")).encode())
            if len(self.trace) >= MAX_EVENTS or self._trace_bytes + size > MAX_FILE:
                raise ValueError("Procedure output event budget exceeded")
            self.trace.append(event)
            self._trace_bytes += size

    def next_event(self) -> dict:
        self.check()
        if self.position >= len(self.events):
            raise ValueError("Procedure recording exhausted")
        return self.events[self.position]

    def driver(self, operation: str, arguments: list) -> Any:
        with self._lock:
            if operation == "abort":
                if self.position >= len(self.events):
                    raise ValueError("Procedure cleanup recording exhausted")
                event = self.events[self.position]
            else:
                event = self.next_event()
            if (
                event["kind"] != "driver"
                or event["operation"] != operation
                or event["arguments"] != arguments
            ):
                raise ValueError(
                    f"Driver recording mismatch at event {self.position}: {operation}"
                )
            self.position += 1
            self.surface(event)
            return event["result"]

    def exchange(self, ecu: str, request: bytes) -> bytes:
        with self._lock:
            event = self.next_event()
            if event["kind"] != "pdu" or event["options"] is not None:
                raise ValueError(f"PDU recording mismatch at event {self.position}")
            return self._pdu(ecu, request, event)

    def _pdu(self, ecu: str, request: bytes, event: dict) -> bytes:
        if self.replay is None:
            raise ValueError("No recorded native PDU exchange")
        try:
            reply = self.replay.exchange(ecu, request)
        except NativeStatus:
            self.position += 1
            self.surface(event)
            raise
        self.position += 1
        self.surface(event)
        self.check()
        return reply

    def native_exchange(
        self, ecu: str, request: bytes, options: CommunicationOptions
    ) -> ExchangeResult:
        with self._lock:
            event = self.next_event()
            captured = event.get("options")
            if (
                event["kind"] != "pdu"
                or captured is None
                or (
                    captured["retry_count"],
                    captured["address_type"],
                    captured["plural"],
                )
                != (options.retry_count, options.address_type, options.plural)
            ):
                raise ValueError(f"ScriptLib options mismatch at event {self.position}")
            count = captured["response_count"]
            if not options.plural and count > 1:
                raise ValueError("Single receive cannot consume plural responses")
            first = self._pdu(ecu, request, event)
            replies = [first] if count else []
            for _ in range(max(0, count - 1)):
                replies.append(self.exchange(ecu, b""))
            return ExchangeResult(captured["sequence_code"], tuple(replies))

    def complete(self) -> None:
        self.check()
        if self.position != len(self.events):
            raise ValueError(
                f"Procedure has {len(self.events) - self.position} unconsumed events"
            )
        if self.replay is not None:
            self.replay.assert_complete()


def _records(
    files: Mapping[bytes, Path] | None,
    inputs: _Inputs,
) -> tuple[Callable[[bytes], bytes], list[str]]:
    loaded, paths, retained = {}, [], 0
    for name, path in (files or {}).items():
        if not isinstance(name, bytes) or not name or b"\0" in name or len(name) > 255:
            raise ValueError("Record attachments require bounded logical byte names")
        data = inputs.read(path)
        retained += len(data)
        if retained > MAX_FILE:
            raise ValueError("Record attachment aggregate budget exceeded")
        loaded[name] = data
        paths.append(str(Path(path).resolve()))

    def read(name: bytes) -> bytes:
        if name not in loaded:
            raise FileNotFoundError("Explicit record attachment unavailable")
        return loaded[name]

    return read, paths


def _report(
    profile: VehicleProfile,
    resource: str | Path,
    recording: str | Path,
    state: ProcedureRecording,
    inputs: _Inputs,
) -> dict:
    return {
        "status": "running",
        "source": state.source,
        "physical_status": "PHYSICAL_UNCONFIRMED",
        "source_paths": [
            *(source["path"] for source in inputs.sources),
            str(profile.catalog.root / "Toyota.ddb"),
            str(profile.catalog.root / "M_English.ddb"),
            str(profile.catalog.root / profile.filename),
        ],
        "profile": profile.report(),
        "events": [],
        "remaining_events": len(state.events),
        "input_sources": inputs.sources,
        "profile_sources": [
            {"path": str(profile.catalog.root / name), "sha256": digest}
            for name, digest in (
                ("Toyota.ddb", profile.catalog.management.sha256),
                ("M_English.ddb", profile.catalog.language.sha256),
                (profile.filename, profile.database.sha256),
            )
        ],
        "resource_sha256": inputs.sources[0]["sha256"],
    }


def _error_detail(error: BaseException) -> dict[str, Any]:
    remaining = 100

    def visit(current: BaseException, depth: int) -> dict[str, Any]:
        nonlocal remaining
        remaining -= 1
        detail: dict[str, Any] = {
            "type": type(current).__name__,
            "message": str(current),
        }
        if isinstance(current, NativeStatus):
            detail.update(
                native_status=current.code, partial_response=current.reply.hex()
            )
        if isinstance(current, BaseExceptionGroup):
            children = []
            if depth < 8:
                for child in current.exceptions:
                    if remaining == 0:
                        break
                    children.append(visit(child, depth + 1))
            detail["exceptions"] = children
            if len(children) < len(current.exceptions):
                detail["omitted_exceptions"] = len(current.exceptions) - len(children)
        return detail

    return visit(error, 0)


def _failure(report: dict, error: BaseException) -> None:
    report["status"] = (
        "cancelled"
        if isinstance(error, (InterruptedError, Cancelled, KeyboardInterrupt))
        else "failed"
    )
    report["error"] = _error_detail(error)


def read_utility_symbols(path: Path) -> dict[str, tuple[int, int]]:
    """Read UtilityResID_NK.rsd's native group/resource/name records.

    IT3UtilityTY2 RVA3EFD0 reads two u32 values, a u16 byte length and UTF16
    name. These are symbolic IDs, not direct indexes into any language DDB.
    """
    data, position, result = _read(path), 0, {}
    while position < len(data):
        if len(result) >= MAX_EVENTS or len(data) - position < 10:
            raise ValueError("Invalid native utility symbol count/header")
        group, identifier, size = struct.unpack_from("<IIH", data, position)
        position += 10
        if not size or size % 2 or size > len(data) - position:
            raise ValueError("Invalid native utility symbol name length")
        name = data[position : position + size].decode("utf-16le")
        position += size
        if re.fullmatch("IDS_[A-Za-z0-9_]{1,128}", name) is None or name in result:
            raise ValueError("Invalid or duplicate native utility symbol")
        result[name] = (group, identifier)
    if not result:
        raise ValueError("Native utility symbol catalogue is empty")
    return result


def load_translations(path: Path) -> dict[str, Any]:
    """Load original U-language DDB mappings or an explicit supplied catalogue."""
    return _translations(_read(path))


def _translations(data: bytes) -> dict[str, Any]:
    if data[10:28] == b"DiagTool DataCtrl\0":
        database = parse_database(data)
        if database.kind != 6 or not {0, 1} <= database.sections.keys():
            raise ValueError("Utility translations require original U-language DDB")
        if any(database.sections[slot].count > MAX_EVENTS for slot in (0, 1)):
            raise ValueError("Native utility translation table exceeds entry limit")
        if (
            sum(len(section.payload) for section in database.sections.values())
            > MAX_FILE
        ):
            raise ValueError("Native utility decoded translation budget exceeded")
        language = Language(database)
        values: dict[str, str] = {}
        for row in database.sections[1].rows(164):
            fields = []
            for encoded in (row[:80], row[80:160]):
                text = encoded.decode("utf-16le")
                head, separator, tail = text.partition("\0")
                if separator and tail.strip("\0"):
                    raise ValueError("Invalid native utility translation key padding")
                fields.append(head)
            key = fields[0]
            if re.fullmatch("IDS_[A-Za-z0-9_]{1,128}", key) is None:
                raise ValueError("Invalid native utility translation symbol")
            # Native K1 returns GetDispStringName(0): the first matching row.
            values.setdefault(
                key, language.resolve(struct.unpack_from("<I", row, 160)[0])
            )
        return {
            "schema": "native-utility-language-ddb",
            "source": "recorded_unverified",
            "locale": None,
            "translations": values,
        }
    try:
        doc = json.loads(data, object_pairs_hook=_object)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise ValueError("Invalid utility translation catalogue") from error
    if (
        not isinstance(doc, dict)
        or set(doc) != {"schema", "source", "locale", "translations"}
        or doc["schema"] != "techstream-utility-translations-v1"
        or doc["source"] not in ("authored_synthetic", "recorded_unverified")
    ):
        raise ValueError("Unsupported utility translation catalogue schema")
    if (
        not isinstance(doc["locale"], str)
        or re.fullmatch("[A-Za-z0-9_-]{1,32}", doc["locale"]) is None
    ):
        raise ValueError("Translation catalogue requires explicit locale")
    values = doc["translations"]
    if not isinstance(values, dict) or len(values) > MAX_EVENTS:
        raise ValueError("Invalid translation entry count")
    for key, value in values.items():
        if (
            not isinstance(key, str)
            or re.fullmatch("IDS_[A-Za-z0-9_]{1,128}", key) is None
            or not isinstance(value, str)
            or not value
            or len(value.encode("utf-8")) > 65535
            or "\0" in value
        ):
            raise ValueError("Invalid symbolic translation entry")
    return doc


def _presentation(
    resource: UtilityResource, policy: Any, external: Mapping[str, str] | None = None
) -> tuple[Callable[[Any], Any], set[str]]:
    if (
        not isinstance(policy, dict)
        or set(policy) != {"locale", "missing"}
        or policy["missing"] not in ("preserve", "error")
    ):
        raise ValueError("Explicit locale/missing-token policy required")
    locale = policy["locale"]
    if locale is not None and (
        not isinstance(locale, str)
        or re.fullmatch("[A-Za-z0-9_-]{1,32}", locale) is None
    ):
        raise ValueError("Invalid resource language selector")
    language = resource.root.find("LANGUAGE")
    selected = (
        language.find(locale) if language is not None and locale is not None else None
    )
    if locale is not None and selected is None:
        raise ValueError("Selected language is absent from utility resource")
    translations = {}
    if selected is not None:
        for node in selected:
            if node.tag in translations:
                raise ValueError("Duplicate utility language token")
            translations[node.tag] = node.text or ""
    unresolved: set[str] = set()

    def resolve(value: Any) -> Any:
        remaining, nodes = MAX_FILE, 0

        def reserve(text: str) -> None:
            nonlocal remaining
            for char in text:
                code = ord(char)
                remaining -= 1 + (code > 127) + (code > 2047) + (code > 65535)
                if remaining < 0:
                    raise ValueError("Resolved utility presentation budget exceeded")

        def visit(item: Any) -> Any:
            nonlocal nodes
            nodes += 1
            if nodes > MAX_EVENTS:
                raise ValueError("Resolved utility presentation entry limit exceeded")
            if isinstance(item, str):
                parts, position = [], 0
                for match in re.finditer(r"\{(LANG[A-Za-z0-9_]+)\}", item):
                    nodes += 1
                    if nodes > MAX_EVENTS:
                        raise ValueError(
                            "Resolved utility presentation entry limit exceeded"
                        )
                    literal = item[position : match.start()]
                    reserve(literal)
                    parts.append(literal)
                    text = substitute(match)
                    reserve(text)
                    parts.append(text)
                    position = match.end()
                tail = item[position:]
                reserve(tail)
                parts.append(tail)
                return "".join(parts)
            if isinstance(item, list):
                return [visit(child) for child in item]
            if isinstance(item, dict):
                result = {}
                for key, child in item.items():
                    if isinstance(key, str):
                        reserve(key)
                    result[key] = visit(child)
                return result
            return item

        def substitute(match: re.Match) -> str:
            token = match.group(1)
            if token not in translations:
                if policy["missing"] == "error":
                    raise ValueError(f"Missing resource language token: {token}")
                unresolved.add(token)
                return match.group(0)
            text = translations[token]
            if text.startswith("IDS_"):
                translated = (external or {}).get(text)
                if translated is None:
                    unresolved.add(text)
                else:
                    text = translated
            return text

        return visit(value)

    return resolve, unresolved


def _finish(report: dict, state: ProcedureRecording) -> None:
    state.complete()
    faults = [
        event
        for event in state.trace
        if (
            event["kind"] == "driver"
            and event["operation"] in ("initialize", "finalize")
            and event["result"] != 0
        )
        or (
            event["kind"] == "pdu"
            and event["options"] is not None
            and event["options"]["sequence_code"] != 0
        )
    ]
    report["status"] = "partial" if faults else "completed"
    report["observed_native_failures"] = faults


def replay_utility(
    profile: VehicleProfile,
    resource_path: str | Path,
    recording_path: str | Path,
    *,
    function_id: str,
    dialog: Callable[[dict], str | dict],
    cancelled: Callable[[], bool],
    key_library: Path | None = None,
    record_files: Mapping[bytes, Path] | None = None,
    translation_file: Path | None = None,
) -> dict:
    inputs = _Inputs()
    resource_data = inputs.read(resource_path)
    resource = _utility(
        resource_data, inputs.read(key_library) if key_library is not None else None
    )
    state = ProcedureRecording(
        recording_path, cancelled, raw=inputs.read(recording_path)
    )
    _records(record_files, inputs)
    catalogue = (
        _translations(inputs.read(translation_file))
        if translation_file is not None
        else None
    )
    report = _report(profile, resource_path, recording_path, state, inputs)
    if catalogue is not None and translation_file is not None:
        report["translation_catalogue"] = {
            "locale": catalogue["locale"],
            "source": catalogue["source"],
            "path": str(Path(translation_file).resolve()),
        }
    resolve, unresolved = _presentation(
        resource,
        state.context["language"],
        catalogue["translations"] if catalogue is not None else None,
    )

    def present(screen: dict) -> str | dict:
        state.check()
        shown = resolve(screen)
        state.check()
        shown["deadline_monotonic"] = state.deadline
        shown["remaining_ms"] = max(0, int((state.deadline - time.monotonic()) * 1000))
        selection = dialog(shown)
        state.check()
        state.surface(
            {
                "kind": "dialog",
                "block": screen.get("block"),
                "block_instance": screen.get("block_instance"),
                "event_type": "key"
                if isinstance(selection, str)
                else next(iter(selection), "invalid")
                if isinstance(selection, dict)
                else "invalid",
            }
        )
        return selection

    session = ToyotaSession(
        state.exchange,
        state.ecu,
        {},
        limits=Limits(
            seconds=state.context["limits"]["seconds"],
            exchanges=state.context["limits"]["exchanges"],
        ),
        cancelled=cancelled,
    )
    if state.broker is None:
        raise ValueError("XML utility requires explicit broker context")
    bindings = UtilityBindings.from_profile(
        profile,
        session,
        broker=state.broker,
        support=state.support,
        initialize=lambda broker, refresh: state.driver(
            "initialize", [{str(k): v for k, v in broker.items()}, refresh]
        ),
        finalize=lambda: state.driver("finalize", []),
        configure=lambda name, value: state.driver("configure", [name, value]),
        keepalive=lambda value: state.driver("keepalive", [value]),
        abort=lambda: state.driver("abort", []),
    )
    runtime = UtilityRuntime(
        resource,
        exchange=state.exchange,
        receive=lambda ecu: state.exchange(ecu, b""),
        library=bindings,
        dialog=present,
        ecu=state.ecu,
        cancelled=cancelled,
        max_steps=state.context["limits"]["steps"],
        timeout=state.context["limits"]["seconds"],
    )
    try:
        report["result"] = runtime.run(function_id)
    except (Exception, KeyboardInterrupt, BaseExceptionGroup) as error:  # noqa: BLE001 -- public execution boundary returns provider failures as JSON.
        _failure(report, error)
        report["result"] = runtime.report()
    finally:
        worker = bindings._worker
        if worker is not None and worker.is_alive():
            state._cleanup_thread = worker.ident
            state._cleanup_deadline = time.monotonic() + 5.0
            bindings._stop.set()
            try:
                state.driver("abort", [])
            except (Exception, KeyboardInterrupt, BaseExceptionGroup) as error:  # noqa: BLE001 -- retain primary failure and still join.
                report["cleanup_error"] = _error_detail(error)
                if "error" not in report:
                    _failure(report, error)
            finally:
                for _attempt in range(2):
                    try:
                        worker.join(
                            timeout=max(0, state._cleanup_deadline - time.monotonic())
                        )
                        break
                    except (Exception, KeyboardInterrupt, BaseExceptionGroup) as error:  # noqa: BLE001 -- cleanup interruption must remain visible.
                        report["join_error"] = _error_detail(error)
                        if "error" not in report:
                            _failure(report, error)
            if worker.is_alive():
                report["status"] = "failed"
                report["cleanup_error"] = "Native utility worker did not terminate"
        if worker is not None and not worker.is_alive():
            try:
                status = bindings._thread_status()
                report["thread_status"] = status
                if status and report["status"] == "running":
                    report["status"] = "partial"
            except (Exception, KeyboardInterrupt, BaseExceptionGroup) as error:  # noqa: BLE001 -- retain worker/provider failure.
                if "error" not in report:
                    _failure(report, error)
                else:
                    report["thread_error"] = _error_detail(error)
        if report["status"] in ("running", "partial"):
            try:
                previous = report["status"]
                _finish(report, state)
                if previous == "partial" and report["status"] == "completed":
                    report["status"] = "partial"
            except (Exception, KeyboardInterrupt, BaseExceptionGroup) as error:  # noqa: BLE001 -- completion must retain evidence mismatch.
                _failure(report, error)
        report["unresolved_language_tokens"] = sorted(unresolved)
        if unresolved and report["status"] == "completed":
            report["status"] = "partial"
        report["events"] = state.trace
        report["remaining_events"] = len(state.events) - state.position
    return report


def replay_script(
    profile: VehicleProfile,
    resource_path: str | Path,
    recording_path: str | Path,
    *,
    cancelled: Callable[[], bool],
    record_files: Mapping[bytes, Path] | None = None,
) -> dict:
    inputs = _Inputs()
    script = parse_object(inputs.read(resource_path))
    state = ProcedureRecording(
        recording_path, cancelled, raw=inputs.read(recording_path)
    )
    read_record, _ = _records(record_files, inputs)
    report = _report(profile, resource_path, recording_path, state, inputs)
    identifier = _uint(state.context["script_ecu_id"], 255)
    initial = state.context["initial_variables"]
    if not isinstance(initial, dict):
        raise TypeError("CSDF native initial variables must be explicit")
    variables = {}
    for key, value in initial.items():
        if (
            not isinstance(key, str)
            or re.fullmatch("[0-9]{5}", key) is None
            or not isinstance(value, dict)
            or set(value) != {"tag", "payload"}
        ):
            raise ValueError("Invalid CSDF initial variable declaration")
        identifier_key, tag = _uint(int(key), 65535), _uint(value["tag"], 5)
        if identifier_key < 0x8000 or tag == 0:
            raise ValueError("Invalid native CSDF variable ID or type")
        variables[identifier_key] = (tag, _hex(value["payload"]))
    ranges = state.context["did_ranges"]
    if ranges is not None and (
        not isinstance(ranges, list)
        or any(
            not isinstance(pair, list)
            or len(pair) != 2
            or any(type(value) is not int for value in pair)
            or not 0 <= pair[0] <= pair[1] <= 65535
            for pair in ranges
        )
    ):
        raise ValueError("Invalid explicit DID range observations")
    host = ScriptLibraries(
        state.exchange,
        ecu=state.ecu,
        ecu_id=identifier,
        native_exchange=state.native_exchange,
        read_record=read_record if record_files is not None else None,
        did_ranges=tuple(map(tuple, ranges)) if ranges is not None else None,
        cancelled=cancelled,
        deadline=state.deadline,
        post_message=lambda value: state.surface(
            {"kind": "post_message", "value": value}
        ),
        debug=lambda values: state.surface(
            {
                "kind": "debug",
                "values": [{"tag": tag, "payload": data.hex()} for tag, data in values],
            }
        ),
    )
    try:
        stack = evaluate(
            script,
            libraries=host.libraries,
            cancelled=lambda: state.check() or False,
            max_steps=state.context["limits"]["steps"],
            initial_variables=variables,
        )
        _finish(report, state)
        report["result"] = {
            "stack": [{"tag": tag, "payload": data.hex()} for tag, data in stack],
            "library_events": host.events,
            "messages": host.log_messages,
        }
    except (Exception, KeyboardInterrupt, BaseExceptionGroup) as error:  # noqa: BLE001 -- public execution boundary returns provider failures as JSON.
        _failure(report, error)
    report["events"] = state.trace
    report["remaining_events"] = len(state.events) - state.position
    return report


def create_example_files(directory: Path) -> dict[str, Path]:
    """Write four authored demonstration files; never import test fixtures."""
    directory.mkdir(parents=True, exist_ok=True)
    xml = """<UTILITY><FUNCTION><NAME>Authored offline procedure</NAME><FUNCID>demo</FUNCID>
<STORAGE><DATA DATAID="INT01"/><DATA DATAID="INT02"/><DATA DATAID="INT03"/></STORAGE>
<BLOCK ID="choose" TYPE="G002"><TITLE>{LANG001}</TITLE><AREA ID="1" TYPE="TEXT"><TEXT>{LANG002}</TEXT></AREA>
<INITACTION><CALLFUNC NAME="InitialCom" OUT="INT03">"INT01"</CALLFUNC></INITACTION>
<RADIOTYPE ID="1" OUT="INT02" DEFAULT="1"><RADIO ID="1"><TEXT>{LANG003}</TEXT></RADIO><RADIO ID="2"><TEXT>{LANG004}</TEXT></RADIO></RADIOTYPE>
<DISPACTION><IF COND="INT02 EQ 2"><KEYSTATE ID="1" MODE="ENABLE"/></IF></DISPACTION>
<KEYTYPE><KEY ID="1" MODE="DISABLED"><TEXT>{LANG005}</TEXT><ACTION MODE="COMM" NEXT="read"/></KEY></KEYTYPE>
<COMM COMMID="read"><EVENT TYPE="SEND" TIMEOUT="100"><FRAME>$01,$0D</FRAME></EVENT><EVENT TYPE="SUCCESS" MODE="BLOCK" NEXT="done"><FRAME>$41,$0D,*</FRAME></EVENT></COMM>
</BLOCK><BLOCK ID="done" TYPE="G002"><FASTACTION><CALLFUNC NAME="FinalCom" OUT="INT03">"INT01"</CALLFUNC><ACTION MODE="BLOCK" NEXT="END"/></FASTACTION></BLOCK>
</FUNCTION><LANGUAGE><XX><LANG001>Recorded procedure</LANG001><LANG002>Choose the recorded read operation.</LANG002><LANG003>Waiting</LANG003><LANG004>Read vehicle speed</LANG004><LANG005>Continue</LANG005></XX></LANGUAGE></UTILITY>"""
    broker = {"116": 2016, "171": 2024, "111": 3, "112": 17, "115": 3}
    context = {
        "broker": broker,
        "script_ecu_id": 3,
        "support": None,
        "initial_variables": {},
        "did_ranges": None,
        "language": {"locale": "XX", "missing": "error"},
        "limits": {"seconds": 30, "steps": 10000, "exchanges": 100},
    }
    document = {
        "schema": SCHEMA,
        "source": "authored_synthetic",
        "ecu": "authored-ecu",
        "context": context,
        "events": [
            {
                "kind": "driver",
                "operation": "initialize",
                "arguments": [broker, False],
                "result": 0,
            },
            {
                "kind": "pdu",
                "transaction": {
                    "ecu": "authored-ecu",
                    "request": "010d",
                    "response": "410d32",
                },
                "options": None,
            },
            {"kind": "driver", "operation": "finalize", "arguments": [], "result": 0},
        ],
    }
    # Raw CSDF object: one explicit output variable, one Send invocation.
    name = b"ScriptLibCommunication"
    steps = [
        b"\x13\x02\x01\x0d",
        b"\x15\x02\x00\x80",
        b"\x40\x03\x01\x00\x02",
        b"\x44\x00",
    ]
    program = (
        b"\x01\x00\x00\x00\x01"
        + bytes([len(name)])
        + name
        + len(steps).to_bytes(2, "little")
        + b"".join(steps)
    )
    script_context = dict(
        context,
        broker=None,
        initial_variables={"32768": {"tag": 3, "payload": ""}},
        language={"locale": None, "missing": "preserve"},
    )
    script_recording = dict(
        document,
        context=script_context,
        events=[
            {
                "kind": "pdu",
                "transaction": document["events"][1]["transaction"],
                "options": {
                    "retry_count": 2,
                    "address_type": False,
                    "plural": False,
                    "sequence_code": 0,
                    "response_count": 1,
                },
            }
        ],
    )
    content = {
        "utility": ("authored-utility.srp", b"demo\xff\xfe" + xml.encode("utf-16le")),
        "utility_recording": (
            "authored-utility.json",
            (json.dumps(document, indent=2) + "\n").encode(),
        ),
        "script": ("authored-script.bin", program),
        "script_recording": (
            "authored-script.json",
            (json.dumps(script_recording, indent=2) + "\n").encode(),
        ),
    }
    result = {}
    for key, (name, data) in content.items():
        path = directory / name
        if path.exists():
            if _read(path) != data:
                raise FileExistsError("Existing procedure example differs")
        else:
            with path.open("xb") as stream:
                stream.write(data)
        result[key] = path
    return result
