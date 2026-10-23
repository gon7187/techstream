"""Source-bound native programming replay over chronological captured host events."""

from __future__ import annotations

import hashlib
import json
import math
import re
import tempfile
from array import array
from collections.abc import Callable, Mapping, Sequence
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

from scripts.calibration import _metadata_parser, parse_cuw
from scripts.calibration_catalog import CalibrationCatalog, SelectionContext
from scripts.cuw_large import NativeLargeContainer2026, validate_large_container_2026
from scripts.native_modules import NativeModuleIdentity, identify_native_module
from scripts.programming import NativeTransportError

if TYPE_CHECKING:
    from scripts.cuw_engine_worker import _NativeGetterContinuation2026
    from scripts.j2534_2026 import J2534Device2026, J2534InterfacePair2026
    from scripts.programming_2026_common import NativeParameterBinding2026

SCHEMA = "techstream-programming-replay-v1"
MAX_BYTES = 64 * 1024 * 1024
MAX_STREAM_BYTES = 8 * 1024 * 1024 * 1024
MAX_STREAM_EVENTS = 16_777_216


def _same_trace_callable2026(actual, expected) -> bool:
    """Compare a retained callable, including fresh bound-method views."""
    if actual is expected:
        return True
    return (
        getattr(actual, "__self__", None) is not None
        and getattr(actual, "__self__", None) is getattr(expected, "__self__", None)
        and getattr(actual, "__func__", None) is getattr(expected, "__func__", None)
    )


DEVICE_ACTIONS2026 = frozenset(
    [
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
    ]
)


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate programming JSON field")
        result[key] = value
    return result


def _json(raw: bytes) -> dict:
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_BYTES:
        raise ValueError("Bounded immutable programming JSON required")
    try:
        result = json.loads(
            raw,
            object_pairs_hook=_object,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError("Nonfinite JSON")
            ),
        )
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ValueError("Malformed programming JSON") from exc
    if not isinstance(result, dict):
        raise TypeError("Programming JSON object required")
    return result


def _hex(value, maximum=65535):
    if (
        not isinstance(value, str)
        or len(value) > maximum * 2
        or len(value) % 2
        or re.fullmatch("[0-9a-fA-F]*", value) is None
    ):
        raise ValueError("Bounded strict programming hexadecimal required")
    return bytes.fromhex(value)


def _uint(value, maximum=0xFFFFFFFF):
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError("Bounded unsigned programming observation required")
    return value


def _safe_json(value, depth=0):
    if depth > 12:
        raise ValueError("Programming event nesting exceeds bound")
    if value is None or type(value) is bool:
        return
    if type(value) is int:
        _uint(value)
        return
    if type(value) is float and math.isfinite(value) and abs(value) <= 1e12:
        return
    if isinstance(value, str) and len(value) <= 131070:
        return
    if isinstance(value, list) and len(value) <= 4096:
        for item in value:
            _safe_json(item, depth + 1)
        return
    if isinstance(value, dict) and len(value) <= 64:
        for key, item in value.items():
            if not isinstance(key, str) or not 0 < len(key) <= 128:
                raise ValueError("Invalid programming event key")
            _safe_json(item, depth + 1)
        return
    raise ValueError("Invalid bounded programming event value")


def _typed_value(result, depth=0):
    """Decode bounded, explicitly tagged native control values, including bytes."""
    if depth > 8 or not isinstance(result, dict) or set(result) != {"type", "value"}:
        raise ValueError("Malformed nested native result")
    kind, value = result["type"], result["value"]
    if kind == "none" and value is None:
        return None
    if kind == "bool" and type(value) is bool:
        return value
    if kind == "int":
        return _uint(value)
    if kind == "bytes":
        return _hex(value)
    if kind == "text" and isinstance(value, str) and len(value) <= 4096:
        return value
    if kind == "mapping" and isinstance(value, dict) and len(value) <= 256:
        if any(not isinstance(key, str) or not 0 < len(key) <= 128 for key in value):
            raise ValueError("Malformed native result mapping keys")
        return {key: _typed_value(item, depth + 1) for key, item in value.items()}
    if kind == "sequence" and isinstance(value, list) and len(value) <= 4096:
        return [_typed_value(item, depth + 1) for item in value]
    if kind == "tuple" and isinstance(value, list) and len(value) <= 4096:
        return tuple(_typed_value(item, depth + 1) for item in value)
    raise ValueError("Malformed native typed result")


def _native_request(value) -> Any:
    if isinstance(value, bytes):
        return {"type": "bytes", "value": value.hex()}
    if isinstance(value, Mapping):
        return {key: _native_request(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_native_request(item) for item in value]
    if value is not None and type(value) not in (str, int, bool, float):
        from scripts.j2534_2026 import NativeMessage, NativeReadBatch2026

        if type(value) is NativeMessage:
            return _native_request({"_native_type": "PASSTHRU_MSG_2026", **vars(value)})
        if type(value) is NativeReadBatch2026:
            return _native_request(
                {
                    "_native_type": "READ_BATCH_2026",
                    "messages": value.messages,
                    "count": value.count,
                }
            )
    return value


def _driver_value2026(value, depth=0):
    """Decode only explicit bounded J2534 message records, never native objects."""
    from scripts.j2534_2026 import NativeMessage, NativeReadBatch2026

    if depth > 8:
        raise ValueError("Recorded driver nesting exceeds bound")
    if isinstance(value, dict):
        native_type = value.get("_native_type")
        if native_type == "PASSTHRU_MSG_2026":
            fields = {key: item for key, item in value.items() if key != "_native_type"}
            if set(fields) != {
                "protocol_id",
                "data",
                "rx_status",
                "tx_flags",
                "timestamp",
                "extra_data_index",
            }:
                raise ValueError("Exact recorded PASSTHRU_MSG fields required")
            return NativeMessage(**fields)
        if native_type == "READ_BATCH_2026":
            if set(value) != {"_native_type", "messages", "count"}:
                raise ValueError("Exact recorded read-batch fields required")
            messages = _driver_value2026(value["messages"], depth + 1)
            if type(messages) is not tuple:
                raise ValueError("Recorded read backing must be a native tuple")
            return NativeReadBatch2026(messages, value["count"])
        if native_type is not None:
            raise ValueError("Unknown recorded native driver object")
        return {key: _driver_value2026(item, depth + 1) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        values = (_driver_value2026(item, depth + 1) for item in value)
        return tuple(values) if isinstance(value, tuple) else list(values)
    return value


def _request_descriptor(value):
    if isinstance(value, dict):
        if value.get("type") == "bytes_sha256":
            if set(value) != {"type", "length", "sha256"}:
                raise ValueError("Exact captured byte descriptor required")
            _uint(value["length"], 1024 * 1024 * 1024)
            if (
                not isinstance(value["sha256"], str)
                or re.fullmatch(r"[0-9a-f]{64}", value["sha256"]) is None
            ):
                raise ValueError("Captured byte descriptor SHA256 required")
        else:
            for item in value.values():
                _request_descriptor(item)
    elif isinstance(value, list):
        for item in value:
            _request_descriptor(item)


def _request_matches(expected, actual):
    if actual is not None and type(actual) not in (
        bytes,
        str,
        int,
        bool,
        float,
        dict,
        tuple,
        list,
    ):
        from scripts.j2534_2026 import NativeMessage, NativeReadBatch2026

        if type(actual) is NativeMessage:
            return _request_matches(
                expected, {"_native_type": "PASSTHRU_MSG_2026", **vars(actual)}
            )
        if type(actual) is NativeReadBatch2026:
            return _request_matches(
                expected,
                {
                    "_native_type": "READ_BATCH_2026",
                    "messages": actual.messages,
                    "count": actual.count,
                },
            )
    if isinstance(expected, dict) and expected.get("type") == "bytes_sha256":
        return (
            isinstance(actual, bytes)
            and len(actual) == expected["length"]
            and hashlib.sha256(actual).hexdigest() == expected["sha256"]
        )
    if isinstance(actual, bytes):
        return expected == _native_request(actual)
    if isinstance(expected, dict) and isinstance(actual, Mapping):
        return expected.keys() == actual.keys() and all(
            _request_matches(value, actual[key]) for key, value in expected.items()
        )
    if isinstance(expected, list) and isinstance(actual, (list, tuple)):
        return len(expected) == len(actual) and all(
            _request_matches(left, right) for left, right in zip(expected, actual)
        )
    return type(expected) is type(actual) and expected == actual


def native_device_action2026(device, event, remaining, *, cleanup=False):
    """Translate a source-authorized native view without selecting its role."""
    from scripts.j2534_2026 import J2534Device2026

    if type(device) is not J2534Device2026 or type(cleanup) is not bool:
        raise TypeError("Concrete native interface and cleanup Boolean required")
    operation = event.get("operation")
    if operation not in DEVICE_ACTIONS2026:
        raise ValueError("Operation is not a native interface primitive")
    if cleanup:
        if operation == "ioctl":
            event = {
                "operation": "control_io",
                "ioctl": event["ioctl"],
                "parameters": event.get("config", ()),
            }
        return device.cleanup_primitive(event, remaining)
    if (
        operation in ("ioctl", "wrap_read_messages")
        or (operation == "connect" and event.get("protocol") == 3)
        or (
            device.protocol_id == 3 and operation in ("write_messages", "read_messages")
        )
    ):
        from scripts.programming_2026_sil import sil_j2534_action

        return sil_j2534_action(device)(event, remaining)
    return device.primitive(event, remaining)


@dataclass(repr=False)
class ProgrammingTrace:
    rows: Sequence[dict] = field(repr=False)
    cancelled: Callable[[], bool] = field(default=lambda: False, repr=False)
    position: int = 0
    elapsed: float = 0
    attachments: Mapping[str, bytes] = field(default_factory=dict, repr=False)
    _online_recordings2026: dict[str, tuple[object, str, object, object]] = field(
        default_factory=dict, repr=False
    )
    _device2026: J2534Device2026 | None = field(default=None, repr=False)
    _interface_pair2026: J2534InterfacePair2026 | None = field(default=None, repr=False)

    @property
    def interface_pair(self) -> J2534InterfacePair2026 | None:
        if self._interface_pair2026 is not None:
            self._interface_pair2026.validate_views()
        return self._interface_pair2026

    @property
    def engine_device(self) -> J2534Device2026 | None:
        pair = self.interface_pair
        return pair.engine if pair is not None else None

    @property
    def device(self) -> J2534Device2026 | None:
        return self._device2026

    def bind_recorded_device2026(self, *, timeout: float, max_calls: int):
        from scripts.j2534_2026 import J2534Device2026, J2534InterfacePair2026

        if self._device2026 is None:
            provider, clock, cancelled = (
                self.driver_primitive,
                self.clock,
                self.cancelled,
            )

            def make_device():
                return J2534Device2026(
                    provider,
                    timeout=timeout,
                    clock=clock,
                    cancelled=cancelled,
                    background_workers=False,
                    max_calls=max_calls,
                    max_cleanup_calls=max_calls * 2 + 256,
                )

            self._device2026 = make_device()
            self._interface_pair2026 = J2534InterfacePair2026(
                make_device(), self._device2026
            )
        elif (
            self._device2026.provider != self.driver_primitive
            or self._device2026.clock != self.clock
            or self._device2026.cancelled != self.cancelled
            or self._device2026.max_calls != max_calls
        ):
            raise ValueError("Recorded native device ownership or budget changed")
        pair = self.interface_pair
        if pair is None or pair.control is not self._device2026:
            raise ValueError("Recorded native interface pair ownership changed")
        return self._device2026

    def driver_primitive(self, event, remaining):
        from scripts.j2534_2026 import PrimitiveResult

        result = self.consume("action", event, remaining)
        if not isinstance(result, dict) or set(result) != {"status", "value"}:
            raise ValueError("Recorded driver requires explicit status/value result")
        return PrimitiveResult(
            _uint(result["status"]), _driver_value2026(result["value"])
        )

    def close(self):
        """Release an owned streamed-event spool after controller finalization."""
        if isinstance(self.rows, _EventSpool):
            self.rows.close()

    @classmethod
    def validate(cls, rows, cancelled=lambda: False):
        if not isinstance(rows, list) or len(rows) > 100000:
            raise ValueError("Bounded chronological programming events required")
        for row in rows:
            if not isinstance(row, dict) or set(row) != {
                "kind",
                "request",
                "result",
                "elapsed_ms",
            }:
                raise ValueError("Invalid programming event fields")
            if row["kind"] not in (
                "action",
                "exchange",
                "receive",
                "raw_write",
                "raw_read",
                "security",
            ):
                raise ValueError("Unknown low-level programming event")
            _uint(row["elapsed_ms"], 86400000)
            if not isinstance(row["request"], dict):
                raise TypeError("Explicit programming request fields required")
            _safe_json(row["request"])
            _request_descriptor(row["request"])
            if row["kind"] in ("exchange", "receive", "raw_write", "raw_read"):
                if (
                    set(row["request"]) != {"ecu", "payload_hex"}
                    or not isinstance(row["request"]["ecu"], str)
                    or not 0 < len(row["request"]["ecu"]) <= 128
                ):
                    raise ValueError("Explicit ECU/PDU fields required")
                _hex(row["request"]["payload_hex"])
                if (
                    row["kind"] in ("receive", "raw_read")
                    and row["request"]["payload_hex"]
                ):
                    raise ValueError("Receive-only event must have empty request")
            result = row["result"]
            if not isinstance(result, dict) or set(result) != {"type", "value"}:
                raise ValueError("Typed programming event result required")
            if (
                row["kind"] == "action"
                and row["request"].get("operation") == "wait"
                and result["type"] != "error"
            ):
                minimum = _uint(row["request"].get("milliseconds"), 86400000)
                if row["elapsed_ms"] < minimum:
                    raise ValueError(
                        "Successful recorded native wait must include its elapsed duration"
                    )
            kind, value = result["type"], result["value"]
            if (
                row["kind"] == "action"
                and row["request"].get("operation")
                in ("get_local_seconds_of_day", "get_local_milliseconds_of_day")
                and kind != "error"
            ):
                maximum = (
                    86399
                    if row["request"]["operation"] == "get_local_seconds_of_day"
                    else 86399999
                )
                if kind != "int":
                    raise ValueError(
                        "Native captured clock requires unsigned integer result"
                    )
                _uint(value, maximum)
            permitted = {
                "exchange": ("bytes", "error"),
                "receive": ("bytes", "error"),
                "raw_write": ("int", "error"),
                "raw_read": ("bytes", "error"),
                "security": ("attachment", "error"),
            }
            if row["kind"] in permitted and kind not in permitted[row["kind"]]:
                raise ValueError(
                    "Programming event result type does not match I/O kind"
                )
            if (
                row["kind"] in ("exchange", "raw_write")
                and not row["request"]["payload_hex"]
            ):
                raise ValueError("Transmitted programming PDU must not be empty")
            if kind == "attachment":
                if (
                    not isinstance(value, str)
                    or re.fullmatch(r"[A-Za-z0-9_.-]{1,260}", value) is None
                    or row["request"].get("attachment") != value
                ):
                    raise ValueError(
                        "Security result must reference its selected attachment"
                    )
                continue
            if kind == "none" and value is None:
                continue
            if (
                kind == "error"
                and isinstance(value, dict)
                and set(value) in ({"domain", "code"}, {"domain", "code", "detail"})
                and value["domain"]
                in ("native", "vendor", "m16c", "host", "cpass2026", "j2534_2026")
            ):
                if value["domain"] in ("cpass2026", "j2534_2026"):
                    if (
                        type(value["code"]) is not int
                        or not -(1 << 31) <= value["code"] < 1 << 31
                    ):
                        raise ValueError("Native2026 signed error enum required")
                else:
                    _uint(value["code"])
                if value["domain"] == "j2534_2026" and "detail" not in value:
                    raise ValueError("Native2026 J2534 error requires driver status")
                if "detail" in value:
                    if value["domain"] == "j2534_2026":
                        if (
                            type(value["detail"]) is not int
                            or not -(1 << 31) <= value["detail"] < 1 << 31
                        ):
                            raise ValueError("Native2026 signed driver status required")
                    elif value["domain"] == "native":
                        _uint(value["detail"])
                    else:
                        raise ValueError(
                            "Driver detail requires its native error domain"
                        )
            else:
                _typed_value(result)
        return cls(tuple(json.loads(json.dumps(rows))), cancelled)

    def clock(self):
        return self.elapsed

    def absorb_online_elapsed(self, seconds: float) -> None:
        """Account for the concrete nested online capture once at its boundary."""
        if (
            type(seconds) not in (int, float)
            or not math.isfinite(seconds)
            or not 0 <= seconds <= 600
        ):
            raise ValueError("Bounded captured online elapsed time required")
        self.elapsed += seconds

    def consume(self, kind: str, request: dict, remaining: float | None = None) -> Any:
        # The native runner enforces cancellation. Cleanup callbacks must still
        # consume their captured driver events after cancellation/deadline.
        if remaining is not None and (
            isinstance(remaining, bool)
            or not isinstance(remaining, (int, float))
            or not math.isfinite(remaining)
            or remaining < 0
        ):
            raise ValueError("Finite nonnegative remaining replay time required")
        if self.position >= len(self.rows):
            raise ValueError("Programming replay exhausted")
        row = self.rows[self.position]
        if row["kind"] != kind or not _request_matches(row["request"], request):
            raise ValueError(
                f"Programming chronology mismatch at event {self.position}"
            )
        self.position += 1
        self.elapsed += row["elapsed_ms"] / 1000
        result = row["result"]
        if result["type"] == "error":
            code = result["value"]["code"]
            domain = result["value"]["domain"]
            if domain in ("cpass2026", "j2534_2026"):
                from scripts.programming_2026_common import (
                    NativeJ2534Exception2026,
                    NativePassThruException2026,
                )

                if domain == "j2534_2026":
                    error = NativeJ2534Exception2026(
                        result["value"]["detail"], "captured-native-driver", 0
                    )
                    error.set_error(code)
                    raise error
                raise NativePassThruException2026(code, "captured-native-driver", 0)
            if domain == "native":
                if "detail" in result["value"]:
                    from scripts.programming import NativeRecoveryTransportError

                    raise NativeRecoveryTransportError(code, result["value"]["detail"])
                raise NativeTransportError(code)
            if domain == "vendor":
                from scripts.programming_vendor import (
                    NativeTransportError as VendorError,
                )

                raise VendorError(code, "Captured native transport failure")
            if domain == "m16c":
                from scripts.programming_m16c import M16CReadError

                raise M16CReadError(code)
            raise OSError("Captured host operation failed")
        if result["type"] == "attachment":
            if result["value"] not in self.attachments:
                raise ValueError("Selected security attachment is unavailable")
            return self.attachments[result["value"]]
        return _typed_value(result)

    def action(self, event, remaining):
        if (
            self._device2026 is not None
            and event.get("operation") in DEVICE_ACTIONS2026
        ):
            return native_device_action2026(self._device2026, event, remaining)
        return self.consume("action", event, remaining)

    def cleanup_primitive(self, event, remaining):
        if (
            self._device2026 is not None
            and event.get("operation") in DEVICE_ACTIONS2026
        ):
            return native_device_action2026(
                self._device2026, event, remaining, cleanup=True
            )
        return self.consume("action", event, remaining)

    def native_local_seconds_of_day(self):
        """Actual captured GetLocalTime observation, used only by native timers."""
        return _uint(
            self.consume("action", {"operation": "get_local_seconds_of_day"}), 86399
        )

    def native_local_milliseconds_of_day(self):
        """Captured local millisecond clock for native OTA pending policy."""
        return _uint(
            self.consume("action", {"operation": "get_local_milliseconds_of_day"}),
            86399999,
        )

    def platform(self, event, remaining) -> None:
        if self.consume("action", event, remaining) is not None:
            raise ValueError("Native platform action requires a void result")

    def exchange(self, ecu, payload):
        return self.consume("exchange", {"ecu": ecu, "payload_hex": payload.hex()})

    def receive(self, ecu):
        return self.consume("receive", {"ecu": ecu, "payload_hex": ""})

    def wait(self, milliseconds, remaining):
        self.platform({"operation": "wait", "milliseconds": milliseconds}, remaining)

    def raw_stream(self, ecu, timeout):
        from scripts.programming_vendor import VendorCAN

        def write(payload, remaining):
            value = self.consume(
                "raw_write", {"ecu": ecu, "payload_hex": payload.hex()}, remaining
            )
            if type(value) is not int:
                raise TypeError("Raw driver write requires an accepted message count")
            return value

        return VendorCAN(
            write,
            lambda remaining: self.consume(
                "raw_read", {"ecu": ecu, "payload_hex": ""}, remaining
            ),
            timeout=timeout,
            clock=self.clock,
            cancelled=self.cancelled,
            wait=self.wait,
        )

    def assert_complete(self):
        if self.position != len(self.rows):
            raise ValueError("Unconsumed chronological programming events")


def _writer_state(value):
    expected = {
        "returned",
        "result_status_update",
        "native_error_code",
        "driver_error_code",
        "retry_password",
        "finish_flag_update",
        "completion_flag_update",
        "recovery_flag_update",
        "progress_bytes",
        "progress_percent",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError("Malformed native writer output state")
    if any(
        item is not None and type(item) not in (bool, int) for item in value.values()
    ):
        raise ValueError("Native writer output state must contain scalar native fields")
    if any(
        type(item) is int and not 0 <= item <= 0xFFFFFFFF for item in value.values()
    ):
        raise ValueError("Native writer output exceeds unsigned field bounds")
    return dict(value)


def _report(result):
    """Native histories can contain seeds or identifiers; never export raw history."""
    allowed = (
        "state",
        "family",
        "mode",
        "version",
        "compatible",
        "compatibility_evaluated",
        "timed_out",
        "transferred",
        "programming_completed",
        "physical_status",
        "finished",
        "native_result",
        "native_return",
        "native_success",
        "reset_requested",
        "gateway_mode_changed",
        "assembly_valid",
        "host_succeeded",
    )
    report = {
        key: value
        for key, value in result.items()
        if key in allowed and (value is None or type(value) in (bool, int, str))
    }
    if isinstance(result.get("native_result"), dict):
        report["native_result"] = _writer_state(result["native_result"])
    for key in (
        "native_error_code",
        "native_error",
        "driver_error_code",
        "native_result_code",
        "native_error_kind",
        "native_primary_error",
        "native_passthru_error",
        "native_pending_timeout_ms",
    ):
        value = result.get(key)
        if type(value) is int and -(1 << 31) <= value <= 0xFFFFFFFF:
            report[key] = value
    domains = {
        "CPassThruException",
        "CJ2534Exception",
        "diagnostic_response",
        "NativePassThruException2026",
        "NativeJ2534Exception2026",
    }
    if result.get("native_error_domain") in domains:
        report["native_error_domain"] = result["native_error_domain"]
    observed_native = result.get("observed_native_error")
    if isinstance(observed_native, dict):
        observed = _report(
            {
                key: value
                for key, value in observed_native.items()
                if key in ("native_error_code", "native_error_domain", "error_type")
            }
        )
        if observed:
            report["observed_native_error"] = observed
            for key in ("native_error_code", "native_error_domain"):
                if key in observed:
                    report.setdefault(key, observed[key])
    if type(result.get("gateway_kind")) is int and 0 <= result["gateway_kind"] <= 255:
        report["gateway_kind"] = result["gateway_kind"]
    if result.get("host_result") in ("completed", "cleanup_failed"):
        report["host_result"] = result["host_result"]
    if (
        type(result.get("native_comm_phase")) is int
        and 0 <= result["native_comm_phase"] <= 255
    ):
        report["native_comm_phase"] = result["native_comm_phase"]
    suppressed = result.get("suppressed_cleanup_errors")
    if (
        isinstance(suppressed, (list, tuple))
        and len(suppressed) <= 4096
        and all(
            isinstance(name, str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,95}", name)
            for name in suppressed
        )
    ):
        report["suppressed_cleanup_errors"] = list(suppressed)
    assembly = result.get("assembly")
    if isinstance(assembly, str) and len(assembly) <= 260 and assembly.isascii():
        report["assembly"] = assembly
    assembly_error = result.get("assembly_error")
    if type(assembly_error) is int and 0 <= assembly_error <= 0xFFFFFFFF:
        report["assembly_error"] = assembly_error
    elif isinstance(assembly_error, dict):
        report["assembly_error"] = _report(
            {
                key: value
                for key, value in assembly_error.items()
                if key in ("native_error_code", "native_error_domain", "error_type")
            }
        )
    native_results = result.get("native_results")
    if isinstance(native_results, (tuple, list)) and len(native_results) <= 32:
        report["native_results"] = [
            _report(
                {key: value for key, value in item.items() if key != "native_results"}
            )
            for item in native_results
            if isinstance(item, dict)
        ]
    cleanup = result.get("cleanup_error_details")
    if isinstance(cleanup, (list, tuple)) and len(cleanup) <= 4096:
        details = []
        for item in cleanup:
            if not isinstance(item, dict):
                continue
            detail = {}
            phase = item.get("phase")
            if isinstance(phase, str) and re.fullmatch(
                r"[A-Za-z_][A-Za-z0-9_]{0,95}", phase
            ):
                detail["phase"] = phase
            if item.get("native_error_domain") in domains:
                detail["native_error_domain"] = item["native_error_domain"]
            code = item.get("native_error_code")
            if type(code) is int and -(1 << 31) <= code <= 0xFFFFFFFF:
                detail["native_error_code"] = code
            if detail:
                details.append(detail)
        report["cleanup_error_details"] = details
    error_type = result.get("error_type")
    if isinstance(error_type, str) and re.fullmatch(
        r"[A-Za-z_][A-Za-z0-9_]{0,95}", error_type
    ):
        report["error_type"] = error_type
    # Calibration identifiers are useful read results; arbitrary histories are not.
    identifiers = result.get("identifiers", result.get("cids"))
    preserved = result.get("identifier_records")
    if isinstance(preserved, list) and len(preserved) <= 1024:
        restored = []
        for record in preserved:
            if not isinstance(record, dict) or set(record) != {"bytes_hex", "ascii"}:
                raise ValueError("Malformed preserved native identifier record")
            raw = _hex(record["bytes_hex"], 260)
            display = raw.decode("ascii") if raw.isascii() else None
            if record["ascii"] != display:
                raise ValueError(
                    "Preserved identifier display differs from native bytes"
                )
            restored.append(raw)
        identifiers = restored
    if identifiers is None and isinstance(result.get("nodes"), list):
        identifiers = [
            value for node in result["nodes"] for value in node.get("software_ids", [])
        ]
    if isinstance(identifiers, (list, tuple)) and len(identifiers) <= 1024:
        values = []
        records = []
        for value in identifiers:
            if isinstance(value, bytes):
                if len(value) > 260:
                    raise ValueError("Malformed native calibration identifier result")
                raw = value
            elif isinstance(value, str) and len(value) <= 260 and value.isascii():
                raw = value.encode("ascii")
            else:
                raise ValueError("Malformed native calibration identifier result")
            display = raw.decode("ascii") if raw.isascii() else None
            records.append({"bytes_hex": raw.hex(), "ascii": display})
            if display is not None:
                values.append(display)
        report["identifiers"] = values
        report["identifier_records"] = records
        report["identifier_bytes_hex"] = [record["bytes_hex"] for record in records]
    return report


@dataclass(frozen=True)
class BoundModule:
    name: str
    sha256: str
    build: int
    family: str
    exports: tuple[str, ...]
    kind: str = "verified_native_source"
    file_version: str | None = None
    native_identity: NativeModuleIdentity | None = field(default=None, repr=False)


@dataclass(repr=False)
class ProgrammingReplay:
    # Factories authenticate either ordinary framing or the issued large-file backing.
    # Family adapters retain their own source-format guards.
    container: Any = field(repr=False)
    context: dict = field(repr=False)
    catalog: CalibrationCatalog = field(repr=False)
    modules: Mapping[str, BoundModule] = field(repr=False)
    attachments: Mapping[str, bytes] = field(repr=False)
    trace: ProgrammingTrace = field(repr=False)
    input_hashes: dict = field(repr=False)
    used: bool = False
    _last_report: dict | None = field(default=None, repr=False)
    _engine2026: Any = field(default=None, repr=False)
    _runtime2026: Any = field(default=None, repr=False)
    _controller2026: Any = field(default=None, repr=False)
    _selection2026: object | None = field(default=None, repr=False)
    _retained_export2026: str | None = field(default=None, repr=False)
    _alternate_parent2026: ProgrammingReplay | None = field(default=None, repr=False)
    _executed_selection2026: object | None = field(default=None, repr=False)
    _catalog_sources: Mapping[str, bytes] = field(default_factory=dict, repr=False)
    _module_files: Mapping[str, bytes] = field(default_factory=dict, repr=False)
    _control_target2026: Any = field(default=None, repr=False)
    _control_export2026: str | None = field(default=None, repr=False)

    @property
    def operation(self):
        return self.context["operation"]

    @property
    def node(self):
        return self.context["node"]

    @property
    def available_operations(self):
        return (self.operation,)

    def selected_identity(self) -> NativeModuleIdentity:
        """Resolve the exact source identity without consuming driver events."""
        _, module, *_ = self._dispatch()
        if module.native_identity is None:
            raise ValueError("Authored fixtures have no original module identity")
        return module.native_identity

    def selected_binding2026(self) -> NativeParameterBinding2026:
        """Expose the actual controller/engine-bound immutable native parameter row."""
        from scripts.programming_2026_common import NativeParameterBinding2026

        if self._engine2026 is None or self._controller2026 is None:
            raise ValueError("Actual bound native2026 engine and controller required")
        if self._control_target2026 is not None:
            with self._control_scope2026():
                selection = self._control_target2026.binding
                if (
                    self._engine2026.family_metadata
                    != self._control_target2026.metadata
                ):
                    raise ValueError("CONTROL family view differs from issued target")
        else:
            selection, *_ = self._dispatch2026()
        if type(selection) is not NativeParameterBinding2026:
            raise TypeError("Source-bound native2026 parameter selection required")
        return selection

    def bind_engine2026(self, engine) -> None:
        """Attach the source-bound engine state without consuming trace events."""
        from scripts.cuw_2026 import CUWEngine2026

        if not isinstance(engine, CUWEngine2026):
            raise TypeError("Concrete CUW2026 engine required")
        if self.used or self.trace.position and self._runtime2026 is None:
            raise ValueError(
                "Engine binding requires an unused or shared-runtime recording"
            )
        if self._control_target2026 is not None:
            with self._control_scope2026():
                held = engine.family_metadata
                if (
                    held.source_sha256 != self.container.digest
                    or held.source_container.digest != self.container.digest
                    or held.node != self.node
                    or held != self._control_target2026.metadata
                    or engine is not self._control_target2026._engine
                ):
                    raise ValueError("Engine differs from held CONTROL source target")
            if self._engine2026 is not None and self._engine2026 is not engine:
                raise ValueError("Recording already bound to another engine")
            self._engine2026 = engine
            return
        state = engine.dh_state
        cpu_index = self.context["observations"]["host"].get("cpu_index", 0)
        if (
            engine.source_sha256 != self.container.digest
            or state.source_sha256 != self.container.digest
            or state.node != self.node
            or state.selection_cpu_index != cpu_index
        ):
            raise ValueError("Engine and recording source selection differ")
        if self._engine2026 is not None and self._engine2026 is not engine:
            raise ValueError("Recording already bound to another engine")
        from scripts.programming_2026_common import NativeFrontendParameters2026

        frontend_names = ("Parameter.ini", "CanIDTable.ini", "LogicalAddressTable.ini")
        if all(name in self._catalog_sources for name in frontend_names):
            bundle = NativeFrontendParameters2026.from_sources(
                self._catalog_sources, encoded=True
            )
            retained = engine.frontend_parameters
            if retained is not None:
                if retained != bundle:
                    raise ValueError(
                        "Selected frontend sources differ from native engine"
                    )
            else:
                engine.bind_frontend_parameters(bundle)
        previous = self._engine2026
        self._engine2026 = engine
        try:
            if self.selected_identity().cuw_builds != ("2026",):
                raise ValueError("CUW2026 engine requires an exact2026 module identity")
        except (Exception, KeyboardInterrupt):
            self._engine2026 = previous
            raise
        descriptor = self.context["observations"]["host"].get("online2026")
        if descriptor is not None:
            if (
                not isinstance(descriptor, dict)
                or set(descriptor) != {"configuration", "recording"}
                or any(
                    not isinstance(alias, str) or alias not in self.attachments
                    for alias in descriptor.values()
                )
            ):
                raise ValueError(
                    "Explicit online configuration/recording aliases required"
                )
            configuration = self.attachments[descriptor["configuration"]]
            if (
                hashlib.sha256(configuration).hexdigest()
                != engine.rks_configuration.last_source_sha256
            ):
                engine.load_rks_configuration(configuration)
        self.input_hashes["engine"] = engine.identity.sha256
        if self._runtime2026 is not None:
            self._bind_recorded_transport2026(self._runtime2026)

    def bind_runtime2026(self, runtime) -> None:
        """Retain one concrete primitive runtime across native controller exports."""
        from scripts.programming_2026_common import NativeRuntime2026

        if not isinstance(runtime, NativeRuntime2026):
            raise TypeError("Concrete native2026 primitive runtime required")
        if (
            self.used
            or not self.modules
            or any(
                module.native_identity is None
                or module.native_identity.cuw_builds != ("2026",)
                for module in self.modules.values()
            )
        ):
            raise ValueError("Unused exact2026 source identities required")
        if (
            runtime.action != self.trace.action
            or runtime.clock != self.trace.clock
            or runtime.cancelled != self.trace.cancelled
            or runtime.local_seconds_of_day != self.trace.native_local_seconds_of_day
            or runtime.local_milliseconds_of_day
            != self.trace.native_local_milliseconds_of_day
        ):
            raise ValueError(
                "Runtime must share the exact chronological trace and boundaries"
            )
        if self._runtime2026 is not None and self._runtime2026 is not runtime:
            raise ValueError("Recording already bound to another native runtime")
        self._runtime2026 = runtime
        self._bind_recorded_transport2026(runtime)

    def _bind_control_root2026(self, engine, controller, runtime) -> None:
        """Bind the unused root recording to the active held CONTROL source."""
        from scripts.cuw_2026 import CUWEngine2026
        from scripts.programming_2026_common import (
            _NATIVE_CONTROL_RAW_EXECUTIONS_2026,
            ControlCommPhase2026,
            NativeControlContext2026,
            NativeRuntime2026,
        )

        if (
            type(engine) is not CUWEngine2026
            or type(controller) is not ControlCommPhase2026
            or not isinstance(runtime, NativeRuntime2026)
            or controller.runtime is not runtime
            or engine.worker.controller is not controller
            or engine.worker.runtime is not runtime
            or self.used
            or (self._engine2026 is not None and self._engine2026 is not engine)
            or (
                self._controller2026 is not None
                and self._controller2026 is not controller
            )
            or (self._runtime2026 is not None and self._runtime2026 is not runtime)
        ):
            raise ValueError("Unused CONTROL root and exact native owners required")
        context = controller.native_control_context2026(engine)
        token = controller._native_control_raw_execution2026
        if (
            type(context) is not NativeControlContext2026
            or _NATIVE_CONTROL_RAW_EXECUTIONS_2026.get(id(token))
            != (token, engine, controller, context)
            or token is None
            or context._runtime is not runtime
            or context._capture.metadata.source_sha256 != self.container.digest
            or context._capture.metadata.source_container.digest
            != self.container.digest
            or context._capture.metadata.node != self.node
            or not _same_trace_callable2026(runtime.action, self.trace.action)
            or not _same_trace_callable2026(runtime.clock, self.trace.clock)
            or not _same_trace_callable2026(runtime.cancelled, self.trace.cancelled)
            or not _same_trace_callable2026(
                runtime.local_seconds_of_day,
                self.trace.native_local_seconds_of_day,
            )
            or not _same_trace_callable2026(
                runtime.local_milliseconds_of_day,
                self.trace.native_local_milliseconds_of_day,
            )
        ):
            raise ValueError("Active held CONTROL source and exact trace required")
        self._validate_control_frontend_sources2026(engine, context._capture.metadata)
        already_bound = (
            self._runtime2026 is runtime
            and self._controller2026 is controller
            and self._engine2026 is engine
        )
        self._runtime2026 = runtime
        self._controller2026 = controller
        self.input_hashes["controller"] = controller.identity.sha256
        self._engine2026 = engine
        self.input_hashes["engine"] = engine.identity.sha256
        if not already_bound:
            self._bind_recorded_transport2026(runtime)

    def _bind_control_prelude2026(self, engine, controller, runtime) -> None:
        """Bind owners to the held CONTROL source before raw execution starts."""
        from scripts.cuw_2026 import CUWEngine2026
        from scripts.programming_2026_common import (
            ControlCommPhase2026,
            NativeControlContext2026,
            NativeRuntime2026,
        )

        if (
            type(engine) is not CUWEngine2026
            or type(controller) is not ControlCommPhase2026
            or not isinstance(runtime, NativeRuntime2026)
            or controller.runtime is not runtime
            or engine.worker.controller is not controller
            or engine.worker.runtime is not runtime
            or self.used
            or (self._engine2026 is not None and self._engine2026 is not engine)
            or (
                self._controller2026 is not None
                and self._controller2026 is not controller
            )
            or (self._runtime2026 is not None and self._runtime2026 is not runtime)
            or controller._native_control_raw_execution2026 is not None
            or controller._native_control_helper_entry2026 is not None
        ):
            raise ValueError("Unused CONTROL prelude and exact native owners required")
        context = controller.native_control_context2026(engine)
        if (
            type(context) is not NativeControlContext2026
            or context._runtime is not runtime
            or context._capture.metadata.source_sha256 != self.container.digest
            or context._capture.metadata.source_container.digest
            != self.container.digest
            or context._capture.metadata.node != self.node
            or not _same_trace_callable2026(runtime.action, self.trace.action)
            or not _same_trace_callable2026(runtime.clock, self.trace.clock)
            or not _same_trace_callable2026(runtime.cancelled, self.trace.cancelled)
            or not _same_trace_callable2026(
                runtime.local_seconds_of_day, self.trace.native_local_seconds_of_day
            )
            or not _same_trace_callable2026(
                runtime.local_milliseconds_of_day,
                self.trace.native_local_milliseconds_of_day,
            )
        ):
            raise ValueError("Held CONTROL source and exact trace required")
        self._validate_control_frontend_sources2026(engine, context._capture.metadata)
        already_bound = (
            self._runtime2026 is runtime
            and self._controller2026 is controller
            and self._engine2026 is engine
        )
        self._runtime2026 = runtime
        self._controller2026 = controller
        self.input_hashes["controller"] = controller.identity.sha256
        self._engine2026 = engine
        self.input_hashes["engine"] = engine.identity.sha256
        if not already_bound:
            self._bind_recorded_transport2026(runtime)

    def _validate_control_frontend_sources2026(self, engine, metadata) -> None:
        """Check supplied canonical frontend inputs without binding them late."""
        from scripts.programming_2026_common import (
            NativeFrontendParameters2026,
            NativeGeneralParameters2026,
        )

        supplied = self._catalog_sources
        if metadata.parser_parameters_validated and "Parameter.ini" in supplied:
            general = NativeGeneralParameters2026.from_sources(supplied, encoded=True)
            if general != metadata.parser_general_parameters:
                raise ValueError("Held parser General source differs from catalog")

        frontend = engine.frontend_parameters
        names = ("Parameter.ini", "CanIDTable.ini", "LogicalAddressTable.ini")
        if frontend is not None:
            frontend.validate_source()
            for name in names:
                if (
                    name in supplied
                    and name in frontend.sources
                    and supplied[name] != frontend.sources[name]
                ):
                    raise ValueError(
                        "Supplied frontend source differs from native engine"
                    )
            if all(name in supplied for name in names):
                selected = NativeFrontendParameters2026.from_sources(
                    supplied, encoded=True
                )
                if frontend != selected:
                    raise ValueError(
                        "Supplied frontend bundle differs from native engine"
                    )
        elif all(name in supplied for name in names):
            raise ValueError(
                "Frontend sources must be bound before the native worker starts"
            )

    def _bind_recorded_transport2026(self, runtime) -> None:
        host = self.context["observations"]["host"]
        driver_recording = host.get("driver_recording")
        if driver_recording is not None or self.trace.device is not None:
            if driver_recording not in (None, "j2534_2026"):
                raise ValueError("Unknown recorded native driver selection")
            driver = self.modules.get("TCUWJ2534DeviceIF.dll")
            if (
                driver is None
                or driver.native_identity is None
                or driver.native_identity.cuw_builds != ("2026",)
            ):
                raise ValueError("Actual selected2026 J2534 interface source required")
            device = self.trace.bind_recorded_device2026(
                timeout=self.context["observations"]["timeout_seconds"],
                max_calls=runtime.max_calls,
            )
            runtime.bind_recorded_device2026(self.trace, device)
            if self._engine2026 is not None:
                from scripts.cuw_2026 import CUWEngine2026

                assert isinstance(self._engine2026, CUWEngine2026)
                retained_pair = self._engine2026.interface_pair
                if retained_pair is None:
                    self._engine2026.bind_interface_pair(self.trace.interface_pair)
                elif retained_pair is not self.trace.interface_pair:
                    raise ValueError("Selected trace pair differs from native engine")

    def _bind_online2026(self, runtime, host) -> None:
        from scripts.cuw_2026 import CUWEngine2026
        from scripts.cuw_online import OnlineKeyController2026, OnlineReplay2026

        descriptor = host.get("online2026")
        engine = self._engine2026
        if descriptor is None:
            if isinstance(engine, CUWEngine2026):
                runtime.validate_online_binding(
                    engine, self.trace.absorb_online_elapsed
                )
            return
        if (
            not isinstance(descriptor, dict)
            or set(descriptor) != {"configuration", "recording"}
            or any(
                not isinstance(alias, str) or alias not in self.attachments
                for alias in descriptor.values()
            )
            or not isinstance(engine, CUWEngine2026)
        ):
            raise ValueError(
                "Selected online capture/configuration and actual engine required"
            )
        configuration = self.attachments[descriptor["configuration"]]
        recording = self.attachments[descriptor["recording"]]
        if len(recording) > 8 * 1024 * 1024:
            raise ValueError("Online recording attachment exceeds its byte budget")
        digest = hashlib.sha256(recording).hexdigest()
        config_digest = hashlib.sha256(configuration).hexdigest()
        cached = self.trace._online_recordings2026.get(digest)
        if cached is None:
            from scripts.programming_2026_common import ControlCommPhase2026

            if self._controller2026 is None:
                module = self.modules.get("TCUWControlCommPhase.dll")
                if module is None or module.native_identity is None:
                    raise ValueError(
                        "Actual selected native online control module required"
                    )
                self.bind_controller2026(
                    ControlCommPhase2026(module.native_identity, runtime)
                )
            worker = engine.bind_worker(self._controller2026)
            controller = OnlineKeyController2026(worker, configuration)
            chronology = OnlineReplay2026(_json(recording))
            self.trace._online_recordings2026[digest] = (
                engine,
                config_digest,
                controller,
                chronology,
            )
        else:
            cached_engine, cached_configuration, controller, chronology = cached
            if cached_engine is not engine or cached_configuration != config_digest:
                raise ValueError(
                    "Online capture is already bound to another source engine"
                )
        runtime.bind_p5_online(
            controller, chronology, advance_clock=self.trace.absorb_online_elapsed
        )

    def bind_controller2026(self, controller) -> None:
        """Attach the authenticated concrete controller and its native history."""
        from scripts.programming_2026_common import ControlCommPhase2026

        if not isinstance(controller, ControlCommPhase2026):
            raise TypeError("Concrete native2026 control phase required")
        self.bind_runtime2026(controller.runtime)
        if self._controller2026 is not None and self._controller2026 is not controller:
            raise ValueError("Recording already bound to another native controller")
        self._controller2026 = controller
        self.input_hashes["controller"] = controller.identity.sha256

    def next_session2026(
        self,
        operation: str,
        *,
        node: int,
        cpu_index: int,
        parameter_binding=None,
        _native_export: str | None = None,
    ):
        """Construct the next concrete export on this controller's shared trace."""
        from scripts.programming_2026_common import ControlCommPhase2026

        if not isinstance(self._controller2026, ControlCommPhase2026):
            raise TypeError(
                "Native phase construction requires the bound concrete controller"
            )
        if operation not in (
            "get_cid",
            "prepare",
            "write",
            "recovery",
            "probe",
            "change_gateway",
        ):
            raise ValueError("Unknown native controller export phase")
        _uint(node, 9)
        if node == 0:
            raise ValueError("Native target node must be positive")
        _uint(cpu_index, 4095)
        context = dict(self.context)
        observations = dict(context["observations"])
        host = dict(observations["host"])
        host["cpu_index"] = cpu_index
        if "native2026" in host:
            values = dict(host["native2026"])
            values["cpu_index"] = cpu_index
            values.pop("stage", None)
            if operation != self.operation:
                values.pop("export", None)
            host["native2026"] = values
        if _native_export is not None:
            if _native_export != "ProcessBeforeIGOffOnAtRetry" or operation not in (
                "prepare",
                "write",
            ):
                raise ValueError("Unknown retained native phase export")
            values = dict(host.get("native2026", {}))
            values["export"] = _native_export
            host["native2026"] = values
        observations["host"] = host
        context.update(operation=operation, node=node, observations=observations)
        following = ProgrammingReplay(
            self.container,
            context,
            self.catalog,
            self.modules,
            self.attachments,
            self.trace,
            dict(self.input_hashes),
            _selection2026=parameter_binding,
            _retained_export2026=_native_export,
            _catalog_sources=self._catalog_sources,
            _module_files=self._module_files,
        )
        following.bind_controller2026(self._controller2026)
        if self._engine2026 is not None:
            following.bind_engine2026(self._engine2026)
        following.selected_identity()
        return following

    def _next_vbf_prepare2026(self, job, request):
        """Build the unused raw prepare root from the authenticated FILE view."""
        from scripts.cuw_engine_threads import validate_vbf_process_before2026

        validated = validate_vbf_process_before2026(request, job, states=("prepared",))
        if (
            validated is not request
            or self is not request.previous_session
            or not self.used
        ):
            raise ValueError("Actual used previous raw root required")
        container = request.container
        digest = container.digest
        if digest != request.source_sha256:
            raise ValueError("Prepared FILE digest differs from its container")

        context = dict(self.context)
        observations = dict(context["observations"])
        observations["current_cids"] = tuple(
            identifier.decode("latin1") for identifier in request.received_identifiers
        )
        host = dict(observations["host"])
        host["cpu_index"] = request.cpu_index
        if "native2026" in host:
            native = dict(host["native2026"])
            native.pop("export", None)
            native.pop("stage", None)
            native["cpu_index"] = request.cpu_index
            host["native2026"] = native
        host.pop("export", None)
        host.pop("stage", None)
        observations["host"] = host
        context.update(
            operation="prepare",
            node=request.node,
            calibration_sha256=digest,
            observations=observations,
        )
        input_hashes = dict(self.input_hashes)
        input_hashes["calibration"] = digest

        # Preserve owner identities without bind_engine2026's eager module selection.
        return ProgrammingReplay(
            container,
            context,
            self.catalog,
            self.modules,
            self.attachments,
            self.trace,
            input_hashes,
            _engine2026=self._engine2026,
            _runtime2026=self._runtime2026,
            _controller2026=self._controller2026,
            _catalog_sources=self._catalog_sources,
            _module_files=self._module_files,
        )

    def _next_cid_root_34cb0_2026(
        self, entry: _NativeGetterContinuation2026
    ) -> ProgrammingReplay:
        """Build the next raw getter root from a promoted native continuation."""
        from scripts.calibration_2026 import Native2026Metadata
        from scripts.cuw_engine_threads import EngineThreadJob2026
        from scripts.cuw_engine_worker import (
            EngineWorker2026,
            _NativeGetterContinuation2026,
        )

        if type(entry) is not _NativeGetterContinuation2026:
            raise TypeError("Exact native getter continuation required")
        if type(entry.job) is not EngineThreadJob2026:
            raise TypeError("Exact native getter job required")
        if type(entry.worker) is not EngineWorker2026:
            raise TypeError("Exact native getter worker required")

        entry.job._validate_promoted_getter_continuation_2026(entry)

        previous = entry.old_session
        metadata = entry.post_tail_metadata
        if (
            type(previous) is not ProgrammingReplay
            or previous is not self
            or type(metadata) is not Native2026Metadata
        ):
            raise ValueError("Promoted getter source root and metadata required")
        container = metadata.source_container
        digest = metadata.source_sha256
        if container is None or container.digest != digest:
            raise ValueError("Promoted getter FILE identity is inconsistent")

        context = deepcopy(previous.context)
        observations = dict(context["observations"])
        observations["current_cids"] = tuple(
            cid.decode("latin1") for cid in entry.observation.received_cids
        )
        host = dict(observations["host"])
        host["cpu_index"] = metadata.cpu_index
        if "native2026" in host:
            native = dict(host["native2026"])
            native.pop("export", None)
            native.pop("stage", None)
            native["cpu_index"] = metadata.cpu_index
            host["native2026"] = native
        host.pop("export", None)
        host.pop("stage", None)
        observations["host"] = host
        context.update(
            operation="get_cid",
            node=metadata.node,
            calibration_sha256=digest,
            observations=observations,
        )
        input_hashes = dict(previous.input_hashes)
        input_hashes["calibration"] = digest

        # Owner references are already authenticated; binding the engine reselects a module.
        return ProgrammingReplay(
            container,
            context,
            previous.catalog,
            previous.modules,
            previous.attachments,
            previous.trace,
            input_hashes,
            _engine2026=previous._engine2026,
            _runtime2026=previous._runtime2026,
            _controller2026=previous._controller2026,
            _catalog_sources=previous._catalog_sources,
            _module_files=previous._module_files,
        )

    def _next_control_export2026(self, target, export: str):
        """Clone one source-issued CONTROL export onto this exact shared trace."""
        from scripts.cuw_2026 import CUWEngine2026
        from scripts.programming_2026_common import (
            ControlCommPhase2026,
            NativeControlExportTarget2026,
        )

        operations = {
            "StartGetCID": "get_cid",
            "StartPrepareWrite": "prepare",
            "StartFlashWrite": "write",
            "ChangeToReprogGatewayMode": "change_gateway",
            "PrepareRetry": "recovery",
            "IsFinishReprogramming": "probe",
        }
        if export == "ProcessBeforeIGOffOnAtRetry":
            if type(
                target
            ) is not NativeControlExportTarget2026 or target.binding.operation not in (
                "prepare",
                "write",
            ):
                raise ValueError("Retained CONTROL prepare/write target required")
            operation = target.binding.operation
        else:
            operation = operations.get(export)
        if (
            type(target) is not NativeControlExportTarget2026
            or operation is None
            or not isinstance(self._engine2026, CUWEngine2026)
            or not isinstance(self._controller2026, ControlCommPhase2026)
            or self._runtime2026 is not self._controller2026.runtime
            or target._engine is not self._engine2026
            or target._controller is not self._controller2026
            or not _same_trace_callable2026(self._runtime2026.action, self.trace.action)
            or not _same_trace_callable2026(self._runtime2026.clock, self.trace.clock)
            or not _same_trace_callable2026(
                self._runtime2026.cancelled, self.trace.cancelled
            )
            or not _same_trace_callable2026(
                self._runtime2026.local_seconds_of_day,
                self.trace.native_local_seconds_of_day,
            )
            or not _same_trace_callable2026(
                self._runtime2026.local_milliseconds_of_day,
                self.trace.native_local_milliseconds_of_day,
            )
        ):
            raise ValueError("Issued CONTROL target and exact replay owners required")
        target.validate(self._engine2026, self._controller2026)
        if self._engine2026._controller_export_target2026 is target:
            metadata = self._engine2026.family_metadata
        else:
            with self._engine2026.controller_export_target(
                self._controller2026, target
            ):
                metadata = self._engine2026.family_metadata
        if (
            metadata.source_sha256 != self.container.digest
            or metadata.source_container.digest != self.container.digest
            or metadata != target.metadata
            or target.binding.catalog_sources != self._catalog_sources
            or target.module_binding.catalog_sources != self._catalog_sources
        ):
            raise ValueError("CONTROL target source differs from replay inputs")
        held_container = target.binding.metadata.source_container
        if (
            held_container is not target.metadata.source_container
            or held_container.digest != self.container.digest
        ):
            raise ValueError("CONTROL stage requires the exact held FILE container")
        context = dict(self.context)
        observations = dict(context["observations"])
        held_identifiers = target._context.identifiers
        if type(held_identifiers) is not tuple or any(
            type(identifier) is not bytes for identifier in held_identifiers
        ):
            raise ValueError("Exact held CONTROL identifiers required")
        observations["current_cids"] = tuple(
            identifier.decode("latin1") for identifier in held_identifiers
        )
        host = dict(observations["host"])
        host.pop("native2026", None)
        host["cpu_index"] = target.entry_cpu_index
        observations["host"] = host
        context.update(
            operation=operation, node=metadata.node, observations=observations
        )
        following = ProgrammingReplay(
            held_container,
            context,
            self.catalog,
            self.modules,
            self.attachments,
            self.trace,
            dict(self.input_hashes),
            _engine2026=self._engine2026,
            _runtime2026=self._runtime2026,
            _controller2026=self._controller2026,
            _selection2026=target.binding,
            _retained_export2026=export
            if export == "ProcessBeforeIGOffOnAtRetry"
            else None,
            _catalog_sources=self._catalog_sources,
            _module_files=self._module_files,
            _control_target2026=target,
            _control_export2026=export,
        )
        following._validate_control_stage2026()
        return following

    def _validate_control_stage2026(self) -> None:
        from scripts.cuw_2026 import CUWEngine2026
        from scripts.programming_2026_common import (
            ControlCommPhase2026,
            NativeControlExportTarget2026,
        )

        target = self._control_target2026
        export = self._control_export2026
        if (
            type(target) is not NativeControlExportTarget2026
            or not isinstance(self._engine2026, CUWEngine2026)
            or type(self._controller2026) is not ControlCommPhase2026
            or self._runtime2026 is not self._controller2026.runtime
            or self._selection2026 is not target.binding
            or not _same_trace_callable2026(self._runtime2026.action, self.trace.action)
            or not _same_trace_callable2026(self._runtime2026.clock, self.trace.clock)
            or not _same_trace_callable2026(
                self._runtime2026.cancelled, self.trace.cancelled
            )
            or not _same_trace_callable2026(
                self._runtime2026.local_seconds_of_day,
                self.trace.native_local_seconds_of_day,
            )
            or not _same_trace_callable2026(
                self._runtime2026.local_milliseconds_of_day,
                self.trace.native_local_milliseconds_of_day,
            )
            or export is None
            or self.operation
            != {
                "StartGetCID": "get_cid",
                "StartPrepareWrite": "prepare",
                "StartFlashWrite": "write",
                "ChangeToReprogGatewayMode": "change_gateway",
                "PrepareRetry": "recovery",
                "IsFinishReprogramming": "probe",
                "ProcessBeforeIGOffOnAtRetry": target.binding.operation,
            }.get(export)
        ):
            raise ValueError("Private CONTROL replay lineage is invalid")
        target.validate(self._engine2026, self._controller2026)
        metadata = target.binding.metadata
        if (
            metadata.source_sha256 != self.container.digest
            or metadata.source_container.digest != self.container.digest
            or target.entry_cpu_index
            != self.context["observations"]["host"].get("cpu_index")
            or self.node != metadata.node
            or target.binding.catalog_sources != self._catalog_sources
            or self._control_export2026
            not in (
                "StartGetCID",
                "StartPrepareWrite",
                "StartFlashWrite",
                "ChangeToReprogGatewayMode",
                "PrepareRetry",
                "IsFinishReprogramming",
                "ProcessBeforeIGOffOnAtRetry",
            )
        ):
            raise ValueError("Private CONTROL replay target/source changed")

    @contextmanager
    def _control_scope2026(self):
        self._validate_control_stage2026()
        target = self._control_target2026
        if self._engine2026._controller_export_target2026 is target:
            yield target
        else:
            with self._engine2026.controller_export_target(
                self._controller2026, target
            ):
                yield target

    def next_alternate_getter2026(self, primary=None):
        """Select only the alternate getter issued by the current native row."""
        from scripts.programming_2026_common import NativeParameterBinding2026

        if self._control_target2026 is not None:
            self._validate_control_stage2026()
            raise ValueError(
                "CONTROL getter continuation must use its newly issued source target"
            )
        if self.operation != "get_cid":
            raise ValueError("Alternate getter requires the actual CID phase")
        selection = primary or self._executed_selection2026
        if self.used and selection != self._executed_selection2026:
            raise ValueError("Alternate getter must retain the executed primary row")
        if selection is None:
            selection, *_ = self._dispatch()
        if type(selection) is not NativeParameterBinding2026:
            raise TypeError("Source-bound native2026 parameter selection required")
        if selection.catalog_sources != self._catalog_sources:
            raise ValueError("Alternate getter source differs from selected catalog")
        selection.validate_against(
            self.container,
            operation="get_cid",
            node=self.node,
            cpu_index=self.context["observations"]["host"].get("cpu_index", 0),
        )
        if self._engine2026 is None:
            raise ValueError("Actual loaded native getter engine required")
        from scripts.cuw_2026 import CUWEngine2026

        assert isinstance(self._engine2026, CUWEngine2026)
        selection = selection.rebind_getter_metadata(
            self._engine2026.metadata_for(
                self.node, self.context["observations"]["host"].get("cpu_index", 0)
            )
        )
        alternate = selection.alternate_cid_binding()
        if alternate is None:
            return None
        following = self.next_session2026(
            "get_cid",
            node=self.node,
            cpu_index=self.context["observations"]["host"].get("cpu_index", 0),
            parameter_binding=alternate,
        )
        following.selected_identity()
        if (
            self.used
            and isinstance(self._executed_selection2026, NativeParameterBinding2026)
            and not self._executed_selection2026.alternate_cid
        ):
            following._alternate_parent2026 = self
        return following

    def alternate_parent2026(self) -> ProgrammingReplay | None:
        """Validate direct source-issued primary→alternate getter continuation."""
        parent = self._alternate_parent2026
        if parent is None:
            return None
        from scripts.cuw_2026 import CUWEngine2026
        from scripts.programming_2026_common import NativeParameterBinding2026

        if (
            type(parent) is not ProgrammingReplay
            or not parent.used
            or self.operation != "get_cid"
            or parent.operation != "get_cid"
            or type(parent._executed_selection2026) is not NativeParameterBinding2026
            or parent._executed_selection2026.alternate_cid
            or type(self._selection2026) is not NativeParameterBinding2026
            or not self._selection2026.alternate_cid
            or not isinstance(self._engine2026, CUWEngine2026)
            or self._engine2026 is not parent._engine2026
            or self._controller2026 is None
            or self._controller2026 is not parent._controller2026
            or self._runtime2026 is None
            or self._runtime2026 is not parent._runtime2026
            or self.trace is not parent.trace
            or self.container.digest != parent.container.digest
            or self._catalog_sources != parent._catalog_sources
            or self._engine2026.source_sha256 != self.container.digest
        ):
            raise ValueError("Alternate getter lineage differs from executed primary")
        return parent

    @property
    def catalog_sources2026(self) -> Mapping[str, bytes]:
        """Immutable selected raw catalog bytes for concrete source controller binding."""
        return MappingProxyType(dict(self._catalog_sources))

    def has_catalog_source2026(self, name: str) -> bool:
        """Test selected raw source presence without parsing its native profile."""
        if (
            not isinstance(name, str)
            or re.fullmatch(r"[A-Za-z0-9_.-]{1,260}", name) is None
        ):
            raise ValueError("Bounded selected catalog filename alias required")
        return name in self._catalog_sources

    def executed_binding2026(
        self, *, engine=None, controller=None
    ) -> NativeParameterBinding2026:
        """Return the immutable binding actually used at native export entry."""
        from scripts.cuw_2026 import CUWEngine2026
        from scripts.programming_2026_common import (
            ControlCommPhase2026,
            NativeParameterBinding2026,
        )

        if engine is not None and engine is not self._engine2026:
            raise ValueError("Executed session belongs to another native engine")
        if controller is not None and (
            type(controller) is not ControlCommPhase2026
            or controller is not self._controller2026
            or self._runtime2026 is not controller.runtime
        ):
            raise ValueError(
                "Executed session belongs to another native controller/runtime"
            )
        selection = self._executed_selection2026
        if (
            not self.used
            or type(selection) is not NativeParameterBinding2026
            or not isinstance(self._engine2026, CUWEngine2026)
            or selection.catalog_sources != self._catalog_sources
            or (
                self._control_target2026 is None
                and self._engine2026.source_sha256 != self.container.digest
            )
            or selection.metadata.source_sha256 != self.container.digest
        ):
            raise ValueError("Executed native source binding and engine required")
        if self._control_target2026 is not None:
            with self._control_scope2026():
                if (
                    selection is not self._control_target2026.binding
                    or self._engine2026.family_metadata
                    != self._control_target2026.metadata
                    or self._engine2026.family_metadata.source_sha256
                    != selection.metadata.source_sha256
                ):
                    raise ValueError(
                        "Executed binding differs from held CONTROL family view"
                    )
        return selection

    def _next_loaded_writer2026(self, operation):
        """Retain the actual writer DLL/parameter row for its auxiliary export."""
        if self._control_target2026 is not None:
            exports = {"recovery": "PrepareRetry", "probe": "IsFinishReprogramming"}
            export = exports.get(operation)
            if export is None:
                raise ValueError("Unknown retained CONTROL writer continuation")
            return self._next_control_export2026(self._control_target2026, export)
        from scripts.cuw_2026 import CUWEngine2026
        from scripts.programming_2026_common import NativeParameterBinding2026

        selection = self._executed_selection2026
        if (
            self.operation != "write"
            or not self.used
            or type(selection) is not NativeParameterBinding2026
            or selection.operation != "write"
            or not isinstance(self._engine2026, CUWEngine2026)
            or selection.catalog_sources != self._catalog_sources
        ):
            raise ValueError(
                "Auxiliary export requires the executed native writer binding"
            )
        cpu_index = self.context["observations"]["host"].get("cpu_index", 0)
        retained = selection.rebind_writer_metadata(
            self._engine2026.metadata_for(self.node, cpu_index)
        )
        return self.next_session2026(
            operation,
            node=self.node,
            cpu_index=cpu_index,
            parameter_binding=retained,
        )

    def next_retry2026(self):
        """Select PrepareRetry from the retained actual writer."""
        return self._next_loaded_writer2026("recovery")

    def next_finish2026(self):
        """Select IsFinishReprogramming from the retained actual writer."""
        return self._next_loaded_writer2026("probe")

    def next_ig_cycle_process2026(self, selected=None):
        """Select the retained phase's literal ProcessBeforeIGOffOnAtRetry export."""
        if self._control_target2026 is not None:
            if (
                selected is not None
                and selected is not self._control_target2026.binding
            ):
                raise ValueError("IG cycle process must retain the issued CONTROL row")
            return self._next_control_export2026(
                self._control_target2026, "ProcessBeforeIGOffOnAtRetry"
            )
        from scripts.cuw_2026 import CUWEngine2026
        from scripts.programming_2026_common import NativeParameterBinding2026

        actual = (
            self._executed_selection2026 if self.used else self.selected_binding2026()
        )
        selection = actual if selected is None else selected
        if (
            self.operation not in ("prepare", "write")
            or type(selection) is not NativeParameterBinding2026
            or selection != actual
            or selection.operation != self.operation
            or selection.catalog_sources != self._catalog_sources
            or not isinstance(self._engine2026, CUWEngine2026)
        ):
            raise ValueError(
                "IG cycle process requires the actual retained phase binding"
            )
        dispatch = selection.dispatch(
            self._module_files,
            module_versions={
                name: module.file_version
                for name, module in self.modules.items()
                if module.file_version is not None
            },
        )
        if (
            "ProcessBeforeIGOffOnAtRetry"
            not in self.modules[dispatch["module"]].exports
        ):
            raise ValueError("Selected native DLL has no IG cycle process export")
        cpu_index = self.context["observations"]["host"].get("cpu_index", 0)
        metadata = self._engine2026.metadata_for(self.node, cpu_index)
        selection = (
            selection.rebind_writer_metadata(metadata)
            if self.operation == "write"
            else selection.rebind_prepare_metadata(metadata)
        )
        return self.next_session2026(
            self.operation,
            node=self.node,
            cpu_index=cpu_index,
            parameter_binding=selection,
            _native_export="ProcessBeforeIGOffOnAtRetry",
        )

    @staticmethod
    def _explicit_control_native_return2026(result):
        """Read only an explicit source-computed BOOL from a family report."""
        if not isinstance(result, dict):
            return None
        if "native_return" in result:
            return result["native_return"]
        native_result = result.get("native_result")
        if isinstance(native_result, dict):
            returned = native_result.get("returned")
            if type(returned) is bool:
                return returned
        return None

    def run_bound2026(self, runtime) -> dict:
        """Run one actual export inside a controller-owned chronological recording.

        The concrete outer controller owns final chronology validation and resource
        lifetime. This method neither closes the runtime nor promotes completion.
        """
        self.bind_runtime2026(runtime)
        from scripts import programming_2026_suzuki_fhi as suzuki2026

        if self._control_target2026 is None:
            selection, module, addresses, node, cpu, vehicle = self._dispatch()
            self._executed_selection2026 = selection
            runner = self._runner(selection, module, addresses, node, cpu, vehicle)
            family = suzuki2026._MAIN_MODULES.get(module.name)
            if family is not None and family[1].startswith("suzuki"):
                with runtime._suzuki_igoffon_wait_scope_2026(
                    self, engine=self._engine2026, controller=self._controller2026
                ):
                    self.used = True
                    result = runner()
            else:
                self.used = True
                result = runner()
        else:
            self._validate_control_stage2026()
            with self._engine2026.controller_export_target(
                self._controller2026, self._control_target2026
            ):
                selection, module, addresses, node, cpu, vehicle = self._dispatch()
                self._executed_selection2026 = selection
                runner = self._runner(selection, module, addresses, node, cpu, vehicle)
                self._engine2026._record_getter_protocol_ingress2026(self)
                family = suzuki2026._MAIN_MODULES.get(module.name)
                if family is not None and family[1].startswith("suzuki"):
                    with runtime._suzuki_igoffon_wait_scope_2026(
                        self,
                        engine=self._engine2026,
                        controller=self._controller2026,
                    ):
                        self.used = True
                        result = runner()
                else:
                    self.used = True
                    result = runner()
                if (
                    isinstance(result, dict)
                    and self._control_export2026 == "StartGetCID"
                ):
                    from scripts import programming_2026_common as common2026

                    record_getter = getattr(
                        common2026,
                        "_record_control_getter_family_return2026",
                        None,
                    )
                    if not callable(record_getter):
                        raise RuntimeError(
                            "CONTROL getter return receipt producer is pending"
                        )
                    record_getter(self._control_target2026, result)
                if isinstance(result, dict) and self._control_export2026 in (
                    "StartPrepareWrite",
                    "StartFlashWrite",
                ):
                    returned = self._explicit_control_native_return2026(result)
                    if type(returned) is bool:
                        from scripts import programming_2026_common as common2026

                        record_return = getattr(
                            common2026, "_record_control_family_return2026", None
                        )
                        if not callable(record_return):
                            raise RuntimeError(
                                "CONTROL family return receipt producer is pending"
                            )
                        record_return(
                            self._control_target2026,
                            self._control_export2026,
                            returned,
                        )
        runtime.check()
        if not isinstance(result, dict):
            raise TypeError("Native2026 export must return an actual result mapping")
        native_return = result.get("native_return")
        if "native_return" not in result:
            explicit = result.get("native_result")
            if isinstance(explicit, dict) and type(explicit.get("returned")) is bool:
                native_return = explicit["returned"]
        if native_return is not None and type(native_return) is not bool:
            raise TypeError("Native export return must be explicit Boolean or unknown")
        return {**result, "native_return": native_return}

    def _metadata(self):
        parser, metadata_version = _metadata_parser(self.container.attached.data)
        sections = {name.casefold(): dict(parser[name]) for name in parser.sections()}
        vehicle = sections.get("vehicle", {})
        node = sections.get(f"node{self.node:02}", {})
        from scripts.calibration import native_selection_metadata

        metadata = native_selection_metadata(
            self.container,
            node=self.node,
            cpu_index=0,
        )
        kind, contact, cpu_type = (
            metadata[key] for key in ("kind_of_ecu", "contact_type", "cpu_type")
        )
        if any(module.kind == "authored_fixture" for module in self.modules.values()):
            # Exact fixture bytes select an explicit demo recipe, never OEM metadata.
            cpu_type = "DEMO"
        cpu = {}
        if metadata_version < 101 or metadata["required_spec"] == "02":
            from scripts.calibration import bind_native_cpu_records

            cpus = bind_native_cpu_records(self.container)
            index = self.context["observations"]["host"].get("cpu_index", 0)
            if type(index) is not int or not 0 <= index < len(cpus):
                raise ValueError("Native CPU index is outside imported metadata")
            cpu = dict(cpus[index].values)
        return kind, contact, cpu_type, node, cpu, vehicle

    def _dispatch2026(self):
        from scripts.programming_2026_common import bind_parameter2026

        if self._control_target2026 is not None:
            if (
                self._engine2026._controller_export_target2026
                is not self._control_target2026
            ):
                with self._control_scope2026():
                    return self._dispatch2026()
            self._validate_control_stage2026()
            from scripts import programming_2026_common as common2026

            target = self._control_target2026
            export = self._control_export2026
            if export is None:
                raise ValueError("CONTROL export name is missing")
            dispatch_lookup = getattr(common2026, "_control_export_dispatch2026", None)
            if not callable(dispatch_lookup):
                raise RuntimeError(
                    "Native CONTROL dispatch receipt producer is pending"
                )
            receipt = dispatch_lookup(target, export)
            address_lookup = getattr(common2026, "_control_helper_addresses2026", None)
            if not callable(address_lookup):
                raise RuntimeError("Native CONTROL helper address receipt is pending")
            addresses = address_lookup(target)
            if type(addresses) is not tuple:
                raise ValueError(
                    "Immutable source-preflighted CONTROL addresses required"
                )
            receipt_fields = {
                "module",
                "operation",
                "required_exports",
                "selectors",
                "identity",
                "module_version_checked",
                "source_name",
                "source_sha256",
                "key",
            }
            if (
                type(receipt) is not type(MappingProxyType({}))
                or set(receipt) != receipt_fields
            ):
                raise ValueError(
                    "Exact source-issued CONTROL dispatch receipt required"
                )
            expected_operation = {
                "StartGetCID": "get_cid",
                "StartPrepareWrite": "prepare",
                "StartFlashWrite": "write",
                "ChangeToReprogGatewayMode": "change_gateway",
                "PrepareRetry": "recovery",
                "IsFinishReprogramming": "probe",
                "ProcessBeforeIGOffOnAtRetry": target.binding.operation,
            }[export]
            metadata = target.metadata
            binding = target.binding
            module_binding = target.module_binding
            module_name = receipt["module"]
            module = self.modules.get(module_name)
            required = receipt["required_exports"]
            if (
                receipt["operation"] != export
                or self.operation != expected_operation
                or module is None
                or type(module.native_identity) is not type(receipt["identity"])
                or module.native_identity != receipt["identity"]
                or receipt["identity"].sha256 != module.sha256
                or module.name != module_binding.module_name
                or receipt["module"] != module_binding.module_name
                or module.sha256 != receipt["identity"].sha256
                or receipt["source_name"] != binding.source_name
                or receipt["source_sha256"] != binding.source_sha256
                or receipt["key"] != binding.key
                or receipt["module_version_checked"] is not True
                or not isinstance(required, tuple)
                or export not in required
                or any(name not in module.exports for name in required)
                or any(
                    name not in receipt["identity"].callable_exports
                    for name in required
                )
                or receipt["selectors"] != binding.selector_functions
            ):
                raise ValueError("CONTROL dispatch receipt differs from held source")
            return (
                binding,
                module,
                list(addresses),
                dict(metadata.node_values),
                dict(metadata.cpu.values) if metadata.cpus else {},
                dict(metadata.vehicle),
            )

        observations = self.context["observations"]
        host = observations["host"]
        stage = "write" if self.operation in ("recovery", "probe") else self.operation
        metadata_state = None
        if self._engine2026 is not None:
            from scripts.cuw_2026 import CUWEngine2026

            assert isinstance(self._engine2026, CUWEngine2026)
            metadata_state = self._engine2026.metadata_for(
                self.node, host.get("cpu_index", 0)
            )
        if self._selection2026 is not None:
            from scripts.programming_2026_common import NativeParameterBinding2026

            if (
                type(self._selection2026) is not NativeParameterBinding2026
                or self._selection2026.metadata != metadata_state
                or not (
                    (self.operation == "get_cid" and self._selection2026.alternate_cid)
                    or (
                        self.operation in ("recovery", "probe")
                        and self._selection2026.operation == "write"
                    )
                    or (
                        self.operation in ("prepare", "write")
                        and self._selection2026.operation == self.operation
                        and self._retained_export2026 == "ProcessBeforeIGOffOnAtRetry"
                    )
                )
                or self._selection2026.catalog_sources != self._catalog_sources
            ):
                raise ValueError("Retained native export differs from current target")
            binding = self._selection2026.validate_against(
                self.container,
                operation=stage,
                node=self.node,
                cpu_index=host.get("cpu_index", 0),
            )
        else:
            binding = bind_parameter2026(
                self.container,
                self._catalog_sources,
                stage,
                node=self.node,
                cpu_index=host.get("cpu_index", 0),
                metadata_state=metadata_state,
            )
        dispatch = binding.dispatch(
            self._module_files,
            module_versions={
                name: module.file_version
                for name, module in self.modules.items()
                if module.file_version is not None
            },
        )
        module = self.modules[dispatch["module"]]
        metadata = binding.metadata
        addresses = []
        return (
            binding,
            module,
            addresses,
            dict(metadata.node_values),
            (dict(metadata.cpu.values) if metadata.cpus else {}),
            dict(metadata.vehicle),
        )

    def _dispatch(self):
        if any(module.build == 2026 for module in self.modules.values()):
            return self._dispatch2026()
        kind, contact, cpu_type, node, cpu, vehicle = self._metadata()
        stage = (
            "write"
            if self.operation in ("recovery", "probe")
            else "gateway"
            if self.operation == "change_gateway"
            else self.operation
        )
        selection = self.catalog.select_metadata(
            kind,
            cpu_type,
            contact,
            stage=stage,
            required_spec=node.get("requiredspecreprover", "02"),
        )
        observations = self.context["observations"]
        diag = node.get("diagid", "")
        location = cpu.get("locationid", "")
        context = SelectionContext(
            tuple(observations["current_cids"]),
            _hex(location, 8) if location else None,
            (_hex(diag, 3),) if diag else (),
        )
        dispatch = selection.dispatch(
            stage,
            context,
            {name: module.exports for name, module in self.modules.items()},
            module_versions={
                name: module.file_version
                for name, module in self.modules.items()
                if module.file_version is not None
            },
        )
        module = self.modules[dispatch["module"]]
        addresses = dispatch["addresses"]
        return selection, module, addresses, node, cpu, vehicle

    def run(self, operation: str | None = None, node: int | None = None):
        if self.used or self.trace.position:
            raise ValueError("Programming replay is single-use; no blind resume")
        if (
            operation is not None
            and operation != self.operation
            or node is not None
            and node != self.node
        ):
            raise ValueError(
                "Requested operation differs from captured programming context"
            )
        # Complete metadata/source preflight before consuming any captured event.
        try:
            selection, module, addresses, node_values, cpu_values, vehicle = (
                self._dispatch()
            )
            self._executed_selection2026 = selection
            runner = self._runner(
                selection, module, addresses, node_values, cpu_values, vehicle
            )
        except (Exception, KeyboardInterrupt):  # noqa: BLE001 - suppress supplied metadata and secret values
            raise ValueError("Imported native programming preflight failed") from None
        self.used = True
        report: dict[str, Any]
        deadline = self.trace.clock() + self.context["observations"]["timeout_seconds"]
        result = None
        try:
            result = runner()
            if self.trace.cancelled():
                raise InterruptedError("Programming workflow cancelled after callback")
            if self.trace.clock() >= deadline:
                raise TimeoutError(
                    "Programming workflow deadline expired after callback"
                )
            if not isinstance(result, dict):
                raise TypeError("Native runner returned an invalid result")
            if result.get("state") == "complete":
                result = {
                    **result,
                    "state": {
                        "get_cid": "read_completed",
                        "prepare": "prepare_completed",
                        "change_gateway": "gateway_completed",
                        "write": "writer_completed",
                        "recovery": "prepare_retry_completed",
                    }[self.operation],
                }
            if result.get("state") == "writer_completed" and self.operation in (
                "prepare",
                "recovery",
            ):
                result = {
                    **result,
                    "state": "prepare_completed"
                    if self.operation == "prepare"
                    else "prepare_retry_completed",
                }
            successful = result.get("state") in (
                "writer_completed",
                "prepare_completed",
                "preparation_completed",
                "read_completed",
                "recovery_completed",
                "probe_completed",
                "prepare_retry_completed",
                "gateway_completed",
                "gateway_skipped",
            )
            if successful:
                self.trace.assert_complete()
            report = _report(result)
            if not successful:
                report["state"] = (
                    "recovery_required"
                    if self.trace.position
                    else "cancelled"
                    if self.trace.cancelled() or result.get("state") == "cancelled"
                    else "failed"
                )
        except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - retain uncertainty without exposing native buffers
            report = {}
            if isinstance(result, dict):
                try:
                    report = _report(result)
                except (ValueError, UnicodeError, TypeError):
                    pass
            report.update(
                state="recovery_required"
                if self.trace.position
                else "cancelled"
                if isinstance(exc, InterruptedError)
                else "failed",
                error_type=type(exc).__name__,
            )
            from scripts.programming_2026_m16c import NativeWriterState2026

            native_state = getattr(exc, "native_state", None)
            if isinstance(native_state, NativeWriterState2026):
                report["native_result"] = _writer_state(native_state.report())
            native_code = getattr(exc, "native_cuw_code", None)
            if type(native_code) is int and 0 <= native_code <= 0xFFFFFFFF:
                report["native_error_code"] = native_code
                from scripts.programming import NativeNegativeResponse

                if isinstance(exc, NativeNegativeResponse):
                    report["negative_response_code"] = exc.code
        final = {
            **report,
            "operation": self.operation,
            "node": self.node,
            "source_identity": {
                "kind": module.kind,
                "module": module.name,
                "sha256": module.sha256,
                "native_build": module.build,
                "artifact_form": module.native_identity.artifact_form
                if module.native_identity is not None
                else "authored_metadata_fixture",
            },
            "input_hashes": self.input_hashes,
            "events_consumed": self.trace.position,
            "events_remaining": len(self.trace.rows) - self.trace.position,
            "programming_completed": False,
            "physical_status": "PHYSICAL_UNCONFIRMED",
            "automatic_retry": False,
            "resume_authorized": False,
        }
        self._last_report = json.loads(json.dumps(final))
        return final

    def export_result(self, destination, *, input_paths):
        if self._last_report is None:
            raise ValueError("Run the captured programming workflow before export")
        export_programming_report(
            self._last_report, destination, input_paths=input_paths
        )

    def _security(self, purpose, *inputs):
        if self.trace.position >= len(self.trace.rows):
            raise ValueError("Explicit selected authorization attachment required")
        event = self.trace.rows[self.trace.position]
        alias = event["request"].get("attachment")
        if event["kind"] != "security" or alias not in self.attachments:
            raise ValueError("Explicit chronological authorization attachment required")
        aliases = self.context["observations"]["host"].get("security_attachments", {})
        if aliases and aliases.get(purpose) != alias:
            raise ValueError(
                "Authorization alias differs from explicit captured binding"
            )
        return self.trace.consume(
            "security",
            {
                "operation": purpose,
                "input_hex": [value.hex() for value in inputs],
                "attachment": alias,
            },
        )

    def _runner(self, selection, module, addresses, node, cpu, vehicle):
        from scripts import programming
        from scripts.programming_cid import ChargeBus, CIDNode, get_cids

        observations = self.context["observations"]
        if self.operation == "change_gateway" and (
            module.native_identity is None
            or "ChangeToReprogGatewayMode" not in module.exports
        ):
            raise ValueError("Selected source has no actual gateway-mode export")
        if self.operation == "recovery":
            requested = (
                observations["host"].get("native2026", {}).get("export", "PrepareRetry")
            )
            if (
                requested not in ("PrepareRetry", "ProcessBeforeIGOffOnAtRetry")
                or requested not in module.exports
            ):
                raise ValueError(
                    "Selected source has no recovered requested retry export"
                )
        if self.operation == "probe" and "IsFinishReprogramming" not in module.exports:
            raise ValueError("Selected source has no native finish probe export")
        current_cids = tuple(observations["current_cids"])
        tester = _hex(observations["tester_info_hex"], 32)
        system_time = tuple(observations["system_time"])
        timeout = observations["timeout_seconds"]
        from scripts import programming_legacy as legacy

        if module.build == 2026:
            return self._runner2026(selection, module, addresses)
        if self.operation == "probe":
            address = legacy.bind_legacy_finish_probe(
                self.container, self.node, selection, module.native_identity
            )
            row = address.report()
            stream = self.trace.raw_stream(address.request.hex(), timeout)

            def lifecycle(operation, parameters, remaining):
                values = dict(parameters)
                if operation == "start_filter":
                    if values.pop("target_index") != 0:
                        raise ValueError("Native finish probe requires CPU0")
                    values["addresses"] = [row]
                result = self.trace.action(
                    {"operation": operation, **values}, remaining
                )
                if type(result) is not (
                    int if operation == "start_filter" else type(None)
                ):
                    raise TypeError(
                        "Native finish-probe lifecycle result has incorrect type"
                    )
                return result

            return lambda: {
                "state": "probe_completed",
                "finished": legacy.legacy_is_finished(
                    module.name, stream, lifecycle=lifecycle
                ),
            }
        if module.family in (
            "TCUWCanM16CFlashWriter",
            "TCUWCanSecurityM16CFlashWriter",
            "TCUWCanSecurityVFORESTFlashWriter",
        ):
            return self._m16c_runner(selection, module, timeout)
        if module.name in legacy._WRITERS | legacy._PREPARERS or module.name in (
            "TCUWP4P5CanCIDGetter.dll",
            "TCUWP5CanCIDGetter.dll",
            "TCUWP5CanCIDGetterWithSetBS.dll",
        ):
            return self._legacy_runner(selection, module, timeout)
        if not addresses:
            raise ValueError("Selected native family requires communication addresses")
        first = addresses[0]
        ecu = first["request_hex"]
        common = {
            "timeout": timeout,
            "cancelled": self.trace.cancelled,
            "clock": self.trace.clock,
            "receive": self.trace.receive,
        }
        from scripts.programming_vendor import VendorP5Channel

        native_controls, _ = self._controls([first], self.trace.clock() + timeout)

        def channel_factory(*args, **kwargs):
            return VendorP5Channel(
                *args,
                **kwargs,
                get_timeout=native_controls.get_timeout,
                set_timeout=native_controls.set_timeout,
                minimum_response_timeout_ms=5530,
            )

        family = module.family
        host = observations["host"]
        if self.operation == "write" and family in (
            "TCUWCanUnifiedFlashWriter",
            "TCUWCanUnifiedFlashWriterEachArea",
        ):
            if module.build == 12 and family.endswith("EachArea"):
                raise ValueError("Unified EachArea module is absent from CUW12")
            from scripts.calibration import bind_native_cpu_records

            cpu_index = host.get("cpu_index", 0)
            cpus = bind_native_cpu_records(self.container)
            if type(cpu_index) is not int or not 0 <= cpu_index < len(cpus):
                raise ValueError(
                    "Selected Unified CPU index is outside imported metadata"
                )
            if (cpus[cpu_index].node or 1) != self.node:
                raise ValueError(
                    "Selected Unified CPU belongs to a different native node"
                )
            program = programming.native_unified_program(
                self.container,
                cpu_index,
                current_cids,
                extended_addressing=first["extended"],
            )
            pending_timeout = programming.native_unified_pending_timeout(
                self.container, cpu_index, native_build=module.build
            )
            return lambda: programming.unified_write(
                self.trace.platform,
                self.trace.exchange,
                ecu,
                program,
                each_area=family.endswith("EachArea"),
                native_build=module.build,
                pending_response_timeout_seconds=pending_timeout,
                channel_factory=channel_factory,
                **common,
            )
        if self.operation == "prepare" and family in (
            "TCUWCanReproStdPrepareWriter",
            "TCUWCanUnifiedPrepareWriter",
        ):
            if module.build == 12 and family == "TCUWCanReproStdPrepareWriter":
                raise ValueError("ReproStd preparation module is absent from CUW12")
            values = {
                "gateway_kind": host["gateway_kind"] if module.build == 18 else 0,
                "extended_addressing": first["extended"],
            }
            if family == "TCUWCanReproStdPrepareWriter":
                context: Any = programming.native_reprostd_prepare_context(
                    self.container, self.node, **values
                )
                function = programming.reprostd_prepare
            else:
                from scripts.calibration import bind_native_cpu_records

                cpus = bind_native_cpu_records(self.container)
                cpu_index = host.get("cpu_index", 0)
                if type(cpu_index) is not int or not 0 <= cpu_index < len(cpus):
                    raise ValueError(
                        "Native Unified preparation CPU is outside metadata"
                    )
                if (cpus[cpu_index].node or 1) != self.node:
                    raise ValueError("Native Unified preparation CPU/node mismatch")
                context = programming.native_unified_prepare_context(
                    self.container,
                    cpus[cpu_index].node,
                    native_flag_724=host[
                        "native_flag_724" if module.build == 18 else "native_flag_5e8"
                    ],
                    **values,
                )
                function = programming.unified_prepare
            version_options = (
                {
                    "native_build": module.build,
                    "pending_response_timeout_seconds": programming.native_unified_pending_timeout(
                        self.container, cpu_index, native_build=module.build
                    ),
                }
                if family == "TCUWCanUnifiedPrepareWriter"
                else {}
            )

            def prepare_action(event, remaining):
                if event != {"operation": "judge_reprogramming_gateway"}:
                    return self.trace.platform(event, remaining)
                from scripts import programming_vendor as vendor

                if module.build != 18:
                    raise ValueError("Native gateway classification is absent in CUW12")
                controls, _ = self._controls(
                    [
                        {
                            "request_hex": "07505f",
                            "response_hex": "07585f",
                            "extended": True,
                        }
                    ],
                    self.trace.clock() + remaining,
                )
                old = self._diagnostic(
                    "07505f",
                    remaining,
                    True,
                    controls,
                    extension=0x5F,
                    response_extension=0x5F,
                )
                p5 = self._diagnostic(
                    "07505f",
                    remaining,
                    False,
                    controls,
                    minimum_response_timeout_ms=5530,
                    pending_expiry_write=True,
                )
                assert isinstance(old, vendor.VendorDiagnosticChannel)
                assert isinstance(p5, vendor.VendorP5Channel)
                token = None
                error = None
                gateway_kind = None
                try:
                    token = controls.start_filter()
                    gateway_kind = vendor.common_judge_gateway(old, p5)
                except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - stop the native filter on every host failure
                    error = exc
                finally:
                    if token is not None:
                        try:
                            controls.stop_filter(token)
                        except (Exception, KeyboardInterrupt) as cleanup:  # noqa: BLE001 - retain primary failure through cleanup
                            if error is None:
                                error = cleanup
                            else:
                                error.__dict__["cleanup_error_details"] = [
                                    {
                                        "phase": "stop_filter",
                                        **vendor._native_error_info(cleanup),
                                    }
                                ]
                try:
                    if self.trace.cancelled():
                        raise InterruptedError(
                            "Native gateway classification cancelled"
                        )
                    if self.trace.clock() >= old.deadline:
                        raise TimeoutError(
                            "Native gateway classification deadline expired"
                        )
                except (InterruptedError, TimeoutError) as boundary:
                    if error is not None:
                        boundary.__dict__["observed_native_error"] = (
                            vendor._native_error_info(error)
                        )
                        cleanup_details = getattr(error, "cleanup_error_details", None)
                        if isinstance(cleanup_details, list):
                            boundary.__dict__["cleanup_error_details"] = cleanup_details
                    error = boundary
                if error is not None:
                    raise error
                return gateway_kind

            return lambda: function(
                prepare_action,
                self.trace.exchange,
                ecu,
                context,
                self._security,
                channel_factory=channel_factory,
                **version_options,
                **common,
            )
        if self.operation == "write" and family in (
            "TCUWCanReproStdFlashWriter",
            "TCUWEthernetReprostdFlashWriter",
        ):
            blocks = programming.native_reprostd_blocks(
                self.container, self.node, current_cids, tester, system_time
            )
            if family == "TCUWEthernetReprostdFlashWriter":
                return lambda: programming.ethernet_write(
                    self.trace.platform,
                    self.trace.exchange,
                    ecu,
                    _hex(ecu, 2),
                    blocks,
                    **common,
                )
            return lambda: programming.reprostd_write(
                self.trace.platform,
                self.trace.exchange,
                ecu,
                blocks,
                extended_addressing=first["extended"],
                channel_factory=channel_factory,
                **common,
            )
        if self.operation == "get_cid" and family in (
            "TCUWCanUnifiedCIDGetter",
            "TCUWEthernetCIDGetter",
        ):
            parser, metadata_version = _metadata_parser(self.container.attached.data)
            wake_ms = int(node.get("wakeuptimeafterreset", "0")) * 50
            charge_bus = None
            if family == "TCUWCanUnifiedCIDGetter" and metadata_version < 101:
                raise ValueError(
                    "Historical Unified CID node association requires recovered constructor binding"
                )
            if family == "TCUWCanUnifiedCIDGetter" and metadata_version >= 101:
                from scripts.calibration import (
                    bind_native_cpu_records,
                    bind_native_logical_records,
                )

                required = node.get("requiredspecreprover", "02")
                rows = (
                    bind_native_cpu_records(self.container)
                    if required == "02"
                    else bind_native_logical_records(self.container)
                )
                times = [
                    int(row.node_values.get("wakeuptimeafterreset", "0")) * 50
                    for row in rows
                ]
                if any(not 0 <= value <= 120000 for value in times):
                    raise ValueError("Native CID wake time exceeds host bounds")
                wake_ms = max(times, default=0)
                if module.build == 18:
                    values = {
                        name.casefold(): dict(parser[name])
                        for name in parser.sections()
                    }
                    count = int(values.get("vehicle", {}).get("numberofnode", "0"))
                    if not 0 <= count <= 9:
                        raise ValueError("Native CID node count exceeds host bounds")
                    for index in range(1, count + 1):
                        item = values.get(f"node{index:02}", {})
                        if item.get("chargelocalbusecureprogrammingflow", "") == "01":
                            request_id = _hex(
                                item.get(
                                    "chargelocalbuspoweroncontrollingecudiagid", ""
                                ),
                                2,
                            )
                            if len(request_id) != 2:
                                raise ValueError(
                                    "Native charge controller requires two bytes"
                                )
                            response_id = bytes(
                                (request_id[0], (request_id[1] + 8) & 255)
                            )
                            delay = (
                                int(
                                    item.get(
                                        "chargelocalbusecustarttimeafterpoweron", "0"
                                    )
                                )
                                * 50
                            )
                            charge_bus = ChargeBus(
                                CIDNode(request_id, response_id), delay
                            )
                            break
            allowed = (
                selection.value("RequestCANIDAllowingTimeout")
                if family == "TCUWCanUnifiedCIDGetter"
                else ""
            )
            timeout_allowing_id = _hex(allowed, 3) if allowed else None
            nodes = tuple(
                CIDNode(
                    _hex(row["request_hex"], 3),
                    _hex(row["response_hex"], 3),
                    row["extended"],
                    wake_ms,
                )
                for row in addresses
            )
            receive_timeout = int(selection.value("ReceiveTimeoutBeforeGetCID"))
            return lambda: {
                "state": "read_completed",
                **get_cids(
                    self.trace.action,
                    self.trace.exchange,
                    nodes,
                    family="ethernet"
                    if family == "TCUWEthernetCIDGetter"
                    else "unified",
                    mode=observations["cid_mode"],
                    version=module.build,
                    receive_timeout_ms=receive_timeout,
                    charge_bus=charge_bus,
                    timeout_allowing_id=timeout_allowing_id,
                    channel_factory=channel_factory
                    if family == "TCUWCanUnifiedCIDGetter"
                    else None,
                    **common,
                ),
            }
        return self._vendor_runner(selection, module, addresses, timeout)

    def _runner2026(self, selection, module, addresses):
        from scripts import programming_2026_body as body2026
        from scripts import programming_2026_p5_getters as p5getters2026
        from scripts import programming_2026_p5_prepare as p5prepare2026
        from scripts import programming_2026_unified as unified2026
        from scripts.programming_2026_common import NativeRuntime2026
        from scripts.programming_2026_sil import (
            SIL_OPERATIONS,
            SILCIDState2026,
            bind_context,
            execute_context_report,
        )

        dh_modules = {
            "TCUWCanDHUDSSoftwareIDGetter.dll",
            "TCUWCanDHSoftMaskIDGetter.dll",
            "TCUWCanDHSoftwareIDAndSoftMaskIDGetter.dll",
            "TCUWP5CanDHVehicleInfoCIDGetter.dll",
            "TCUWCanDHSoftwareIDGetter.dll",
            "TCUWCanDHWritableCIDGetter.dll",
            "TCUWCanDHWritableSoftMaskIDAndCIDGetter.dll",
            "TCUWCanDHPrepareWriter.dll",
            "TCUWCanDHFlashWriter.dll",
            "TCUWCanDHGatewayPrepareWriter.dll",
            "TCUWCanDHUDSPrepareWriter.dll",
            "TCUWCanDHUDSFlashWriter.dll",
            "TCUWP5CanDHUDSFlashWriter.dll",
            "TCUWCanDHGatewayFlashWriter.dll",
            "TCUWCanDH19PFSURegGatewayPrepareWriter.dll",
            "TCUWCanDH19PFSURegGatewayFlashWriter.dll",
            "TCUWP5CanDHUDSPrepareWriter.dll",
            "TCUWCanDHMultiROMPrepareWriter.dll",
            "TCUWCanDHMultiROMFlashWriter.dll",
        }
        observed = self.context["observations"]
        host = observed["host"]
        aliases = host.get("native2026_attachments", {})
        if not isinstance(aliases, dict) or any(
            alias not in self.attachments for alias in aliases.values()
        ):
            raise ValueError("Explicit selected2026 attachment aliases required")
        material = {name: self.attachments[alias] for name, alias in aliases.items()}
        values = dict(host.get("native2026", {}))
        values.setdefault("cpu_index", host.get("cpu_index", 0))
        if (
            module.name not in dh_modules
            and self._control_target2026 is not None
            and self._control_export2026
            in (
                "PrepareRetry",
                "IsFinishReprogramming",
                "ProcessBeforeIGOffOnAtRetry",
            )
        ):
            values["export"] = self._control_export2026
        if isinstance(values.get("target_indices"), list):
            values["target_indices"] = tuple(values["target_indices"])
        if values.get("previous_addresses") == []:
            values["previous_addresses"] = ()
        if self._controller2026 is not None:
            from scripts.programming_2026_common import ControlCommPhase2026

            assert isinstance(self._controller2026, ControlCommPhase2026)
            if values.get("previous_addresses"):
                raise ValueError(
                    "Native controller owns the communication-address history"
                )
            if (
                module.name not in SIL_OPERATIONS
                and module.name not in body2026.IMPLEMENTED_EXPORTS
                and module.name not in body2026._WRITER_MODULES
                and module.name not in p5getters2026.IMPLEMENTED_EXPORTS
                and module.name not in p5prepare2026.IMPLEMENTED_EXPORTS
                and module.name
                not in unified2026._GETTERS
                | unified2026._PREPARERS
                | unified2026._WRITERS
                and module.name != "TCUWCanCIDGetter.dll"
            ):
                values["previous_addresses"] = tuple(
                    self._controller2026.address_history
                )
        runtime = self._runtime2026
        if runtime is None:
            native_cancelled = None
            if self._engine2026 is not None:
                from scripts.cuw_2026 import CUWEngine2026

                assert isinstance(self._engine2026, CUWEngine2026)
                native_cancelled = self._engine2026.native_cancelled
            runtime = NativeRuntime2026(
                self.trace.action,
                timeout=observed["timeout_seconds"],
                clock=self.trace.clock,
                cancelled=self.trace.cancelled,
                native_cancelled=native_cancelled,
                max_calls=_uint(host.get("native_max_calls", 65536), MAX_STREAM_EVENTS),
                local_seconds_of_day=self.trace.native_local_seconds_of_day,
                local_milliseconds_of_day=self.trace.native_local_milliseconds_of_day,
            )
        if not isinstance(runtime, NativeRuntime2026):
            raise TypeError("Concrete bound native2026 runtime required")
        self._bind_recorded_transport2026(runtime)
        self._bind_online2026(runtime, host)
        from scripts import programming_2026_p6 as p62026

        if module.name in body2026._WRITER_MODULES and self.operation == "write":
            from scripts.cuw_2026 import CUWEngine2026

            if not isinstance(self._engine2026, CUWEngine2026):
                raise ValueError("Actual retained writer engine/worker required")
            values.pop("cpu_index", None)
            if set(values) & {
                "target_index",
                "retry_password",
                "native_initial_command_retry_980",
            }:
                raise ValueError(
                    "Retained writer state must originate from native worker"
                )
            values["target_index"] = self._engine2026.native_writer_target_index
            values["retry_password"] = self._engine2026.dh_state.use_new_password
            if module.name in (body2026._SONAR_WRITER, *body2026._SHRINK_WRITERS):
                values["native_initial_command_retry_980"] = (
                    self._engine2026.native_initial_command_retry980
                )
            context = body2026.bind_native_context(
                self.container,
                self.node,
                tuple(observed["current_cids"]),
                selection,
                module.native_identity,
                material,
                values,
            )

            def run_body_writer():
                result = body2026.run_native_context(
                    context, runtime, engine=self._engine2026
                )
                return {
                    **result,
                    "state": "writer_completed"
                    if result.get("state") == "write_completed"
                    else result.get("state"),
                    "programming_completed": False,
                }

            return run_body_writer

        if self.operation == "probe" and module.name in body2026._FINISH_WRAPPERS:
            values.pop("cpu_index", None)
            context = body2026.bind_finish_context(
                self.container,
                self.node,
                tuple(observed["current_cids"]),
                selection,
                module.native_identity,
                material,
                values,
            )

            def run_body_probe():
                finished = body2026.is_finish_reprogramming(
                    context.identity, runtime, context.groups
                )
                return {
                    "state": "probe_completed",
                    "finished": finished,
                    "native_return": finished,
                    "native_success": None,
                }

            return run_body_probe
        if (
            module.name in body2026.IMPLEMENTED_EXPORTS
            and self.operation in ("prepare", "change_gateway")
            and "StartPrepareWrite" in body2026.IMPLEMENTED_EXPORTS[module.name]
        ):
            values.pop("cpu_index", None)
            expected_export = (
                "ChangeToReprogGatewayMode"
                if self.operation == "change_gateway"
                else "StartPrepareWrite"
            )
            export = values.pop("export", expected_export)
            if self.operation == "change_gateway" and export != expected_export:
                raise ValueError("Native gateway phase requires its exact export")
            if export not in body2026.IMPLEMENTED_EXPORTS[module.name]:
                raise ValueError("Unknown selected body preparation export")
            from scripts.cuw_2026 import CUWEngine2026

            if not isinstance(self._engine2026, CUWEngine2026):
                raise ValueError("Actual native preparation engine state required")
            if module.name == body2026._P4_POWERTRAIN:
                if "native_retry_flag_964" in values:
                    raise ValueError(
                        "Native preparation state must originate from engine"
                    )
                values["native_retry_flag_964"] = (
                    self._engine2026.dh_state.native_context_964
                )
            context = body2026.bind_native_context(
                self.container,
                self.node,
                tuple(observed["current_cids"]),
                selection,
                module.native_identity,
                material,
                values,
            )
            options: dict[str, Any] = {}
            if module.name in body2026._CHASSIS:
                options["completion_notification"] = self._engine2026.notification
            else:
                options["retry_notification"] = self._engine2026.notification
            if module.name == body2026._CENTRAL_GATEWAY:
                options["engine"] = self._engine2026
            if export == "ChangeToReprogGatewayMode":
                options["gateway_only"] = True
            if module.name in (
                body2026._SECURITY_AIRBAG,
                "TCUWP4CanSecurityChassisShrinkPrepareWriter.dll",
            ):
                from scripts.programming_2026_common import NativeSecurityComposer2026

                composer = NativeSecurityComposer2026.from_native_modules(
                    self._module_files["SecretInfo.dll"], self._module_files["CUW.dll"]
                )
                runtime.bind_security_composer(composer)
                options["secret_info"] = composer.client
            return lambda: body2026.run_native_context(context, runtime, **options)
        if module.name in p5prepare2026.IMPLEMENTED_EXPORTS:
            values.pop(
                "cpu_index", None
            )  # Actual selected CPU is retained by the native binding.
            context = p5prepare2026.bind_native_context(
                self.container,
                self.node,
                tuple(observed["current_cids"]),
                selection,
                module.native_identity,
                material,
                values,
            )
            if self._engine2026 is None:
                raise ValueError(
                    "Native preparation notification requires the loaded engine"
                )
            from scripts.cuw_2026 import CUWEngine2026

            assert isinstance(self._engine2026, CUWEngine2026)
            notification = self._engine2026.notification
            secret_info = None
            if module.name == p5prepare2026.SECURITY:
                from scripts.programming_2026_common import NativeSecurityComposer2026

                composer = NativeSecurityComposer2026.from_native_modules(
                    self._module_files["SecretInfo.dll"], self._module_files["CUW.dll"]
                )
                runtime.bind_security_composer(composer)
                secret_info = composer.client
            return lambda: p5prepare2026.run_native_context(
                context,
                runtime,
                retry_notification=notification,
                secret_info=secret_info,
            )
        if module.name in p5getters2026.IMPLEMENTED_EXPORTS:
            if material or set(values) - {"cpu_index"}:
                raise ValueError("Native P5 getter has no captured state override")
            context = p5getters2026.bind_native_context(
                self.container,
                self.node,
                tuple(observed["current_cids"]),
                selection,
                module.native_identity,
                {},
                {},
            )
            return lambda: p5getters2026.run_native_context(context, runtime)

        if module.name in p62026.MODULE_OPERATIONS:
            values.setdefault("stage", selection.operation)
            if module.file_version is not None:
                values["module_version"] = module.file_version
            dependencies = [("selected_module", module.name)]
            if (
                selection.operation == "prepare"
                and values.get("export") != "ProcessBeforeIGOffOnAtRetry"
                and module.name == "TCUWP6CanReprostdPrepareWriter.dll"
            ):
                dependencies.extend(
                    (
                        ("secret_info_module", "SecretInfo.dll"),
                        ("cuw_module", "CUW.dll"),
                    )
                )
            for alias, name in dependencies:
                if name in self._module_files:
                    data = self._module_files[name]
                    if alias in material and material[alias] != data:
                        raise ValueError(
                            "Native P6 dependency differs from selected source"
                        )
                    material[alias] = data
            if "dh_state" in values or "dcm_getter_state" in values:
                raise ValueError("P6/DCM state must originate from the loaded engine")

            def run_p6():
                from scripts.cuw_2026 import CUWEngine2026

                native_values = dict(values)
                if values.get("export") != "ProcessBeforeIGOffOnAtRetry":
                    if not isinstance(self._engine2026, CUWEngine2026):
                        raise ValueError("Actual P6/DCM controller state required")
                    native_values["dh_state"] = self._engine2026.dh_state
                    if module.name == "TCUWCanDCMPRLVersionGetter.dll":
                        native_values["dcm_getter_state"] = (
                            self._engine2026.dcm_getter_state
                        )
                context = p62026.bind_native_context(
                    self.container,
                    self.node,
                    tuple(observed["current_cids"]),
                    selection,
                    module.native_identity,
                    material,
                    native_values,
                )
                return p62026.execute_context(context, runtime)

            return run_p6
        from scripts import programming_2026_mmc as mmc2026

        if module.name in mmc2026._MODULES:
            if self.operation == "prepare":
                data = material.get("prepare_engine", self._module_files[module.name])
                if (
                    module.native_identity is None
                    or hashlib.sha256(data).hexdigest()
                    != module.native_identity.engine_sha256
                ):
                    raise ValueError(
                        "Native MMC inspection engine differs from registered source"
                    )
                material["prepare_engine"] = data
            context = mmc2026.bind_native_context(
                self.container,
                self.node,
                tuple(observed["current_cids"]),
                selection,
                module.native_identity,
                material,
                values,
            )

            def preparation_state():
                if self._engine2026 is not None:
                    from scripts.cuw_2026 import CUWEngine2026

                    assert isinstance(self._engine2026, CUWEngine2026)
                    return _uint(self._engine2026.native_prepare_handshake)
                return _uint(runtime.call("preparation_state"))

            def notify(event):
                result = runtime.call("progress", **event)
                if result is not None:
                    raise TypeError("Native progress callback must return None")

            def run_mmc():
                from scripts.cuw_2026 import CUWEngine2026

                engine = None
                if self.operation == "get_cid" and self._engine2026 is not None:
                    assert isinstance(self._engine2026, CUWEngine2026)
                    engine = self._engine2026
                result = mmc2026.run_native(
                    context,
                    runtime,
                    preparation_state=preparation_state,
                    engine=engine,
                    notify=notify,
                )
                identifiers = result.get("identifiers")
                if isinstance(identifiers, (tuple, list)):
                    result = {
                        **result,
                        "identifiers": tuple(
                            value.encode("latin1") if isinstance(value, str) else value
                            for value in identifiers
                        ),
                    }
                if result.get("state") == "identification_completed":
                    result = {**result, "state": "read_completed"}
                return result

            return run_mmc
        from scripts import programming_2026_m16c as m16c2026

        if module.name in m16c2026.MODULE_EXPORTS:
            values.setdefault(
                "stage",
                "prepare_retry" if self.operation == "recovery" else self.operation,
            )
            context = m16c2026.bind_native_context(
                self.container,
                self.node,
                tuple(observed["current_cids"]),
                selection,
                module.native_identity,
                material,
                values,
            )
            return lambda: m16c2026.run_native_context(context, runtime)
        if module.name in dh_modules:
            from scripts import programming_2026_dh as dh2026

            if "dh_state" in values:
                raise ValueError("DH state must originate from the bound engine")
            if self._engine2026 is not None:
                from scripts.cuw_2026 import CUWEngine2026

                assert isinstance(self._engine2026, CUWEngine2026)
                values["dh_state"] = self._engine2026.dh_state
            values.setdefault("stage", selection.operation)
            if self.operation == "recovery":
                values["operation"] = "recovery"
            if module.file_version is not None:
                values["module_version"] = module.file_version
            retry_prepare_name = {
                "TCUWCanDHUDSFlashWriter.dll": "TCUWCanDHUDSPrepareWriter.dll",
                "TCUWP5CanDHUDSFlashWriter.dll": "TCUWP5CanDHUDSPrepareWriter.dll",
            }.get(module.name, "TCUWCanDHPrepareWriter.dll")
            for alias, name in (
                ("selected_module", module.name),
                ("dh_utils_module", "TCUWDHUtils.dll"),
                ("secret_info_module", "SecretInfo.dll"),
                ("cuw_module", "CUW.dll"),
                ("retry_prepare_module", retry_prepare_name),
            ):
                if name in self._module_files:
                    data = self._module_files[name]
                    if alias in material and material[alias] != data:
                        raise ValueError(
                            "Selected native dependency attachment differs from source"
                        )
                    material[alias] = data
            context = dh2026.bind_native_context(
                self.container,
                self.node,
                tuple(observed["current_cids"]),
                selection,
                module.native_identity,
                material,
                values,
            )

            def run_dh():
                result = dh2026.execute_context(context, runtime)
                identifiers = result.get("identifiers")
                if isinstance(identifiers, (tuple, list)):
                    result = {
                        **result,
                        "identifiers": tuple(
                            item["identifier"] if isinstance(item, dict) else item
                            for item in identifiers
                        ),
                    }
                return result

            return run_dh
        from scripts import programming_2026_vendor as vendor2026

        if module.name in vendor2026._MODULES:
            context = vendor2026.bind_native_context(
                self.container,
                self.node,
                tuple(observed["current_cids"]),
                selection,
                module.native_identity,
                material,
                values,
            )
            if module.name == "TCUWCanSBRFlashWriter.dll":
                vendor_notify = lambda field, value: (
                    runtime.call("progress", field=field, value=value)
                    if field in ("writing", "next_cpu")
                    else None
                )
            else:
                vendor_notify = lambda field, value: runtime.call(
                    "progress", field=field, value=value
                )
            return lambda: vendor2026.run_native(
                context,
                runtime,
                entrypoint="PrepareRetry" if self.operation == "recovery" else None,
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
                notify=vendor_notify,
            )
        if (
            module.name
            in unified2026._GETTERS | unified2026._PREPARERS | unified2026._WRITERS
        ):
            if "CUW.dll" in self._module_files:
                from scripts.programming_2026_common import NativeCentralGatewayKey2026

                runtime.bind_central_gateway_key(
                    NativeCentralGatewayKey2026.from_native_module(
                        self._module_files["CUW.dll"]
                    )
                )
            if "rks_software_identity" in values:
                raise ValueError(
                    "Retained native RKS identity must originate from engine"
                )
            if module.name == "TCUWEthernetReprostdFlashWriter.dll":
                from scripts.cuw_2026 import CUWEngine2026

                if not isinstance(self._engine2026, CUWEngine2026):
                    raise ValueError("Actual loaded RKS engine state required")
                if "rks_ini" in material:
                    raise ValueError("Retained native RKS identity cannot be replaced")
                values["rks_software_identity"] = self._engine2026.rks_software_identity
            if "CalculationHmacAPI.dll" in self._module_files:
                from scripts.programming_2026_common import NativeSMCHmac2026

                runtime.bind_smc_hmac(
                    NativeSMCHmac2026.from_native_module(
                        self._module_files["CalculationHmacAPI.dll"]
                    )
                )
            if self._engine2026 is not None and self.operation in ("prepare", "write"):
                from scripts.cuw_2026 import CUWEngine2026

                assert isinstance(self._engine2026, CUWEngine2026)
                if "gateway_state" in values or "dh_state" in values:
                    raise ValueError(
                        "Native Unified state must originate from the loaded engine"
                    )
                values["gateway_state"] = self._engine2026
                values["dh_state"] = self._engine2026.dh_state
            for alias, name in (
                ("secret_info_module", "SecretInfo.dll"),
                ("cuw_module", "CUW.dll"),
                ("dh_utils_module", "TCUWDHUtils.dll"),
                ("suzuki_utils_module", "TCUWCanSuzukiUDSUtils.dll"),
            ):
                if name in self._module_files:
                    data = self._module_files[name]
                    if alias in material and material[alias] != data:
                        raise ValueError(
                            "Native authorization dependency differs from selected source"
                        )
                    material[alias] = data
            context = unified2026.bind_native_context(
                self.container,
                self.node,
                tuple(observed["current_cids"]),
                selection,
                module.native_identity,
                material,
                values,
            )
            return lambda: unified2026.execute_context(context, runtime)
        from scripts import programming_2026_suzuki_fhi as suzuki2026

        if module.name in suzuki2026._MAIN_MODULES:
            if "suzuki_state" in values or "notification" in values:
                raise ValueError(
                    "Native Suzuki state must originate from the bound engine"
                )
            if self._engine2026 is None:
                raise ValueError("Loaded native2026 engine state required")
            from scripts.cuw_2026 import CUWEngine2026

            assert isinstance(self._engine2026, CUWEngine2026)
            values["suzuki_state"] = self._engine2026.suzuki_state
            utility = (
                "TCUWFHIUtils.dll"
                if "FHI" in module.name
                else "TCUWCanSuzukiUDSUtils.dll"
            )
            for alias, name in (
                ("selected_module", module.name),
                ("utils_module", utility),
            ):
                if name in self._module_files:
                    data = self._module_files[name]
                    if alias in material and material[alias] != data:
                        raise ValueError(
                            "Native utility attachment differs from selected source"
                        )
                    material[alias] = data
            context = suzuki2026.bind_native_context(
                self.container,
                self.node,
                tuple(observed["current_cids"]),
                selection,
                module.native_identity,
                material,
                values,
            )
            return lambda: suzuki2026.execute_context(context, runtime)
        if module.name == "TCUWCanCIDGetter.dll" and self.operation == "get_cid":
            from scripts.programming_2026_legacy import (
                bind_can_cid_context,
                run_can_cid,
            )

            # This export consumes no per-CPU observations or external attachments.
            if set(values) - {"cpu_index"} or values.get("cpu_index", 0) != 0:
                raise ValueError("Native CAN CID export has no captured state override")
            context = bind_can_cid_context(
                self.container,
                self.node,
                tuple(observed["current_cids"]),
                selection,
                module.native_identity,
                material,
                {},
            )

            def run_native_can_cid():
                from scripts.cuw_2026 import CUWEngine2026

                engine = (
                    self._engine2026
                    if isinstance(self._engine2026, CUWEngine2026)
                    and self._engine2026.active
                    else None
                )
                return run_can_cid(
                    context, runtime, controller=self._controller2026, engine=engine
                )

            return run_native_can_cid
        if module.name in SIL_OPERATIONS:
            if set(values) & {
                "use_new_password",
                "reset_requested",
                "prepare_status",
                "received_cid_count",
            }:
                raise ValueError("SIL state must originate from the loaded engine")
            native_operation = SIL_OPERATIONS[module.name]

            def run_sil():
                from scripts.cuw_2026 import CUWEngine2026

                transfer = None
                progress = None
                native_values = dict(values)
                if native_operation in (
                    "write",
                    "dcmprl_write",
                    "hino_write",
                    "dcmprl_prepare",
                    "hino_prepare",
                ):
                    if not isinstance(self._engine2026, CUWEngine2026):
                        raise ValueError("Actual active SIL controller state required")
                    transfer = self._engine2026.make_sil_transfer(selection)
                    if native_operation in ("write", "dcmprl_write", "hino_write"):
                        progress = self._engine2026.make_sil_progress(selection)
                    if native_operation == "write":
                        native_values["use_new_password"] = transfer.use_new_password
                    elif native_operation == "dcmprl_prepare":
                        native_values["reset_requested"] = transfer.reset_requested
                        native_values["prepare_status"] = transfer.status
                if native_operation == "dcmprl_version":
                    if not isinstance(self._engine2026, CUWEngine2026):
                        raise ValueError("Actual SIL getter engine state required")
                    # The SIL helper's legacy name denotes *context+74c (progress0).
                    native_values["received_cid_count"] = (
                        self._engine2026.dh_state.progress[0]
                    )
                context = bind_context(
                    self.container,
                    self.node,
                    tuple(observed["current_cids"]),
                    selection,
                    module.native_identity,
                    material,
                    native_values,
                )
                try:
                    cid_state = (
                        SILCIDState2026() if self.operation == "get_cid" else None
                    )
                    output = execute_context_report(
                        context,
                        runtime,
                        transfer=transfer,
                        progress=progress,
                        cid_state=cid_state,
                    )
                finally:
                    if transfer is not None:
                        assert isinstance(self._engine2026, CUWEngine2026)
                        self._engine2026.apply_sil_transfer(transfer)
                if (
                    native_operation == "dcmprl_version"
                    and isinstance(self._engine2026, CUWEngine2026)
                    and cid_state is not None
                ):
                    self._engine2026.apply_sil_getter_context(
                        module.native_identity, cid_state.contact_type
                    )
                result: Any = output.result
                native_output: dict[str, Any] = {
                    "native_return": output.native_return,
                    "native_success": output.native_success,
                }
                if output.error_code is not None:
                    native_output["native_primary_error"] = output.error_code
                if output.j2534_error is not None:
                    native_output["native_passthru_error"] = output.j2534_error
                if output.native_error is not None:
                    from scripts.programming_2026_common import native_error_fields2026

                    failure: dict[str, Any] = {"state": "failed", **native_output}
                    if isinstance(output.result, tuple) and all(
                        isinstance(value, (bytes, str)) for value in output.result
                    ):
                        failure["identifiers"] = tuple(
                            value.encode("latin1") if isinstance(value, str) else value
                            for value in output.result
                        )
                    if transfer is not None:
                        failure["native_transfer_state"] = transfer
                    try:
                        primary, secondary = native_error_fields2026(
                            output.native_error
                        )
                    except TypeError:
                        # Native CException has no assigned enum/driver fields.
                        pass
                    else:
                        failure.update(
                            native_primary_error=primary,
                            native_passthru_error=secondary,
                        )
                    return failure
                report: dict[str, Any]
                if self.operation == "get_cid":
                    identifiers = (
                        result[0] if context.operation == "dcmprl_version" else result
                    )
                    return {
                        "state": "read_completed",
                        "identifiers": tuple(
                            value.encode("latin1") if isinstance(value, str) else value
                            for value in identifiers
                        ),
                        **native_output,
                    }
                if self.operation == "prepare":
                    report = {"state": "prepare_completed", **native_output}
                    if context.operation == "dcmprl_prepare":
                        report["reset_requested"] = result
                    return report
                if self.operation != "write":
                    raise ValueError("SIL export has no selected recovery operation")
                report = {"state": "writer_completed", **native_output}
                if type(result) is int:
                    report["transferred"] = result
                elif isinstance(result, dict):
                    count = result.get("bytes_written")
                    if type(count) is not int or count < 0:
                        raise ValueError("Native SIL writer count is unavailable")
                    report["transferred"] = count
                return report

            return run_sil
        if (
            module.name == "TCUWP4CanSecurityPowerTrainPrepareWriter.dll"
            and self.operation == "prepare"
        ):
            from scripts.programming_2026_legacy import (
                bind_native_context,
                run_p4_security_powertrain,
            )

            values.setdefault("stage", "prepare")
            context = bind_native_context(
                self.container,
                self.node,
                tuple(observed["current_cids"]),
                selection,
                module.native_identity,
                material,
                values,
            )
            return lambda: run_p4_security_powertrain(
                context,
                runtime,
                lambda seed, service: self._security(
                    "p4_security_powertrain", seed, service
                ),
            )
        raise ValueError(
            "Selected2026 family requires its recovered concrete input adapter"
        )

    def _m16c_runner(self, selection, module, timeout):
        from scripts import programming_m16c as native

        host = self.context["observations"]["host"]
        values = dict(host.get("m16c", {}))
        if self.operation == "recovery":
            values["stage"] = "prepare_retry"
        elif self.operation != "write":
            raise ValueError("M16C operation has no matching native export")
        material = {
            name: self.attachments[alias]
            for name, alias in host.get("m16c_attachments", {}).items()
        }
        inputs = native.bind_m16c_context(
            self.container,
            self.node,
            tuple(self.context["observations"]["current_cids"]),
            selection,
            module.native_identity,
            material,
            values,
        )
        addresses = [address.report() for address in inputs.target_metadata]
        controls, _ = self._controls([addresses[0]], self.trace.clock() + timeout)
        lifecycle = native.M16CControls(
            controls.get_timeout,
            controls.set_timeout,
            controls.start_filter,
            controls.stop_filter,
        )
        channel = self.trace.raw_stream(addresses[0]["request_hex"], timeout)
        if inputs.stage == "prepare_retry":
            return lambda: native.m16c_prepare_retry(
                channel, lifecycle, wait_after_dummy_ms=inputs.wait_after_dummy_ms
            )
        finish = (
            self.trace.raw_stream(addresses[1]["request_hex"], timeout)
            if inputs.last_cpu
            else None
        )
        if inputs.module == "TCUWCanSecurityVFORESTFlashWriter.dll":
            return lambda: native.security_vforest_write(
                channel,
                lifecycle,
                inputs.image,
                finish_channel=finish,
                **inputs.vforest_options,
            )
        options = inputs.options
        if options is None:
            raise ValueError("Imported native M16C options required")
        return lambda: native.m16c_write(
            channel,
            lifecycle,
            inputs.segments,
            options,
            finish_channel=finish,
            last_cpu=inputs.last_cpu,
        )

    def _controls(self, addresses, deadline, *, wait_before_filter_ms=0):
        """Bind actual driver controls; result types are checked at each boundary."""
        from scripts.programming_vendor import VendorControls

        def call(operation, result_type: type | None = None, **values) -> Any:
            result_type = type(None) if result_type is None else result_type
            result = self.trace.action(
                {"operation": operation, **values},
                max(0.001, deadline - self.trace.clock()),
            )
            if type(result) is not result_type:
                raise TypeError("Captured driver control result has incorrect type")
            return result

        def start_filter():
            if wait_before_filter_ms:
                self.trace.wait(wait_before_filter_ms, deadline - self.trace.clock())
            return call("start_filter", int, addresses=addresses)

        controls = VendorControls(
            lambda: call("get_timeout", int),
            lambda value: call("set_timeout", milliseconds=value),
            start_filter,
            lambda token: call("stop_filter", token=token),
            lambda protocol: call("connect", protocol=protocol),
            lambda: call("disconnect"),
            lambda enabled: call("set_padding", enabled=enabled),
        )
        return controls, call

    def _diagnostic(
        self,
        ecu,
        timeout,
        old,
        controls,
        *,
        extension=None,
        response_extension=None,
        minimum_response_timeout_ms=None,
        pending_expiry_write=False,
    ):
        from scripts.programming import NativeProgrammingChannel
        from scripts.programming_vendor import VendorDiagnosticChannel, VendorP5Channel

        values: dict[str, Any] = {
            "timeout": timeout,
            "cancelled": self.trace.cancelled,
            "clock": self.trace.clock,
            "receive": self.trace.receive,
        }
        if pending_expiry_write:

            def expiry_write(target, payload):
                count = self.trace.consume(
                    "raw_write", {"ecu": target, "payload_hex": payload.hex()}
                )
                if type(count) is not int or count != 1:
                    raise OSError("Native pending-expiry write was not accepted")

            values["pending_timeout_write"] = expiry_write
        if not old:
            if minimum_response_timeout_ms is not None:
                return VendorP5Channel(
                    self.trace.exchange,
                    ecu,
                    **values,
                    get_timeout=controls.get_timeout,
                    set_timeout=controls.set_timeout,
                    minimum_response_timeout_ms=minimum_response_timeout_ms,
                )
            return NativeProgrammingChannel(self.trace.exchange, ecu, **values)

        def cleanup(target, payload):
            count = self.trace.consume(
                "raw_write", {"ecu": target, "payload_hex": payload.hex()}
            )
            if type(count) is not int:
                raise TypeError("Cleanup write requires a message count")
            return count

        return VendorDiagnosticChannel(
            self.trace.exchange,
            ecu,
            **values,
            send_cleanup=cleanup,
            get_timeout=controls.get_timeout,
            set_timeout=controls.set_timeout,
            address_extension=extension,
            response_address_extension=response_extension,
        )

    def _legacy_runner(self, selection, module, timeout):
        from scripts import programming_legacy as legacy

        host = self.context["observations"]["host"]
        bindings = host.get("legacy_attachments", {})
        if not isinstance(bindings, dict):
            raise TypeError("Explicit legacy authorization attachment aliases required")
        attachments = {
            name: self.attachments[alias] for name, alias in bindings.items()
        }
        legacy_observations = dict(host.get("legacy", {}))
        if self.operation == "change_gateway":
            if legacy_observations.get("stage", "gateway") != "gateway":
                raise ValueError("Captured legacy stage differs from gateway export")
            legacy_observations["stage"] = "gateway"
        elif legacy_observations.get("stage") == "gateway":
            raise ValueError(
                "Gateway parameters require the distinct gateway operation"
            )
        native = legacy.bind_legacy_context(
            self.container,
            self.node,
            tuple(self.context["observations"]["current_cids"]),
            selection,
            module.native_identity,
            attachments,
            legacy_observations,
        )
        addresses = [address.report() for address in native.target_metadata]
        deadline = self.trace.clock() + timeout
        controls, call = self._controls(addresses, deadline)

        def lifecycle(operation, parameters, remaining):
            values = dict(parameters)
            if operation == "start_filter":
                index = values.pop("target_index")
                values["addresses"] = [addresses[index]]
            result = self.trace.action({"operation": operation, **values}, remaining)
            expected = (
                int
                if operation in ("get_timeout", "get_send_timeout", "start_filter")
                else type(None)
            )
            if type(result) is not expected:
                raise TypeError("Native legacy driver result has incorrect type")
            return result

        def set_bs(value):
            call("set_bs", value=value)

        if self.operation == "write":
            if native.cpu is None or len(addresses) != 2:
                raise ValueError(
                    "Actual legacy CPU and physical/finish addresses required"
                )
            stream = self.trace.raw_stream(addresses[0]["request_hex"], timeout)
            finish = self.trace.raw_stream(addresses[1]["request_hex"], timeout)
            native_cpu = native.cpu

            def tester_present():
                if native.tester_present_request is None:
                    raise ValueError("Native tester-present request is unavailable")
                count = self.trace.action(
                    dict(native.tester_present_request),
                    max(0.001, deadline - self.trace.clock()),
                )
                if type(count) is not int or count != 1:
                    raise OSError("Native tester-present write was not accepted")

            return lambda: legacy.legacy_write(
                module.name,
                stream,
                native_cpu,
                finish_channel=finish,
                set_bs=set_bs,
                tester_present=tester_present,
                native_build=module.build,
                lifecycle=lifecycle,
            )
        targets = native.bind_targets(
            lambda address, policy: self._diagnostic(
                address.request.hex(),
                timeout,
                policy == "p4",
                controls,
                minimum_response_timeout_ms=5530
                if policy == "p5" and self.operation in ("get_cid", "prepare")
                else None,
                pending_expiry_write=policy == "p5"
                and self.operation in ("get_cid", "prepare"),
            )
        )
        if self.operation == "get_cid":
            return lambda: legacy.legacy_get_cids(
                module.name,
                targets,
                query_kind=self.context["observations"]["cid_mode"],
                set_bs=set_bs,
                native_build=module.build,
                parameters=native.parameters,
                lifecycle=lifecycle,
            )
        if self.operation in ("prepare", "change_gateway"):
            if native.prepare is None:
                raise ValueError("Imported legacy preparation context required")
            prepare_context = native.prepare
            return lambda: legacy.legacy_prepare(
                module.name,
                targets,
                prepare_context,
                self._security,
                raw_write=self._broadcast,
                wait=self.trace.wait,
                set_bs=set_bs,
                confirm_gateway=lambda: call("confirm_gateway", bool),
                gateway_only=self.operation == "change_gateway",
                native_build=module.build,
                timeout=timeout,
                cancelled=self.trace.cancelled,
                clock=self.trace.clock,
                lifecycle=lifecycle,
            )
        raise ValueError("Legacy recovery requires its distinct native retry operation")

    def _broadcast(self, identifier, payload, remaining):
        result = self.trace.action(
            {
                "operation": "raw_write",
                "identifier": identifier,
                "payload_hex": payload.hex(),
            },
            remaining,
        )
        if type(result) is not int:
            raise TypeError("Broadcast driver requires a message count")
        return result

    def _vendor_runner(self, selection, module, addresses, timeout):
        from scripts import programming_vendor as vendor
        from scripts.programming_legacy import bind_native_cpu_context

        kind, contact, _, _, _, _ = self._metadata()
        host = self.context["observations"]["host"]
        native = bind_native_cpu_context(
            self.container,
            self.node,
            tuple(self.context["observations"]["current_cids"]),
            selection,
            stage="write" if self.operation == "recovery" else self.operation,
            cpu_index=host.get("cpu_index", 0),
            materialize_images=(
                self.operation == "write"
                and ("PowerTrain" in module.name or "Solar" in module.name)
            ),
        )
        parameter = lambda name: native.parameters.get(name, "")
        profile = vendor.vendor_module_profile(
            module.name,
            module.build,
            parameter=parameter,
            contact_type=contact,
            cpu_type=native.selected.values.get("cputype", ""),
        )
        family = profile["family"]
        if profile.get("fixed_address_width") == 2:
            addresses = [
                {
                    "request_hex": row["request_hex"][:4],
                    "response_hex": row["response_hex"][:4],
                    "extended": False,
                }
                for row in addresses
            ]
        if self.operation == "recovery":
            profile = {**profile, "wait_before_filter_ms": 0}
        if self.operation != "recovery" and profile["stage"] != self.operation:
            raise ValueError("Native entrypoint differs from requested stage")
        deadline = self.trace.clock() + timeout
        controls, call = self._controls(
            addresses[:1],
            deadline,
            wait_before_filter_ms=profile["wait_before_filter_ms"],
        )
        ecu = addresses[0]["request_hex"]
        old = profile["policy"] == "old"
        extension = _hex(ecu, 3)[2] if addresses[0]["extended"] else None
        channel: Any = self._diagnostic(
            ecu,
            timeout,
            old,
            controls,
            extension=extension,
            minimum_response_timeout_ms=profile["minimum_response_timeout_ms"]
            or (5000 if profile["policy"] == "p5" else None),
        )
        channel.pending_response_timeout_seconds = profile[
            "pending_response_timeout_seconds"
        ]

        def periodic(enabled, *values):
            budget = values[-1]
            typed = [
                value.hex() if isinstance(value, bytes) else value
                for value in values[:-1]
            ]
            self.trace.platform(
                {"operation": "periodic", "enabled": enabled, "arguments": typed},
                budget,
            )

        def configure(parameter, value, budget):
            self.trace.platform(
                {"operation": "configure", "parameter": parameter, "value": value},
                budget,
            )
            if parameter == "pending_timeout_ms":
                channel.minimum_response_timeout_ms = _uint(value)

        def authorize(purpose, *values):
            return self._security(purpose, *values)

        if self.operation == "write":
            observed = {}
            if family == "PSA":
                observed = {
                    "software_response": self.attachments[
                        host["software_response_attachment"]
                    ],
                    "date": tuple(host["date"]),
                }
            if family == "PowerTrain" and module.build == 18:
                observed["finish_ack_flags"] = vendor.vendor_finish_ack(
                    self.container, self.catalog, kind, contact
                )
            if family in ("PowerTrain", "Solar"):
                observed["recovery"] = host.get("recovery", False)
                password = vendor.vendor_password_input(
                    native,
                    tuple(self.context["observations"]["current_cids"]),
                    parameter,
                    family=family,
                    use_new=host["use_new_password"],
                    recovery=observed["recovery"],
                )
                if "password_attachment" in host:
                    supplied = self.attachments[host["password_attachment"]]
                    if (
                        len(supplied) != 4
                        or password is not None
                        and int.from_bytes(supplied, "big") != password
                    ):
                        raise ValueError(
                            "Password attachment differs from native metadata branch"
                        )
                observed["password"] = password
            if family == "SBR":
                observed["padded_files"] = {
                    int(index): self.attachments[alias]
                    for index, alias in host.get("padded_file_attachments", {}).items()
                }
            inputs = vendor.vendor_write_inputs(
                self.container,
                host.get("cpu_index", 0),
                family,
                parameter,
                observed=observed,
                native_build=module.build,
                resolve_parameter=lambda cpu_type: (
                    self.catalog.select_native(kind, cpu_type, contact).value
                ),
            )
            if family == "PSA":
                action = lambda: vendor.psa_write(
                    channel, wait=self.trace.wait, **inputs
                )
            elif family == "MMC":
                action = lambda: vendor.mmc_write(channel, **inputs)
            elif family.startswith("HINO"):
                action = lambda: vendor.hino_write(
                    channel, raw_write=self._broadcast, wait=self.trace.wait, **inputs
                )
            elif family == "SBR":
                action = lambda: vendor.sbr_write(
                    channel,
                    raw_write=self._broadcast,
                    wait=self.trace.wait,
                    periodic=periodic,
                    **inputs,
                )
            elif family in ("PowerTrain", "Solar"):
                if len(addresses) != 2:
                    raise ValueError(
                        "Native physical and functional finish addresses required"
                    )
                channel = self.trace.raw_stream(ecu, timeout)
                finish = self.trace.raw_stream(addresses[1]["request_hex"], timeout)
                action = lambda: vendor.powertrain_write(
                    channel,
                    finish_stream=finish,
                    set_timeout=lambda value, budget: self.trace.platform(
                        {"operation": "set_timeout", "milliseconds": value}, budget
                    ),
                    completion_callback=lambda slot, budget: self.trace.platform(
                        {"operation": "native_callback", "slot": slot}, budget
                    ),
                    set_native_flags=lambda changes, budget: self.trace.platform(
                        {"operation": "set_native_flags", "changes": changes},
                        budget,
                    ),
                    **inputs,
                )
            else:
                raise ValueError("Unsupported native vendor writer")
        elif self.operation == "get_cid":
            return self._vendor_getter_runner(
                vendor, profile, parameter, addresses, timeout, kind, module.build
            )
        elif family == "SBR" and self.operation in ("prepare", "recovery"):
            if self.operation == "recovery" and "PrepareRetry" not in module.exports:
                raise ValueError("Selected native source has no PrepareRetry export")
            flags = host["sbr"]
            if not isinstance(flags, dict) or set(flags) != {"retry", "error_kind"}:
                raise ValueError("Explicit native SBR retry/error context required")
            inputs = vendor.vendor_prepare_inputs(
                family,
                parameter,
                cpu_index=host.get("cpu_index", 0),
                retry=flags["retry"],
                error_kind=flags["error_kind"],
                prepare_retry=self.operation == "recovery",
                kind_of_ecu=kind,
            )
            # SBRUtils14d0/2470 fixed gateway;20a0 selects second7-byte row.
            gateway_address = {
                "request_hex": "0763",
                "response_hex": "076b",
                "extended": False,
            }
            gateway_controls, _ = self._controls([gateway_address], deadline)
            gateway = self._diagnostic(
                "0763",
                timeout,
                False,
                gateway_controls,
                minimum_response_timeout_ms=5000,
            )
            master_channel = master_controls = None
            if inputs["slave"]:
                if len(addresses) < 2:
                    raise ValueError(
                        "Native SBR slave requires second selected master pair"
                    )
                master = {
                    "request_hex": _hex(addresses[1]["request_hex"], 3)[:2].hex(),
                    "response_hex": _hex(addresses[1]["response_hex"], 3)[:2].hex(),
                    "extended": False,
                }
                master_controls, _ = self._controls([master], deadline)
                master_channel = self._diagnostic(
                    master["request_hex"],
                    timeout,
                    False,
                    master_controls,
                    minimum_response_timeout_ms=5000,
                )
            action = lambda: vendor.sbr_prepare(
                channel,
                gateway,
                lambda identifier, seed: authorize("SBR_prepare", identifier, seed),
                lambda seed: authorize("SBR_gateway", seed),
                raw_write=self._broadcast,
                wait=self.trace.wait,
                periodic=periodic,
                gateway_controls=gateway_controls,
                master_controls=master_controls,
                main_controls=controls,
                master_channel=master_channel,
                **inputs,
            )
            profile = {
                **profile,
                "manage_filter": False,
                "fixed_receive_timeout_ms": 100,
            }
        elif self.operation == "recovery" and family == "PowerTrain":
            if "PrepareRetry" not in module.exports:
                raise ValueError("Selected native source has no PrepareRetry export")
            previous = _uint(host["previous_error"])
            channel = self.trace.raw_stream(ecu, timeout)
            wait = _uint(int(parameter("WaitTimeAfterSendDummyData") or "0"))
            special = native.selected.values.get("cputype", "") == "22"
            action = lambda: vendor.powertrain_prepare_retry(
                channel, previous, wait_after_dummy_ms=wait, special_cpu=special
            )
        elif self.operation == "recovery" and family == "HINO-DSS":
            if "PrepareRetry" not in module.exports:
                raise ValueError("Selected native source has no PrepareRetry export")
            action = lambda: vendor.hino_dss_prepare_retry(
                channel,
                lambda seed: authorize("HINO-DSS_prepare", seed),
                raw_write=self._broadcast,
                wait=self.trace.wait,
            )
        elif self.operation == "prepare" and family in (
            "PSA",
            "MMC",
            "HINO",
            "HINO-DSS",
            "HINO-VCS",
        ):
            purpose = family + "_prepare"
            key_provider = lambda seed: authorize(purpose, seed)
            if family == "PSA":
                inputs = vendor.vendor_prepare_inputs(family, parameter)
                action = lambda: vendor.psa_prepare(
                    channel, key_provider, periodic=periodic, **inputs
                )
            elif family == "MMC":

                def send_start(payload, budget):
                    value = self.trace.consume(
                        "raw_write", {"ecu": ecu, "payload_hex": payload.hex()}, budget
                    )
                    if type(value) is not int:
                        raise TypeError("MMC start write requires a message count")
                    return value

                action = lambda: vendor.mmc_prepare(
                    channel,
                    key_provider,
                    preparation_state=lambda: call("preparation_state", int),
                    send_start=send_start,
                    periodic=periodic,
                    configure=configure,
                )
            else:
                inputs = vendor.vendor_prepare_inputs(
                    family, parameter, kind_of_ecu=kind
                )
                action = lambda: vendor.hino_prepare(
                    channel,
                    key_provider=key_provider,
                    raw_write=self._broadcast,
                    wait=self.trace.wait,
                    configure=configure,
                    **inputs,
                )
        else:
            raise LookupError(
                "Native preparation/recovery container adapter is pending"
            )

        def before_timeout():
            if profile["initial_native_flags"]:
                self.trace.platform(
                    {
                        "operation": "set_native_flags",
                        "changes": profile["initial_native_flags"],
                    },
                    deadline - self.trace.clock(),
                )
            if profile["wait_before_timeout_ms"]:
                self.trace.wait(
                    profile["wait_before_timeout_ms"], deadline - self.trace.clock()
                )

        return lambda: vendor.vendor_stage(
            channel,
            controls,
            action,
            reading=self.operation == "get_cid",
            receive_timeout_ms=int(selection.value("ReceiveTimeoutBeforeGetCID"))
            if self.operation == "get_cid"
            else profile["fixed_receive_timeout_ms"],
            padding=profile["padding"],
            restore_timeout=profile["restore_timeout"],
            manage_filter=profile["manage_filter"],
            before_timeout=before_timeout
            if profile["wait_before_timeout_ms"] or profile["initial_native_flags"]
            else None,
        )

    def _vendor_getter_runner(
        self, vendor, profile, parameter, addresses, timeout, kind, build
    ):
        family = profile["family"]
        scope = profile["address_scope"]
        selected_addresses = addresses if scope == "all" else addresses[:1]
        if profile.get("fixed_address_width") == 2:
            # These getter exports copy two bytes and ignore the record extension flag.
            selected_addresses = [
                {
                    "request_hex": address["request_hex"][:4],
                    "response_hex": address["response_hex"][:4],
                    "extended": False,
                }
                for address in selected_addresses
            ]
        deadline = self.trace.clock() + timeout
        outer_controls, _ = self._controls(selected_addresses, deadline)
        prepared = []
        query_kind = self.context["observations"]["cid_mode"]
        settings = dict(profile["settings"])
        if family == "PSA":
            settings.update(vendor.psa_getter_inputs(parameter))
        if family == "DH":
            settings["complement"] = parameter("ComplementCID").encode("ascii")
        if family == "SoftwareInfo":
            settings["byte_count"] = _uint(
                int(parameter("SoftwareInfoIDByteNum") or "0"), 16
            )
        for address in selected_addresses:
            controls, call = self._controls([address], deadline)
            ecu = address["request_hex"]
            extension = _hex(ecu, 3)[2] if address["extended"] else None
            response_extension = (
                _hex(address["response_hex"], 3)[2] if address["extended"] else None
            )
            channel = self._diagnostic(
                ecu,
                timeout,
                profile["policy"] == "old",
                controls,
                extension=extension,
                response_extension=response_extension,
                minimum_response_timeout_ms=profile["minimum_response_timeout_ms"],
            )
            channel.pending_response_timeout_seconds = profile[
                "pending_response_timeout_seconds"
            ]
            prepared.append(
                (address, channel, controls, call, extension, response_extension)
            )

        def run_nodes():
            identifiers = []
            native_results = []
            wait = profile["wait_before_ms"]
            if wait:
                self.trace.wait(wait, deadline - self.trace.clock())
            for (
                address,
                channel,
                controls,
                call,
                extension,
                response_extension,
            ) in prepared:

                def query(
                    channel=channel,
                    controls=controls,
                    extension=extension,
                    address=address,
                    response_extension=response_extension,
                ):
                    if family == "PSA":
                        return vendor.psa_get_cid(channel, **settings)
                    if family == "DH":
                        return vendor.dh_get_cid(
                            channel,
                            address_extension=extension,
                            response_address_extension=response_extension,
                            **settings,
                        )
                    if family == "SoftwareInfo":
                        return vendor.software_info_get_cid(
                            channel,
                            start_filter=controls.start_filter,
                            stop_filter=controls.stop_filter,
                            set_bs=lambda enabled, budget: self.trace.platform(
                                {"operation": "set_bs", "enabled": enabled}, budget
                            ),
                            kind_of_ecu=kind,
                            address_extension=extension,
                            response_address_extension=response_extension,
                            query_kind=query_kind,
                            native_build=build,
                            request_id=_hex(address["request_hex"], 3),
                            existing_identifier_count=len(identifiers),
                            **settings,
                        )
                    return vendor.vendor_get_cid(
                        channel,
                        family,
                        address_extension=extension,
                        response_address_extension=response_extension,
                        query_kind=query_kind,
                        native_build=build,
                        **settings,
                    )

                result = vendor.vendor_stage(
                    channel,
                    controls,
                    query,
                    reading=False,
                    restore_timeout=False,
                    manage_filter=profile["manage_filter"],
                )
                identifiers.extend(result.get("identifiers", ()))
                native_results.append(_report(result))
                if result.get("state") != "read_completed":
                    return {
                        **result,
                        "identifiers": tuple(identifiers),
                        "native_results": tuple(native_results),
                    }
            return {
                "state": "read_completed",
                "family": family,
                "identifiers": tuple(identifiers),
                "native_results": tuple(native_results),
            }

        return lambda: vendor.vendor_stage(
            prepared[0][1],
            outer_controls,
            run_nodes,
            reading=True,
            receive_timeout_ms=int(parameter("ReceiveTimeoutBeforeGetCID")),
            padding=profile["padding"],
            restore_timeout=profile["restore_timeout"],
            manage_filter=False,
        )


def _parse_recording(context_bytes: bytes, cancelled=lambda: False):
    context = _json(context_bytes)
    if (
        set(context)
        != {
            "schema",
            "source",
            "calibration_sha256",
            "operation",
            "node",
            "observations",
            "events",
        }
        or context["schema"] != SCHEMA
        or context["source"] not in ("authored_synthetic", "recorded_unverified")
    ):
        raise ValueError("Invalid programming context schema/source")
    if (
        context["operation"]
        not in ("get_cid", "prepare", "write", "recovery", "probe", "change_gateway")
        or not 1 <= _uint(context["node"], 9) <= 9
    ):
        raise ValueError("Invalid captured native operation/node")
    if (
        not isinstance(context["calibration_sha256"], str)
        or re.fullmatch(r"[0-9a-f]{64}", context["calibration_sha256"]) is None
    ):
        raise ValueError("Captured calibration source hash must be SHA-256")
    observations = context["observations"]
    if not isinstance(observations, dict) or set(observations) != {
        "current_cids",
        "tester_info_hex",
        "system_time",
        "timeout_seconds",
        "cid_mode",
        "host",
    }:
        raise ValueError("Explicit native programming observations required")
    cids = observations["current_cids"]
    if (
        not isinstance(cids, list)
        or not 0 <= len(cids) <= 4096
        or any(
            not isinstance(cid, str) or not 0 < len(cid) <= 256 or not cid.isascii()
            for cid in cids
        )
    ):
        raise ValueError("Bounded observed current calibration identities required")
    if len(_hex(observations["tester_info_hex"], 32)) != 32:
        raise ValueError("Observed tester identity must contain32 bytes")
    stamp = observations["system_time"]
    if not isinstance(stamp, list) or len(stamp) != 8:
        raise ValueError("Explicit observed Windows SYSTEMTIME fields required")
    for value in stamp:
        _uint(value, 65535)
    if (
        not 1 <= _uint(observations["timeout_seconds"], 86400)
        or observations["cid_mode"] not in (1, 2)
        or type(observations["cid_mode"]) is not int
        or not isinstance(observations["host"], dict)
    ):
        raise ValueError("Invalid bounded native observation controls")
    _safe_json(observations["host"])
    trace = ProgrammingTrace.validate(context["events"], cancelled)
    return context, trace


def inspect_recording(raw: bytes) -> dict:
    """Inspect structure only; no module/CUW binding or execution is implied."""
    context, trace = _parse_recording(raw)
    return {
        "format": SCHEMA,
        "source": context["source"],
        "operation": context["operation"],
        "node": context["node"],
        "calibration_sha256": context["calibration_sha256"],
        "sha256": hashlib.sha256(raw).hexdigest(),
        "events": len(trace.rows),
        "event_kinds": sorted({row["kind"] for row in trace.rows}),
        "source_identity_validated": False,
        "programming_completed": False,
        "physical_status": "PHYSICAL_UNCONFIRMED",
    }


class _RecordingStream:
    """Incremental parser for the existing JSON schema, with bounded values."""

    def __init__(self, source):
        import codecs

        self.source = source
        self.decoder = codecs.getincrementaldecoder("utf-8")("strict")
        self.json_decoder = json.JSONDecoder(object_pairs_hook=_object)
        self.buffer = ""
        self.eof = False
        self.length = 0
        self.digest = hashlib.sha256()

    def fill(self):
        if self.eof:
            return
        chunk = self.source.read(65536)
        if not isinstance(chunk, bytes):
            raise TypeError("Explicit binary programming recording stream required")
        self.length += len(chunk)
        if self.length > MAX_STREAM_BYTES:
            raise ValueError("Programming recording stream exceeds disk/input bound")
        self.digest.update(chunk)
        self.eof = not chunk
        self.buffer += self.decoder.decode(chunk, final=self.eof)

    def peek(self):
        while True:
            self.buffer = self.buffer.lstrip(" \t\r\n")
            if self.buffer or self.eof:
                return self.buffer[:1]
            self.fill()

    def punctuation(self, expected):
        if self.peek() != expected:
            raise ValueError("Malformed streamed programming JSON structure")
        self.buffer = self.buffer[1:]

    def value(self, limit=MAX_BYTES):
        self.peek()
        while True:
            if len(self.buffer) > limit + 65536:
                raise ValueError("Streamed programming JSON value exceeds bound")
            try:
                value, end = self.json_decoder.raw_decode(self.buffer)
            except (ValueError, RecursionError):
                if self.eof:
                    raise ValueError(
                        "Malformed streamed programming JSON value"
                    ) from None
                self.fill()
                continue
            # A token ending exactly at a chunk edge may continue in the next chunk.
            if end == len(self.buffer) and not self.eof:
                self.fill()
                continue
            if end > limit:
                raise ValueError("Streamed programming JSON value exceeds bound")
            self.buffer = self.buffer[end:]
            return value


class _EventSpool(Sequence[dict]):
    """Private temporary storage; no recording-provided path is ever opened."""

    def __init__(self):
        self.file = tempfile.TemporaryFile(mode="w+b")  # noqa: SIM115 - the returned trace owns this anonymous spool
        self.offsets = array("Q")
        self.bytes_written = 0

    def append(self, row):
        if len(self.offsets) >= MAX_STREAM_EVENTS:
            raise ValueError("Streamed programming event count exceeds bound")
        ProgrammingTrace.validate([row])
        encoded = json.dumps(row, separators=(",", ":"), allow_nan=False).encode()
        if self.bytes_written + len(encoded) + 1 > MAX_STREAM_BYTES:
            raise ValueError("Streamed programming event spool exceeds disk bound")
        self.offsets.append(self.file.tell())
        self.file.write(encoded + b"\n")
        self.bytes_written += len(encoded) + 1

    def __len__(self):
        return len(self.offsets)

    def __getitem__(self, index):
        if type(index) is not int or not 0 <= index < len(self.offsets):
            raise IndexError(index)
        self.file.seek(self.offsets[index])
        return json.loads(self.file.readline())

    def close(self):
        self.file.close()

    def __del__(self):
        if hasattr(self, "file"):
            self.file.close()


def load_programming_recording_stream(
    cuw_bytes: bytes | NativeLargeContainer2026,
    recording,
    catalog_sources: Mapping[str, bytes],
    module_files: Mapping[str, bytes],
    *,
    attachments: Mapping[str, bytes] | None = None,
    cancelled: Callable[[], bool] = lambda: False,
) -> ProgrammingReplay:
    """Read the same JSON recording incrementally and validate it before I/O.

    The explicitly supplied binary stream remains caller-owned. The returned
    trace owns an anonymous temporary event spool, closed when the trace is
    released, or explicitly through ``session.trace.close()``.
    """
    parser = _RecordingStream(recording)
    rows = _EventSpool()
    try:
        context = {}
        parser.punctuation("{")
        while parser.peek() != "}":
            key = parser.value(256)
            if not isinstance(key, str) or key in context:
                raise ValueError("Duplicate/invalid streamed programming field")
            parser.punctuation(":")
            if key == "events":
                context[key] = []
                parser.punctuation("[")
                while parser.peek() != "]":
                    row = parser.value(1024 * 1024)
                    rows.append(row)
                    if parser.peek() == "]":
                        break
                    parser.punctuation(",")
                    if parser.peek() == "]":
                        raise ValueError("Trailing streamed event comma")
                parser.punctuation("]")
            else:
                context[key] = parser.value()
            if parser.peek() == "}":
                break
            parser.punctuation(",")
            if parser.peek() == "}":
                raise ValueError("Trailing streamed recording comma")
        parser.punctuation("}")
        if parser.peek():
            raise ValueError("Trailing streamed programming JSON content")
        session = load_programming_replay(
            cuw_bytes,
            json.dumps(context, allow_nan=False).encode(),
            catalog_sources,
            module_files,
            attachments=attachments,
            cancelled=cancelled,
        )
        for row in rows:
            if (
                row["result"]["type"] == "attachment"
                and row["result"]["value"] not in session.trace.attachments
            ):
                raise ValueError("Streamed recording references unselected attachment")
        session.trace.rows = rows
        session.input_hashes["context"] = parser.digest.hexdigest()
        return session
    except (Exception, KeyboardInterrupt):
        rows.close()
        raise


def load_programming_replay(
    cuw_bytes: bytes | NativeLargeContainer2026,
    context_bytes: bytes,
    catalog_sources: Mapping[str, bytes],
    module_files: Mapping[str, bytes],
    *,
    attachments: Mapping[str, bytes] | None = None,
    cancelled: Callable[[], bool] = lambda: False,
) -> ProgrammingReplay:
    """Import explicit bytes or authenticated large backing; JSON opens no paths."""
    context, trace = _parse_recording(context_bytes, cancelled)
    large = not isinstance(cuw_bytes, bytes)
    if large:
        validate_large_container_2026(cuw_bytes)
        source_digest = cuw_bytes.digest
    else:
        source_digest = hashlib.sha256(cuw_bytes).hexdigest()
    if context["calibration_sha256"] != source_digest:
        raise ValueError("Captured calibration source hash mismatch")
    hashes = {
        "calibration": source_digest,
        "context": hashlib.sha256(context_bytes).hexdigest(),
        "catalog": {},
        "modules": {},
        "attachments": {},
    }
    for sources in (catalog_sources, module_files, attachments or {}):
        if (
            not isinstance(sources, Mapping)
            or len(sources) > 4096
            or any(
                not isinstance(name, str)
                or re.fullmatch(r"[A-Za-z0-9_.-]{1,260}", name) is None
                or not isinstance(data, bytes)
                for name, data in sources.items()
            )
            or sum(len(data) for data in sources.values()) > MAX_BYTES
        ):
            raise ValueError(
                "Explicit bounded file aliases and immutable bytes required"
            )
    trace.attachments = dict(attachments or {})
    if any(
        row["result"]["type"] == "attachment"
        and row["result"]["value"] not in trace.attachments
        for row in trace.rows
    ):
        raise ValueError("Recording references an unselected security attachment")
    catalog = CalibrationCatalog.from_tables(
        {
            name: data
            for name, data in catalog_sources.items()
            if name not in ("CanIDTable.ini", "LogicalAddressTable.ini")
        }
    )
    modules = {}
    for name, data in module_files.items():
        digest = hashlib.sha256(data).hexdigest()
        fixture_cuw, fixture_module, _ = _fixture_inputs()
        from scripts.calibration_catalog import inspect_module_bytes

        if name == "SyntheticProgramming.dll":
            if (
                context["source"] != "authored_synthetic"
                or cuw_bytes != fixture_cuw
                or data != fixture_module
            ):
                raise ValueError(
                    "Authored identity is restricted to exact fixture recipe bytes"
                )
            modules[name] = BoundModule(
                name,
                digest,
                18,
                "TCUWCanReproStdFlashWriter",
                ("StartFlashWrite",),
                "authored_fixture",
                file_version=inspect_module_bytes(data, name)["version"],
            )
        else:
            identity = identify_native_module(digest, name)
            if name == "CalculationHmacAPI.dll":
                from scripts.programming_2026_common import NativeSMCHmac2026

                NativeSMCHmac2026.from_native_module(data)
                # This exact original has no version resource; identity binds exports.
                pe = {"exports": identity.callable_exports, "version": None}
            else:
                pe = inspect_module_bytes(data, name)
            if not set(identity.callable_exports).issubset(pe["exports"]):
                raise ValueError(
                    "Verified module export evidence differs from selected file"
                )
            if identity.cuw_build not in ("12", "18", "2026"):
                raise ValueError("Operation module has no unique verified native build")
            modules[name] = BoundModule(
                name,
                digest,
                int(identity.cuw_build),
                identity.family,
                identity.callable_exports,
                file_version=pe["version"],
                native_identity=identity,
            )
        hashes["modules"][name] = digest
    hashes["catalog"] = {
        name: hashlib.sha256(data).hexdigest() for name, data in catalog_sources.items()
    }
    hashes["attachments"] = {
        name: hashlib.sha256(data).hexdigest()
        for name, data in (attachments or {}).items()
    }
    builds = {module.build for module in modules.values()}
    if len(builds) != 1:
        raise ValueError("Selected programming source builds must agree")
    if builds == {2026}:
        from scripts.calibration_2026 import parse_cuw_2026

        container = cuw_bytes if large else parse_cuw_2026(cuw_bytes)
    else:
        if large:
            raise ValueError("Authenticated large backing requires exact2026 modules")
        container = parse_cuw(cuw_bytes)
    return ProgrammingReplay(
        container,
        context,
        catalog,
        modules,
        dict(attachments or {}),
        trace,
        hashes,
        _catalog_sources=MappingProxyType(dict(catalog_sources)),
        _module_files=MappingProxyType(dict(module_files)),
    )


def _fixture_inputs() -> tuple[bytes, bytes, dict[str, bytes]]:
    import struct
    import zlib

    from scripts.calibration import SIGNATURE
    from scripts.demo_calibration import version_resource

    def record(header, payload):
        return (
            struct.pack(">H", len(header))
            + header
            + struct.pack(">II", len(payload), zlib.crc32(payload))
            + payload
        )

    metadata = (
        "[Format]\nVersion=206\n[Vehicle]\nKindOfECU=DEMO\nContactType=P5\nNumberOfNode=1\n[Node01]\nRequiredSpecReproVer=03\nNumberOfLogicalBlock=1\n[LogicalBlock101]\nNewCID=AUTHORED-NEW\nNumberOfTargets=1\n01_TargetCalibration=AUTHORED-OLD\nReproMethod=05\nNonce="
        + bytes(16).hex()
        + "\n[ReproData101]\nStartAddress=00001000\nLength=00000004\nCRC=01020304\nCMAC="
        + bytes(16).hex()
        + "\n"
    ).encode()
    tail = (
        record(b"authored.att", metadata) + b"\x01" + record(b"authored.bin", b"DEMO")
    )
    cuw = SIGNATURE + b"\x65" + bytes(4) + struct.pack(">I", 22 + len(tail)) + tail
    cuw = cuw[:14] + struct.pack(">I", zlib.crc32(cuw[18:])) + cuw[18:]
    module = bytearray(2048)
    module[:2] = b"MZ"
    struct.pack_into("<I", module, 0x3C, 0x80)
    module[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", module, 0x84, 0x14C, 1, 0, 0, 0, 224, 0x2102)
    optional = 0x98
    struct.pack_into("<H", module, optional, 0x10B)
    struct.pack_into("<I", module, optional + 28, 0x10000000)
    struct.pack_into("<II", module, optional + 32, 4096, 512)
    struct.pack_into("<II", module, optional + 56, 8192, 512)
    struct.pack_into("<I", module, optional + 92, 16)
    struct.pack_into("<II", module, optional + 96, 0x1000, 256)
    struct.pack_into("<II", module, optional + 112, 0x1200, 0x400)
    module[0x178:0x180] = b".rdata\0\0"
    struct.pack_into(
        "<IIIIIIHHI", module, 0x180, 1536, 0x1000, 1536, 512, 0, 0, 0, 0, 0x40000040
    )
    struct.pack_into(
        "<IIHHIIIIIII",
        module,
        0x200,
        0,
        0,
        0,
        0,
        0x1040,
        1,
        1,
        1,
        0x1060,
        0x1064,
        0x1068,
    )
    module[0x240:0x259] = b"SyntheticProgramming.dll\0"
    struct.pack_into("<IIH", module, 0x260, 0x1100, 0x1070, 0)
    module[0x270:0x280] = b"StartFlashWrite\0\0"
    for offset, identifier, target in (
        (0, 16, 0x80000018),
        (24, 1, 0x80000030),
        (48, 0x409, 72),
    ):
        struct.pack_into("<HII", module, 0x400 + offset + 14, 1, identifier, target)
    version = version_resource()
    struct.pack_into("<II", module, 0x448, 0x1300, len(version))
    module[0x500 : 0x500 + len(version)] = version
    # Read-only export data only; no executable section or entry point.
    plain = (
        b"ParamFileKeySystemProtocolMicon,DLLFileNameForFlashWrite,GetCANIDFunctionNameForFlashWrite,CanIDForPrepareWrite\n"
        b"DEMOP5DEMO,SyntheticProgramming.dll,GetCanIDsFromParamForPrepareWrite,0700/0708\n"
    )
    encoded = bytes(
        value
        for byte in plain
        for value in (((byte >> 4) + 8) << 2, ((byte & 15) + 8) << 2)
    )
    return cuw, bytes(module), {"DEMOP5DEMO.ini": encoded}


def create_programming_examples() -> dict[str, bytes]:
    """Deterministic authored CUW/PE/capture; uses the actual native writer engine."""
    from scripts.programming import (
        reprostd_download_request,
        reprostd_fingerprint_requests,
        reprostd_routine_request,
    )

    cuw, module, catalog = _fixture_inputs()
    rows = []

    def event(kind, request, value=None, value_type="none"):
        rows.append(
            {
                "kind": kind,
                "request": request,
                "result": {"type": value_type, "value": value},
                "elapsed_ms": 0,
            }
        )

    def action(operation, **values):
        event("action", {"operation": operation, **values})

    def pdu(request, response):
        event("action", {"operation": "get_timeout"}, 5000, "int")
        event(
            "exchange",
            {"ecu": "0700", "payload_hex": request.hex()},
            response.hex(),
            "bytes",
        )
        action("set_timeout", milliseconds=5000)

    stamp = (2026, 10, 2, 20, 12, 0, 0, 0)
    action("start_flow_control_filter")
    action("select_logical_block", index=0)
    for request, response in reprostd_fingerprint_requests(
        1, bytes(16), bytes(32), stamp
    ):
        pdu(request, response)
    action("set_reprogramming_active", active=True)
    pdu(*reprostd_routine_request("erase", 0x1000, 4))
    action("save_send_timeout")
    pdu(reprostd_download_request(0x1000, 4), b"\x74\x20\x00\x06")
    action("set_send_timeout", milliseconds=1161)
    pdu(b"\x36\x01DEMO", b"\x76\x01")
    action("restore_send_timeout")
    pdu(b"\x37", b"\x77")
    pdu(
        *reprostd_routine_request(
            "verify", 0x1000, 4, checksum=b"\x01\x02\x03\x04", signature=bytes(16)
        )
    )
    pdu(b"\x11\x01", b"\x51\x01")
    action("stop_periodic")
    action("raw_write", data_hex="000007771081", tx_flags=0)
    action("raw_write", data_hex="0000077ffe1081", tx_flags=128)
    action("set_reprogramming_active", active=False)
    context = {
        "schema": SCHEMA,
        "source": "authored_synthetic",
        "calibration_sha256": hashlib.sha256(cuw).hexdigest(),
        "operation": "write",
        "node": 1,
        "observations": {
            "current_cids": ["AUTHORED-OLD"],
            "tester_info_hex": bytes(32).hex(),
            "system_time": list(stamp),
            "timeout_seconds": 30,
            "cid_mode": 2,
            "host": {},
        },
        "events": rows,
    }
    return {
        "authored.cuw": cuw,
        "authored-programming.json": json.dumps(
            context, separators=(",", ":")
        ).encode(),
        "SyntheticProgramming.dll": module,
        **catalog,
    }


def export_programming_report(report: dict, destination, *, input_paths):
    """Atomically export a redacted result without replacing any selected input."""
    import os
    import tempfile
    from pathlib import Path

    if not isinstance(input_paths, (tuple, list)) or not input_paths:
        raise ValueError("Every selected input path is required for export guards")
    target = Path(destination)
    for source in map(Path, input_paths):
        if (
            target.resolve() == source.resolve()
            or target.exists()
            and source.exists()
            and target.samefile(source)
        ):
            raise ValueError("Programming output aliases a selected source")
    if target.is_symlink():
        raise ValueError("Programming output must not replace a symbolic link")
    data = (
        json.dumps(report, ensure_ascii=True, sort_keys=True, indent=2).encode() + b"\n"
    )
    if len(data) > 1024 * 1024:
        raise ValueError("Redacted programming report exceeds output bound")
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=target.parent, prefix=".programming-", delete=False
        ) as output:
            temporary = output.name
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, target)
        temporary = None
    finally:
        if temporary is not None:
            os.unlink(temporary)


def load_programming_files(
    cuw_path,
    context_path,
    catalog_paths,
    module_paths,
    *,
    attachment_paths=None,
    cancelled=lambda: False,
):
    """Read only explicitly selected regular files; never follow JSON path fields."""
    import os
    import stat

    from scripts.cuw_large import native_large_cuw_2026
    from scripts.local_files import read_regular

    all_paths = (
        cuw_path,
        context_path,
        *catalog_paths.values(),
        *module_paths.values(),
        *(attachment_paths or {}).values(),
    )
    catalogs = {
        name: read_regular(path, limit=MAX_BYTES)
        for name, path in catalog_paths.items()
    }
    modules = {
        name: read_regular(path, limit=MAX_BYTES) for name, path in module_paths.items()
    }
    attachments = {
        name: read_regular(path, limit=MAX_BYTES)
        for name, path in (attachment_paths or {}).items()
    }
    probe = os.open(cuw_path, os.O_PATH | os.O_CLOEXEC)
    try:
        info = os.fstat(probe)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("Selected calibration must be a regular file")
        large = info.st_size > MAX_BYTES
        cuw = (
            native_large_cuw_2026(cuw_path, cancelled=cancelled)
            if large
            else read_regular(cuw_path, limit=MAX_BYTES)
        )
    finally:
        os.close(probe)
    probe = None
    try:
        probe = os.open(context_path, os.O_PATH | os.O_CLOEXEC)
        before = os.fstat(probe)
        if (
            not stat.S_ISREG(before.st_mode)
            or not 0 < before.st_size <= MAX_STREAM_BYTES
        ):
            raise ValueError("Selected recording must be a bounded regular file")
        with open(f"/proc/self/fd/{probe}", "rb") as source:
            session = load_programming_recording_stream(
                cuw,
                source,
                catalogs,
                modules,
                attachments=attachments,
                cancelled=cancelled,
            )
        after = os.fstat(probe)
        identity = lambda value: (
            value.st_dev,
            value.st_ino,
            value.st_size,
            value.st_mtime_ns,
            value.st_ctime_ns,
        )
        if identity(before) != identity(after) or identity(after) != identity(
            os.stat(context_path)
        ):
            session.trace.close()
            raise ValueError("Selected recording changed during import")
    except (Exception, KeyboardInterrupt):
        if large:
            assert isinstance(cuw, NativeLargeContainer2026)
            cuw.close()
        raise
    finally:
        if probe is not None:
            os.close(probe)
    return session, all_paths
