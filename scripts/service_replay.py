"""Strict offline replay of CUW HTTP, DOM and local notification primitives."""

from __future__ import annotations

import copy
import hashlib
import json
import math
import os
import tempfile
import threading
import time
from collections.abc import Callable
from pathlib import Path
from types import MappingProxyType
from typing import Any

from scripts import cuw_services as native
from scripts.local_files import read_regular

SCHEMA = "techstream-service-replay-v1"
MAX_CAPTURE = 8 * 1024 * 1024
MAX_STEPS = 20000
# These identify ported native contracts, never the authored capture itself.
PORT_SOURCES = MappingProxyType(
    {
        "tis12": "308494b4dbe725ad9e784f2f4ddf73838e4fe2c5741d21cfa257a764ae1bf5e0",
        "tis18": "171f91fe78d643591f6566efc45afd7acd3d658e37e32739a1108185fcd43643",
        "euro12": "248ff75abd4563a098712c74497f81e682eef15e33d63b96ef288269f8d7471c",
        "euro18": "7322e5c268c9a063cd790ea9ad94d82354c0c3971a6d49b1881df0cb159bca7b",
        "rks18": "f5628faf55f987233b07105ddab493abd0de734825b8ad66fb1a7d6d9dcad7a1",
        "wrapper18": "dfce5f1043abf21b9522decdb7306812bb84948607a94271968e79374f14b457",
        "notice18": "93f3ca9374b5086d996f94ad47681a5ccbeb9d7b0dbbe6a4e95aa1a938566194",
    }
)


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate capture field")
        result[key] = value
    return result


def _fields(value: Any, names: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != names:
        raise ValueError("Unexpected capture fields")
    return value


def _json(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode()


def _hex(value: Any) -> bytes:
    if not isinstance(value, str) or len(value) > native.MAX_XML * 2:
        raise ValueError("Invalid captured bytes")
    try:
        result = bytes.fromhex(value)
    except ValueError:
        raise ValueError("Invalid captured bytes") from None
    if result.hex() != value:
        raise ValueError("Captured bytes must be canonical lowercase hex")
    return result


def _typed_request(operation: str, value: dict[str, Any]):
    cls = (
        native.TISRequest
        if operation.startswith("tis-")
        else native.ProaceRequest
        if operation == "euro-key"
        else native.EuroRequest
    )
    fields = copy.deepcopy(value)
    for name in ("old_calibrations", "new_calibrations"):
        if name in fields:
            if not isinstance(fields[name], list) or len(fields[name]) > 10:
                raise ValueError("At most ten captured calibration entries allowed")
            fields[name] = tuple(native.CalibrationID(**row) for row in fields[name])
    for name in ("frame_ids", "frames"):
        if name in fields:
            if not isinstance(fields[name], list) or len(fields[name]) != 2:
                raise ValueError("Exactly two captured frame entries required")
            fields[name] = tuple(fields[name])
    return cls(**fields)


def _http_args(request: native.ServiceHTTPRequest) -> dict:
    return {
        "endpoint": request.endpoint,
        "action": request.action,
        "body": request.body.hex(),
        "connector_properties": [list(row) for row in request.connector_properties],
        "content_type": request.content_type,
    }


class _Chronology:
    def __init__(
        self,
        steps: list[dict],
        deadline: float,
        cancelled: Callable[[], bool],
        clock: Callable[[], float],
        *,
        started: float,
    ):
        self.started = self.last_wall = started
        self.steps, self.deadline, self.cancelled, self._wall_clock = (
            steps,
            deadline,
            cancelled,
            clock,
        )
        self.index = 0
        self.cleanup_calls = 0
        self.elapsed_ms = 0.0

    def call(
        self, method: str, args: Any, *, timeout: float, cleanup: bool = False
    ) -> Any:
        if cleanup:
            self.cleanup_calls += 1
        else:
            self.check()
        if self.index == len(self.steps):
            raise ValueError("Captured chronology exhausted")
        step = self.steps[self.index]
        if step["method"] != method or _json(step["args"]) != _json(args):
            raise ValueError("Captured primitive chronology mismatch")
        self.index += 1
        elapsed = step.get("elapsed_ms", 0)
        self.elapsed_ms += elapsed
        # One nanosecond tolerance only absorbs binary float roundoff.
        if elapsed > timeout * 1000 + 0.000001:
            raise TimeoutError("Captured primitive exceeded its requested timeout")
        if (
            method
            in {
                "http.close",
                "browser.navigate",
                "browser.set",
                "browser.wait",
                "browser.close",
                "notice.render",
                "notice.beep",
                "notice.close",
            }
            and step["result"] is not None
        ):
            raise ValueError("Void primitive must have an explicit null result")
        if step["fault"] is not None:
            errors = {
                "io": OSError,
                "timeout": TimeoutError,
                "cancel": InterruptedError,
            }
            raise errors[step["fault"]]("Captured primitive fault")
        if not cleanup:
            self.check()
        return copy.deepcopy(step["result"])

    def clock(self) -> float:
        now = self._wall_clock()
        if not math.isfinite(now):
            raise ValueError("Invalid replay clock")
        if now < self.last_wall:
            raise ValueError("Replay wall clock moved backwards")
        self.last_wall = now
        if now >= self.deadline:
            raise TimeoutError("Service replay wall deadline exhausted")
        return self.started + self.elapsed_ms / 1000

    def check(self):
        if self.cancelled():
            raise InterruptedError("Service replay cancelled")
        now = self.clock()
        if not math.isfinite(now):
            raise ValueError("Invalid replay clock")
        if now >= self.deadline:
            raise TimeoutError("Service replay deadline exhausted")


class _Transport:
    def __init__(self, chronology: _Chronology):
        self.c = chronology

    def exchange(self, request, *, timeout, cancelled):
        result = self.c.call("http.exchange", _http_args(request), timeout=timeout)
        _fields(result, {"status", "body", "source"})
        return native.ServiceHTTPResponse(
            result["status"], _hex(result["body"]), result["source"]
        )

    def close(self):
        self.c.call("http.close", {}, cleanup=True, timeout=5)


class _Browser:
    def __init__(self, chronology: _Chronology):
        self.c = chronology

    def create_window(self, *, timeout, cancelled):
        return self.c.call("browser.create", {}, timeout=timeout)

    def navigate(self, window, url, *, timeout, cancelled):
        self.c.call("browser.navigate", {"window": window, "url": url}, timeout=timeout)

    def snapshot(self, window, *, timeout, cancelled):
        result = self.c.call("browser.snapshot", {"window": window}, timeout=timeout)
        _fields(result, {"window", "url", "busy", "ready_state", "elements", "closed"})
        elements = result["elements"]
        if not isinstance(elements, list) or len(elements) > 1024:
            raise ValueError("Captured DOM element budget exceeded")
        result["elements"] = tuple(native.DOMElement(**row) for row in elements)
        return native.BrowserSnapshot(**result)

    def set_value(self, window, tag, name, value, *, timeout, cancelled):
        self.c.call(
            "browser.set",
            {"window": window, "tag": tag, "name": name, "value": value},
            timeout=timeout,
        )

    def wait(self, seconds, *, cancelled):
        # Floating remaining-deadline values are scheduling bounds, not native data.
        self.c.call("browser.wait", {}, timeout=seconds)

    def close(self, window, *, timeout):
        self.c.call("browser.close", {"window": window}, cleanup=True, timeout=timeout)


class _Notice:
    def __init__(self, chronology: _Chronology):
        self.c = chronology

    def cursor(self, *, timeout, cancelled):
        return tuple(self.c.call("notice.cursor", {}, timeout=timeout))

    def create_window(self, title, message, *, fullscreen, topmost, timeout, cancelled):
        return self.c.call(
            "notice.create",
            {
                "title": title,
                "message": message,
                "fullscreen": fullscreen,
                "topmost": topmost,
            },
            timeout=timeout,
        )

    def render(self, window, color, title, message, *, timeout, cancelled):
        self.c.call(
            "notice.render",
            {"window": window, "color": color, "title": title, "message": message},
            timeout=timeout,
        )

    def beep(self, mode, frequency, duration_ms, *, timeout, cancelled):
        self.c.call(
            "notice.beep",
            {"mode": mode, "frequency": frequency, "duration_ms": duration_ms},
            timeout=timeout,
        )

    def poll_event(self, window, *, timeout, cancelled):
        value = self.c.call("notice.event", {"window": window}, timeout=timeout)
        return None if value is None else native.NoticeEvent(**value)

    def close(self, window, *, timeout):
        self.c.call("notice.close", {"window": window}, cleanup=True, timeout=timeout)


class ServiceReplay:
    """Single-use capture. Reports deliberately omit all caller/DOM/XML text."""

    def __init__(self, capture: dict[str, Any]):
        # JSON roundtrip prevents aliases, subclasses and retained mutable inputs.
        encoded = _json(capture)
        if len(encoded) > MAX_CAPTURE:
            raise ValueError("Capture aggregate byte budget exceeded")
        data = json.loads(encoded, object_pairs_hook=_object)
        _fields(data, {"schema", "provenance", "port_sources", "workflow", "steps"})
        if data["schema"] != SCHEMA or data["provenance"] not in (
            "authored",
            "captured",
        ):
            raise ValueError("Unknown capture schema or provenance")
        if (
            not isinstance(data["steps"], list)
            or not 1 <= len(data["steps"]) <= MAX_STEPS
        ):
            raise ValueError("Capture step budget exceeded")
        elapsed_ms = 0.0
        for step in data["steps"]:
            if not isinstance(step, dict):
                raise TypeError("Primitive step object required")
            _fields(
                step,
                {"method", "args", "result", "fault"}
                | ({"elapsed_ms"} if "elapsed_ms" in step else set()),
            )
            elapsed = step.get("elapsed_ms", 0)
            if (
                type(elapsed) not in (int, float)
                or not math.isfinite(elapsed)
                or not 0 <= elapsed <= 600000
            ):
                raise ValueError("Invalid primitive elapsed time")
            elapsed_ms += elapsed
            if elapsed_ms > 600000:
                raise ValueError("Aggregate captured elapsed time exceeds 600 seconds")
            if not isinstance(step["method"], str) or step["fault"] not in (
                None,
                "io",
                "timeout",
                "cancel",
            ):
                raise ValueError("Invalid primitive step")
        workflow = data["workflow"]
        if not isinstance(workflow, dict):
            raise TypeError("Workflow required")
        kind = workflow.get("kind")
        if kind in native.OPERATIONS:
            _fields(workflow, {"kind", "request", "endpoint"})
            request = _typed_request(kind, workflow["request"])
            native.build_service_request(kind, request, endpoint=workflow["endpoint"])
            required = [
                ("tis" if kind.startswith("tis-") else "euro")
                + str(request.product_version)
            ]
        elif kind == "rks":
            _fields(
                workflow,
                {"kind", "data", "url", "allowed_origins", "watch_count", "key_xml"},
            )
            native.rks_xml(native.RKSData(**workflow["data"]))
            if (
                type(workflow["watch_count"]) is not int
                or not 1 <= workflow["watch_count"] <= 10000
            ):
                raise ValueError("Invalid RKS watch budget")
            if not isinstance(workflow["allowed_origins"], list):
                raise ValueError("Explicit origin list required")
            _hex(workflow["key_xml"])
            required = ["rks18", "wrapper18"]
        elif kind == "notice":
            _fields(workflow, {"kind", "config"})
            native.NoticeConfig(**workflow["config"])
            required = ["notice18"]
        else:
            raise ValueError("Unsupported recovered workflow")
        if data["port_sources"] != {name: PORT_SOURCES[name] for name in required}:
            raise ValueError("Exact recovered native port identities required")
        self._data = data
        self.capture_sha256 = hashlib.sha256(encoded).hexdigest()
        self._state = "new"
        self._report: dict[str, Any] | None = None
        self._lock = threading.Lock()

    @classmethod
    def from_bytes(cls, data: bytes) -> ServiceReplay:
        if not isinstance(data, bytes) or len(data) > MAX_CAPTURE:
            raise ValueError("Capture byte budget exceeded")
        try:
            capture = json.loads(
                data,
                object_pairs_hook=_object,
                parse_constant=lambda _: (_ for _ in ()).throw(
                    ValueError("Nonfinite capture value")
                ),
            )
            return cls(capture)
        except (RecursionError, UnicodeError) as error:
            raise ValueError("Malformed capture") from error

    @classmethod
    def load(cls, path: str | Path) -> ServiceReplay:
        return cls.from_bytes(read_regular(path, limit=MAX_CAPTURE))

    def run(
        self,
        *,
        timeout: float = 30,
        cancelled: Callable[[], bool] | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> dict[str, Any]:
        if not math.isfinite(timeout) or not 0 < timeout <= 600:
            raise ValueError("Replay timeout must be in (0,600]")
        with self._lock:
            if self._state != "new":
                raise RuntimeError("Replay is single-use")
            self._state = "running"
        workflow = self._data["workflow"]
        kind = workflow["kind"]
        report: dict[str, Any] = {
            "schema": SCHEMA,
            "capture_sha256": self.capture_sha256,
            "provenance": self._data["provenance"],
            "port_sources": copy.deepcopy(self._data["port_sources"]),
            "kind": kind,
        }
        c: _Chronology | None = None
        try:
            start = clock()
            if not math.isfinite(start):
                self._state = "failed"
                raise ValueError("Invalid replay clock")
            c = _Chronology(
                self._data["steps"],
                start + timeout,
                cancelled or (lambda: False),
                clock,
                started=start,
            )
            c.check()
            if kind in native.OPERATIONS:
                result = native.ServiceClient(
                    _Transport(c),
                    timeout=timeout,
                    cancelled=c.cancelled,
                    clock=c.clock,
                ).run(
                    kind,
                    _typed_request(kind, workflow["request"]),
                    endpoint=workflow["endpoint"],
                )
                report.update(
                    native_status=result.native_status,
                    response_sha256=result.source_sha256,
                    message_count=len(result.messages),
                    unlocking_value_present=result.unlock is not None
                    and result.unlock.value is not None,
                )
            elif kind == "rks":
                access = native.RKSAccess(
                    _Browser(c), timeout=timeout, cancelled=c.cancelled, clock=c.clock
                )
                access.set_data(native.RKSData(**workflow["data"]))
                original = None
                try:
                    access.request(
                        workflow["url"],
                        allowed_origins=tuple(workflow["allowed_origins"]),
                    )
                    statuses = []
                    for _ in range(workflow["watch_count"]):
                        c.check()
                        statuses.append(access.watch().native_status)
                    key = native.import_repro_key(
                        _hex(workflow["key_xml"]), source="captured-key"
                    )
                    report.update(
                        watch_statuses=statuses,
                        key_sha256=key.source_sha256,
                        signature_characters=len(key.value),
                        request_sha256=hashlib.sha256(access.xml()).hexdigest(),
                    )
                except BaseException as error:
                    original = error
                    raise
                finally:
                    native._cleanup(access.close, original)
            else:
                report["dismissal"] = native.CompletionNotice(
                    _Notice(c), timeout=timeout, cancelled=c.cancelled, clock=c.clock
                ).run(native.NoticeConfig(**workflow["config"]))
            c.check()
            if c.index != len(c.steps):
                raise ValueError("Unconsumed captured primitive steps")
            self._state = "complete"
        except BaseException as error:
            self._state = "failed"
            report["error_type"] = type(error).__name__
            if isinstance(error, native.ServiceError):
                report["native_status"] = error.status
            raise
        finally:
            report.update(
                state=self._state,
                consumed_steps=c.index if c is not None else 0,
                total_steps=len(self._data["steps"]),
                cleanup_calls=c.cleanup_calls if c is not None else 0,
                elapsed_ms=c.elapsed_ms if c is not None else 0,
            )
            self._report = report
        return copy.deepcopy(report)

    def report(self) -> dict[str, Any]:
        if self._report is None:
            raise RuntimeError("Replay has no execution report")
        return copy.deepcopy(self._report)

    def export_report(self, path: str | Path) -> None:
        """Publish a complete 0600 file atomically, preserving all existing paths."""
        self._export(path, _json(self.report()) + b"\n")

    def rks_request_bytes(self) -> bytes:
        """Return explicitly requested seed/license-bearing native XML."""
        workflow = self._data["workflow"]
        if workflow["kind"] != "rks":
            raise ValueError("RKS workflow required")
        return native.rks_xml(native.RKSData(**workflow["data"]))

    def export_rks_request(self, path: str | Path) -> None:
        self._export(path, self.rks_request_bytes())

    @staticmethod
    def _export(path: str | Path, payload: bytes) -> None:
        target = Path(path)
        descriptor, temporary = tempfile.mkstemp(
            prefix=".service-report-", dir=target.parent
        )
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.link(temporary, target)
        finally:
            os.unlink(temporary)


def create_demo_service_capture(kind: str = "tis-check") -> bytes:
    """Create authored primitive observations; no original bytes or key material."""
    steps = []

    def step(method, args, result=None):
        steps.append({"method": method, "args": args, "result": result, "fault": None})

    if kind in native.OPERATIONS:
        if kind.startswith("tis-"):
            request = {
                "product_version": 18,
                "vehicle_session": "authored-session",
                "software_version": "18",
                "vin": "TEST0000000000000",
                "date": "2026-10-20",
                "language": "en",
                "software_id": "AUTHORED",
                "user_type": "Public User",
                "dealer_code": "EXAMPLE",
            }
        elif kind == "euro-key":
            request = {
                "product_version": 18,
                "language": "en",
                "gts_guid": "authored",
                "date": "2026-10-20",
                "request_id": "example",
                "ecu_software_id": "SW",
                "ecu_hardware_id": "HW",
                "vin": "TEST0000000000000",
                "iea": "01",
                "frame_ids": ["01", "02"],
                "frames": ["AA", "BB"],
                "unlock_seed": "AUTHORED-SEED",
            }
        else:
            request = {"product_version": 18, "software_id": "AUTHORED"}
        endpoint = "https://example.invalid/offline"
        workflow = {"kind": kind, "request": request, "endpoint": endpoint}
        name = native.OPERATIONS[kind]
        if kind == "euro-key":
            # A denial demonstrates parsing without manufacturing a working key.
            body = b"<milmessage><repairing-requests><requests><unlocking-content><return-code><level>E</level><value>999999</value><comment>Authored denial</comment></return-code></unlocking-content></requests></repairing-requests></milmessage>"
        else:
            message = (
                "OnlineCheck message OK."
                if kind == "euro-online"
                else "Message received OK."
            )
            fields = (
                "<MessageId>demo</MessageId><Title>Authored</Title><MessageContentType>TEXT</MessageContentType>"
                if kind.startswith("tis-")
                else ""
            )
            body = f'<{name}Response xmlns="{native.NAMESPACE}"><{name}Result><MilMessages><MilMessage>{fields}<Message>{message}</Message></MilMessage></MilMessages></{name}Result></{name}Response>'.encode()
        step(
            "http.exchange",
            _http_args(
                native.build_service_request(
                    kind, _typed_request(kind, request), endpoint=endpoint
                )
            ),
            {"status": 200, "body": body.hex(), "source": "authored-response"},
        )
        step("http.close", {})
        sources = [("tis" if kind.startswith("tis-") else "euro") + "18"]
    elif kind == "rks":
        data = {
            "x_version": "1",
            "software_id": "AUTHORED",
            "software_version": "18",
            "license_key": "NOT-A-LICENSE",
            "vin": "TEST0000000000000",
            "requester_kind": "EXAMPLE",
            "keypair_id": "EXAMPLE",
            "seed": "NOT-A-SEED",
        }
        xml = native.rks_xml(native.RKSData(**data)).decode()
        url, window = "https://example.invalid/offline", "authored-browser"
        # Alphanumeric shape fixture only; not an OEM signature or authorization.
        workflow = {
            "kind": kind,
            "data": data,
            "url": url,
            "allowed_origins": [],
            "watch_count": 1,
            "key_xml": (b"<Signature>" + b"A" * 512 + b"</Signature>").hex(),
        }
        element = {"tag": "textarea", "name": "ReproKeyRequest"}

        def snapshot(elements):
            return {
                "window": window,
                "url": url,
                "busy": False,
                "ready_state": 4,
                "elements": elements,
                "closed": False,
            }

        step("browser.create", {}, window)
        step("browser.navigate", {"window": window, "url": url})
        step("browser.snapshot", {"window": window}, snapshot([element]))
        step(
            "browser.set",
            {
                "window": window,
                "tag": "textarea",
                "name": "ReproKeyRequest",
                "value": xml,
            },
        )
        step(
            "browser.snapshot",
            {"window": window},
            snapshot([{**element, "value": xml}]),
        )
        # Pending authorization: fixture cannot imply a licensed session approved.
        step("browser.snapshot", {"window": window}, snapshot([]))
        step("browser.close", {"window": window})
        sources = ["rks18", "wrapper18"]
    elif kind == "notice":
        config = {
            "title": "Authored notice",
            "message": "Offline replay",
            "color1": 0,
            "color2": 255,
            "interval_ms": 1000,
            "sound_mode": 1,
        }
        workflow = {"kind": kind, "config": config}
        window = "authored-notice"
        step("notice.cursor", {}, [0, 0])
        step(
            "notice.create",
            {
                "title": config["title"],
                "message": config["message"],
                "fullscreen": True,
                "topmost": True,
            },
            window,
        )
        step(
            "notice.render",
            {
                "window": window,
                "color": 255,
                "title": config["title"],
                "message": config["message"],
            },
        )
        step("notice.beep", {"mode": 1, "frequency": 0x6C0, "duration_ms": 1000})
        step("notice.event", {"window": window}, {"window": window, "kind": "key"})
        step("notice.close", {"window": window})
        sources = ["notice18"]
    else:
        raise ValueError("Unknown authored workflow")
    return _json(
        {
            "schema": SCHEMA,
            "provenance": "authored",
            "port_sources": {name: PORT_SOURCES[name] for name in sources},
            "workflow": workflow,
            "steps": steps,
        }
    )
