"""Native CUW service marshalling, RKS browser handoff and local notification.

All external I/O is explicitly injected. No import/constructor opens a browser,
file, service, COM object, device or window. Server-produced keys are never made up.
"""

from __future__ import annotations

import hashlib
import math
import os
import re
import threading
import time
import xml.etree.ElementTree as ET
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol
from urllib.parse import unquote, urlsplit

from scripts.local_files import read_regular

NAMESPACE = "http://www.openuri.org/"
SOAP = "http://schemas.xmlsoap.org/soap/envelope/"
CONVERSATION = "http://www.openuri.org/2002/04/soap/conversation/"
MAX_XML = 1024 * 1024
USER_TYPES_NA = {
    0: "US Dealer",
    1: "Non US Dealer",
    2: "Canadian Dealer",
    3: "Corporate User",
    4: "Public User",
    5: "TMC/TEMA",
}
USER_TYPES_EU = {
    100: "Authorized Repairer",
    101: "Independent Repairer",
    102: "Corporate",
    103: "Standalone",
}
OPERATIONS = {
    "tis-check": "getHealthCheckResults",
    "tis-save": "saveEcuProgram",
    "euro-online": "OnlineCheck",
    "euro-save": "saveEcuProgram",
    "euro-key": "GetKeyForUnlockECUForPSA",
}


class ServiceError(ValueError):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


def _text(value: str, maximum: int = 4096, *, required: bool = False) -> str:
    if not isinstance(value, str) or (required and not value):
        raise ValueError("Required bounded text missing")
    if any(
        not (
            ch in "\t\n\r"
            or 0x20 <= ord(ch) <= 0xD7FF
            or 0xE000 <= ord(ch) <= 0xFFFD
            or 0x10000 <= ord(ch) <= 0x10FFFF
        )
        for ch in value
    ):
        raise ValueError("Text contains invalid XML characters")
    if len(value.encode("utf-16-le")) // 2 > maximum:
        raise ValueError("Text exceeds native field limit")
    return value


def _origin(url: str) -> str:
    _text(url, 4096, required=True)
    parsed = urlsplit(url)
    if (
        parsed.scheme not in ("http", "https")
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or any(ch.isspace() for ch in url)
    ):
        raise ValueError("Explicit HTTP(S) URL without credentials/fragment required")
    port = parsed.port
    default = 443 if parsed.scheme == "https" else 80
    host = parsed.hostname.encode("idna").decode("ascii").lower()
    if any(character in host for character in ("%", "\\")) or any(
        ord(character) < 32 or ord(character) == 127 for character in unquote(url)
    ):
        raise ValueError("URL contains invalid authority or encoded controls")
    if ":" in host:
        host = "[" + host + "]"
    return f"{parsed.scheme}://{host}" + (
        f":{port}" if port is not None and port != default else ""
    )


def _xml(data: bytes) -> ET.Element:
    if not isinstance(data, bytes) or not 1 <= len(data) <= MAX_XML:
        raise ServiceError(42, "XML response exceeds byte bounds")
    try:
        text = (
            data.decode("utf-16")
            if data.startswith((b"\xff\xfe", b"\xfe\xff"))
            else data.decode("utf-8-sig")
        )
        if re.search(r"<!\s*(?:DOCTYPE|ENTITY)\b", text, re.IGNORECASE):
            raise ValueError(
                "XML declarations with external/entity content are forbidden"
            )
        root = ET.fromstring(text)
    except (UnicodeError, ET.ParseError, ValueError) as error:
        raise ServiceError(42, "Malformed or unsafe XML") from error
    nodes = list(root.iter())
    if len(nodes) > 4096:
        raise ServiceError(42, "XML node budget exceeded")
    # Iterative depth accounting avoids recursion on caller-controlled XML.
    pending = [(root, 1)]
    while pending:
        node, depth = pending.pop()
        if depth > 32:
            raise ServiceError(42, "XML depth budget exceeded")
        pending.extend((child, depth + 1) for child in node)
    return root


def _one(parent: ET.Element, tag: str, namespace: str = "") -> ET.Element:
    matches = parent.findall(f"{{{namespace}}}{tag}" if namespace else tag)
    if len(matches) != 1:
        raise ServiceError(49, "Missing or duplicate XML result field")
    return matches[0]


def _value(parent: ET.Element, tag: str, maximum: int, namespace: str = "") -> str:
    node = _one(parent, tag, namespace)
    if list(node):
        raise ServiceError(49, "Nested data in scalar XML result")
    return _text(node.text or "", maximum)


def _element(parent: ET.Element, name: str, value: str | None = None) -> ET.Element:
    child = ET.SubElement(parent, name)
    if value is not None:
        child.text = _text(value)
    return child


@dataclass(frozen=True)
class CalibrationID:
    kind: int
    value: str


def _calibrations(
    parent: ET.Element,
    name: str,
    values: tuple[CalibrationID, ...],
    *,
    product_version: int,
    old: bool,
) -> None:
    if not isinstance(values, tuple) or len(values) > 10:
        raise ValueError("At most ten native calibration entries are allowed")
    container = _element(parent, name)
    for item in values:
        if (
            not isinstance(item, CalibrationID)
            or type(item.kind) is not int
            or not 0 <= item.kind <= 0xFFFFFFFF
        ):
            raise ValueError("Invalid calibration type")
        _text(item.value, 49)
        if not item.value:
            if old and item.kind in (0x49, 0x4A):
                pass
            elif old and product_version == 18:
                continue
            else:
                break
        row = _element(container, "CalibrationDataType")
        _element(row, "CalibrationType", str(item.kind))
        _element(row, "CalibrationId", item.value)


@dataclass(frozen=True, repr=False)
class TISRequest:
    product_version: int
    vehicle_session: str
    software_version: str
    vin: str
    date: str
    language: str
    software_id: str
    user_type: str | int
    dealer_code: str
    old_calibrations: tuple[CalibrationID, ...] = ()
    new_calibrations: tuple[CalibrationID, ...] = ()
    flash_success: bool = False
    european_user: bool = False


@dataclass(frozen=True, repr=False)
class EuroRequest:
    product_version: int
    software_id: str
    dealer_code: str = ""
    date: str = ""
    user_type: int = 100
    vin: str = ""
    time: str = ""
    old_calibrations: tuple[CalibrationID, ...] = ()
    new_calibrations: tuple[CalibrationID, ...] = ()


@dataclass(frozen=True, repr=False)
class ProaceRequest:
    product_version: int
    language: str
    gts_guid: str
    date: str
    request_id: str
    ecu_software_id: str
    ecu_hardware_id: str
    vin: str
    iea: str
    frame_ids: tuple[str, str]
    frames: tuple[str, str]
    unlock_seed: str


def _user_type(value: str | int, product_version: int, european: bool) -> str:
    if product_version == 18:
        if not isinstance(value, str):
            raise ValueError("Version 18 requires a literal UserType string")
        return _text(value, 512)
    if type(value) is not int:
        raise ValueError("Version 12 requires the native numeric UserType")
    return (USER_TYPES_EU if european else USER_TYPES_NA).get(value, "")


def _body(operation: str, data: TISRequest | EuroRequest | ProaceRequest) -> ET.Element:
    if data.product_version not in (12, 18):
        raise ValueError("Only supplied CUW builds 12/18 are supported")
    name = OPERATIONS[operation]
    if operation.startswith("tis-"):
        if not isinstance(data, TISRequest):
            raise ValueError("TIS request structure required")
        root = ET.Element(name, xmlns=NAMESPACE)
        body = _element(root, "milInput")
        fields = [
            ("DealerCode", data.dealer_code, 272),
            ("VehicleConnectSession", data.vehicle_session, 127),
            ("Version", data.software_version, 255),
            ("Vin", data.vin, 17),
            ("Date", data.date, 39),
            ("Language", data.language, 4),
            (
                "Type",
                "ReprogramCheck-CUW" if operation == "tis-check" else "ReprogramResult",
                64,
            ),
            ("SoftwareId", data.software_id, 63),
            (
                "UserType",
                _user_type(data.user_type, data.product_version, data.european_user),
                512,
            ),
        ]
        for tag, value, limit in fields:
            _element(body, tag, _text(value, limit))
        _calibrations(
            body,
            "CalibrationId",
            data.old_calibrations,
            product_version=data.product_version,
            old=True,
        )
        if operation == "tis-save":
            _calibrations(
                body,
                "NewCalibrationId",
                data.new_calibrations,
                product_version=data.product_version,
                old=False,
            )
            if type(data.flash_success) is not bool:
                raise ValueError("Explicit flash result must be boolean")
            _element(body, "IsFlashSuccess", "true" if data.flash_success else "false")
        return root
    if operation == "euro-key":
        if not isinstance(data, ProaceRequest):
            raise ValueError("PROACE key request structure required")
        root = ET.Element("proace_request")
        body = _element(root, "milInput")
        for tag, value, limit in [
            ("user-language", data.language, 4),
            ("gts-guid", data.gts_guid, 63),
            ("date", data.date, 39),
            ("request-id", data.request_id, 83),
            ("ecusoftwareid", data.ecu_software_id, 10),
            ("ecuhardwareid", data.ecu_hardware_id, 10),
        ]:
            _element(body, tag, _text(value, limit))
        repairing = _element(body, "repairing-requests")
        parameters = _element(repairing, "parameters")
        _element(parameters, "vin", _text(data.vin, 17))
        ecu = _element(parameters, "ecu")
        _element(ecu, "iea", _text(data.iea, 2))
        frames = _element(ecu, "frames")
        if len(data.frame_ids) != 2 or len(data.frames) != 2:
            raise ValueError("Native PROACE request requires two frames")
        for frame_id, value in zip(data.frame_ids, data.frames, strict=True):
            row = _element(frames, "frame")
            _element(row, "id", _text(frame_id, 4))
            _element(row, "value", _text(value, 510))
        _element(ecu, "unlock-seed", _text(data.unlock_seed, 511))
        _element(_element(repairing, "requests"), "unlock-request")
        return root
    if not isinstance(data, EuroRequest):
        raise TypeError("Euro service request structure required")
    root = ET.Element(name, xmlns=NAMESPACE)
    body = _element(root, "milInput")
    if operation == "euro-save":
        _element(body, "DealerCode", _text(data.dealer_code, 255))
        _element(body, "Date", _text(data.date, 39))
    _element(body, "SoftwareId", _text(data.software_id, 63))
    if operation == "euro-save":
        _element(body, "UserType", USER_TYPES_EU.get(data.user_type, ""))
        event = _element(body, "CalibrationEvent")
        _element(event, "Vin", _text(data.vin, 17))
        _element(event, "Time", _text(data.time, 255))
        for name, values in [
            ("OldCalibrationId", data.old_calibrations),
            ("NewCalibrationId", data.new_calibrations),
        ]:
            if not isinstance(values, tuple) or len(values) > 10:
                raise ValueError("At most ten Euro calibration entries allowed")
            container = _element(event, name)
            for item in values:
                if (
                    not isinstance(item, CalibrationID)
                    or type(item.kind) is not int
                    or not 0 <= item.kind <= 0xFFFFFFFF
                ):
                    raise ValueError("Invalid calibration entry")
                if not _text(item.value, 49):
                    break
                _element(container, "CalibrationType", str(item.kind))
                _element(container, "CalibrationId", item.value)
    return root


@dataclass(frozen=True)
class ServiceHTTPRequest:
    endpoint: str
    action: str
    body: bytes = field(repr=False)
    connector_properties: tuple[tuple[str, str], ...] = ()
    content_type: str = "text/xml; charset=utf-8"


def build_service_request(
    operation: str, data: TISRequest | EuroRequest | ProaceRequest, *, endpoint: str
) -> ServiceHTTPRequest:
    if operation not in OPERATIONS:
        raise ValueError("Unknown CUW service operation")
    if not isinstance(data, (TISRequest, EuroRequest, ProaceRequest)):
        raise TypeError("Typed CUW request required")
    _origin(endpoint)
    body = _body(operation, data)
    envelope = ET.Element("soap:Envelope", {"xmlns:soap": SOAP})
    header = _element(envelope, "soap:Header")
    ET.SubElement(header, "con:StartHeader", {"xmlns:con": CONVERSATION})
    container = _element(envelope, "soap:Body")
    container.append(body)
    encoded = ET.tostring(envelope, encoding="utf-8", xml_declaration=True)
    if len(encoded) > MAX_XML:
        raise ValueError("Service request XML byte budget exceeded")
    # Native COM ConnectTimeout string points at DOS-header byte 8 (0x04).
    # Retain it as opaque connector metadata; the transport uses seconds separately.
    properties = (
        ("EndPointURL", endpoint),
        ("ProxyServer", "<CURRENT_USER>"),
        ("Timeout", "30000"),
        ("ConnectTimeout", "\x04"),
        ("SoapAction", NAMESPACE + OPERATIONS[operation]),
    )
    return ServiceHTTPRequest(
        endpoint, NAMESPACE + OPERATIONS[operation], encoded, properties
    )


@dataclass(frozen=True)
class ServiceMessage:
    message_id: str
    title: str
    content_type: str
    message: str


@dataclass(frozen=True)
class UnlockResult:
    level: str
    code: str
    comment: str
    value: str | None = field(repr=False)


@dataclass(frozen=True)
class ServiceResult:
    native_status: int
    operation: str
    source: str
    source_sha256: str
    messages: tuple[ServiceMessage, ...] = ()
    unlock: UnlockResult | None = None


def parse_service_response(
    operation: str, body: bytes, *, source: str
) -> ServiceResult:
    if operation not in OPERATIONS:
        raise ValueError("Unknown CUW service operation")
    _text(source, 4096, required=True)
    root = _xml(body)
    digest = hashlib.sha256(body).hexdigest()
    if root.tag == f"{{{SOAP}}}Envelope":
        soap_body = _one(root, "Body", SOAP)
        faults = soap_body.findall(f"{{{SOAP}}}Fault")
        if faults:
            if len(faults) != 1:
                raise ServiceError(44, "Duplicate SOAP fault")
            fault = faults[0]
            message = ServiceMessage(
                "",
                _value(fault, "faultcode", 99),
                "TEXT",
                _value(fault, "faultstring", 2500),
            )
            return ServiceResult(3, operation, source, digest, (message,))
        candidates = list(soap_body)
        if len(candidates) != 1:
            raise ServiceError(48, "Ambiguous SOAP body")
        root = candidates[0]
    if operation == "euro-key":
        if root.tag == f"{{{NAMESPACE}}}{OPERATIONS[operation]}Response":
            result = _one(root, OPERATIONS[operation] + "Result", NAMESPACE)
            if list(result):
                raise ServiceError(42, "Expected embedded PROACE response XML text")
            root = _xml((result.text or "").encode())
        if root.tag != "milmessage":
            raise ServiceError(49, "Expected native milmessage response")
        repairing = _one(root, "repairing-requests")
        unlocking = _one(_one(repairing, "requests"), "unlocking-content")
        code_node = _one(unlocking, "return-code")
        level = _value(code_node, "level", 1)
        code = _value(code_node, "value", 6)
        comment = _value(code_node, "comment", 100)
        value = _value(unlocking, "unlocking-value", 24) if code == "000000" else None
        if code == "000000" and not value:
            raise ServiceError(49, "Server returned no unlocking value")
        return ServiceResult(
            1 if code == "000000" else 50,
            operation,
            source,
            digest,
            unlock=UnlockResult(level, code, comment, value),
        )
    name = OPERATIONS[operation]
    if root.tag == f"{{{NAMESPACE}}}{name}Response":
        result = _one(root, name + "Result", NAMESPACE)
    elif root.tag == f"{{{NAMESPACE}}}{name}Result":
        result = root
    else:
        raise ServiceError(49, "Service response operation/namespace mismatch")
    nodes = _one(result, "MilMessages", NAMESPACE).findall(f"{{{NAMESPACE}}}MilMessage")
    if len(nodes) > 50:
        raise ServiceError(48, "Native response message limit exceeded")
    if operation.startswith("tis-"):
        messages = tuple(
            ServiceMessage(
                _value(node, "MessageId", 29, NAMESPACE),
                _value(node, "Title", 99, NAMESPACE),
                _value(node, "MessageContentType", 9, NAMESPACE),
                _value(node, "Message", 2500, NAMESPACE),
            )
            for node in nodes
        )
        return ServiceResult(1, operation, source, digest, messages)
    if len(nodes) != 1:
        raise ServiceError(48, "Euro service requires exactly one message")
    message = _value(nodes[0], "Message", 255, NAMESPACE)
    expected = (
        "OnlineCheck message OK."
        if operation == "euro-online"
        else "Message received OK."
    )
    return ServiceResult(
        1 if message == expected else 50,
        operation,
        source,
        digest,
        (ServiceMessage("", "", "TEXT", message),),
    )


@dataclass(frozen=True)
class ServiceHTTPResponse:
    status: int
    body: bytes = field(repr=False)
    source: str


class ServiceTransport(Protocol):
    def exchange(
        self,
        request: ServiceHTTPRequest,
        *,
        timeout: float,
        cancelled: Callable[[], bool],
    ) -> ServiceHTTPResponse: ...
    def close(self) -> None: ...


class _Deadline:
    def __init__(
        self, timeout: float, cancelled: Callable[[], bool], clock: Callable[[], float]
    ):
        if not math.isfinite(timeout) or not 0 < timeout <= 600:
            raise ValueError("Timeout must be finite and in (0, 600] seconds")
        self.cancelled, self.clock = cancelled, clock
        started = clock()
        if not math.isfinite(started):
            raise ValueError("Deadline clock must be finite")
        self.end = started + timeout

    def remaining(self) -> float:
        if self.cancelled():
            raise InterruptedError("CUW operation cancelled")
        remaining = self.end - self.clock()
        if not math.isfinite(remaining):
            raise ValueError("Deadline clock must be finite")
        if remaining <= 0:
            raise TimeoutError("CUW operation deadline exhausted")
        return remaining

    def stopped(self) -> bool:
        return self.cancelled() or self.clock() >= self.end


def _cleanup(close: Callable[[], None], original: BaseException | None) -> bool:
    try:
        close()
    except BaseException as error:
        if original is None:
            raise
        original.add_note(f"Owned CUW cleanup also failed: {type(error).__name__}")
        return False
    return True


class ServiceClient:
    def __init__(
        self,
        transport: ServiceTransport,
        *,
        cancelled: Callable[[], bool] | None = None,
        timeout: float = 30,
        clock: Callable[[], float] = time.monotonic,
    ):
        if not math.isfinite(timeout) or not 0 < timeout <= 600:
            raise ValueError("Invalid service timeout")
        self.transport, self.cancelled, self.timeout, self.clock = (
            transport,
            cancelled or (lambda: False),
            timeout,
            clock,
        )
        self.state = "new"
        self._lock = threading.RLock()

    def run(
        self,
        operation: str,
        data: TISRequest | EuroRequest | ProaceRequest,
        *,
        endpoint: str,
    ) -> ServiceResult:
        request = build_service_request(operation, data, endpoint=endpoint)
        with self._lock:
            if self.state != "new":
                raise RuntimeError(
                    "Service execution is terminal; automatic retry forbidden"
                )
            self.state = "running"
            original = None
            try:
                budget = _Deadline(self.timeout, self.cancelled, self.clock)
                response = self.transport.exchange(
                    request, timeout=budget.remaining(), cancelled=budget.stopped
                )
                budget.remaining()
                if (
                    not isinstance(response, ServiceHTTPResponse)
                    or type(response.status) is not int
                    or not 100 <= response.status <= 599
                ):
                    raise ValueError("Invalid HTTP/COM response structure")
                if response.status != 200:
                    if response.status != 500:
                        raise ServiceError(
                            21, "Service returned unsuccessful HTTP status"
                        )
                    fault = parse_service_response(
                        operation, response.body, source=response.source
                    )
                    if fault.native_status != 3:
                        raise ServiceError(21, "HTTP 500 did not contain a SOAP fault")
                    result = fault
                else:
                    result = parse_service_response(
                        operation, response.body, source=response.source
                    )
                self.state = "result"
                return result
            except BaseException as error:
                original = error
                self.state = "uncertain"
                raise
            finally:
                try:
                    _cleanup(self.transport.close, original)
                except BaseException:
                    self.state = "uncertain"
                    raise


@dataclass(frozen=True, repr=False)
class RKSData:
    x_version: str
    software_id: str
    software_version: str
    license_key: str
    vin: str
    requester_kind: str
    keypair_id: str
    seed: str


def rks_xml(data: RKSData) -> bytes:
    if not isinstance(data, RKSData):
        raise TypeError("Stored RKS request data required")
    root = ET.Element("ReproKeyRequest")
    _element(root, "X-Version", _text(data.x_version))
    terminal = _element(root, "TerminalInfo")
    for tag, value in [
        ("SoftwareID", data.software_id),
        ("SoftwareVersion", data.software_version),
        ("LicenseKey", data.license_key),
    ]:
        _element(terminal, tag, _text(value))
    for tag, value in [
        ("VehicleIdentificationNumber", data.vin),
        ("RequesterKind", data.requester_kind),
        ("KeypairID", data.keypair_id),
        ("SeedValue", data.seed),
    ]:
        _element(root, tag, _text(value))
    ET.indent(root, space="  ")
    body = ET.tostring(root, encoding="utf-8", short_empty_elements=False).replace(
        b"\n", b"\r\n"
    )
    return b'<?xml version="1.0" encoding="UTF-8"?>\r\n' + body


@dataclass(frozen=True)
class ReproKey:
    value: str = field(repr=False)
    source: str
    source_sha256: str


def import_repro_key(data: bytes, *, source: str) -> ReproKey:
    _text(source, 4096, required=True)
    try:
        root = _xml(data)
    except ServiceError as error:
        raise ServiceError(8, "Malformed repro key XML") from error
    if root.tag != "Signature" or list(root):
        raise ServiceError(8, "Repro key XML must have a scalar Signature root")
    value = root.text or ""
    if len(value) != 512:
        raise ServiceError(9, "Repro signature must contain exactly 512 characters")
    if re.fullmatch("[0-9a-zA-Z]+", value, flags=re.ASCII) is None:
        raise ServiceError(10, "Repro signature contains invalid characters")
    return ReproKey(value, source, hashlib.sha256(data).hexdigest())


def _write_new(path: str | Path, data: bytes) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(
        target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600
    )
    with os.fdopen(descriptor, "wb") as destination:
        destination.write(data)
        destination.flush()
        os.fsync(destination.fileno())


@dataclass(frozen=True)
class DOMElement:
    tag: str
    name: str = ""
    element_id: str = ""
    value: str | None = field(default="", repr=False)
    kind: str = ""


@dataclass(frozen=True)
class BrowserSnapshot:
    window: str
    url: str
    busy: bool
    ready_state: int
    elements: tuple[DOMElement, ...] = field(repr=False)
    closed: bool = False


class Browser(Protocol):
    def create_window(
        self, *, timeout: float, cancelled: Callable[[], bool]
    ) -> str: ...
    def navigate(
        self, window: str, url: str, *, timeout: float, cancelled: Callable[[], bool]
    ) -> None: ...
    def snapshot(
        self, window: str, *, timeout: float, cancelled: Callable[[], bool]
    ) -> BrowserSnapshot: ...
    def set_value(
        self,
        window: str,
        tag: str,
        name: str,
        value: str,
        *,
        timeout: float,
        cancelled: Callable[[], bool],
    ) -> None: ...
    def wait(self, seconds: float, *, cancelled: Callable[[], bool]) -> None: ...
    def close(self, window: str, *, timeout: float) -> None: ...


@dataclass(frozen=True)
class WatchingResult:
    native_status: int
    window: str
    url: str


class RKSAccess:
    """Equivalent to five mixed CLR exports, with instance-owned stored data."""

    def __init__(
        self,
        browser: Browser | None = None,
        *,
        cancelled: Callable[[], bool] | None = None,
        timeout: float = 300,
        clock: Callable[[], float] = time.monotonic,
    ):
        if not math.isfinite(timeout) or not 0 < timeout <= 600:
            raise ValueError("Invalid RKS timeout")
        self.browser, self.cancelled, self.timeout, self.clock = (
            browser,
            cancelled or (lambda: False),
            timeout,
            clock,
        )
        self.data: RKSData | None = None
        self.window: str | None = None
        self.origins: frozenset[str] = frozenset()
        self.state = "new"
        self._lock = threading.RLock()

    def set_data(self, data: RKSData) -> None:
        with self._lock:
            if self.state != "new":
                raise RuntimeError("Cannot change seed data after browser handoff")
            rks_xml(data)
            self.data = data

    def xml(self) -> bytes:
        if self.data is None:
            raise ServiceError(1, "Repro request data has not been stored")
        return rks_xml(self.data)

    def export_data(self, path: str | Path) -> None:
        _write_new(path, self.xml())

    def import_key(self, path: str | Path) -> ReproKey:
        try:
            data = read_regular(path, limit=MAX_XML)
        except FileNotFoundError as error:
            raise ServiceError(7, "Repro key file does not exist") from error
        return import_repro_key(data, source="file:" + Path(path).name)

    def _snapshot(self, budget: _Deadline) -> BrowserSnapshot:
        if self.browser is None or self.window is None:
            raise InterruptedError("Owned RKS browser was closed")
        snapshot = self.browser.snapshot(
            self.window, timeout=budget.remaining(), cancelled=budget.stopped
        )
        budget.remaining()
        if (
            not isinstance(snapshot, BrowserSnapshot)
            or snapshot.window != self.window
            or type(snapshot.closed) is not bool
            or snapshot.closed
        ):
            raise ServiceError(13, "Owned browser window is absent or changed")
        if _origin(snapshot.url) not in self.origins:
            raise ServiceError(13, "Browser left the explicit authorization origins")
        if (
            type(snapshot.busy) is not bool
            or type(snapshot.ready_state) is not int
            or snapshot.ready_state not in range(5)
            or not isinstance(snapshot.elements, tuple)
            or len(snapshot.elements) > 1024
        ):
            raise ValueError("Invalid browser snapshot")
        dom_bytes = 0
        for element in snapshot.elements:
            if not isinstance(element, DOMElement):
                raise TypeError("Invalid DOM element")
            for value in (element.tag, element.name, element.element_id, element.kind):
                _text(value, 256)
                dom_bytes += len(value.encode("utf-8"))
            if element.value is not None:
                _text(element.value, MAX_XML // 2)
                dom_bytes += len(element.value.encode("utf-8"))
            if dom_bytes > MAX_XML:
                raise ValueError("DOM text byte budget exceeded")
        return snapshot

    def _close(self, original: BaseException | None = None) -> None:
        if self.window is not None and self.browser is not None:
            window, browser = self.window, self.browser
            if _cleanup(lambda: browser.close(window, timeout=5), original):
                self.window = None

    def request(self, url: str, *, allowed_origins: tuple[str, ...] = ()) -> str:
        with self._lock:
            xml = self.xml().decode("utf-8")
            if self.state != "new" or self.browser is None:
                raise RuntimeError(
                    "An explicit browser provider and new RKS session are required"
                )
            if not isinstance(allowed_origins, tuple) or len(allowed_origins) > 16:
                raise ValueError("Bounded explicit authorization origins required")
            self.origins = frozenset(
                [_origin(url)] + [_origin(origin) for origin in allowed_origins]
            )
            budget = _Deadline(self.timeout, self.cancelled, self.clock)
            self.state = "opening"
            try:
                window = self.browser.create_window(
                    timeout=budget.remaining(), cancelled=budget.stopped
                )
                _text(window, 256, required=True)
                self.window = window
                self.browser.navigate(
                    window, url, timeout=budget.remaining(), cancelled=budget.stopped
                )
                for _ in range(6000):
                    snapshot = self._snapshot(budget)
                    if not snapshot.busy and snapshot.ready_state == 4:
                        fields = [
                            element
                            for element in snapshot.elements
                            if element.tag == "textarea"
                            and element.name == "ReproKeyRequest"
                        ]
                        if len(fields) > 1:
                            raise ServiceError(5, "Ambiguous ReproKeyRequest textareas")
                        if fields:
                            if any(
                                element.element_id == "result_code"
                                and element.value == "0"
                                for element in snapshot.elements
                            ):
                                raise ServiceError(
                                    5, "Stale browser approval preceded the request"
                                )
                            self.browser.set_value(
                                window,
                                "textarea",
                                "ReproKeyRequest",
                                xml,
                                timeout=budget.remaining(),
                                cancelled=budget.stopped,
                            )
                            pasted = self._snapshot(budget)
                            values = [
                                element.value
                                for element in pasted.elements
                                if element.tag == "textarea"
                                and element.name == "ReproKeyRequest"
                            ]
                            if values != [xml]:
                                raise ServiceError(
                                    5, "Browser did not preserve the exact request XML"
                                )
                            self.state = "awaiting-result"
                            return window
                    self.browser.wait(
                        min(0.1, budget.remaining()), cancelled=budget.stopped
                    )
                raise TimeoutError("RKS browser polling work budget exhausted")
            except BaseException as error:
                self.state = "uncertain"
                self._close(error)
                raise

    def watch(self) -> WatchingResult:
        with self._lock:
            if self.state not in ("awaiting-result", "approved") or self.window is None:
                raise RuntimeError("No owned RKS browser handoff to watch")
            try:
                budget = _Deadline(self.timeout, self.cancelled, self.clock)
                snapshot = self._snapshot(budget)
                self.state = "awaiting-result"
                fields = [
                    element
                    for element in snapshot.elements
                    if element.element_id == "result_code"
                ]
                if len(fields) > 1:
                    raise ServiceError(13, "Duplicate browser result_code")
                status = 12
                if fields:
                    result = fields[0]
                    if result.tag != "input" or result.kind != "hidden":
                        raise ServiceError(
                            13, "Authorization result must be an owned hidden input"
                        )
                    if result.value is None:
                        status = 11
                    elif (
                        result.value == "0"
                        and not snapshot.busy
                        and snapshot.ready_state == 4
                    ):
                        status = 0
                        self.state = "approved"
                return WatchingResult(status, self.window, snapshot.url)
            except BaseException as error:
                self.state = "uncertain"
                self._close(error)
                raise

    def close(self) -> None:
        with self._lock:
            try:
                self._close()
            except BaseException:
                self.state = "uncertain"
                raise
            else:
                self.state = "closed"


@dataclass(frozen=True)
class NoticeConfig:
    title: str
    message: str
    color1: int
    color2: int
    interval_ms: int
    sound_mode: int = 2


@dataclass(frozen=True)
class NoticeEvent:
    window: str
    kind: str
    x: int = 0
    y: int = 0


class NoticeHost(Protocol):
    def cursor(
        self, *, timeout: float, cancelled: Callable[[], bool]
    ) -> tuple[int, int]: ...
    def create_window(
        self,
        title: str,
        message: str,
        *,
        fullscreen: bool,
        topmost: bool,
        timeout: float,
        cancelled: Callable[[], bool],
    ) -> str: ...
    def render(
        self,
        window: str,
        color: int,
        title: str,
        message: str,
        *,
        timeout: float,
        cancelled: Callable[[], bool],
    ) -> None: ...
    def beep(
        self,
        mode: int,
        frequency: int,
        duration_ms: int,
        *,
        timeout: float,
        cancelled: Callable[[], bool],
    ) -> None: ...
    def poll_event(
        self, window: str, *, timeout: float, cancelled: Callable[[], bool]
    ) -> NoticeEvent | None: ...
    def close(self, window: str, *, timeout: float) -> None: ...


class CompletionNotice:
    """Local-only notification lifecycle; no completion server or worker thread."""

    def __init__(
        self,
        host: NoticeHost,
        *,
        cancelled: Callable[[], bool] | None = None,
        timeout: float = 300,
        clock: Callable[[], float] = time.monotonic,
    ):
        if not math.isfinite(timeout) or not 0 < timeout <= 600:
            raise ValueError("Invalid completion-notice timeout")
        self.host, self.cancelled, self.timeout, self.clock = (
            host,
            cancelled or (lambda: False),
            timeout,
            clock,
        )
        self.state = "new"
        self.window: str | None = None
        self._lock = threading.RLock()

    def close(self) -> None:
        with self._lock:
            if self.window is not None:
                try:
                    self.host.close(self.window, timeout=5)
                except BaseException:
                    self.state = "uncertain"
                    raise
                else:
                    self.window = None

    def run(self, config: NoticeConfig) -> str:
        if not isinstance(config, NoticeConfig):
            raise TypeError("Completion notice configuration required")
        _text(config.title, 4096)
        _text(config.message, 4096)
        if (
            any(
                type(color) is not int or not 0 <= color <= 0xFFFFFF
                for color in (config.color1, config.color2)
            )
            or type(config.interval_ms) is not int
            or not 1 <= config.interval_ms <= 60000
            or type(config.sound_mode) is not int
            or not -(2**31) <= config.sound_mode < 2**31
        ):
            raise ValueError("Invalid native notice colors, interval or sound mode")
        with self._lock:
            if self.state != "new":
                raise RuntimeError("Completion notice execution is terminal")
            budget = _Deadline(self.timeout, self.cancelled, self.clock)
            window = None
            original = None
            self.state = "showing"
            try:
                anchor = self.host.cursor(
                    timeout=budget.remaining(), cancelled=budget.stopped
                )
                if (
                    not isinstance(anchor, tuple)
                    or len(anchor) != 2
                    or any(type(value) is not int for value in anchor)
                ):
                    raise ValueError("Invalid initial cursor location")
                window = self.host.create_window(
                    config.title,
                    config.message,
                    fullscreen=True,
                    topmost=True,
                    timeout=budget.remaining(),
                    cancelled=budget.stopped,
                )
                _text(window, 256, required=True)
                self.window = window
                phase, next_pulse = 1, self.clock()
                for _ in range(120000):
                    budget.remaining()
                    if self.window is None:
                        raise InterruptedError("Completion notice was closed")
                    now = self.clock()
                    if now >= next_pulse:
                        self.host.render(
                            window,
                            config.color2 if phase else config.color1,
                            config.title,
                            config.message,
                            timeout=budget.remaining(),
                            cancelled=budget.stopped,
                        )
                        if phase and config.sound_mode in (0, 1):
                            self.host.beep(
                                config.sound_mode,
                                0x6C0,
                                config.interval_ms,
                                timeout=budget.remaining(),
                                cancelled=budget.stopped,
                            )
                        phase ^= 1
                        next_pulse = now + config.interval_ms / 1000
                    event = self.host.poll_event(
                        window,
                        timeout=min(
                            0.05,
                            budget.remaining(),
                            max(0.001, next_pulse - self.clock()),
                        ),
                        cancelled=budget.stopped,
                    )
                    budget.remaining()
                    if event is not None:
                        if not isinstance(event, NoticeEvent) or event.window != window:
                            raise ValueError("Notice event belongs to another window")
                        if event.kind in ("key", "left-click", "right-click", "close"):
                            self.state = "dismissed"
                            return event.kind
                        if (
                            event.kind != "move"
                            or type(event.x) is not int
                            or type(event.y) is not int
                        ):
                            raise ValueError("Unknown completion notice event")
                        if (
                            abs(event.x - anchor[0]) > 50
                            or abs(event.y - anchor[1]) > 50
                        ):
                            self.state = "dismissed"
                            return "move"
                raise TimeoutError("Completion notice polling work budget exhausted")
            except BaseException as error:
                original = error
                self.state = "uncertain"
                raise
            finally:
                if window is not None:
                    try:
                        _cleanup(self.close, original)
                    except BaseException:
                        self.state = "uncertain"
                        raise
