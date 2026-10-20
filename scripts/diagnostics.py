"""Read-only, reassembled ISO 15765 OBD application PDUs; no adapter I/O.

This standard OBD subset does not implement Toyota proprietary diagnostics.
The exchange callable must return one complete PDU from the addressed ECU.
"""

import math
import time
from collections.abc import Callable, Iterator, Sequence
from typing import Any

MAX_PDU = 4095
LIVE_PIDS = (0x05, 0x0C, 0x0D, 0x11)
# PID: (byte length, name, scale numerator, denominator, offset, unit).
NUMERIC_PIDS = {
    0x04: (1, "engine_load", 100, 255, 0, "%"),
    0x05: (1, "coolant_temperature", 1, 1, -40, "degC"),
    0x06: (1, "short_term_fuel_trim_bank_1", 100, 128, -100, "%"),
    0x07: (1, "long_term_fuel_trim_bank_1", 100, 128, -100, "%"),
    0x08: (1, "short_term_fuel_trim_bank_2", 100, 128, -100, "%"),
    0x09: (1, "long_term_fuel_trim_bank_2", 100, 128, -100, "%"),
    0x0A: (1, "fuel_gauge_pressure", 3, 1, 0, "kPa"),
    0x0B: (1, "intake_manifold_absolute_pressure", 1, 1, 0, "kPa"),
    0x0C: (2, "engine_speed", 1, 4, 0, "rpm"),
    0x0D: (1, "vehicle_speed", 1, 1, 0, "km/h"),
    0x0E: (1, "timing_advance", 1, 2, -64, "deg"),
    0x0F: (1, "intake_air_temperature", 1, 1, -40, "degC"),
    0x10: (2, "mass_air_flow", 1, 100, 0, "g/s"),
    0x11: (1, "throttle_position", 100, 255, 0, "%"),
    0x1F: (2, "engine_runtime", 1, 1, 0, "s"),
}
PID_SIZES = {
    0x00: 4,
    0x01: 4,
    0x02: 2,
    **{pid: fields[0] for pid, fields in NUMERIC_PIDS.items()},
}
Exchange = Callable[[str, bytes], bytes]


class DiagnosticError(ValueError):
    """Malformed, unsupported or uncorrelated application message."""


class Cancelled(DiagnosticError):
    pass


class NegativeResponse(DiagnosticError):
    def __init__(self, service: int, code: int):
        self.service, self.code = service, code
        super().__init__(f"service {service:02X}: negative response {code:02X}")


def validate_ecu(ecu: str) -> None:
    if (
        not isinstance(ecu, str)
        or not 1 <= len(ecu) <= 64
        or not all(char.isascii() and (char.isalnum() or char in "_-.") for char in ecu)
    ):
        raise DiagnosticError("ECU identifier must be 1..64 ASCII letters/digits/_-.")


def validate_request(request: bytes) -> None:
    """Allow only exact requests understood here; never pass arbitrary writes."""
    if not isinstance(request, bytes):
        raise DiagnosticError("request must be bytes")
    if request in (b"\x03", b"\x07", b"\x0a") or (
        len(request) == 2 and request[0] == 9 and request[1] in (0, 2, 4, 6)
    ):
        return
    if len(request) == 2 and request[0] == 1 and request[1] in PID_SIZES:
        return
    if (
        len(request) == 3
        and request[0] == 2
        and request[1] in (0x00, 0x02, *NUMERIC_PIDS)
        and request[2] == 0
    ):
        return
    raise DiagnosticError("unsupported or non-read-only OBD request")


def correlate(request: bytes, response: bytes) -> bytes:
    """Validate echoed service/PID/frame and return only its data bytes."""
    validate_request(request)
    if not isinstance(response, bytes) or not 1 <= len(response) <= MAX_PDU:
        raise DiagnosticError("response must contain 1..4095 bytes")
    if response[0] == 0x7F:
        if len(response) != 3 or response[1] != request[0]:
            raise DiagnosticError("malformed/unrelated negative response")
        raise NegativeResponse(request[0], response[2])
    prefix = bytes([request[0] + 0x40]) + request[1:]
    if not response.startswith(prefix):
        raise DiagnosticError("response service/PID/frame does not match request")
    data = response[len(prefix) :]
    if request[0] in (1, 2):
        expected = PID_SIZES[request[1]]
        if len(data) != expected:
            raise DiagnosticError(
                f"PID {request[1]:02X} requires {expected} data bytes"
            )
    if request == b"\x09\x00" and len(data) != 4:
        raise DiagnosticError("vehicle information support requires four bytes")
    return data


def decode_dtc(pair: bytes) -> str | None:
    if len(pair) != 2:
        raise DiagnosticError("DTC requires two bytes")
    value = int.from_bytes(pair, "big")
    if value == 0:
        return None
    return f"{'PCBU'[value >> 14]}{(value >> 12) & 3}{value & 0xFFF:03X}"


def decode_dtcs(data: bytes) -> list[str]:
    """CAN OBD response: count byte followed by exactly that many DTC pairs."""
    if not data or len(data) != 1 + data[0] * 2:
        raise DiagnosticError("DTC count/length mismatch (CAN OBD required)")
    codes = [decode_dtc(data[i : i + 2]) for i in range(1, len(data), 2)]
    if None in codes:
        raise DiagnosticError("zero DTC inside counted response")
    return [code for code in codes if code is not None]


def decode_vin(data: bytes) -> str:
    if len(data) != 18 or data[0] != 1:
        raise DiagnosticError("VIN requires one CAN record and 17 characters")
    try:
        vin = data[1:].decode("ascii")
    except UnicodeDecodeError as exc:
        raise DiagnosticError("VIN is not ASCII") from exc
    if not all(char in "ABCDEFGHJKLMNPRSTUVWXYZ0123456789" for char in vin):
        raise DiagnosticError("invalid VIN characters")
    return vin


def decode_readiness(data: bytes) -> dict[str, Any]:
    if len(data) != 4:
        raise DiagnosticError("readiness requires four bytes")
    a, b, c, d = data
    monitors = []
    for bit, name in enumerate(("misfire", "fuel_system", "components")):
        supported = bool(b & (1 << bit))
        monitors.append(
            {
                "name": name,
                "supported": supported,
                "complete": not bool(b & (16 << bit)) if supported else None,
            }
        )
    diesel = bool(b & 8)
    names = (
        {
            0: "NMHC_catalyst",
            1: "NOx_SCR",
            3: "boost_pressure",
            5: "exhaust_gas_sensor",
            6: "particulate_filter",
            7: "EGR_VVT",
        }
        if diesel
        else dict(
            enumerate(
                (
                    "catalyst",
                    "heated_catalyst",
                    "evaporative_system",
                    "secondary_air",
                    "AC_refrigerant",
                    "oxygen_sensor",
                    "oxygen_sensor_heater",
                    "EGR_VVT",
                )
            )
        )
    )
    for bit, name in names.items():
        supported = bool(c & (1 << bit))
        monitors.append(
            {
                "name": name,
                "supported": supported,
                "complete": not bool(d & (1 << bit)) if supported else None,
            }
        )
    return {
        "mil_on": bool(a & 128),
        "dtc_count": a & 127,
        "ignition": "compression" if diesel else "spark",
        "monitors": monitors,
        "raw": data.hex(),
    }


def decode_pid(pid: int, data: bytes) -> dict[str, Any]:
    if type(pid) is not int or pid not in NUMERIC_PIDS or len(data) != PID_SIZES[pid]:
        raise DiagnosticError("unsupported PID or wrong payload length")
    _, name, numerator, denominator, offset, unit = NUMERIC_PIDS[pid]
    raw = int.from_bytes(data, "big")
    value = (
        raw * numerator + offset
        if denominator == 1
        else raw * numerator / denominator + offset
    )
    return {
        "pid": f"{pid:02X}",
        "name": name,
        "value": value,
        "unit": unit,
        "raw": data.hex(),
    }


def _counted_records(data: bytes, width: int) -> list[bytes]:
    if not data or not data[0] or len(data) != 1 + data[0] * width:
        raise DiagnosticError("vehicle information record count/length mismatch")
    return [data[index : index + width] for index in range(1, len(data), width)]


def decode_calibration_ids(data: bytes) -> list[str]:
    result = []
    for record in _counted_records(data, 16):
        value = record.rstrip(b"\x00")
        if not value or any(byte < 0x20 or byte > 0x7E for byte in value):
            raise DiagnosticError(
                "calibration ID requires printable ASCII and trailing NUL padding"
            )
        result.append(value.decode("ascii"))
    return result


def decode_cvns(data: bytes) -> list[str]:
    return [record.hex().upper() for record in _counted_records(data, 4)]


def supported_pids(data: bytes) -> list[int]:
    if len(data) != 4:
        raise DiagnosticError("PID support requires four bytes")
    bitmap = int.from_bytes(data, "big")
    return [pid for pid in range(1, 33) if bitmap & (1 << (32 - pid))]


class Session:
    def __init__(
        self,
        exchange: Exchange,
        cancelled: Callable[[], bool] | None = None,
        clock: Callable[[], float] = time.monotonic,
    ):
        self.clock = clock
        self.exchange = exchange
        self.cancelled = cancelled or (lambda: False)

    def read(self, ecu: str, request: bytes) -> bytes:
        validate_ecu(ecu)
        validate_request(request)
        if self.cancelled():
            raise Cancelled("diagnostic operation cancelled")
        response = self.exchange(ecu, request)
        if self.cancelled():
            raise Cancelled("diagnostic operation cancelled")
        return correlate(request, response)

    def ecu_snapshot(self, ecu: str) -> dict[str, Any]:
        result: dict[str, Any] = {"ecu": ecu, "status": "ok", "errors": []}

        def attempt(name: str, request: bytes, decoder: Callable[[bytes], Any]):
            try:
                result[name] = decoder(self.read(ecu, request))
            except Cancelled:
                raise
            except (DiagnosticError, TimeoutError) as exc:
                result["status"] = "partial"
                result["errors"].append(
                    {"field": name, "type": type(exc).__name__, "message": str(exc)}
                )

        attempt("vin", b"\x09\x02", decode_vin)
        for name, service in (
            ("stored_dtcs", 3),
            ("pending_dtcs", 7),
            ("permanent_dtcs", 10),
        ):
            attempt(name, bytes([service]), decode_dtcs)
        attempt("supported_pids", b"\x01\x00", supported_pids)
        supported = result.get("supported_pids", [])
        if 1 in supported:
            attempt("readiness", b"\x01\x01", decode_readiness)
        result["live"] = []
        for pid in LIVE_PIDS:
            if pid in supported:
                key = f"live_{pid:02X}"
                attempt(
                    key, bytes([1, pid]), lambda data, pid=pid: decode_pid(pid, data)
                )
                if key in result:
                    result["live"].append(result.pop(key))
        # shortcut: only standard frame 0; add other frames after support is proven.
        attempt("freeze_supported_pids", b"\x02\x00\x00", supported_pids)
        freeze_supported = result.get("freeze_supported_pids", [])
        if 2 in freeze_supported:
            attempt("freeze_dtc", b"\x02\x02\x00", decode_dtc)
        result["freeze"] = []
        if result.get("freeze_dtc"):
            for pid in LIVE_PIDS:
                if pid in freeze_supported:
                    key = f"freeze_{pid:02X}"
                    attempt(
                        key,
                        bytes([2, pid, 0]),
                        lambda data, pid=pid: decode_pid(pid, data),
                    )
                    if key in result:
                        result["freeze"].append(result.pop(key))
        return result

    def health_check(self, ecus: Sequence[str]) -> dict[str, Any]:
        if (
            isinstance(ecus, (str, bytes))
            or not ecus
            or len(ecus) > 64
            or any(not isinstance(ecu, str) for ecu in ecus)
            or len(set(ecus)) != len(ecus)
        ):
            raise DiagnosticError("health check requires 1..64 unique configured ECUs")
        for ecu in ecus:
            validate_ecu(ecu)
        return {
            "physical_status": "PHYSICAL_UNCONFIRMED",
            "scope": "standard_obd_can_subset",
            "ecu_source": "configured_not_discovered",
            "ecus": [self.ecu_snapshot(ecu) for ecu in ecus],
        }

    def calibration(self, ecu: str) -> dict[str, Any]:
        result: dict[str, Any] = {
            "ecu": ecu,
            "physical_status": "PHYSICAL_UNCONFIRMED",
            "scope": "standard_obd_can_subset",
            "status": "ok",
            "errors": [],
        }
        validate_ecu(ecu)
        try:
            supported = supported_pids(self.read(ecu, b"\x09\x00"))
        except Cancelled:
            raise
        except (DiagnosticError, TimeoutError) as exc:
            result["status"] = "partial"
            result["errors"].append(
                {
                    "field": "supported_info_types",
                    "type": type(exc).__name__,
                    "message": str(exc),
                }
            )
            return result
        result["supported_info_types"] = supported
        for pid, name, decoder in (
            (4, "calibration_ids", decode_calibration_ids),
            (6, "cvns", decode_cvns),
        ):
            if pid in supported:
                try:
                    result[name] = decoder(self.read(ecu, bytes([9, pid])))
                except Cancelled:
                    raise
                except (DiagnosticError, TimeoutError) as exc:
                    result["status"] = "partial"
                    result["errors"].append(
                        {"field": name, "type": type(exc).__name__, "message": str(exc)}
                    )
        return result

    def poll(
        self, ecu: str, pids: Sequence[int] = LIVE_PIDS, samples: int = 1
    ) -> list[dict[str, Any]]:
        return list(self.iter_poll(ecu, pids, samples))

    def iter_poll(
        self, ecu: str, pids: Sequence[int] = LIVE_PIDS, samples: int = 1
    ) -> Iterator[dict[str, Any]]:
        if type(samples) is not int or not 1 <= samples <= 10000:
            raise DiagnosticError("samples must be 1..10000")
        if (
            not pids
            or len(pids) > len(NUMERIC_PIDS)
            or any(type(pid) is not int or pid not in NUMERIC_PIDS for pid in pids)
            or len(set(pids)) != len(pids)
        ):
            raise DiagnosticError("poll requires unique supported live PIDs")
        validate_ecu(ecu)
        started = previous = self.clock()
        if not math.isfinite(started):
            raise DiagnosticError("poll clock must be finite and monotonic")
        for index in range(samples):
            now = self.clock()
            if not math.isfinite(now) or now < previous:
                raise DiagnosticError("poll clock must be finite and monotonic")
            previous = now
            yield {
                "sample": index,
                "elapsed_seconds": now - started,
                "ecu": ecu,
                "values": [
                    decode_pid(pid, self.read(ecu, bytes([1, pid]))) for pid in pids
                ],
            }
