"""Read-only OBD application PDUs; CAN plus explicitly selected legacy Mode 05.

This standard OBD subset does not implement Toyota proprietary diagnostics.
The exchange callable must return one complete PDU from the addressed ECU.
"""

import math
import struct
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
# SAE J1979 APR2002 Annex B: scalar parameters through PID 4E.
NUMERIC_PIDS.update(
    {
        0x21: (2, "distance_with_mil", 1, 1, 0, "km"),
        0x22: (2, "fuel_rail_relative_pressure", 79, 1000, 0, "kPa"),
        0x23: (2, "fuel_rail_gauge_pressure", 10, 1, 0, "kPa"),
        0x2C: (1, "commanded_egr", 100, 255, 0, "%"),
        0x2D: (1, "egr_error", 100, 128, -100, "%"),
        0x2E: (1, "commanded_evaporative_purge", 100, 255, 0, "%"),
        0x2F: (1, "fuel_tank_level", 100, 255, 0, "%"),
        0x30: (1, "warmups_since_clear", 1, 1, 0, "count"),
        0x31: (2, "distance_since_clear", 1, 1, 0, "km"),
        0x33: (1, "barometric_pressure", 1, 1, 0, "kPa"),
        **{
            pid: (
                2,
                f"catalyst_temperature_bank_{bank}_sensor_{sensor}",
                1,
                10,
                -40,
                "degC",
            )
            for pid, bank, sensor in (
                (0x3C, 1, 1),
                (0x3D, 2, 1),
                (0x3E, 1, 2),
                (0x3F, 2, 2),
            )
        },
        0x42: (2, "control_module_voltage", 1, 1000, 0, "V"),
        0x43: (2, "absolute_load", 100, 255, 0, "%"),
        0x44: (2, "commanded_equivalence_ratio", 1, 32768, 0, "lambda"),
        **{
            pid: (1, name, 100, 255, 0, "%")
            for pid, name in (
                (0x45, "relative_throttle_position"),
                (0x47, "absolute_throttle_B"),
                (0x48, "absolute_throttle_C"),
                (0x49, "accelerator_D"),
                (0x4A, "accelerator_E"),
                (0x4B, "accelerator_F"),
                (0x4C, "commanded_throttle"),
            )
        },
        0x46: (1, "ambient_air_temperature", 1, 1, -40, "degC"),
        0x4D: (2, "runtime_with_mil", 1, 1, 0, "min"),
        0x4E: (2, "time_since_clear", 1, 1, 0, "min"),
    }
)
# Later scalar fields independently checked against CSS Electronics' PID data.
NUMERIC_PIDS.update(
    {
        0x52: (1, "ethanol_percentage", 100, 255, 0, "%"),
        0x53: (2, "absolute_evaporative_vapor_pressure", 1, 200, 0, "kPa"),
        0x54: (2, "evaporative_vapor_pressure", 1, 1, -32767, "Pa"),
        0x59: (2, "fuel_rail_absolute_pressure", 10, 1, 0, "kPa"),
        0x5A: (1, "relative_accelerator_position", 100, 255, 0, "%"),
        0x5B: (1, "hybrid_battery_remaining_life", 100, 255, 0, "%"),
        0x5C: (1, "engine_oil_temperature", 1, 1, -40, "degC"),
        0x5D: (2, "fuel_injection_timing", 1, 128, -210, "deg"),
        0x5E: (2, "engine_fuel_rate", 1, 20, 0, "L/h"),
        0x61: (1, "driver_demand_torque", 1, 1, -125, "%"),
        0x62: (1, "actual_engine_torque", 1, 1, -125, "%"),
        0x63: (2, "engine_reference_torque", 1, 1, 0, "Nm"),
        0x8D: (1, "throttle_position_G", 100, 255, 0, "%"),
        0x8E: (1, "engine_friction_torque", 1, 1, -125, "%"),
        0xA2: (2, "cylinder_fuel_rate", 1, 32, 0, "mg/stroke"),
        0xA6: (4, "odometer", 1, 10, 0, "km"),
    }
)
SUPPORT_BASES = tuple(range(0, 0x100, 0x20))
COMPOUND_SIZES = {
    0x51: 1,
    0x5F: 1,
    0x65: 2,
    0x66: 5,
    0x67: 3,
    0x68: 7,
    0x4F: 4,
    0x50: 4,
    0x64: 5,
    **{pid: 2 for pid in range(0x55, 0x59)},
    0x03: 2,
    0x12: 1,
    0x13: 1,
    0x1C: 1,
    0x1D: 1,
    0x1E: 1,
    0x32: 2,
    0x41: 4,
    **{pid: 2 for pid in range(0x14, 0x1C)},
    **{pid: 4 for pid in (*range(0x24, 0x2C), *range(0x34, 0x3C))},
}
# SAE J1979-DA OCT2011 tables B85-B114: byte offset, width, scale, offset,
# unit, support bit, signedness. Support is separate from the value bytes.
LATE_COMPOUNDS: dict[
    int, tuple[tuple[str, int, int, float, float, str, int, bool], ...]
] = {
    0x69: tuple(
        (
            f"egr_{bank}_{kind}",
            1 + i,
            1,
            100 / (128 if kind == "error" else 255),
            -100 if kind == "error" else 0,
            "%",
            i,
            False,
        )
        for i, (bank, kind) in enumerate(
            (bank, kind)
            for bank in ("A", "B")
            for kind in ("commanded", "actual", "error")
        )
    ),
    **{
        pid: tuple(
            (f"{name}_{bank}_{kind}", 1 + i, 1, 100 / 255, 0, "%", i, False)
            for i, (bank, kind) in enumerate(
                (bank, kind) for bank in ("A", "B") for kind in ("commanded", "actual")
            )
        )
        for pid, name in (
            (0x6A, "intake_flow"),
            (0x6C, "throttle"),
            (0x72, "wastegate"),
        )
    },
    0x6D: (
        ("fuel_pressure_A_commanded", 1, 2, 10, 0, "kPa", 0, False),
        ("fuel_pressure_A_actual", 3, 2, 10, 0, "kPa", 1, False),
        ("fuel_temperature_A", 5, 1, 1, -40, "degC", 2, False),
        ("fuel_pressure_B_commanded", 6, 2, 10, 0, "kPa", 3, False),
        ("fuel_pressure_B_actual", 8, 2, 10, 0, "kPa", 4, False),
        ("fuel_temperature_B", 10, 1, 1, -40, "degC", 5, False),
    ),
    0x6E: tuple(
        (f"injection_pressure_{bank}_{kind}", 1 + i * 2, 2, 10, 0, "kPa", i, False)
        for i, (bank, kind) in enumerate(
            (bank, kind) for bank in ("A", "B") for kind in ("commanded", "actual")
        )
    ),
    0x70: tuple(
        (f"boost_pressure_{bank}_{kind}", 1 + i * 2, 2, 1 / 32, 0, "kPa", bit, False)
        for i, (bank, kind, bit) in enumerate(
            (
                ("A", "commanded", 0),
                ("A", "actual", 1),
                ("B", "commanded", 3),
                ("B", "actual", 4),
            )
        )
    ),
    0x71: tuple(
        (f"vgt_{bank}_{kind}", 1 + i, 1, 100 / 255, 0, "%", bit, False)
        for i, (bank, kind, bit) in enumerate(
            (
                ("A", "commanded", 0),
                ("A", "actual", 1),
                ("B", "commanded", 3),
                ("B", "actual", 4),
            )
        )
    ),
    0x73: tuple(
        (f"exhaust_pressure_bank_{i + 1}", 1 + i * 2, 2, 0.01, 0, "kPa", i, False)
        for i in range(2)
    ),
    0x74: tuple(
        (f"turbo_{bank}_speed", 1 + i * 2, 2, 10, 0, "rpm", i, False)
        for i, bank in enumerate(("A", "B"))
    ),
    **{
        pid: (
            (
                f"turbo_{bank}_compressor_inlet_temperature",
                1,
                1,
                1,
                -40,
                "degC",
                0,
                False,
            ),
            (
                f"turbo_{bank}_compressor_outlet_temperature",
                2,
                1,
                1,
                -40,
                "degC",
                1,
                False,
            ),
            (
                f"turbo_{bank}_turbine_inlet_temperature",
                3,
                2,
                0.1,
                -40,
                "degC",
                2,
                False,
            ),
            (
                f"turbo_{bank}_turbine_outlet_temperature",
                5,
                2,
                0.1,
                -40,
                "degC",
                3,
                False,
            ),
        )
        for pid, bank in ((0x75, "A"), (0x76, "B"))
    },
    0x77: tuple(
        (
            f"charge_air_temperature_bank_{bank}_sensor_{sensor}",
            1 + i,
            1,
            1,
            -40,
            "degC",
            i,
            False,
        )
        for i, (bank, sensor) in enumerate(((1, 1), (1, 2), (2, 1), (2, 2)))
    ),
    **{
        pid: tuple(
            (
                f"exhaust_temperature_bank_{bank}_sensor_{i + 1}",
                1 + i * 2,
                2,
                0.1,
                -40,
                "degC",
                i,
                False,
            )
            for i in range(4)
        )
        for pid, bank in ((0x78, 1), (0x79, 2))
    },
    **{
        pid: tuple(
            (
                f"dpf_bank_{bank}_{name}_pressure",
                1 + i * 2,
                2,
                0.01,
                0,
                "kPa",
                i,
                i == 0,
            )
            for i, name in enumerate(("differential", "inlet", "outlet"))
        )
        for pid, bank in ((0x7A, 1), (0x7B, 2))
    },
    0x7C: tuple(
        (
            f"dpf_bank_{bank}_{kind}_temperature",
            1 + i * 2,
            2,
            0.1,
            -40,
            "degC",
            i,
            False,
        )
        for i, (bank, kind) in enumerate(
            ((1, "inlet"), (1, "outlet"), (2, "inlet"), (2, "outlet"))
        )
    ),
    0x7F: tuple(
        (name, 1 + i * 4, 4, 1, 0, "s", i, False)
        for i, name in enumerate(("engine_runtime", "idle_runtime", "pto_runtime"))
    ),
    0x83: tuple(
        (f"nox_bank_{bank}_sensor_{sensor}", 1 + i * 2, 2, 1, 0, "ppm", i, False)
        for i, (bank, sensor) in enumerate(((1, 1), (1, 2), (2, 1), (2, 2)))
    ),
    0x85: (
        ("reagent_consumption", 1, 2, 0.005, 0, "L/h", 0, False),
        ("reagent_demand", 3, 2, 0.005, 0, "L/h", 1, False),
        ("reagent_level", 5, 1, 100 / 255, 0, "%", 2, False),
        ("nox_warning_runtime", 6, 4, 1, 0, "s", 3, False),
    ),
    0x86: tuple(
        (f"pm_bank_{i + 1}_sensor_1", 1 + i * 2, 2, 0.0125, 0, "mg/m3", i, False)
        for i in range(2)
    ),
    0x87: tuple(
        (f"manifold_pressure_{bank}", 1 + i * 2, 2, 1 / 32, 0, "kPa", i, False)
        for i, bank in enumerate(("A", "B"))
    ),
}
COMPOUND_SIZES.update(
    {
        pid: max(offset + width for _, offset, width, *_ in fields)
        for pid, fields in LATE_COMPOUNDS.items()
    }
)
COMPOUND_SIZES.update(
    {0x6B: 5, 0x6F: 3, 0x70: 10, 0x71: 6, 0x7D: 1, 0x7E: 1, 0x81: 41, 0x82: 41}
)
NUMERIC_PIDS[0x84] = (1, "manifold_surface_temperature", 1, 1, -40, "degC")


def decode_late_compound(pid: int, data: bytes) -> list[dict[str, Any]]:
    if (
        type(pid) is not int
        or pid not in COMPOUND_SIZES
        or len(data) != COMPOUND_SIZES[pid]
    ):
        raise DiagnosticError("unsupported compound PID or wrong payload length")
    fields: list[dict[str, Any]] = []
    if pid in LATE_COMPOUNDS:
        for name, start, width, scale, offset, unit, bit, signed in LATE_COMPOUNDS[pid]:
            supported = bool(data[0] & (1 << bit))
            raw = int.from_bytes(data[start : start + width], "big", signed=signed)
            fields.append(
                {
                    "name": name,
                    "supported": supported,
                    "value": raw * scale + offset if supported else None,
                    "unit": unit,
                }
            )
        if pid in (0x70, 0x71):
            for i, bank in enumerate(("A", "B")):
                supported = bool(data[0] & (1 << (2 + i * 3)))
                code = (data[-1] >> (i * 2)) & 3
                fields.append(
                    {
                        "name": f"control_status_{bank}",
                        "supported": supported,
                        "value": ("reserved", "open_loop", "closed_loop", "fault")[code]
                        if supported
                        else None,
                        "unit": "state",
                    }
                )
    elif pid in (0x6B, 0x6F):
        count, high_offset, factor, offset, unit = (
            (4, 4, 4, -40, "degC") if pid == 0x6B else (2, 2, 8, 0, "kPa")
        )
        for i in range(count):
            wide = bool(data[0] & (1 << (i + high_offset)))
            supported = wide or bool(data[0] & (1 << i))
            fields.append(
                {
                    "name": f"egr_temperature_{('A', 'C', 'B', 'D')[i]}"
                    if pid == 0x6B
                    else f"turbo_inlet_pressure_{('A', 'B')[i]}",
                    "supported": supported,
                    "wide_range": wide,
                    "value": data[1 + i] * (factor if wide else 1) + offset
                    if supported
                    else None,
                    "unit": unit,
                }
            )
    elif pid in (0x7D, 0x7E):
        for bit, name in enumerate(
            (
                "inside_control_area",
                "outside_control_area",
                "manufacturer_carveout",
                "deficiency_area",
            )
        ):
            fields.append(
                {
                    "name": name,
                    "supported": True,
                    "value": bool(data[0] & (1 << bit)),
                    "unit": "bool",
                }
            )
    elif pid in (0x81, 0x82):
        for i in range(5):
            supported = bool(data[0] & (1 << i))
            for timer in (1, 2):
                start = 1 + i * 8 + (timer - 1) * 4
                raw = int.from_bytes(data[start : start + 4], "big")
                available = supported and not (timer == 2 and raw == 0xFFFFFFFF)
                fields.append(
                    {
                        "name": f"aecd_{i + (1 if pid == 0x81 else 6)}_timer_{timer}",
                        "supported": supported,
                        "available": available,
                        "value": raw if available else None,
                        "unit": "s",
                    }
                )
    else:
        raise DiagnosticError("compound PID has no definition")
    return fields


PID_SIZES = {
    **{base: 4 for base in SUPPORT_BASES},
    **COMPOUND_SIZES,
    0x01: 4,
    0x02: 2,
    **{pid: fields[0] for pid, fields in NUMERIC_PIDS.items()},
}
OXYGEN_TEST_SCALES = {
    **{tid: (0.005, "V") for tid in (1, 2, 3, 4, 7, 8)},
    **{tid: (0.004, "s") for tid in (5, 6)},
    **{tid: (0.04, "s") for tid in (9, 10)},
    **{
        tid: (scale, unit)
        for first, last, scale, unit in (
            (0x21, 0x2F, 0.004, "s"),
            (0x30, 0x3F, 0.04, "s"),
            (0x41, 0x4F, 0.005, "V"),
            (0x50, 0x5F, 0.05, "V"),
            (0x61, 0x6F, 0.1, "Hz"),
            (0x70, 0x7F, 1, "count"),
        )
        for tid in range(first, last + 1)
    },
}
VARIABLE_TRIM_PIDS = (6, 7, 8, 9, 0x55, 0x56, 0x57, 0x58)
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
        len(request) == 2
        and request[0] == 9
        and request[1] in (*SUPPORT_BASES, *range(1, 16))
    ):
        return
    if len(request) == 2 and request[0] == 1 and request[1] in PID_SIZES:
        return
    if (
        len(request) == 3
        and request[0] == 2
        and request[1] in PID_SIZES
        and request[1] not in (1, 0x41)
        and request[2] == 0
    ):
        return
    if len(request) == 2 and request[0] == 6:
        return
    if (
        len(request) == 3
        and request[0] == 5
        and request[1] in (*SUPPORT_BASES, *OXYGEN_TEST_SCALES)
        and request[2] in (1, 2, 4, 8, 16, 32, 64, 128)
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
    if request[0] == 6 and request[1] not in SUPPORT_BASES:
        if response[0] != 0x46:
            raise DiagnosticError("response service does not match Mode 06")
        records = decode_monitor_records(request[1], response[1:])
        if not records:
            raise DiagnosticError("empty Mode 06 response")
        return response[1:]
    prefix = bytes([request[0] + 0x40]) + request[1:]
    if not response.startswith(prefix):
        raise DiagnosticError("response service/PID/frame does not match request")
    data = response[len(prefix) :]
    if request[0] in (1, 2):
        expected = PID_SIZES[request[1]]
        if len(data) not in (
            (1, 2) if request[1] in VARIABLE_TRIM_PIDS else (expected,)
        ):
            raise DiagnosticError(
                f"PID {request[1]:02X} requires {expected} data bytes"
            )
    if request[0] in (5, 6, 9) and request[1] in SUPPORT_BASES and len(data) != 4:
        raise DiagnosticError("support bitmap requires four bytes")
    if request[0] == 5 and request[1] not in SUPPORT_BASES:
        decode_oxygen_test(request[1], data)
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


def supported_pids(data: bytes, base: int = 0) -> list[int]:
    if type(base) is not int or base not in SUPPORT_BASES or len(data) != 4:
        raise DiagnosticError("PID support requires four bytes and a valid base")
    if base == 0xE0 and data[3] & 1:
        raise DiagnosticError("final support page cannot advertise identifier 256")
    bitmap = int.from_bytes(data, "big")
    return [
        base + pid
        for pid in range(1, 33)
        if base + pid < 256 and bitmap & (1 << (32 - pid))
    ]


# (scale, offset, unit); signedness is the UASID high bit, not a midpoint offset.
# SAE J1979-DA OCT2011 Annex E, tables E1-E92. Decimal scaling/bit columns
# are authoritative here; rounded min/max example text is not a conversion.
MONITOR_SCALES = {
    0x01: (1, 0, "1"),
    0x02: (0.1, 0, "1"),
    0x03: (0.01, 0, "1"),
    0x04: (0.001, 0, "1"),
    0x05: (0.0000305, 0, "1"),
    0x06: (0.000305, 0, "1"),
    0x07: (0.25, 0, "rpm"),
    0x08: (0.01, 0, "km/h"),
    0x09: (1, 0, "km/h"),
    0x0A: (0.000122, 0, "V"),
    0x0B: (0.001, 0, "V"),
    0x0C: (0.01, 0, "V"),
    0x0D: (0.00390625, 0, "mA"),
    0x0E: (0.001, 0, "A"),
    0x0F: (0.01, 0, "A"),
    0x10: (0.001, 0, "s"),
    0x11: (0.1, 0, "s"),
    0x12: (1, 0, "s"),
    0x13: (0.001, 0, "ohm"),
    0x14: (1, 0, "ohm"),
    0x15: (1, 0, "kohm"),
    0x16: (0.1, -40, "degC"),
    0x17: (0.01, 0, "kPa"),
    0x18: (0.0117, 0, "kPa"),
    0x19: (0.079, 0, "kPa"),
    0x1A: (1, 0, "kPa"),
    0x1B: (10, 0, "kPa"),
    0x1C: (0.01, 0, "deg"),
    0x1D: (0.5, 0, "deg"),
    0x1E: (0.0000305, 0, "lambda"),
    0x1F: (0.05, 0, "A/F"),
    0x20: (0.00390625, 0, "1"),
    0x21: (0.001, 0, "Hz"),
    0x22: (1, 0, "Hz"),
    0x23: (1, 0, "kHz"),
    0x24: (1, 0, "count"),
    0x25: (1, 0, "km"),
    0x26: (0.0001, 0, "V/ms"),
    0x27: (0.01, 0, "g/s"),
    0x28: (1, 0, "g/s"),
    0x29: (0.25, 0, "Pa/s"),
    0x2A: (0.001, 0, "kg/h"),
    0x2B: (1, 0, "switches"),
    0x2C: (0.01, 0, "g/cyl"),
    0x2D: (0.01, 0, "mg/stroke"),
    0x2E: (1, 0, "bool"),
    0x2F: (0.01, 0, "%"),
    0x30: (0.001526, 0, "%"),
    0x31: (0.001, 0, "L"),
    0x32: (0.0000305, 0, "inch"),
    0x33: (0.00024414, 0, "lambda"),
    0x34: (1, 0, "min"),
    0x35: (0.01, 0, "s"),
    0x36: (0.01, 0, "g"),
    0x37: (0.1, 0, "g"),
    0x38: (1, 0, "g"),
    0x39: (0.01, -327.68, "%"),
    0x3A: (0.001, 0, "g"),
    0x3B: (0.0001, 0, "g"),
    0x3C: (0.1, 0, "us"),
    0x3D: (0.01, 0, "mA"),
    0x3E: (0.00006103516, 0, "mm2"),
    0x3F: (0.01, 0, "L"),
    0x40: (1, 0, "ppm"),
    0x41: (0.01, 0, "uA"),
    **{
        code + 0x80: (scale, 0, "1")
        for code, scale in (
            (1, 1),
            (2, 0.1),
            (3, 0.01),
            (4, 0.001),
            (5, 0.0000305),
            (6, 0.000305),
        )
    },
    0x87: (1, 0, "ppm"),
    0x8A: (0.000122, 0, "V"),
    0x8B: (0.001, 0, "V"),
    0x8C: (0.01, 0, "V"),
    0x8D: (0.00390625, 0, "mA"),
    0x8E: (0.001, 0, "A"),
    0x90: (0.001, 0, "s"),
    0x96: (0.1, 0, "degC"),
    0x99: (0.1, 0, "kPa"),
    0x9C: (0.01, 0, "deg"),
    0x9D: (0.5, 0, "deg"),
    0xA8: (1, 0, "g/s"),
    0xA9: (0.25, 0, "Pa/s"),
    0xAD: (0.01, 0, "mg/stroke"),
    0xAE: (0.1, 0, "mg/stroke"),
    0xAF: (0.01, 0, "%"),
    0xB0: (0.003052, 0, "%"),
    0xB1: (2, 0, "mV/s"),
    0xFC: (0.01, 0, "kPa"),
    0xFD: (0.001, 0, "kPa"),
    0xFE: (0.25, 0, "Pa"),
}
MONITOR_NAMES = {
    **{
        base + i: f"{name}_bank_{(i - 1) // 4 + 1}_sensor_{(i - 1) % 4 + 1}"
        for base, name in (
            (0, "exhaust_gas_sensor"),
            (0x40, "exhaust_gas_sensor_heater"),
        )
        for i in range(1, 17)
    },
    **{
        base + i: f"{name}_bank_{i}"
        for base, name, count in (
            (0x20, "catalyst", 4),
            (0x30, "EGR", 4),
            (0x34, "VVT", 4),
            (0x60, "heated_catalyst", 4),
            (0x80, "fuel_system", 4),
            (0x84, "boost_pressure", 2),
        )
        for i in range(1, count + 1)
    },
    0x39: "EVAP_cap_off_0.150_inch",
    0x3A: "EVAP_0.090_inch",
    0x3B: "EVAP_0.040_inch",
    0x3C: "EVAP_0.020_inch",
    0x3D: "purge_flow",
    **{0x70 + i: f"secondary_air_{i}" for i in range(1, 5)},
    0x90: "NOx_adsorber_bank_1",
    0x91: "NOx_adsorber_bank_2",
    0x98: "NOx_SCR_catalyst_bank_1",
    0x99: "NOx_SCR_catalyst_bank_2",
    0xA1: "misfire_general",
    **{0xA1 + i: f"misfire_cylinder_{i}" for i in range(1, 17)},
    0xB2: "PM_filter_bank_1",
    0xB3: "PM_filter_bank_2",
}
OXYGEN_TEST_NAMES = (
    "rich_to_lean_threshold",
    "lean_to_rich_threshold",
    "low_switch_voltage",
    "high_switch_voltage",
    "rich_to_lean_switch_time",
    "lean_to_rich_switch_time",
    "minimum_voltage",
    "maximum_voltage",
    "transition_time",
    "sensor_period",
    "EWMA_misfire_count",
    "misfire_count",
)


def decode_monitor_records(mid: int, data: bytes) -> list[dict[str, Any]]:
    """CAN Mode 06 records include the MID again for EACH 9-byte record."""
    if type(mid) is not int or not 0 < mid <= 255 or mid in SUPPORT_BASES:
        raise DiagnosticError("invalid monitor ID")
    if not data or len(data) > MAX_PDU - 1 or len(data) % 9:
        raise DiagnosticError("Mode 06 requires complete nine-byte records")
    results = []
    seen = set()
    for echoed, tid, scaling, raw_value, raw_min, raw_max in struct.iter_unpack(
        ">BBBHHH", data
    ):
        if echoed != mid or tid in seen or tid in (0, 255):
            raise DiagnosticError("uncorrelated, duplicate or reserved monitor test")
        seen.add(tid)
        if 1 <= tid <= 10 and scaling != (0x10 if tid in (5, 6, 9, 10) else 0x0A):
            raise DiagnosticError(
                "standard oxygen TID contradicts its specified scaling ID"
            )
        if tid in (11, 12) and (not 0xA2 <= mid <= 0xAD or scaling != 0x24):
            raise DiagnosticError(
                "standard misfire TID requires cylinder MID A2..AD and scaling24"
            )
        record: dict[str, Any] = {
            "mid": f"{mid:02X}",
            "monitor_name": MONITOR_NAMES.get(
                mid, "manufacturer_defined" if mid >= 0xE1 else "reserved"
            ),
            "tid": f"{tid:02X}",
            "scaling_id": f"{scaling:02X}",
            "raw_value": raw_value,
            "raw_minimum": raw_min,
            "raw_maximum": raw_max,
            "definition_source": "SAE_J1979_DA_201110_Annex_E",
            "test_name": OXYGEN_TEST_NAMES[tid - 1]
            if 1 <= tid <= 12
            else "manufacturer_defined"
            if tid >= 128
            else "reserved",
        }
        if scaling not in MONITOR_SCALES:
            record.update(status="unresolved_scaling", unit=None)
            results.append(record)
            continue
        scale, offset, unit = MONITOR_SCALES[scaling]
        raw = (raw_value, raw_min, raw_max)
        if scaling == 0x2E and any(value > 1 for value in raw):
            raise DiagnosticError("boolean monitor value must be zero or one")
        values = [
            (
                (value - 65536 if scaling & 128 and value & 32768 else value) * scale
                + offset
            )
            for value in raw
        ]
        value, minimum, maximum = values
        if minimum > maximum:
            raise DiagnosticError("monitor minimum exceeds maximum")
        status = (
            "not_completed"
            if raw == (0, 0, 0)
            else "pass"
            if minimum <= value <= maximum
            else "fail"
        )
        record.update(
            value=value, minimum=minimum, maximum=maximum, unit=unit, status=status
        )
        results.append(record)
    return results


def decode_oxygen_test(tid: int, data: bytes) -> dict[str, Any]:
    """Legacy non-CAN service 05, constant tests omit both limit bytes."""
    if (
        type(tid) is not int
        or tid not in OXYGEN_TEST_SCALES
        or len(data) != (1 if tid <= 4 else 3)
    ):
        raise DiagnosticError("invalid legacy oxygen test or length")
    scale, unit = OXYGEN_TEST_SCALES[tid]
    result: dict[str, Any] = {
        "tid": f"{tid:02X}",
        "name": OXYGEN_TEST_NAMES[tid - 1] if tid <= 10 else "manufacturer_defined",
        "value": data[0] * scale,
        "unit": unit,
        "raw": data.hex(),
    }
    if len(data) == 3:
        if data[1] > data[2]:
            raise DiagnosticError("oxygen test minimum exceeds maximum")
        result.update(
            minimum=data[1] * scale,
            maximum=data[2] * scale,
            status="pass" if data[1] <= data[0] <= data[2] else "fail",
        )
    else:
        result["status"] = "constant"
    return result


def decode_parameter(
    pid: int,
    data: bytes,
    configuration_4f: bytes | None = None,
    configuration_50: bytes | None = None,
) -> dict[str, Any]:
    """Decode scalar or compound service 01/02 data with exact field bounds."""
    if (
        type(pid) is not int
        or pid not in PID_SIZES
        or len(data) not in ((1, 2) if pid in VARIABLE_TRIM_PIDS else (PID_SIZES[pid],))
    ):
        raise DiagnosticError("unsupported parameter or wrong payload length")
    if any(
        config is not None and (not isinstance(config, bytes) or len(config) != 4)
        for config in (configuration_4f, configuration_50)
    ):
        raise DiagnosticError("scaling configuration requires four bytes")
    if pid in (6, 7, 8, 9) and len(data) == 2:
        banks = (1, 3) if pid in (6, 7) else (2, 4)
        return {
            "pid": f"{pid:02X}",
            "raw": data.hex(),
            "fuel_trims": [
                {"bank": bank, "value": byte * 100 / 128 - 100, "unit": "%"}
                for bank, byte in zip(banks, data, strict=True)
            ],
        }
    if pid in NUMERIC_PIDS:
        result = decode_pid(pid, data)
        if configuration_4f and pid in (0x0B, 0x44):
            raw = int.from_bytes(data, "big")
            if pid == 0x0B and configuration_4f[3]:
                result["value"] = raw * configuration_4f[3] * 10 / 255
            elif pid == 0x44 and configuration_4f[0]:
                result["value"] = raw * configuration_4f[0] / 65535
        if configuration_50 and pid == 0x10 and configuration_50[0]:
            result["value"] = (
                int.from_bytes(data, "big") * configuration_50[0] * 10 / 65535
            )
        return result
    result: dict[str, Any] = {"pid": f"{pid:02X}", "raw": data.hex()}
    if pid in LATE_COMPOUNDS or pid in (0x6B, 0x6F, 0x7D, 0x7E, 0x81, 0x82):
        result["fields"] = decode_late_compound(pid, data)
        result["definition_source"] = "SAE_J1979_DA_201110_Annex_B"
    elif pid in SUPPORT_BASES:
        result["supported_pids"] = supported_pids(data, pid)
    elif pid in (1, 0x41):
        status = decode_readiness(data)
        if pid == 0x41:
            status.pop("mil_on")
            status.pop("dtc_count")
        result.update(status)
    elif pid == 2:
        result["dtc"] = decode_dtc(data)
    elif 0x14 <= pid <= 0x1B:
        result.update(
            voltage=data[0] / 200,
            voltage_unit="V",
            fuel_trim=None if data[1] == 255 else data[1] * 100 / 128 - 100,
            fuel_trim_unit="%",
            sensor_index=pid - 0x13,
        )
    elif 0x24 <= pid <= 0x2B or 0x34 <= pid <= 0x3B:
        a, b = struct.unpack(">HH", data)
        result.update(
            equivalence_ratio=a / 32768,
            equivalence_ratio_unit="lambda",
            sensor_index=pid - (0x23 if pid < 0x30 else 0x33),
        )
        if pid < 0x30:
            result.update(voltage=b / 8192, voltage_unit="V")
        else:
            result.update(current=b / 256 - 128, current_unit="mA")
    elif pid == 0x51:
        names = (
            "not_available",
            "gasoline",
            "methanol",
            "ethanol",
            "diesel",
            "LPG",
            "CNG",
            "propane",
            "electric",
            "bifuel_gasoline",
            "bifuel_methanol",
            "bifuel_ethanol",
            "bifuel_LPG",
            "bifuel_CNG",
            "bifuel_propane",
            "bifuel_electric",
            "bifuel_electric_combustion",
            "hybrid_gasoline",
            "hybrid_ethanol",
            "hybrid_diesel",
            "hybrid_electric",
            "hybrid_electric_combustion",
            "hybrid_regeneration",
            "bifuel_diesel",
        )
        result["fuel_type"] = names[data[0]] if data[0] < len(names) else "reserved"
    elif pid == 0x5F:
        result["emission_requirement"] = {
            14: "EURO_IV_B1",
            15: "EURO_V_B2",
            16: "EURO_EEV_C",
        }.get(data[0], "reserved")
    elif pid == 0x65:
        result["auxiliary_status"] = [
            {
                "name": name,
                "supported": bool(data[0] & (1 << bit)),
                "active": bool(data[1] & (1 << bit)) if data[0] & (1 << bit) else None,
            }
            for bit, name in enumerate(
                (
                    "PTO",
                    "automatic_transmission_drive",
                    "manual_transmission_gear",
                    "glow_plug_lamp",
                )
            )
        ]
    elif pid in (0x66, 0x67, 0x68):
        values = struct.unpack(">HH", data[1:]) if pid == 0x66 else data[1:]
        result["name"] = {
            0x66: "mass_air_flow",
            0x67: "coolant_temperature",
            0x68: "intake_air_temperature",
        }[pid]
        result["sensors"] = [
            {
                "sensor": index + 1,
                "supported": bool(data[0] & (1 << index)),
                "value": (value / 32 if pid == 0x66 else value - 40)
                if data[0] & (1 << index)
                else None,
                "unit": "g/s" if pid == 0x66 else "degC",
            }
            for index, value in enumerate(values)
        ]
    elif pid == 0x4F:
        result["scaling_maxima"] = dict(
            zip(
                (
                    "equivalence_ratio",
                    "oxygen_voltage_V",
                    "oxygen_current_mA",
                    "manifold_pressure_tens_kPa",
                ),
                data,
                strict=True,
            )
        )
    elif pid == 0x50:
        result["mass_air_flow_maximum_g_s"] = data[0] * 10
        result["reserved_bytes"] = data[1:].hex()
    elif 0x55 <= pid <= 0x58:
        banks = (1, 3) if pid in (0x55, 0x56) else (2, 4)
        result["secondary_oxygen_trims"] = [
            {"bank": bank, "value": byte * 100 / 128 - 100, "unit": "%"}
            for bank, byte in zip(banks, data, strict=False)
        ]
    elif pid == 0x64:
        result["torque_percent"] = dict(
            zip(
                ("idle", "point_2", "point_3", "point_4", "point_5"),
                (byte - 125 for byte in data),
                strict=True,
            )
        )
    elif pid == 0x32:
        result.update(
            name="evaporative_vapor_pressure",
            value=int.from_bytes(data, "big", signed=True) / 4,
            unit="Pa",
        )
    elif pid in (0x13, 0x1D):
        sensors_per_bank = 4 if pid == 0x13 else 2
        result["sensors"] = [
            {
                "bank": bit // sensors_per_bank + 1,
                "sensor": bit % sensors_per_bank + 1,
                "present": bool(data[0] & (1 << bit)),
            }
            for bit in range(8)
        ]
    elif pid == 3:
        states = {
            0: "unused",
            1: "open_loop_temperature",
            2: "closed_loop",
            4: "open_loop_load_or_deceleration",
            8: "open_loop_fault",
            16: "closed_loop_feedback_fault",
        }
        result["fuel_systems"] = [
            {
                "system": index + 1,
                "status": states.get(value, "reserved"),
                "code": value,
            }
            for index, value in enumerate(data)
        ]
    elif pid == 0x12:
        result["secondary_air"] = {
            1: "upstream",
            2: "downstream",
            4: "off",
            8: "diagnostic_pump",
        }.get(data[0], "reserved")
    elif pid == 0x1C:
        names = (
            "OBD_II",
            "OBD",
            "OBD_and_OBD_II",
            "OBD_I",
            "not_OBD_compliant",
            "EOBD",
            "EOBD_and_OBD_II",
            "EOBD_and_OBD",
            "EOBD_OBD_and_OBD_II",
            "JOBD",
            "JOBD_and_OBD_II",
            "JOBD_and_EOBD",
            "JOBD_EOBD_and_OBD_II",
        )
        result["obd_requirement"] = (
            names[data[0] - 1] if 1 <= data[0] <= len(names) else "reserved"
        )
    elif pid == 0x1E:
        result["pto_active"] = bool(data[0] & 1)
    else:
        raise DiagnosticError("parameter has no semantic decoder")
    if configuration_4f and (0x24 <= pid <= 0x2B or 0x34 <= pid <= 0x3B):
        ratio, voltage, current, _ = configuration_4f
        a, b = struct.unpack(">HH", data)
        if ratio:
            result["equivalence_ratio"] = a * ratio / 65535
        if pid < 0x30 and voltage:
            result["voltage"] = b * voltage / 65535
        elif pid >= 0x30 and current:
            result["current"] = (b - 32768) * current / 32768
    return result


def decode_response(request: bytes, response: bytes) -> Any:
    """One semantic validator shared by replay and recording."""
    data = correlate(request, response)
    service = request[0]
    if service in (3, 7, 10):
        return decode_dtcs(data)
    if service == 6 and request[1] not in SUPPORT_BASES:
        return decode_monitor_records(request[1], data)
    if service in (5, 6, 9) and request[1] in SUPPORT_BASES:
        return supported_pids(data, request[1])
    if service == 5:
        return decode_oxygen_test(request[1], data)
    if service == 9:
        return decode_information(request[1], data)
    return decode_parameter(request[1], data)


def decode_ecu_names(data: bytes) -> list[str]:
    names = []
    for record in _counted_records(data, 20):
        if record[4] != 0x2D:
            raise DiagnosticError("ECU name requires dash delimiter at byte five")
        fields = [field.rstrip(b"\x00") for field in (record[:4], record[5:])]
        if any(
            not field or any(byte < 32 or byte > 126 for byte in field)
            for field in fields
        ):
            raise DiagnosticError(
                "ECU acronym/name require printable ASCII and per-field trailing NULs"
            )
        names.append("-".join(field.decode("ascii") for field in fields))
    return names


def decode_information(pid: int, data: bytes) -> Any:
    """CAN service 09 NODI counts items, not transport response messages."""
    if pid in (1, 3, 5, 7, 9, 12, 14):
        if len(data) != 1 or not data[0]:
            raise DiagnosticError("information message count requires one nonzero byte")
        return {"message_count": data[0]}
    if pid == 2:
        return decode_vin(data)
    if pid == 4:
        return decode_calibration_ids(data)
    if pid == 6:
        return decode_cvns(data)
    if pid == 10:
        return decode_ecu_names(data)
    if pid in (8, 11):
        records = _counted_records(data, 2)
        allowed = (16, 20) if pid == 8 else (16, 18)
        if len(records) not in allowed:
            raise DiagnosticError(
                "in-use tracking counter count not defined by annex G"
            )
        groups = (
            (
                "catalyst_bank_1",
                "catalyst_bank_2",
                "oxygen_bank_1",
                "oxygen_bank_2",
                "EGR_VVT",
                "secondary_air",
                "EVAP",
                "secondary_oxygen_bank_1",
                "secondary_oxygen_bank_2",
            )
            if pid == 8
            else (
                "NMHC_catalyst",
                "NOx_SCR_catalyst",
                "NOx_adsorber",
                "particulate_filter",
                "exhaust_gas_sensor",
                "EGR_VVT",
                "boost_pressure",
                "fuel_system",
            )
        )
        names = ["obd_conditions", "ignition_cycles"] + [
            f"{group}_{kind}"
            for group in groups
            for kind in ("completion", "conditions")
        ]
        return {
            "ignition": "spark" if pid == 8 else "compression",
            "counters": dict(
                zip(
                    names,
                    (int.from_bytes(record, "big") for record in records),
                    strict=False,
                )
            ),
            "unit": "count",
            "definition_source": "SAE_J1979_DA_201110_Annex_G",
        }
    if pid in (13, 15):
        records = _counted_records(data, 17)
        if len(records) != 1:
            raise DiagnosticError("one serial/type approval value required")
        text = records[0].lstrip(b"\x00")
        allowed_chars = b"ABCDEFGHJKLMNPRSTUVWXYZ0123456789" + (
            b" *-./" if pid == 15 else b""
        )
        if not text or any(byte not in allowed_chars for byte in text):
            raise DiagnosticError("invalid serial/type approval text")
        return text.decode("ascii")
    raise DiagnosticError("unsupported information type")


def _unresolved_definition(value: Any) -> bool:
    if isinstance(value, str):
        return value in ("reserved", "manufacturer_defined")
    if isinstance(value, dict):
        return any(_unresolved_definition(item) for item in value.values())
    if isinstance(value, (list, tuple)):
        return any(_unresolved_definition(item) for item in value)
    return False


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

    def support(
        self, ecu: str, service: int = 1, frame: int = 0, sensor: int = 1
    ) -> list[int]:
        """Walk at most eight support maps; continuation bits are not signals."""
        if (
            type(service) is not int
            or service not in (1, 2, 5, 6, 9)
            or type(frame) is not int
            or frame != 0
        ):
            raise DiagnosticError("invalid support service/frame")
        if service == 5 and (
            type(sensor) is not int or sensor not in (1, 2, 4, 8, 16, 32, 64, 128)
        ):
            raise DiagnosticError("oxygen sensor must be a one-bit location mask")
        result = []
        for base in SUPPORT_BASES:
            request = bytes([service, base]) + (
                bytes([frame])
                if service == 2
                else bytes([sensor])
                if service == 5
                else b""
            )
            supported = supported_pids(self.read(ecu, request), base)
            result.extend(pid for pid in supported if pid not in SUPPORT_BASES)
            if base + 32 not in supported:
                break
        return result

    def monitors(self, ecu: str) -> dict[str, Any]:
        """Read all advertised CAN monitor tests; never initiate a monitor."""
        validate_ecu(ecu)
        report: dict[str, Any] = {
            "ecu": ecu,
            "status": "ok",
            "errors": [],
            "results": [],
            "physical_status": "PHYSICAL_UNCONFIRMED",
            "scope": "standard_obd_can",
            "definition_source": "SAE_J1979_APR2002_6.6_and_J1979_DA_OCT2011_Annex_E",
        }
        try:
            report["supported_mids"] = self.support(ecu, 6)
        except Cancelled:
            raise
        except (DiagnosticError, TimeoutError) as exc:
            report["status"] = "partial"
            report["errors"].append(
                {
                    "field": "supported_mids",
                    "type": type(exc).__name__,
                    "message": str(exc),
                }
            )
            return report
        for mid in report["supported_mids"]:
            try:
                records = decode_monitor_records(mid, self.read(ecu, bytes([6, mid])))
                report["results"].extend(records)
                if any(record["status"] == "unresolved_scaling" for record in records):
                    report["status"] = "partial"
                    report["errors"].append(
                        {
                            "field": f"monitor_{mid:02X}",
                            "type": "UnresolvedScaling",
                            "message": "unit/scaling ID is not defined by the supported SAE annex",
                        }
                    )
                if any(_unresolved_definition(record) for record in records):
                    report["status"] = "partial"
                    report["errors"].append(
                        {
                            "field": f"monitor_{mid:02X}",
                            "type": "UnresolvedTestDefinition",
                            "message": "numeric limits decoded, but the test description is not defined by the selected SAE annex",
                        }
                    )
            except Cancelled:
                raise
            except (DiagnosticError, TimeoutError) as exc:
                report["status"] = "partial"
                report["errors"].append(
                    {
                        "field": f"monitor_{mid:02X}",
                        "type": type(exc).__name__,
                        "message": str(exc),
                    }
                )
        return report

    def parameters(
        self, ecu: str, pids: Sequence[int] | None = None, freeze: bool = False
    ) -> dict[str, Any]:
        """Support-gated compound/scalar reads, distinct from the health fixture."""
        if type(freeze) is not bool:
            raise DiagnosticError("freeze must be boolean")
        if pids is not None and (
            isinstance(pids, (bytes, str))
            or not pids
            or any(
                type(pid) is not int or pid not in PID_SIZES or pid in SUPPORT_BASES
                for pid in pids
            )
            or len(set(pids)) != len(pids)
        ):
            raise DiagnosticError("parameters require unique defined PIDs")
        service = 2 if freeze else 1
        supported = self.support(ecu, service)
        selected = (
            list(pids)
            if pids is not None
            else [
                pid
                for pid in supported
                if pid in PID_SIZES and (not freeze or pid not in (1, 0x41))
            ]
        )
        unavailable = [
            pid
            for pid in selected
            if pid not in supported or (freeze and pid in (1, 0x41))
        ]
        if unavailable:
            raise DiagnosticError(
                "requested parameters are not advertised by this ECU/frame"
            )
        configurations: dict[int, bytes] = {}
        needs = {
            0x4F: any(
                pid in (0x0B, 0x44) or 0x24 <= pid <= 0x2B or 0x34 <= pid <= 0x3B
                for pid in selected
            ),
            0x50: 0x10 in selected,
        }
        for config, needed in needs.items():
            if needed and config in supported:
                configurations[config] = self.read(
                    ecu, bytes([service, config]) + (b"\x00" if freeze else b"")
                )
        values = [
            decode_parameter(
                pid,
                configurations[pid]
                if pid in configurations
                else self.read(
                    ecu, bytes([service, pid]) + (b"\x00" if freeze else b"")
                ),
                configurations.get(0x4F),
                configurations.get(0x50),
            )
            for pid in selected
        ]
        unknown = [pid for pid in supported if pid not in PID_SIZES]
        unresolved = [row["pid"] for row in values if _unresolved_definition(row)]
        return {
            "ecu": ecu,
            "physical_status": "PHYSICAL_UNCONFIRMED",
            "service": service,
            "supported_pids": supported,
            "unresolved_pids": unknown,
            "status": "partial" if unknown or unresolved else "ok",
            "values": values,
            "errors": [
                {
                    "field": pid,
                    "type": "UnresolvedDefinition",
                    "message": "parameter enum/state is reserved by the selected standard",
                }
                for pid in unresolved
            ],
        }

    def information(self, ecu: str) -> dict[str, Any]:
        supported = self.support(ecu, 9)
        known = [pid for pid in supported if 1 <= pid <= 15]
        unresolved = [pid for pid in supported if pid not in known]
        return {
            "ecu": ecu,
            "physical_status": "PHYSICAL_UNCONFIRMED",
            "supported_info_types": supported,
            "status": "partial" if unresolved else "ok",
            "unresolved_info_types": unresolved,
            "values": {
                f"{pid:02X}": decode_information(pid, self.read(ecu, bytes([9, pid])))
                for pid in known
            },
        }

    def oxygen_tests(
        self, ecu: str, sensor: int = 1, protocol: str = "can"
    ) -> dict[str, Any]:
        """Explicit legacy mode: service 05 does not exist on ISO 15765 CAN."""
        if protocol not in ("iso9141", "iso14230", "j1850"):
            raise DiagnosticError(
                "Mode 05 requires legacy non-CAN OBD; use monitors() on CAN"
            )
        if type(sensor) is not int or sensor not in (1, 2, 4, 8, 16, 32, 64, 128):
            raise DiagnosticError("oxygen sensor must be a one-bit location mask")
        supported = self.support(ecu, 5, sensor=sensor)
        results = []
        unresolved = []
        for tid in supported:
            if tid not in OXYGEN_TEST_SCALES:
                unresolved.append(f"{tid:02X}")
                continue
            results.append(
                decode_oxygen_test(tid, self.read(ecu, bytes([5, tid, sensor])))
            )
            if tid > 10:
                unresolved.append(f"{tid:02X}")
        return {
            "ecu": ecu,
            "protocol": protocol,
            "sensor_mask": sensor,
            "supported_tids": supported,
            "results": results,
            "unresolved_tids": unresolved,
            "status": "partial" if unresolved else "ok",
            "physical_status": "PHYSICAL_UNCONFIRMED",
        }

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
