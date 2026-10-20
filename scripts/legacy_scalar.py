"""Native scalar semantics of the legacy 12 CommandAPI ConvertData@20 export.

Labels must already contain the caller's ACP conversion, not UTF-16 wire data.
This module does not load or execute any vendor component.
"""

from __future__ import annotations

import codecs
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scripts.tse_conversion import LegacyConversionTable


class LegacyScalarError(ValueError):
    """Input would fault or overrun a buffer in the original scalar converter."""


def _u32(value: int) -> int:
    return value & 0xFFFFFFFF


def _i32(value: int) -> int:
    value &= 0xFFFFFFFF
    return value - 0x100000000 if value & 0x80000000 else value


def _div(value: int, divisor: int) -> int:
    quotient = abs(value) // abs(divisor)
    return -quotient if (value < 0) != (divisor < 0) else quotient


def _signed(raw: int, flag: int, bits: int) -> int:
    sign = 1 << ((bits - 1) & 31)
    if raw & sign:
        if flag == 1:
            return _i32(raw | _u32(-sign))
        if flag == 3:
            return -(raw & (sign - 1))
    return raw


def _linear(raw: int, flag: int, bits: int, coefficients: tuple[int, int, int]) -> int:
    multiplier, divisor, offset = coefficients
    value = _signed(raw, flag, bits)
    if multiplier != 1:
        value *= _i32(multiplier)
    if divisor > 1:
        value = _div(value, _i32(divisor))
    return _i32(value + offset)


def _numeric(value: int, precision: int, decimal_point: bytes) -> bytes:
    if precision == 0:
        return str(value).encode("ascii")
    # _ftol returns signed int64; its caller consumes EAX, then divides by ten.
    # 10**(precision+1) is exact through 10**18; larger values yield INT64_MIN.
    power_low = _i32(10 ** (precision + 1)) if precision < 18 else 0
    divisor = _div(power_low, 10) or 1
    sign = "-" if value < 0 else " "
    magnitude = _i32(-value) if value < 0 else value
    integer = _div(magnitude, divisor)
    remainder = magnitude - integer * divisor
    prefix = f"{sign}{integer}".encode("ascii")
    if decimal_point == b"\0":
        return prefix
    if decimal_point == b"%":
        return prefix + f"%0{precision}d".encode("ascii")
    return prefix + decimal_point + f"{remainder:0{precision}d}".encode("ascii")


def _reversed(raw: int, selector: int, coefficients: tuple[int, int, int]) -> int:
    count = {7: 10, 8: 12, 9: 10, 10: 8, 11: 16}[selector]
    signed = selector in (7, 8)
    value = 0
    negative = False
    for bit in range(count):
        source = (raw >> ((bit // 8) * 8 + 7 - bit % 8)) & 1
        if signed and bit == count - 1:
            negative = bool(source)
        else:
            value |= source << bit
    multiplier, divisor, offset = coefficients
    value = _i32((-value if negative else value) * _i32(multiplier))
    if divisor:
        denominator = _i32(divisor)
        if value == -0x80000000 and denominator == -1:
            raise LegacyScalarError("signed 32-bit division overflow")
        value = _div(value, denominator)
    return _i32(value + offset)


def _label(table: LegacyConversionTable, key: int) -> bytes | None:
    for display in table.displays:
        if display.value_raw == _u32(key):
            text = display.text_raw
            return None if text is None else text.split(b"\0", 1)[0]
    return None


def convert_legacy_scalar(
    selector: int,
    raw_value: int,
    table: LegacyConversionTable,
    field_3d: int,
    field_16: int,
    *,
    codepage: str,
    decimal_point: bytes = b".",
) -> bytes | None:
    """Convert one raw DWORD using the exact legacy-12 five-argument ABI.

    ``field_16`` is the fifth export argument (signal +0x16), distinct from
    ``table.field_16_raw``. Only the literal value 1 forces signed conversion.
    ``codepage`` explicitly identifies the caller's prior label conversion;
    this export produces ASCII, raw %c bytes, or those already-converted labels.
    ``decimal_point`` defaults to an authored C-locale policy; parity with another
    process requires that process's actual first localeconv decimal-point byte.
    """
    for name, value, limit in (
        ("selector", selector, 0xFFFFFFFF),
        ("raw_value", raw_value, 0xFFFFFFFF),
        ("field_3d", field_3d, 0xFF),
        ("field_16", field_16, 0xFF),
    ):
        if type(value) is not int or not 0 <= value <= limit:
            raise LegacyScalarError(f"{name} outside unsigned ABI range")
    if not codepage:
        raise LegacyScalarError("an explicit caller codepage is required")
    try:
        codecs.lookup(codepage)
    except LookupError as error:
        raise LegacyScalarError("unknown caller codepage") from error
    if not isinstance(decimal_point, bytes) or len(decimal_point) != 1:
        raise LegacyScalarError("decimal_point must be exactly one native locale byte")
    selector &= 0xFF
    raw = raw_value
    coefficients = table.coefficients_raw
    flag = 1 if field_16 == 1 else table.field_16_raw
    bits = table.field_18_raw & 0xFF
    if selector in (1, 20, 22):
        # Label lookup intentionally ignores the fifth argument's override.
        key = _linear(raw, table.field_16_raw, bits, coefficients)
        result = _label(table, key) or b"-No Data-"
    elif selector == 3:
        result = f"{raw:0{field_3d}X}".encode("ascii")
    elif selector == 4:
        result = bytes((raw & 0xFF,)).split(b"\0", 1)[0]
    elif selector == 5:
        result = f"{'PCBU'[(raw >> 14) & 3]}{raw & 0x3FFF:04X}".encode("ascii")
    elif selector in (13, 24, 25):
        # Range-label paths use the table flag, ignoring the argument override.
        if selector == 24:
            value = _i32(raw >> 1 if raw <= 3000 else raw * 8 - 22500)
        elif selector == 25:
            sign = 1 << ((bits - 1) & 31)
            multiplier, divisor, offset = coefficients
            if raw & sign:
                raw = _u32(sign - raw_value)
            else:
                offset = 0
            value = _linear(
                raw, table.field_16_raw, bits, (multiplier, divisor, offset)
            )
        else:
            value = _linear(raw, table.field_16_raw, bits, coefficients)
        result = None
        if selector != 25:
            lower, upper = table.fields_30_3c_raw[:2]
            comparison = raw_value
            if selector == 13 and table.field_16_raw in (1, 3):
                comparison = _i32(_signed(raw_value, table.field_16_raw, bits))
                lower = _i32(_signed(lower, table.field_16_raw, bits))
                upper = _i32(_signed(upper, table.field_16_raw, bits))
            key = 0 if comparison <= upper else 1 if comparison >= lower else None
            if key is not None:
                for display in table.displays:
                    if display.value_raw == key:
                        # Native strcpy(NULL) faults, unlike the lookup lane.
                        if display.text_raw is None:
                            raise LegacyScalarError("range display has NULL text")
                        result = display.text_raw.split(b"\0", 1)[0]
                        break
        result = _numeric(value, field_3d, decimal_point) if result is None else result
    elif selector in (2, 6, 7, 8, 9, 10, 11, 19, 21, 23):
        if selector == 6:
            value = 0
            if raw:
                first = 30000 // raw
                value = max(0, first - 50 if first < 623 else 240000 // raw - 4400)
        elif selector in (7, 8, 9, 10, 11):
            value = _reversed(raw, selector, coefficients)
        elif selector == 19:
            # The time lane scales an unsigned raw value, then wraps to int32.
            value = _linear(raw, 0, bits, coefficients)
            quotient = _div(value, 60)
            remainder = value - quotient * 60
            packed = _u32(remainder | _u32(quotient << 8))
            seconds = min(packed & 0xFF, 59)
            result = f"{packed >> 8:02d}:{seconds:02d}".encode("ascii")
        else:
            value = _linear(raw, flag, bits, coefficients)
        if selector != 19:
            result = _numeric(value, field_3d, decimal_point)
    else:
        result = b"-TypeErr-"
    if len(result) >= 256:
        raise LegacyScalarError("legacy 256-byte output buffer would overflow")
    return result
