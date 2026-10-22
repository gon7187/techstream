"""Source-derived CommandAPI ConvertData display; never guess symbolic values."""

from __future__ import annotations

import math
import struct
from collections.abc import Sequence
from typing import Any

from scripts.signal_conversion import affine, convert, i32, trunc_div

NUMERIC_SELECTORS = frozenset((2, 6, 7, 8, 9, 10, 11, 12, 21, 23, 25, 26, 30, 34))
SYMBOLIC_SELECTORS = frozenset((1, 20, 22))
THRESHOLD_SELECTORS = frozenset((13, 24, 27, 33))
Pattern = tuple[int, str, int, int]


def _format_integer(value: int, precision: int) -> str:
    # CommandAPI 67DF/680A/684E: low32 NEG/FTOL, signed quotient/remainder.
    if precision == 0:
        return str(value)
    magnitude = i32(-value) if value < 0 else value
    denominator = (
        trunc_div(i32(10 ** (precision + 1)), 10) if precision < 18 else 0
    ) or 1
    whole = trunc_div(magnitude, denominator)
    remainder = magnitude - whole * denominator
    return f"{'-' if value < 0 else ' '}{whole}.{remainder:0{precision}d}"


def render_signal(
    raw: int,
    *,
    selector: int,
    sign_mode: int,
    bits: int,
    multiplier: int,
    divisor: int,
    offset: int,
    precision: int,
    patterns: Sequence[Pattern] = (),
    minimum_raw: int | None = None,
    maximum_raw: int | None = None,
    extended: Sequence[tuple[int, int, int]] = (),
    raw_words: tuple[int, int] | None = None,
) -> dict[str, Any]:
    """Render original metadata, preserving unavailable/unresolved as None.

    Pattern order is significant. Their low/high fields are retained metadata;
    the recovered ConvertData path compares pattern.value only. raw_words is an
    explicitly correlated low/high pair for selector29, never inferred from an
    arbitrary extended record. No device or locale state is accessed.
    """
    if any(type(v) is not int for v in (raw, selector, sign_mode, bits, precision)):
        raise ValueError("Native raw/display fields must be integers")
    if not 0 <= raw <= 0xFFFFFFFF or not 0 <= selector <= 255 or not 1 <= bits <= 32:
        raise ValueError("Raw, selector or bit width out of range")
    if not 0 <= sign_mode <= 255 or not 0 <= precision <= 255:
        raise ValueError("Signing mode or precision out of range")
    if any(
        type(v) is not int or not -0x80000000 <= v <= 0xFFFFFFFF
        for v in (multiplier, divisor, offset)
    ):
        raise ValueError("Native coefficients must be signed or unsigned dwords")
    for value, label, low, high in patterns:
        if not isinstance(label, str) or any(
            type(x) is not int or not 0 <= x <= 0xFFFFFFFF for x in (value, low, high)
        ):
            raise ValueError("Malformed native display pattern")
    for record in extended:
        if len(record) != 3 or any(
            type(x) is not int or not 0 <= x <= 0xFFFFFFFF for x in record
        ):
            raise ValueError("Malformed extended metadata")
    result: dict[str, Any] = {
        "raw": raw,
        "value": None,
        "display": None,
        "kind": "unresolved",
        "status": "unresolved",
    }

    def numeric(value: float, display: str | None = None) -> dict[str, Any]:
        result.update(
            value=value,
            display=display
            if display is not None
            else _format_integer(int(value), precision),
            kind="numeric",
            status="ok",
        )
        return result

    def label_for(value: int) -> str | None:
        return next(
            (label for key, label, _, _ in patterns if key == value & 0xFFFFFFFF), None
        )

    args = (multiplier, divisor, offset, bits, sign_mode)
    if selector in SYMBOLIC_SELECTORS:
        value = affine(raw, *args)
        label = label_for(value)
        result.update(
            display=label if label is not None else "-No Data-",
            kind="symbolic",
            status="ok" if label is not None else "unresolved",
        )
        return result
    if selector in (3, 31):
        result.update(display=f"{raw:0{precision}X}", kind="hex", status="ok")
        return result
    if selector in (4, 32):
        result.update(
            display=chr(raw & 255) if raw & 255 else "", kind="character", status="ok"
        )
        return result
    if selector == 5:
        result.update(
            display="PCBU"[(raw >> 14) & 3] + f"{raw & 0x3FFF:04X}",
            kind="dtc",
            status="ok",
        )
        return result
    if selector == 19:
        value = convert(raw, *args, selector=19) & 0xFFFFFFFF
        result.update(
            display=f"{value >> 8}:{min(value & 255, 59):02d}", kind="time", status="ok"
        )
        return result
    if selector in (28, 29):
        if selector == 28:
            invalid = 0x4F000000 <= raw <= 0x7FFFFFFF or raw >= 0xCF000001
            value = struct.unpack("<f", struct.pack("<I", raw))[0]
        else:
            if raw_words is None:
                return result
            if len(raw_words) != 2 or any(
                type(x) is not int or not 0 <= x <= 0xFFFFFFFF for x in raw_words
            ):
                raise ValueError("Explicit float64 low/high words required")
            low, high = raw_words
            packed = low | high << 32
            invalid = (
                0x41DFFFFFFFC00001 <= packed <= 0x7FFFFFFFFFFFFFFF
                or packed >= 0xC1E0000000000001
            )
            value = struct.unpack("<d", struct.pack("<Q", packed))[0]
        if invalid or not math.isfinite(value):
            result.update(display="-No Data-", kind="numeric", status="unavailable")
            return result
        return numeric(value, f"{value:.{precision}f}")
    if selector in THRESHOLD_SELECTORS:
        value = (
            convert(raw, *args, selector=24) if selector == 24 else affine(raw, *args)
        )
        if selector == 27:
            value = i32(-value)
        if minimum_raw is None or maximum_raw is None:
            return result
        for endpoint in (minimum_raw, maximum_raw):
            if type(endpoint) is not int or not 0 <= endpoint <= 0xFFFFFFFF:
                raise ValueError("Threshold endpoints must be u32")
        current, lower, upper = raw, minimum_raw, maximum_raw
        if selector != 24 and sign_mode in (1, 3):
            current = affine(raw, 1, 1, 0, bits, sign_mode)
            lower = affine(minimum_raw, 1, 1, 0, bits, sign_mode)
            upper = affine(maximum_raw, 1, 1, 0, bits, sign_mode)
            if selector == 27:
                current = i32(-current)
        index = 0 if current <= upper else 1 if current >= lower else None
        label = label_for(index) if index is not None else None
        return numeric(
            value, label
        )  # Native falls back to numeric without a matching label.
    if selector in NUMERIC_SELECTORS:
        if selector in (21, 23):
            selector = 2
        if selector == 25:
            if raw & (1 << (bits - 1)):
                value = affine(((1 << (bits - 1)) - raw) & 0xFFFFFFFF, *args)
            else:
                value = affine(raw, multiplier, divisor, 0, bits, sign_mode)
        else:
            value = convert(raw, *args, selector=selector)
            if selector == 26:
                value = i32(-value)
        return numeric(value)
    result.update(display="-TypeErr-")
    return result
