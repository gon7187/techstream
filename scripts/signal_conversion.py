"""Native Techstream numeric conversion; payload boundary is supplied by the caller.

Instruction anchors and supported numeric paths: docs/signal-conversion.md.
Vehicle-specific runtime overrides must be applied before live decoding.
"""

import struct


def i32(value: int) -> int:
    """x86 low dword interpreted as a signed long."""
    return (value + 0x80000000) % 0x100000000 - 0x80000000


def trunc_div(numerator: int, denominator: int) -> int:
    """Integer division toward zero, matching signed x86 division helpers."""
    quotient = abs(numerator) // abs(denominator)
    return -quotient if (numerator < 0) != (denominator < 0) else quotient


def phy_fields(record: bytes) -> tuple[int, int, int, int]:
    """Fields copied by GetDatMonSignalInfo RVA 0x19ee..0x1a0b."""
    if len(record) != 24:
        raise ValueError("PhyData record must be exactly 24 bytes")
    numerator, denominator, offset = struct.unpack_from("<iii", record)
    return numerator, denominator, offset, record[20]


def signal_metadata(freeze: bytes, physical: bytes) -> dict[str, int]:
    """Static Freeze84 -> PhyData24 link; caller resolves original exception rules."""
    if len(freeze) != 84 or len(physical) != 24:
        raise ValueError("expected exact Freeze84 and PhyData24 records")
    key = struct.unpack_from("<H", freeze, 60)[0]
    if key != struct.unpack_from("<H", physical, 12)[0]:
        raise ValueError("Freeze/PhyData lookup keys differ")
    numerator, denominator, offset, mode = phy_fields(physical)
    start, end = struct.unpack_from("<HH", freeze, 62)
    return {
        "physical_key": key,
        "start_bit": start,
        "end_bit": end,
        "multiplier": numerator,
        "divisor": denominator,
        "offset": offset,
        "sign_mode": mode,
        "decimal_precision": physical[21],
        "selector": freeze[76],
        "unit_key": struct.unpack_from("<H", physical, 14)[0],
    }


def extract_bits(payload: bytes, start: int, end: int, baseline: int = 0) -> int:
    """MSB-first inclusive bit range; caller supplies diagnostic payload boundary."""
    if (
        type(start) is not int
        or type(end) is not int
        or not 0 <= start <= end <= 0xFFFFFFFF
        or end >= len(payload) * 8
    ):
        raise ValueError("invalid response bit range")
    first, last = start // 8, end // 8
    tail = 7 - end % 8
    raw = payload[last] >> tail
    if first == last:
        raw &= (1 << (end - start + 1)) - 1
    else:
        # Native DWORD OR assembly wraps EACH x86 shift count modulo32,
        # including fields wider than a DWORD (18:9bfee,12:6d33e).
        for index in range(last - 1, first, -1):
            shift = (8 * (last - index) - tail) & 31
            raw |= (payload[index] << shift) & 0xFFFFFFFF
        # First byte is shifted in DL before its DWORD shift, losing overflow.
        head = (payload[first] << (start & 7)) & 0xFF
        raw |= (head << ((end - start - 7) & 31)) & 0xFFFFFFFF
    return (raw - baseline) & 0xFFFFFFFF


def affine(
    raw: int, numerator: int, denominator: int, offset: int, bits: int, mode: int
) -> int:
    """DatMonCommon RVA 0x7480: sign -> signed64 multiply/divide -> low32 add."""
    if not 1 <= bits <= 32 or not 0 <= raw <= 0xFFFFFFFF:
        raise ValueError("raw must be a u32 and bit width must be 1..32")
    numerator, denominator, offset = map(i32, (numerator, denominator, offset))
    if mode in (1, 3) and raw & (1 << (bits - 1)):
        raw = (
            i32(raw | (0xFFFFFFFF << (bits - 1)))
            if mode == 1
            else -(raw & ((1 << (bits - 1)) - 1))
        )
    value = raw * numerator
    if denominator & 0xFFFFFFFF > 1:
        value = trunc_div(value, denominator)
    return i32(value + offset)


def convert(
    raw: int,
    numerator: int,
    denominator: int,
    offset: int,
    bits: int,
    mode: int,
    selector: int = 0,
) -> int:
    """RVA 0x7505 dispatch; selector is separate from PhyData signing mode."""
    if not 0 <= raw <= 0xFFFFFFFF or not 0 <= selector <= 255:
        raise ValueError("raw/selector out of range")
    numerator, denominator, offset = map(i32, (numerator, denominator, offset))
    if selector == 6:
        if raw == 0:
            return 0
        value = 30000 // raw
        value = i32(240000 // raw - 4400) if i32(value) > 622 else i32(value - 50)
        return max(0, value)
    if selector == 24:
        return raw // 2 if raw <= 3000 else i32(raw * 8 - 22500)
    if selector == 19:
        value = raw * numerator
        if denominator & 0xFFFFFFFF > 1:
            value = trunc_div(value, denominator)
        value = i32(value + offset)
        quotient = trunc_div(value, 60)
        return i32((quotient << 8) | ((value - quotient * 60) & 0xFFFFFFFF))
    if 7 <= selector <= 11:
        width, signed = {
            7: (10, True),
            8: (12, True),
            9: (10, False),
            10: (8, True),
            11: (16, False),
        }[selector]
        serial = [
            (byte >> bit) & 1
            for byte in raw.to_bytes(4, "little")
            for bit in range(7, -1, -1)
        ][:width]
        sign = signed and serial[-1] == 1
        value = sum(
            bit << index
            for index, bit in enumerate(serial[: width - 1] if signed else serial)
        )
        if sign:
            value = -value
        value = i32(value * numerator)
        if denominator != 0:
            if value == -0x80000000 and denominator == -1:
                raise OverflowError("native signed32 IDIV overflow")
            value = trunc_div(value, denominator)
        return i32(value + offset)
    return affine(raw, numerator, denominator, offset, bits, mode)


def format_scaled(value: int, digits: int, decimal_separator: str = ".") -> str:
    """CommandAPI RVA 0x66e0 common path: equal scale/display digits, no rounding."""
    if not -0x7FFFFFFF <= value <= 0x7FFFFFFF or not 0 <= digits <= 9:
        raise ValueError("unsupported native display integer or decimal precision")
    if len(decimal_separator) != 1:
        raise ValueError("native locale decimal separator is one byte")
    if digits == 0:
        return str(value)
    whole, fraction = divmod(abs(value), 10**digits)
    return f"{'-' if value < 0 else ' '}{whole}{decimal_separator}{fraction:0{digits}d}"
