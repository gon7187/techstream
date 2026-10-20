"""Selected Common12/18 signal LSB queries over bounded support primitives."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from scripts.monitor_support import MonitorSupportCache, monitor_source_identity
from scripts.signal_conversion import extract_bits
from scripts.support import word
from scripts.toyota import ToyotaCodecError
from scripts.toyota_session import SessionError, expand_supported_pid


def _uint(value: int, maximum: int) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError("LSB argument outside native unsigned bounds")
    return value


def _signed(value: int) -> int:
    value &= 0xFFFFFFFF
    return value if value < 0x80000000 else value - 0x100000000


def _quotient(left: int, right: int) -> int:
    if not right or left == -0x80000000 and right == -1:
        raise ToyotaCodecError("Native LSB signed division fault", 0xC0040001)
    return (abs(left) // abs(right)) * (-1 if (left < 0) != (right < 0) else 1)


def _coefficients(row: bytes, exponent: int, observed: int) -> tuple[int, int]:
    # FISTP QWORD truncates; an overflowing signed64 result has low DWORD zero.
    power = 10**exponent if exponent <= 18 else 0
    first = _signed(power * observed * int.from_bytes(row[:4], "little"))
    second = _signed(int.from_bytes(row[4:8], "little"))
    divisor = 1
    if first and second:
        small, large = sorted((first, second))
        while True:
            remainder = large - _quotient(large, small) * small
            if not remainder:
                divisor = small
                break
            large, small = small, remainder
    return _quotient(first, divisor) & 0xFFFFFFFF, _quotient(
        second, divisor
    ) & 0xFFFFFFFF


@dataclass(frozen=True)
class LSBObservation:
    multiplier: int
    divisor: int
    threshold: int
    changed: bool = False

    @property
    def values(self) -> tuple[int, int, int]:
        return self.multiplier, self.divisor, self.threshold


class SignalLSB:
    """InitLSB/ChangeSignalLSB; build selection is independent of DDB format.

    The supplied cache owns chronological exchange, source binding, cancellation,
    deadline and resource limits. It never supplies a business success decision.
    """

    def __init__(self, cache: MonitorSupportCache, *, source_build: Literal[12, 18]):
        if type(source_build) is not int or source_build not in (12, 18):
            raise ValueError("LSB requires explicit original Common build12 or18")
        if not isinstance(cache, MonitorSupportCache):
            raise TypeError("LSB requires a concrete selected support cache")
        if cache.source_build != source_build:
            raise SessionError("LSB Common build differs from selected support cache")
        self.cache, self.source_build = cache, source_build
        self.profile = cache.profile
        self.identity = monitor_source_identity(cache.profile, cache.ecu)
        category = cache.profile.category_record
        if len(category) < 73:
            raise ToyotaCodecError("InitLSB category group empty", 0xC0050101)
        self.flags = category[72]
        self._pids: dict[int, int] | None = None
        self._dids: tuple[int, ...] | None = None
        self._temporary_cache = cache.new_temporary_cache()

    def _check(self) -> None:
        self.cache._check()
        if self.cache.source_build != self.source_build:
            raise SessionError("LSB Common build changed during query")
        if monitor_source_identity(self.cache.profile, self.cache.ecu) != self.identity:
            raise SessionError("LSB selected source identity changed")

    def p4(
        self,
        pid: int,
        *,
        exponent: int,
        width: int,
        multiplier: int,
        divisor: int,
        threshold: int,
    ) -> LSBObservation:
        with self.cache.temporary_scope(self._temporary_cache):
            return self._observe(
                pid, exponent, width, multiplier, divisor, threshold, p5=False
            )

    def p5(
        self,
        pid: int,
        *,
        exponent: int,
        width: int,
        multiplier: int,
        divisor: int,
        threshold: int,
    ) -> LSBObservation:
        with self.cache.temporary_scope(self._temporary_cache):
            return self._observe(
                pid, exponent, width, multiplier, divisor, threshold, p5=True
            )

    def _observe(
        self,
        pid: int,
        exponent: int,
        width: int,
        multiplier: int,
        divisor: int,
        threshold: int,
        *,
        p5: bool,
    ) -> LSBObservation:
        self._check()
        for value, maximum in (
            (pid, 65535),
            (exponent, 255 if p5 else 65535),
            (width, 65535),
            (multiplier, 0xFFFFFFFF),
            (divisor, 0xFFFFFFFF),
            (threshold, 0xFFFFFFFF),
        ):
            _uint(value, maximum)
        original = LSBObservation(multiplier, divisor, threshold)
        eligible = (0x14, 0x15, 0x34) if self.source_build == 18 else (0x14, 0x15)
        if (p5 and self.flags not in eligible) or (not p5 and self.flags != 4):
            return original
        rows = (
            self.cache.profile.signal_did_lsb_records(pid)
            if p5
            else self.cache.profile.signal_lsb_records(pid)
        )
        if len(rows) > 32767 or any(len(row) != 20 for row in rows):
            raise ToyotaCodecError("Malformed selected LSB records", 0xC0040101)
        if not rows:
            return original
        row = rows[0]
        # Native FIRST row only; later matching alternatives are not attempted.
        begin, end = (
            (word(row, 12), word(row, 14)) if p5 else (word(row, 10), word(row, 12))
        )
        command = word(row, 8) if p5 else row[17]
        try:
            if p5:
                if self._dids is None:
                    family = (
                        "subaru"
                        if self.source_build == 18 and self.flags & 0xE0 == 0x20
                        else "normal"
                    )
                    self._dids = self.cache.data_ids(family=family).identifiers
                if command not in self._dids:
                    return original
                if not self.cache.check_support_pid(
                    pid,
                    enabled_dids=self._dids,
                    raw_support=True,
                    source_build=self.source_build,
                ):
                    return original
            else:
                masks = self.cache.support_bits(1)
                if self._pids is None:
                    self._pids = self.cache.enabled_pids(family="p4", kind=1)
                if command not in self._pids:
                    return original
                mask = masks.get(command, b"")
                if not mask or end >= len(mask) * 8 or begin > end or end - begin >= 32:
                    return original
                if not extract_bits(mask, begin, end):
                    return original
        except ToyotaCodecError:
            # 1f1c2/1fa5a and 1f2f0/1fb80 turn discovery failures into identity.
            return original
        frames = self.cache.profile.frame_records(0xCA if p5 else 0x6B)
        if len(frames) != 1:
            raise ToyotaCodecError(
                "LSB requires exactly one selected frame", 0xC0040102
            )
        frame = frames[0]
        request = bytearray(frame.frame.request)
        header = 3 if p5 else 2
        if not header <= len(request) <= (65535 if p5 else 255):
            raise ToyotaCodecError(
                "LSB selected request lacks command bytes", 0xC0040102
            )
        request[1:header] = command.to_bytes(header - 1, "big")
        try:
            reply = self.cache.transaction(frame, bytes(request), extended=p5)
        except ToyotaCodecError:
            # Native communication helper failures are suppressed by GetLSB.
            return original
        data = reply[header:]
        if not p5:
            try:
                data = expand_supported_pid(data, masks[command])
            except ToyotaCodecError:
                return original
        if not data or len(data) <= end // 8:
            raise ToyotaCodecError("LSB successful reply truncated", 0xA0040202)
        if begin > end or end - begin >= 32:
            return original
        observed = extract_bits(data, begin, end)
        if not observed:
            return original
        multiplier, divisor = _coefficients(row, exponent, observed)
        return LSBObservation(
            multiplier, divisor, ((1 << (width & 31)) - 1) & 0xFFFFFFFF, True
        )
