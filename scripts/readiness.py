"""Native enhanced readiness from selected Freeze84/PhyData24 definitions.

No adapter is opened. Native support flags and numeric values are independent;
this module never substitutes the standard OBD readiness bit interpretation.
"""

from __future__ import annotations

import math
import struct
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import replace
from typing import Any

from scripts.profiles import VehicleProfile
from scripts.signal_conversion import extract_bits, signal_metadata
from scripts.signal_display import render_signal
from scripts.support import check_pid_support, word
from scripts.toyota import MISSING_RECORD, SHORT_REPLY, ToyotaCodecError
from scripts.toyota_session import (
    Cancelled,
    CommandSpec,
    Exchange,
    Limits,
    SessionError,
)

NO_SUPPORT_SIGNAL = 0x90040501


class ReadinessSession:
    """GetReadinessCode_DT Execute with caller-observed native PID lengths.

    pid_lengths/did_lengths are GetEnableIdList observations, not guessed lengths
    from local records. The blocking exchange must impose its own I/O timeout.
    """

    def __init__(
        self,
        profile: VehicleProfile,
        exchange: Exchange,
        ecu: str,
        pid_lengths: Mapping[int, int],
        *,
        did_lengths: Mapping[int, int] | None = None,
        limits: Limits | None = None,
        cancelled: Callable[[], bool] = lambda: False,
        clock: Callable[[], float] = time.monotonic,
    ):
        if not ecu:
            raise ValueError("Selected ECU identity required")
        for lengths in (pid_lengths, did_lengths or {}):
            if any(
                type(key) is not int
                or not 0 <= key <= 255
                or type(size) is not int
                or not 0 <= size <= 255
                for key, size in lengths.items()
            ):
                raise ValueError(
                    "PID observations must map byte identifiers to byte lengths"
                )
        self.profile, self.exchange, self.ecu = profile, exchange, ecu
        self.pid_lengths = dict(pid_lengths)
        self.did_lengths = dict(did_lengths) if did_lengths is not None else None
        self.limits = limits or Limits()
        self.cancelled, self.clock = cancelled, clock
        self._deadline = 0.0
        self._remaining = 0
        self._cache: dict[bytes, bytes] = {}
        self.trace: list[dict[str, Any]] = []

    def _check(self) -> None:
        if self.cancelled():
            raise Cancelled("Enhanced readiness cancelled")
        now = self.clock()
        if not math.isfinite(now) or now >= self._deadline:
            raise SessionError("Enhanced readiness deadline exceeded")

    def _call(self, request: bytes) -> bytes:
        self._check()
        if request in self._cache:
            return self._cache[request]
        if self._remaining <= 0:
            raise SessionError("Enhanced readiness exchange budget exhausted")
        self._remaining -= 1
        try:
            reply = self.exchange(self.ecu, request)
        finally:
            self._check()
        if not isinstance(reply, bytes):
            raise TypeError("Exchange must return bytes")
        self._check()
        self.trace.append({"request": request.hex(), "response": reply.hex()})
        self._cache[request] = reply
        return reply

    def readiness(self) -> dict[str, Any]:
        """Select exactly native record flag+4E&20; do not infer completion."""
        return self._read(None)

    def data_list(self, signal_keys: Sequence[int]) -> dict[str, Any]:
        """Same original definition pipeline for explicitly selected signals.

        This includes original CARB PIDs above87 without a fabricated modern
        standard compound table or accepting arbitrary requests.
        """
        if (
            not signal_keys
            or any(type(key) is not int or not 0 <= key <= 65535 for key in signal_keys)
            or len(set(signal_keys)) != len(signal_keys)
        ):
            raise ValueError("Select unique u16 signal keys")
        return self._read(tuple(signal_keys))

    def _read(self, keys: tuple[int, ...] | None) -> dict[str, Any]:
        rows = self.profile.records(10)
        selected = tuple(
            row
            for row in rows
            if (row[78] & 32 if keys is None else word(row, 56) in keys)
        )
        if not selected:
            raise ToyotaCodecError("No selected readiness signals", NO_SUPPORT_SIGNAL)
        if keys is not None and (
            len(selected) != len(keys)
            or {word(row, 56) for row in selected} != set(keys)
        ):
            raise ToyotaCodecError(
                "Selected signal definition is missing or ambiguous", MISSING_RECORD
            )
        frames = self.profile.frame_records(0x6B)
        if len(frames) != 1 or len(frames[0].frame.request) < 2:
            raise ToyotaCodecError(
                "GetEcuDataP3 requires exactly one frame of at least two bytes",
                MISSING_RECORD,
            )
        physical_rows = self.profile.records(13)
        physical = {}
        for row in selected:
            matches = [
                item for item in physical_rows if word(item, 12) == word(row, 60)
            ]
            if len(matches) != 1:
                raise ToyotaCodecError(
                    "Signal requires exactly one selected PhyData record",
                    MISSING_RECORD,
                )
            # Validate all definition joins before the first exchange.
            signal_metadata(row, matches[0])
            physical[row] = matches[0]
        started = self.clock()
        if not math.isfinite(started):
            raise SessionError("Enhanced readiness clock must be finite")
        self._deadline = started + self.limits.seconds
        self._remaining = self.limits.exchanges
        self._cache.clear()
        self.trace.clear()
        pid_bits = self.profile.pid_bits()
        result: dict[str, Any] = {
            "ecu": self.ecu,
            "status": "ok",
            "native_status": 0,
            "signals": [],
            "omitted": [],
            "physical_status": "PHYSICAL_UNCONFIRMED",
            "provenance": self.profile.report(),
            "definition_source": "GetReadinessCode_DT.Execute/CCmdEcuData.GetEcuDataP3",
        }
        for row in selected:
            self._check()
            supported = check_pid_support(
                row,
                self.pid_lengths,
                pid_bits,
                self.profile.command_frames,
                self._call,
                did_lengths=self.did_lengths,
            )
            pid = row[79]
            frame = frames[0].frame
            patched = replace(
                frame, request=frame.request[:1] + bytes([pid]) + frame.request[2:]
            )
            try:
                reply = self._call(patched.request)
                payload = CommandSpec(
                    patched,
                    check="sid",
                    payload_offset=len(patched.request),
                    provenance=frames[0].provenance,
                ).validate(reply)
                if not payload:
                    raise ToyotaCodecError(
                        "GetEcuDataP3 response has no payload", SHORT_REPLY
                    )
                metadata = signal_metadata(row, physical[row])
                raw = extract_bits(payload, metadata["start_bit"], metadata["end_bit"])
                patterns = (
                    [
                        (
                            (
                                word(item, 10)
                                if self.profile.database.version == 0x0100030C
                                else struct.unpack_from("<I", item, 4)[0]
                            ),
                            self.profile.catalog.language.resolve(
                                struct.unpack_from("<I", item, 0)[0]
                            ),
                            0,
                            0,
                        )
                        for item in self.profile.records(14)
                        if word(
                            item,
                            4 if self.profile.database.version == 0x0100030C else 12,
                        )
                        == word(row, 70)
                    ]
                    if 14 in self.profile.database.sections
                    else []
                )
                value: dict[str, Any] = render_signal(
                    raw,
                    selector=metadata["selector"],
                    sign_mode=metadata["sign_mode"],
                    bits=metadata["end_bit"] - metadata["start_bit"] + 1,
                    multiplier=metadata["multiplier"],
                    divisor=metadata["divisor"],
                    offset=metadata["offset"],
                    precision=metadata["decimal_precision"],
                    patterns=patterns,
                    minimum_raw=struct.unpack_from("<I", row, 32)[0],
                    maximum_raw=struct.unpack_from("<I", row, 36)[0],
                )
                value["unit_key"] = metadata["unit_key"]
                if value["status"] != "ok":
                    result["status"] = "partial"
            except ToyotaCodecError as error:
                if error.code != SHORT_REPLY:
                    raise
                # Native omits a wrong-length signal and continues with other rows.
                result["omitted"].append(
                    {
                        "signal_key": word(row, 56),
                        "pid": pid,
                        "native_status": error.code,
                    }
                )
                result["status"] = "partial"
                continue
            unit_key = value["unit_key"]
            units = [
                unit for unit in self.profile.records(15) if word(unit, 4) == unit_key
            ]
            value["unit"] = (
                self.profile.catalog.language.resolve(
                    struct.unpack_from("<I", units[0], 0)[0]
                )
                if len(units) == 1
                else None
            )
            value["unit_status"] = "resolved" if len(units) == 1 else "unresolved"
            if len(units) != 1:
                result["status"] = "partial"
            name_key = struct.unpack_from("<I", row, 48)[0]
            result["signals"].append(
                {
                    "signal_key": word(row, 56),
                    "pid": pid,
                    "native_support": supported,
                    "name": self.profile.catalog.language.resolve(name_key),
                    "native_34": struct.unpack_from("<I", row, 52)[0],
                    "value": value,
                    "provenance": frames[0].provenance,
                }
            )
        if not result["signals"]:
            raise ToyotaCodecError(
                "No readiness signal returned a value", NO_SUPPORT_SIGNAL
            )
        return result
