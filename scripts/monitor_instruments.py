"""Native selected voltage descriptors and bounded DST-i oscilloscope acquisition.

Device observations are injected; importing this module never opens hardware.
"""

from __future__ import annotations

import math
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, ClassVar, Protocol

from scripts.data_monitor import (
    MonitorError,
    MonitorSignalMetadata,
    selected_signal_metadata,
)
from scripts.drive_recorder import (
    NativeMonitorBuffer,
    NativeMonitorPacket,
    NativeRecorderCapture,
    RecorderCancelled,
    native_monitor_buffer,
)
from scripts.profiles import VehicleProfile
from scripts.support import word

if TYPE_CHECKING:
    from scripts.monitor_dlc12 import DLC12VoltageObservation, DLC12VoltageState

# DataListIF SetSamplingRate; native integer rounding is part of the format.
SAMPLING_PERIODS = (
    0x9502F,
    62500000,
    0x1DCD650,
    0xEE6B28,
    0x5F5E10,
    0x2FAF08,
    0x17D784,
    0x9502F,
    0x4A817,
    0x2540B,
    0xEE6B,
    0x7735,
    0x3B9A,
    0x17D7,
    0xBEB,
    0x5F5,
    0x254,
    0x12A,
    0x95,
    0x3B,
    0x1D,
    0xE,
)


def _uint(value: int, bits: int = 32) -> int:
    if type(value) is not int or not 0 <= value < 1 << bits:
        raise MonitorError(f"Instrument field must fit uint{bits}")
    return value


def _range(value: int | None, default: int) -> int:
    # Native INI producer falls back for every invalid/missing time range.
    return value if type(value) is int and 1 <= value <= 21 else default


@dataclass(frozen=True)
class SelectedInstrumentMonitor:
    category: int
    selected_ids: tuple[int, ...]
    descriptors: tuple[bytes, ...]
    frame_sizes: tuple[tuple[int, int], ...]
    signals: tuple[MonitorSignalMetadata, ...]
    mode: int
    source_sha256: str

    def monitor_buffer(
        self, *, allocation_size: int, name: bytes, text_encoding: str
    ) -> NativeMonitorBuffer:
        return native_monitor_buffer(
            self.category,
            self.signals,
            self.frame_sizes,
            self.selected_ids,
            phase=0,
            allocation_size=allocation_size,
            name=name,
            text_encoding=text_encoding,
        )


def selected_instrument_monitor(
    profile: VehicleProfile,
    selected_ids: Sequence[int],
    *,
    measure_time_range: int | None = None,
    forward_time_range: int | None = None,
    voltage_state: DLC12VoltageState | None = None,
    voltage_observations: Mapping[int, DLC12VoltageObservation] | None = None,
) -> SelectedInstrumentMonitor:
    """P4 2ec0/5da0 actual Freeze producer; category68 has no working sampler."""
    if profile.category not in (0x68, 999):
        raise MonitorError("Instrument category must be0x68 or999")
    if not isinstance(selected_ids, (tuple, list)) or len(selected_ids) > 4:
        raise MonitorError("Instrument selection exceeds four signals")
    ids = tuple(dict.fromkeys(_uint(pid, 16) for pid in selected_ids))
    expected = 1 if profile.category == 0x68 else 4
    if len(ids) != expected:
        raise MonitorError(
            "Instrument selection has invalid native signal count",
            0x90051003 if profile.category == 0x68 else 0x90051016,
        )
    records = {}
    for row in profile.records(10):
        if len(row) != 84:
            raise MonitorError("Instrument Freeze record must be84 bytes")
        # Native first key0x100 skips BYTE79 filtering; second key is PID56.
        records.setdefault(word(row, 56), row)
    descriptors, layouts = [], []
    for pid in ids:
        row = records.get(pid)
        if row is None:
            raise MonitorError("Selected instrument Freeze row is absent", 0xC0050101)
        start, end = word(row, 62), word(row, 64)
        if end < start:
            raise MonitorError("Instrument Freeze bit range is reversed", 0xC0050102)
        if profile.category == 0x68:
            if (end - start) // 8 != 1:
                raise MonitorError(
                    "Native voltage sample requires two bytes", 0xC0050102
                )
            descriptors.append(b"\x04\0\0\0\x01")
        else:
            channel = start >> 3
            if channel >= 4:
                raise MonitorError(
                    "Oscilloscope channel exceeds native four-byte sample"
                )
            descriptors.append(
                bytes(
                    (
                        channel,
                        _range(measure_time_range, 11),
                        _range(forward_time_range, 7),
                        (row[79] - 1) & 255,
                    )
                )
            )
        layouts.append((pid, 0, start, end))
    metadata = selected_signal_metadata(
        profile,
        layouts,
        voltage_state=voltage_state,
        voltage_observations=voltage_observations,
    )
    return SelectedInstrumentMonitor(
        profile.category,
        ids,
        tuple(descriptors),
        ((0, 2 if expected == 1 else 4),),
        metadata,
        0x40 if expected == 1 else 0x4000,
        profile.database.sha256,
    )


class VoltageMonitorInterface:
    """Literal12/18 exported implementation, not fabricated voltage acquisition."""

    @staticmethod
    def get_error() -> int:
        return 0xFFFFFFFF

    @staticmethod
    def setup(_selector: int, _mode: int, _buffer: object) -> bool:
        return False

    @staticmethod
    def start() -> bool:
        return False

    stop = start


@dataclass(frozen=True)
class OscParameter:
    """DstiOscGetParameter native status and returned bytes."""

    status: int
    data: bytes
    MAX_BYTES: ClassVar[int] = 0x1068

    def __post_init__(self) -> None:
        _uint(self.status)
        if not isinstance(self.data, bytes) or len(self.data) > self.MAX_BYTES:
            raise MonitorError("DST-i parameter output exceeds native buffer")


@dataclass(frozen=True)
class OscRead(OscParameter):
    """DstiOscReadBuffer DWORD outputs: status, size, timestamp, opaque, remaining."""

    timestamp: int = 0
    opaque: int = 0
    remaining: int = 0
    MAX_BYTES: ClassVar[int] = 0x41A0

    def __post_init__(self) -> None:
        super().__post_init__()
        for value in (self.timestamp, self.opaque, self.remaining):
            _uint(value)
        if self.status == 0 and len(self.data) % 4:
            raise MonitorError("Oscilloscope read ends inside a four-byte sample")


class OscPrimitives(Protocol):
    """Actual CCommFrameCtrl primitives; each call must respect its deadline."""

    def command(self, command: int, *, deadline: float) -> int: ...
    def set_parameter(self, parameter: int, data: bytes, *, deadline: float) -> int: ...
    def read_buffer(self, maximum: int, *, deadline: float) -> OscRead: ...


@dataclass(frozen=True)
class OscDriverCall:
    """Named native driver-extension call; these are not invented IOCTL packets."""

    export: str
    selector: int | None = None
    data: bytes | None = None
    maximum: int = 0


class DstiOscDriver:
    """KGP 3ca0..3ec0 dynamic driver exports over typed observations only."""

    EXPORTS = frozenset(
        (
            "DstiOscCommand",
            "DstiOscSetParameter",
            "DstiOscGetParameter",
            "DstiOscReadBuffer",
        )
    )

    def __init__(
        self,
        exchange: Callable[[OscDriverCall, float], int | OscParameter],
        *,
        module_loaded: bool,
        exports: frozenset[str],
    ):
        if type(module_loaded) is not bool or not isinstance(exports, frozenset):
            raise MonitorError("Driver module/export observations must be explicit")
        if any(not isinstance(name, str) for name in exports):
            raise MonitorError("Driver export observation must contain names")
        self.exchange, self.module_loaded, self.exports = (
            exchange,
            module_loaded,
            exports,
        )

    def _invoke(self, call: OscDriverCall, deadline: float) -> int | OscParameter:
        if not self.module_loaded:
            return 0x90020101
        if call.export not in self.exports:
            return 0x90020102
        return self.exchange(call, deadline)

    def command(self, command: int, *, deadline: float) -> int:
        result = self._invoke(
            OscDriverCall("DstiOscCommand", _uint(command, 8)), deadline
        )
        if type(result) is not int:
            raise MonitorError("DstiOscCommand requires native DWORD status")
        return _uint(result)

    def set_parameter(self, parameter: int, data: bytes, *, deadline: float) -> int:
        _uint(parameter, 8)
        if not isinstance(data, bytes) or len(data) > 0x1068:
            raise MonitorError("DstiOscSetParameter input exceeds native buffer")
        result = self._invoke(
            OscDriverCall("DstiOscSetParameter", parameter, data), deadline
        )
        if type(result) is not int:
            raise MonitorError("DstiOscSetParameter requires native DWORD status")
        return _uint(result)

    def get_parameter(
        self, parameter: int, maximum: int, *, deadline: float
    ) -> OscParameter:
        return self._read(
            OscDriverCall("DstiOscGetParameter", _uint(parameter, 8), maximum=maximum),
            deadline,
        )

    def read_buffer(self, maximum: int, *, deadline: float) -> OscRead:
        result = self._read(
            OscDriverCall("DstiOscReadBuffer", maximum=maximum), deadline
        )
        if not isinstance(result, OscRead):
            if result.status:
                return OscRead(result.status, b"")
            raise MonitorError(
                "DST-i read needs native timestamp and remaining outputs"
            )
        return result

    def _read(self, call: OscDriverCall, deadline: float) -> OscParameter:
        if type(call.maximum) is not int or not 0 <= call.maximum <= 0x1068:
            raise MonitorError("DST-i output capacity exceeds native buffer")
        result = self._invoke(call, deadline)
        if type(result) is int:
            if result == 0:
                raise MonitorError(
                    "Successful DST-i read needs actual output observations"
                )
            return OscParameter(result, b"")
        # KGP15520 uses zero as the read-buffer sentinel with a 0x41a0 backing
        # buffer. GetParameter retains its literal requested capacity.
        capacity = (
            0x41A0
            if call.export == "DstiOscReadBuffer" and call.maximum == 0
            else call.maximum
        )
        if not isinstance(result, OscParameter) or len(result.data) > capacity:
            raise MonitorError("DST-i output observation exceeds requested capacity")
        return result


@dataclass
class OscConfiguration:
    measure: bytearray = field(default_factory=lambda: bytearray(8))
    reverse: bytearray = field(default_factory=lambda: bytearray(4))
    forward: bytearray = field(default_factory=lambda: bytearray(4))
    voltage: bytearray = field(default_factory=lambda: bytearray(4))
    mode: int = 0

    @classmethod
    def selected(cls, plan: SelectedInstrumentMonitor) -> OscConfiguration:
        if plan.category != 999 or len(plan.descriptors) != 4:
            raise MonitorError("Oscilloscope requires selected category999")
        result = cls()
        for descriptor in plan.descriptors:
            if len(descriptor) != 4:
                raise MonitorError("Oscilloscope descriptor must contain four bytes")
            channel, measure, forward, voltage = descriptor
            result.set_measure_time_range(channel, measure)
            result.set_forward_time_range(channel, forward)
            result.set_volt_range(channel, voltage)
        result.mode = 4
        return result

    @staticmethod
    def _channel(channel: int, value: int) -> None:
        _uint(value, 8)
        if type(channel) is not int or not 0 <= channel < 4:
            raise MonitorError("Instrument channel must be0..3")

    def set_measure_time_range(self, channel: int, value: int) -> None:
        self._channel(channel, value)
        self.measure[2 * channel : 2 * channel + 2] = bytes((channel, value))
        self.reverse[channel] = value

    def set_forward_time_range(self, channel: int, value: int) -> None:
        self._channel(channel, value)
        self.forward[channel] = value

    def set_volt_range(self, channel: int, value: int) -> None:
        self._channel(channel, value)
        self.voltage[channel] = value

    def set_measure_mode(self, value: int) -> None:
        self.mode = _uint(value, 8)


class OscilloscopeRuntime:
    """DataListIF normal/Dual DST-i setup, stop/drain and exact native timestamps."""

    def __init__(
        self,
        provider: OscPrimitives,
        configuration: OscConfiguration,
        *,
        timeout: float = 5,
        max_reads: int = 1024,
        max_packets: int = 100_000,
        cancelled: Callable[[], bool] = lambda: False,
        clock: Callable[[], float] = time.monotonic,
        write_sample: Callable[[NativeMonitorPacket], int] | None = None,
    ):
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            raise MonitorError("Instrument timeout must be positive and finite")
        for value in (max_reads, max_packets):
            if type(value) is not int or not 1 <= value <= 100_000:
                raise MonitorError("Instrument resource budget is invalid")
        for value, length in (
            (configuration.measure, 8),
            (configuration.reverse, 4),
            (configuration.forward, 4),
            (configuration.voltage, 4),
        ):
            if not isinstance(value, bytearray) or len(value) != length:
                raise MonitorError("Instrument configuration length is invalid")
        _uint(configuration.mode, 8)
        self.provider, self.configuration = provider, configuration
        self.timeout, self.max_reads, self.max_packets = timeout, max_reads, max_packets
        self.cancelled, self.clock, self.write_sample = cancelled, clock, write_sample
        self.packets: list[NativeMonitorPacket] = []
        self.calls: list[dict] = []
        self.sampling_period = SAMPLING_PERIODS[0]
        self.cursor = self.previous = self.wrap_ms = self.wrap_fraction = (
            self.fraction
        ) = 0
        self.error_word = self.error_parameter = 0
        self.state = "configured"
        self.read_count = 0

    def _check(self, deadline: float, *, cancel: bool = True) -> None:
        now = self.clock()
        if (
            type(deadline) not in (int, float)
            or not math.isfinite(deadline)
            or type(now) not in (int, float)
            or not math.isfinite(now)
        ):
            raise MonitorError("Instrument clock and deadline must be finite")
        if cancel and self.cancelled():
            raise RecorderCancelled("Instrument acquisition cancelled")
        if now >= deadline:
            raise MonitorError("Instrument acquisition deadline exceeded")

    def _call(
        self,
        command: int,
        data: bytes | None,
        deadline: float,
        *,
        cleanup: bool = False,
    ) -> int:
        self._check(deadline, cancel=not cleanup)
        status = (
            self.provider.command(command, deadline=deadline)
            if data is None
            else self.provider.set_parameter(command, data, deadline=deadline)
        )
        _uint(status)
        if status:
            self.error_word = 0x907F if data is None else 0x917F
            self.error_parameter = command
        self._check(deadline, cancel=not cleanup)
        self.calls.append(
            {
                "operation": "command" if data is None else "set_parameter",
                "parameter": command,
                "data_hex": None if data is None else data.hex(),
                "status": status,
            }
        )
        return status

    def _rate(self, selector: int) -> None:
        self.sampling_period = SAMPLING_PERIODS[selector if selector <= 21 else 0]

    def start(self) -> int:
        if self.state != "configured":
            raise MonitorError("Oscilloscope start requires configured state")
        deadline = self.clock() + self.timeout
        cfg = self.configuration
        self.state = "starting"
        for command, data in (
            (0, None),
            (9, bytes(cfg.measure)),
            (10, bytes(cfg.forward)),
            (6, bytes(cfg.voltage)),
            (8, bytes((cfg.mode,))),
            (2, None),
        ):
            status = self._call(command, data, deadline)
            if status:
                self.state = "fault"
                return status
            if command == 10:
                self._rate(cfg.forward[0])
        self.state = "running"
        return 0

    def _samples(self, observed: OscRead, deadline: float) -> int:
        current = self.cursor or observed.timestamp
        for offset in range(0, len(observed.data), 4):
            self._check(deadline)
            if len(self.packets) >= self.max_packets:
                raise MonitorError("Oscilloscope packet budget exceeded")
            if current < self.previous:
                carry = self.wrap_fraction + 0x128
                self.wrap_ms = (self.wrap_ms + carry // 1000 + 0x418937) & 0xFFFFFFFF
                self.wrap_fraction = carry % 1000
            self.previous = current
            timestamp = (
                (current % 1000 + self.wrap_fraction) // 1000
                + current // 1000
                + self.wrap_ms
            ) & 0xFFFFFFFF
            packet = NativeMonitorPacket(timestamp, observed.data[offset : offset + 4])
            status = 0 if self.write_sample is None else self.write_sample(packet)
            _uint(status)
            self._check(deadline)
            if status:
                self.error_word, self.error_parameter = 0x937F, 0
                return status
            self.packets.append(packet)
            carry = self.sampling_period % 1000 + self.fraction
            current = (
                current + self.sampling_period // 1000 + carry // 1000
            ) & 0xFFFFFFFF
            self.cursor, self.fraction = current, carry % 1000
        return 0

    def drain(self, *, deadline: float | None = None) -> int:
        if self.state not in ("running", "stopping"):
            raise MonitorError("Oscilloscope drain requires active state")
        until = self.clock() + self.timeout if deadline is None else deadline
        for _ in range(self.max_reads):
            if self.read_count >= self.max_reads:
                raise MonitorError("Oscilloscope read budget exceeded")
            self.read_count += 1
            self._check(until)
            observed = self.provider.read_buffer(0x1068, deadline=until)
            self._check(until)
            if not isinstance(observed, OscRead):
                raise MonitorError(
                    "Oscilloscope provider must return typed read observation"
                )
            if len(observed.data) > 0x1068:
                raise MonitorError(
                    "Oscilloscope drain exceeds native0x1068-byte buffer"
                )
            self.calls.append(
                {
                    "operation": "read_buffer",
                    "status": observed.status,
                    "size": len(observed.data),
                    "remaining": observed.remaining,
                }
            )
            if observed.status:
                self.error_word, self.error_parameter = 0x937F, 0
                return observed.status
            if not observed.data:
                return 0
            status = self._samples(observed, until)
            if status or not observed.remaining:
                return status
        raise MonitorError("Oscilloscope read budget exceeded")

    def stop(self) -> int:
        if self.state not in ("running", "fault", "starting"):
            raise MonitorError("Oscilloscope stop requires started state")
        deadline = self.clock() + self.timeout
        self.state = "stopping"
        status = 0
        failure: Exception | None = None
        try:
            for command, data in (
                (3, None),
                (11, None),
                (10, bytes(self.configuration.reverse)),
            ):
                status = self._call(command, data, deadline)
                if status:
                    break
            if status == 0:
                self._rate(self.configuration.reverse[0])
                self.packets.clear()  # Native FlashBuffer before final reverse-time read.
                self.cursor = self.previous = self.wrap_ms = self.wrap_fraction = (
                    self.fraction
                ) = 0
                status = self.drain(deadline=deadline)
        except Exception as exc:  # noqa: BLE001 - preserve provider failure across release
            failure = exc
        finally:
            # Release gets its own bounded deadline even after acquisition cancellation.
            prior = (self.error_word, self.error_parameter)
            preserve_primary = bool(status or failure is not None)
            try:
                cleanup = self._call(1, None, self.clock() + self.timeout, cleanup=True)
                if status or failure is not None:
                    self.error_word, self.error_parameter = prior
                elif cleanup:
                    status = cleanup
            except Exception as exc:  # noqa: BLE001 - preserve provider failure across release
                if failure is None:
                    failure = exc
            if preserve_primary:
                self.error_word, self.error_parameter = prior
            self.state = "fault" if status or failure is not None else "stopped"
        if failure is not None:
            raise failure
        return status

    def capture(self, trigger_timestamp_ms: int = 0) -> NativeRecorderCapture:
        return NativeRecorderCapture(_uint(trigger_timestamp_ms), tuple(self.packets))

    def report(self) -> dict:
        notification = {
            0x907F: 0xE2001000,
            0x917F: 0xE2001001,
            0x927F: 0xE2001002,
            0x937F: 0xE2001003,
        }.get(self.error_word)
        return {
            "state": self.state,
            "packets": len(self.packets),
            "error_word": self.error_word,
            "error_parameter": self.error_parameter,
            "notification": notification,
            "calls": list(self.calls),
            "physical": "PHYSICAL_UNCONFIRMED",
            "provenance": "DataListIF12/18 DST-i instrument primitives and native ring packets",
        }
