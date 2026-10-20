"""Bounded ComTol32 transfer scheduling over an explicitly supplied byte stream.

There is no device discovery, opening, firmware loading or command retransmission.
The stream must honour read/write timeouts and report accepted write bytes exactly.
"""

from __future__ import annotations

import math
import struct
import threading
import time
from collections.abc import Callable
from typing import Protocol, Self

from scripts.drive_recorder import (
    NativeTransferSession,
    RecorderCancelled,
    RecorderError,
    UnsupportedRecorderOperation,
)


class RecorderStream(Protocol):
    def read(self, size: int, *, timeout: float) -> bytes:
        """Return at most size bytes; empty bytes mean temporary idle, not EOF."""
        ...

    def write(self, data: bytes, *, timeout: float) -> int:
        """Return the exact accepted prefix size; raise on disconnect/uncertainty."""
        ...

    def close(self) -> None: ...


class RecorderTransport:
    """NativeVimExchange adapter owning one already supplied stream.

    Native transfer errors poison this connection: an unobserved ACK cannot prove
    whether a command ran. Construct a new adapter with a newly synchronized
    stream after a failure; no recovery method silently replays application PDUs.
    """

    def __init__(
        self,
        stream: RecorderStream,
        *,
        capabilities: frozenset[str],
        clock: Callable[[], float] = time.monotonic,
        max_size: int = 64 * 1024 * 1024,
        io_timeout: float = 0.05,
        max_events: int = 100000,
    ):
        if (
            not isinstance(capabilities, frozenset)
            or "denso-vim-control" not in capabilities
        ):
            raise UnsupportedRecorderOperation(
                "Stream did not explicitly declare denso-vim-control"
            )
        if type(max_size) is not int or not 1 <= max_size <= 64 * 1024 * 1024:
            raise RecorderError("Native transfer limit must be 1..64 MiB")
        if type(max_events) is not int or not 1 <= max_events <= 1000000:
            raise RecorderError("Native transfer event budget must be 1..1000000")
        if not math.isfinite(io_timeout) or not 0 < io_timeout <= 1:
            raise RecorderError("Stream I/O timeout must be finite within (0,1]")
        self.stream, self.capabilities, self.clock = stream, capabilities, clock
        self.max_size, self.io_timeout, self.max_events = (
            max_size,
            io_timeout,
            max_events,
        )
        self.session = NativeTransferSession(max_size=max_size, clock=clock)
        self._busy = threading.Lock()
        self._close_lock = threading.Lock()
        self._cancel_lock = threading.Lock()
        self._active = False
        self._cancelled, self._closed = threading.Event(), threading.Event()
        self._fault = False
        self._events = 0
        self._buffer = bytearray()
        self.bytes_written = self.bytes_read = self.exchanges = 0
        self.last_error: str | None = None

    def _check(self, deadline: float, cancelled: Callable[[], bool]) -> None:
        if self._closed.is_set():
            raise ConnectionError("Native recorder stream is closed")
        if self._cancelled.is_set() or cancelled():
            raise RecorderCancelled("Native recorder transfer cancelled")
        if self.clock() >= deadline:
            raise TimeoutError("Native recorder exchange deadline exceeded")

    def _event(self) -> None:
        self._events += 1
        if self._events > self.max_events:
            raise RecorderError("Native recorder I/O event budget exceeded")

    def _write(
        self, data: bytes, deadline: float, cancelled: Callable[[], bool]
    ) -> None:
        position = 0
        while position < len(data):
            self._check(deadline, cancelled)
            self._event()
            count = self.stream.write(
                data[position:], timeout=min(self.io_timeout, deadline - self.clock())
            )
            if type(count) is not int or not 0 < count <= len(data) - position:
                raise RecorderError("Native stream write made invalid or zero progress")
            self.bytes_written += count
            position += count
            self._check(deadline, cancelled)

    def _read(self, deadline: float, cancelled: Callable[[], bool]) -> bytes | None:
        target = 4
        if len(self._buffer) >= 4:
            size = struct.unpack_from("<H", self._buffer, 2)[0]
            if size > 511:
                raise RecorderError("Native stream frame length exceeds 511 bytes")
            target = size + 6
        self._check(deadline, cancelled)
        self._event()
        try:
            data = self.stream.read(
                target - len(self._buffer),
                timeout=min(self.io_timeout, deadline - self.clock()),
            )
        except TimeoutError:
            self._check(deadline, cancelled)
            return None
        self._check(deadline, cancelled)
        if not isinstance(data, bytes) or len(data) > target - len(self._buffer):
            raise RecorderError("Native stream read violated its byte bound")
        self.bytes_read += len(data)
        self._buffer.extend(data)
        if self._buffer and self._buffer[0] != 2:
            raise RecorderError("Native stream lost STX framing")
        if len(self._buffer) == target and target != 4:
            result = bytes(self._buffer)
            self._buffer.clear()
            return result
        return None

    def __call__(
        self,
        request: bytes,
        *,
        deadline: float,
        cancelled: Callable[[], bool],
    ) -> bytes:
        if (
            not isinstance(request, bytes)
            or not request
            or len(request) > self.max_size
        ):
            raise RecorderError("Native request must be nonempty bounded bytes")
        if not math.isfinite(deadline):
            raise RecorderError("Native exchange deadline must be finite")
        if not self._busy.acquire(blocking=False):
            raise RecorderError("Native recorder transport is busy")
        started = False
        try:
            if self._fault:
                raise RecorderError("Native stream requires explicit reconnection")
            with self._cancel_lock:
                self._cancelled.clear()
                self._active = True
            self._check(deadline, cancelled)
            self._events = 0
            started = True
            self._write(self.session.start(request), deadline, cancelled)
            next_probe = self.clock() + 1.0
            while True:
                data = self._read(deadline, cancelled)
                if data is not None:
                    for frame in self.session.receive(data):
                        self._write(frame, deadline, cancelled)
                    if self.session.complete:
                        result = self.session.take_response()
                        self._check(deadline, cancelled)
                        self.exchanges += 1
                        return result
                # poll also enforces the native 2s ACK / 10s receive timers.
                for frame in self.session.poll():
                    if self.clock() >= next_probe:
                        self._write(frame, deadline, cancelled)
                        next_probe = self.clock() + 1.0
        except Exception as exc:
            self.last_error = str(exc)
            if started:
                self._fault = True
                self.session.cancel()
                self._buffer.clear()
            try:
                self._check(deadline, cancelled)
            except Exception as boundary:
                self.last_error = str(boundary)
                raise boundary from exc
            raise
        finally:
            with self._cancel_lock:
                self._active = False
            self._busy.release()

    def cancel(self) -> None:
        """Interrupt the current exchange at its next bounded I/O boundary."""
        with self._cancel_lock:
            if self._active:
                self._cancelled.set()

    def close(self) -> None:
        """Close the supplied stream once, including while an exchange is active."""
        with self._close_lock:
            if not self._closed.is_set():
                self._closed.set()
                self._cancelled.set()
                self.stream.close()

    def __enter__(self) -> Self:
        if self._closed.is_set():
            raise ConnectionError("Native recorder stream is closed")
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def report(self) -> dict:
        return {
            "state": "closed"
            if self._closed.is_set()
            else "fault"
            if self._fault
            else "busy"
            if self._busy.locked()
            else "idle",
            "native_state": self.session.state,
            "exchanges": self.exchanges,
            "bytes_written": self.bytes_written,
            "bytes_read": self.bytes_read,
            "last_error": self.last_error,
            "capabilities": sorted(self.capabilities),
            "command_retransmissions": 0,
            "physical_status": "PHYSICAL_UNCONFIRMED",
        }
