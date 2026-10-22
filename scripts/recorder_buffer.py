"""Bounded native recorder byte storage and serial images; no device execution."""

from __future__ import annotations

import struct
from collections.abc import Callable
from typing import Literal

MAX_BUFFER_BYTES = 32 * 1024 * 1024
U32 = 0xFFFFFFFF


class RecorderBufferError(ValueError):
    """Invalid native buffer request or unavailable bytes."""


def _integer(value: int, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise RecorderBufferError("Native buffer integer outside supported bounds")
    return value


class NativeRecorderRing:
    """Native allocation, unread accounting, oldest cursor and selected output.

    `written` saturates independently of `free`. `write_position` may equal
    capacity, while `start` and `read_position` are normalized byte offsets.
    """

    def __init__(
        self,
        capacity: int,
        packet_size: int,
        block_packets: int = 1,
        *,
        phase: int = 0,
        max_bytes: int = MAX_BUFFER_BYTES,
        max_packets: int = 100_000,
        native_source: Literal["x86", "sh3"] = "x86",
    ):
        self.max_bytes = _integer(max_bytes, 1, MAX_BUFFER_BYTES)
        self.max_packets = _integer(max_packets, 1, 100_000)
        if native_source not in ("x86", "sh3"):
            raise RecorderBufferError("Unknown native recorder source")
        self.native_source = native_source
        self.capacity = _integer(capacity, 1, max_bytes)
        self.packet_size = _integer(packet_size, 4, capacity)
        self.block_packets = _integer(block_packets, 1, 65535)
        self.phase = _integer(phase, 0, 1)
        if packet_size * block_packets > capacity:
            raise RecorderBufferError("Native block exceeds allocation")
        self._image = bytearray(capacity)
        self.free = capacity
        self.start = self.read_position = self.write_position = self.written = 0
        self.current_packet = 0
        self.record_start = self.record_size = 0
        self.complement = self.complement_bytes = 0

    @property
    def image(self) -> bytes:
        return bytes(self._image)

    def _slice(self, start: int, size: int) -> bytes:
        _integer(start, 0, self.capacity)
        _integer(size, 0, self.capacity)
        start %= self.capacity
        tail = min(size, self.capacity - start)
        return bytes(self._image[start : start + tail] + self._image[: size - tail])

    def write(self, data: bytes) -> None:
        """Base WriteBuffer: preserve the inclusive collision and end cursor."""
        if not isinstance(data, bytes):
            raise RecorderBufferError("Native buffer write requires bytes")
        size = len(data)
        if not size:
            return
        if size > self.free:
            raise RecorderBufferError(
                "Native buffer has insufficient unread free space"
            )
        start = self.start
        limit = start + self.capacity if start <= self.write_position else start
        if limit <= self.write_position + size:
            start += size
            if self.capacity <= start:
                start -= self.capacity
        position = self.write_position % self.capacity
        tail = min(size, self.capacity - position)
        self._image[position : position + tail] = data[:tail]
        self._image[: size - tail] = data[tail:]
        self.start = start
        self.write_position = position + size
        if self.write_position > self.capacity:
            self.write_position -= self.capacity
        self.written = min(self.capacity, self.written + size)
        self.free -= size

    def read(self, size: int) -> bytes:
        """Base ReadBuffer consumes unread bytes without changing history."""
        _integer(size, 0, self.capacity)
        if size > self.capacity - self.free:
            raise RecorderBufferError("Native buffer has insufficient unread data")
        result = self._slice(self.read_position, size)
        self.read_position = (self.read_position + size) % self.capacity
        self.free += size
        return result

    def append(self, timestamp: int, payload: bytes, *, consume: bool = True) -> None:
        """WriteItem, optionally followed by the recorder consumer read."""
        _integer(timestamp, 0, U32)
        if type(consume) is not bool:
            raise RecorderBufferError("Native packet consumption flag must be boolean")
        if not isinstance(payload, bytes) or len(payload) != self.packet_size - 4:
            raise RecorderBufferError("Native recorder payload size mismatch")
        self.write(struct.pack("<I", timestamp) + payload)
        self.current_packet = (self.current_packet + 1) % self.block_packets
        if consume:
            self.read(self.packet_size)

    def reset_seek(self) -> None:
        """ForceRecalcValidArea restores unread history from the oldest cursor."""
        self.free = self.capacity - self.written
        self.read_position = self.start

    @property
    def active_size(self) -> int:
        size = self.write_position - self.start
        return size + self.capacity if size < 0 else size

    def packet_bytes(self) -> bytes:
        """Current oldest-to-write span, distinct from saturated write count."""
        if self.active_size % self.packet_size:
            raise RecorderBufferError("Native active area ends inside a packet")
        return self._slice(self.start, self.active_size)

    def _check_packet_count(self, count: int) -> None:
        if count > self.max_packets:
            raise RecorderBufferError(
                "Native packet materialization or scan budget exceeded"
            )

    def packets(self) -> tuple[bytes, ...]:
        self._check_packet_count(self.active_size // self.packet_size)
        data = self.packet_bytes()
        return tuple(
            data[offset : offset + self.packet_size]
            for offset in range(0, len(data), self.packet_size)
        )

    def packet_slot(self, position: int) -> int:
        """Generator cache slot for an appended packet retained at this offset."""
        _integer(position, 0, self.capacity - 1)
        distance = (position - self.start) % self.capacity
        if (
            distance % self.packet_size
            or distance + self.packet_size > self.active_size
        ):
            raise RecorderBufferError(
                "Native packet slot references outside complete history"
            )
        count = self.active_size // self.packet_size
        return (
            self.current_packet - count + distance // self.packet_size
        ) % self.block_packets

    def select_positions(self, start: int, end: int) -> bytes:
        """StartRecording/StopRecording: end denotes the first byte of a block."""
        _integer(start, 0, self.capacity - 1)
        _integer(end, 0, self.capacity)
        stop = end + self.capacity if end < start else end
        size = self.block_packets * self.packet_size - start + stop
        if size > self.capacity:
            raise RecorderBufferError("Native recording area exceeds allocation")
        self.record_start, self.record_size = start, size
        return self._slice(start, size)

    def set_record_area(self, start: int, size: int) -> None:
        """SetRecordStart/SetRecordSize with bounded host memory validation."""
        _integer(start, 0, self.capacity)
        _integer(size, 0, self.capacity)
        self.record_start, self.record_size = start, size

    def set_complement(self, value: int, packet_bytes: int | None = None) -> None:
        """SetComplement: signed low32 delta and byte width, without resampling."""
        _integer(value, -0x80000000, U32)
        value &= U32
        if value & 0x80000000:
            value -= 1 << 32
        width = (
            self.block_packets * self.packet_size
            if packet_bytes is None
            else packet_bytes
        )
        _integer(width, 0, self.capacity)
        self.complement, self.complement_bytes = value, width

    def calc_complement(self, first: int, second: int, third: int) -> None:
        for value in (first, second, third):
            _integer(value, 0, U32)
        self.set_complement((first - third + second) & U32)

    def serialize(self, serial_mode: int = 0) -> bytes:
        """Ring WriteImage/WriteInvalidArea, retaining their distinct headers."""
        _integer(serial_mode, 0, 1)
        if serial_mode == 0:
            fields = (
                self.capacity,
                self.capacity - self.written,
                self.start,
                self.start,
                self.write_position,
                self.written,
                self.capacity,
            )
            image = self.image
        else:
            image = bytearray(self._slice(self.record_start, self.record_size))
            width = self.complement_bytes
            delta = self.complement
            total = self.record_size + (width if delta > 0 else 0)
            if total > self.max_bytes:
                raise RecorderBufferError(
                    "Native serial image exceeds host byte budget"
                )
            if width > 4 and width > self.record_size:
                raise RecorderBufferError(
                    "Native complement references outside recorded bytes"
                )
            if width > 4:
                offset = self.record_size - width
                timestamp = struct.unpack_from("<I", image, offset)[0]
                timestamp = (timestamp + delta) & U32
                if delta > 0:
                    image += struct.pack("<I", timestamp) + image[offset + 4 :]
                else:
                    struct.pack_into("<I", image, offset, timestamp)
            elif delta > 0 and width:
                # Native allocates this tail but does not initialize it.
                raise RecorderBufferError(
                    "Native complement tail has no defined source bytes"
                )
            fields = (
                self.capacity,
                self.capacity - self.record_size,
                0,
                0,
                total,
                total,
                total,
            )
        return (
            struct.pack("<HHIH7I", 1, 0, self.phase, self.block_packets, *fields)
            + image
        )

    def packet_time(self, index: int) -> int:
        """GetPacketTime, including its strict capacity boundary and sentinel."""
        _integer(index, 0, U32)
        position = (self.start + self.packet_size * index) & U32
        if position > self.capacity:
            position -= self.capacity
        extension = (
            self.capacity if self.start > 0 and self.write_position < self.start else 0
        )
        if (
            position >= self.capacity
            or position + self.packet_size > self.write_position + extension
        ):
            return U32
        # Native reads four contiguous bytes; reject an unsafe native pointer.
        if position + 4 > self.capacity:
            return U32
        return struct.unpack_from("<I", self._image, position)[0]

    def _seek_fallback(self, ceiling: bool) -> int:
        if self.native_source == "sh3":
            raise RecorderBufferError(
                "Unknown SH3 native seek result after interior sentinel or exhausted scan"
            )
        return int(not ceiling)

    def approximate_time(self, target: int, ceiling: bool) -> int:
        """GetApproximateTime uses unsigned source values, not interpolation."""
        _integer(target, 0, U32)
        if type(ceiling) is not bool:
            raise RecorderBufferError("Native approximation direction must be boolean")
        count = self.active_size // self.packet_size // self.block_packets
        self._check_packet_count(count)
        if count < 1:
            return U32
        first = self.packet_time(0)
        if first == U32 or target <= first:
            return first
        index = count - 1
        last = self.packet_time(index)
        if last == U32 or target >= last:
            return last
        if (last - first) >> 1 < target - first:
            while index >= 0:
                value = self.packet_time(index)
                if value == U32:
                    return self._seek_fallback(ceiling)
                if value == target:
                    return value
                if value < target:
                    return last if ceiling else value
                index -= 1
                last = value
            return self._seek_fallback(ceiling)
        for index in range(count):
            value = self.packet_time(index)
            if value == U32:
                return self._seek_fallback(ceiling)
            if value == target:
                return value
            if target < value:
                return value if ceiling else first
            first = value
        return self._seek_fallback(ceiling)

    def absolute_position(self, target: int) -> int:
        """GetAbsolutePosFromTime/GetPacketIndex, including two-sided scan."""
        _integer(target, 0, U32)
        span = (
            self.write_position - self.start
            if self.start < self.write_position
            else self.capacity
        )
        count = span // self.packet_size // self.block_packets
        self._check_packet_count(count)
        stride = self.block_packets * self.packet_size
        middle = count // 2
        offset = count * stride
        for front in range(middle):
            back = count - front - 1
            if self.packet_time(front) <= target < self.packet_time(front + 1):
                offset = front * stride
                break
            if self.packet_time(back - 1) < target <= self.packet_time(back):
                offset = back * stride
                break
        else:
            if target <= self.packet_time(middle):
                offset = middle * stride
        position = self.start + offset
        if position >= self.capacity:
            position -= self.capacity
        if not 0 <= position < self.capacity:
            raise RecorderBufferError(
                "Native time lookup produced an invalid byte offset"
            )
        return position

    def seek_timestamp(self, target: int, *, floor: bool) -> tuple[int, int]:
        """Return native rounded timestamp and its native block byte offset."""
        if type(floor) is not bool:
            raise RecorderBufferError("Native seek direction must be boolean")
        timestamp = self.approximate_time(target, not floor)
        if timestamp == U32:
            raise RecorderBufferError("Native timestamp lookup has no available packet")
        return timestamp, self.absolute_position(timestamp)

    def select(self, left_target: int, right_target: int) -> bytes:
        """Native Save composition: round left down, right up, include end block."""
        _, start = self.seek_timestamp(left_target, floor=True)
        _, end = self.seek_timestamp(right_target, floor=False)
        return self.select_positions(start, end)

    def feed(
        self,
        records: tuple[tuple[int, bytes], ...],
        *,
        cancelled: Callable[[], bool] = lambda: False,
    ) -> None:
        """Append bounded caller records, checking cancellation before mutation."""
        if not isinstance(records, tuple) or len(records) > min(
            self.max_packets, self.max_bytes // self.packet_size
        ):
            raise RecorderBufferError("Native feed exceeds aggregate byte budget")
        for timestamp, payload in records:
            if cancelled():
                raise RecorderBufferError("Native recorder buffer feed cancelled")
            self.append(timestamp, payload)
