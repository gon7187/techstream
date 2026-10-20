"""Bounded native Classical CAN ISO-TP state machines for the raw CAN channel.

This is a native host policy, NOT a claim to reproduce JLR firmware timers.
No CAN FD, escape-length FF, functional multi-frame or broad masked peer IDs.
Caller supplies monotonic timestamps; the module never sleeps or performs I/O.
"""

import math
from dataclasses import dataclass


class ProtocolError(ValueError):
    pass


def stmin_seconds(value: int) -> float:
    if 0 <= value <= 0x7F:
        return value / 1000
    if 0xF1 <= value <= 0xF9:
        return (value - 0xF0) / 10000
    raise ProtocolError("reserved STmin")


@dataclass(frozen=True)
class Peer:
    tx_id: int
    rx_id: int
    extended_id: bool = False
    tx_address: int | None = None
    rx_address: int | None = None

    def __post_init__(self):
        maximum = 0x1FFFFFFF if self.extended_id else 0x7FF
        if not 0 <= self.tx_id <= maximum or not 0 <= self.rx_id <= maximum:
            raise ValueError("CAN ID out of range")
        if (self.tx_address is None) != (self.rx_address is None):
            raise ValueError("both extended address bytes are required")
        for address in (self.tx_address, self.rx_address):
            if address is not None and not 0 <= address <= 255:
                raise ValueError("extended address out of range")

    def output(self, data: bytes, padding: int | None) -> bytes:
        prefix = b"" if self.tx_address is None else bytes([self.tx_address])
        result = prefix + data
        if len(result) > 8:
            raise ProtocolError("Classical CAN frame too long")
        return result if padding is None else result.ljust(8, bytes([padding]))

    def input(self, can_id: int, data: bytes, extended_id: bool) -> bytes | None:
        if can_id != self.rx_id or extended_id != self.extended_id:
            return None
        if not 1 <= len(data) <= 8:
            raise ProtocolError("Classical CAN frame size outside1..8")
        if self.rx_address is not None:
            if data[0] != self.rx_address:
                return None
            data = data[1:]
        if not data:
            raise ProtocolError("missing ISO PCI")
        return data


def _time(now: float, previous: float) -> float:
    if not math.isfinite(now) or now < previous:
        raise ValueError("timestamps must be finite and monotonic")
    return now


def _configuration(timeout: float, padding: int | None):
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("timeout must be finite and positive")
    if padding is not None and not 0 <= padding <= 255:
        raise ValueError("padding byte out of range")


class Receiver:
    def __init__(
        self,
        peer: Peer,
        *,
        timeout: float = 1.0,
        blocksize: int = 0,
        stmin: int = 0,
        padding: int | None = None,
    ):
        _configuration(timeout, padding)
        if not 0 <= blocksize <= 255:
            raise ValueError("block size out of range")
        stmin_seconds(stmin)
        self.peer, self.timeout = peer, timeout
        self.blocksize, self.stmin, self.padding = blocksize, stmin, padding
        self.last_time = float("-inf")
        self.reset()

    def reset(self):
        self.buffer = bytearray()
        self.total = 0
        self.sequence = 1
        self.block_count = 0
        self.deadline: float | None = None

    def tick(self, now: float):
        self.last_time = _time(now, self.last_time)
        if self.deadline is not None and now >= self.deadline:
            self.reset()
            raise TimeoutError("ISO consecutive-frame timeout")

    def feed(
        self, can_id: int, data: bytes, now: float, *, extended_id: bool = False
    ) -> tuple[bytes | None, bytes | None]:
        self.tick(now)
        try:
            raw = self.peer.input(can_id, data, extended_id)
            if raw is None:
                return None, None
            kind, nibble = raw[0] >> 4, raw[0] & 15
            address_size = int(self.peer.rx_address is not None)
            if kind == 0:
                if not 1 <= nibble <= 7 - address_size or len(raw) < nibble + 1:
                    raise ProtocolError("invalid single-frame length")
                # Original20fc0 interrupts an active segmented receive with an SF.
                self.reset()
                return raw[1 : 1 + nibble], None
            if kind == 1:
                if len(raw) != 8 - address_size:
                    raise ProtocolError("first frame must occupy Classical CAN MTU")
                total = nibble * 256 + raw[1]
                if not 8 - address_size <= total <= 4095:
                    raise ProtocolError("invalid first-frame total length")
                # Original21790/21440 resets a previous FF before accepting a new FF.
                self.reset()
                self.total = total
                self.buffer.extend(raw[2:])
                self.deadline = now + self.timeout + stmin_seconds(self.stmin)
                fc = self.peer.output(
                    bytes([0x30, self.blocksize, self.stmin]), self.padding
                )
                return None, fc
            if kind != 2 or self.deadline is None:
                raise ProtocolError("unexpected PCI or consecutive frame without FF")
            if nibble != self.sequence or len(raw) < 2:
                raise ProtocolError("wrong consecutive-frame sequence/length")
            remaining = self.total - len(self.buffer)
            if remaining > len(raw) - 1 and len(raw) != 8 - address_size:
                raise ProtocolError("short nonfinal consecutive frame")
            self.buffer.extend(raw[1 : 1 + remaining])
            self.sequence = (self.sequence + 1) & 15
            self.block_count += 1
            self.deadline = now + self.timeout + stmin_seconds(self.stmin)
            if len(self.buffer) == self.total:
                pdu = bytes(self.buffer)
                self.reset()
                return pdu, None
            if self.blocksize and self.block_count == self.blocksize:
                self.block_count = 0
                return None, self.peer.output(
                    bytes([0x30, self.blocksize, self.stmin]), self.padding
                )
            return None, None
        except ProtocolError:
            self.reset()
            raise


class Sender:
    def __init__(
        self,
        peer: Peer,
        *,
        timeout: float = 1.0,
        wait_limit: int = 3,
        padding: int | None = None,
    ):
        _configuration(timeout, padding)
        if not 0 <= wait_limit <= 255:
            raise ValueError("wait limit out of range")
        self.peer, self.timeout, self.wait_limit, self.padding = (
            peer,
            timeout,
            wait_limit,
            padding,
        )
        self.last_time = float("-inf")
        self.reset()

    def reset(self):
        self.data = b""
        self.offset = 0
        self.sequence = 1
        self.state = "idle"
        self.deadline: float | None = None
        self.waits = 0
        self.blocksize = self.block_remaining = 0
        self.spacing = self.next_due = 0.0
        self.last_cf: float | None = None

    def tick(self, now: float):
        self.last_time = _time(now, self.last_time)
        if self.deadline is not None and now >= self.deadline:
            self.reset()
            raise TimeoutError("ISO flow-control/transmit-progress timeout")

    def start(self, data: bytes, now: float) -> bytes:
        self.tick(now)
        if self.state != "idle":
            raise RuntimeError("ISO transmitter is busy")
        if not 1 <= len(data) <= 4095:
            raise ValueError("ISO PDU must contain1..4095 bytes")
        address_size = int(self.peer.tx_address is not None)
        if len(data) <= 7 - address_size:
            return self.peer.output(bytes([len(data)]) + data, self.padding)
        self.data = bytes(data)
        self.offset = 6 - address_size
        self.state, self.deadline = "flow", now + self.timeout
        pci = bytes([0x10 | len(data) >> 8, len(data) & 255])
        return self.peer.output(pci + data[: self.offset], self.padding)

    def flow(self, can_id: int, data: bytes, now: float, *, extended_id: bool = False):
        self.tick(now)
        try:
            raw = self.peer.input(can_id, data, extended_id)
            if raw is None:
                return
            if self.state != "flow" or len(raw) < 3 or raw[0] >> 4 != 3:
                raise ProtocolError("unexpected flow control")
            status = raw[0] & 15
            if status == 1:
                self.waits += 1
                if self.waits > self.wait_limit:
                    raise ProtocolError("flow-control WAIT limit exceeded")
                self.deadline = now + self.timeout
                return
            if status != 0:
                raise ProtocolError("flow-control overflow/reserved status")
            self.spacing = stmin_seconds(raw[2])
            self.blocksize = self.block_remaining = raw[1]
            self.next_due = (
                now if self.last_cf is None else max(now, self.last_cf + self.spacing)
            )
            self.deadline = self.next_due + self.timeout
            self.state = "send"
        except ProtocolError:
            self.reset()
            raise

    def poll(self, now: float) -> bytes | None:
        self.tick(now)
        if self.state != "send" or now < self.next_due:
            return None
        size = 7 - int(self.peer.tx_address is not None)
        chunk = self.data[self.offset : self.offset + size]
        frame = self.peer.output(bytes([0x20 | self.sequence]) + chunk, self.padding)
        self.offset += len(chunk)
        self.sequence = (self.sequence + 1) & 15
        self.last_cf = now
        self.next_due = now + self.spacing
        self.deadline = now + self.timeout + self.spacing
        if self.offset == len(self.data):
            self.reset()
        elif self.blocksize:
            self.block_remaining -= 1
            if self.block_remaining == 0:
                self.state, self.deadline = "flow", now + self.timeout
        return frame
