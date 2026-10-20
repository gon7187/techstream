"""Offline native JLR adapter firmware codec and injected update state machine.

No import, constructor or parser discovers/opens hardware. Vendor images are BYOD.
"""

from __future__ import annotations

import hashlib
import math
import struct
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from scripts.jlr import JLRClient
from scripts.local_files import read_regular

MAX_IMAGE = 16 * 1024 * 1024
HEADER_SIZE = 108
MAX_CHUNK = 8192


@dataclass(frozen=True)
class FirmwareImage:
    data: bytes
    role: int  # Native resource selector: 0 bootloader, 1 application.
    version: int
    fingerprint: int
    sha256: str


def parse_image(data: bytes) -> FirmwareImage:
    """Parse the native resource envelope; preserve opaque payload byte for byte."""
    if not isinstance(data, bytes) or not HEADER_SIZE < len(data) <= MAX_IMAGE:
        raise ValueError("Firmware image must contain 109 bytes..16 MiB")
    size, kind, version = struct.unpack_from("<III", data)
    if size != HEADER_SIZE or kind not in (0x50001, 0x50002):
        raise ValueError("Unsupported native JLR firmware header")
    return FirmwareImage(
        data,
        kind - 0x50001,
        version,
        struct.unpack_from("<I", data, 76)[0],
        hashlib.sha256(data).hexdigest(),
    )


def load_image(path: str | Path) -> FirmwareImage:
    return parse_image(read_regular(path, limit=MAX_IMAGE))


def images_from_pe(data: bytes) -> tuple[FirmwareImage, FirmwareImage]:
    """Read explicit PE RT_RCDATA 5005/5006 without loading/executing the PE."""
    if (
        not isinstance(data, bytes)
        or not 64 <= len(data) <= 64 * 1024 * 1024
        or data[:2] != b"MZ"
    ):
        raise ValueError("Bounded PE bytes required")

    def num(offset: int, width: int = 4) -> int:
        if offset < 0 or offset + width > len(data):
            raise ValueError("Truncated PE")
        return int.from_bytes(data[offset : offset + width], "little")

    pe = num(60)
    if data[pe : pe + 4] != b"PE\0\0":
        raise ValueError("Invalid PE signature")
    count, optional = num(pe + 6, 2), pe + 24
    optional_size = num(pe + 20, 2)
    minimum = {0x10B: 96, 0x20B: 112}.get(num(optional, 2))
    if minimum is None or optional_size < minimum + 24 or not 1 <= count <= 96:
        raise ValueError("Invalid PE headers")
    table = optional + optional_size
    sections = [
        (num(table + i * 40 + 12), num(table + i * 40 + 16), num(table + i * 40 + 20))
        for i in range(count)
    ]

    def mapped(rva: int, size: int) -> int:
        spans = [
            p + rva - r
            for r, n, p in sections
            if r <= rva
            and 0 <= size <= n
            and rva - r <= n - size
            and p + n <= len(data)
        ]
        if len(spans) != 1:
            raise ValueError("Unmapped or ambiguous PE span")
        return spans[0]

    resource_rva, resource_size = (
        num(optional + minimum + 16),
        num(optional + minimum + 20),
    )
    root = mapped(resource_rva, resource_size)
    found: dict[int, FirmwareImage] = {}
    seen: set[int] = set()

    def walk(relative: int, keys: tuple[int, ...]) -> None:
        if len(keys) > 2 or relative in seen or relative + 16 > resource_size:
            raise ValueError("Invalid PE resource directory")
        seen.add(relative)
        base = root + relative
        total = num(base + 12, 2) + num(base + 14, 2)
        if total > 4096 or relative + 16 + total * 8 > resource_size:
            raise ValueError("Resource directory exceeds bounds")
        for index in range(total):
            key, value = num(base + 16 + index * 8), num(base + 20 + index * 8)
            # Only the known integer type/name routes are relevant.
            if (not keys and key != 10) or (keys == (10,) and key not in (5005, 5006)):
                continue
            if value & 0x80000000:
                walk(value & 0x7FFFFFFF, keys + (key,))
            else:
                if len(keys) != 2 or value + 16 > resource_size:
                    raise ValueError("Invalid firmware resource leaf")
                rva, size = num(root + value), num(root + value + 4)
                if size > MAX_IMAGE or keys[1] in found:
                    raise ValueError("Duplicate/oversized firmware resource")
                offset = mapped(rva, size)
                image = parse_image(data[offset : offset + size])
                if image.role != (1 if keys[1] == 5005 else 0):
                    raise ValueError("Firmware resource role disagrees with header")
                found[keys[1]] = image

    walk(0, ())
    if set(found) != {5005, 5006}:
        raise ValueError("Required firmware resources 5005/5006 absent")
    return found[5006], found[5005]


def load_library(path: str | Path) -> tuple[FirmwareImage, FirmwareImage]:
    return images_from_pe(read_regular(path, limit=64 * 1024 * 1024))


@dataclass(frozen=True)
class UpdateRecord:
    slot: int  # Native board bitmask, one of 1,2,4,...128.
    board_kind: int
    image: FirmwareImage


def plan(
    board_reply: bytes, images: tuple[FirmwareImage, ...], *, force: bool = False
) -> tuple[UpdateRecord, ...]:
    if not isinstance(board_reply, bytes) or len(board_reply) != 180:
        raise ValueError("Eight native 20-byte board records required")
    if not isinstance(images, tuple) or not all(
        isinstance(image, FirmwareImage) for image in images
    ):
        raise ValueError("Explicit tuple of parsed FirmwareImage objects required")
    roles = {image.role: image for image in images}
    if len(roles) != len(images) or set(roles) - {0, 1}:
        raise ValueError("Duplicate or invalid firmware role")
    for image in images:
        if parse_image(image.data) != image:
            raise ValueError("Firmware image metadata does not match bytes")
    records = []
    for index in range(8):
        raw = board_reply[20 + index * 20 : 40 + index * 20]
        kind = raw[0]
        if not kind:
            continue
        if kind not in range(1, 12):
            raise ValueError("Board kind absent from recovered firmware table")
        for role, image in sorted(roles.items()):
            present, fingerprint = (
                (raw[2], struct.unpack_from("<I", raw, 4)[0])
                if role == 0
                else (raw[3], struct.unpack_from("<I", raw, 8)[0])
            )
            if force or not present or fingerprint != image.fingerprint:
                records.append(UpdateRecord(1 << index, kind, image))
    return tuple(records)


def begin_body(record: UpdateRecord) -> bytes:
    if (
        not isinstance(record, UpdateRecord)
        or record.slot not in (1, 2, 4, 8, 16, 32, 64, 128)
        or record.board_kind not in range(1, 12)
        or not isinstance(record.image, FirmwareImage)
        or parse_image(record.image.data) != record.image
    ):
        raise ValueError("Invalid firmware update record")
    return (
        struct.pack("<III", 1, record.slot.bit_length(), len(record.image.data))
        + record.image.data[:HEADER_SIZE]
        + bytes(4)  # Native op1 sends four unwritten tail bytes; never leak memory.
    )


def chunk_body(slot: int, data: bytes) -> bytes:
    if (
        slot not in (1, 2, 4, 8, 16, 32, 64, 128)
        or not isinstance(data, bytes)
        or not 1 <= len(data) <= MAX_CHUNK
    ):
        raise ValueError("Invalid firmware slot/chunk")
    return struct.pack("<IIII", 2, slot.bit_length(), len(data), 0x5A000000) + data


class _Cancellation(threading.Event):
    """Owned-run predicate bridge for JLRClient's existing 50 ms read checks."""

    def __init__(self, previous: threading.Event | None, cancelled: Callable[[], bool]):
        super().__init__()
        self.previous, self.cancelled = previous, cancelled

    def is_set(self) -> bool:
        return (
            super().is_set()
            or (self.previous is not None and self.previous.is_set())
            or self.cancelled()
        )

    def set(self) -> None:
        super().set()
        if self.previous is not None:
            self.previous.set()

    def clear(self) -> None:
        super().clear()
        if self.previous is not None:
            self.previous.clear()


class FirmwareUpdater:
    """One-shot bounded executor over an explicitly owned, injected JLR client.

    reopen replaces a master device connection after a mode transition. It must
    return a new client; the caller owns discovery and transport construction.
    """

    def __init__(
        self,
        client: JLRClient,
        *,
        reopen: Callable[[], JLRClient] | None = None,
        cancelled: Callable[[], bool] | None = None,
        timeout: float = 300,
    ):
        if not math.isfinite(timeout) or not 0 < timeout <= 600:
            raise ValueError("Firmware timeout must be finite and in (0, 600] seconds")
        self.timeout = timeout
        self.deadline: float | None = None
        self.client, self.reopen = client, reopen
        self.cancelled = cancelled or (lambda: False)
        self.state = "new"
        self.acknowledged = 0
        self.attempted = False
        self.history: list[str] = []
        self._cancel_events: dict[JLRClient, threading.Event | None] = {}

    def _claim(self, client: JLRClient) -> None:
        if client.channel_owner is not None:
            raise RuntimeError("JLR device already has an owner")
        self._cancel_events[client] = client.cancel
        client.cancel = _Cancellation(client.cancel, self.cancelled)
        client.channel_owner = self

    def _release(self, client: JLRClient) -> None:
        if client.channel_owner is self:
            client.channel_owner = None
            client.cancel = self._cancel_events.pop(client)

    def _check(self) -> None:
        if self.cancelled():
            raise InterruptedError("Firmware update cancelled")
        if self.deadline is not None and time.monotonic() >= self.deadline:
            raise TimeoutError("Firmware update deadline exhausted")

    def _command(self, opcode: int, body: bytes = b"", *, reset: bool = False) -> bytes:
        self._check()
        self.attempted = True
        return self.client.transact(
            1,
            opcode,
            body,
            timeout=min(
                10, max(0, (self.deadline or time.monotonic()) - time.monotonic())
            ),
            accepted_statuses=(0, 7) if reset else (0,),
        )

    def _boards(self) -> bytes:
        reply = self._command(0x109)
        if len(reply) != 180:
            raise ValueError("Truncated firmware board reply")
        return reply

    def _reconnect(self) -> None:
        self._check()
        self.client.transport.close()
        if self.reopen is None:
            raise RuntimeError(
                "Master mode transition requires explicit reopen provider"
            )
        old = self.client
        new = self.reopen()
        if (
            not isinstance(new, JLRClient)
            or new is old
            or new.transport is old.transport
        ):
            raise ValueError(
                "Reopen provider must return a new JLR client and transport"
            )
        with new.io_lock:
            if new.channel_owner is not None:
                raise RuntimeError("Reopened device already has an owner")
            self._claim(new)
            self.client = new
        self._release(old)

    def run(
        self, images: tuple[FirmwareImage, ...], *, force: bool = False
    ) -> tuple[UpdateRecord, ...]:
        if self.state != "new":
            raise RuntimeError(
                "Firmware executor is terminal; automatic retry/resume forbidden"
            )
        # Validate every image before I/O, including when no boards need updates.
        plan(bytes(180), images, force=force)
        with self.client.io_lock:
            if self.state != "new":
                raise RuntimeError("Firmware executor already started")
            if self.client.channel_owner is not None:
                raise RuntimeError("JLR device already owned")
            self._claim(self.client)
            self.state = "running"
            self.deadline = time.monotonic() + self.timeout
            try:
                boards = self._boards()
                completed: list[UpdateRecord] = []
                for attempt in range(2):
                    self._check()
                    application = next(
                        (image for image in images if image.role == 1), None
                    )
                    if (
                        boards[21] != 1
                        and boards[23] == 1
                        and application is not None
                        and struct.unpack_from("<I", boards, 28)[0]
                        == application.fingerprint
                    ):
                        self._command(0x103, reset=True)
                        boards = self._boards()
                    another_pass = boards[21] != 1
                    records = plan(boards, images, force=force and attempt == 0)
                    if self.reopen is None and any(
                        record.slot == 1 or (record.image.role == 1 and boards[21] != 2)
                        for record in records
                    ):
                        raise ValueError(
                            "Firmware mode transition requires reopen provider"
                        )
                    for record in records:
                        self._check()
                        completed.append(record)
                        self.history.append(
                            f"slot-{record.slot}:role-{record.image.role}"
                        )
                        mode = boards[21]
                        if record.image.role == 1 and mode != 2:
                            self._command(0x102)
                            self._reconnect()
                            boards = self._boards()
                        elif record.image.role == 0 and mode != 1:
                            self._command(0x103, reset=True)
                            boards = self._boards()
                        board_offset = 20 + (record.slot.bit_length() - 1) * 20
                        if boards[board_offset] != record.board_kind:
                            raise ValueError(
                                "Board identity changed before firmware transfer"
                            )
                        if record.image.role == 0:
                            self._command(
                                0x10C,
                                struct.pack(
                                    "<III",
                                    record.slot.bit_length(),
                                    0x5A81C30E,
                                    0x5A000000,
                                ),
                            )
                        reply = self._command(0x10A, begin_body(record))
                        offset = HEADER_SIZE
                        self.acknowledged += HEADER_SIZE
                        for _ in range(MAX_IMAGE):
                            if len(reply) < 24:
                                raise ValueError("Truncated firmware next-size reply")
                            size = struct.unpack_from("<I", reply, 20)[0]
                            if not size:
                                if offset != len(record.image.data):
                                    raise ValueError(
                                        "Device ended firmware transfer early"
                                    )
                                break
                            if (
                                not 1
                                <= size
                                <= min(MAX_CHUNK, len(record.image.data) - offset)
                            ):
                                raise ValueError(
                                    "Device requested invalid firmware chunk extent"
                                )
                            reply = self._command(
                                0x10A,
                                chunk_body(
                                    record.slot,
                                    record.image.data[offset : offset + size],
                                ),
                            )
                            offset += size
                            self.acknowledged += size
                        else:
                            raise ValueError("Firmware transfer work budget exhausted")
                        if record.slot == 1 and record.image.role == 0:
                            self._reconnect()
                        boards = self._boards()
                        raw = boards[
                            20 + (record.slot.bit_length() - 1) * 20 : 40
                            + (record.slot.bit_length() - 1) * 20
                        ]
                        fingerprint = struct.unpack_from(
                            "<I", raw, 4 if record.image.role == 0 else 8
                        )[0]
                        present = raw[2 if record.image.role == 0 else 3]
                        if (
                            raw[0] != record.board_kind
                            or not present
                            or fingerprint != record.image.fingerprint
                        ):
                            raise ValueError(
                                "Post-transfer firmware identity not confirmed"
                            )
                    if not another_pass or attempt == 1:
                        break
                    boards = self._boards()
                self._check()
                self.state = "verified"
                return tuple(completed)
            except BaseException:
                self.state = "uncertain" if self.attempted else "cancelled"
                raise
            finally:
                original = sys.exception()
                try:
                    self.client.transport.close()
                except BaseException as cleanup:
                    self.state = "uncertain"
                    if original is None:
                        raise
                    original.add_note(
                        f"Firmware transport cleanup also failed: {cleanup}"
                    )
                finally:
                    self._release(self.client)
