"""Bounded virtual uint32 pointers; never dereference a process address."""

from __future__ import annotations

import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass

MAX_SIZE = 16 * 1024 * 1024
_address_lock = threading.Lock()
_next_address = 0x10000


def _uint32(value: int) -> int:
    if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
        raise ValueError("Virtual native address/length must fit uint32")
    return value


def _reserve(size: int) -> int:
    global _next_address
    with _address_lock:
        address = _next_address
        following = (address + size + 31) & ~15
        if following > 0xFFFFFFFF:
            raise MemoryError("Virtual native uint32 address space exhausted")
        # shortcut: lifetime reservations stop at 4 GiB; use generation handles if exhausted.
        # Never reuse a logical address: stale and cross-arena pointers stay invalid.
        _next_address = following
        return address


@dataclass
class _Block:
    data: bytearray
    pins: int = 0


class NativeMemoryArena:
    """One source/owner-bound allocation domain, shared by its native consumers.

    Allocation bytes and count are bounded. realloc moves on success and retains
    the old allocation on failure. Freed addresses are never reused. The Python
    bytearray lease pins a complete allocation and prevents its resizing.
    """

    def __init__(
        self,
        source_sha256: str,
        owner: object,
        *,
        limit: int = MAX_SIZE,
        cancelled: Callable[[], bool] | None = None,
    ):
        if (
            type(source_sha256) is not str
            or len(source_sha256) != 64
            or any(c not in "0123456789abcdef" for c in source_sha256)
        ):
            raise ValueError("Exact lowercase native source SHA256 required")
        if owner is None:
            raise ValueError("Explicit native memory owner required")
        if type(limit) is not int or not 1 <= limit <= MAX_SIZE:
            raise ValueError("Native arena budget must be between 1 byte and 16 MiB")
        self._source_sha256, self._owner = source_sha256, owner
        self._limit, self.cancelled = limit, cancelled
        self._blocks: dict[int, _Block] = {}
        self._used = 0
        self._closed = False
        self._lock = threading.RLock()

    @property
    def source_sha256(self) -> str:
        return self._source_sha256

    @property
    def owner(self) -> object:
        return self._owner

    @property
    def limit(self) -> int:
        return self._limit

    def _check(self, *, cleanup: bool = False) -> None:
        if self._closed:
            raise ValueError("Native arena is closed")
        if not cleanup and self.cancelled is not None and self.cancelled():
            raise InterruptedError("Native memory operation cancelled")

    def assert_owner(self, source_sha256: str, owner: object) -> None:
        with self._lock:
            self._check(cleanup=True)
            if self.source_sha256 != source_sha256 or self.owner is not owner:
                raise ValueError("Native memory source/owner does not match consumer")

    def _base(self, address: int) -> _Block:
        block = self._blocks.get(_uint32(address))
        if block is None:
            raise ValueError("Unknown, freed or non-base native allocation")
        return block

    def _span(self, address: int, size: int) -> tuple[_Block, int]:
        address, size = _uint32(address), _uint32(size)
        if not address or address + size > 0x100000000:
            raise ValueError("Null or overflowing native span")
        for base, block in self._blocks.items():
            offset = address - base
            if 0 <= offset <= len(block.data) and size <= len(block.data) - offset:
                return block, offset
        raise ValueError("Native span exceeds its live allocation")

    def _allocate(self, size: int, *, replacing: int = 0) -> int:
        size = _uint32(size)
        if not size:
            raise ValueError("Native allocation requires a positive size")
        if self._used - replacing + size > self.limit or (
            not replacing and len(self._blocks) >= 4096
        ):
            raise MemoryError("Native arena allocation budget exceeded")
        data = bytearray(size)
        address = _reserve(size)
        self._blocks[address] = _Block(data)
        self._used += size
        return address

    def alloc(self, size: int) -> int:
        with self._lock:
            self._check()
            return self._allocate(size)

    def realloc(self, address: int, size: int) -> int:
        with self._lock:
            self._check()
            address, size = _uint32(address), _uint32(size)
            if not address:
                return self._allocate(size)
            old = self._base(address)
            if old.pins:
                raise BufferError("Borrowed native allocation cannot be reallocated")
            if not size:
                self.free(address)
                return 0
            result = self._allocate(size, replacing=len(old.data))
            try:
                new = self._blocks[result].data
                length = min(len(old.data), size)
                new[:length] = old.data[:length]
                self.free(address)
            except BaseException:
                del self._blocks[result]
                self._used -= size
                raise
            return result

    def free(self, address: int) -> None:
        with self._lock:
            self._check(cleanup=True)
            if not _uint32(address):
                return
            block = self._base(address)
            if block.pins:
                raise BufferError("Borrowed native allocation cannot be freed")
            block.data[:] = bytes(len(block.data))
            self._used -= len(block.data)
            del self._blocks[address]

    def read(self, address: int, size: int) -> bytes:
        with self._lock:
            self._check()
            block, offset = self._span(address, size)
            return bytes(block.data[offset : offset + size])

    def write(self, address: int, data: bytes) -> None:
        if type(data) is not bytes:
            raise TypeError("Immutable bytes required for native memory write")
        with self._lock:
            self._check()
            block, offset = self._span(address, len(data))
            block.data[offset : offset + len(data)] = data

    @contextmanager
    def borrow(self, address: int) -> Iterator[bytearray]:
        with self._lock:
            self._check()
            block = self._base(address)
            guard = memoryview(block.data)
            block.pins += 1
        try:
            yield block.data
        finally:
            with self._lock:
                guard.release()
                block.pins -= 1

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            if any(block.pins for block in self._blocks.values()):
                raise BufferError("Native arena still has borrowed allocations")
            for block in self._blocks.values():
                block.data[:] = bytes(len(block.data))
            self._blocks.clear()
            self._used = 0
            self._closed = True
