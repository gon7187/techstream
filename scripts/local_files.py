"""Bounded reads of regular Linux files, without opening a device or FIFO."""

from __future__ import annotations

import os
import stat
from pathlib import Path


def read_regular(path: str | Path, *, limit: int) -> bytes:
    if type(limit) is not int or limit < 0:
        raise ValueError("File byte limit must be a nonnegative integer")
    # O_PATH pins the inode without running a device's open operation.
    probe = os.open(path, os.O_PATH | os.O_CLOEXEC)
    try:
        info = os.fstat(probe)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("Input must be a regular file")
        if info.st_size > limit:
            raise ValueError(f"Input file exceeds {limit} bytes")
        with open(f"/proc/self/fd/{probe}", "rb") as source:
            data = source.read(limit + 1)
        if len(data) > limit:
            raise ValueError(f"Input file exceeds {limit} bytes")
        return data
    finally:
        os.close(probe)
