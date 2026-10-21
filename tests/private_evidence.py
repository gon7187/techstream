"""Explicit skips for tests that require local private OEM evidence.

The public repository ships authored code and synthetic fixtures only. OEM
binaries, extracted applications, databases and research packets stay outside
the public tree, so tests that consume them must skip with a precise reason when
that corpus is absent instead of failing as if public code regressed.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from typing import Any

_PRIVATE_ROOTS = ("analysis", "artifacts", ".unlazy")


def _is_private(path: str | Path) -> bool:
    parts = Path(path).parts
    if any(root in parts for root in _PRIVATE_ROOTS):
        return True
    return "runtime" in parts and any(part.startswith("no-car-") for part in parts)


def require_private(*paths: str | Path) -> None:
    """Skip the current test when any required private path is absent."""
    missing = []
    for path in paths:
        if not _is_private(path):
            raise AssertionError(f"Not a private evidence path: {path}")
        if not Path(path).exists():
            missing.append(str(path))
    if missing:
        shown = ", ".join(missing[:3])
        if len(missing) > 3:
            shown += f", ... ({len(missing)} paths)"
        raise unittest.SkipTest(f"Private OEM evidence unavailable: {shown}")


def read_private_bytes(path: str | Path) -> bytes:
    require_private(path)
    return Path(path).read_bytes()


def read_private_text(path: str | Path, *, encoding: str = "utf-8") -> str:
    require_private(path)
    return Path(path).read_text(encoding=encoding)


def read_private_json(path: str | Path) -> Any:
    return json.loads(read_private_text(path))
