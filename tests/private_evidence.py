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
_REPO_ROOT = Path(__file__).resolve().parents[1]


def _canonical_path(path: str | Path) -> Path:
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = _REPO_ROOT / candidate
    return candidate.resolve()


def _is_private(path: str | Path) -> bool:
    candidate = _canonical_path(path)
    repo_root = _REPO_ROOT.resolve()
    try:
        parts = candidate.relative_to(repo_root).parts
    except ValueError:
        return False
    if parts and parts[0] in _PRIVATE_ROOTS:
        return True
    return (
        len(parts) >= 2
        and parts[0] == "runtime"
        and parts[1].startswith("no-car-")
        and len(parts[1]) > len("no-car-")
    )


def require_private(*paths: str | Path) -> None:
    """Skip the current test when any required private path is absent."""
    missing = []
    for path in paths:
        candidate = _canonical_path(path)
        if not _is_private(candidate):
            raise AssertionError(f"Not a private evidence path: {path}")
        if not candidate.exists():
            missing.append(str(path))
    if missing:
        shown = ", ".join(missing[:3])
        if len(missing) > 3:
            shown += f", ... ({len(missing)} paths)"
        raise unittest.SkipTest(f"Private OEM evidence unavailable: {shown}")


def read_private_bytes(path: str | Path) -> bytes:
    candidate = _canonical_path(path)
    require_private(candidate)
    return candidate.read_bytes()


def read_private_text(path: str | Path, *, encoding: str = "utf-8") -> str:
    candidate = _canonical_path(path)
    require_private(candidate)
    return candidate.read_text(encoding=encoding)


def read_private_json(path: str | Path) -> Any:
    return json.loads(read_private_text(path))
