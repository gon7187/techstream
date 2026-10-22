"""Authored synthetic native-utility fixtures.

The recovered TY18 DCM45 and BSM controllers require the exact OEM caller and
engine images. This module composes the same real controllers over authored
bytes and an injected communication provider, so the public test suite and the
desktop smoke can drive them without OEM images.

The fixture deliberately bypasses the source-issued caller/engine pair check of
`scripts.script_libraries.NativeProcedureLibraries`. It must never be used to
replay a production procedure: `scripts.utility.open_native_utility` keeps that
check intact, and every fixture restores the global source registry when it is
closed.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import replace
from types import SimpleNamespace
from typing import Any, Self, cast

AUTHORED_CALLER_SHA256 = (
    "ecba533aeaa2ec2a014fa59a113d025a8efe90338767c2786b8a5a891ca0f599"
)
AUTHORED_MODULE_BYTES = b"authored native procedure integration fixture"
_FIXTURE_OWNERSHIP = threading.Lock()
DCM_UTILITY_GROUP = 0x1352
BSM_UTILITY_GROUP = 0x134A
DCM_TEXT_IDENTIFIERS = (
    0x948A,
    0x948B,
    0x948C,
    0x948D,
    0x948E,
    0x9490,
    0x9492,
)
DCM_COMMON_IDENTIFIERS = (0x102F, 0x1043, 0x104A, 0x104B)


class AuthoredNativeUtility:
    """Real native controller over authored bytes and an injected provider.

    The fixture owns the temporary source-registry entries it needs and
    releases them on `close()`. The retained `events` list records the exact
    communication chronology of the authored provider.
    """

    def __init__(
        self,
        *,
        initial: int = 0,
        clear: int = 0,
        fault: bool = False,
        hold: bool = False,
        dcm_value: int | None = None,
    ):
        from scripts import utility_ex_ty_body
        from scripts.script_libraries import NativeProcedureLibraries
        from scripts.utility import NativeUtilityRuntime
        from scripts.utility_ex import SOURCES, UtilityExContext, UtilityExEngine
        from scripts.utility_ex_ty import SHA_18_TY, TYEngine, load_contract

        if dcm_value is not None and (
            type(dcm_value) is not int or not 0 <= dcm_value <= 255
        ):
            raise ValueError("Authored DCM readback value must be one byte")
        data = AUTHORED_MODULE_BYTES
        digest = hashlib.sha256(data).hexdigest()
        contract = replace(
            load_contract(SHA_18_TY),
            source_sha256=digest,
            frames={
                **load_contract(SHA_18_TY).frames,
                "door_clear": b"\x80\x01\x02\x03",
            },
        )
        events: list[Any] = []
        cancel = threading.Event()
        entered = threading.Event()

        class Comm:
            def initialize(self, mode=0):
                events.append("initialize")
                return initial

            def configure(self, field, value):
                events.append((field, value))

            def session(self, mode, *args, **kwargs):
                events.append(("session", mode))
                return 0

            def exchange(self, request):
                events.append(request)
                if fault:
                    raise OSError("authored exchange fault")
                if dcm_value is not None:
                    return (
                        0,
                        b"\x6e\x20\x61"
                        if request == b"\x2e\x20\x61\x00"
                        else b"\x62\x20\x61" + bytes([dcm_value]),
                    )
                return clear, b"\xc0\x01\x02\x03"

            def finalize(self):
                events.append("finalize")

        def sleep(ms):
            events.append(("sleep", ms))
            if hold:
                entered.set()
                if not cancel.wait(2):
                    raise TimeoutError("authored worker was not cancelled")

        context = SimpleNamespace(
            module_bytes=data,
            module_sha256=digest,
            mode=20,
            state={},
            _cancel=cancel,
            _worker=None,
            is_cancelled=cancel.is_set,
            comm=lambda _: Comm(),
            sleep=sleep,
        )

        class Engine(UtilityExEngine):
            def _providers(self):
                if dcm_value is not None:
                    return [
                        (
                            utility_ex_ty_body,
                            utility_ex_ty_body.supported_exports(digest),
                        )
                    ]
                return [(TYEngine(contract), contract.exports)]

        engine = Engine(cast(UtilityExContext, context))
        libraries = object.__new__(NativeProcedureLibraries)
        # Source-shaped caller fixture: the constructor source rejection stays
        # covered by the production path in scripts.utility.open_native_utility.
        libraries.caller_sha256 = AUTHORED_CALLER_SHA256
        libraries.engine = engine

        if not _FIXTURE_OWNERSHIP.acquire(blocking=False):
            raise RuntimeError("An authored native utility fixture is already active")
        self._sources = SOURCES
        self._digest = digest
        self._had_source = digest in SOURCES
        self._previous_source = SOURCES.get(digest)
        self._body_module = utility_ex_ty_body
        self._previous_body_sha = utility_ex_ty_body.SHA_18_TY
        self._close_lock = threading.Lock()
        self.closed = False
        try:
            SOURCES[digest] = "TY18"
            if dcm_value is not None:
                utility_ex_ty_body.SHA_18_TY = digest
            self.runtime = NativeUtilityRuntime(libraries)
            self.events = events
            self.entered = entered
        except BaseException:
            self._restore_globals()
            _FIXTURE_OWNERSHIP.release()
            raise

    def _restore_globals(self) -> None:
        if self._had_source:
            self._sources[self._digest] = cast(str, self._previous_source)
        else:
            self._sources.pop(self._digest, None)
        self._body_module.SHA_18_TY = self._previous_body_sha

    def close(self) -> None:
        """Release the temporary source registry and the authored worker."""
        with self._close_lock:
            if self.closed:
                return
            worker = self.runtime.libraries.engine.worker
            try:
                if worker._thread is not None:
                    if self.runtime.done:
                        worker.stop()
                    else:
                        self.runtime.cancel()
                if worker._thread is not None:
                    raise RuntimeError("Authored native utility worker remains active")
            finally:
                if worker._thread is None:
                    self._restore_globals()
                    self.closed = True
                    _FIXTURE_OWNERSHIP.release()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exception) -> None:
        self.close()
