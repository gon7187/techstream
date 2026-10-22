"""CUW2026 41080 online key controller, driven by offline primitive captures.

No image execution, licensed service contact or credential substitution occurs here.
Browser approval is modal state only; the native SetReprogrammingKey input supplies
signature bytes. Historical12/18 callers retain their separate service contracts.
"""

from __future__ import annotations

import configparser
import hashlib
import json
import math
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import quote_plus

from scripts.cuw_2026 import (
    RKSAccess2026,
    decode_rks_configuration2026,
    import_repro_key_2026,
    rks_data_from_native,
)
from scripts.cuw_services import ServiceError, _cleanup
from scripts.service_replay import _Browser, _Chronology, _fields, _hex, _json, _object

if TYPE_CHECKING:
    from scripts.cuw_engine_worker import EngineWorker2026

ENGINE_SHA256 = "acc95323a291671294fef648be1642b675b59015078532aeabaee4872e551261"
SCHEMA = "techstream-online-controller-replay-v1"
_KEY_TOKEN = object()


@dataclass(frozen=True, repr=False)
class OnlineKey2026:
    value: bytes
    engine_sha256: str
    request_sha256: str
    capture_sha256: str
    _token: object = field(compare=False)

    def __post_init__(self) -> None:
        if self._token is not _KEY_TOKEN or len(self.value) not in (64, 256):
            raise TypeError("Online key must originate from the native controller")


def _configuration(source: bytes) -> dict[str, str]:
    """55490/1c420 decoding; private fields are never included in reports/repr."""
    if not isinstance(source, bytes) or not 0 < len(source) <= 1024 * 1024:
        raise ValueError("Bounded encoded RKS.ini required")
    # 5c7d0 consumes the decoded allocation as a NUL-terminated C string.
    decoded = decode_rks_configuration2026(source).split(b"\0", 1)[0]
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    try:
        parser.read_string(decoded.decode("latin1"))
        if parser.defaults():
            raise ValueError("Inherited RKS.ini defaults unsupported")
        section = parser["ReproKeyRequest"]
        names = (
            "IFVersion",
            "SoftwareID",
            "SoftwareVersion",
            "LicenseKey",
            "SUBARU_LicenseKey",
            "SUZUKI_LicenseKey",
            "DAIHATSU_LicenseKey",
            "VehicleIdentificationNumber",
            "RequesterKind",
            "KeypairID",
            "DAIHATSU_KeypairID",
        )
        values = {name: section[name] for name in names}
        if any(not value for value in values.values()):
            raise ValueError("All eleven native RKS.ini fields must be nonempty")
        return values
    except (configparser.Error, KeyError):
        raise ValueError("Incomplete or malformed source RKS.ini") from None


class NativeRKSConfiguration2026:
    """One54f50 singleton's55490 imports, shared by online and Ethernet users."""

    def __init__(self, engine):
        import struct

        from scripts.cuw_2026 import (
            _RKS_SOFTWARE_TOKEN,
            CUWEngine2026,
            RKSSoftwareIdentity2026,
        )

        if type(engine) is not CUWEngine2026 or engine.identity.sha256 != ENGINE_SHA256:
            raise TypeError("RKS store requires the authenticated native engine")
        self._engine = engine
        self._fields: dict[str, str] = dict.fromkeys(
            (
                "IFVersion",
                "SoftwareID",
                "SoftwareVersion",
                "LicenseKey",
                "SUBARU_LicenseKey",
                "SUZUKI_LicenseKey",
                "DAIHATSU_LicenseKey",
                "VehicleIdentificationNumber",
                "RequesterKind",
                "KeypairID",
                "DAIHATSU_KeypairID",
            ),
            "",
        )
        self._source_sha256 = engine.identity.sha256
        self._last_source_sha256: str | None = None
        self._configuration_sha256 = engine.identity.sha256
        self._loaded = False
        # 54f50 global initialization is known, including both adjacent zeroed SSOs.
        self._software_identity = RKSSoftwareIdentity2026(
            engine.identity.sha256,
            bytes(16) + struct.pack("<II", 0, 15) + bytes(40),
            _RKS_SOFTWARE_TOKEN,
        )

    @property
    def source_sha256(self) -> str:
        """Latest successful import; before any success, the native image source."""
        return self._source_sha256

    @property
    def configuration_sha256(self) -> str:
        """Replay binding includes retained strings when they differ from the file."""
        return self._configuration_sha256

    @property
    def last_source_sha256(self) -> str | None:
        """Last completed native import attempt, including nativeFalse failures."""
        return self._last_source_sha256

    @property
    def software_identity(self):
        return self._software_identity

    def fields_snapshot(self) -> dict[str, str]:
        return self._fields.copy()

    def load(self, source: bytes) -> bool:
        from scripts.cuw_2026 import rks_software_identity2026

        if not isinstance(source, bytes) or len(source) > 1024 * 1024:
            raise ValueError("Bounded encoded RKS.ini bytes required")
        source_sha256 = hashlib.sha256(source).hexdigest()
        try:
            candidate = _configuration(source)
        except ValueError:
            self._last_source_sha256 = source_sha256
            return False
        # A HOST failure has no native completion and must never suppress a retry.
        self._last_source_sha256 = source_sha256
        retained_differs = self._loaded and any(
            candidate[name] != self._fields[name]
            for name in ("SoftwareID", "SoftwareVersion")
        )
        if self._loaded:
            # 55490 assigns these two only while their native strings are empty.
            candidate["SoftwareID"] = self._fields["SoftwareID"]
            candidate["SoftwareVersion"] = self._fields["SoftwareVersion"]
        else:
            identity = rks_software_identity2026(source)
            self._software_identity = identity
        self._fields = candidate
        self._source_sha256 = self._last_source_sha256
        self._configuration_sha256 = (
            hashlib.sha256(_json(candidate)).hexdigest()
            if retained_differs
            else self._last_source_sha256
        )
        self._loaded = True
        return True


def _request_buffer(values: tuple[str, ...]) -> bytes:
    """41080 controller+251, wrapper58 eight inline ANSI C strings."""
    offsets = (0, 3, 38, 53, 100, 118, 120, 127, 160)
    output = bytearray(160)
    for value, start, stop in zip(values, offsets, offsets[1:], strict=False):
        encoded = value.encode("latin1")
        if b"\0" in encoded or len(encoded) >= stop - start:
            raise ValueError("RKS.ini value exceeds native inline field")
        output[start : start + len(encoded)] = encoded
    return bytes(output)


class OnlineKeyController2026:
    """53010/54e10/41080 state, with actual worker-issued engine context."""

    def __init__(self, worker: EngineWorker2026, encoded_rks_ini: bytes | None = None):
        from scripts.cuw_engine_worker import EngineWorker2026

        if type(worker) is not EngineWorker2026:
            raise TypeError("Concrete source-bound engine worker required")
        self.worker = worker
        store = worker.engine.rks_configuration
        if encoded_rks_ini is not None:
            if not isinstance(encoded_rks_ini, bytes):
                raise TypeError("Encoded RKS.ini bytes required")
            if hashlib.sha256(encoded_rks_ini).hexdigest() != store.last_source_sha256:
                worker.engine.load_rks_configuration(encoded_rks_ini)
        self._rks_store: NativeRKSConfiguration2026 | None = store
        self._config = store.fields_snapshot()
        self.configuration_sha256 = store.configuration_sha256
        self._request = b""
        self._key = b""
        self._result = 0  # controller+4
        self._modal_history: list[int] = []
        self._request_status = 0  # accessor+30
        self._watch_status = 0  # accessor+34
        self._started = False
        self._closed = False
        self._capture_sha256 = ""
        self._access: RKSAccess2026 | None = None
        self._exported_path: Path | None = None

    def rebind_worker(self, old: EngineWorker2026, new: EngineWorker2026) -> None:
        """59070 replaces its worker; engine-global438 and RKS/browser data survive."""
        from scripts.cuw_engine_worker import EngineWorker2026

        if type(old) is not EngineWorker2026 or type(new) is not EngineWorker2026:
            raise TypeError("Actual previous and replacement engine workers required")
        engine = old.engine
        if (
            self.worker is not old
            or old is new
            or new.engine is not engine
            or old.runtime is not new.runtime
            or old.controller is not new.controller
            or not old._closed
            or new._closed
            or engine.active
            or engine._worker is not new
            or getattr(new.controller, "worker", None) is not new
            or old._file_sources is not new._file_sources
            or old._all_loaded_metadata is not new._all_loaded_metadata
            or old._online_loaded_metadata is not new._online_loaded_metadata
            or self._rks_store is not engine.rks_configuration
        ):
            raise ValueError(
                "Actual stopped-worker online reissue transaction required"
            )
        new.validate_source(engine)
        if engine.worker is not new:
            raise ValueError("Replacement is not the engine's current issued worker")
        self.worker = new

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def modal_state(self) -> int:
        return self.worker.engine.online_modal_state

    @property
    def modal_history(self) -> tuple[int, ...]:
        return tuple(self._modal_history)

    @property
    def request_status(self) -> int:
        """643d0 GetStatusOfRequestReprogrammingKey@0, including inactive1b5a."""
        if self._closed or not self._started or self._result or self.modal_state == 0:
            return 0x1B5A
        return {
            1: 2,
            2: 1,
            3: 1,
            4: 3,
            5: 4,
            6: 0x1B63,
            7: 0x1B5C,
            8: 0x1B62,
            9: 0x1B5D,
            10: 0x1B5B,
        }.get(self.modal_state, 0x1B5A)

    @property
    def request_buffer(self) -> bytes:
        return self._request

    def validate_source(self) -> None:
        if self.worker.online_context().engine_sha256 != ENGINE_SHA256:
            raise ValueError("Online controller requires exact CUW2026 engine")
        if not self._started and not self._closed and self._rks_store is not None:
            # 41080 reads the singleton at request creation, not at53010 construction.
            self._config = self._rks_store.fields_snapshot()
            self.configuration_sha256 = self._rks_store.configuration_sha256

    def _set_modal(self, state: int) -> None:
        self.worker.engine._publish_online_modal(self, state)
        self._modal_history.append(state)

    def start(self, seed: bytes) -> None:
        self.validate_source()
        if self._started or self._closed:
            raise RuntimeError("Online controller is single use")
        context = self.worker.online_context()
        self._started = True
        if not context.vin:
            self._set_modal(6)
            return
        region = context.region
        # 4a6f0 scans all loaded FILES; the current ECU kind alone is insufficient.
        daihatsu = context.is_daihatsu
        license_name = (
            "DAIHATSU_LicenseKey"
            if daihatsu
            else "SUBARU_LicenseKey"
            if self.worker.engine.native_metadata.format_version == 9
            else "SUZUKI_LicenseKey"
            if region == 2
            else "LicenseKey"
        )
        seed_length = 8 if region == 2 else 16
        if not isinstance(seed, bytes) or len(seed) != seed_length:
            raise ValueError("Native online seed length differs from region")
        vin = context.vin.decode("latin1").ljust(17)
        config = self._config
        self._request = _request_buffer(
            (
                config["IFVersion"],
                config["SoftwareID"],
                config["SoftwareVersion"],
                config[license_name],
                vin,
                config["RequesterKind"],
                config["DAIHATSU_KeypairID" if region == 2 else "KeypairID"],
                seed.hex().upper(),
            )
        )
        self._set_modal(1)

    def _callback(self, kind: str) -> None:
        if kind == "watch":  # 415b0
            self._set_modal(
                4 if self._watch_status == 0 else 9 if self._watch_status == 13 else 10
            )
        elif kind == "request":  # 41600
            self._set_modal(7 if self._request_status == 3 else 9)
        elif kind == "cancel":  # 41640
            self._set_modal(1)
        else:
            raise ValueError("Unknown native modal callback")
        self._request_status = self._watch_status = 0

    def _native_input(self, key: bytes) -> None:
        """64a20 input primitive; no externally supplied key-success flag exists."""
        if not self._started or not self._request or self._closed or self._result:
            raise RuntimeError("No active native reprogramming-key destination")
        size = 128 if self.worker.online_context().region == 2 else 512
        if not isinstance(key, bytes) or len(key) > 4096:
            raise ValueError("Bounded native reprogramming-key C string required")
        key = key.split(b"\0", 1)[0]
        if len(key) != size:
            raise ValueError("Native reprogramming-key LengthError")
        if re.fullmatch(b"[0-9a-fA-F]+", key) is None:
            raise ValueError("Native reprogramming-key hex format error")
        self._key = bytes.fromhex(key.decode("ascii"))
        self._result = 1
        self._set_modal(0)

    def request_parameters(self) -> bytes | None:
        """64800 mode3 returns the two fixed ANSI fields and sets state5."""
        if not self._request or self._closed or self._result or self.modal_state == 6:
            return None
        self._set_modal(5)
        # strncpy_s33/7 preserves a terminator and zero padding.
        return self._request[127:160] + self._request[120:127]

    def query_string(self, utc_time: datetime, filetime_remainder: int) -> str:
        """53c30 UTC timestamp and27460 selective ANSI URL encoding."""
        if not self._request or self._closed or self._result:
            raise RuntimeError("No active native query destination")
        if (
            not isinstance(utc_time, datetime)
            or type(filetime_remainder) is not int
            or not 0 <= filetime_remainder < 10000
        ):
            raise ValueError(
                "Captured UTC SYSTEMTIME and submillisecond FILETIME required"
            )
        data = rks_data_from_native(self._request, encoding="latin1")
        timestamp = (
            utc_time.strftime("%Y.%m.%d.%H:%M:%S:")
            + f"{utc_time.microsecond // 1000:03d}{filetime_remainder:04d}"
        )

        def encoded(value: str) -> str:
            return quote_plus(value, safe="*-._!$@'(),", encoding="latin1").replace(
                "~", "%7E"
            )

        return (
            f"ver={data.x_version}&sid={data.software_id}"
            f"&sver={encoded(data.software_version)}&lkey={data.license_key}"
            f"&vin={encoded(data.vin)}&timestamp={encoded(timestamp)}"
            f"&rk={data.requester_kind}&kid={data.keypair_id}&sval={data.seed}"
        )

    def export_data(self, directory: str | Path, local_time: datetime) -> Path | None:
        """533c0/644f0 filename and wrapper5c; only an owned old export is removed."""
        if not self._request or self._closed or self._result:
            return None
        if not isinstance(local_time, datetime):
            raise TypeError("Captured native local calendar time required")
        if self._exported_path is not None:
            self._exported_path.unlink(missing_ok=True)
        vin = self._request[100:118].split(b"\0", 1)[0].decode("latin1")
        if "/" in vin or "\\" in vin or vin in (".", ".."):
            raise ValueError("VIN cannot form a host path component")
        path = Path(directory) / (
            vin + "_" + local_time.strftime("%Y%m%d%H%M%S") + ".xml"
        )
        access = self._access
        if access is None:
            access = RKSAccess2026()
            access.set_data(rks_data_from_native(self._request, encoding="latin1"))
        access.export_data(path)
        self._exported_path = path
        self._set_modal(4)
        return path

    def _import_xml(self, data: bytes) -> None:
        """3a650/wrapper64 supplies a512-character signature even for region2."""
        if not self._request or self._closed or self._result:
            raise RuntimeError("No active native XML-key destination")
        self._key = b""
        key = import_repro_key_2026(
            data, source="captured:LoadXMLFileForReprogrammingKey"
        )
        if re.fullmatch("[0-9a-fA-F]+", key.value) is None:
            raise ValueError("Native CBytes signature hex format error")
        size = 64 if self.worker.online_context().region == 2 else 256
        self._key = bytes.fromhex(key.value)[:size]
        self._result = 1
        self._set_modal(0)

    def calculate(
        self,
        seed: bytes,
        chronology: OnlineReplay2026,
        *,
        timeout: float = 300,
        cancelled: Callable[[], bool] = lambda: False,
        clock: Callable[[], float] = time.monotonic,
    ) -> OnlineKey2026 | None:
        if type(chronology) is not OnlineReplay2026:
            raise TypeError("Concrete primitive chronology required")
        return chronology.run(
            self, seed, timeout=timeout, cancelled=cancelled, clock=clock
        )

    def close(self) -> None:
        try:
            if self._access is not None:
                self._access.close()
        finally:
            self._closed = True
            self._key = b""
            self._request = b""
            self._config.clear()
        self._access = None


class _OnlineChronology(_Chronology):
    """Do not let native error mapping conceal a host capture mismatch in cleanup."""

    invalid: ValueError | None = None

    def call(
        self, method: str, args: Any, *, timeout: float, cleanup: bool = False
    ) -> Any:
        try:
            return super().call(method, args, timeout=timeout, cleanup=cleanup)
        except ValueError as error:
            self.invalid = error
            raise


class OnlineReplay2026:
    """Strict browser primitives plus recorded native64a20 input, without network."""

    def __init__(self, capture: dict[str, Any]):
        raw = _json(capture)
        if len(raw) > 8 * 1024 * 1024:
            raise ValueError("Online capture byte budget exceeded")
        data = json.loads(raw, object_pairs_hook=_object)
        _fields(
            data,
            {
                "schema",
                "provenance",
                "engine_sha256",
                "configuration_sha256",
                "source_sha256",
                "seed_sha256",
                "steps",
            },
        )
        if data["schema"] != SCHEMA or data["provenance"] not in (
            "authored",
            "captured",
        ):
            raise ValueError("Unknown online primitive capture")
        if data["engine_sha256"] != ENGINE_SHA256:
            raise ValueError("Exact native online engine identity required")
        for name in ("configuration_sha256", "source_sha256", "seed_sha256"):
            if (
                not isinstance(data[name], str)
                or re.fullmatch("[0-9a-f]{64}", data[name]) is None
            ):
                raise ValueError("Online capture binding digest required")
        if not isinstance(data["steps"], list) or not 1 <= len(data["steps"]) <= 20000:
            raise ValueError("Online primitive step budget exceeded")
        elapsed = 0.0
        for step in data["steps"]:
            _fields(step, {"method", "args", "result", "fault", "elapsed_ms"})
            milliseconds = step["elapsed_ms"]
            if (
                type(milliseconds) not in (int, float)
                or not math.isfinite(milliseconds)
                or milliseconds < 0
            ):
                raise ValueError("Bounded native primitive timing required")
            elapsed += milliseconds
            if elapsed > 600000 or step["fault"] not in (
                None,
                "io",
                "timeout",
                "cancel",
            ):
                raise ValueError("Online primitive budget/fault invalid")
        self._data = data
        self.sha256 = hashlib.sha256(raw).hexdigest()
        self.used = False
        self._chronology: _Chronology | None = None

    @property
    def consumed_elapsed_seconds(self) -> float:
        return 0.0 if self._chronology is None else self._chronology.elapsed_ms / 1000

    @classmethod
    def from_path(cls, path: str | Path) -> OnlineReplay2026:
        from scripts.local_files import read_regular

        raw = read_regular(path, limit=8 * 1024 * 1024)
        return cls(json.loads(raw, object_pairs_hook=_object))

    def run(
        self,
        controller: OnlineKeyController2026,
        seed: bytes,
        *,
        timeout: float = 300,
        cancelled: Callable[[], bool] = lambda: False,
        clock: Callable[[], float] = time.monotonic,
    ) -> OnlineKey2026 | None:
        if self.used or not math.isfinite(timeout) or not 0 < timeout <= 600:
            raise ValueError("Fresh online capture and bounded deadline required")
        controller.validate_source()
        context = controller.worker.online_context()
        data = self._data
        if (
            data["source_sha256"] != context.source_sha256
            or data["configuration_sha256"] != controller.configuration_sha256
            or data["seed_sha256"] != hashlib.sha256(seed).hexdigest()
        ):
            raise ValueError("Online primitive capture source/seed binding mismatch")
        self.used = True
        started = clock()
        chronology = _OnlineChronology(
            data["steps"], started + timeout, cancelled, clock, started=started
        )
        self._chronology = chronology
        access = RKSAccess2026(
            _Browser(chronology),
            cancelled=cancelled,
            timeout=timeout,
            clock=chronology.clock,
        )
        controller._access = access
        controller._capture_sha256 = self.sha256
        error: BaseException | None = None
        try:
            controller.start(seed)
            if controller.request_buffer:
                access.set_data(
                    rks_data_from_native(controller.request_buffer, encoding="latin1")
                )
            while chronology.index < len(chronology.steps):
                chronology.check()
                method = chronology.steps[chronology.index]["method"]
                if method == "online.request":
                    args = chronology.call(method, {}, timeout=timeout)
                    _fields(args, {"url", "allowed_origins"})
                    opened = chronology.call(
                        "registry.open",
                        {
                            "root": "HKLM",
                            "key": r"SOFTWARE\Microsoft\Internet Explorer",
                            "access": 0x20019,
                        },
                        timeout=timeout,
                    )
                    if type(opened) is not int or not 0 <= opened <= 0xFFFFFFFF:
                        raise ValueError("Captured native registry status required")
                    if opened != 0:
                        controller._set_modal(7)
                        continue
                    try:
                        version = chronology.call(
                            "registry.read", {"name": "svcVersion"}, timeout=timeout
                        )
                        if not isinstance(version, str) or len(version) > 4096:
                            raise ValueError(
                                "Captured native browser version text required"
                            )
                        match = re.match(r"[ \t\n\r\v\f]*([+-]?[0-9]+)", version)
                        if match is None:
                            raise ValueError(
                                "Native browser version stol invalid argument"
                            )
                        number = int(match[1])
                        if not -(2**31) <= number < 2**31:
                            raise ValueError("Native browser version stol out of range")
                    finally:
                        if (
                            chronology.call(
                                "registry.close", {}, timeout=5, cleanup=True
                            )
                            is not None
                        ):
                            raise ValueError("Native registry close must return null")
                    if (number & 0xFFFFFFFF) <= 10:
                        controller._set_modal(7)
                        continue
                    controller._set_modal(2)
                    try:
                        access.request(
                            args["url"], allowed_origins=tuple(args["allowed_origins"])
                        )
                    except ServiceError as native_error:
                        controller._request_status = native_error.status
                        controller._callback("request")
                elif method == "online.watch":
                    chronology.call(method, {}, timeout=timeout)
                    try:
                        controller._watch_status = access.watch().native_status
                    except ServiceError as native_error:
                        controller._watch_status = native_error.status
                    # 54cf0 repeats ONLY status11;12 and13 must reach415b0.
                    if controller._watch_status != 11:
                        controller._callback("watch")
                elif method == "online.SetReprogrammingKey":
                    key = _hex(chronology.call(method, {}, timeout=timeout))
                    controller._native_input(key)
                elif method == "online.start_query":
                    values = chronology.call(method, {}, timeout=timeout)
                    _fields(values, {"url", "utc_time", "filetime_remainder"})
                    utc_time = datetime.fromisoformat(values["utc_time"])
                    query = controller.query_string(
                        utc_time, values["filetime_remainder"]
                    )
                    native_result = chronology.call(
                        "shell.open", {"url": values["url"] + query}, timeout=timeout
                    )
                    if (
                        type(native_result) is not int
                        or not -(2**31) <= native_result < 2**31
                    ):
                        raise ValueError("Captured native ShellExecute result required")
                    controller._set_modal(5 if native_result > 32 else 8)
                elif method == "online.LoadXMLFileForReprogrammingKey":
                    controller._import_xml(
                        _hex(chronology.call(method, {}, timeout=timeout))
                    )
                elif method == "online.request_parameters":
                    expected = _hex(chronology.call(method, {}, timeout=timeout))
                    if controller.request_parameters() != expected:
                        raise ValueError("Native request-parameter capture mismatch")
                elif method == "online.cancel":
                    chronology.call(method, {}, timeout=timeout)
                    if controller.modal_state in (2, 3):
                        controller._callback("cancel")
                    else:
                        controller._result = 3
                        break
                elif method == "online.finish":
                    chronology.call(method, {}, timeout=timeout)
                    break
                else:
                    raise ValueError("Expected captured native online operation")
            if controller._result != 1:
                return None
            return OnlineKey2026(
                controller._key,
                ENGINE_SHA256,
                hashlib.sha256(controller.request_buffer).hexdigest(),
                self.sha256,
                _KEY_TOKEN,
            )
        except BaseException as caught:
            if isinstance(caught, InterruptedError):
                controller._callback("cancel")
            error = caught
            raise
        finally:
            _cleanup(controller.close, error)
            if error is None and chronology.invalid is not None:
                raise ValueError(
                    "Online primitive capture mismatch during cleanup"
                ) from chronology.invalid
            if error is None and chronology.index != len(chronology.steps):
                raise ValueError("Unconsumed online primitive chronology")
