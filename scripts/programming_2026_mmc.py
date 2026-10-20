"""Source-bound CUW2026 MMC exports over injected native CAN primitives."""

from __future__ import annotations

import hashlib
import re
import struct
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from scripts.calibration import CalibrationContainer
from scripts.calibration_2026 import (
    native2026_archive,
    native2026_header_info,
)
from scripts.j2534_2026 import (
    NativeCommunicationAddress,
    communication_addresses_from_parameter,
)
from scripts.native_modules import NativeModuleIdentity, identify_native_module
from scripts.programming import NativeTransportError
from scripts.programming_2026_common import (
    CanDiag2026,
    CommonResponseError,
    NativeJ2534Exception2026,
    NativeParameterBinding2026,
    NativePassThruException2026,
    NativeRuntime2026,
    is_native_exception2026,
)
from scripts.programming_vendor import VendorSegment, mmc_segments

if TYPE_CHECKING:
    from scripts.cuw_2026 import CUWEngine2026

_MODULES = {
    "TCUWCanMMCCIDGetter.dll": "get_cid",
    "TCUWCanMMCPrepareWriter.dll": "prepare",
    "TCUWCanMMCFlashWriter.dll": "write",
}


def _uint(value, maximum=0xFFFFFFFF) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError("Bounded native unsigned value required")
    return value


def _number(binding, name):
    text = binding.value(name) or "0"
    if not text.isascii() or not text.isdecimal():
        raise ValueError("Unsigned decimal native parameter required")
    return _uint(int(text))


@dataclass(frozen=True)
class MMC2026Context:
    identity: NativeModuleIdentity
    selection: NativeParameterBinding2026 = field(repr=False)
    addresses: tuple[NativeCommunicationAddress, ...]
    loader: tuple[VendorSegment, ...] = field(default=(), repr=False)
    image: tuple[VendorSegment, ...] = field(default=(), repr=False)
    loader_selector: int = 0
    image_selector: int = 0
    loader_routine: bytes = b""
    erase_areas: tuple[tuple[int, int], ...] = ()
    prepare_engine: bytes = field(default=b"", repr=False)
    native_pending_timeout_ms: int = 5000
    native_error_kind: int = 0
    native_driver_error_code: int = 0
    native_writing: bool = False

    @property
    def stage(self):
        return _MODULES[self.identity.module_name]

    def __post_init__(self):
        if (
            not isinstance(self.identity, NativeModuleIdentity)
            or self.identity
            != identify_native_module(self.identity.sha256, self.identity.module_name)
            or self.identity.cuw_build != "2026"
            or self.identity.module_name not in _MODULES
            or not isinstance(self.selection, NativeParameterBinding2026)
            or self.selection.operation != self.stage
            or self.selection.module_name != self.identity.module_name
            or type(self.addresses) is not tuple
            or not self.addresses
            or any(
                not isinstance(a, NativeCommunicationAddress)
                or len(a.request) != 2
                or len(a.response) != 2
                for a in self.addresses
            )
            or type(self.native_writing) is not bool
        ):
            raise ValueError(
                "Exact2026 MMC identity, parameter and two-byte addresses required"
            )
        if self.stage == "write" and self.selection.metadata.cpu_index >= len(
            self.addresses
        ):
            raise ValueError("Selected MMC CPU address absent")
        if len(self.addresses) > 256:
            raise ValueError("MMC address count exceeds host bound")
        _uint(self.native_pending_timeout_ms)
        _uint(self.native_error_kind)
        _uint(self.native_driver_error_code)
        if self.stage == "write":
            for segments in (self.loader, self.image):
                if (
                    type(segments) is not tuple
                    or len(segments) > 4096
                    or any(
                        not isinstance(s, VendorSegment) or len(s.checksum) != 2
                        for s in segments
                    )
                ):
                    raise ValueError("Bounded native MMC encoded segments required")
            _uint(self.loader_selector, 255)
            _uint(self.image_selector, 255)
            if type(self.loader_routine) is not bytes or len(self.loader_routine) != 4:
                raise ValueError("Four-byte imported loader start address required")
            for address, size in self.erase_areas:
                _uint(address)
                _uint(size)
                if not size or address + size > 1 << 32:
                    raise ValueError("Native erase range overflow")
        if self.stage == "prepare":
            security_tables(self.prepare_engine)


def bind_native_context(
    container: CalibrationContainer,
    node: int,
    observed_cids: tuple[str, ...],
    selection: NativeParameterBinding2026,
    identity: NativeModuleIdentity,
    attachments: Mapping[str, bytes],
    observations: Mapping,
) -> MMC2026Context:
    """Actual31 selected row → actual47 CPU/archive → actual48 address producer."""
    if (
        not isinstance(selection, NativeParameterBinding2026)
        or not isinstance(identity, NativeModuleIdentity)
        or identity.module_name not in _MODULES
        or not isinstance(attachments, Mapping)
        or set(attachments) - {"prepare_engine"}
        or not isinstance(observations, Mapping)
        or set(observations)
        - {
            "cpu_index",
            "previous_addresses",
            "response_canids",
            "native_pending_timeout_ms",
            "native_error_kind",
            "native_driver_error_code",
            "native_writing",
        }
        or type(observed_cids) is not tuple
    ):
        raise ValueError(
            "Actual imported MMC metadata and explicit native observations required"
        )
    cpu_index = observations.get("cpu_index", 0)
    selection.validate_against(
        container,
        operation=_MODULES[identity.module_name],
        node=node,
        cpu_index=cpu_index,
    )
    # validate_against reproduces the exact immutable catalog and parser state.
    metadata = selection.metadata
    resolver = communication_addresses_from_parameter(
        container,
        selection.parameter,
        response_canids=observations.get("response_canids"),
        history=list(observations.get("previous_addresses", ())),
    )
    success, addresses = resolver.resolve(
        selection.selector_functions,
        cids=observed_cids,
        location_id=metadata.cpu.values.get("locationid", ""),
    )
    if not success:
        raise ValueError("Native MMC address selector did not resolve")
    values: dict[str, Any] = {}
    if selection.operation == "write":

        def hexadecimal(text, width):
            if (
                not text
                or len(text) > width * 2
                or any(c not in "0123456789abcdefABCDEF" for c in text)
            ):
                raise ValueError(
                    "Native MMC header hexadecimal field missing or malformed"
                )
            return int(text, 16)

        loader = metadata.cpu.headers["flash_code"]
        image = metadata.cpu.headers["image"]
        loader_data = native2026_archive(metadata, flash_code=True).data
        image_data = native2026_archive(metadata).data
        values = {
            "loader": mmc_segments(loader_data) if loader_data else (),
            "image": mmc_segments(image_data) if image_data else (),
            "loader_selector": hexadecimal(loader.get("dataformatid", ""), 1),
            "image_selector": hexadecimal(image.get("dataformatid", ""), 1),
            "loader_routine": hexadecimal(
                loader.get("01_startaddress", ""), 4
            ).to_bytes(4, "big"),
            "erase_areas": native2026_header_info(metadata, "image").numeric_areas(),
        }
    if selection.operation != "prepare" and attachments:
        raise ValueError("MMC engine attachment applies only to preparation")
    return MMC2026Context(
        identity,
        selection,
        addresses,
        prepare_engine=attachments.get("prepare_engine", b""),
        native_pending_timeout_ms=observations.get("native_pending_timeout_ms", 5000),
        native_error_kind=observations.get("native_error_kind", 0),
        native_driver_error_code=observations.get("native_driver_error_code", 0),
        native_writing=observations.get("native_writing", False),
        **values,
    )


def security_tables(
    engine: bytes,
) -> tuple[tuple[tuple[int, ...], tuple[int, ...]], ...]:
    """Recover immediate CBytes initializer words; no PE code is executed.

    Only the registered reconstructed2026 preparation image is accepted. OEM
    security tables remain in the caller's private input rather than this source.
    """
    if type(engine) is not bytes or not 64 <= len(engine) <= 16 * 1024 * 1024:
        raise ValueError("Exact recovered MMC preparation PE bytes required")
    identity = identify_native_module(
        hashlib.sha256(engine).hexdigest(), "TCUWCanMMCPrepareWriter.dll"
    )
    if (
        identity.cuw_build != "2026"
        or identity.artifact_form != "reconstructed-inspection"
    ):
        raise ValueError("Exact recovered2026 MMC preparation identity required")
    pe = struct.unpack_from("<I", engine, 60)[0]
    sections = struct.unpack_from("<H", engine, pe + 6)[0]
    optional_size = struct.unpack_from("<H", engine, pe + 20)[0]
    base = struct.unpack_from("<I", engine, pe + 24 + 28)[0]

    def code(rva, length):
        for index in range(sections):
            size, start, raw_size, offset = struct.unpack_from(
                "<IIII", engine, pe + 24 + optional_size + index * 40 + 8
            )
            if start <= rva and rva + length <= start + min(size, raw_size):
                return engine[offset + rva - start : offset + rva - start + length]
        raise ValueError("MMC initializer lies outside recovered PE code")

    words = {}
    for rva, end in (
        (0x1000, 0x1170),
        (0x1170, 0x21C0),
        (0x21C0, 0x2330),
        (0x2330, 0x3380),
    ):
        data = code(rva, end - rva)
        # Compiler emits the first argument pair in reverse order to subsequent pairs.
        for match in re.finditer(
            rb"\xb9(.{4})\x68(.{4})\xff\xd6|\x68(.{4})\xb9(.{4})", data, re.DOTALL
        ):
            first, second, third, fourth = match.groups()
            address, value = (first, second) if first is not None else (fourth, third)
            words[struct.unpack("<I", address)[0]] = struct.unpack("<I", value)[0]
    result = []
    for p, s in ((0x4A960, 0x4F1F0), (0x8F9F0, 0xA160)):
        try:
            result.append(
                (
                    tuple(words[base + p + i * 0x408] for i in range(18)),
                    tuple(words[base + s + i * 0x408] for i in range(256)),
                )
            )
        except KeyError as error:
            raise ValueError(
                "Incomplete source-bound MMC security initializers"
            ) from error
    return tuple(result)


def mmc_key(seed: bytes, p: tuple[int, ...], s: tuple[int, ...]) -> bytes:
    """2026 RVA3380: one shared256-entry S table, uint32 wrapping each round."""
    if (
        type(seed) is not bytes
        or len(seed) != 8
        or type(p) is not tuple
        or len(p) != 18
        or type(s) is not tuple
        or len(s) != 256
    ):
        raise ValueError("MMC eight-byte seed and18/256 native key words required")
    for value in p + s:
        _uint(value)
    left, right = struct.unpack(">II", seed)
    for value in p[:16]:
        mixed = left ^ value
        left = (
            (
                ((s[mixed >> 24] + s[mixed >> 16 & 255]) ^ s[mixed >> 8 & 255])
                + s[mixed & 255]
            )
            ^ right
        ) & 0xFFFFFFFF
        right = mixed
    return struct.pack(">II", right ^ p[17], left ^ p[16])


def run_native(
    context: MMC2026Context,
    runtime: NativeRuntime2026,
    *,
    preparation_state: Callable[[], int] | None = None,
    engine: CUWEngine2026 | None = None,
    notify: Callable[[dict], None] = lambda _: None,
) -> dict:
    """Execute one native export; provider callbacks perform only CAN/J2534 I/O."""
    if (
        not isinstance(context, MMC2026Context)
        or not isinstance(runtime, NativeRuntime2026)
        or not callable(notify)
    ):
        raise TypeError("Bound MMC context, native runtime and observer required")
    if context.stage == "prepare" and not callable(preparation_state):
        raise TypeError("Explicit native UI preparation-state observation required")
    if engine is not None:
        from scripts.cuw_2026 import CUWEngine2026

        if type(engine) is not CUWEngine2026 or context.stage != "get_cid":
            raise TypeError("Concrete CUW2026 engine is only valid for MMC getter")
        engine._require_owned_phase()
        if (
            engine.worker_phase != 0
            or engine.native_metadata.source_sha256
            != context.selection.metadata.source_sha256
        ):
            raise ValueError("Actual matching GetCID engine phase required")
    rt, diag = runtime, CanDiag2026(runtime)
    target = context.addresses[
        context.selection.metadata.cpu_index if context.stage == "write" else 0
    ]
    request, response = b"\0\0" + target.request, b"\0\0" + target.response
    result: dict = {
        "family": "MMC",
        "stage": context.stage,
        "state": "running",
        "physical_status": "PHYSICAL_UNCONFIRMED",
        "source_sha256": context.identity.sha256,
        "calibration_sha256": context.selection.metadata.source_sha256,
        "parameter_sha256": context.selection.source_sha256,
        "node": context.selection.metadata.node,
        "cpu_index": context.selection.metadata.cpu_index,
        "error_kind": context.native_error_kind,
        "error_code": context.native_driver_error_code,
        "native_error_code": context.native_error_kind,
        "driver_error_code": context.native_driver_error_code,
        "writing": context.native_writing,
        "count": 0,
        "percent": 0,
        "history": [],
        "native_return": None,
        "native_success": None,
    }
    if context.stage == "get_cid":
        # StartGetCID1de0 clears its result vector even if either query fails.
        result["identifiers"] = []
    pending = 5000 if context.stage == "prepare" else context.native_pending_timeout_ms
    filters = []
    periodic_owned = False
    native_value = False
    native_cleanup_unknown = False
    prepare_handler_active = False

    def call(payload, expected, error, minimum=None, seconds=10):
        rt.check()
        result["history"].append(
            "2742:redacted" if payload.startswith(b"\x27\x42") else payload.hex()
        )
        return diag.call(
            request,
            response,
            payload,
            expected,
            minimum=len(expected) if minimum is None else minimum,
            error_code=error,
            phase5=True,
            pending_limit=seconds,
            busy_limit=pending,
            pending_timeout_ms=pending,
            send_tester_present=False,
        )

    def entry_write():
        try:
            diag.write(request + b"\x10\x82")
        except Exception as error:
            if not is_native_exception2026(error):
                raise
            # Native3c71/3d48 suppress native-domain entry-write faults.
            rt.check()

    def emit(field):
        notify({"field": field, "value": result[field]})
        rt.check()

    try:
        if context.stage == "get_cid":
            rt.call_owned("connect", "disconnect", protocol=6)
            rt.call(
                "set_timeout",
                milliseconds=_number(context.selection, "ReceiveTimeoutBeforeGetCID"),
            )
        if context.stage != "prepare":
            filters.append(diag.start_filter(request, response))
        if context.stage == "get_cid":

            def identifier_field(did):
                if rt.native_cancelled is not None:
                    aborted = rt.native_cancelled()
                    if type(aborted) is not bool:
                        raise ValueError("Native MMC abort observation must be Boolean")
                    rt.check()
                    if aborted:
                        return ""
                reply = call(b"\x22" + did, b"\x62" + did, 3, minimum=27)
                return reply[3:27].split(b"\0", 1)[0].decode("latin1")

            result["identifier_f111"] = identifier_field(b"\xf1\x11")
            if engine is not None:
                engine.apply_mmc_getter_hardware(
                    context.identity, result["identifier_f111"].encode("latin1")
                )
            identifier = identifier_field(b"\xf1\x88")
            result["identifiers"] = [identifier] if identifier else []
            native_value = True
        elif context.stage == "prepare":
            assert preparation_state is not None
            while True:
                state = preparation_state()
                _uint(state)
                rt.check()
                if state != 1:
                    break
                entry_write()
            state = preparation_state()
            _uint(state)
            rt.check()
            if state != 3:
                result["state"] = "prepare_declined"
                result["native_return"] = False
                return result
            start = _uint(rt.call("local_time_ms"), 86399999)
            while True:
                now = _uint(rt.call("local_time_ms"), 86399999)
                elapsed = (now - start) % 86400000
                entry_write()
                if elapsed > 2000:
                    break
            filters.append(diag.start_filter(request, response))
            prepare_handler_active = True
            rt.call_owned(
                "start_sync_periodic",
                "stop_sync_periodic",
                frames=((bytes.fromhex("000007df3e80"), 0),),
                count=1,
                interval_ms=2000,
                retry_ms=100,
                delay_ms=0,
            )
            periodic_owned = True
            session = call(b"\x10\x02", b"\x50\x02", 41, minimum=6)
            rt.call("set_timeout", milliseconds=int.from_bytes(session[2:4], "big"))
            pending = int.from_bytes(session[4:6], "big") * 10
            seed = call(b"\x27\x41", b"\x67\x41", 16, minimum=10)
            engine_words, other = security_tables(context.prepare_engine)
            # CalibrationFile exported Engine_MMC points to literal65.
            material = (
                engine_words
                if context.selection.metadata.vehicle.get("kindofecu", "") == "65"
                else other
            )
            key = mmc_key(seed[2:10], *material)
            call(b"\x27\x42" + key, b"\x67\x42", 17)
            native_value = True
            result["pending_timeout_ms"] = pending
            result["periodic_active"] = True
        else:

            def transfer(segments, selector, image):
                cursor = 0
                total = sum(10 + len(segment.data) for segment in segments)
                for segment in segments:
                    maximum = call(
                        bytes((0x34, selector, 0x44))
                        + segment.address.to_bytes(4, "big")
                        + len(segment.data).to_bytes(4, "big"),
                        b"\x74\x20",
                        26,
                        minimum=4,
                    )
                    width = min(int.from_bytes(maximum[2:4], "big"), 4095) - 2
                    if width <= 0:
                        raise ValueError("MMC transfer maximum cannot contain data")
                    cursor += 8
                    for index, offset in enumerate(
                        range(0, len(segment.data), width), 1
                    ):
                        chunk = segment.data[offset : offset + width]
                        sequence = index & 255
                        call(
                            bytes((0x36, sequence)) + chunk, bytes((0x76, sequence)), 34
                        )
                        cursor += len(chunk)
                        if image:
                            result["count"] = cursor + 2
                            emit("count")
                            result["percent"] = (cursor + 2) * 100 // total
                            emit("percent")
                    call(b"\x37", b"\x77" + segment.checksum, 28)
                    cursor += 2

            transfer(context.loader, context.loader_selector, False)
            call(
                b"\x31\x01\x03\x01" + context.loader_routine,
                b"\x71\x01\x03\x01\x10",
                68,
            )
            result["writing"] = True
            emit("writing")
            for address, size in context.erase_areas:
                call(
                    b"\x31\x01\xff\0" + struct.pack(">II", address, size),
                    b"\x71\x01\xff\0\x10",
                    69,
                    seconds=90,
                )
            transfer(context.image, context.image_selector, True)
            call(b"\x31\x01\x03\x04", b"\x71\x01\x03\x04\x10\x02", 70)
            if rt.owns_resource("stop_sync_periodic"):
                rt.release("stop_sync_periodic")
            else:
                rt.call("stop_sync_periodic", cleanup=True)
            diag.write(bytes.fromhex("000007df1181"))
            rt.call(
                "wait",
                milliseconds=_number(context.selection, "WaitTimeAfterEndOfFlashing"),
            )
            native_value = True
            result["writing"] = False
            emit("writing")
        result["state"] = {
            "get_cid": "identification_completed",
            "prepare": "prepare_completed",
            "write": "writer_completed",
        }[context.stage]
    except (InterruptedError, TimeoutError) as error:
        result["state"] = (
            "cancelled" if isinstance(error, InterruptedError) else "deadline_expired"
        )
        raise
    except Exception as error:
        if not is_native_exception2026(error):
            raise
        if context.stage == "prepare" and not prepare_handler_active:
            raise
        result["state"] = "failed"
        typed = isinstance(
            error,
            (NativeTransportError, NativePassThruException2026, CommonResponseError),
        )
        if context.stage == "write" and not typed:
            # Writer state2 has only typed catches;1354 belongs to filter cleanup.
            raise
        if typed:
            result["error_kind"] = (
                1
                if isinstance(error, NativeTransportError)
                else error.error
                if isinstance(error, NativePassThruException2026)
                else error.code
                if isinstance(error, CommonResponseError)
                else 9999
            )
            result["error_code"] = (
                error.j2534_error
                if isinstance(error, NativeJ2534Exception2026)
                else error.code
                if isinstance(error, NativeTransportError)
                else result["error_code"]
            )
        elif context.stage == "prepare":
            # Native3b2d assigns9999; getter1c66 preserves caller fields.
            result["error_kind"] = 9999
        result["native_error_code"] = result["error_kind"]
        result["driver_error_code"] = result["error_code"]
        if context.stage == "write" and typed:
            result["count"] = 0
            notify({"field": "count", "value": 0})
            result["percent"] = 0
            notify({"field": "percent", "value": 0})
        if typed or context.stage == "prepare":
            result["failure_status"] = (
                2 if context.stage == "write" and result["writing"] else 1
            )
        result["exception_class"] = type(error).__name__
    finally:
        cleanup = []
        active = sys.exception()
        periodic_error = None
        host_cleanup_error = None
        if (
            context.stage == "write"
            or periodic_owned
            and result["state"] != "prepare_completed"
        ):
            try:
                if rt.owns_resource("stop_sync_periodic"):
                    rt.release("stop_sync_periodic")
                else:
                    rt.call("stop_sync_periodic", cleanup=True)
            except Exception as error:  # noqa: BLE001 - attempt every native release
                native_cleanup_unknown = True
                periodic_error = error
                if not is_native_exception2026(error):
                    host_cleanup_error = error
                cleanup.append(type(error).__name__)
        for identifier in reversed(filters):
            try:
                rt.release("stop_filter", identifier=identifier)
            except Exception as error:  # noqa: BLE001 - attempt every native release
                if not is_native_exception2026(error):
                    native_cleanup_unknown = True
                    host_cleanup_error = error
                cleanup.append(type(error).__name__)
        if context.stage == "get_cid" and rt.owns_resource("disconnect"):
            try:
                rt.release("disconnect")
            except Exception as error:  # noqa: BLE001 - attempt native device cleanup
                native_cleanup_unknown = True
                if not is_native_exception2026(error):
                    host_cleanup_error = error
                cleanup.append(type(error).__name__)
        if cleanup:
            result["cleanup_errors"] = cleanup
            result["state"] = "cleanup_failed"
            if active is not None:
                active.add_note("MMC cleanup failures: " + ", ".join(cleanup))
        if host_cleanup_error is not None and active is None:
            raise host_cleanup_error
        if context.stage == "write" and periodic_error is not None and active is None:
            # Cleanup StopSync is state1, outside native writer catch scopes.
            raise periodic_error
    if not native_cleanup_unknown:
        result["native_success" if context.stage == "get_cid" else "native_return"] = (
            native_value
        )
    return result
