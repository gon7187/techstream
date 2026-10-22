"""Actual CUW2026 M16C wire primitives and selected native input adapter.

Only injected typed host I/O is used. No vendor image or vehicle is executed.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass, field

from scripts.calibration import CalibrationContainer
from scripts.calibration_2026 import (
    native2026_archive,
    native2026_archive_password,
    native2026_cpu_count,
    native2026_cpu_targets,
    native2026_cpu_type,
    native2026_global_cpu_index,
    native2026_metadata_for_cpu,
    native2026_new_password,
)
from scripts.native_modules import NativeModuleIdentity, identify_native_module
from scripts.programming import NativeTransportError
from scripts.programming_2026_common import (
    CommonResponseError,
    NativeParameterBinding2026,
    NativePassThruException2026,
    NativeRuntime2026,
    bind_native_parameter2026,
    is_native_exception2026,
    native_block_info,
    native_error_fields2026,
)
from scripts.programming_2026_vendor import native2026_write_address_groups

MODULE_EXPORTS = {
    "TCUWCanM16CFlashWriter.dll": ("StartFlashWrite", "PrepareRetry"),
    "TCUWCanSecurityM16CFlashWriter.dll": ("StartFlashWrite",),
    "TCUWCanSecurityVFORESTFlashWriter.dll": ("StartFlashWrite",),
    "TCUWP4CanVFORESTFlashWriter.dll": ("StartFlashWrite",),
}


@dataclass(frozen=True)
class NativeWriterState2026:
    """Native output assignments; None means unchanged or no native assignment.

    Host cancellation/validation is not invented as an OEM result. A suppressed
    native finish fault can have returned=True while the host still raises it.
    """

    returned: bool | None
    result_status_update: int | None
    native_error_code: int | None
    driver_error_code: int | None
    retry_password: bool | None
    finish_flag_update: bool | None
    completion_flag_update: bool | None
    recovery_flag_update: bool | None
    progress_bytes: int
    progress_percent: int

    def report(self) -> dict:
        return asdict(self)


def _uint(value: int, bits: int, name: str) -> int:
    if type(value) is not int or not 0 <= value < 1 << bits:
        raise ValueError(f"{name} must fit uint{bits}")
    return value


class M16C2026Error(ValueError):
    def __init__(self, code: int):
        self.code = _uint(code, 32, "Native error")
        super().__init__(f"CUW2026 M16C operation failed ({code})")


class M16C2026:
    """M16C3470/2be0/3270 and SecurityM16C29e0/3060 raw protocol.

    The native WriteMsgs two-message batches remain a single primitive call;
    partial writes fail without retrying the unknown subset.
    """

    def __init__(
        self,
        runtime: NativeRuntime2026,
        request: bytes,
        response: bytes,
        progress: Callable[[int], None] | None = None,
    ):
        if not isinstance(runtime, NativeRuntime2026) or any(
            type(value) is not bytes or len(value) != 4 for value in (request, response)
        ):
            raise ValueError("Runtime and exact four-byte raw CAN addresses required")
        if progress is not None and not callable(progress):
            raise TypeError("Callable progress observer required")
        self.runtime, self.request, self.response = runtime, request, response
        self.progress = progress
        self.written = self.verified = 0

    def write(self, *payloads: bytes) -> None:
        if not 1 <= len(payloads) <= 2 or any(
            type(data) is not bytes or not 0 < len(data) <= 4095 for data in payloads
        ):
            raise ValueError("One/two bounded immutable native payloads required")
        data = tuple(self.request + payload for payload in payloads)
        result = self.runtime.call(
            "write_messages",
            protocol=6,
            tx_flags=0,
            data=data[0] if len(data) == 1 else data,
            count=len(data),
        )
        if type(result) is not int or result != len(data):
            raise ValueError("Native WriteMsgs did not accept the entire batch")

    def read(self, minimum: int) -> bytes | None:
        try:
            result = self.runtime.call(
                "read_specified_can_message", address=self.response, count=1, frame=0
            )
        except (NativeTransportError, NativePassThruException2026) as exc:
            if native_error_fields2026(exc)[1] in (9, 16):
                return None
            raise
        if (
            type(result) is not bytes
            or not result.startswith(self.response)
            or not 4 + minimum <= len(result) <= 4128
        ):
            raise ValueError("Truncated or incorrectly addressed M16C response")
        return result[4:]

    def status(self, *, verify: bool = False) -> bytes | None:
        if type(verify) is not bool:
            raise TypeError("Native Boolean required")
        self.write(b"\xa8" if verify else b"\xa4")
        return self.read(1 if verify else 2)

    def wait(self, milliseconds: int) -> None:
        _uint(milliseconds, 32, "Native wait")
        if self.runtime.call("wait", milliseconds=milliseconds) is not None:
            raise ValueError("Native wait primitive must return None")

    def password(self, address: bytes, password: int, suffix: bytes) -> None:
        if any(type(v) is not bytes or len(v) != 3 for v in (address, suffix)):
            raise ValueError("Three-byte native password address and suffix required")
        _uint(password, 32, "Password")
        self.write(b"\xa0" + address + b"\x07", password.to_bytes(4, "big") + suffix)
        status = self.status()
        if status is None or status[1] & 12 != 12:
            raise M16C2026Error(7)

    def poll(self, operation: str, wait_ms: int) -> None:
        code = {"erase": 12, "write": 13, "verify": 15}[operation]
        for _ in range(4096):
            self.wait(wait_ms)
            status = self.status(verify=operation == "verify")
            if status is None:
                raise M16C2026Error(code)
            if operation == "verify":
                if status[0] == 255:
                    continue
                failed = status[0] != 0
            else:
                if status[0] & 128 == 0:
                    continue
                failed = bool(
                    status[0] & 48 or (operation == "write" and status[1] & 2)
                )
            if failed:
                raise M16C2026Error(code)
            return
        raise TimeoutError("Host M16C poll budget exceeded")

    def erase(self, last_address: int, wait_ms: int = 0) -> None:
        _uint(last_address, 24, "Erase address")
        _uint(wait_ms, 32, "Erase wait")
        self.write(b"\xa6")
        self.write(
            bytes((0xA1, (last_address >> 8) & 255, last_address >> 16)) + b"\xd0"
        )
        self.poll("erase", wait_ms)

    def page(
        self, address: int, data: bytes, *, verify: bool = False, wait_ms: int = 0
    ) -> None:
        _uint(address, 24, "Page address")
        _uint(wait_ms, 32, "Page wait")
        if (
            type(verify) is not bool
            or address % 256
            or type(data) is not bytes
            or len(data) != 256
        ):
            raise ValueError("Aligned complete native 256-byte page required")
        if not verify:
            self.write(b"\xa6")
        self.write(
            bytes((0xA3 if verify else 0xA2, (address >> 8) & 255, address >> 16)), data
        )
        if self.progress is not None:
            self.progress(256)
        self.poll("verify" if verify else "write", wait_ms)
        if verify:
            self.verified += 256
        else:
            self.written += 256

    def prepare_retry(self, wait_ms: int = 0) -> None:
        _uint(wait_ms, 32, "Dummy wait")
        for attempt in range(4):
            if self.status() is not None:
                return
            if attempt == 3:
                raise M16C2026Error(20)
            if self.status(verify=True) is not None:
                return
            self.write(bytes(256))
            self.wait(wait_ms)


@dataclass(frozen=True)
class M16C2026Context:
    identity: NativeModuleIdentity
    binding: NativeParameterBinding2026 = field(repr=False)
    stage: str
    cpu_index: int
    cpu_count: int
    parent_index: int | None
    request: bytes
    response: bytes
    finish_request: bytes | None
    image: bytes = field(repr=False)
    segments: tuple[tuple[int, bytes], ...] = field(repr=False)
    location_id: bytes = field(repr=False)
    password: int = field(repr=False)
    parent_password: int = field(repr=False)
    nonce: bytes = field(repr=False)
    key: bytes = field(repr=False)
    parent_big_endian: bool = False
    recovery: bool = False
    previous_retry_password: bool = False
    force_retry_password: bool = False

    def __post_init__(self):
        if (
            not isinstance(self.identity, NativeModuleIdentity)
            or self.identity.module_name not in MODULE_EXPORTS
            or self.identity.cuw_build != "2026"
            or identify_native_module(self.identity.sha256, self.identity.module_name)
            != self.identity
            or not isinstance(self.binding, NativeParameterBinding2026)
            or self.binding.module_name != self.identity.module_name
            or self.stage not in ("write", "prepare_retry")
            or self.stage == "prepare_retry"
            and "PrepareRetry" not in self.identity.callable_exports
            or type(self.cpu_count) is not int
            or not 1 <= self.cpu_count <= 99
            or type(self.cpu_index) is not int
            or not 0 <= self.cpu_index < self.cpu_count
            or any(
                type(value) is not bytes or len(value) != 4
                for value in (self.request, self.response)
            )
            or self.finish_request is not None
            and (
                type(self.finish_request) is not bytes or len(self.finish_request) != 4
            )
            or type(self.location_id) is not bytes
            or len(self.location_id) not in (0, 8)
            or any(
                type(value) is not bool
                for value in (
                    self.parent_big_endian,
                    self.recovery,
                    self.previous_retry_password,
                    self.force_retry_password,
                )
            )
        ):
            raise ValueError("Exact bounded actual2026 context required")
        _uint(self.password, 32, "Native password")
        _uint(self.parent_password, 32, "Native parent password")
        if self.stage == "write":
            initial = not self.recovery or bool(
                self.binding.parameter.boolean("IGOffRetriableFlag")
            )
            if (self.parent_index is None or initial) and len(self.location_id) != 8:
                raise ValueError(
                    "Native initial command requires its eight-byte LocationID"
                )
            if (
                type(self.image) is not bytes
                or not 0 < len(self.image) <= 64 * 1024 * 1024
            ):
                raise ValueError("Complete bounded native image required")
            if "Security" in self.identity.module_name and any(
                type(value) is not bytes or len(value) != 16
                for value in (self.nonce, self.key)
            ):
                raise ValueError(
                    "Explicit native sixteen-byte security fields required"
                )
            if "M16C" in self.identity.module_name:
                if (
                    type(self.parent_index) is not int
                    or not 0 <= self.parent_index < self.cpu_count
                    or self.parent_index == self.cpu_index
                ):
                    raise ValueError("Distinct selected parent CPU required")
                if (
                    type(self.segments) is not tuple
                    or not 1 <= len(self.segments) <= 255
                ):
                    raise ValueError("Complete native M16C segments required")
                for address, data in self.segments:
                    _uint(address, 24, "Native segment address")
                    if (
                        address % 256
                        or type(data) is not bytes
                        or not data
                        or len(data) % 256
                        or address + len(data) > 1 << 24
                    ):
                        raise ValueError("Aligned bounded native segment required")
                if b"".join(data for _address, data in self.segments) != self.image:
                    raise ValueError(
                        "Native segments must consume the entire selected image"
                    )
            else:
                vforest_groups_2026(self.image)
            if self.cpu_index == self.cpu_count - 1 and self.finish_request is None:
                raise ValueError(
                    "Last native CPU requires its functional finish address"
                )

    def report(self) -> dict:
        return {
            "module": self.identity.module_name,
            "build": "2026",
            "stage": self.stage,
            "cpu_index": self.cpu_index,
            "parent_index": self.parent_index,
            "input_sha256": self.binding.metadata.source_sha256,
        }


def bind_native_context(
    container: CalibrationContainer,
    node: int,
    observed_cids: tuple[str, ...],
    selection: NativeParameterBinding2026,
    identity: NativeModuleIdentity,
    attachments: Mapping[str, bytes] | None = None,
    observations: Mapping | None = None,
) -> M16C2026Context:
    """Actual2026 selected CUW/parameter producer, never an older catalog adapter."""
    if (
        not isinstance(selection, NativeParameterBinding2026)
        or not isinstance(identity, NativeModuleIdentity)
        or identity.module_name not in MODULE_EXPORTS
        or identity.cuw_build != "2026"
        or identify_native_module(identity.sha256, identity.module_name) != identity
        or selection.module_name != identity.module_name
        or selection.operation != "write"
    ):
        raise ValueError(
            "Exact registered2026 writer and native parameter binding required"
        )
    attachments = {} if attachments is None else attachments
    observations = {} if observations is None else observations
    flags = {"recovery", "previous_retry_password", "force_retry_password"}
    if (
        not isinstance(attachments, Mapping)
        or set(attachments) - {"nonce", "authorized_key"}
        or not isinstance(observations, Mapping)
        or set(observations)
        - flags
        - {
            "cpu_index",
            "stage",
            "previous_addresses",
            "target_indices",
        }
        or any(
            type(observations[name]) is not bool for name in flags & observations.keys()
        )
    ):
        raise ValueError(
            "Only native runtime state and authorized key attachments allowed"
        )
    local_index = observations.get("cpu_index", 0)
    selection = selection.validate_against(
        container, operation="write", node=node, cpu_index=local_index
    )
    metadata = selection.metadata
    index = native2026_global_cpu_index(metadata)
    cpu_count = native2026_cpu_count(metadata)
    stage = observations.get("stage", "write")
    if stage not in ("write", "prepare_retry") or (
        stage == "prepare_retry" and "PrepareRetry" not in identity.callable_exports
    ):
        raise ValueError("Requested export is absent from exact native module")
    parameter = selection.parameter
    parent = None
    if "M16C" in identity.module_name:
        parents = (parameter.values("ParentCPUTypeList") or ())[:100]
        parent = next(
            (
                i
                for i in range(cpu_count)
                if i != index and native2026_cpu_type(metadata, i) in parents
            ),
            None,
        )
        if parent is None:
            raise ValueError("Selected native parent CPU is absent")
    target_index = index if parent is None else parent
    target = native2026_metadata_for_cpu(metadata, target_index)
    initial = (
        parent is None
        or not observations.get("recovery", False)
        or bool(parameter.boolean("IGOffRetriableFlag"))
    )
    location_required = stage == "write" and initial
    location_text = target.cpu.values.get("locationid", "")
    if (location_required or location_text) and re.fullmatch(
        r"[0-9a-fA-F]{16}", location_text
    ) is None:
        raise ValueError("Native LocationID requires exactly eight hexadecimal bytes")
    history = observations.get("previous_addresses", ())
    if type(history) is not tuple:
        raise TypeError("Immutable native address history required")
    groups = native2026_write_address_groups(
        container, selection, history=list(history)
    )
    addresses = groups[target_index]
    if not addresses or (
        index == cpu_count - 1 and stage == "write" and len(addresses) < 2
    ):
        raise ValueError(
            "Native parent and functional communication addresses unavailable"
        )
    # Native M16C and VFOREST construct CBytes(ptr,2), then SetNum(4).
    request = b"\0\0" + addresses[0].request[:2]
    response = b"\0\0" + addresses[0].response[:2]
    finish_request = b"\0\0" + addresses[1].request[:2] if len(addresses) > 1 else None
    target_indices = observations.get("target_indices")
    if target_indices is not None and (
        type(target_indices) is not tuple
        or len(target_indices) != cpu_count
        or any(type(i) is not int or i < 0 for i in target_indices)
    ):
        raise ValueError("Native target-index array must cover every selected CPU")

    def password(cpu_metadata):
        targets = native2026_cpu_targets(cpu_metadata)
        if target_indices is not None:
            chosen = target_indices[native2026_global_cpu_index(cpu_metadata)]
            if chosen >= len(targets):
                raise ValueError("Observed target index outside imported targets")
            return targets[chosen].password
        matches = [
            value.password for value in targets if value.calibration in observed_cids
        ]
        if len(matches) != 1:
            raise ValueError("Exactly one observed CID must match native CPU target")
        return matches[0]

    image = b""
    segments = ()
    old = parent_password = 0
    if stage == "write":
        archive = native2026_archive(metadata)
        if archive.data is None:
            raise ValueError("Native writer requires a materialized archive image")
        image = archive.data
        if parent is not None and initial:
            old, parent_password = password(metadata), password(target)
        elif parent is None and not observations.get("previous_retry_password", False):
            old = password(metadata)
        if observations.get("previous_retry_password", False) and parent is None:
            password_parameters = {
                name: selection.value(name) for name in ("PasswordAddress", "ByteOrder")
            }
            old = (
                native2026_new_password(metadata, password_parameters)
                if "Security" in identity.module_name
                else native2026_archive_password(archive, password_parameters)
            )
        if parent is not None:
            starts = selection.lines("StartAddress")
            blocks = native_block_info(
                {"BlockSizeInfo": selection.value("BlockSizeInfo")}
            )
            if not starts or len(starts) != len(blocks):
                raise ValueError("Native start addresses must match block-size rows")
            rows = []
            offset = 0
            for start, block in zip(starts, blocks, strict=True):
                if re.fullmatch(r"[0-9a-fA-F]{1,6}", start) is None:
                    raise ValueError("Native M16C address must fit24bits")
                address, size = int(start, 16), block.size_kib << 10
                if (
                    address % 256
                    or not size
                    or address + size > 1 << 24
                    or offset + size > len(image)
                ):
                    raise ValueError("Native image does not cover complete M16C blocks")
                rows.append((address, image[offset : offset + size]))
                offset += size
            if offset != len(image):
                raise ValueError("Native M16C blocks must consume the selected image")
            segments = tuple(rows)

    def authorization(name, metadata_name):
        text = metadata.cpu.values.get(metadata_name, "")
        if text and re.fullmatch(r"[0-9a-fA-F]{32}", text) is None:
            raise ValueError("Invalid native authorization field")
        native = bytes.fromhex(text) if text else None
        attached = attachments.get(name)
        if attached is not None and (
            type(attached) is not bytes or len(attached) != 16
        ):
            raise ValueError("Explicit sixteen-byte authorization required")
        if native is not None and attached is not None and native != attached:
            raise ValueError("Attachment conflicts with imported authorization")
        value = native if native is not None else attached
        if value is None:
            raise ValueError("Authorized native security material unavailable")
        return value

    security = "Security" in identity.module_name and stage == "write"
    # Parent CheckID loads the parent's own native parameter row for BigEndianFlag.
    parent_endian = False
    if parent is not None and stage == "write" and initial:
        parent_binding = bind_native_parameter2026(
            container,
            selection.catalog_sources,
            "write",
            node=target.node,
            cpu_index=target.cpu_index,
            encoded=selection.encoded,
            metadata_state=target,
        )
        parent_parameter = parent_binding.parameter
        parent_endian = bool(parent_parameter.boolean("BigEndianFlag"))
    return M16C2026Context(
        identity,
        selection,
        stage,
        index,
        cpu_count,
        parent,
        request,
        response,
        finish_request,
        image,
        segments,
        bytes.fromhex(location_text),
        old,
        parent_password,
        authorization("nonce", "nonce") if security else b"",
        authorization("authorized_key", "seedkey") if security else b"",
        parent_endian,
        *(
            observations.get(name, False)
            for name in ("recovery", "previous_retry_password", "force_retry_password")
        ),
    )


def vforest_groups_2026(image: bytes) -> tuple[bytes, ...]:
    """SecurityVFOREST12b0/P4VFOREST1170: BE16 length plus ZV00/01 header."""
    if type(image) is not bytes or not 0 < len(image) <= 64 * 1024 * 1024:
        raise ValueError("Bounded native VFOREST archive required")
    groups = []
    offset = 0
    while offset < len(image):
        if len(groups) >= 65536 or len(image) - offset < 5:
            raise ValueError("Truncated native VFOREST record header")
        prefix = image[offset : offset + 3]
        overhead = 5 if prefix == b"ZV\0" else 7 if prefix == b"ZV\1" else 0
        length = int.from_bytes(image[offset + 3 : offset + 5], "big") + overhead
        if length < 5 or offset + length > len(image):
            raise ValueError("Invalid native VFOREST record length")
        groups.append(image[offset : offset + length])
        offset += length
    return tuple(groups)


def run_native_context(
    context: M16C2026Context,
    runtime: NativeRuntime2026,
    *,
    progress_observer: Callable[[str, int, int], None] | None = None,
    writing_observer: Callable[[bool], None] | None = None,
) -> dict:
    """Execute selected2026 chronology through raw typed primitives only.

    Cleanup releases only resources acquired here; preexisting caller handles are
    retained. Cleanup failure prevents a success report and preserves its cause.
    """
    from scripts.programming_2026_common import (
        check_cpu_type_from_firmware,
        select_retry_password,
    )
    from scripts.programming_2026_legacy import (
        CommonFlash2026,
        NativeMappedTransportError,
    )

    if not isinstance(context, M16C2026Context) or not isinstance(
        runtime, NativeRuntime2026
    ):
        raise TypeError("Bound actual2026 context and runtime required")
    if (
        context.identity.module_name not in MODULE_EXPORTS
        or context.identity.cuw_build != "2026"
        or identify_native_module(context.identity.sha256, context.identity.module_name)
        != context.identity
        or context.stage not in ("write", "prepare_retry")
        or context.stage == "prepare_retry"
        and context.identity.module_name != "TCUWCanM16CFlashWriter.dll"
    ):
        raise ValueError("Exact actual2026 export identity required")
    parameter = context.binding.parameter
    module = context.identity.module_name
    m16c = "M16C" in module
    security = "Security" in module
    if not m16c and context.stage == "write":
        groups = vforest_groups_2026(context.image)
    else:
        groups = ()
    transferred = 0
    total = len(context.image) * 2

    def observe(callback, *values, cleanup=False):
        if not cleanup:
            runtime.check()
        if callback is not None and callback(*values) is not None:
            raise ValueError("Native observer must return None")
        if not cleanup:
            runtime.check()

    def progress(count):
        nonlocal transferred
        transferred += count
        percent = 0 if not total else transferred * 100 // total
        observe(progress_observer, "count", context.cpu_index, transferred)
        observe(progress_observer, "percent", context.cpu_index, percent)

    wire = M16C2026(runtime, context.request, context.response, progress)
    common = CommonFlash2026(runtime)

    def number(name):
        return _uint(parameter.long(name) or 0, 32, name)

    def flag(name):
        return bool(parameter.boolean(name))

    def void(operation, **values):
        if runtime.call(operation, **values) is not None:
            raise ValueError("Native void primitive must return None")

    def notify(value):
        observe(writing_observer, value)

    previous_timeout = None
    filter_id = None
    error = None
    cleanup_errors = []
    writing = False
    success = False
    phase = "setup"
    finish_called = False
    retry_previous = context.previous_retry_password
    native_progress = 0
    try:
        if m16c and context.stage == "write":
            timeout_value = runtime.call("get_timeout")
            if type(timeout_value) is not int:
                raise TypeError("Unsigned native timeout required")
            previous_timeout = _uint(timeout_value, 32, "Native timeout")
        phase = "initial"
        filter_id = runtime.acquire(
            "start_flow_control_filter",
            "stop_filter",
            request_address=context.request,
            response_address=context.response,
        )
        if context.stage == "prepare_retry":
            wire.prepare_retry(number("WaitTimeAfterSendDummyData"))
        else:
            initial = not context.recovery or flag("IGOffRetriableFlag")
            if not m16c or initial:
                wire.wait(number("WaitTimeAfterReprogrammingMode"))
                common.check_id_with_wait_of_sfs(
                    context.request,
                    context.response,
                    context.location_id,
                    context.parent_password if m16c else context.password,
                    number("WaitTimeBetweenSF"),
                    number("ReceiveTimeoutBeforeInitialCommand"),
                    context.parent_big_endian if m16c else flag("BigEndianFlag"),
                )
            if security:
                common.send_nonce_and_seed_key(
                    context.request,
                    context.response,
                    context.nonce,
                    context.key,
                    number("WaitTimeBetweenSF"),
                )
            if m16c:
                if not security and flag("GetMemoryInfoForWatchCPUFlag"):
                    common.get_memory_info(context.request, context.response)
                void(
                    "set_timeout", milliseconds=number("ReceiveTimeoutBeforeFlashWrite")
                )
                if initial:

                    def triple(name):
                        values = parameter.values(name) or ()
                        if len(values) != 3 or any(
                            re.fullmatch(r"(?:[0-9a-fA-F]{2}){1,129}", value) is None
                            for value in values
                        ):
                            raise ValueError(
                                "Three native hexadecimal password fields required"
                            )
                        return bytes(bytes.fromhex(value)[0] for value in values)

                    phase = "password"
                    wire.password(
                        triple("PasswordCheckIDAddress"),
                        context.password,
                        triple("PasswordCheckPassword"),
                    )
                writing = True
                notify(True)
                phase = "program"
                for address, data in context.segments:
                    wire.erase(
                        address + len(data) - 1,
                        number("WaitTimeBeforeStatusCheckForEraseBlock"),
                    )
                    for offset in range(0, len(data), 256):
                        page = data[offset : offset + 256]
                        wire.page(
                            address + offset,
                            page,
                            wait_ms=number("WaitTimeBeforeStatusCheckForWriteBlock"),
                        )
                        wire.page(
                            address + offset,
                            page,
                            verify=True,
                            wait_ms=number("WaitTimeBeforeStatusCheckForVerify"),
                        )
                phase = "post_write"
                wire.wait(number("WaitTimeAfterFlashWrite"))
                if security:
                    phase = "falsify"
                    common.detect_falsify(context.request, context.response)
            else:
                phase = "vforest"
                memory, extended = common.get_memory_info(
                    context.request, context.response
                )

                def matches():
                    values = {
                        name: parameter.string(name) or ""
                        for name in ("CPUIDNo", "ShrinkFlag")
                    }
                    return check_cpu_type_from_firmware(
                        memory.firmware_version, values, extended
                    )

                if not matches():
                    try:
                        alternate_binding = context.binding.reselect_alternate_cpu()
                    except (ValueError, LookupError) as exc:
                        raise M16C2026Error(10) from exc
                    parameter = alternate_binding.parameter
                    if not matches():
                        raise M16C2026Error(10)
                writing = True
                notify(True)
                for verify in (False, True):
                    code = 30 if verify else 29
                    try:
                        wire.write(
                            bytes((0x17 if verify else 0x42, 0, 0))
                            + (len(groups) - 1).to_bytes(2, "big")
                            + b"\xff"
                        )
                        if not common.receive_ack(context.response):
                            raise M16C2026Error(code)
                        for group in groups:
                            for offset in range(0, len(group), 1024):
                                data = group[offset : offset + 1024]
                                wire.write(data)
                                progress(len(data))
                                if not common.receive_ack(context.response):
                                    raise M16C2026Error(code)
                                for _ in range(4096):
                                    wire.wait(
                                        number(
                                            "WaitTimeBeforeStatusCheckForVerify"
                                            if verify
                                            else "WaitTimeBeforeStatusCheckForWriteBlock"
                                        )
                                    )
                                    status = common.get_status(
                                        context.request, context.response, True
                                    )
                                    if status != (0x20 if verify else 0x40):
                                        break
                                else:
                                    raise TimeoutError(
                                        "Host VFOREST status poll budget exceeded"
                                    )
                                if status:
                                    raise M16C2026Error(code)
                                if verify:
                                    wire.verified += len(data)
                                else:
                                    wire.written += len(data)
                    except (
                        NativeTransportError,
                        NativePassThruException2026,
                        CommonResponseError,
                    ) as exc:
                        # Native phase catch updates the error before rethrowing.
                        _, driver_code = native_error_fields2026(exc)
                        if driver_code is not None:
                            raise NativeMappedTransportError(driver_code, code) from exc
                        if isinstance(exc, NativePassThruException2026):
                            exc.set_error(code)
                        elif isinstance(exc, CommonResponseError):
                            exc.code = code
                        else:
                            from scripts.j2534_2026 import NativePassThruError2026

                            raise NativePassThruError2026(code) from exc
                        raise
                if security:
                    common.detect_falsify(context.request, context.response)
            retry_previous = False
            phase = "change_cpu"
            if context.cpu_index < context.cpu_count - 1:
                common.change_next_cpu(context.request, context.response)
            else:
                if context.finish_request is None:
                    raise ValueError(
                        "Last CPU requires native functional finish address"
                    )
                phase = "finish"
                finish_called = True
                common.finish_reprogramming(context.finish_request)
            phase = "observer"
            notify(False)
            writing = False
        success = True
    except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - cleanup before propagation
        error = exc
        native_progress = transferred
        if context.stage == "write" and phase != "finish":
            transferred = 0
            for kind in ("count", "percent"):
                try:
                    observe(progress_observer, kind, context.cpu_index, 0, cleanup=True)
                except (Exception, KeyboardInterrupt) as notification_error:  # noqa: BLE001
                    cleanup_errors.append(type(notification_error).__name__)
    finally:
        if writing:
            try:
                observe(writing_observer, False, cleanup=True)
            except (Exception, KeyboardInterrupt) as notification_error:  # noqa: BLE001
                cleanup_errors.append(type(notification_error).__name__)
        if filter_id is not None:
            try:
                runtime.release("stop_filter", identifier=filter_id)
            except (Exception, KeyboardInterrupt) as cleanup_error:  # noqa: BLE001
                cleanup_errors.append(type(cleanup_error).__name__)
        if previous_timeout is not None:
            try:
                runtime.call("set_timeout", cleanup=True, milliseconds=previous_timeout)
            except (Exception, KeyboardInterrupt) as cleanup_error:  # noqa: BLE001
                cleanup_errors.append(type(cleanup_error).__name__)
    if error is not None:
        typed = isinstance(
            error,
            (
                M16C2026Error,
                CommonResponseError,
                NativeTransportError,
                NativePassThruException2026,
            ),
        )
        native_code, driver_code = (
            (error.code, None)
            if isinstance(error, M16C2026Error)
            else native_error_fields2026(error)
            if typed
            else (None, None)
        )
        native_fault = typed or is_native_exception2026(error)
        if phase == "change_cpu" and native_fault and not typed:
            typed, native_code = True, 9999
        swallowed_finish = phase == "finish" and native_fault
        returned = (
            True if swallowed_finish else False if typed and phase != "setup" else None
        )
        main_fatal = (
            context.recovery
            or phase in ("program", "falsify")
            or (phase == "vforest" and native_code != 10)
        )
        status = (
            (2 if main_fatal or phase == "change_cpu" else 1)
            if returned is False and context.stage == "write"
            else None
        )
        state = NativeWriterState2026(
            returned=returned,
            result_status_update=status,
            native_error_code=native_code if returned is False else None,
            driver_error_code=driver_code if returned is False else None,
            retry_password=(
                select_retry_password(
                    context.force_retry_password, native_code or 0, retry_previous
                )
                if returned is False and context.stage == "write"
                else False
                if swallowed_finish
                else None
            ),
            finish_flag_update=True if finish_called else None,
            completion_flag_update=True
            if returned is False and not main_fatal and context.stage == "write"
            else None,
            recovery_flag_update=False if swallowed_finish else None,
            progress_bytes=native_progress if phase == "finish" else 0,
            progress_percent=(native_progress * 100 // total)
            if phase == "finish" and total
            else 0,
        )
        error.__dict__.update(native_state=state)
        if state.native_error_code is not None:
            error.__dict__.update(native_cuw_code=state.native_error_code)
        error.add_note(
            f"CUW2026 retry_password={state.retry_password}; native_returned={state.returned}"
        )
        if cleanup_errors:
            error.add_note("Native cleanup failures: " + ",".join(cleanup_errors))
        raise error
    native_state = NativeWriterState2026(
        returned=True,
        result_status_update=None,
        native_error_code=None,
        driver_error_code=None,
        retry_password=False if context.stage == "write" else None,
        finish_flag_update=True if finish_called else None,
        completion_flag_update=None,
        recovery_flag_update=False if context.stage == "write" else None,
        progress_bytes=transferred,
        progress_percent=transferred * 100 // total if total else 0,
    )
    if cleanup_errors:
        cleanup_failure = OSError("CUW2026 cleanup failed: " + ",".join(cleanup_errors))
        cleanup_failure.__dict__.update(native_state=native_state)
        raise cleanup_failure
    return {
        **context.report(),
        "native_result": native_state.report(),
        "state": "writer_completed" if success else "writer_failed",
        "written": wire.written,
        "verified": wire.verified,
        "progress_bytes": transferred,
        "retry_password": select_retry_password(
            context.force_retry_password, 0, context.previous_retry_password
        )
        if not success
        else False,
        "physical_state": "PHYSICAL_UNCONFIRMED",
    }
