"""Recovered M16C and security VFOREST writers over supplied raw CAN callbacks.

No DLL is executed and no authorization value, adapter or vehicle is inferred.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from dataclasses import field as dataclass_field
from types import MappingProxyType
from typing import Any, TypeVar

from scripts.calibration import CalibrationContainer
from scripts.calibration_catalog import Address, CalibrationSelection
from scripts.native_modules import NativeModuleIdentity, identify_native_module
from scripts.programming_legacy import (
    bind_native_cpu_context,
    native_cpu_passwords,
    parse_block_info,
    vforest_groups,
    vforest_transfer,
)
from scripts.programming_vendor import VendorCAN, common_cpu_matches

_T = TypeVar("_T")


def _uint(value: int, bits: int, name: str) -> int:
    if type(value) is not int or not 0 <= value < 1 << bits:
        raise ValueError(f"{name} must fit uint{bits}")
    return value


def _wait_context(channel: VendorCAN, value: int) -> None:
    _uint(value, 32, "Native wait")
    if value and channel.wait_callback is None:
        raise ValueError("Native wait requires an explicit provider")


def _native_phase(
    channel: VendorCAN, operation: str, code: int, action: Callable[[], _T]
) -> _T:
    try:
        return action()
    except (OSError, ValueError) as exc:
        channel.remaining()
        raise M16CError(operation, code) from exc


def _finish(channel: VendorCAN, finish_channel: VendorCAN) -> None:
    previous = finish_channel.deadline
    finish_channel.deadline = min(
        previous, finish_channel.clock() + channel.remaining()
    )
    try:
        _native_phase(
            channel, "finish", 0x23, lambda: finish_channel.finish(acknowledge=False)
        )
    finally:
        finish_channel.deadline = previous


class M16CError(ValueError):
    def __init__(self, operation: str, code: int, status: bytes = b""):
        self.operation, self.code, self.status = operation, code, status
        super().__init__(f"Native M16C {operation} failed ({code}): {status.hex()}")


class M16CReadError(OSError):
    """Explicit native read errors9/16 are recoverable probe failures."""

    def __init__(self, code: int):
        self.code = _uint(code, 32, "Native read error")
        super().__init__(f"Native read error {code}")


def parent_cpu(
    cpu_types: tuple[str, ...], parents: tuple[str, ...], current: int
) -> int:
    """Native first exact ParentCPUTypeList match excluding the current CPU."""
    if (
        not isinstance(cpu_types, tuple)
        or not 1 <= len(cpu_types) <= 255
        or not isinstance(parents, tuple)
        or not 1 <= len(parents) <= 100
        or any(
            not isinstance(name, str) or not 1 <= len(name) <= 259
            for name in cpu_types + parents
        )
        or type(current) is not int
        or not 0 <= current < len(cpu_types)
    ):
        raise ValueError("Invalid bounded CPU selection context")
    for index, name in enumerate(cpu_types):
        if index != current and name in parents:
            return index
    raise ValueError("No configured parent CPU exists")


def retry_password(previous: bool, error: int, *, force: bool = False) -> bool:
    """FlashWriterUtils1280: force=true; code7 toggles; other errors clear."""
    if type(previous) is not bool or type(force) is not bool:
        raise ValueError("Boolean retry-password flags required")
    _uint(error, 32, "Native error")
    return True if force else not previous if error == 7 else False


def new_password(
    image: bytes | None, address: int, byte_order: int, *, explicit: int | None = None
) -> int:
    """CalibrationFile3090 cached value or CalibArchivedFile2ef0 image lookup.

    ByteOrder's low16bits equal zero selects little endian; otherwise big endian.
    The caller supplies its selected calibration image, never device memory.
    """
    if explicit is not None:
        return _uint(explicit, 32, "Explicit replacement password")
    _uint(address, 32, "PasswordAddress")
    _uint(byte_order, 32, "ByteOrder")
    if (
        not isinstance(image, bytes)
        or len(image) > 64 * 1024 * 1024
        or address + 4 > len(image)
    ):
        raise ValueError("PasswordAddress must select four supplied image bytes")
    return int.from_bytes(
        image[address : address + 4], "big" if byte_order & 0xFFFF else "little"
    )


def m16c_password_frames(
    address: bytes, password: int, suffix: bytes
) -> tuple[bytes, bytes]:
    if (
        not isinstance(address, bytes)
        or len(address) != 3
        or not isinstance(suffix, bytes)
        or len(suffix) != 3
    ):
        raise ValueError(
            "PasswordCheckIDAddress and PasswordCheckPassword need three bytes"
        )
    return b"\xa0" + address + b"\x07", _uint(password, 32, "Password").to_bytes(
        4, "big"
    ) + suffix


def m16c_address_frame(operation: str, address: int) -> bytes:
    """Native A1/A2/A3 carry address bits8..23, low byte first."""
    _uint(address, 24, "M16C address")
    try:
        opcode = {"erase": 0xA1, "write": 0xA2, "verify": 0xA3}[operation]
    except KeyError as exc:
        raise ValueError("Unknown M16C address operation") from exc
    return bytes((opcode, (address >> 8) & 255, (address >> 16) & 255)) + (
        b"\xd0" if operation == "erase" else b""
    )


@dataclass(frozen=True)
class M16CSegment:
    address: int
    data: bytes

    def __post_init__(self):
        _uint(self.address, 24, "Segment address")
        if (
            self.address % 256
            or not isinstance(self.data, bytes)
            or not self.data
            or len(self.data) % 256
            or self.address + len(self.data) > 1 << 24
        ):
            raise ValueError(
                "M16C segments require aligned complete256-byte pages within24bits"
            )


def m16c_segments(
    image: bytes, starts: tuple[int, ...], sizes_kib: tuple[int, ...]
) -> tuple[M16CSegment, ...]:
    """GetBlockInfo/StartAddress pairing; image bytes are concatenated block data."""
    if (
        not isinstance(image, bytes)
        or not 0 < len(image) <= 64 * 1024 * 1024
        or not isinstance(starts, tuple)
        or not isinstance(sizes_kib, tuple)
        or not 1 <= len(starts) == len(sizes_kib) <= 255
    ):
        raise ValueError("Bounded complete block metadata and immutable image required")
    sizes = tuple(_uint(size, 22, "Block KiB size") * 1024 for size in sizes_kib)
    if not all(sizes) or sum(sizes) != len(image):
        raise ValueError("Every native block byte must be supplied exactly once")
    offset = 0
    result = []
    for start, size in zip(starts, sizes, strict=True):
        result.append(M16CSegment(start, image[offset : offset + size]))
        offset += size
    return tuple(result)


class M16CWriter:
    """M16C-specific A4/A8 status protocol; never CommonWrite/ACK3c."""

    def __init__(
        self, channel: VendorCAN, progress: Callable[[int], None] | None = None
    ):
        self.channel = channel
        self.progress = progress
        self.written = self.verified = 0

    def _read(self, minimum: int) -> bytes | None:
        try:
            result = self.channel.read()
        except OSError as exc:
            self.channel.remaining()
            if getattr(exc, "code", None) in (9, 16):
                return None
            raise
        if len(result) < minimum:
            raise ValueError("Truncated native M16C status")
        return result

    def status(self) -> bytes | None:
        self.channel.write(b"\xa4")
        return self._read(2)

    def verify_status(self) -> bytes | None:
        self.channel.write(b"\xa8")
        return self._read(1)

    def password_check(self, address: bytes, password: int, suffix: bytes) -> None:
        for frame in m16c_password_frames(address, password, suffix):
            self.channel.write(frame)
        status = self.status()
        if status is None or status[1] & 12 != 12:
            raise M16CError("password", 7, status or b"")

    def _poll(self, operation: str, wait_ms: int) -> None:
        code = {"erase": 12, "write": 13, "verify": 15}[operation]
        for _ in range(4096):
            self.channel.wait(wait_ms)
            status = self.verify_status() if operation == "verify" else self.status()
            if status is None:
                raise M16CError(operation, code)
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
                raise M16CError(operation, code, status)
            return
        raise TimeoutError("Host M16C status poll budget exceeded")

    def erase(self, last_address: int, *, wait_ms: int = 0) -> None:
        _wait_context(self.channel, wait_ms)
        request = m16c_address_frame("erase", last_address)
        self.channel.write(b"\xa6")
        self.channel.write(request)
        self._poll("erase", wait_ms)

    def page(
        self, address: int, data: bytes, *, verify: bool = False, wait_ms: int = 0
    ) -> None:
        _wait_context(self.channel, wait_ms)
        if (
            type(verify) is not bool
            or address % 256
            or not isinstance(data, bytes)
            or len(data) != 256
        ):
            raise ValueError("Aligned M16C page must contain exactly256bytes")
        operation = "verify" if verify else "write"
        request = m16c_address_frame(operation, address)
        if not verify:
            self.channel.write(b"\xa6")
        self.channel.write(request)
        self.channel.write(data)
        if self.progress is not None:
            self.progress(len(data))
        self._poll(operation, wait_ms)
        if verify:
            self.verified += len(data)
        else:
            self.written += len(data)
            self.channel.transferred += len(data)

    def prepare_retry(self, *, wait_after_dummy_ms: int = 0) -> None:
        """M16C1f00: at most4 A4 probes,3 A8 probes and3 dummy256 writes."""
        _uint(wait_after_dummy_ms, 32, "Dummy wait")
        if wait_after_dummy_ms and self.channel.wait_callback is None:
            raise ValueError("Dummy wait requires explicit wait provider")
        for attempt in range(4):
            if self.status() is not None:
                return
            if attempt == 3:
                raise M16CError("prepare retry", 20)
            if self.verify_status() is not None:
                return
            self.channel.write(bytes(256))
            self.channel.wait(wait_after_dummy_ms)


@dataclass(frozen=True)
class M16CControls:
    """Explicit native transport lifecycle callbacks; cleanup runs after failure."""

    get_timeout: Callable[[], int]
    set_timeout: Callable[[int], None]
    start_filter: Callable[[], int]
    stop_filter: Callable[[int], None]


@dataclass(frozen=True)
class M16COptions:
    location_id: bytes
    parent_password: int
    password: int
    id_address: bytes
    password_suffix: bytes
    receive_timeout_ms: int
    security: bool = False
    nonce: bytes = b""
    key: bytes = b""
    recovery: bool = False
    igoff_retriable: bool = False
    get_memory: bool = False
    swap_endian: bool = False
    wait_after_reprogramming_ms: int = 0
    wait_between_sf_ms: int = 0
    initial_timeout_ms: int = 0
    wait_erase_ms: int = 0
    wait_write_ms: int = 0
    wait_verify_ms: int = 0
    wait_after_write_ms: int = 0
    previous_retry_password: bool = False
    force_retry_password: bool = False
    version: str = "18"

    def __post_init__(self):
        if self.version not in ("12", "18") or (self.security and self.version != "18"):
            raise ValueError("M16C supports CUW12/18; SecurityM16C is CUW18 only")
        m16c_password_frames(self.id_address, self.password, self.password_suffix)
        _uint(self.parent_password, 32, "Parent password")
        if not isinstance(self.location_id, bytes) or len(self.location_id) != 8:
            raise ValueError("Supplied location ID must contain8bytes")
        for field in (
            "security",
            "recovery",
            "igoff_retriable",
            "get_memory",
            "swap_endian",
            "previous_retry_password",
            "force_retry_password",
        ):
            if type(getattr(self, field)) is not bool:
                raise ValueError("Boolean native flags required")
        for field in (
            "receive_timeout_ms",
            "wait_after_reprogramming_ms",
            "wait_between_sf_ms",
            "initial_timeout_ms",
            "wait_erase_ms",
            "wait_write_ms",
            "wait_verify_ms",
            "wait_after_write_ms",
        ):
            _uint(getattr(self, field), 32, field)
        if self.security and (
            not isinstance(self.nonce, bytes)
            or len(self.nonce) != 16
            or not isinstance(self.key, bytes)
            or len(self.key) != 16
        ):
            raise ValueError("SecurityM16C requires supplied nonce16 and key16")


class _Progress:
    def __init__(self, total: int, callback: Callable[[int, int], None] | None):
        if callback is not None and not callable(callback):
            raise ValueError("Progress observer must be callable")
        self.total, self.callback = total, callback
        self.count = self.percent = 0

    def notify(self) -> None:
        if self.callback is not None:
            self.callback(self.count, self.percent)

    def advance(self, amount: int) -> None:
        self.count += amount
        self.notify()
        self.percent = self.count * 100 // self.total
        self.notify()

    def reset(self, *, notify: bool) -> None:
        self.count = 0
        try:
            if notify:
                self.notify()
        finally:
            self.percent = 0
        if notify:
            self.notify()


def _lifecycle(
    channel: VendorCAN,
    controls: M16CControls,
    action: Callable[[], None],
    *,
    restore_timeout: bool = True,
    on_error: Callable[[], None] | None = None,
) -> dict:
    if not isinstance(controls, M16CControls) or any(
        not callable(getattr(controls, name))
        for name in ("get_timeout", "set_timeout", "start_filter", "stop_filter")
    ):
        raise ValueError("Explicit native lifecycle callbacks required")
    result = {
        "state": "failed",
        "programming_completed": False,
        "physical_status": "PHYSICAL_UNCONFIRMED",
        "automatic_retry": False,
        "history": channel.history,
        "provenance": "static-native-CUW18-M16C",
    }
    original = token = None
    failure: BaseException | None = None
    try:
        channel.remaining()
        if restore_timeout:
            original = _uint(controls.get_timeout(), 32, "Original timeout")
            channel.remaining()
        token = _uint(controls.start_filter(), 32, "Filter handle")
        channel.remaining()
        action()
        channel.remaining()
        result["state"] = "writer_completed"
    except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - retain uncertain native write outcome.
        failure = exc
        observed: BaseException = exc
        for _ in range(8):
            previous = observed.__cause__ or observed.__context__
            if previous is None:
                break
            observed = previous
        result["observed_error"] = str(observed) or type(observed).__name__
        try:
            channel.remaining()
        except (Exception, KeyboardInterrupt) as boundary:  # noqa: BLE001 - cancellation/deadline take precedence.
            failure = boundary
        result.update(
            state="recovery_required"
            if channel.attempted
            else "cancelled"
            if isinstance(failure, (InterruptedError, KeyboardInterrupt))
            else "failed",
            error=str(failure) or type(failure).__name__,
            native_error=getattr(failure, "code", None),
        )
        if on_error is not None:
            try:
                on_error()
            except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - retain original failure and still clean up.
                result["progress_callback_error"] = str(exc) or type(exc).__name__
    finally:
        cleanup_errors = []
        if token is not None:
            try:
                controls.stop_filter(token)
            except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - always attempt remaining cleanup.
                cleanup_errors.append(str(exc) or type(exc).__name__)
        if original is not None:
            try:
                controls.set_timeout(original)
            except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - preserve restoration failures.
                cleanup_errors.append(str(exc) or type(exc).__name__)
        if cleanup_errors:
            result.update(state="recovery_required", cleanup_errors=cleanup_errors)
    return result


def m16c_write(
    channel: VendorCAN,
    controls: M16CControls,
    segments: tuple[M16CSegment, ...],
    options: M16COptions,
    *,
    finish_channel: VendorCAN | None = None,
    last_cpu: bool = True,
    progress: Callable[[int, int], None] | None = None,
) -> dict:
    """Native M16C/SecurityM16C full selected-parent writer; one page write+verify."""
    if not isinstance(options, M16COptions):
        raise TypeError("Explicit M16C options required")
    if (
        not isinstance(segments, tuple)
        or not 1 <= len(segments) <= 255
        or any(not isinstance(segment, M16CSegment) for segment in segments)
        or sum(len(segment.data) for segment in segments) > 64 * 1024 * 1024
    ):
        raise ValueError("Bounded complete M16C segments required")
    if type(last_cpu) is not bool or (last_cpu and finish_channel is None):
        raise ValueError("Last CPU requires an explicitly addressed finish channel")
    waits = [options.wait_erase_ms, options.wait_write_ms, options.wait_verify_ms]
    if not options.recovery or options.igoff_retriable:
        waits.extend((options.wait_after_reprogramming_ms, options.wait_between_sf_ms))
    if options.security:
        waits.append(options.wait_between_sf_ms)
    else:
        waits.append(options.wait_after_write_ms)
    for wait_ms in waits:
        _wait_context(channel, wait_ms)
    progress_state = _Progress(
        sum(len(segment.data) for segment in segments) * 2, progress
    )
    writer = M16CWriter(channel, progress_state.advance)
    observed: dict = {}

    def run():
        if not options.recovery or options.igoff_retriable:
            channel.wait(options.wait_after_reprogramming_ms)
            observed["check_id_hex"] = _native_phase(
                channel,
                "parent CheckID",
                7,
                lambda: channel.check_id(
                    options.location_id,
                    options.parent_password,
                    swap_endian=options.swap_endian,
                    wait_ms=options.wait_between_sf_ms,
                    first_timeout_ms=options.initial_timeout_ms,
                    set_timeout=lambda ms, _remaining: controls.set_timeout(ms),
                ),
            ).hex()
        if options.security:
            _native_phase(
                channel,
                "nonce/key",
                0x48,
                lambda: channel.auth_combined(
                    options.nonce, options.key, wait_ms=options.wait_between_sf_ms
                ),
            )
        elif options.get_memory:
            observed["memory_info"] = _native_phase(
                channel, "watch memory info", 10, channel.memory_info
            )
        controls.set_timeout(options.receive_timeout_ms)
        channel.remaining()
        if not options.recovery or options.igoff_retriable:
            writer.password_check(
                options.id_address, options.password, options.password_suffix
            )
        for segment in segments:
            writer.erase(
                segment.address + len(segment.data) - 1, wait_ms=options.wait_erase_ms
            )
            for offset in range(0, len(segment.data), 256):
                data = segment.data[offset : offset + 256]
                writer.page(
                    segment.address + offset, data, wait_ms=options.wait_write_ms
                )
                writer.page(
                    segment.address + offset,
                    data,
                    verify=True,
                    wait_ms=options.wait_verify_ms,
                )
        # Plain M16C reads WaitTimeAfterFlashWrite; SecurityM16C does not.
        if not options.security:
            channel.wait(options.wait_after_write_ms)
        if last_cpu:
            assert finish_channel is not None
            channel.remaining()
            _finish(channel, finish_channel)
            channel.remaining()
        else:
            _native_phase(channel, "change CPU", 0x13, channel.change_cpu)

    result = _lifecycle(
        channel,
        controls,
        run,
        on_error=lambda: progress_state.reset(notify=options.version == "18"),
    )
    error = result.get("native_error") or 0
    result.update(
        family="SecurityM16C" if options.security else "M16C",
        written=writer.written,
        verified=writer.verified,
        **observed,
    )

    if result["state"] != "writer_completed":
        # WritingErrorDispose clears both native progress counters on failure.
        result.update(
            progress_bytes=0,
            progress_percent=0,
            retry_password=retry_password(
                options.previous_retry_password,
                error,
                force=options.force_retry_password,
            ),
        )
    else:
        result.update(
            progress_bytes=writer.written + writer.verified,
            progress_percent=100,
            retry_password=False,
        )
    return result


def m16c_prepare_retry(
    channel: VendorCAN, controls: M16CControls, *, wait_after_dummy_ms: int = 0
) -> dict:
    _wait_context(channel, wait_after_dummy_ms)
    writer = M16CWriter(channel)
    return _lifecycle(
        channel,
        controls,
        lambda: writer.prepare_retry(wait_after_dummy_ms=wait_after_dummy_ms),
        restore_timeout=False,
    )


@dataclass(frozen=True)
class VForestPolicy:
    cpuid: int
    configured_shrink: bool = False
    wait_write_ms: int = 0
    wait_verify_ms: int = 0

    def __post_init__(self):
        _uint(self.cpuid, 8, "CPUIDNo")
        if type(self.configured_shrink) is not bool:
            raise ValueError("Boolean ShrinkFlag required")
        _uint(self.wait_write_ms, 32, "Write wait")
        _uint(self.wait_verify_ms, 32, "Verify wait")


def security_vforest_write(
    channel: VendorCAN,
    controls: M16CControls,
    image: bytes,
    *,
    location_id: bytes,
    password: int,
    nonce: bytes,
    key: bytes,
    policy: VForestPolicy,
    finish_channel: VendorCAN | None = None,
    last_cpu: bool = True,
    wait_after_reprogramming_ms: int = 0,
    wait_between_sf_ms: int = 0,
    initial_timeout_ms: int = 0,
    swap_endian: bool = False,
    alternate_policy: Callable[[], VForestPolicy] | None = None,
    previous_retry_password: bool = False,
    force_retry_password: bool = False,
    progress: Callable[[int, int], None] | None = None,
    version: str = "18",
    replacement_password: int | None = None,
) -> dict:
    """Native SecurityVFOREST orchestration; proven identical42/17 body is shared."""
    if version != "18":
        raise ValueError("SecurityVFOREST is a CUW18 family")
    vforest_groups(image)
    from scripts.programming_vendor import common_auth_frames, common_check_id_frames

    common_check_id_frames(location_id, password, swap_endian=swap_endian)
    if previous_retry_password:
        if replacement_password is None:
            raise ValueError(
                "Retry-password branch requires its explicitly resolved new password"
            )
        password = _uint(replacement_password, 32, "Replacement password")
    common_auth_frames(nonce)
    common_auth_frames(key, key=True)
    if (
        not isinstance(policy, VForestPolicy)
        or type(last_cpu) is not bool
        or type(previous_retry_password) is not bool
        or type(force_retry_password) is not bool
        or (last_cpu and finish_channel is None)
    ):
        raise ValueError("Explicit VFOREST CPU/finish context required")
    for value in (wait_after_reprogramming_ms, wait_between_sf_ms, initial_timeout_ms):
        _uint(value, 32, "Native wait/timeout")
    if (
        any(
            (
                wait_after_reprogramming_ms,
                wait_between_sf_ms,
                policy.wait_write_ms,
                policy.wait_verify_ms,
            )
        )
        and channel.wait_callback is None
    ):
        raise ValueError("Native waits require explicit wait provider")
    observed: dict = {}
    transferred_before = channel.transferred
    progress_state = _Progress(len(image) * 2, progress)

    def run():
        channel.wait(wait_after_reprogramming_ms)
        observed["check_id_hex"] = _native_phase(
            channel,
            "CheckID",
            7,
            lambda: channel.check_id(
                location_id,
                password,
                swap_endian=swap_endian,
                wait_ms=wait_between_sf_ms,
                first_timeout_ms=initial_timeout_ms,
                set_timeout=lambda ms, _remaining: controls.set_timeout(ms),
            ),
        ).hex()
        _native_phase(
            channel,
            "nonce/key",
            0x48,
            lambda: channel.auth_combined(nonce, key, wait_ms=wait_between_sf_ms),
        )
        info = _native_phase(channel, "memory info", 10, channel.memory_info)
        observed["memory_info"] = info
        selected = policy

        def matches(value: VForestPolicy) -> bool:
            return common_cpu_matches(
                info["firmware_descriptor"],
                value.cpuid,
                shrink=info["extended"],
                configured_shrink=value.configured_shrink,
            )

        if not matches(selected):
            if alternate_policy is None:
                raise M16CError("CPU compatibility", 10)
            selected = alternate_policy()
            channel.remaining()
            if not isinstance(selected, VForestPolicy) or not matches(selected):
                raise M16CError("alternate CPU compatibility", 10)
            observed["alternate_parameters_loaded"] = True
        _wait_context(channel, selected.wait_write_ms)
        _wait_context(channel, selected.wait_verify_ms)
        _native_phase(
            channel,
            "VFOREST write",
            0x1D,
            lambda: vforest_transfer(
                channel,
                image,
                wait_before_status_ms=selected.wait_write_ms,
                progress=progress_state.advance,
            ),
        )
        _native_phase(
            channel,
            "VFOREST verify",
            0x1E,
            lambda: vforest_transfer(
                channel,
                image,
                verify=True,
                wait_before_status_ms=selected.wait_verify_ms,
                progress=progress_state.advance,
            ),
        )
        _native_phase(channel, "falsification check", 0x49, channel.detect_falsify)
        if last_cpu:
            assert finish_channel is not None
            channel.remaining()
            _finish(channel, finish_channel)
        else:
            _native_phase(channel, "change CPU", 0x13, channel.change_cpu)

    result = _lifecycle(
        channel,
        controls,
        run,
        restore_timeout=False,
        on_error=lambda: progress_state.reset(notify=True),
    )
    written = channel.transferred - transferred_before
    success = result["state"] == "writer_completed"
    return dict(
        result,
        family="SecurityVFOREST",
        written=written,
        progress_bytes=len(image) * 2 if success else 0,
        progress_percent=100 if success else 0,
        retry_password=False
        if success
        else retry_password(
            previous_retry_password,
            result.get("native_error") or 0,
            force=force_retry_password,
        ),
        **observed,
    )


@dataclass(frozen=True)
class M16CInputs:
    """Imported, selected native arguments; constructing these performs no I/O."""

    module: str
    stage: str
    native_build: int
    container_sha256: str
    cpu_index: int
    parent_index: int | None
    last_cpu: bool
    target_metadata: tuple[Address, ...]
    segments: tuple[M16CSegment, ...] = dataclass_field(default=(), repr=False)
    options: M16COptions | None = dataclass_field(default=None, repr=False)
    image: bytes = dataclass_field(default=b"", repr=False)
    vforest_options: Mapping[str, Any] = dataclass_field(
        default_factory=lambda: MappingProxyType({}), repr=False
    )
    wait_after_dummy_ms: int = 0

    def report(self) -> dict:
        return {
            "module": self.module,
            "stage": self.stage,
            "native_build": self.native_build,
            "container_sha256": self.container_sha256,
            "cpu_index": self.cpu_index,
            "parent_index": self.parent_index,
            "last_cpu": self.last_cpu,
            "addresses": [address.report() for address in self.target_metadata],
            "programming_authorized": False,
            "vehicle_compatibility_validated": False,
        }


def bind_m16c_context(
    container: CalibrationContainer,
    node: int,
    observed_cids: tuple[str, ...],
    selection: CalibrationSelection,
    identity: NativeModuleIdentity,
    attachments: Mapping[str, bytes] | None = None,
    observations: Mapping[str, object] | None = None,
) -> M16CInputs:
    """Native CUW/catalog producer for M16C, SecurityM16C and SecurityVFOREST.

    Images, geometry, CPU types, addresses and passwords come from imported data.
    Only runtime state and explicitly authorized nonce/key bytes are supplied.
    """
    modules = {
        "TCUWCanM16CFlashWriter.dll",
        "TCUWCanSecurityM16CFlashWriter.dll",
        "TCUWCanSecurityVFORESTFlashWriter.dll",
    }
    if (
        not isinstance(container, CalibrationContainer)
        or not isinstance(selection, CalibrationSelection)
        or not isinstance(identity, NativeModuleIdentity)
        or identity.module_name not in modules
        or identify_native_module(identity.sha256, identity.module_name) != identity
        or identity.cuw_build not in ("12", "18")
        or (
            identity.module_name != "TCUWCanM16CFlashWriter.dll"
            and identity.cuw_build != "18"
        )
    ):
        raise ValueError("Exact supported native M16C module/build identity required")
    observations = {} if observations is None else observations
    attachments = {} if attachments is None else attachments
    flags = {"recovery", "previous_retry_password", "force_retry_password"}
    if (
        not isinstance(observations, Mapping)
        or set(observations) - flags - {"stage", "cpu_index", "previous_addresses"}
        or any(
            type(observations[name]) is not bool for name in flags & observations.keys()
        )
        or not isinstance(attachments, Mapping)
        or set(attachments) - {"nonce", "authorized_key"}
    ):
        raise ValueError(
            "Only native runtime observations and nonce/key attachments allowed"
        )
    for value in attachments.values():
        if type(value) is not bytes or len(value) != 16:
            raise ValueError("Native nonce/key attachments require exactly16bytes")
    stage = observations.get("stage", "write")
    if (
        type(stage) is not str
        or stage not in ("write", "prepare_retry")
        or (
            stage == "prepare_retry" and "PrepareRetry" not in identity.callable_exports
        )
    ):
        raise ValueError("Native module does not export the requested M16C stage")
    if selection.value("DLLFileNameForFlashWrite") != identity.module_name:
        raise ValueError("Imported native writer dispatch differs from module identity")
    index = observations.get("cpu_index", 0)
    if type(index) is not int:
        raise ValueError("Observed CPU index must be an integer")
    previous = observations.get("previous_addresses", ())
    if not isinstance(previous, tuple):
        raise TypeError("Previous native addresses require an immutable tuple")
    context = bind_native_cpu_context(
        container,
        node,
        observed_cids,
        selection,
        stage="write",
        cpu_index=index,
        previous_addresses=previous,
    )
    params = context.parameters

    def number(
        name: str, source: Mapping[str, str] = params, *, hexadecimal: bool = False
    ) -> int:
        value = source.get(name, "0") or "0"
        try:
            result = int(value, 16 if hexadecimal else 10)
        except ValueError as error:
            raise ValueError(f"Invalid native numeric parameter {name}") from error
        return _uint(result, 32, name)

    def flag(name: str, source: Mapping[str, str] = params) -> bool:
        value = number(name, source)
        if value not in (0, 1):
            raise ValueError(f"Native parameter {name} must be0/1")
        return bool(value)

    security = identity.module_name != "TCUWCanM16CFlashWriter.dll"
    vforest = identity.module_name == "TCUWCanSecurityVFORESTFlashWriter.dll"
    parent_index = (
        None
        if vforest
        else parent_cpu(
            tuple(cpu.values.get("cputype", "") for cpu in context.cpus),
            tuple(params.get("ParentCPUTypeList", "").splitlines()),
            index,
        )
    )
    target = (
        context
        if parent_index is None
        else bind_native_cpu_context(
            container,
            node,
            observed_cids,
            selection,
            stage="write",
            cpu_index=parent_index,
            previous_addresses=previous,
        )
    )
    last_cpu = index == len(context.cpus) - 1
    if not target.target_metadata or (
        last_cpu and stage == "write" and len(target.target_metadata) != 2
    ):
        raise ValueError(
            "Native raw parent/functional communication addresses unavailable"
        )
    # Native M16C CBytes constructors copy two bytes, excluding extended-address byte3.
    addresses = (
        Address(
            target.target_metadata[0].request[:2],
            target.target_metadata[0].response[:2],
        ),
    )
    if last_cpu and stage == "write":
        addresses += (Address(target.target_metadata[1].request[:2], bytes(2)),)
    common = M16CInputs(
        module=identity.module_name,
        stage=stage,
        native_build=int(identity.cuw_build),
        container_sha256=container.digest,
        cpu_index=index,
        parent_index=parent_index,
        last_cpu=last_cpu,
        target_metadata=addresses,
    )
    if stage == "prepare_retry":
        return replace(common, wait_after_dummy_ms=number("WaitTimeAfterSendDummyData"))
    if context.image is None or target.location_id is None:
        raise ValueError("Native writer requires bound CPU image and target LocationID")
    old, replacement = native_cpu_passwords(
        context,
        observed_cids,
        require_new=vforest
        and bool(observations.get("previous_retry_password", False)),
        resolve_new=vforest
        and bool(observations.get("previous_retry_password", False)),
    )

    def authorization(name: str, metadata_name: str) -> bytes:
        value = context.selected.values.get(metadata_name, "")
        if value and re.fullmatch(r"[0-9a-fA-F]{32}", value) is None:
            raise ValueError("Invalid imported native nonce/key metadata")
        native = bytes.fromhex(value) if value else None
        supplied = attachments.get(name)
        if native is not None and supplied is not None and native != supplied:
            raise ValueError(
                "Authorization attachment disagrees with imported metadata"
            )
        result = native if native is not None else supplied
        if result is None:
            raise ValueError("Explicit native nonce/key authorization is unavailable")
        return result

    nonce, key = (
        (authorization("nonce", "nonce"), authorization("authorized_key", "seedkey"))
        if security
        else (b"", b"")
    )
    if vforest:

        def policy(source: Mapping[str, str]) -> VForestPolicy:
            if not source.get("CPUIDNo"):
                raise ValueError("Selected native VFOREST CPU lacks CPUIDNo")
            return VForestPolicy(
                number("CPUIDNo", source, hexadecimal=True),
                flag("ShrinkFlag", source),
                number("WaitTimeBeforeStatusCheckForWriteBlock", source),
                number("WaitTimeBeforeStatusCheckForVerify", source),
            )

        def alternate_policy() -> VForestPolicy:
            # Native LoadParameter runs only after the current CPU gate fails.
            selected = selection.catalog.select_metadata(
                context.base_metadata["kind_of_ecu"],
                params["AlternateCPUType"],
                context.base_metadata["contact_type"],
                stage="write",
                required_spec=context.base_metadata["required_spec"],
            )
            return policy(
                {
                    name: selected.value(name)
                    for name in (
                        "CPUIDNo",
                        "ShrinkFlag",
                        "WaitTimeBeforeStatusCheckForWriteBlock",
                        "WaitTimeBeforeStatusCheckForVerify",
                    )
                }
            )

        kwargs: dict[str, Any] = {
            "location_id": target.location_id,
            "password": old,
            "nonce": nonce,
            "key": key,
            "policy": policy(params),
            "last_cpu": last_cpu,
            "version": identity.cuw_build,
            "wait_after_reprogramming_ms": number("WaitTimeAfterReprogrammingMode"),
            "wait_between_sf_ms": number("WaitTimeBetweenSF"),
            "initial_timeout_ms": number("ReceiveTimeoutBeforeInitialCommand"),
            "swap_endian": flag("BigEndianFlag"),
            "previous_retry_password": observations.get(
                "previous_retry_password", False
            ),
            "force_retry_password": observations.get("force_retry_password", False),
            "replacement_password": replacement,
        }
        if params.get("AlternateCPUType"):
            kwargs["alternate_policy"] = alternate_policy
        vforest_groups(context.image.data)
        return replace(
            common, image=context.image.data, vforest_options=MappingProxyType(kwargs)
        )
    parent_password, _ = native_cpu_passwords(target, observed_cids, resolve_new=False)

    def byte_parameters(name: str) -> bytes:
        values = params.get(name, "").splitlines()
        if len(values) != 3 or any(
            re.fullmatch(r"(?:[0-9a-fA-F]{2}){1,129}", value) is None
            for value in values
        ):
            raise ValueError(
                f"Native {name} requires three bounded hexadecimal strings"
            )
        # Password2430 copies CBytes(string)[0], even for multi-byte parameters.
        return bytes(bytes.fromhex(value)[0] for value in values)

    blocks = parse_block_info(params.get("BlockSizeInfo", ""))
    starts = params.get("StartAddress", "").splitlines()
    if any(re.fullmatch(r"[0-9a-fA-F]{1,8}", value) is None for value in starts):
        raise ValueError(
            "Native StartAddress list must contain bounded hexadecimal addresses"
        )
    segments = m16c_segments(
        context.image.data,
        tuple(int(value, 16) for value in starts),
        tuple(block.size_kib for block in blocks),
    )
    options = M16COptions(
        target.location_id,
        parent_password,
        old,
        byte_parameters("PasswordCheckIDAddress"),
        byte_parameters("PasswordCheckPassword"),
        number("ReceiveTimeoutBeforeFlashWrite"),
        security=security,
        nonce=nonce,
        key=key,
        recovery=bool(observations.get("recovery", False)),
        igoff_retriable=flag("IGOffRetriableFlag"),
        get_memory=not security and flag("GetMemoryInfoForWatchCPUFlag"),
        swap_endian=flag("BigEndianFlag"),
        wait_after_reprogramming_ms=number("WaitTimeAfterReprogrammingMode"),
        wait_between_sf_ms=number("WaitTimeBetweenSF"),
        initial_timeout_ms=number("ReceiveTimeoutBeforeInitialCommand"),
        wait_erase_ms=number("WaitTimeBeforeStatusCheckForEraseBlock"),
        wait_write_ms=number("WaitTimeBeforeStatusCheckForWriteBlock"),
        wait_verify_ms=number("WaitTimeBeforeStatusCheckForVerify"),
        wait_after_write_ms=number("WaitTimeAfterFlashWrite"),
        previous_retry_password=bool(
            observations.get("previous_retry_password", False)
        ),
        force_retry_password=bool(observations.get("force_retry_password", False)),
        version=identity.cuw_build,
    )
    return replace(common, segments=segments, options=options)
