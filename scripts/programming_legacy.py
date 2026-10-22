"""Bounded native P4/P5 programming codecs over explicitly injected replay I/O.

No original DLL is loaded and no authorization material is derived. Transport
providers bind the exact native communication addresses outside these codecs.
"""

from __future__ import annotations

import hashlib
import math
import re
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scripts.calibration import CalibrationContainer, NativeCPU
    from scripts.calibration_catalog import Address, CalibrationSelection
    from scripts.native_modules import NativeModuleIdentity

from scripts.programming import (
    NativeDiagnosticError as SharedNativeDiagnosticError,
)
from scripts.programming import (
    NativeNegativeResponse,
    NativePendingTimeout,
    NativeProgrammingChannel,
    NativeUnexpectedResponse,
    decode_native_data,
    native_data_request,
)
from scripts.programming import (
    NativeTransportError as LegacyTransportError,
)
from scripts.programming_vendor import (
    NativeDiagnosticError,
    VendorCAN,
    VendorDiagnosticChannel,
    VendorInitialCommandError,
    VendorOperationError,
    VendorStatusAckError,
    VendorUtilityTimeout,
    common_block_request,
    common_cpu_matches,
)
from scripts.programming_vendor import NativeTransportError as VendorTransportError


def _lifecycle_action(
    callback: Callable, operation: str, parameters: dict, remaining: float
):
    result = callback(operation, parameters, remaining)
    if operation in ("get_timeout", "get_send_timeout", "start_filter"):
        if type(result) is not int or not 0 <= result <= 0xFFFFFFFF:
            raise ValueError("Native lifecycle result must be uint32")
    elif result is not None:
        raise ValueError("Native void lifecycle callback must return None")
    return result


def _guarded_callback(callback, boundary, *, defer_filter_result=False):
    def invoke(*args):
        try:
            result = callback(*args)
        except (Exception, KeyboardInterrupt) as error:
            try:
                boundary()
            except (Exception, KeyboardInterrupt) as limit:
                raise limit from error
            raise
        # The caller must retain an acquired filter ID before its boundary check.
        if not (defer_filter_result and args and args[0] == "start_filter"):
            boundary()
        return result

    return invoke


def _failure_chain(error):
    result, seen = [], set()
    while error is not None and id(error) not in seen and len(result) < 8:
        seen.add(id(error))
        result.append(type(error).__name__)
        error = error.__cause__ if error.__cause__ is not None else error.__context__
    return result


def _legacy_diagnostic_call(channel, request, expected, native_code=None):
    if isinstance(channel, VendorDiagnosticChannel):
        try:
            return channel.call(request, expected)
        except (
            NativeNegativeResponse,
            SharedNativeDiagnosticError,
            NativePendingTimeout,
            VendorUtilityTimeout,
        ) as error:
            error.__dict__["native_cuw_code"] = native_code
            raise
    prior_timeout = channel.pending_response_timeout_seconds
    prior_write = channel.pending_timeout_write

    def missing_cleanup(ecu, payload):
        raise ValueError(
            "Native legacy pending expiry requires explicit write-only provider"
        )

    channel.pending_response_timeout_seconds = 180
    channel.pending_timeout_write = prior_write or missing_cleanup
    try:
        return channel.call(request, expected)
    except (
        NativeNegativeResponse,
        SharedNativeDiagnosticError,
        NativePendingTimeout,
        VendorUtilityTimeout,
    ) as error:
        error.__dict__["native_cuw_code"] = native_code
        raise
    finally:
        channel.pending_response_timeout_seconds = prior_timeout
        channel.pending_timeout_write = prior_write


def _legacy_operation_ack(channel, code):
    try:
        channel.ack()
    except (VendorTransportError, LegacyTransportError) as error:
        if error.code not in (9, 16):
            raise
        raise VendorOperationError(code, "Native operation ACK failed") from error


def legacy_security(
    channel: NativeProgrammingChannel,
    request: bytes,
    seed_size: int,
    key_provider: Callable[[bytes], bytes],
    *,
    seed_suffix: bytes = b"",
    key_suffix: bytes = b"",
    wait_ms: int = 0,
    wait: Callable[[int], None] | None = None,
) -> None:
    """Run a recovered seed/key exchange using an explicitly authorized provider.

    Native P4 Airbag/Sonar use2703+password2, seed2 and suffix34;
    Body uses2761, seed6 and key suffix34; Chassis uses2701+CPU, seed4.
    The request and exact width are supplied by the family runner.
    """
    if (
        not isinstance(request, bytes)
        or not 2 <= len(request) <= 258
        or request[0] != 0x27
        or request[1] % 2 != 1
        or type(seed_size) is not int
        or seed_size not in (2, 4, 6, 16)
        or not isinstance(seed_suffix, bytes)
        or len(seed_suffix) > 1
        or not isinstance(key_suffix, bytes)
        or len(key_suffix) > 1
        or type(wait_ms) is not int
        or not 0 <= wait_ms <= 0xFFFFFFFF
        or (wait_ms and wait is None)
    ):
        raise ValueError("Invalid native security exchange context")
    response = _legacy_diagnostic_call(channel, request, bytes((0x67, request[1])), 16)
    end = 2 + seed_size
    if (
        len(response) < end + len(seed_suffix)
        or response[end : end + len(seed_suffix)] != seed_suffix
    ):
        raise VendorOperationError(16, "Malformed native security seed response")
    key = key_provider(response[2:end])
    if not isinstance(key, bytes) or len(key) != seed_size:
        raise ValueError("Authorized provider returned an invalid key width")
    if wait_ms:
        assert wait is not None
        wait(wait_ms)
    _legacy_diagnostic_call(
        channel,
        bytes((0x27, request[1] + 1)) + key,
        bytes((0x67, request[1] + 1)) + key_suffix,
        17,
    )


def cxpi_erase(
    channel: VendorCAN,
    first: int,
    last: int,
    tester_present: Callable[[], None],
    *,
    wait_before_status_ms: int = 0,
) -> None:
    """Native CXPI1c60: wide erase, three3e02 sends and four2000ms waits.

    tester_present is bound to the catalog's first prepare address with native
    extended addressing/TX flag0x80; it sends3e02 without waiting for a response.
    The raw-CAN channel remains bound to the writer's own request/response pair.
    """
    if (
        type(wait_before_status_ms) is not int
        or not 0 <= wait_before_status_ms <= 0xFFFFFFFF
    ):
        raise ValueError("Invalid native erase status wait")
    request = common_block_request("erase", first, last, wide=True)
    channel.write(request)
    _legacy_operation_ack(channel, 12)
    for _ in range(3):
        channel.wait(2000)
        tester_present()
        channel.remaining()
    channel.wait(2000)
    if channel.poll(wait_ms=wait_before_status_ms):
        raise VendorOperationError(12, "Native CXPI erase failed")


def vforest_groups(image: bytes) -> tuple[bytes, ...]:
    """VFOREST1ad0 record lengths: ZV00 adds5, ZV01 adds7 to BE16 length.

    Other native prefixes add zero. Host bounds reject truncated/zero-length
    records rather than reproducing native out-of-bounds access or endless loops.
    """
    if not isinstance(image, bytes) or not 0 < len(image) <= 64 * 1024 * 1024:
        raise ValueError("Bounded immutable VFOREST image required")
    result = []
    offset = 0
    while offset < len(image):
        if len(result) >= 65536 or len(image) - offset < 5:
            raise ValueError("VFOREST record count or header bound exceeded")
        prefix = image[offset : offset + 3]
        overhead = 5 if prefix == b"ZV\x00" else 7 if prefix == b"ZV\x01" else 0
        length = int.from_bytes(image[offset + 3 : offset + 5], "big") + overhead
        if length < 5 or offset + length > len(image):
            raise ValueError("Malformed VFOREST record length")
        result.append(image[offset : offset + length])
        offset += length
    return tuple(result)


def vforest_transfer(
    channel: VendorCAN,
    image: bytes,
    *,
    verify: bool = False,
    wait_before_status_ms: int = 0,
    progress: Callable[[int], None] | None = None,
) -> None:
    """VFOREST1c20/1f20:42(write)/17(verify), grouped1024-byte raw chunks."""
    if (
        type(verify) is not bool
        or type(wait_before_status_ms) is not int
        or not 0 <= wait_before_status_ms <= 0xFFFFFFFF
    ):
        raise ValueError("Invalid VFOREST transfer context")
    groups = vforest_groups(image)
    code = 30 if verify else 29
    try:
        channel.write(
            bytes((0x17 if verify else 0x42, 0, 0))
            + (len(groups) - 1).to_bytes(2, "big")
            + b"\xff"
        )
        _legacy_operation_ack(channel, code)
        for group in groups:
            for offset in range(0, len(group), 1024):
                fragment = group[offset : offset + 1024]
                channel.write(fragment)
                if progress is not None:
                    progress(len(fragment))
                _legacy_operation_ack(channel, code)
                if channel.poll(
                    wait_ms=wait_before_status_ms, busy=0x20 if verify else 0x40
                ):
                    raise VendorOperationError(
                        code, "Native VFOREST transfer status failed"
                    )
                if not verify:
                    channel.transferred += len(fragment)
    except (VendorTransportError, LegacyTransportError) as error:
        # Native catches retain the transport exception and replace its code.
        error.code = code
        raise
    except VendorStatusAckError as error:
        raise VendorOperationError(code, "Native VFOREST status failed") from error


def decode_legacy_cids(response: bytes, *, p5: bool = True) -> tuple[str, ...]:
    """Native CID1ba0/1ac0: exact count*16 framing and ANSI NUL truncation.

    Prefix validation belongs to the native exchange utility. The native parser
    itself accepts the header bytes as opaque and checks length and count only.
    """
    header = 4 if p5 else 3
    if (
        type(p5) is not bool
        or not isinstance(response, bytes)
        or not header + 16 <= len(response) <= 4095
    ):
        raise ValueError("Malformed legacy CID response size")
    count = response[header - 1]
    if len(response) != header + count * 16:
        raise ValueError("Legacy CID count does not match response size")
    result = []
    for offset in range(header, len(response), 16):
        value = response[offset : offset + 16].split(b"\0", 1)[0]
        if value:
            result.append(value.decode("latin-1"))
    return tuple(result)


@dataclass(frozen=True)
class BlockInfo:
    """Native zero-based first block, size in KiB, and number of blocks."""

    start: int
    size_kib: int
    count: int

    def __post_init__(self) -> None:
        if any(
            type(value) is not int or not 0 <= value <= 65535
            for value in (self.start, self.size_kib, self.count)
        ):
            raise ValueError("Invalid native block info")


def parse_block_info(value: str) -> tuple[BlockInfo, ...]:
    """FlashWriterUtils28d0 splits decimal triples on any comma, colon or x."""
    if not isinstance(value, str) or not 1 <= len(value) <= 259:
        raise ValueError("Bounded BlockSizeInfo string required")
    tokens = [token.strip() for token in re.split("[,:x]", value) if token]
    if (
        not tokens
        or len(tokens) % 3
        or any(not re.fullmatch(r"[+]?[0-9]+", token) for token in tokens)
    ):
        raise ValueError("Malformed native BlockSizeInfo triples")
    return tuple(
        BlockInfo(*(int(token) for token in tokens[index : index + 3]))
        for index in range(0, len(tokens), 3)
    )


def complete_block_info(
    info: Sequence[BlockInfo], address: int, end_address: int, default_size_kib: int
) -> tuple[BlockInfo, ...]:
    """Native1460 fills zero sizes and the final zero count from inclusive memory."""
    if (
        not info
        or len(info) > 87
        or any(not isinstance(item, BlockInfo) for item in info)
        or type(address) is not int
        or type(end_address) is not int
        or not 0 <= address <= end_address <= 0xFFFFFFFF
        or type(default_size_kib) is not int
        or not 0 <= default_size_kib <= 255
    ):
        raise ValueError("Invalid native memory/block completion context")
    result = [
        BlockInfo(item.start, item.size_kib or default_size_kib, item.count)
        for item in info
    ]
    last = result[-1]
    if not last.size_kib:
        raise ValueError("Native block size remains zero")
    if not last.count:
        count = (
            (end_address - address + 1) // (last.size_kib * 1024)
            - last.start
            + result[0].start
        )
        result[-1] = BlockInfo(last.start, last.size_kib, count)
    return tuple(result)


def block_sizes(info: Sequence[BlockInfo]) -> tuple[int, ...]:
    """Native1bf0 expands groups, filling inter-group gaps with the next size."""
    if (
        not info
        or len(info) > 87
        or any(not isinstance(item, BlockInfo) for item in info)
    ):
        raise ValueError("Bounded block info required")
    result = []
    previous_end = None
    for item in info:
        gap = 0 if previous_end is None else item.start - previous_end
        if (
            gap < 0
            or not item.size_kib
            or not item.count
            or len(result) + gap + item.count > 65536
        ):
            raise ValueError("Invalid or excessive native block sizes")
        result.extend([item.size_kib * 1024] * (gap + item.count))
        previous_end = item.start + item.count
    if sum(result) > 64 * 1024 * 1024:
        raise ValueError("Block byte budget exceeded")
    return tuple(result)


def block_ranges(
    info: Sequence[BlockInfo], *, grouped: bool = False, s0_header: bytes | None = None
) -> tuple[tuple[int, int], ...]:
    """Native2190/24f0/2540 returns one-based ranges; S0 endpoints are zero-based."""
    if type(grouped) is not bool:
        raise ValueError("Boolean group mode required")
    sizes = block_sizes(info)
    if s0_header is None:
        return (
            tuple((item.start + 1, item.start + item.count) for item in info)
            if grouped
            else tuple((index, index) for index in range(1, len(sizes) + 1))
        )
    if not isinstance(s0_header, bytes) or len(s0_header) > 1024 * 1024:
        raise ValueError("Bounded immutable S0 bytes required")
    result = []
    offset = 0
    while offset < len(s0_header):
        if s0_header[offset : offset + 4] == b"\xaa\x55\xaa\x55":
            if len(s0_header) - offset < 8:
                raise ValueError("Truncated native S0 block header")
            count = s0_header[offset + 7]
            end = offset + 8 + count * 4
            if end > len(s0_header):
                raise ValueError("Truncated native S0 block ranges")
            for position in range(offset + 8, end, 4):
                first = int.from_bytes(s0_header[position : position + 2], "big")
                last = int.from_bytes(s0_header[position + 2 : position + 4], "big")
                if (
                    first > last
                    or last >= len(sizes)
                    or len(result) + last - first + 1 > 65536
                ):
                    raise ValueError("Invalid native S0 block endpoints")
                result.extend(
                    (index + 1, index + 1) for index in range(first, last + 1)
                )
            offset = end
        else:
            offset += 1
    if not result:
        raise ValueError("S0 contains no native block ranges")
    return tuple(result)


@dataclass(frozen=True)
class LegacyBlock:
    first: int
    last: int
    address: int
    data: bytes = field(repr=False)


def legacy_blocks(
    image: bytes,
    sizes: Sequence[int],
    ranges: Sequence[tuple[int, int]],
    base_address: int,
) -> tuple[LegacyBlock, ...]:
    """Native WriteBlock mapping with explicit host bounds before destructive I/O."""
    if (
        not isinstance(image, bytes)
        or not 0 < len(image) <= 64 * 1024 * 1024
        or not sizes
        or len(sizes) > 65536
        or not ranges
        or len(ranges) > 65536
        or any(
            type(size) is not int or not 0 <= size <= 64 * 1024 * 1024 for size in sizes
        )
        or sum(sizes) > 64 * 1024 * 1024
        or type(base_address) is not int
        or not 0 <= base_address <= 0xFFFFFFFF
    ):
        raise ValueError("Invalid bounded native image/block mapping")
    offsets = [0]
    for size in sizes:
        offsets.append(offsets[-1] + size)
    result = []
    previous = 0
    for first, last in ranges:
        if (
            type(first) is not int
            or type(last) is not int
            or not previous < first <= last <= len(sizes)
            or not sizes[first - 1]
            or any(size != sizes[first - 1] for size in sizes[first - 1 : last])
        ):
            raise ValueError("Native block ranges overlap or cross unequal sizes")
        offset = offsets[first - 1]
        length = (last - first + 1) * sizes[first - 1]
        address = base_address + offset
        if offset + length > len(image) or address + length > 0x100000000:
            raise ValueError("Native block mapping exceeds image/address bounds")
        result.append(
            LegacyBlock(first, last, address, image[offset : offset + length])
        )
        previous = last
    return tuple(result)


@dataclass(frozen=True)
class LegacyTarget:
    request: bytes
    channel: NativeProgrammingChannel = field(repr=False)

    def __post_init__(self) -> None:
        if (
            not isinstance(self.request, bytes)
            or len(self.request) not in (2, 3)
            or not isinstance(self.channel, NativeProgrammingChannel)
        ):
            raise ValueError(
                "A native two- or three-byte legacy diagnostic target is required"
            )


def legacy_get_cids(
    module: str,
    targets: Sequence[LegacyTarget],
    *,
    query_kind: int = 0,
    allowing_timeout_request: bytes | None = None,
    set_bs: Callable[[int], None] | None = None,
    native_build: int = 18,
    parameters: Mapping[str, str] | None = None,
    lifecycle: Callable[[str, dict, float], object] | None = None,
) -> dict:
    """Execute all three native legacy GetCID entrypoints against replay channels.

    P4P5 queries exactly primaryP5 then secondaryP4. P5 iterates the supplied
    addresses. Only explicit J2534 statuses9/16 on the configured request may be
    skipped; a host deadline, cancellation or malformed response always escapes.
    """
    modules = {
        "TCUWP4P5CanCIDGetter.dll",
        "TCUWP5CanCIDGetter.dll",
        "TCUWP5CanCIDGetterWithSetBS.dll",
    }
    if (
        module not in modules
        or type(native_build) is not int
        or native_build not in (12, 18)
        or not targets
        or len(targets) > 32
        or any(
            not isinstance(target, LegacyTarget) or len(target.request) != 2
            for target in targets
        )
        or type(query_kind) is not int
        or not 0 <= query_kind <= 255
        or (
            allowing_timeout_request is not None
            and (
                not isinstance(allowing_timeout_request, bytes)
                or len(allowing_timeout_request) != 2
            )
        )
    ):
        raise ValueError("Invalid legacy CID module/target context")
    mixed = module == "TCUWP4P5CanCIDGetter.dll"
    if mixed and len(targets) != 2:
        raise ValueError("Native P4P5 getter requires both exact target pairs")
    for index, target in enumerate(targets):
        old = mixed and index == 1
        if old != isinstance(target.channel, VendorDiagnosticChannel):
            raise ValueError(
                "Target channel must implement the native P4/P5 retry policy"
            )
    if any(target.channel.cancelled() for target in targets):
        raise InterruptedError("Legacy CID operation cancelled")
    if any(target.channel.clock() >= target.channel.deadline for target in targets):
        raise TimeoutError("Legacy CID deadline expired")
    with_bs = module.endswith("WithSetBS.dll")
    if with_bs and set_bs is None:
        raise ValueError("Native getter requires explicit BS configuration provider")
    if lifecycle is not None and (
        not callable(lifecycle) or not isinstance(parameters, Mapping)
    ):
        raise ValueError("Native CID lifecycle requires selected parameter row")
    receive_timeout = _number(parameters or {}, "ReceiveTimeoutBeforeGetCID")
    connected = False
    bs_attempted = False

    def budget(cleanup=False):
        if not cleanup and any(target.channel.cancelled() for target in targets):
            raise InterruptedError("Legacy CID operation cancelled")
        value = min(
            target.channel.deadline - target.channel.clock() for target in targets
        )
        if value <= 0 and not cleanup:
            raise TimeoutError("Legacy CID deadline expired")
        return max(0.0, value)

    if set_bs is not None:
        set_bs = _guarded_callback(set_bs, budget)
    cleanup_errors = []
    primary_error = None
    result = None
    if lifecycle is not None:
        lifecycle = _guarded_callback(lifecycle, budget, defer_filter_result=True)

    def cleanup(operation, action):
        try:
            action()
        except (Exception, KeyboardInterrupt) as error:  # noqa: BLE001 - preserve state across injected callback failures
            cleanup_errors.append((operation, error))

    try:
        if lifecycle is not None:
            connected = True
            _lifecycle_action(lifecycle, "connect", {"protocol": 6}, budget())
            _lifecycle_action(
                lifecycle, "set_timeout", {"milliseconds": receive_timeout}, budget()
            )
        if with_bs:
            assert set_bs is not None
            bs_attempted = True
            set_bs(1)
        cids = []
        rows = []
        auxiliary = []
        skipped = []
        optional_errors = []
        address_metadata = []
        for index, target in enumerate(targets):
            p5 = not mixed or index == 0
            filter_id = None
            try:
                if lifecycle is not None:
                    filter_id = _lifecycle_action(
                        lifecycle, "start_filter", {"target_index": index}, budget()
                    )
                    budget()
                if not p5:
                    support = _legacy_diagnostic_call(
                        target.channel, b"\x09\x00", None, 3
                    )
                    if len(support) != 6 or not support[2] & 0x30:
                        raise ValueError(
                            "Native P4 calibration-ID support check failed"
                        )
                response = _legacy_diagnostic_call(
                    target.channel, b"\x22\xf1\x81" if p5 else b"\x09\x04", None, 3
                )
                decoded = decode_legacy_cids(response, p5=p5)
                if len(cids) + len(decoded) > 4096:
                    raise ValueError("Legacy CID result budget exceeded")
                cids.extend(decoded)
                if native_build == 18:
                    address_metadata.extend(
                        {"flag": 0, "request_id": target.request.hex().upper()}
                        for cid in decoded[: max(0, 32 - len(address_metadata))]
                    )
                rows.extend(
                    {"target": target.request.hex(), "cid": cid}
                    for cid in decoded[: max(0, 32 - len(rows))]
                )
                names = (
                    ("slave_cid", "assembly_p5", "serial", "cbest")
                    if native_build == 18 and p5 and query_kind == 2
                    else ("assembly_p4",)
                    if native_build == 18 and not p5 and query_kind != 2
                    else ()
                )
                values = {}
                for name in names:
                    spec = native_data_request(name)
                    try:
                        raw = _legacy_diagnostic_call(
                            target.channel,
                            bytes.fromhex(spec["request_hex"]),
                            bytes.fromhex(spec["response_prefix_hex"]),
                            {
                                "slave_cid": 3,
                                "assembly_p5": 92,
                                "assembly_p4": 92,
                                "serial": 94,
                                "cbest": 3,
                            }[name],
                        )
                        if len(raw) < spec["minimum_response_bytes"]:
                            error = NativeUnexpectedResponse(
                                bytes.fromhex(spec["request_hex"]), raw
                            )
                            error.__dict__["native_cuw_code"] = {
                                "slave_cid": 3,
                                "assembly_p5": 92,
                                "assembly_p4": 92,
                                "serial": 94,
                                "cbest": 3,
                            }[name]
                            raise error
                        values[name] = decode_native_data(name, raw)
                    except (
                        NativeNegativeResponse,
                        NativePendingTimeout,
                        LegacyTransportError,
                        VendorTransportError,
                        SharedNativeDiagnosticError,
                    ) as error:
                        if name == "assembly_p4":
                            raise
                        values[name] = [] if name == "slave_cid" else ""
                        optional_errors.append(
                            {
                                "target": target.request.hex(),
                                "helper": name,
                                "error_type": type(error).__name__,
                                "native_error_code": getattr(
                                    error, "native_cuw_code", None
                                ),
                            }
                        )
                auxiliary.append({"target": target.request.hex(), "values": values})
            except (LegacyTransportError, VendorTransportError) as error:
                if mixed or error.code not in (9, 16):
                    raise
                allowed_request = allowing_timeout_request
                configured = (parameters or {}).get("RequestCANIDAllowingTimeout", "")
                if configured:
                    if not re.fullmatch(r"[0-9a-fA-F]{4}", configured):
                        raise ValueError(
                            "Native timeout-allowed request must contain two hexadecimal bytes"
                        ) from error
                    imported_request = bytes.fromhex(configured)
                    if (
                        allowed_request is not None
                        and allowed_request != imported_request
                    ):
                        raise ValueError(
                            "Explicit timeout allowance conflicts with native parameter"
                        ) from error
                    allowed_request = imported_request
                if target.request != allowed_request:
                    raise
                skipped.append(target.request.hex())
            finally:
                if filter_id is not None:
                    assert lifecycle is not None
                    cleanup(
                        "stop_filter",
                        lambda filter_id=filter_id: _lifecycle_action(
                            lifecycle,
                            "stop_filter",
                            {"filter_id": filter_id},
                            budget(True),
                        ),
                    )
            if cleanup_errors:
                raise cleanup_errors[-1][1]
        result = {
            "state": "complete",
            "module": module,
            "native_build": native_build,
            "cids": cids,
            "cid_addresses": rows,
            "address_metadata": address_metadata,
            "cid_address_association": "host-observed-target-association",
            "auxiliary": auxiliary,
            "skipped_timeout_targets": skipped,
            "optional_errors": optional_errors,
            "vehicle_compatibility_validated": False,
            "programming_authorized": False,
            "provenance": "native-legacy-GetCID-codecs-and-replay",
        }
    except (Exception, KeyboardInterrupt) as error:  # noqa: BLE001 - preserve state across injected callback failures
        primary_error = error
    finally:
        if bs_attempted:
            assert set_bs is not None
            cleanup("set_bs", lambda: set_bs(0))
        if connected:
            assert lifecycle is not None
            cleanup(
                "disconnect",
                lambda: _lifecycle_action(lifecycle, "disconnect", {}, budget(True)),
            )
    try:
        budget()
    except (Exception, KeyboardInterrupt) as boundary:  # noqa: BLE001 - preserve state across injected callback failures
        if primary_error is not None:
            boundary.__cause__ = primary_error
        primary_error = boundary
    if primary_error is None and cleanup_errors:
        primary_error = cleanup_errors[0][1]
    if primary_error is not None:
        if cleanup_errors:
            details = tuple(
                {
                    "operation": operation,
                    "error_type": type(error).__name__,
                    "error_chain": _failure_chain(error),
                }
                for operation, error in cleanup_errors
            )
            primary_error.add_note("Legacy CID cleanup failures: " + repr(details))
            primary_error.__dict__["legacy_cleanup_errors"] = details
        raise primary_error
    assert result is not None
    return result


@dataclass(frozen=True)
class LegacyCPU:
    """Explicit native metadata and authorized input for one selected CPU image."""

    image: bytes = field(repr=False)
    location_id: bytes = field(repr=False)
    password: int = field(repr=False)
    parameters: Mapping[str, str] = field(repr=False)
    cpu_index: int = 0
    cpu_count: int = 1
    s0_header: bytes | None = field(default=None, repr=False)
    nonce: bytes | None = field(default=None, repr=False)
    authorized_key: bytes | None = field(default=None, repr=False)
    id_big_endian: bool | None = None
    native_retry_flag_72c: bool = False
    native_retry_flag_728: bool = False
    native_flag_740: bool = False
    password_is_new: bool = False
    alternate_password: int | None = field(default=None, repr=False)
    alternate_parameters: Mapping[str, str] | Callable[[], Mapping[str, str]] | None = (
        field(default=None, repr=False)
    )
    flash_size: int | None = None

    def __post_init__(self) -> None:
        if (
            not isinstance(self.image, bytes)
            or not 0 < len(self.image) <= 64 * 1024 * 1024
            or not isinstance(self.location_id, bytes)
            or len(self.location_id) != 8
            or type(self.password) is not int
            or not 0 <= self.password <= 0xFFFFFFFF
            or type(self.cpu_index) is not int
            or type(self.cpu_count) is not int
            or not 0 <= self.cpu_index < self.cpu_count <= 128
            or any(
                type(flag) is not bool
                for flag in (
                    self.native_retry_flag_72c,
                    self.native_retry_flag_728,
                    self.native_flag_740,
                    self.password_is_new,
                )
            )
            or (
                self.alternate_password is not None
                and (
                    type(self.alternate_password) is not int
                    or not 0 <= self.alternate_password <= 0xFFFFFFFF
                )
            )
            or (
                self.flash_size is not None
                and (
                    type(self.flash_size) is not int
                    or not 0 < self.flash_size <= 64 * 1024 * 1024
                )
            )
            or (self.id_big_endian is not None and type(self.id_big_endian) is not bool)
        ):
            raise ValueError("Invalid bounded legacy CPU metadata")
        for data in (self.nonce, self.authorized_key):
            if data is not None and (not isinstance(data, bytes) or len(data) != 16):
                raise ValueError("Explicit native authorization fields require16 bytes")
        if self.s0_header is not None and (
            not isinstance(self.s0_header, bytes) or len(self.s0_header) > 1024 * 1024
        ):
            raise ValueError("Invalid bounded S0 header")
        for name in ("parameters", "alternate_parameters"):
            values = getattr(self, name)
            if values is None or (name == "alternate_parameters" and callable(values)):
                continue
            object.__setattr__(self, name, _parameter_snapshot(values))


def _parameter_snapshot(values):
    if (
        not isinstance(values, Mapping)
        or len(values) > 256
        or any(
            not isinstance(key, str)
            or not 0 < len(key) <= 128
            or not isinstance(value, str)
            or len(value) > 4096
            for key, value in values.items()
        )
    ):
        raise ValueError("Invalid bounded native parameter mapping")
    return MappingProxyType(dict(values))


def _number(
    parameters: Mapping[str, str], name: str, default: int = 0, *, base: int = 10
) -> int:
    value = parameters.get(name)
    if value is None or value == "":
        return default
    try:
        number = int(value, base)
    except ValueError as error:
        raise ValueError(f"Invalid native numeric parameter {name}") from error
    if not 0 <= number <= 0xFFFFFFFF:
        raise ValueError(f"Native parameter {name} exceeds uint32")
    return number


def _flag(parameters: Mapping[str, str], name: str) -> bool:
    value = _number(parameters, name)
    if value not in (0, 1):
        raise ValueError(f"Native boolean parameter {name} must be0 or1")
    return bool(value)


_WRITERS = {
    "TCUWP4CanAirbagFlashWriter.dll": "airbag",
    "TCUWP4CanBodyFlashWriter.dll": "body4",
    "TCUWP5CanBodyFlashWriter.dll": "body5",
    "TCUWP4CanBodyFlashWriterForCXPI.dll": "cxpi",
    "TCUWP4CanChassisShrinkFlashWriter.dll": "chassis",
    "TCUWP4CanClearanceSonarFlashWriter.dll": "sonar",
    "TCUWP4CanDSS1FlashWriter.dll": "dss",
    "TCUWP4CanSecurityAirbagFlashWriter.dll": "security_airbag",
    "TCUWP4CanSecurityChassisShrinkFlashWriter.dll": "security_chassis",
    "TCUWP4CanVFORESTFlashWriter.dll": "vforest",
}


def legacy_write(
    module: str,
    channel: VendorCAN,
    cpu: LegacyCPU,
    *,
    finish_channel: VendorCAN,
    set_timeout: Callable[[int, float], None] | None = None,
    get_timeout: Callable[[], int] | None = None,
    set_bs: Callable[[int], None] | None = None,
    tester_present: Callable[[], None] | None = None,
    checkpoint: Mapping | None = None,
    native_build: int = 18,
    progress: Callable[[str, int], None] | None = None,
    lifecycle: Callable[[str, dict, float], object] | None = None,
) -> dict:
    """Run a native one-CPU stage, retaining uncertain destructive checkpoints.

    The finish provider writes to the native finish address and reads the writer
    response address. There is no automatic continuation of an uncertain journal.
    Caller-selected retry metadata/authorized passwords remain explicit.
    """
    if (
        module not in _WRITERS
        or not isinstance(channel, VendorCAN)
        or not isinstance(finish_channel, VendorCAN)
        or not isinstance(cpu, LegacyCPU)
    ):
        raise ValueError(
            "Known legacy writer and explicit native replay context required"
        )
    if (
        type(native_build) is not int
        or native_build not in (12, 18)
        or (progress is not None and not callable(progress))
    ):
        raise ValueError("Explicit native build12/18 and callable progress required")
    if any(
        callback is not None and not callable(callback)
        for callback in (
            set_timeout,
            get_timeout,
            set_bs,
            tester_present,
        )
    ):
        raise ValueError("Callable native transport configuration providers required")
    if lifecycle is not None and not callable(lifecycle):
        raise ValueError("Callable native transport lifecycle provider required")
    if lifecycle is not None:
        lifecycle = _guarded_callback(
            lifecycle, channel.remaining, defer_filter_result=True
        )

        def lifecycle_get_timeout() -> int:
            value = _lifecycle_action(lifecycle, "get_timeout", {}, channel.remaining())
            assert type(value) is int
            return value

        def lifecycle_set_timeout(value: int, budget: float) -> None:
            _lifecycle_action(lifecycle, "set_timeout", {"milliseconds": value}, budget)

        if get_timeout is None:
            get_timeout = lifecycle_get_timeout
        if set_timeout is None:
            set_timeout = lifecycle_set_timeout
    if get_timeout is not None:
        get_timeout = _guarded_callback(get_timeout, channel.remaining)
    if set_timeout is not None:
        set_timeout = _guarded_callback(set_timeout, channel.remaining)
    if set_bs is not None:
        set_bs = _guarded_callback(set_bs, channel.remaining)
    if tester_present is not None:
        tester_present = _guarded_callback(tester_present, channel.remaining)
    if progress is not None:
        progress = _guarded_callback(progress, channel.remaining)
    kind = _WRITERS[module]
    digest = hashlib.sha256(cpu.image).hexdigest()
    if checkpoint is not None:
        if (
            checkpoint.get("module") != module
            or checkpoint.get("image_sha256") != digest
            or checkpoint.get("cpu_index") != cpu.cpu_index
        ):
            raise ValueError("Legacy checkpoint does not match native CPU input")
        return {
            "state": "recovery_required",
            "checkpoint": dict(checkpoint),
            "resumed": False,
            "reason": "native-retry-context-and-ECU-state-must-be-reconciled",
            "programming_authorized": False,
        }
    params = cpu.parameters
    body = kind in ("body4", "body5", "cxpi")
    grouped = kind in ("chassis", "security_chassis", "sonar")
    security = kind in ("security_airbag", "security_chassis")
    change_cpu = kind in (
        "chassis",
        "security_chassis",
        "security_airbag",
        "dss",
        "vforest",
    )
    if security and (cpu.nonce is None or cpu.authorized_key is None):
        raise ValueError(
            "Native security writer requires explicit nonce and authorized key"
        )
    if body and cpu.id_big_endian is None:
        raise ValueError(
            "Body CheckID requires explicit BigEndianFlag from native context744 source"
        )
    if kind == "cxpi" and (tester_present is None or set_bs is None):
        raise ValueError(
            "CXPI requires explicit BS and prepare-address tester-present providers"
        )
    external = body and _flag(params, "ExternalMemoryFlag")
    non_verify = body and _flag(params, "FlagToNonVerifyProcess")
    endian = cpu.id_big_endian if body else _flag(params, "BigEndianFlag")
    times = {
        name: _number(params, name)
        for name in (
            "WaitTimeAfterReprogrammingMode",
            "WaitTimeBetweenSF",
            "ReceiveTimeoutBeforeInitialCommand",
            "ReceiveTimeoutBeforeFlashWrite",
            "WaitTimeBeforeStatusCheckForEraseBlock",
            "WaitTimeBeforeStatusCheckForWriteBlock",
            "WaitTimeBeforeStatusCheckForInVerify",
            "WaitTimeBeforeStatusCheckForVerify",
            "WaitTimeAfterEndOfFlashing",
            "WaitTimeAfterInitialCommandError",
        )
    }
    if (
        times["ReceiveTimeoutBeforeInitialCommand"] or kind != "vforest"
    ) and set_timeout is None:
        raise ValueError(
            "Native receive timeout requires explicit transport configuration"
        )
    if (
        cpu.native_flag_740
        and kind in ("chassis", "security_chassis", "sonar")
        and set_timeout is None
    ):
        raise ValueError(
            "Native retry timeout requires explicit transport configuration"
        )
    if kind != "vforest" and get_timeout is None:
        raise ValueError(
            "Native timeout restoration requires explicit snapshot provider"
        )
    if (
        cpu.native_retry_flag_728
        and kind in ("airbag", "security_airbag")
        and cpu.alternate_password is None
    ):
        raise ValueError(
            "Native initial retry requires both explicitly supplied passwords"
        )
    cpuid = _number(params, "CPUIDNo", base=16)
    shrink = _flag(params, "ShrinkFlag")
    info = (
        None if kind == "vforest" else parse_block_info(params.get("BlockSizeInfo", ""))
    )
    read_s0 = body and _flag(params, "ReadBlockRangeFromS0HeaderFlag")
    if read_s0 and cpu.s0_header is None:
        raise ValueError("Native S0 block selection requires supplied S0 data")
    send_type = _number(params, "SendDataByteForWriteBlockType")
    send_type = send_type if send_type in (1, 2) else 0
    phase = "check_id"
    block_index = 0
    destructive = False
    completed = []
    transitions = []
    error_name = None
    error_chain = []
    boundary_error_chain = []
    cleanup_error_chains = []
    progress_count = 0
    progress_percent = 0
    progress_cleanup_error = None
    transferred_start = channel.transferred
    old_timeout = None
    timeout_changed = False
    timeout_cleanup_error = None
    bs_changed = False
    bs_cleanup_error = None
    filter_id = None
    send_timeout_old = None
    send_timeout_changed = False
    lifecycle_cleanup_error = None
    initial_attempts = 0
    password_is_new = cpu.password_is_new
    current_password = cpu.password
    error_code = None

    def fragment_progress(length: int) -> None:
        nonlocal progress_count, progress_percent
        progress_count += length
        size = cpu.flash_size if cpu.flash_size is not None else len(cpu.image)
        denominator = size if non_verify else size * 2
        progress_percent = progress_count * 100 // denominator
        if progress is not None:
            progress("count", progress_count)
            progress("percent", progress_percent)

    try:

        def configure_timeout() -> None:
            nonlocal old_timeout, timeout_changed
            assert get_timeout is not None and set_timeout is not None
            channel.remaining()
            old_timeout = get_timeout()
            if type(old_timeout) is not int or not 0 <= old_timeout <= 0xFFFFFFFF:
                raise ValueError("Invalid native transport timeout snapshot")
            timeout_changed = True
            set_timeout(times["ReceiveTimeoutBeforeFlashWrite"], channel.remaining())
            channel.remaining()

        def start_filter() -> None:
            nonlocal filter_id
            if lifecycle is not None:
                filter_id = _lifecycle_action(
                    lifecycle, "start_filter", {"target_index": 0}, channel.remaining()
                )
                channel.remaining()

        early_timeout = kind in ("chassis", "security_chassis", "sonar")
        if early_timeout:
            configure_timeout()
        if kind == "sonar" and lifecycle is not None:
            send_timeout_old = _lifecycle_action(
                lifecycle, "get_send_timeout", {}, channel.remaining()
            )
            send_timeout_changed = True
            _lifecycle_action(
                lifecycle,
                "set_send_timeout",
                {"milliseconds": _number(params, "SendTimeoutBeforePrepareWrite")},
                channel.remaining(),
            )
            channel.remaining()
        if early_timeout or kind == "vforest":
            start_filter()
        channel.wait(times["WaitTimeAfterReprogrammingMode"])
        if kind == "cxpi":
            assert set_bs is not None
            bs_changed = True
            set_bs(1)
            channel.remaining()
        if kind != "vforest" and not early_timeout:
            configure_timeout()
            start_filter()
        initial_timeout = (
            10000
            if cpu.native_flag_740 and kind in ("chassis", "security_chassis", "sonar")
            else times["ReceiveTimeoutBeforeInitialCommand"]
        )
        attempts = (
            11
            if cpu.native_retry_flag_728
            and (body or kind in ("airbag", "security_airbag"))
            else 1
        )
        for attempt in range(attempts):
            initial_attempts += 1
            try:
                channel.check_id(
                    cpu.location_id,
                    current_password,
                    swap_endian=bool(endian),
                    wait_ms=times["WaitTimeBetweenSF"],
                    first_timeout_ms=initial_timeout,
                    set_timeout=set_timeout,
                )
                break
            except (InterruptedError, TimeoutError):
                raise
            except (
                LegacyTransportError,
                VendorTransportError,
                VendorInitialCommandError,
            ) as error:
                channel.remaining()
                if attempt + 1 == attempts or (
                    not body and not isinstance(error, VendorInitialCommandError)
                ):
                    raise
                if not body:
                    channel.wait(times["WaitTimeAfterInitialCommandError"])
                    password_is_new = not password_is_new
                    current_password = (
                        cpu.alternate_password
                        if password_is_new != cpu.password_is_new
                        else cpu.password
                    )
                    assert current_password is not None
        if kind not in ("airbag", "security_airbag", "vforest"):
            channel.wait(times["WaitTimeBetweenSF"])
        if security:
            assert cpu.nonce is not None and cpu.authorized_key is not None
            channel.auth(cpu.nonce, wait_ms=times["WaitTimeBetweenSF"])
            channel.auth(
                cpu.authorized_key, key=True, wait_ms=times["WaitTimeBetweenSF"]
            )
        phase = "memory_info"
        memory = channel.memory_info(wide=external)
        if not common_cpu_matches(
            memory["firmware_descriptor"],
            cpuid,
            shrink=memory["extended"],
            configured_shrink=shrink,
        ):
            if (
                kind != "vforest"
                or not params.get("AlternateCPUType")
                or cpu.alternate_parameters is None
            ):
                raise VendorOperationError(
                    10, "Native firmware descriptor/CPU parameter mismatch"
                )
            params = _parameter_snapshot(
                _guarded_callback(cpu.alternate_parameters, channel.remaining)()
                if callable(cpu.alternate_parameters)
                else cpu.alternate_parameters
            )
            if not common_cpu_matches(
                memory["firmware_descriptor"],
                _number(params, "CPUIDNo", base=16),
                shrink=memory["extended"],
                configured_shrink=_flag(params, "ShrinkFlag"),
            ):
                raise VendorOperationError(
                    10, "Native alternate CPU parameter mismatch"
                )
        if kind == "vforest":
            vforest_groups(cpu.image)
            phase = "write"
            destructive = True
            vforest_transfer(
                channel,
                cpu.image,
                wait_before_status_ms=_number(
                    params, "WaitTimeBeforeStatusCheckForWriteBlock"
                ),
                progress=fragment_progress,
            )
            phase = "verify"
            vforest_transfer(
                channel,
                cpu.image,
                verify=True,
                wait_before_status_ms=_number(
                    params, "WaitTimeBeforeStatusCheckForVerify"
                ),
                progress=fragment_progress,
            )
        else:
            assert info is not None
            if grouped:
                info = complete_block_info(
                    info,
                    memory["address"],
                    memory["end_address"],
                    memory["block_size_kib"],
                )
            sizes = block_sizes(info)
            ranges = block_ranges(
                info, grouped=grouped, s0_header=cpu.s0_header if read_s0 else None
            )
            if kind in ("chassis", "security_chassis") and ranges[0][0] != 1:
                sizes = (0,) + sizes
            if read_s0 and sum(sizes[first - 1] for first, last in ranges) != (
                cpu.flash_size if cpu.flash_size is not None else len(cpu.image)
            ):
                raise ValueError(
                    "Native S0 selected block sizes do not match image length"
                )
            blocks = legacy_blocks(cpu.image, sizes, ranges, memory["address"])
            for block in blocks:
                if len(block.data) % (1024, 512, 128)[send_type]:
                    raise ValueError(
                        "Native block is not a complete write-fragment multiple"
                    )
            for block_index, block in enumerate(blocks):
                phase = "erase"
                destructive = True
                if kind == "cxpi":
                    assert tester_present is not None
                    cxpi_erase(
                        channel,
                        block.first,
                        block.last,
                        tester_present,
                        wait_before_status_ms=times[
                            "WaitTimeBeforeStatusCheckForEraseBlock"
                        ],
                    )
                else:
                    channel.common_block(
                        "erase",
                        block.first,
                        block.last,
                        wide=memory["extended"],
                        wait_ms=times["WaitTimeBeforeStatusCheckForEraseBlock"],
                    )
                phase = "write"
                channel.common_write(
                    block.address,
                    block.data,
                    send_type=send_type,
                    wide=external,
                    wait_ms=times["WaitTimeBeforeStatusCheckForWriteBlock"],
                    first_wait_ms=0
                    if kind in ("airbag", "security_airbag")
                    else times["WaitTimeBetweenSF"],
                    progress=fragment_progress,
                )
                phase = "inverify"
                channel.common_block(
                    "inverify",
                    block.first,
                    block.last,
                    wide=memory["extended"],
                    wait_ms=times["WaitTimeBeforeStatusCheckForInVerify"],
                )
                if not non_verify:
                    phase = "verify"
                    channel.common_verify(
                        block.first,
                        block.last,
                        block.data,
                        wide=memory["extended"],
                        variant2=kind == "cxpi",
                        wait_ms=times["WaitTimeBeforeStatusCheckForVerify"],
                        progress=fragment_progress,
                    )
                completed.append(block_index)
        if security:
            phase = "detect_falsify"
            channel.detect_falsify()
        phase = "finish"
        if change_cpu and cpu.cpu_index + 1 < cpu.cpu_count:
            channel.change_cpu()
            transitions.append("next_cpu")
        else:
            finish_channel.finish(
                acknowledge=kind not in ("chassis", "security_chassis", "vforest")
                and not (kind == "sonar" and native_build == 12)
            )
            if kind not in ("chassis", "security_chassis", "sonar", "vforest"):
                channel.wait(times["WaitTimeAfterEndOfFlashing"])
            if body and cpu.cpu_index + 1 < cpu.cpu_count:
                transitions.append("catalog-FlagToDoIGOFFONAtCPUTypeChange")
        channel.remaining()
        phase = "complete"
        state = "complete"
    except (Exception, KeyboardInterrupt) as error:  # noqa: BLE001 - preserve state across injected callback failures
        error_name = type(error).__name__
        error_chain = _failure_chain(error)
        if isinstance(
            error,
            (
                LegacyTransportError,
                VendorTransportError,
                VendorInitialCommandError,
                VendorOperationError,
                VendorStatusAckError,
            ),
        ):
            error_code = error.code
            password_is_new = (
                True
                if cpu.native_retry_flag_72c
                else not password_is_new
                if error_code == 7
                else False
            )
        progress_count = progress_percent = 0
        if progress is not None and not (kind == "vforest" and native_build == 12):
            for field_name in ("count", "percent"):
                try:
                    progress(field_name, 0)
                except (Exception, KeyboardInterrupt) as cleanup:  # noqa: BLE001 - attempt all reset callbacks
                    progress_cleanup_error = type(cleanup).__name__
                    cleanup_error_chains.append(
                        {
                            "operation": "progress_" + field_name,
                            "error_chain": _failure_chain(cleanup),
                        }
                    )
        state = (
            "recovery_required"
            if destructive
            else "cancelled"
            if isinstance(error, InterruptedError)
            else "failed"
        )
    finally:
        if bs_changed:
            assert set_bs is not None
            try:
                set_bs(0)
            except (Exception, KeyboardInterrupt) as cleanup:  # noqa: BLE001 - preserve state across injected callback failures
                bs_cleanup_error = type(cleanup).__name__
                cleanup_error_chains.append(
                    {"operation": "set_bs", "error_chain": _failure_chain(cleanup)}
                )
                state = "recovery_required"
        if filter_id is not None:
            assert lifecycle is not None
            try:
                _lifecycle_action(
                    lifecycle,
                    "stop_filter",
                    {"filter_id": filter_id},
                    max(0.0, channel.deadline - channel.clock()),
                )
            except (Exception, KeyboardInterrupt) as cleanup:  # noqa: BLE001 - preserve state across injected callback failures
                lifecycle_cleanup_error = type(cleanup).__name__
                cleanup_error_chains.append(
                    {"operation": "lifecycle", "error_chain": _failure_chain(cleanup)}
                )
                state = "recovery_required"
        if timeout_changed:
            assert old_timeout is not None and set_timeout is not None
            try:
                # Cleanup must remain possible after cancellation/deadline expiry.
                set_timeout(old_timeout, max(0.0, channel.deadline - channel.clock()))
            except (Exception, KeyboardInterrupt) as cleanup:  # noqa: BLE001 - preserve state across injected callback failures
                timeout_cleanup_error = type(cleanup).__name__
                cleanup_error_chains.append(
                    {"operation": "set_timeout", "error_chain": _failure_chain(cleanup)}
                )
                state = "recovery_required"
        if send_timeout_changed:
            assert lifecycle is not None
            try:
                _lifecycle_action(
                    lifecycle,
                    "set_send_timeout",
                    {"milliseconds": send_timeout_old},
                    max(0.0, channel.deadline - channel.clock()),
                )
            except (Exception, KeyboardInterrupt) as cleanup:  # noqa: BLE001 - preserve state across injected callback failures
                lifecycle_cleanup_error = type(cleanup).__name__
                cleanup_error_chains.append(
                    {"operation": "lifecycle", "error_chain": _failure_chain(cleanup)}
                )
                state = "recovery_required"
    try:
        channel.remaining()
    except (Exception, KeyboardInterrupt) as boundary:  # noqa: BLE001 - preserve state across injected callback failures
        error_name = type(boundary).__name__
        boundary_error_chain = _failure_chain(boundary)
        state = (
            "recovery_required"
            if destructive or state == "recovery_required"
            else "cancelled"
            if isinstance(boundary, InterruptedError)
            else "failed"
        )
    journal = {
        "module": module,
        "image_sha256": digest,
        "cpu_index": cpu.cpu_index,
        "phase": phase,
        "block_index": block_index,
        "completed_blocks": completed,
        "uncertain": state == "recovery_required",
    }
    return {
        "state": state,
        "scope": "native-one-CPU-stage",
        "module": module,
        "checkpoint": journal,
        "resumed": False,
        "transferred_bytes": channel.transferred - transferred_start,
        "native_build": native_build,
        "initial_command_attempts": initial_attempts,
        "next_password_is_new": password_is_new,
        "native_error_code": error_code,
        "progress_count": progress_count,
        "progress_percent": progress_percent,
        "progress_cleanup_error_type": progress_cleanup_error,
        "timeout_cleanup_error_type": timeout_cleanup_error,
        "bs_cleanup_error_type": bs_cleanup_error,
        "lifecycle_cleanup_error_type": lifecycle_cleanup_error,
        "transitions": transitions,
        "error_type": error_name,
        "error_chain": error_chain,
        "boundary_error_chain": boundary_error_chain,
        "cleanup_error_chains": cleanup_error_chains,
        "programming_authorized": False,
        "vehicle_compatibility_validated": False,
        "provenance": "native-P4-P5-distinct-stage-orchestration-and-replay",
    }


@dataclass(frozen=True)
class LegacyPrepareContext:
    cpu_image: bytes | None = field(repr=False)
    kind_of_ecu: str
    parameters: Mapping[str, str] = field(default_factory=dict, repr=False)
    cpu_count: int = 1
    address_extended: bool = False
    security_access_password: bytes | None = field(default=None, repr=False)
    ecu_auth_key: bytes | None = field(default=None, repr=False)
    native_flag_728_nonempty: bool = False

    def __post_init__(self) -> None:
        if (
            not isinstance(self.parameters, Mapping)
            or len(self.parameters) > 256
            or any(
                not isinstance(key, str)
                or not 0 < len(key) <= 128
                or not isinstance(value, str)
                or len(value) > 4096
                for key, value in self.parameters.items()
            )
            or (
                self.cpu_image is not None
                and (
                    not isinstance(self.cpu_image, bytes)
                    or not 0 < len(self.cpu_image) <= 64 * 1024 * 1024
                )
            )
            or type(self.cpu_count) is not int
            or not 1 <= self.cpu_count <= 128
            or not isinstance(self.kind_of_ecu, str)
            or len(self.kind_of_ecu) > 128
            or type(self.address_extended) is not bool
            or type(self.native_flag_728_nonempty) is not bool
        ):
            raise ValueError("Invalid bounded native prepare context")
        for data, width in (
            (self.security_access_password, 2),
            (self.ecu_auth_key, 16),
        ):
            if data is not None and (not isinstance(data, bytes) or len(data) != width):
                raise ValueError(
                    "Explicit authorization field has incorrect native width"
                )
        object.__setattr__(self, "parameters", MappingProxyType(dict(self.parameters)))


def legacy_bus_type(image: bytes | None, parameters: Mapping[str, str]) -> int:
    """CommonPrepare1630: absent/unknown→2; byte at supplied hex address0/1."""
    value = parameters.get("CANCommunicationSpeedAddress", "")
    if not value:
        return 2
    if not isinstance(image, bytes) or len(image) > 64 * 1024 * 1024:
        raise ValueError("Bounded immutable CPU image required")
    offset = _number(parameters, "CANCommunicationSpeedAddress", base=16)
    if offset >= len(image):
        raise ValueError("Native communication speed address exceeds image")
    return image[offset] if image[offset] in (0, 1) else 2


_PREPARERS = {
    "TCUWP4CanAirbagPrepareWriter.dll": "airbag",
    "TCUWP4CanBodyPrepareWriter.dll": "body",
    "TCUWP4CanCentralGWPrepareWriter.dll": "central",
    "TCUWP4CanChassisShrinkPrepareWriter.dll": "chassis",
    "TCUWP4CanClearanceSonarPrepareWriter.dll": "sonar",
    "TCUWP4CanPowerTrainPrepareWriter.dll": "power4",
    "TCUWP4CanSecurityAirbagPrepareWriter.dll": "security_airbag",
    "TCUWP4CanSecurityChassisShrinkPrepareWriter.dll": "security_chassis",
    "TCUWP4P5CanPowerTrainPrepareWriter.dll": "power45",
    "TCUWP5CanPowerTrainPrepareWriter.dll": "power5",
    "TCUWP5CanPowerTrainPrepareWriterForBodyMicon.dll": "body_micon",
    "TCUWP5CanPowerTrainPrepareWriterForSolar.dll": "solar",
    "TCUWP5CanSecurityPowerTrainPrepareWriter.dll": "security_power5",
}


def legacy_prepare(
    module: str,
    targets: Sequence[LegacyTarget],
    context: LegacyPrepareContext,
    key_provider: Callable[[str, bytes], bytes] | None,
    *,
    raw_write: Callable[[int, bytes, float], int] | None = None,
    wait: Callable[[int, float], None] | None = None,
    set_bs: Callable[[int], None] | None = None,
    confirm_gateway: Callable[[], bool] | None = None,
    gateway_only: bool = False,
    native_build: int = 18,
    timeout: float = 30,
    cancelled: Callable[[], bool] = lambda: False,
    clock: Callable[[], float] = time.monotonic,
    lifecycle: Callable[[str, dict, float], object] | None = None,
) -> dict:
    """Native13-family prepare orchestration over exact old/P5 utility channels.

    Authorization is supplied through key_provider and explicit ECU auth fields.
    Host cancellation/deadline/malformed inputs are never converted to native
    success overrides. Native typed unavailable-target branches are preserved.
    """
    if (
        module not in _PREPARERS
        or type(native_build) is not int
        or native_build not in (12, 18)
        or not isinstance(context, LegacyPrepareContext)
        or len(targets) > 4
        or any(not isinstance(target, LegacyTarget) for target in targets)
        or type(gateway_only) is not bool
        or isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(timeout)
        or timeout <= 0
    ):
        raise ValueError("Invalid bounded legacy preparation context")
    kind = _PREPARERS[module]
    if native_build == 12 and kind == "security_power5":
        raise LookupError("This native preparation DLL exists only in CUW18")
    if (
        kind in ("power45", "power5", "body_micon", "solar", "security_power5")
        or (native_build == 12 and kind == "power4")
    ) and any(len(target.request) != 2 for target in targets):
        raise ValueError("This native helper uses a fixed four-byte CAN prefix")
    if (
        kind == "body"
        and targets
        and context.address_extended != (len(targets[0].request) == 3)
    ):
        raise ValueError(
            "Native extended-address flag must match the selected address width"
        )
    if gateway_only and kind != "body":
        raise ValueError("Only native Body exports the gateway stage")
    body_gateway_skip = (
        gateway_only
        and kind == "body"
        and (
            _flag(context.parameters, "ExternalMemoryFlag")
            or legacy_bus_type(context.cpu_image, context.parameters) != 1
        )
    )
    single = kind in (
        "airbag",
        "body",
        "sonar",
        "chassis",
        "security_chassis",
        "security_airbag",
    )
    if (single and not targets and not body_gateway_skip) or (
        kind == "power45" and len(targets) != 2
    ):
        raise ValueError("Native preparation requires its exact communication targets")
    if kind in ("chassis", "security_chassis") and len(targets) > 2:
        raise ValueError("Native chassis selector storage supports at most two CPUs")
    for index, target in enumerate(targets):
        old = kind in (
            "airbag",
            "body",
            "sonar",
            "chassis",
            "security_chassis",
            "security_airbag",
            "power4",
        ) or (kind == "power45" and index == 1)
        if old != isinstance(target.channel, VendorDiagnosticChannel):
            raise ValueError(
                "Preparation channel must implement exact native utility policy"
            )
    if kind != "central" and not body_gateway_skip and key_provider is None:
        raise ValueError("Explicit authorized key provider required")
    if kind in ("airbag", "sonar") and context.security_access_password is None:
        raise ValueError("Native two-byte SecurityAccessPassword required")
    if (
        kind in ("security_airbag", "security_chassis", "security_power5")
        and context.ecu_auth_key is None
    ):
        raise ValueError("Native sixteen-byte ECU auth input required")
    params = context.parameters
    waits = (
        {}
        if body_gateway_skip
        else {
            name: _number(params, name)
            for name in (
                "WaitTimeAfterSeedData",
                "WaitTimeAfterSeedKey",
                "WaitTimeAfterDiagnosticMask",
                "WaitTimeAfterReprogrammingMode",
            )
        }
    )
    if any(waits.values()) and wait is None:
        raise ValueError("Native nonzero waits require explicit replay provider")
    if kind == "central" and confirm_gateway is None:
        raise ValueError(
            "Native CentralGW stage requires explicit confirmation callback"
        )
    if kind != "central" and not gateway_only and raw_write is None:
        raise ValueError("Native diagnostic mask requires explicit raw provider")
    if (
        kind in ("power5", "body_micon", "solar", "security_power5", "power45")
        and wait is None
    ):
        raise ValueError(
            "Native powertrain10ms scheduling requires explicit wait provider"
        )
    deadline = clock() + timeout
    started = False
    phase = "start"
    accepted = []
    skipped = []
    events = []
    bs_enabled = False
    cleanup_error = None
    native_error_code = None
    gateway_attempted = False
    gateway_result_valid = False
    gateway_result = True
    error_chain = []
    boundary_error_chain = []
    cleanup_error_chains = []

    def remaining() -> float:
        if cancelled() or any(target.channel.cancelled() for target in targets):
            raise InterruptedError("Legacy preparation cancelled")
        values = [deadline - clock()] + [
            target.channel.deadline - target.channel.clock() for target in targets
        ]
        if min(values) <= 0:
            raise TimeoutError("Legacy preparation deadline expired")
        return min(values)

    if lifecycle is not None:
        lifecycle = _guarded_callback(lifecycle, remaining, defer_filter_result=True)

    if key_provider is not None:
        key_provider = _guarded_callback(key_provider, remaining)
    if raw_write is not None:
        raw_write = _guarded_callback(raw_write, remaining)
    if wait is not None:
        wait = _guarded_callback(wait, remaining)
    if confirm_gateway is not None:
        confirm_gateway = _guarded_callback(confirm_gateway, remaining)
    if set_bs is not None:
        set_bs = _guarded_callback(set_bs, remaining)

    def delay(milliseconds: int) -> None:
        current = remaining()
        if milliseconds:
            if wait is None:
                raise ValueError("Native wait requires explicit provider")
            wait(milliseconds, current)
        remaining()

    def mask() -> None:
        nonlocal started, phase
        phase = "diagnostic_mask"
        if raw_write is None:
            raise ValueError("Native diagnostic mask provider missing")
        for _ in range(3):
            started = True
            count = raw_write(0x720, b"\xa0\x27", remaining())
            if type(count) is not int or count != 1:
                raise OSError("Native diagnostic mask write uncertain")
            delay(waits["WaitTimeAfterDiagnosticMask"])
        events.append("diagnostic_mask")

    def call(
        index: int, request: bytes, expected: bytes | None, minimum: int = 0
    ) -> bytes:
        nonlocal started
        remaining()
        started = True
        native_code = (
            25
            if request[:1] == b"\x31"
            else (49 if request[1:2] == b"\x60" else 18)
            if isinstance(targets[index].channel, VendorDiagnosticChannel)
            else 41
        )
        response = _legacy_diagnostic_call(
            targets[index].channel, request, expected, native_code
        )
        if len(response) < minimum:
            raise VendorOperationError(
                native_code, "Native preparation response below required length"
            )
        remaining()
        return response

    def security(
        index: int,
        request: bytes,
        width: int,
        *,
        magic: bool = False,
        key_magic: bool = False,
        seed_wait: bool = True,
    ) -> None:
        nonlocal started, phase
        phase = "security"
        remaining()
        started = True
        provider = key_provider
        assert provider is not None
        legacy_security(
            targets[index].channel,
            request,
            width,
            lambda seed: provider(module, seed),
            seed_suffix=b"\x34" if magic else b"",
            key_suffix=b"\x34" if key_magic else b"",
            wait_ms=waits["WaitTimeAfterSeedData"] if seed_wait else 0,
            wait=delay,
        )
        remaining()

    def unavailable(error: BaseException) -> bool:
        return (
            isinstance(error, (LegacyTransportError, VendorTransportError))
            and error.code in (9, 16)
        ) or (
            isinstance(error, NativeDiagnosticError)
            and len(error.response) == 3
            and error.response[:2] == b"\x7f\x27"
        )

    def probe(index: int, negative_sid: int) -> bool:
        nonlocal phase
        phase = "session_probe"
        try:
            response = call(index, b"\x10\x02", None)
        except (LegacyTransportError, VendorTransportError) as error:
            if error.code in (9, 16):
                return False
            raise
        except NativeNegativeResponse as error:
            if len(error.response) == 3 and error.response[:2] == bytes(
                (0x7F, negative_sid)
            ):
                return False
            raise
        if len(response) == 3 and response[:2] == bytes((0x7F, negative_sid)):
            return False
        if not response.startswith(b"\x50\x02") or len(response) < 6:
            raise VendorOperationError(
                41, "Malformed native powertrain session response"
            )
        return True

    filter_ids = []

    def start_filter(index):
        if lifecycle is not None:
            filter_ids.append(
                _lifecycle_action(
                    lifecycle, "start_filter", {"target_index": index}, remaining()
                )
            )
            remaining()

    try:
        remaining()
        if kind == "central":
            assert confirm_gateway is not None
            phase = "confirmation"
            changed = confirm_gateway()
            if type(changed) is not bool:
                raise ValueError("Native confirmation must return boolean")
            if not changed and not context.native_flag_728_nonempty:
                raise ValueError("Native CentralGW preparation declined")
            if changed:
                delay(waits["WaitTimeAfterReprogrammingMode"])
            events.append("gateway_confirmed" if changed else "native_retry_skip")
        elif body_gateway_skip:
            events.append("native_gateway_bus_skip")
        elif single:
            gateway_attempted = gateway_only and kind == "body"
            enable_bs = (
                kind in ("airbag", "sonar")
                and legacy_bus_type(context.cpu_image, params) == 1
            ) or (kind == "body" and context.address_extended)
            if enable_bs:
                if set_bs is None:
                    raise ValueError("Native preparation requires explicit BS provider")
                bs_enabled = True
                set_bs(1)
            start_filter(0)
            if kind in ("chassis", "security_chassis"):
                selectors = (
                    (1, 0)
                    if len(targets) == 2 and context.kind_of_ecu == "13"
                    else (0, 2)
                )
                for index in range(len(targets)):
                    request = b"\x27\x01" + bytes((selectors[index],))
                    width = 4
                    if kind == "security_chassis":
                        assert context.ecu_auth_key is not None
                        request += context.ecu_auth_key
                        width = 16
                    security(0, request, width)
                    delay(waits["WaitTimeAfterSeedKey"])
                    mask()
                    phase = "change_mode"
                    call(0, b"\x10\x02", b"\x50", 1)
            elif kind == "security_airbag":
                assert context.ecu_auth_key is not None
                for index in range(context.cpu_count):
                    security(
                        0,
                        b"\x27\x03" + context.ecu_auth_key,
                        16,
                        magic=True,
                        key_magic=True,
                    )
                    delay(waits["WaitTimeAfterSeedKey"])
                    if index == 0:
                        mask()
                    phase = "change_mode"
                    call(0, b"\x10\x02", b"\x50", 1)
            else:
                if kind in ("airbag", "sonar"):
                    assert context.security_access_password is not None
                    security(
                        0,
                        b"\x27\x03" + context.security_access_password,
                        2,
                        magic=True,
                        key_magic=True,
                    )
                else:
                    security(0, b"\x27\x61", 6, key_magic=True)
                delay(waits["WaitTimeAfterSeedKey"])
                if not gateway_only:
                    mask()
                phase = "change_mode"
                call(0, b"\x10\x60" if gateway_only else b"\x10\x02", b"\x50", 1)
            accepted.extend(
                range(len(targets)) if kind in ("chassis", "security_chassis") else (0,)
            )
        elif kind == "power4":
            for index in range(len(targets)):
                start_filter(index)
            for index in range(len(targets)):
                try:
                    security(index, b"\x27\x01", 4)
                    accepted.append(index)
                except (
                    LegacyTransportError,
                    VendorTransportError,
                    NativeDiagnosticError,
                ) as error:
                    if not unavailable(error):
                        raise
                    skipped.append(index)
                delay(waits["WaitTimeAfterSeedKey"])
            if not accepted and not context.native_flag_728_nonempty:
                raise ValueError("No native P4 security target accepted")
            if accepted:
                mask()
                for index in accepted:
                    phase = "change_mode"
                    call(index, b"\x10\x02", b"\x50", 1)
        elif kind == "power45":
            for index in range(len(targets)):
                start_filter(index)
            p5 = probe(0, 0x10)
            if not p5 and not context.native_flag_728_nonempty:
                raise ValueError("Native P4P5 primary session unavailable")
            if p5:
                security(0, b"\x27\x01", 4, seed_wait=False)
                accepted.append(0)
            else:
                skipped.append(0)
            try:
                security(1, b"\x27\x01", 4)
                delay(waits["WaitTimeAfterSeedKey"])
                accepted.append(1)
            except (
                LegacyTransportError,
                VendorTransportError,
                NativeDiagnosticError,
            ) as error:
                if not context.native_flag_728_nonempty or not unavailable(error):
                    raise
                skipped.append(1)
            if accepted:
                mask()
                if p5:
                    phase = "routine"
                    call(0, b"\x31\x01\x10\x03", b"\x71\x01\x10\x03", 4)
                    delay(10)
                if 1 in accepted:
                    phase = "change_mode"
                    call(1, b"\x10\x02", b"\x50", 1)
        else:
            for index in range(len(targets)):
                start_filter(index)
            for index in range(len(targets)):
                if probe(index, 0x10 if kind in ("solar", "security_power5") else 0x27):
                    accepted.append(index)
                else:
                    skipped.append(index)
            if not accepted and not context.native_flag_728_nonempty:
                raise ValueError("No native P5 session target accepted")
            for index in accepted:
                request = b"\x27\x01"
                width = 6 if kind == "body_micon" else 4
                if kind == "security_power5":
                    assert context.ecu_auth_key is not None
                    request += context.ecu_auth_key
                    width = 16
                security(index, request, width, seed_wait=False)
            if accepted:
                mask()
                for position, index in enumerate(accepted):
                    phase = "routine"
                    call(index, b"\x31\x01\x10\x03", b"\x71\x01\x10\x03", 4)
                    if position + 1 < len(accepted):
                        delay(10)
        remaining()
        phase = "complete"
        state = "complete"
        error_type = None
        gateway_result_valid = gateway_attempted
    except (Exception, KeyboardInterrupt) as error:  # noqa: BLE001 - preserve state across injected callback failures
        state = (
            "recovery_required"
            if started
            else "cancelled"
            if isinstance(error, InterruptedError)
            else "failed"
        )
        error_type = type(error).__name__
        error_chain = _failure_chain(error)
        native_error_code = getattr(error, "native_cuw_code", None)
        if isinstance(
            error,
            (
                VendorOperationError,
                VendorStatusAckError,
                LegacyTransportError,
                VendorTransportError,
            ),
        ):
            native_error_code = error.code
        gateway_result = False
        gateway_result_valid = gateway_attempted and isinstance(
            error,
            (
                NativeNegativeResponse,
                SharedNativeDiagnosticError,
                VendorUtilityTimeout,
                VendorOperationError,
                VendorStatusAckError,
                LegacyTransportError,
                VendorTransportError,
            ),
        )
    finally:
        if bs_enabled:
            assert set_bs is not None
            try:
                set_bs(0)
            except (Exception, KeyboardInterrupt) as error:  # noqa: BLE001 - preserve state across injected callback failures
                cleanup_error = type(error).__name__
                cleanup_error_chains.append(
                    {"operation": "set_bs", "error_chain": _failure_chain(error)}
                )
                state = "recovery_required"
        if lifecycle is not None:
            for filter_id in filter_ids:
                try:
                    _lifecycle_action(
                        lifecycle,
                        "stop_filter",
                        {"filter_id": filter_id},
                        max(0.0, deadline - clock()),
                    )
                except (Exception, KeyboardInterrupt) as error:  # noqa: BLE001 - preserve state across injected callback failures
                    cleanup_error = type(error).__name__
                    cleanup_error_chains.append(
                        {
                            "operation": "stop_filter",
                            "error_chain": _failure_chain(error),
                        }
                    )
                    state = "recovery_required"
    try:
        remaining()
    except (Exception, KeyboardInterrupt) as boundary:  # noqa: BLE001 - preserve state across injected callback failures
        error_type = type(boundary).__name__
        boundary_error_chain = _failure_chain(boundary)
        gateway_result_valid = False
        gateway_result = False
        state = (
            "recovery_required"
            if started or state == "recovery_required"
            else "cancelled"
            if isinstance(boundary, InterruptedError)
            else "failed"
        )
    if cleanup_error is not None:
        gateway_result_valid = False
        gateway_result = False
    return {
        "state": state,
        "module": module,
        "native_build": native_build,
        "native_error_code": native_error_code,
        "gateway_result_valid": gateway_result_valid,
        "gateway_result": gateway_result,
        "phase": phase,
        "accepted_targets": accepted,
        "skipped_unavailable_targets": skipped,
        "events": events,
        "error_type": error_type,
        "error_chain": error_chain,
        "boundary_error_chain": boundary_error_chain,
        "cleanup_error_chains": cleanup_error_chains,
        "cleanup_error_type": cleanup_error,
        "programming_authorized": False,
        "vehicle_compatibility_validated": False,
        "provenance": "native-P4-P5-distinct-prepare-orchestration-and-replay",
    }


def legacy_is_finished(
    module: str,
    channel: VendorCAN,
    *,
    lifecycle: Callable[[str, dict, float], object] | None = None,
) -> bool:
    """Common2640/1360: CPU0 filter, send3e/read one payload, stop filter.

    A transport failure returns the native negative probe result. Host limits,
    interrupted callbacks and uncertain cleanup remain explicit exceptions.
    """
    if module not in {
        "TCUWP4CanAirbagFlashWriter.dll",
        "TCUWP4CanDSS1FlashWriter.dll",
        "TCUWP4CanSecurityAirbagFlashWriter.dll",
    } or not isinstance(channel, VendorCAN):
        raise ValueError("Native finish-probe export is unavailable")
    if lifecycle is not None:
        if not callable(lifecycle):
            raise TypeError("Callable native probe lifecycle required")
        lifecycle = _guarded_callback(
            lifecycle, channel.remaining, defer_filter_result=True
        )
    filter_id, primary, native_failure = None, None, None
    cleanup_errors = []
    try:
        channel.remaining()
        if lifecycle is not None:
            filter_id = _lifecycle_action(
                lifecycle, "start_filter", {"target_index": 0}, channel.remaining()
            )
            channel.remaining()
        channel.write(b"\x3e")
        channel.read()
    except (InterruptedError, TimeoutError, KeyboardInterrupt) as error:
        primary = error
    except OSError as error:
        native_failure = error
    except Exception as error:  # noqa: BLE001 - preserve callback failure while cleaning up
        primary = error
    finally:
        if filter_id is not None:
            assert lifecycle is not None
            try:
                _lifecycle_action(
                    lifecycle,
                    "stop_filter",
                    {"filter_id": filter_id},
                    max(0.0, channel.deadline - channel.clock()),
                )
            except (Exception, KeyboardInterrupt) as error:  # noqa: BLE001 - retain cleanup uncertainty
                cleanup_errors.append(
                    {"operation": "stop_filter", "error_chain": _failure_chain(error)}
                )
                primary = primary or native_failure or error
    try:
        channel.remaining()
    except (Exception, KeyboardInterrupt) as boundary:  # noqa: BLE001 - host limit wins, original cause retained
        boundary.__cause__ = primary or native_failure
        primary = boundary
    if primary is not None:
        if cleanup_errors:
            primary.add_note(
                "Legacy finish-probe cleanup failures: " + repr(cleanup_errors)
            )
            primary.__dict__["legacy_cleanup_errors"] = tuple(cleanup_errors)
        raise primary
    return native_failure is None


def bind_legacy_finish_probe(
    container: CalibrationContainer,
    node: int,
    selection: CalibrationSelection,
    identity: NativeModuleIdentity,
) -> Address:
    """Bind the native IsFinishReprogramming vector's CPU0 physical address."""
    from scripts.native_modules import NativeModuleIdentity, identify_native_module

    if (
        not isinstance(identity, NativeModuleIdentity)
        or identify_native_module(identity.sha256, identity.module_name) != identity
    ):
        raise ValueError("Exact static native source identity required for probe")
    profile = legacy_module_profile(identity.module_name, identity.sha256)
    if "IsFinishReprogramming" not in profile["callable_exports"]:
        raise LookupError("Selected native module has no finish-probe export")
    if selection.value("DLLFileNameForFlashWrite") != identity.module_name:
        raise ValueError("Native probe module differs from imported write dispatch")
    context = bind_native_cpu_context(
        container,
        node,
        (),
        selection,
        stage="write",
        cpu_index=0,
        materialize_images=False,
    )
    if (
        selection._lines("GetCANIDFunctionNameForFlashWrite")
        != ("GetCanIDsFromLocationIDForWrite",)
        or len(context.target_metadata) != 2
    ):
        raise ValueError(
            "Native finish probe requires imported CPU0 LocationID routing"
        )
    return context.target_metadata[0]


def legacy_module_profile(module: str, sha256: str) -> dict:
    """Bind a local static DLL identity to its exact recovered legacy source build."""
    from scripts.native_modules import identify_native_module

    identity = identify_native_module(sha256, module)
    if module not in set(_WRITERS) | set(_PREPARERS) | {
        "TCUWP4P5CanCIDGetter.dll",
        "TCUWP5CanCIDGetter.dll",
        "TCUWP5CanCIDGetterWithSetBS.dll",
    } or identity.cuw_build not in ("12", "18"):
        raise LookupError("Static module identity is outside legacy P4/P5 scope")
    return {
        "module": module,
        "native_build": int(identity.cuw_build),
        "sha256": sha256,
        "callable_exports": list(identity.callable_exports),
        "provenance": "exact-native-module-hash",
    }


@dataclass(frozen=True)
class LegacyImage:
    data: bytes = field(repr=False)
    s0_header: bytes = field(repr=False)
    flash_size: int
    base_address: int | None


def materialize_legacy_image(data: bytes, *, filename: str = "") -> LegacyImage:
    """Cuw18 47b1c8/4ac054: ordinary SREC or explicit .vbf raw payload.

    Native 4ab4cc fills the address span with ff and copies every data record,
    including the first S1. FlashSize is their sum, distinct from span Length.
    """
    from scripts.calibration import _parse_srecords

    if not isinstance(data, bytes) or not 0 < len(data) <= 64 * 1024 * 1024:
        raise ValueError("Bounded immutable native CPU archive required")
    if not isinstance(filename, str) or len(filename) > 260 or "\0" in filename:
        raise ValueError("Bounded native CPUImageName required")
    if data[:1] != b"S":
        if not filename.casefold().endswith(".vbf"):
            raise ValueError("Ordinary native CPU archive is neither SREC nor VBF")
        return LegacyImage(data, b"", len(data), None)
    _parse_srecords(data, native_area=True)
    header = bytearray()
    spans = []
    for line in data.splitlines():
        kind = line[1] - 48
        raw = bytes.fromhex(line[2:].decode("ascii"))
        if kind == 0:
            header.extend(raw[3:-1])
        elif kind in (1, 2, 3):
            width = kind + 1
            start = int.from_bytes(raw[1 : 1 + width], "big")
            spans.append((start, raw[1 + width : -1]))
    # Native list merge compares unsigned addresses before computing the last end.
    spans.sort(key=lambda item: item[0])
    first = spans[0][0]
    end = spans[-1][0] + len(spans[-1][1])
    if end - first > 64 * 1024 * 1024 or len(header) > 1024 * 1024:
        raise ValueError("Native SREC address/header span exceeds host budget")
    if any(start + len(payload) > end for start, payload in spans):
        raise ValueError("Native SREC record exceeds the last-record address span")
    image = bytearray(b"\xff") * (end - first)
    for start, payload in spans:
        image[start - first : start - first + len(payload)] = payload
    return LegacyImage(
        bytes(image),
        bytes(header),
        sum(len(payload) for start, payload in spans),
        first,
    )


@dataclass(frozen=True)
class LegacyInputs:
    module: str
    stage: str
    native_build: int
    cpu: LegacyCPU | None = field(repr=False)
    prepare: LegacyPrepareContext | None = field(repr=False)
    target_metadata: tuple[Address, ...] = field(repr=False)
    container_sha256: str
    cpu_index: int
    parameters: Mapping[str, str] = field(default_factory=dict, repr=False)
    security_material: Mapping[str, bytes] = field(default_factory=dict, repr=False)
    tester_present_request: Mapping[str, object] | None = field(
        default=None, repr=False
    )

    def bind_targets(self, factory: Callable) -> tuple[LegacyTarget, ...]:
        """Bind validated native pairs to caller-owned old/P5 diagnostic channels."""
        if self.stage == "write" or not callable(factory):
            raise ValueError("Diagnostic target binding requires a diagnostic stage")
        result = []
        mixed = self.module.startswith("TCUWP4P5")
        for index, address in enumerate(self.target_metadata):
            old = (self.module.startswith("TCUWP4") and not mixed) or (
                mixed and index == 1
            )
            channel = factory(address, "p4" if old else "p5")
            if not isinstance(channel, NativeProgrammingChannel) or old != isinstance(
                channel, VendorDiagnosticChannel
            ):
                raise ValueError(
                    "Factory returned a channel with the wrong native retry policy"
                )
            result.append(LegacyTarget(address.request, channel))
        return tuple(result)

    def report(self) -> dict:
        return {
            "module": self.module,
            "stage": self.stage,
            "native_build": self.native_build,
            "container_sha256": self.container_sha256,
            "cpu_index": self.cpu_index,
            "addresses": [address.report() for address in self.target_metadata],
            "programming_authorized": False,
            "vehicle_compatibility_validated": False,
        }


def bind_legacy_context(
    container: CalibrationContainer,
    node: int,
    observed_cids: tuple[str, ...],
    selection: CalibrationSelection,
    identity: NativeModuleIdentity,
    attachments: Mapping[str, bytes] | None = None,
    observations: Mapping | None = None,
) -> LegacyInputs:
    """Bind imported CUW CPU records/catalog rows to actual legacy stage inputs.

    No geometry, image bytes, passwords, identity or CPU type can be supplied as
    observations. Attachments contain only explicit authorized security material;
    duplicate metadata/attachment values must agree. No provider is invoked here.
    """
    from scripts.calibration import (
        CalibrationContainer,
        native_selection_metadata,
    )
    from scripts.calibration_catalog import (
        Address,
        CalibrationSelection,
        SelectionContext,
    )
    from scripts.native_modules import NativeModuleIdentity, identify_native_module

    if (
        not isinstance(container, CalibrationContainer)
        or not isinstance(selection, CalibrationSelection)
        or not isinstance(identity, NativeModuleIdentity)
        or type(node) is not int
        or not 1 <= node <= 9
    ):
        raise TypeError(
            "Parsed CUW, native catalog selection, exact source identity and node required"
        )
    if identify_native_module(identity.sha256, identity.module_name) != identity:
        raise ValueError("Native source identity differs from shared exact registry")
    profile = legacy_module_profile(identity.module_name, identity.sha256)
    module = identity.module_name
    stage = (
        "write"
        if module in _WRITERS
        else "prepare"
        if module in _PREPARERS
        else "get_cid"
    )
    attachments = {} if attachments is None else attachments
    observations = {} if observations is None else observations
    security_names = {
        "ecu_auth_key": 16,
        "service_auth_key": 16,
        "authorized_key": 16,
        "nonce": 16,
        "security_access_password": 2,
    }
    allowed_observations = {
        "stage",
        "cpu_index",
        "use_new_password",
        "native_retry_flag_728",
        "native_retry_flag_72c",
        "native_flag_740",
        "previous_addresses",
    }
    if (
        not isinstance(attachments, Mapping)
        or not isinstance(observations, Mapping)
        or set(attachments) - security_names.keys()
        or set(observations) - allowed_observations
    ):
        raise ValueError(
            "Unknown native authorization attachment or context observation"
        )
    for name, value in attachments.items():
        if type(value) is not bytes or len(value) != security_names[name]:
            raise ValueError("Authorization attachment has incorrect native width")
    for name, value in observations.items():
        if (
            name not in ("cpu_index", "previous_addresses", "stage")
            and type(value) is not bool
        ):
            raise ValueError("Native context flags require observed booleans")
    requested_stage = observations.get("stage", stage)
    if requested_stage != stage:
        if (
            requested_stage != "gateway"
            or "ChangeToReprogGatewayMode" not in identity.callable_exports
        ):
            raise ValueError(
                "Requested native stage differs from supplied source export"
            )
        stage = requested_stage
    index = observations.get("cpu_index", 0)
    bound = bind_native_cpu_context(
        container,
        node,
        observed_cids,
        selection,
        stage=stage,
        cpu_index=index,
        previous_addresses=observations.get("previous_addresses", ()),
        materialize_images=stage == "write"
        or (
            (
                _PREPARERS.get(module) in ("airbag", "sonar")
                or (
                    stage == "gateway"
                    and _PREPARERS.get(module) == "body"
                    and not _flag(
                        _native_parameter_values(selection), "ExternalMemoryFlag"
                    )
                )
            )
            and bool(selection.value("CANCommunicationSpeedAddress"))
        ),
    )
    cpus, item = bound.cpus, bound.selected
    base = bound.base_metadata
    params, base_params = bound.parameters, bound.base_parameters
    suffix = {
        "write": "FlashWrite",
        "prepare": "PrepareWrite",
        "get_cid": "GetCID",
        "gateway": "ChangeToReprogGatewayMode",
    }[stage]
    if selection.value("DLLFileNameFor" + suffix) != module:
        raise ValueError(
            "Imported native dispatch module differs from exact source identity"
        )

    def hex_bytes(value, width):
        if not isinstance(value, str) or not re.fullmatch(
            rf"[0-9a-fA-F]{{{width * 2}}}", value
        ):
            raise ValueError("Missing or malformed native hexadecimal metadata")
        return bytes.fromhex(value)

    def security(name, value):
        native = hex_bytes(value, security_names[name]) if value else None
        supplied = attachments.get(name)
        if native is not None and supplied is not None and native != supplied:
            raise ValueError(
                "Authorization attachment conflicts with imported metadata"
            )
        return native if native is not None else supplied

    location = bound.location_id
    addresses = bound.target_metadata
    selectors = selection._lines("GetCANIDFunctionNameFor" + suffix)
    if not addresses and module != "TCUWP4CanCentralGWPrepareWriter.dll":
        raise ValueError("Imported native stage has no communication addresses")
    if stage == "get_cid":
        return LegacyInputs(
            module,
            stage,
            profile["native_build"],
            None,
            None,
            addresses,
            container.digest,
            index,
            MappingProxyType(base_params),
        )

    image, first_image = bound.image, bound.first_image
    if stage == "write" and (image is None or first_image is None):
        raise ValueError("Selected native stage requires an ordinary CPU image")
    security_password = None
    password_lines = (
        selection.value("SecurityAccessPassword").splitlines()
        if module in _PREPARERS and _PREPARERS[module] in ("airbag", "sonar")
        else []
    )
    if password_lines:
        if len(password_lines) > 2:
            raise ValueError("Native SecurityAccessPassword has more than two rows")
        security_password = password_lines[0]
    security_password = security("security_access_password", security_password)
    # Reader404708 reads Vehicle globals before the node-schema branch.
    # Legacy no-argument getters are distinct from their node overloads.
    ecu_auth = security("ecu_auth_key", item.vehicle_values.get("ecuauthkey", ""))
    service_auth = security(
        "service_auth_key", item.vehicle_values.get("serviceauthkey", "")
    )
    prepare = LegacyPrepareContext(
        first_image.data if first_image is not None else None,
        base["kind_of_ecu"],
        base_params,
        cpu_count=len(cpus),
        address_extended=bool(addresses and addresses[0].extended),
        security_access_password=security_password,
        ecu_auth_key=ecu_auth,
        native_flag_728_nonempty=observations.get("native_retry_flag_728", False),
    )
    cpu = None
    tester_request = None
    if stage == "write":
        assert image is not None
        if location is None:
            raise ValueError("Native legacy writer requires imported CPU LocationID")
        use_new = observations.get("use_new_password", False)
        body = _WRITERS[module] in ("body4", "body5", "cxpi")
        needs_new = (
            use_new and not (body and _flag(params, "ExternalMemoryFlag"))
        ) or (
            observations.get("native_retry_flag_728", False)
            and _WRITERS[module] in ("airbag", "security_airbag")
        )
        old_password, new_password = native_cpu_passwords(
            bound,
            observed_cids,
            require_new=needs_new,
            resolve_new=needs_new,
            use_metadata_new_password=_WRITERS[module]
            in ("body4", "body5", "cxpi", "security_airbag", "security_chassis"),
        )
        selected_password = old_password
        if use_new and not (body and _flag(params, "ExternalMemoryFlag")):
            if new_password is None:
                raise ValueError(
                    "Native new-password selection lacks authorized file data"
                )
            selected_password = new_password
        alternate: Callable[[], Mapping[str, str]] | None = None
        if _WRITERS[module] == "vforest" and params.get("AlternateCPUType"):

            def resolve_alternate():
                return _native_parameter_values(
                    selection.catalog.select_metadata(
                        base["kind_of_ecu"],
                        params["AlternateCPUType"],
                        base["contact_type"],
                        stage="write",
                        required_spec=base["required_spec"],
                    )
                )

            alternate = resolve_alternate

        cpu = LegacyCPU(
            image.data,
            location,
            selected_password,
            params,
            cpu_index=index,
            cpu_count=len(cpus),
            s0_header=image.s0_header or None,
            nonce=security("nonce", item.values.get("nonce", "")),
            authorized_key=security("authorized_key", item.values.get("seedkey", "")),
            id_big_endian=_flag(base_params, "BigEndianFlag")
            if _WRITERS[module] in ("body4", "body5", "cxpi")
            else None,
            native_retry_flag_728=observations.get("native_retry_flag_728", False),
            native_retry_flag_72c=observations.get("native_retry_flag_72c", False),
            native_flag_740=observations.get("native_flag_740", False),
            password_is_new=use_new,
            alternate_password=old_password if use_new else new_password,
            alternate_parameters=alternate,
            flash_size=image.flash_size,
        )
        if len(addresses) != 2 or selectors != ("GetCanIDsFromLocationIDForWrite",):
            raise ValueError(
                "Legacy write requires native LocationID physical/finish routing"
            )
        finish = addresses[1]
        kind = _WRITERS[module]
        if kind in (
            "airbag",
            "security_airbag",
            "sonar",
            "dss",
            "chassis",
            "security_chassis",
        ):
            first_location = cpus[0].values.get("locationid", "")
            first_bytes = hex_bytes(first_location, 8)
            finish_bytes = (
                b"\x07\x20" if first_bytes[6:8] == b"\x07\x20" else b"\x07\x40\xfe"
            )
        else:
            finish_bytes = finish.request
        if kind in ("chassis", "security_chassis", "vforest"):
            finish_bytes = finish_bytes[:2]
        elif kind == "cxpi":
            # LocationID1cb0 zeroes the seven-byte record before assigning0720.
            finish_bytes = finish_bytes.ljust(3, b"\0")
        addresses = (
            addresses[0],
            Address(finish_bytes, bytes(len(finish_bytes)), len(finish_bytes) == 3),
        )
        if kind == "cxpi":
            current_selection = selection.catalog.select_metadata(
                **native_selection_metadata(container, node=node, cpu_index=index),
                stage="write",
            )
            prepare_selectors = current_selection._lines(
                "GetCANIDFunctionNameForPrepareWrite"
            )
            prepare_addresses = current_selection.addresses(
                prepare_selectors, SelectionContext()
            )
            if not prepare_addresses:
                raise ValueError(
                    "Native CXPI tester-present requires its first prepare address"
                )
            prefix = prepare_addresses[0].request.ljust(3, b"\0").rjust(5, b"\0")
            tester_request = MappingProxyType(
                {
                    "operation": "write_messages",
                    "protocol": 6,
                    "tx_flags": 0x80,
                    "data_hex": (prefix + b"\x3e\x02").hex(),
                    "count": 1,
                }
            )
        if _WRITERS[module] == "vforest":
            vforest_groups(cpu.image)
        else:
            info = parse_block_info(params.get("BlockSizeInfo", ""))
            read_s0 = _WRITERS[module] in ("body4", "body5", "cxpi") and _flag(
                params, "ReadBlockRangeFromS0HeaderFlag"
            )
            if read_s0 and cpu.s0_header is None:
                raise ValueError("Imported CPU lacks required decoded S0 block header")
            if all(group.size_kib and group.count for group in info):
                sizes = block_sizes(info)
                ranges = block_ranges(
                    info,
                    grouped=_WRITERS[module]
                    in ("chassis", "security_chassis", "sonar"),
                    s0_header=cpu.s0_header if read_s0 else None,
                )
                if (
                    _WRITERS[module] in ("chassis", "security_chassis")
                    and ranges[0][0] != 1
                ):
                    sizes = (0,) + sizes
                if (
                    read_s0
                    and sum(sizes[first - 1] for first, last in ranges)
                    != cpu.flash_size
                ):
                    raise ValueError(
                        "Imported S0 block selection differs from native flash size"
                    )
                legacy_blocks(cpu.image, sizes, ranges, 0)
        if _WRITERS[module] in ("security_airbag", "security_chassis") and (
            cpu.nonce is None or cpu.authorized_key is None
        ):
            raise ValueError("Imported security writer lacks authorized nonce/key")
    if (
        stage == "prepare"
        and _PREPARERS[module] in ("airbag", "sonar")
        and prepare.security_access_password is None
    ):
        raise ValueError("Native selected catalog lacks SecurityAccessPassword")
    if (
        stage == "prepare"
        and _PREPARERS[module].startswith("security")
        and prepare.ecu_auth_key is None
    ):
        raise ValueError("Imported security preparation lacks ECU authorization")
    return LegacyInputs(
        module,
        stage,
        profile["native_build"],
        cpu,
        prepare,
        addresses,
        container.digest,
        index,
        MappingProxyType(base_params),
        MappingProxyType(
            {
                name: value
                for name, value in {
                    "ecu_auth_key": ecu_auth,
                    "service_auth_key": service_auth,
                    "nonce": cpu.nonce if cpu is not None else None,
                    "authorized_key": cpu.authorized_key if cpu is not None else None,
                }.items()
                if value is not None
            }
        ),
        tester_request,
    )


def _native_parameter_values(source):
    names = {name for table in source.catalog.tables for name in table.headers}
    values = {name: value for name in names if (value := source.value(name)) != ""}
    if len(values) > 256:
        raise ValueError("Native selected parameter row exceeds host field budget")
    return MappingProxyType(values)


@dataclass(frozen=True)
class NativeCPUContext:
    """Shared imported CPU/catalog binding; contains no invented physical fields."""

    selected: NativeCPU = field(repr=False)
    cpus: tuple[NativeCPU, ...] = field(repr=False)
    metadata_version: int
    base_metadata: Mapping[str, str]
    parameters: Mapping[str, str] = field(repr=False)
    base_parameters: Mapping[str, str] = field(repr=False)
    image: LegacyImage | None = field(repr=False)
    first_image: LegacyImage | None = field(repr=False)
    location_id: bytes | None = field(repr=False)
    target_metadata: tuple[Address, ...] = field(repr=False)


def bind_native_cpu_context(
    container: CalibrationContainer,
    node: int,
    observed_cids: tuple[str, ...],
    selection: CalibrationSelection,
    *,
    stage: str,
    cpu_index: int = 0,
    previous_addresses: tuple[Address, ...] = (),
    materialize_images: bool = True,
    original_executable_build: int | None = None,
) -> NativeCPUContext:
    """Shared native metadata/catalog association for ordinary CPU families.

    File-only schemas retain their NativeCPU.files for a family-specific decoder.
    This binder validates source metadata and never calls a transport provider.
    """
    from scripts.calibration import (
        CalibrationContainer,
        bind_native_cpu_records,
        inspect_attached_metadata,
        native_selection_metadata,
    )
    from scripts.calibration_catalog import (
        STAGES,
        CalibrationSelection,
        SelectionContext,
    )

    if not isinstance(container, CalibrationContainer) or not isinstance(
        selection, CalibrationSelection
    ):
        raise TypeError("Parsed CUW and selected native catalog row required")
    if type(materialize_images) is not bool:
        raise TypeError("Explicit native image-materialization flag required")
    if original_executable_build is not None and (
        type(original_executable_build) is not int
        or original_executable_build not in (12, 18)
    ):
        raise ValueError("Original executable CPU binding requires build 12 or 18")
    if stage not in STAGES:
        raise ValueError("Unknown native CPU binding stage")
    cpus = bind_native_cpu_records(container)
    if (
        type(cpu_index) is not int
        or not 0 <= cpu_index < len(cpus)
        or type(node) is not int
        or not 1 <= node <= 9
    ):
        raise ValueError("Selected native CPU/node outside imported metadata")
    item = cpus[cpu_index]
    if (item.node and item.node != node) or (not item.node and node != 1):
        raise ValueError("Selected CPU does not belong to requested native node")
    base = native_selection_metadata(container, node=node, cpu_index=0)
    expected = selection.catalog.select_metadata(**base, stage=stage)
    if expected.key != selection.key:
        raise ValueError("Selected catalog key differs from native base CPU metadata")
    current = native_selection_metadata(container, node=node, cpu_index=cpu_index)
    selected = selection.catalog.select_metadata(**current, stage=stage)

    def image(cpu):
        if not materialize_images or cpu.image is None:
            return None
        if cpu.values.get("compressionalgorithm", "") not in ("", "00"):
            raise ValueError(
                "Ordinary legacy CPU archive declares non-native compression"
            )
        return materialize_legacy_image(
            cpu.image.data, filename=cpu.values.get("cpuimagename", "")
        )

    location_value = item.values.get("locationid", "")
    byte_location = bool(re.fullmatch(r"[0-9a-fA-F]{16}", location_value))
    if location_value and not byte_location and original_executable_build is None:
        raise ValueError("Native LocationID requires eight hexadecimal bytes")
    location = bytes.fromhex(location_value) if byte_location else None
    diag = item.node_values.get("diagid", "") if item.node else ""
    if diag and not re.fullmatch(r"(?:[0-9a-fA-F]{4}|[0-9a-fA-F]{6})", diag):
        raise ValueError("Native node diagnostic ID requires two or three bytes")
    context = SelectionContext(
        observed_cids,
        location,
        (bytes.fromhex(diag),) if diag else (),
        previous_addresses,
    )
    suffix = STAGES[stage][0]
    selectors = selection._lines("GetCANIDFunctionNameFor" + suffix)
    # Original executables retain a string LocationID and use their own headers.
    addresses = (
        selection.addresses(selectors, context)
        if selectors and original_executable_build is None
        else ()
    )
    materialized = image(item)
    return NativeCPUContext(
        item,
        cpus,
        inspect_attached_metadata(container.attached.data)["format_version"],
        MappingProxyType(base),
        _native_parameter_values(selected),
        _native_parameter_values(selection),
        materialized,
        materialized if cpu_index == 0 else image(cpus[0]),
        location,
        addresses,
    )


def native_cpu_passwords(
    context: NativeCPUContext,
    observed_cids: tuple[str, ...],
    *,
    require_new: bool = False,
    use_metadata_new_password: bool = True,
    resolve_new: bool = True,
) -> tuple[int, int | None]:
    """Native TargetData match and GetNewPassword3090/GetPassword2ef0 extraction."""
    from scripts.calibration import NativeCPU

    if any(
        type(flag) is not bool
        for flag in (require_new, use_metadata_new_password, resolve_new)
    ) or (require_new and not resolve_new):
        raise ValueError(
            "Explicit consistent native password-resolution flags required"
        )
    item = context.selected
    if not isinstance(item, NativeCPU):
        raise TypeError("Imported native CPU metadata required for passwords")
    # Validate observed identities without assigning a synthetic address/identity.
    from scripts.calibration_catalog import SelectionContext

    SelectionContext(observed_cids)
    count_value = item.values.get("numberoftargets", "")
    if not re.fullmatch(r"[0-9]{1,4}", count_value) or not 0 < int(count_value) <= 4096:
        raise ValueError("Native CPU target calibration count missing or excessive")

    def value32(value):
        if not re.fullmatch(r"[0-9a-fA-F]{1,8}", value):
            raise ValueError(
                "Native password metadata must be bounded hexadecimal uint32"
            )
        return int(value, 16)

    matches = []
    for ordinal in range(1, int(count_value) + 1):
        cid = item.values.get(f"{ordinal:02}_targetcalibration", "")
        if not cid:
            raise ValueError("Declared native target calibration row missing")
        if cid in observed_cids:
            value = item.values.get(f"{ordinal:02}_targetdata", "")
            matches.append(0 if context.metadata_version in (8, 9) else value32(value))
    if not matches or len(set(matches)) != 1:
        raise ValueError("Observed CID does not select one native CPU password")
    if not resolve_new:
        return matches[0], None
    new_value = item.values.get("newpassword", "")
    if new_value and use_metadata_new_password:
        new = value32(new_value)
    elif require_new or (
        context.image is not None and context.parameters.get("PasswordAddress")
    ):
        if context.image is None:
            raise ValueError(
                "Native image-password extraction requires materialized CPU data"
            )
        address_value = context.parameters.get("PasswordAddress", "")
        # GetParameter failure leaves zeroed text; CBytes(empty).GetUnsignedLong=0.
        offset = value32(address_value) if address_value else 0
        if offset + 4 > len(context.image.data):
            raise ValueError("Native PasswordAddress exceeds materialized CPU buffer")
        order = _number(context.parameters, "ByteOrder")
        new = int.from_bytes(
            context.image.data[offset : offset + 4],
            "little" if order & 0xFFFF == 0 else "big",
        )
    else:
        new = None
    return matches[0], new
