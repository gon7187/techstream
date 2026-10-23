"""Recovered CUW2026 DH wire helpers; physical behavior remains unconfirmed.

Only source-reviewed operations are exposed. Family orchestration is tracked in
leaf-33 and must not be inferred from the presence of these helpers.
"""

import hashlib
import re
import sys
from collections.abc import Mapping
from dataclasses import dataclass, field

from scripts.calibration import CalibrationContainer
from scripts.calibration_2026 import (
    NativeArchive2026,
    native2026_archive,
    native2026_cpu_cmac,
    native2026_cpu_count,
    native2026_cpu_type,
    native2026_global_cpu_index,
    native2026_location_id,
    native2026_metadata_for_cpu,
    native2026_new_calibration_id,
)
from scripts.calibration_catalog import Address, CalibrationSelection, SelectionContext
from scripts.cuw_2026 import DHControllerState2026
from scripts.j2534_2026 import communication_addresses_from_parameter
from scripts.native_modules import NativeModuleIdentity, identify_native_module
from scripts.programming import (
    NativeNegativeResponse,
    NativeProgrammingChannel,
    NativeTransportError,
)
from scripts.programming_2026_common import (
    CanDiag2026,
    CommonResponseError,
    NativeBytes2026,
    NativeControlParameterBase2026,
    NativeGeneralParameters2026,
    NativeParameterBinding2026,
    NativeRuntime2026,
    NativeSecurityComposer2026,
    SecretInfoClient,
    bind_native_parameter2026,
    is_native_exception2026,
)
from scripts.programming_2026_common import (
    diagnostic_mask as common_diagnostic_mask,
)


def _raise_if_host_fault(error: BaseException) -> None:
    if not is_native_exception2026(error) and not isinstance(
        error, (InterruptedError, KeyboardInterrupt)
    ):
        raise error


def _raise_host_cleanup(errors: list[BaseException]) -> None:
    if sys.exception() is None:
        for error in errors:
            if not is_native_exception2026(error):
                raise error


def _require_dh_caller_channel(runtime: NativeRuntime2026) -> None:
    """Native DH phases receive CJ's channel; only opaque wire fixtures create one."""
    connected = runtime.native_channel_connected2026()
    if connected is False:
        raise ValueError("Native DH phase requires its caller's connected channel")
    if connected is None and not runtime.owns_resource("disconnect"):
        runtime.call_owned("connect", "disconnect", protocol=6)


def _record_dh_error(
    state: DHControllerState2026 | None, error: BaseException, kind: int | None
) -> dict:
    """CPass catches preserve prior secondary; CJ2534 adds its distinct status."""
    if isinstance(error, CommonResponseError):
        primary, secondary = error.code, None
    elif isinstance(error, NativeTransportError):
        primary = getattr(error, "native_error_code", 1)
        secondary = getattr(error, "passthru_status", error.code)
    elif is_native_exception2026(error):
        primary, secondary = 9999, None
    else:
        return {}
    if state is not None:
        state.record_native_error(kind, primary, secondary)
        return {
            "native_error_kind": state.error_kind,
            "native_primary_error": state.primary_error,
            "native_passthru_error": state.passthru_error,
        }
    result = {"native_primary_error": primary}
    if secondary is not None:
        result["native_passthru_error"] = secondary
    return result


def _dh_driver_status(error: NativeTransportError) -> int | None:
    """Typed CPass enums must never become CJ2534 timeout/retry statuses."""
    return getattr(error, "passthru_status", error.code)


def _dh_file_view(selection, state):
    """Keep standalone equality; classic CONTROL joins its two native lifetimes."""
    from scripts.programming_2026_common import _control_dh_file_view2026

    if not isinstance(state, DHControllerState2026):
        raise TypeError("Actual loaded-engine DH state required")
    if isinstance(selection, CalibrationSelection):
        return state.metadata, state.global_cpu_index
    classic = isinstance(selection, NativeParameterBinding2026) and (
        selection.module_name
        in ("TCUWCanDHPrepareWriter.dll", "TCUWCanDHFlashWriter.dll")
    )
    view = (
        _control_dh_file_view2026(selection, state)
        if classic or state.metadata != selection.metadata
        else None
    )
    if view is not None:
        return view
    if state.metadata != selection.metadata:
        raise ValueError("Actual same-metadata engine DH state required")
    return state.metadata, state.global_cpu_index


def checksum(data: bytes, extra: bytes = b"") -> int:
    """DHUtils RVA17b0: sum both byte ranges, retaining the low byte."""
    if any(not isinstance(value, bytes) for value in (data, extra)):
        raise ValueError("Immutable checksum bytes required")
    if len(data) + len(extra) > 64 * 1024 * 1024:
        raise ValueError("DH checksum input budget exceeded")
    return (sum(data) + sum(extra)) & 0xFF


def convert_su_characters(data: bytes, start: int, count: int) -> bytes:
    """DHUtils RVA3110: replace nonprintable, quote and backslash with '_'."""
    if (
        not isinstance(data, bytes)
        or len(data) > 4116
        or type(start) is not int
        or type(count) is not int
        or not 0 <= start <= len(data)
        or not 0 <= count <= len(data) - start
    ):
        raise ValueError("Bounded SU regulation byte slice required")
    return (
        data[:start]
        + bytes(
            byte
            if byte == 0 or 0x20 <= byte <= 0x7E and byte not in (0x22, 0x5C)
            else 0x5F
            for byte in data[start : start + count]
        )
        + data[start + count :]
    )


def su_tester_present() -> bytes:
    """DHUtils RVA3150: four-byte CAN ID followed by 3e01."""
    return bytes.fromhex("000007863e01")


def extract_software_id(response: bytes, complement: bytes) -> bytes:
    """DHUtils RVA3db0 consumes five bytes after the four-byte ID and SID."""
    if (
        not isinstance(response, bytes)
        or not 6 <= len(response) <= 4116
        or response[0] != 0x5A
        or not isinstance(complement, bytes)
        or len(complement) > 6
    ):
        raise ValueError("DH software response and six-byte complement required")
    return complement.split(b"\0", 1)[0] + response[1:6].split(b"\0", 1)[0]


def multirom_image_segment(
    archive: NativeArchive2026, start: int, size: int, record_index: int
) -> tuple[bytes, int]:
    """MultiROMFlash1970 copies actual S-records, returning the last consumed row.

    Host bounds reject native uninitialized/overflowing allocation outcomes.
    Address gaps are concatenated exactly as the native record loop does.
    """
    if (
        not isinstance(archive, NativeArchive2026)
        or any(type(value) is not int for value in (start, size, record_index))
        or not 0 <= start <= 0xFFFFFFFF
        or not 0 < size <= 64 * 1024 * 1024
        or not 0 <= record_index <= len(archive.records)
    ):
        raise ValueError("Actual archive and bounded native MultiROM segment required")
    result = bytearray()
    last = 0
    for index in range(record_index, len(archive.records)):
        address, data = archive.records[index]
        if (
            type(address) is not int
            or not 0 <= address <= 0xFFFFFFFF
            or not isinstance(data, bytes)
            or len(data) > 0xFFFFFFFF - address
        ):
            raise ValueError("Malformed native S-record range")
        if address < start:
            if start >= address + len(data):
                continue
            piece = data[start - address :]
            if len(piece) > size - len(result):
                raise ValueError(
                    "Native partial S-record copy would overflow allocation"
                )
        else:
            piece = data[: size - len(result)]
        result.extend(piece)
        last = index
        if len(result) == size:
            return bytes(result), last
    raise ValueError("Native MultiROM allocation would contain uninitialized bytes")


def request_download(
    channel: NativeProgrammingChannel,
    address: bytes,
    size: int,
    *,
    value_subtracted_from_max_number_block_length: int = 1,
) -> int:
    """DHUtils RVA5610 builds 340144 + 4-byte address + 4-byte size."""
    if (
        not isinstance(address, bytes)
        or len(address) != 4
        or type(size) is not int
        or not 0 <= size <= 0x7FFFFFFF
        or type(value_subtracted_from_max_number_block_length) is not int
        or not 0 <= value_subtracted_from_max_number_block_length <= 0xFFFFFFFF
    ):
        raise ValueError("Four-byte native address and signed positive size required")
    response = channel.call(
        b"\x34\x01\x44" + address + size.to_bytes(4, "big"), b"\x74\x20"
    )
    if len(response) < 4:
        raise ValueError("Truncated DH request-download result")
    subtract = value_subtracted_from_max_number_block_length or 1
    return (int.from_bytes(response[2:4], "big") - subtract) & 0xFFFFFFFF


def request_verification_download(
    channel: NativeProgrammingChannel, address: bytes, size: int
) -> int:
    """DHFlashWriter RVA2180 requests the second verify transfer via3101f011."""
    if (
        not isinstance(address, bytes)
        or len(address) != 4
        or type(size) is not int
        or not 0 <= size <= 0x7FFFFFFF
    ):
        raise ValueError(
            "Four-byte native verification address and bounded size required"
        )
    reply = channel.call(
        bytes.fromhex("3101f011000144") + address + size.to_bytes(4, "big"),
        bytes.fromhex("7101f01120"),
    )
    if len(reply) < 7:
        raise CommonResponseError(0x20, reply)
    return int.from_bytes(reply[5:7], "big") - 1


def read_software_id(channel: NativeProgrammingChannel, complement: bytes) -> bytes:
    """DHUtils RVA5300 and3db0:1a81 then configured prefix + five bytes."""
    if not isinstance(complement, bytes) or len(complement) > 6:
        raise ValueError("Six-byte native ComplementCID required")
    return extract_software_id(channel.call(b"\x1a\x81", b"\x5a"), complement)


def transfer_data(
    channel: NativeProgrammingChannel, data: bytes, offset: int, count: int
) -> int:
    """DHUtils RVA7bc0 sends36 plus bytes, advances offset only after76."""
    if (
        not isinstance(data, bytes)
        or len(data) > 64 * 1024 * 1024
        or type(offset) is not int
        or type(count) is not int
        or not 0 <= offset <= len(data)
        or not 0 < count <= min(len(data) - offset, channel.message_limit - 1)
    ):
        raise ValueError("Bounded DH transfer byte range required")
    channel.call(b"\x36" + data[offset : offset + count], b"\x76")
    return offset + count


def request_transfer_exit(channel: NativeProgrammingChannel) -> None:
    """DHUtils RVA5fb0/60d0:37/77 without a synthetic block counter."""
    channel.call(b"\x37", b"\x77")


def ecu_reset(channel: NativeProgrammingChannel, *, phase5: bool = False) -> None:
    """DHUtils RVA3510/3630 use51 versus5101 positive prefixes."""
    if type(phase5) is not bool:
        raise ValueError("Boolean Phase5 protocol selector required")
    channel.call(b"\x11\x01", b"\x51\x01" if phase5 else b"\x51")


def verify_checksum(channel: NativeProgrammingChannel, checksum_byte: int) -> None:
    """DHUtils RVA74e0: checksum is checked in the reply, not sent."""
    if type(checksum_byte) is not int or not 0 <= checksum_byte <= 255:
        raise ValueError("Native byte checksum required")
    channel.call(b"\x31\x01\xf0\x10", b"\x71\x01\xf0\x10" + bytes((checksum_byte,)))


def verify_su_checksum(channel: NativeProgrammingChannel) -> None:
    """DHUtils RVA75c0: SU variant explicitly requests status00."""
    channel.call(b"\x31\x01\xf0\x13\x00", b"\x71\x01\xf0\x13\x00")


def verify_result(channel: NativeProgrammingChannel) -> None:
    """DHUtils RVA76a0 sends3101f01101 and requires7101f01100."""
    channel.call(b"\x31\x01\xf0\x11\x01", b"\x71\x01\xf0\x11\x00")


def change_default_session(channel: NativeProgrammingChannel) -> None:
    """DHUtils RVA1ba0 uses the native1089/5089 session pair."""
    channel.call(b"\x10\x89", b"\x50\x89")


def change_reprogramming_mode(channel: NativeProgrammingChannel) -> None:
    """DHUtils RVA2280 uses1085/5085."""
    channel.call(b"\x10\x85", b"\x50\x85")


def read_current_session(channel: NativeProgrammingChannel) -> int:
    """DHUtils RVA4f20 requests105f and returns the byte following50."""
    response = channel.call(b"\x10\x5f", b"\x50")
    if len(response) < 2:
        raise ValueError("Truncated DH current-session response")
    return response[1]


def read_hard_soft_info(channel: NativeProgrammingChannel) -> bytes:
    """DHUtils RVA5030 reads22fd10 with62fd10 positive prefix."""
    return channel.call(b"\x22\xfd\x10", b"\x62\xfd\x10")


def read_soft_mask(
    channel: NativeProgrammingChannel,
    *,
    pid_for_read_soft_mask_id: int = 0xA7,
    soft_mask_id_resp_data_size: int = 10,
) -> bytes:
    """DHUtils RVA5160 metadata defaults A7/10, response size excludes CAN ID."""
    if (
        type(pid_for_read_soft_mask_id) is not int
        or not 0 <= pid_for_read_soft_mask_id <= 255
        or type(soft_mask_id_resp_data_size) is not int
        or not 2 <= soft_mask_id_resp_data_size <= channel.message_limit
    ):
        raise ValueError("Bounded native soft-mask PID and response size required")
    response = channel.call(
        bytes((0x21, pid_for_read_soft_mask_id)),
        bytes((0x61, pid_for_read_soft_mask_id)),
    )
    if len(response) < soft_mask_id_resp_data_size:
        raise ValueError("Truncated DH soft-mask response")
    return response


def _write_raw(runtime: NativeRuntime2026, data: bytes, tx_flags: int = 0) -> None:
    count = runtime.call(
        "write_messages", protocol=6, tx_flags=tx_flags, data=data, count=1
    )
    if type(count) is not int or count != 1:
        raise ValueError("DH raw CAN write did not write exactly one message")


def change_phase5_session(
    runtime: NativeRuntime2026, *, extended: bool = False
) -> None:
    """DHUtils RVA1cc0/1e50: three writes per address, each followed by100ms."""
    if type(extended) is not bool:
        raise ValueError("Boolean native session selector required")
    pdu = b"\x10\x83" if extended else b"\x10\x81"
    for address, extension, flags in (
        (b"\0\0\x07\x51", b"", 0),
        (b"\0\0\x07\x77", b"", 0),
        (b"\0\0\x07\x7f", b"\xfe", 0x80),
    ):
        for _ in range(3):
            _write_raw(runtime, address + extension + pdu, flags)
            runtime.call("wait", milliseconds=100)


def diagnostic_mask(
    runtime: NativeRuntime2026, *, extended_addressing: bool = False
) -> None:
    """DHUtils RVA31a0/3230: raw07[20|40]a027, three100ms-spaced writes."""
    if type(extended_addressing) is not bool:
        raise ValueError("Boolean native extended-addressing selector required")
    data = (
        b"\0\0\x07\x40\xfe\xa0\x27" if extended_addressing else b"\0\0\x07\x20\xa0\x27"
    )
    for _ in range(3):
        _write_raw(runtime, data, 0x80 if extended_addressing else 0)
        runtime.call("wait", milliseconds=100)


def diagnostic_mask_phase5(runtime: NativeRuntime2026) -> None:
    """DHUtils RVA32e0:8582 broadcast over all three Phase5 addresses."""
    for address, extension, flags in (
        (b"\0\0\x07\x51", b"", 0),
        (b"\0\0\x07\x77", b"", 0),
        (b"\0\0\x07\x7f", b"\xfe", 0x80),
    ):
        for _ in range(3):
            _write_raw(runtime, address + extension + b"\x85\x82", flags)
            runtime.call("wait", milliseconds=100)


def diagnostic_mask_su(runtime: NativeRuntime2026) -> None:
    """DHUtils RVA3470 waits100ms twice, then2000ms after the third write."""
    for index in range(3):
        _write_raw(runtime, b"\0\0\x07\x20\xa0\x27")
        if index != 2:
            runtime.call("wait", milliseconds=100)
    runtime.call("wait", milliseconds=2000)


def calculate_seed_key(seed: bytes, key_table: tuple[bytes, ...]) -> bytes:
    """DHUtils RVA1940 transforms four seed bytes using supplied two-byte rounds.

    No table is embedded or fetched. The native CBytes ushort constructor writes
    big endian; the surrounding x86 loads then exchange its two output bytes.
    """
    if (
        not isinstance(seed, bytes)
        or len(seed) != 4
        or not isinstance(key_table, tuple)
        or len(key_table) > 4096
        or any(not isinstance(key, bytes) or len(key) != 2 for key in key_table)
    ):
        raise ValueError(
            "Four-byte DH seed and bounded supplied two-byte key rounds required"
        )
    a, b, c, d = seed
    for high, low in key_table:
        upper, lower = c ^ high, d ^ low
        feedback = ((lower >> 1) + (lower >> 2) + (lower >> 4) + (upper >> 7)) & 1
        shifted = ((((upper << 8) | lower) << 1) + feedback) & 0xFFFF
        a, b, c, d = (shifted & 255) ^ high ^ a, (shifted >> 8) ^ low ^ b, a, b
    return bytes((a, b, c, d))


def request_seed(
    channel: NativeProgrammingChannel, *, flag_to_non_seed_resp_status: bool = False
) -> bytes:
    """DHUtils RVA5bb0 reads four seed bytes and optional trailing status."""
    if type(flag_to_non_seed_resp_status) is not bool:
        raise ValueError("Boolean native seed response-status flag required")
    response = channel.call(b"\x27\x01", b"\x67\x01")
    if len(response) < (6 if flag_to_non_seed_resp_status else 7):
        raise ValueError("Truncated DH seed response")
    return response[2:6]


def send_key(
    channel: NativeProgrammingChannel,
    key: bytes,
    *,
    flag_to_non_send_key_resp_status: bool = False,
    phase5: bool = False,
) -> None:
    """DHUtils RVA62f0/6480: classic status34; Phase5 only checks6702."""
    if (
        not isinstance(key, bytes)
        or not 0 < len(key) <= channel.message_limit - 2
        or type(flag_to_non_send_key_resp_status) is not bool
        or type(phase5) is not bool
    ):
        raise ValueError(
            "Bounded supplied key and Boolean native response flags required"
        )
    expected = b"\x67\x02"
    if not (phase5 or flag_to_non_send_key_resp_status):
        expected += b"\x34"
    channel.call(b"\x27\x02" + key, expected)


def verify_soft_mask(
    channel: NativeProgrammingChannel,
    expected_id: str,
    *,
    pid_for_read_soft_mask_id: int = 0xA7,
    soft_mask_id_resp_data_size: int = 0,
) -> None:
    """DHUtils RVA7d10 compares response bytes2..3 as four hex characters."""
    if (
        not isinstance(expected_id, str)
        or len(expected_id) > 1024
        or type(soft_mask_id_resp_data_size) is not int
        or not 0 <= soft_mask_id_resp_data_size <= channel.message_limit
    ):
        raise ValueError("Bounded native location text and response size required")
    response = read_soft_mask(
        channel,
        pid_for_read_soft_mask_id=pid_for_read_soft_mask_id,
        soft_mask_id_resp_data_size=max(4, soft_mask_id_resp_data_size),
    )
    if response[2:4].hex().lower() != expected_id.split("\0", 1)[0].lower():
        raise CommonResponseError(0x2F, response)


def write_software_id(
    channel: NativeProgrammingChannel,
    software_id: bytes,
    *,
    write_software_id_resp_type: int = 0,
) -> None:
    """DHUtils RVA7f20 sendsa099 with identifier bytes6..10; replye099[01]."""
    if (
        not isinstance(software_id, bytes)
        or not 11 <= len(software_id) <= 4116
        or type(write_software_id_resp_type) is not int
        or not -0x80000000 <= write_software_id_resp_type <= 0x7FFFFFFF
    ):
        raise ValueError(
            "Bounded eleven-byte DH software identifier and native response type required"
        )
    expected = b"\xe0\x99" + (b"\x01" if write_software_id_resp_type == 1 else b"")
    channel.call(b"\xa0\x99" + software_id[6:11], expected)


def writable_write_soft_mask(
    channel: NativeProgrammingChannel, location_id: str
) -> None:
    """WritableSoftMask getter RVA1e00: 3b08 + two location bytes, 7b08."""
    value = NativeBytes2026.from_hex(location_id)
    value.set_num(2)
    channel.call(b"\x3b\x08" + value.data, b"\x7b\x08")


def writable_write_software_id(
    channel: NativeProgrammingChannel, software_id: bytes
) -> None:
    """WritableSoftMask getter RVA1f50: 3b09 + five ID bytes at6, 7b09."""
    if not isinstance(software_id, bytes) or not 11 <= len(software_id) <= 4116:
        raise ValueError("Bounded eleven-byte native calibration ID required")
    channel.call(b"\x3b\x09" + software_id[6:11], b"\x7b\x09")


def writable_verify_soft_mask(
    channel: NativeProgrammingChannel, location_id: str
) -> None:
    """WritableSoftMask getter RVA1cb0: 1ab0/5a then two raw bytes as hex."""
    if not isinstance(location_id, str) or len(location_id) > 1024:
        raise ValueError("Bounded native location text required")
    reply = channel.call(b"\x1a\xb0", b"\x5a")
    if len(reply) < 3:
        raise CommonResponseError(0x2E, reply)
    if reply[1:3].hex().lower() != location_id.split("\0", 1)[0].lower():
        raise CommonResponseError(0x2F, reply)


def decode_dhuds_software_ids(response: bytes) -> tuple[bytes, ...]:
    """DHUDS getter RVA1520 truncates each sixteen-byte record to15 C chars."""
    if (
        not isinstance(response, bytes)
        or not 4 <= len(response) <= 4116
        or not response.startswith(b"\x62\xf1\x81")
        or len(response) < 4 + response[3] * 16
    ):
        raise ValueError("Malformed DH UDS software ID record array")
    return tuple(
        value
        for index in range(response[3])
        if (value := response[4 + index * 16 : 19 + index * 16].split(b"\0", 1)[0])
    )


def read_dhuds_software_ids(channel: NativeProgrammingChannel) -> tuple[bytes, ...]:
    """DHUDS getter1520 requests22f181 without inventingComplementCID."""
    return decode_dhuds_software_ids(channel.call(b"\x22\xf1\x81", b"\x62\xf1\x81"))


def get_software_info(
    channel: NativeProgrammingChannel,
) -> tuple[int, tuple[bytes, ...]]:
    """DHUtils RVA4bd0/4eb5 reads every nonzero selector, preserving its order."""
    response = channel.call(b"\x1a\x88\x00", b"\x5a\x88\x00")
    selectors = tuple(selector for selector in response[3:63] if selector)
    identifiers = []
    for selector in selectors:
        prefix = bytes((0x5A, 0x88, selector))
        response = channel.call(bytes((0x1A, 0x88, selector)), prefix)
        identifier = response[3:19]
        identifiers.append(
            convert_su_characters(identifier, 0, len(identifier)).split(b"\0", 1)[0]
        )
    return len(selectors), tuple(identifiers)


def request_seed_specified_bytes(
    channel: NativeProgrammingChannel,
    count: int,
    *,
    option: int = 0,
    flag_to_non_seed_16_byte_resp_status: bool = False,
    phase5: bool = False,
) -> bytes:
    """DHUtils RVA5d10/5eb0 appends a nonzero option only for classic CAN."""
    if (
        type(count) is not int
        or not 0 < count <= channel.message_limit - 3
        or type(option) is not int
        or not 0 <= option <= 255
        or type(flag_to_non_seed_16_byte_resp_status) is not bool
        or type(phase5) is not bool
        or phase5
        and option != 0
    ):
        raise ValueError("Bounded native seed byte count, option and flags required")
    request = b"\x27\x01" + (bytes((option,)) if option else b"")
    response = channel.call(request, b"\x67\x01")
    status = not (phase5 or flag_to_non_seed_16_byte_resp_status)
    if len(response) < 2 + count + status:
        raise ValueError("Truncated DH specified-byte seed response")
    return response[2 : 2 + count]


@dataclass(frozen=True)
class DHGetterContext:
    """Actual catalog-dispatch inputs, not manually supplied CAN geometry."""

    identity: NativeModuleIdentity
    addresses: tuple[Address, ...]
    receive_timeout_ms: int
    parameter_sources: tuple[tuple[str, str], ...]

    complement: bytes = b""
    soft_mask_pid: int = 0xA7
    soft_mask_response_size: int = 10
    su_regulation: bool = False
    verify_softmask: bool = False

    def __post_init__(self):
        if (
            not isinstance(self.identity, NativeModuleIdentity)
            or self.identity
            != identify_native_module(self.identity.sha256, self.identity.module_name)
            or self.identity.cuw_build != "2026"
            or self.identity.module_name
            not in (
                "TCUWCanDHUDSSoftwareIDGetter.dll",
                "TCUWCanDHSoftMaskIDGetter.dll",
                "TCUWCanDHSoftwareIDAndSoftMaskIDGetter.dll",
                "TCUWP5CanDHVehicleInfoCIDGetter.dll",
                "TCUWCanDHSoftwareIDGetter.dll",
                "TCUWCanDHWritableCIDGetter.dll",
                "TCUWCanDHWritableSoftMaskIDAndCIDGetter.dll",
            )
            or not isinstance(self.addresses, tuple)
            or not 0 < len(self.addresses) <= 4096
            or any(
                not isinstance(address, Address)
                or address.extended
                and self.identity.module_name != "TCUWCanDHSoftwareIDGetter.dll"
                for address in self.addresses
            )
            or type(self.receive_timeout_ms) is not int
            or not 0 <= self.receive_timeout_ms <= 0x7FFFFFFF
            or not isinstance(self.parameter_sources, tuple)
            or not self.parameter_sources
            or not isinstance(self.complement, bytes)
            or len(self.complement)
            > (
                260
                if self.identity.module_name
                in (
                    "TCUWCanDHSoftwareIDAndSoftMaskIDGetter.dll",
                    "TCUWCanDHSoftwareIDGetter.dll",
                )
                else 6
            )
            or type(self.soft_mask_pid) is not int
            or not 0 <= self.soft_mask_pid <= 255
            or type(self.soft_mask_response_size) is not int
            or not 0 <= self.soft_mask_response_size <= 4095
            or type(self.su_regulation) is not bool
            or type(self.verify_softmask) is not bool
        ):
            raise ValueError(
                "Exact CUW2026 DH UDS getter identity and native catalog inputs required"
            )


def bind_dh_getter(
    selection: CalibrationSelection,
    context: SelectionContext,
    identity: NativeModuleIdentity,
    *,
    module_version: str | None = None,
) -> DHGetterContext:
    """Bind native DLL/address selectors and timeout from selected parameter tables."""
    if not isinstance(selection, CalibrationSelection) or not isinstance(
        context, SelectionContext
    ):
        raise TypeError("Actual native parameter selection and context required")
    if not isinstance(identity, NativeModuleIdentity):
        raise TypeError("Exact native module identity required")
    dispatch = selection.dispatch(
        "get_cid",
        context,
        {identity.module_name: identity.callable_exports},
        module_versions=None
        if module_version is None
        else {identity.module_name: module_version},
    )
    if dispatch["module"] != identity.module_name:
        raise ValueError(
            "Selected DH getter does not match its inspected native module"
        )
    classic = identity.module_name == "TCUWCanDHSoftwareIDGetter.dll"
    verify_text = selection.value("FlagToVerifySoftMaskIDProcess") if classic else ""
    if verify_text not in ("", "0", "1"):
        raise ValueError("Native Boolean soft-mask verification parameter required")
    su_text = selection.value("FlagToSURegulation") if classic else ""
    if su_text not in ("", "0", "1"):
        raise ValueError("Native Boolean SU regulation parameter required")
    timeout_text = selection.value("ReceiveTimeoutBeforeGetCID")
    if timeout_text and (
        not timeout_text.isascii()
        or not timeout_text.isdecimal()
        or len(timeout_text) > 10
    ):
        raise ValueError("Native unsigned getter timeout text required")
    mask_pid_text = selection.value("PIDForReadSoftMaskID") or "A7"
    if len(mask_pid_text) != 2 or any(
        char not in "0123456789abcdefABCDEF" for char in mask_pid_text
    ):
        raise ValueError("Native one-byte soft-mask PID hex text required")
    mask_size_text = selection.value("SoftMaskIDRespDataSize") or (
        "0" if classic or "Writable" in identity.module_name else "10"
    )
    if (
        not mask_size_text.isascii()
        or not mask_size_text.isdecimal()
        or len(mask_size_text) > 10
    ):
        raise ValueError("Native unsigned soft-mask response size text required")
    addresses = tuple(
        Address(
            bytes.fromhex(row["request_hex"]),
            bytes.fromhex(row["response_hex"]),
            row["extended"],
        )
        for row in dispatch["addresses"]
    )
    if identity.module_name == "TCUWP5CanDHVehicleInfoCIDGetter.dll":
        # Native constants at RVAs3118/311c/3120, not catalog/operator geometry.
        addresses = (Address(b"\x07\xdf", b"\x07\xe8"),)
    return DHGetterContext(
        identity,
        addresses,
        int(timeout_text) if timeout_text else 0,
        tuple((row["source"], row["sha256"]) for row in dispatch["sources"]),
        selection.value("ComplementCID").encode("latin1")
        if identity.module_name
        in (
            "TCUWCanDHSoftMaskIDGetter.dll",
            "TCUWCanDHSoftwareIDAndSoftMaskIDGetter.dll",
            "TCUWCanDHSoftwareIDGetter.dll",
            "TCUWCanDHWritableCIDGetter.dll",
            "TCUWCanDHWritableSoftMaskIDAndCIDGetter.dll",
        )
        else b"",
        int(mask_pid_text, 16),
        int(mask_size_text),
        su_text == "1",
        verify_text == "1",
    )


def get_dh_cids(context: DHGetterContext, runtime: NativeRuntime2026) -> dict:
    """2026 DH native getter lifecycle over actual catalog-bound addresses."""
    host_cleanup_errors: list[BaseException] = []
    if not isinstance(context, DHGetterContext) or not isinstance(
        runtime, NativeRuntime2026
    ):
        raise TypeError("Bound native DH UDS getter context and runtime required")
    # Revalidate frozen snapshots before any host side effect.
    context.__post_init__()
    if context.verify_softmask or "Writable" in context.identity.module_name:
        raise ValueError("Stateful DH getter requires engine-owned state binding")
    if context.identity.module_name == "TCUWCanDHSoftwareIDGetter.dll":
        return _get_normal_dh_cids(context, runtime)
    result = {
        "family": context.identity.family,
        "state": "reading",
        "physical_status": "PHYSICAL_UNCONFIRMED",
        "programming_completed": False,
        "native_return": False,
        "identifiers": [],
        "cleanup_errors": [],
    }
    diag = CanDiag2026(runtime)
    try:
        runtime.call("set_timeout", milliseconds=context.receive_timeout_ms)
        for address in context.addresses:
            connected = False
            identifier = None
            try:
                runtime.call_owned("connect", "disconnect", protocol=6)
                connected = True
                request = b"\0\0" + address.request
                response = b"\0\0" + address.response
                filter_request = (
                    b"\0\0\x07\xe0"
                    if context.identity.module_name
                    == "TCUWP5CanDHVehicleInfoCIDGetter.dll"
                    else request
                )
                identifier = diag.start_filter(filter_request, response)
                if context.identity.module_name == "TCUWCanDHUDSSoftwareIDGetter.dll":
                    reply = diag.call(
                        request,
                        response,
                        b"\x22\xf1\x81",
                        b"\x62\xf1\x81",
                        minimum=4,
                        error_code=3,
                        pending_limit=99,
                        busy_limit=255,
                        send_tester_present=False,
                    )
                    try:
                        values = decode_dhuds_software_ids(reply)
                    except ValueError as exc:
                        raise CommonResponseError(3, reply) from exc
                elif (
                    context.identity.module_name
                    == "TCUWP5CanDHVehicleInfoCIDGetter.dll"
                ):
                    reply = diag.call(
                        request,
                        response,
                        b"\x09\x04",
                        b"\x49\x04",
                        minimum=3,
                        error_code=3,
                        phase5=True,
                        pending_limit=0xB4,
                        busy_limit=0x159A,
                        send_tester_present=True,
                    )
                    try:
                        values = decode_p5_vehicle_info_cids(reply)
                    except ValueError as exc:
                        raise CommonResponseError(3, reply) from exc
                elif (
                    context.identity.module_name
                    == "TCUWCanDHSoftwareIDAndSoftMaskIDGetter.dll"
                ):
                    software = diag.call(
                        request,
                        response,
                        b"\x1a\x81",
                        b"\x5a",
                        minimum=6,
                        error_code=3,
                        pending_limit=99,
                        busy_limit=255,
                        send_tester_present=False,
                    )
                    mask = diag.call(
                        request,
                        response,
                        bytes((0x21, context.soft_mask_pid)),
                        bytes((0x61, context.soft_mask_pid)),
                        minimum=max(10, context.soft_mask_response_size),
                        error_code=0x2E,
                        pending_limit=99,
                        busy_limit=255,
                        send_tester_present=False,
                    )
                    value = (
                        context.complement.split(b"\0", 1)[0]
                        + software[1:6].split(b"\0", 1)[0]
                        + mask[2:10].split(b"\0", 1)[0]
                    )
                    if not value:
                        raise CommonResponseError(3)
                    values = (value,)
                else:
                    values_list = []
                    for selector in (1, 2):
                        reply = diag.call(
                            request,
                            response,
                            bytes((0x1A, 0x88, selector)),
                            bytes((0x5A, 0x88, selector)),
                            minimum=7,
                            error_code=0x2E,
                            pending_limit=99,
                            busy_limit=255,
                            send_tester_present=False,
                        )
                        value = (
                            context.complement.split(b"\0", 1)[0]
                            + reply[3:7].split(b"\0", 1)[0]
                        )
                        if not value:
                            raise CommonResponseError(3)
                        values_list.append(value)
                    values = tuple(values_list)
                runtime.check()
                result["identifiers"].extend(
                    {
                        "identifier": value,
                        "request_id": address.request,
                        "response_id": address.response,
                    }
                    for value in values
                )
            finally:
                for operation, values in (
                    ("stop_filter", {"identifier": identifier})
                    if identifier is not None
                    else ("", {}),
                    ("disconnect", {}) if connected else ("", {}),
                ):
                    if operation:
                        try:
                            runtime.release(operation, **values)
                        except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - preserve native failure and attempt every release
                            host_cleanup_errors.append(exc)
                            result["cleanup_errors"].append(type(exc).__name__)
                _raise_host_cleanup(host_cleanup_errors)
        result["native_return"] = True if not result["cleanup_errors"] else None
        result["state"] = "read_completed" if not result["cleanup_errors"] else "failed"
    except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - preserve native failure and attempt every release
        _raise_if_host_fault(exc)
        result["state"] = (
            "cancelled"
            if isinstance(exc, (InterruptedError, KeyboardInterrupt))
            else "failed"
        )
        if isinstance(exc, (InterruptedError, KeyboardInterrupt)):
            result["native_return"] = None
        result["error"] = type(exc).__name__
        result.update(_record_dh_error(None, exc, None))
    _raise_host_cleanup(host_cleanup_errors)
    return result


def _get_normal_dh_cids(context: DHGetterContext, runtime: NativeRuntime2026) -> dict:
    """SoftwareIDGetter RVA12b0/1820: one connection, per-address filters."""
    host_cleanup_errors: list[BaseException] = []
    result = {
        "family": context.identity.family,
        "state": "reading",
        "physical_status": "PHYSICAL_UNCONFIRMED",
        "programming_completed": False,
        "native_return": False,
        "identifiers": [],
        "cleanup_errors": [],
    }
    diag = CanDiag2026(runtime)
    connected = False
    try:
        runtime.call_owned("connect", "disconnect", protocol=6)
        connected = True
        runtime.call("set_timeout", milliseconds=context.receive_timeout_ms)
        for address in context.addresses:
            request, response = b"\0\0" + address.request, b"\0\0" + address.response
            identifier = diag.start_filter(request, response)
            try:

                def exchange(ecu, payload, request=request, response=response):
                    return diag.call(
                        request,
                        response,
                        payload,
                        b"\x5a"
                        if payload == b"\x1a\x81"
                        else b"\x5a\x88" + payload[2:3],
                        minimum=1 if payload == b"\x1a\x81" else 3,
                        error_code=3,
                        pending_limit=99,
                        busy_limit=255,
                        send_tester_present=False,
                    )

                channel = NativeProgrammingChannel(exchange, "DH")
                if context.su_regulation:
                    _, values = get_software_info(channel)
                else:
                    reply = channel.call(b"\x1a\x81", b"\x5a")
                    # Native checks full Data[5] for5a even with standard CAN.
                    # Preserve that offset quirk when the first CID character isZ.
                    raw = address.response[2:] + reply
                    if len(raw) < 2:
                        raise CommonResponseError(3, reply)
                    offset = 1 + int(raw[1] == 0x5A)
                    if len(raw) < offset + 5:
                        raise CommonResponseError(3, reply)
                    values = (
                        context.complement.split(b"\0", 1)[0]
                        + raw[offset : offset + 5].split(b"\0", 1)[0],
                    )
                if any(not value for value in values):
                    raise CommonResponseError(3)
                runtime.check()
                result["identifiers"].extend(
                    {
                        "identifier": value,
                        "request_id": address.request,
                        "response_id": address.response,
                    }
                    for value in values
                )
            finally:
                runtime.release("stop_filter", identifier=identifier)
        result["native_return"] = True
        result["state"] = "read_completed"
    except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - preserve operation outcome through cleanup
        _raise_if_host_fault(exc)
        result["state"] = (
            "cancelled"
            if isinstance(exc, (InterruptedError, KeyboardInterrupt))
            else "failed"
        )
        if isinstance(exc, (InterruptedError, KeyboardInterrupt)):
            result["native_return"] = None
        result["error"] = type(exc).__name__
        result.update(_record_dh_error(None, exc, None))
    finally:
        if connected:
            try:
                runtime.release("disconnect")
            except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - report failed native cleanup
                host_cleanup_errors.append(exc)
                result["cleanup_errors"].append(type(exc).__name__)
                result["native_return"] = None
                result["state"] = "failed"
        _raise_host_cleanup(host_cleanup_errors)
    _raise_host_cleanup(host_cleanup_errors)
    return result


@dataclass(frozen=True)
class DHStatefulGetterContext:
    getter: DHGetterContext
    state: DHControllerState2026
    specific_service: bool
    write_response_type: int

    def __post_init__(self):
        if (
            not isinstance(self.getter, DHGetterContext)
            or not isinstance(self.state, DHControllerState2026)
            or not self.state.progress
            or self.state.progress[0] not in (0, 100)
            or type(self.specific_service) is not bool
            or type(self.write_response_type) is not int
            or not -0x80000000 <= self.write_response_type <= 0x7FFFFFFF
            or self.getter.identity.module_name
            not in (
                "TCUWCanDHSoftwareIDGetter.dll",
                "TCUWCanDHWritableCIDGetter.dll",
                "TCUWCanDHWritableSoftMaskIDAndCIDGetter.dll",
            )
            or len(self.getter.complement) > 6
        ):
            raise ValueError("Source-bound native DH getter state required")
        self.getter.__post_init__()


def bind_stateful_dh_getter(
    selection: CalibrationSelection,
    context: SelectionContext,
    identity: NativeModuleIdentity,
    state: DHControllerState2026,
    *,
    module_version: str | None = None,
) -> DHStatefulGetterContext:
    getter = bind_dh_getter(selection, context, identity, module_version=module_version)
    service = selection.value("FlagToChangeSpecificServiceCertificationModeProcess")
    response_type = selection.value("WriteSoftwareIDRespType") or "0"
    if (
        service not in ("", "0", "1")
        or not response_type.isascii()
        or not response_type.isdecimal()
        or len(response_type) > 10
    ):
        raise ValueError(
            "Native Boolean service and integer response-type parameters required"
        )
    return DHStatefulGetterContext(getter, state, service == "1", int(response_type))


def get_stateful_dh_cids(
    context: DHStatefulGetterContext,
    runtime: NativeRuntime2026,
    *,
    gateway: "DHGateway2026 | None" = None,
) -> dict:
    """Native verification/writable paths with persistent engine-created stages."""
    host_cleanup_errors: list[BaseException] = []
    if not isinstance(context, DHStatefulGetterContext) or not isinstance(
        runtime, NativeRuntime2026
    ):
        raise TypeError("Bound DH getter and runtime required")
    context.__post_init__()
    getter, state = context.getter, context.state
    if (
        getter.identity.module_name == "TCUWCanDHSoftwareIDGetter.dll"
        and not getter.verify_softmask
    ):
        return _get_normal_dh_cids(getter, runtime)
    if context.specific_service and (
        not isinstance(gateway, DHGateway2026) or gateway.runtime is not runtime
    ):
        raise ValueError("Same-runtime native gateway client required")
    result = {
        "family": getter.identity.family,
        "state": "reading",
        "physical_status": "PHYSICAL_UNCONFIRMED",
        "programming_completed": False,
        "native_return": False,
        "identifiers": [],
        "cleanup_errors": [],
    }
    diag = CanDiag2026(runtime)
    connected, identifier = False, None
    # These native branches unconditionally copy two bytes from the first pair.
    address = getter.addresses[0]
    request, response = b"\0\0" + address.request[:2], b"\0\0" + address.response[:2]

    def exchange(ecu, payload):
        prefixes = {b"\x1a\x81": (b"\x5a", 6, 3), b"\x1a\xb0": (b"\x5a", 3, 0x2E)}
        expected, minimum, error_code = prefixes.get(payload, (b"", 2, 0x30))
        if payload.startswith(b"\x21"):
            expected, minimum, error_code = (
                b"\x61" + payload[1:2],
                max(4, getter.soft_mask_response_size),
                0x2E,
            )
        elif payload.startswith(b"\x3b"):
            expected, error_code = (
                b"\x7b" + payload[1:2],
                0x61 if payload[1] == 8 else 0x30,
            )
        elif payload.startswith(b"\xa0\x99"):
            expected = b"\xe0\x99" + (
                b"\x01" if context.write_response_type == 1 else b""
            )
            minimum = len(expected)
        return diag.call(
            request,
            response,
            payload,
            expected,
            minimum=minimum,
            error_code=error_code,
            pending_limit=99,
            busy_limit=255,
            send_tester_present=False,
        )

    channel = NativeProgrammingChannel(exchange, "DH")
    try:
        runtime.call("set_timeout", milliseconds=getter.receive_timeout_ms)
        runtime.call_owned("connect", "disconnect", protocol=6)
        connected = True
        identifier = diag.start_filter(request, response)
        if state.progress[0] == 100:
            location = native2026_location_id(state.metadata, 0)
            writable_mask = (
                getter.identity.module_name
                == "TCUWCanDHWritableSoftMaskIDAndCIDGetter.dll"
            )
            if state.getter_stage == 0:
                if writable_mask:
                    channel.call(b"\x1a\x81", b"\x5a")
                else:
                    verify_soft_mask(
                        channel,
                        location,
                        pid_for_read_soft_mask_id=getter.soft_mask_pid,
                        soft_mask_id_resp_data_size=getter.soft_mask_response_size,
                    )
                state.advance_getter_stage(0, 1)
            if writable_mask:
                for stage, operation in (
                    (1, lambda: writable_write_soft_mask(channel, location)),
                    (
                        2,
                        lambda: writable_write_software_id(
                            channel,
                            native2026_new_calibration_id(state.metadata, 0).encode(
                                "latin1"
                            ),
                        ),
                    ),
                ):
                    if state.getter_stage == stage:
                        if context.specific_service:
                            assert gateway is not None
                            gateway.start_specific_service_mode()
                        operation()
                        if context.specific_service:
                            assert gateway is not None
                            gateway.end_reprogramming_mode()
                        state.advance_getter_stage(stage, stage + 1)
                if state.getter_stage == 3:
                    writable_verify_soft_mask(channel, location)
                    state.advance_getter_stage(3, 4)
            elif (
                getter.identity.module_name == "TCUWCanDHWritableCIDGetter.dll"
                and state.getter_stage == 1
            ):
                write_software_id(
                    channel,
                    native2026_new_calibration_id(state.metadata, 0).encode("latin1"),
                    write_software_id_resp_type=context.write_response_type,
                )
                state.advance_getter_stage(1, 2)
        value = read_software_id(channel, getter.complement)
        if not value:
            raise CommonResponseError(3)
        runtime.check()
        result["identifiers"].append(
            {
                "identifier": value,
                "request_id": address.request[:2],
                "response_id": address.response[:2],
            }
        )
        result["native_return"] = True
        result["state"] = "read_completed"
    except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - native error outcome, cleanup always follows
        _raise_if_host_fault(exc)
        native_error = _record_dh_error(state, exc, None)
        if (
            getter.identity.module_name == "TCUWCanDHWritableCIDGetter.dll"
            and native_error.get("native_primary_error") == 0x30
        ):
            state.mark_writable_cid()
        result["state"] = (
            "cancelled"
            if isinstance(exc, (InterruptedError, KeyboardInterrupt))
            else "failed"
        )
        if isinstance(exc, (InterruptedError, KeyboardInterrupt)):
            result["native_return"] = None
        result["error"] = type(exc).__name__
        result.update(native_error)
    finally:
        for operation, values in (
            ("stop_filter", {"identifier": identifier})
            if identifier is not None
            else ("", {}),
            ("disconnect", {}) if connected else ("", {}),
        ):
            if operation:
                try:
                    runtime.release(operation, **values)
                except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - attempt every release
                    host_cleanup_errors.append(exc)
                    result["cleanup_errors"].append(type(exc).__name__)
                    result["native_return"] = None
                    result["state"] = "failed"
        _raise_host_cleanup(host_cleanup_errors)
    _raise_host_cleanup(host_cleanup_errors)
    return result


# Preserve the first consumer contract while the remaining DH getters are added.
DHUDSGetterContext = DHGetterContext


def bind_dhuds_getter(
    selection: CalibrationSelection,
    context: SelectionContext,
    identity: NativeModuleIdentity,
    *,
    module_version: str | None = None,
) -> DHGetterContext:
    result = bind_dh_getter(selection, context, identity, module_version=module_version)
    if result.identity.module_name != "TCUWCanDHUDSSoftwareIDGetter.dll":
        raise ValueError("Exact DH UDS software getter required")
    return result


def get_dhuds_cids(context: DHGetterContext, runtime: NativeRuntime2026) -> dict:
    if (
        not isinstance(context, DHGetterContext)
        or context.identity.module_name != "TCUWCanDHUDSSoftwareIDGetter.dll"
    ):
        raise ValueError("Exact DH UDS software getter context required")
    return get_dh_cids(context, runtime)


def decode_p5_vehicle_info_cids(response: bytes) -> tuple[bytes, ...]:
    """P5 DH getter1560: count plus16-byte records; any empty record is an error."""
    if (
        not isinstance(response, bytes)
        or not 3 <= len(response) <= 4116
        or not response.startswith(b"\x49\x04")
        or len(response) < 3 + response[2] * 16
    ):
        raise ValueError("Malformed Phase5 DH vehicle-info CID array")
    values = tuple(
        response[3 + index * 16 : 19 + index * 16].split(b"\0", 1)[0]
        for index in range(response[2])
    )
    if any(not value for value in values):
        raise ValueError("Native Phase5 DH vehicle-info CID is empty")
    return values


def gateway_secret_info_identifier(table_kind: int, option: int) -> int:
    """DHUtils RVA2f20 selects a private record; no secret material is embedded."""
    if type(table_kind) is not int or type(option) is not int or not 0 <= option <= 255:
        raise ValueError("Native DH security table kind and byte option required")
    if table_kind == 0:
        return 1
    if table_kind == 1 and option in (2, 3):
        return 0x15 if option == 2 else 0x14
    raise ValueError("Unsupported native DH gateway security table/option pair")


def collate_gateway_seed_key(
    channel: NativeProgrammingChannel,
    runtime: NativeRuntime2026,
    secret_info: SecretInfoClient,
    *,
    table_kind: int = 0,
    option: int = 0,
    specific_service: bool = False,
    flag_to_non_seed_16_byte_resp_status: bool = False,
    flag_to_non_send_key_resp_status: bool = False,
) -> None:
    """DHUtils RVA2f20/3090 client flow; only raw key computation is a primitive."""
    if (
        not isinstance(secret_info, SecretInfoClient)
        or type(specific_service) is not bool
    ):
        raise TypeError(
            "Private native SecretInfo binding and Boolean service mode required"
        )
    if specific_service:
        identifier, option = 3, 4
    else:
        identifier = gateway_secret_info_identifier(table_kind, option)
    seed = request_seed_specified_bytes(
        channel,
        16,
        option=option,
        flag_to_non_seed_16_byte_resp_status=flag_to_non_seed_16_byte_resp_status,
    )
    key = NativeSecurityComposer2026.calculate_security_key(
        secret_info.get(identifier), seed
    )
    if not isinstance(key, bytes) or len(key) != 16:
        raise CommonResponseError(0x11)
    send_key(
        channel, key, flag_to_non_send_key_resp_status=flag_to_non_send_key_resp_status
    )


def collate_gateway_online_seed_key(
    channel: NativeProgrammingChannel,
    runtime: NativeRuntime2026,
    *,
    option: int = 0,
    flag_to_non_seed_16_byte_resp_status: bool = False,
    flag_to_non_send_key_resp_status: bool = False,
) -> None:
    """DHUtils RVA2fe0 obtains8seed bytes, validates64raw key bytes, sends2702."""
    seed = request_seed_specified_bytes(
        channel,
        8,
        option=option,
        flag_to_non_seed_16_byte_resp_status=flag_to_non_seed_16_byte_resp_status,
    )
    key = runtime.call("calculate_dh_gateway_online_key", seed=seed)
    if not isinstance(key, bytes) or len(key) != 64:
        raise CommonResponseError(0x11)
    send_key(
        channel, key, flag_to_non_send_key_resp_status=flag_to_non_send_key_resp_status
    )


def central_gateway_can_ids(*, online: bool = False) -> tuple[bytes, bytes]:
    """DHUtils RVA3e70/3f30 use separate authentication CPU pairs."""
    if type(online) is not bool:
        raise ValueError("Boolean native authentication CPU selector required")
    return (
        (b"\0\0\x07\x86", b"\0\0\x07\x8e")
        if not online
        else (b"\0\0\x07\xa4", b"\0\0\x07\xac")
    )


def central_gateway_request_can_id() -> bytes:
    """DHUtils RVA3ff0 returns the two-byte0786 request identifier."""
    return b"\x07\x86"


def start_sync_periodic(
    runtime: NativeRuntime2026, request_address: bytes, *, su_regulation: bool = False
) -> None:
    """DHUtils RVA77d0/7870 send3e80 every2000ms or3e01 every3000ms."""
    if (
        not isinstance(request_address, bytes)
        or len(request_address) != 4
        or type(su_regulation) is not bool
    ):
        raise ValueError(
            "Four-byte native periodic CAN address and Boolean SU mode required"
        )
    runtime.call_owned(
        "start_sync_periodic",
        "stop_sync_periodic",
        frames=(
            (request_address + (b"\x3e\x01" if su_regulation else b"\x3e\x80"), 0),
        ),
        interval_ms=3000 if su_regulation else 2000,
        retry_ms=100,
        count=1,
        delay_ms=100,
    )


def stop_communication_phase5(runtime: NativeRuntime2026) -> None:
    """DHUtils RVA7a20 broadcasts288101 three times per functional address."""
    for address, extension, flags in (
        (b"\0\0\x07\x51", b"", 0),
        (b"\0\0\x07\x77", b"", 0),
        (b"\0\0\x07\x7f", b"\xfe", 0x80),
    ):
        for _ in range(3):
            _write_raw(runtime, address + extension + b"\x28\x81\x01", flags)
            runtime.call("wait", milliseconds=100)


def resume_communication(runtime: NativeRuntime2026) -> None:
    """DHUtils RVA61a0 broadcasts288001 once per functional address, no wait."""
    for address, extension, flags in (
        (b"\0\0\x07\x51", b"", 0),
        (b"\0\0\x07\x77", b"", 0),
        (b"\0\0\x07\x7f", b"\xfe", 0x80),
    ):
        _write_raw(runtime, address + extension + b"\x28\x80\x01", flags)


def start_sync_periodic_phase5(
    runtime: NativeRuntime2026, central_gateway_type: int
) -> None:
    """DHUtils RVA7910 replaces prior sync frames; type2 adds0786/3e01."""
    if (
        type(central_gateway_type) is not int
        or not -0x80000000 <= central_gateway_type <= 0x7FFFFFFF
    ):
        raise ValueError("Native signed central-gateway type required")
    if runtime.owns_resource("stop_sync_periodic"):
        runtime.release("stop_sync_periodic")
    else:
        runtime.call("stop_sync_periodic")
    frames = (
        (b"\0\0\x07\x51\x3e\x80", 0),
        (b"\0\0\x07\x77\x3e\x80", 0),
        (b"\0\0\x07\x7f\xfe\x3e\x80", 0x80),
    )
    if central_gateway_type == 2:
        frames += ((b"\0\0\x07\x86\x3e\x01", 0),)
    runtime.call_owned(
        "start_sync_periodic",
        "stop_sync_periodic",
        frames=frames,
        interval_ms=2000,
        retry_ms=100,
        count=len(frames),
        delay_ms=100,
    )


def change_specific_service_session(channel: NativeProgrammingChannel) -> None:
    """DHUtils RVA23a0 uses1088/5088 before service-certificate authentication."""
    channel.call(b"\x10\x88", b"\x50\x88")


def change_reprog_gateway_session(
    channel: NativeProgrammingChannel, *, allow_unavailable: bool = False
) -> bool:
    """DHUtils RVA1ff0 returns an unavailable flag only for native accepted errors."""
    if type(allow_unavailable) is not bool:
        raise ValueError("Boolean native gateway fallback flag required")
    try:
        channel.call(b"\x10\x87", b"\x50\x87")
    except NativeTransportError as exc:
        if allow_unavailable and _dh_driver_status(exc) in (9, 16):
            return True
        raise
    except (NativeNegativeResponse, CommonResponseError) as exc:
        if allow_unavailable and exc.response.startswith(b"\x7f\x10"):
            return True
        raise
    return False


def check_gateway_connection(channel: NativeProgrammingChannel) -> bool:
    """DHUtils RVA2470 accepts7e replies of exactly one or two payload bytes."""
    try:
        response = channel.call(b"\x3e\x00", b"\x7e")
    except NativeTransportError as exc:
        if _dh_driver_status(exc) is None or _dh_driver_status(exc) in (9, 16):
            return False
        raise
    except (NativeNegativeResponse, CommonResponseError):
        return False
    return len(response) in (1, 2)


def replace_can_ids(
    request: bytes, response: bytes, target_comm_parameter: str
) -> tuple[bytes, bytes]:
    """DHUtils RVA53d0 replaces only a nine-character four-hex/four-hex pair."""
    if (
        any(
            not isinstance(value, bytes) or not 0 < len(value) <= 512
            for value in (request, response)
        )
        or not isinstance(target_comm_parameter, str)
        or len(target_comm_parameter) > 259
    ):
        raise ValueError(
            "Native CAN bytes and bounded target communication parameter required"
        )
    text = target_comm_parameter.split("\0", 1)[0]
    if len(text) != 9:
        return request, response
    parts = text.split("/")
    if len(parts) != 2 or any(len(part) != 4 for part in parts):
        return request, response
    if any(char not in "0123456789abcdefABCDEF" for part in parts for char in part):
        raise ValueError("Native replacement CAN identifier is not hexadecimal")
    return bytes.fromhex(parts[0]), bytes.fromhex(parts[1])


def request_download_phase5(
    channel: NativeProgrammingChannel, address: bytes, size: int
) -> int:
    """DHUtils RVA5920 shares340144 wire format and always subtracts one."""
    return request_download(
        channel, address, size, value_subtracted_from_max_number_block_length=1
    )


def secret_info_type(first: str, second: str) -> int:
    """DHUtils RVA4010: exact type IDs; this mapping contains no key material."""
    if any(not isinstance(value, str) or len(value) > 259 for value in (first, second)):
        raise ValueError("Bounded native security type strings required")
    first, second = first.split("\0", 1)[0], second.split("\0", 1)[0]
    combined = {"108 383": 0x2E, "141 395": 0x38, "141 396": 0x39, "202 401": 0x3D}
    key = first + " " + second
    if key in combined:
        return combined[key]
    fallback = {
        "124": 0x2C,
        "108": 0x2D,
        "165": 0x2F,
        "166": 0x30,
        "205": 0x31,
        "155": 0x32,
        "36": 0x33,
        "202": 0x34,
        "168": 0x35,
        "169": 0x36,
        "152": 0x37,
        "163": 0x3A,
        "17": 0x3E,
        "208": 0x3C,
    }
    if first not in fallback:
        raise CommonResponseError(0x11)
    return fallback[first]


def dh_sync_exchange(
    runtime: NativeRuntime2026,
    request_address: bytes,
    response_address: bytes,
    payload: bytes,
    expected: bytes | None,
    *,
    minimum: int = 0,
    error_code: int = 9999,
    delay_ms: int = 0,
    pending_limit: int = 99,
    busy_limit: int = 255,
) -> bytes:
    """DHUtils RVA6580: locked sync traffic, count-bounded pending and busy retry.

    Pending is receive-only. This differs from the Phase5 elapsed-time loop.
    """
    if (
        any(
            not isinstance(value, bytes) or len(value) != 4
            for value in (request_address, response_address)
        )
        or not isinstance(payload, bytes)
        or not 0 < len(payload) <= 4116
        or expected is not None
        and (not isinstance(expected, bytes) or not 0 < len(expected) <= 4116)
        or any(
            type(value) is not int or not 0 <= value <= 0xFFFFFFFF
            for value in (minimum, error_code, delay_ms, pending_limit, busy_limit)
        )
        or minimum > 4116
    ):
        raise ValueError("Bounded native DH sync CAN exchange inputs required")
    previous = runtime.call("get_timeout")
    if type(previous) is not int or not 0 <= previous <= 0xFFFFFFFF:
        raise ValueError("Native unsigned prior timeout required")
    diag = CanDiag2026(runtime)
    locked = False

    def lock():
        nonlocal locked
        runtime.call_owned("lock", "unlock")
        locked = True

    def unlock():
        nonlocal locked
        if locked:
            runtime.release("unlock")
            locked = False

    try:
        busy = 0
        while True:
            lock()
            diag.write(request_address + payload)
            runtime.call("wait", milliseconds=delay_ms)
            pending = 0
            pending_mode = False
            while True:
                if pending_mode:
                    lock()
                try:
                    response = runtime.call(
                        "read_specified_can_message",
                        address=response_address,
                        count=1,
                        frame=2,
                    )
                finally:
                    if pending_mode:
                        unlock()
                if (
                    not isinstance(response, bytes)
                    or not 4 <= len(response) <= 4128
                    or not response.startswith(response_address)
                ):
                    raise ValueError("Malformed native DH sync CAN response")
                data = response[4:]
                if not data.startswith(bytes((0x7F, payload[0], 0x78))):
                    break
                if not pending_mode:
                    pending_mode = True
                    unlock()
                busy = 0
                pending += 1
                if pending > pending_limit:
                    raise CommonResponseError(error_code, data)
                runtime.call("set_timeout", milliseconds=1000)
            unlock()
            runtime.call("set_timeout", milliseconds=previous)
            if data.startswith(bytes((0x7F, payload[0], 0x21))):
                busy += 1
                if busy > busy_limit:
                    raise CommonResponseError(error_code, data)
                continue
            if (
                len(data) < minimum
                or expected is not None
                and not data.startswith(expected)
            ):
                raise CommonResponseError(error_code, data)
            return data
    finally:
        try:
            unlock()
        finally:
            runtime.call("set_timeout", cleanup=True, milliseconds=previous)


def check_gateway_security_table_kind(runtime: NativeRuntime2026) -> int:
    """DHUtils RVA2620:06f1/06fe probe; transport9/16 selects table kind1."""
    diag = CanDiag2026(runtime)
    request, response = b"\0\0\x06\xf1", b"\0\0\x06\xfe"
    identifier = diag.start_filter(request, response)
    try:
        try:
            diag.call(
                request,
                response,
                b"\x3e\x00",
                b"\x7e\x00",
                minimum=2,
                error_code=0x3F1,
                pending_limit=99,
                busy_limit=255,
                send_tester_present=False,
            )
        except NativeTransportError as exc:
            if _dh_driver_status(exc) in (9, 16):
                return 1
            raise
        except CommonResponseError as exc:
            if not (
                len(exc.response) >= 3
                and exc.response[:2] == b"\x7f\x3e"
                and exc.response[2] not in (0x21, 0x78)
            ):
                raise
        return 0
    finally:
        runtime.release("stop_filter", identifier=identifier)


def check_gateway_specification(
    runtime: NativeRuntime2026, *, allow_unavailable: bool = False
) -> tuple[int, bool]:
    """DHUtils RVA2960: successful2105 probe=>1; timeout9/16=>0."""
    if type(allow_unavailable) is not bool:
        raise ValueError("Boolean native gateway specification fallback flag required")
    diag = CanDiag2026(runtime)
    request, response = central_gateway_can_ids(online=True)
    identifier = diag.start_filter(request, response)
    try:
        try:
            diag.call(
                request,
                response,
                b"\x21\x05",
                b"\x61\x05",
                minimum=6,
                error_code=0x3FE,
                pending_limit=99,
                busy_limit=255,
                send_tester_present=False,
            )
        except NativeTransportError as exc:
            if _dh_driver_status(exc) in (9, 16):
                return 0, False
            raise
        except CommonResponseError as exc:
            if allow_unavailable and exc.response.startswith(b"\x7f\x21"):
                return 1, True
            raise
        return 1, False
    finally:
        runtime.release("stop_filter", identifier=identifier)


def check_need_repro_center_authentication(runtime: NativeRuntime2026) -> None:
    """DHUtils RVA2cc0 requires literal62011e01 on the online-authentication CPU."""
    diag = CanDiag2026(runtime)
    request, response = central_gateway_can_ids(online=True)
    identifier = diag.start_filter(request, response)
    try:
        diag.call(
            request,
            response,
            b"\x22\x01\x1e",
            b"\x62\x01\x1e\x01",
            minimum=4,
            error_code=0x40D,
            pending_limit=99,
            busy_limit=255,
            send_tester_present=False,
        )
    finally:
        runtime.release("stop_filter", identifier=identifier)


@dataclass(eq=False)
class DHGateway2026:
    """Native CDHUtils gateway state; host providers expose only J2534/crypto primitives."""

    runtime: NativeRuntime2026
    selection: (
        CalibrationSelection
        | NativeParameterBinding2026
        | NativeControlParameterBase2026
    )
    identity: NativeModuleIdentity
    secret_info: SecretInfoClient = field(repr=False)
    engine_state: DHControllerState2026 | None = field(default=None, repr=False)
    mode_could_be_changed: bool = field(default=False, init=False)
    security_table_kind: int = field(default=0, init=False)

    def __post_init__(self):
        if (
            not isinstance(self.runtime, NativeRuntime2026)
            or not isinstance(
                self.selection,
                (
                    CalibrationSelection,
                    NativeParameterBinding2026,
                    NativeControlParameterBase2026,
                ),
            )
            or not isinstance(self.secret_info, SecretInfoClient)
            or not isinstance(self.identity, NativeModuleIdentity)
            or self.identity
            != identify_native_module(self.identity.sha256, self.identity.module_name)
            or self.identity.cuw_build != "2026"
            or self.identity.module_name != "TCUWDHUtils.dll"
        ):
            raise TypeError(
                "Actual native parameter selection, private secret binding and exact DHUtils identity required"
            )
        self._validate_selection()
        if self.engine_state is not None:
            if not isinstance(
                self.engine_state, DHControllerState2026
            ) or not isinstance(
                self.selection,
                (NativeParameterBinding2026, NativeControlParameterBase2026),
            ):
                raise ValueError("Actual engine DH gateway state required")
            if isinstance(self.selection, NativeControlParameterBase2026):
                engine = self.selection.engine
                if self.selection._pool is not None:
                    if self.engine_state is not engine.dh_state:
                        raise ValueError(
                            "Pool BASE gateway must use its exact engine DH state"
                        )
                elif self.engine_state.metadata != self.selection.metadata:
                    raise ValueError(
                        "Constructor-empty gateway metadata differs from engine state"
                    )
            else:
                _dh_file_view(self.selection, self.engine_state)
        self.diag = CanDiag2026(self.runtime)

    def _validate_selection(self) -> None:
        if (
            isinstance(self.selection, NativeParameterBinding2026)
            and self.selection._pool_issued
            and self.selection.module_name
            in ("TCUWCanDHPrepareWriter.dll", "TCUWCanDHFlashWriter.dll")
            and not isinstance(self.engine_state, DHControllerState2026)
        ):
            raise ValueError(
                "Pooled classic DH gateway requires its actual engine state"
            )
        if (
            isinstance(self.selection, NativeParameterBinding2026)
            and self.engine_state is not None
        ):
            _dh_file_view(self.selection, self.engine_state)
            if (
                self.selection._pool_issued
                and self.engine_state.engine.worker.runtime is not self.runtime
            ):
                raise ValueError("DH gateway runtime differs from its CONTROL owner")
        if isinstance(self.selection, NativeControlParameterBase2026):
            if not isinstance(self.engine_state, DHControllerState2026):
                raise TypeError("Source-issued CONTROL BASE requires its engine state")
            engine = self.engine_state.engine
            self.selection.validate(engine)
            if (
                self.selection._pool is not None
                and self.engine_state is not engine.dh_state
            ):
                raise ValueError("Pool BASE gateway state differs from its engine")
            if engine.worker.runtime is not self.runtime:
                raise ValueError("CONTROL BASE runtime differs from its worker")

    def assign(self, other: "DHGateway2026") -> "DHGateway2026":
        """Native RVA15c0 assignment copies dependencies and state without I/O."""
        if not isinstance(other, DHGateway2026):
            raise TypeError("Native DHUtils object required")
        other._validate_selection()
        (
            self.runtime,
            self.selection,
            self.identity,
            self.secret_info,
            self.diag,
            self.engine_state,
        ) = (
            other.runtime,
            other.selection,
            other.identity,
            other.secret_info,
            other.diag,
            other.engine_state,
        )
        self.mode_could_be_changed, self.security_table_kind = (
            other.mode_could_be_changed,
            other.security_table_kind,
        )
        return self

    def set_security_table_kind(self, value: int) -> None:
        self._validate_selection()
        if type(value) is not int or not -0x80000000 <= value <= 0x7FFFFFFF:
            raise ValueError("Native signed security table enum required")
        self.security_table_kind = value

    def _flag(self, name: str) -> bool:
        self._validate_selection()
        if isinstance(
            self.selection,
            (NativeParameterBinding2026, NativeControlParameterBase2026),
        ):
            return self.selection.parameter.boolean(name) or False
        text = self.selection.value(name)
        if text not in ("", "0", "1"):
            raise ValueError("Native Boolean parameter text required")
        return text == "1"

    def _call(
        self,
        request: bytes,
        response: bytes,
        payload: bytes,
        expected: bytes,
        minimum: int,
        error_code: int,
        *,
        sync: bool = True,
    ) -> bytes:
        self._validate_selection()
        if sync:
            sending = self.runtime.call("is_sending_sync_periodic")
            if type(sending) is not bool:
                raise ValueError("Native synchronous periodic state must be Boolean")
            if sending:
                return dh_sync_exchange(
                    self.runtime,
                    request,
                    response,
                    payload,
                    expected,
                    minimum=minimum,
                    error_code=error_code,
                    pending_limit=99,
                    busy_limit=255,
                )
        return self.diag.call(
            request,
            response,
            payload,
            expected,
            minimum=minimum,
            error_code=error_code,
            pending_limit=99,
            busy_limit=255,
            send_tester_present=False,
        )

    def _default(self, request: bytes, response: bytes) -> None:
        self._call(request, response, b"\x10\x89", b"\x50\x89", 2, 0x29)

    def _connected(self, request: bytes, response: bytes) -> bool:
        try:
            reply = self._call(request, response, b"\x3e\x00", b"\x7e", 1, 0x50)
        except NativeTransportError as exc:
            if _dh_driver_status(exc) is None or _dh_driver_status(exc) in (9, 16):
                return False
            raise
        except CommonResponseError:
            return False
        return len(reply) in (1, 2)

    def _reprog_session(
        self, request: bytes, response: bytes, *, allow_unavailable: bool = False
    ) -> bool:
        try:
            self._call(request, response, b"\x10\x87", b"\x50\x87", 2, 0x32)
        except NativeTransportError as exc:
            if allow_unavailable and _dh_driver_status(exc) in (9, 16):
                return True
            raise
        except CommonResponseError as exc:
            if allow_unavailable and exc.response.startswith(b"\x7f\x10"):
                return True
            raise
        return False

    def _seed(self, request: bytes, response: bytes, count: int, option: int) -> bytes:
        payload = b"\x27\x01" + (bytes((option,)) if option else b"")
        status = not self._flag("FlagToNonSeed16ByteRespStatus")
        return self._call(
            request, response, payload, b"\x67\x01", 2 + count + status, 0x10
        )[2 : 2 + count]

    def _send_key(self, request: bytes, response: bytes, key: bytes) -> None:
        expected = b"\x67\x02" + (
            b"" if self._flag("FlagToNonSendKeyRespStatus") else b"\x34"
        )
        self._call(request, response, b"\x27\x02" + key, expected, len(expected), 0x11)

    def _collate(
        self, request: bytes, response: bytes, option: int, *, service: bool = False
    ) -> None:
        identifier = (
            3
            if service
            else gateway_secret_info_identifier(self.security_table_kind, option)
        )
        seed = self._seed(request, response, 16, option)
        key = NativeSecurityComposer2026.calculate_security_key(
            self.secret_info.get(identifier), seed
        )
        if not isinstance(key, bytes) or len(key) != 16:
            raise CommonResponseError(0x11)
        self._send_key(request, response, key)

    def start_reprogramming_mode(self, timeout_ms: int = 0x3FC) -> None:
        """Native RVA6af0 probes the single CPU, authenticates, then marks state."""
        self._validate_selection()
        if type(timeout_ms) is not int or not 0 <= timeout_ms <= 0xFFFFFFFF:
            raise ValueError("Native unsigned timeout required")
        previous = self.runtime.call("get_timeout")
        if type(previous) is not int or not 0 <= previous <= 0xFFFFFFFF:
            raise ValueError("Native unsigned prior timeout required")
        identifier = None
        request, response = central_gateway_can_ids()
        try:
            self.runtime.call("set_timeout", milliseconds=timeout_ms)
            self.mode_could_be_changed = False
            identifier = self.diag.start_filter(request, response)
            if self._connected(request, response):
                self.security_table_kind = check_gateway_security_table_kind(
                    self.runtime
                )
                session = self._call(request, response, b"\x10\x5f", b"\x50", 2, 0x62)[
                    1
                ]
                if session != 1:
                    self._default(request, response)
                self._reprog_session(request, response)
                self._collate(request, response, 3)
                self.mode_could_be_changed = True
        finally:
            try:
                if identifier is not None:
                    self.runtime.release("stop_filter", identifier=identifier)
            finally:
                self.runtime.call("set_timeout", cleanup=True, milliseconds=previous)

    def end_reprogramming_mode(self, timeout_ms: int = 0x3FC) -> None:
        """Native RVA3aa0 probes0786 and restores its default session and timeout."""
        self._validate_selection()
        if type(timeout_ms) is not int or not 0 <= timeout_ms <= 0xFFFFFFFF:
            raise ValueError("Native unsigned timeout required")
        previous = self.runtime.call("get_timeout")
        if type(previous) is not int or not 0 <= previous <= 0xFFFFFFFF:
            raise ValueError("Native unsigned prior timeout required")
        identifier = None
        request, response = central_gateway_can_ids()
        try:
            self.runtime.call("set_timeout", milliseconds=timeout_ms)
            identifier = self.diag.start_filter(request, response)
            if self._connected(request, response):
                self._default(request, response)
        finally:
            try:
                if identifier is not None:
                    self.runtime.release("stop_filter", identifier=identifier)
            finally:
                self.runtime.call("set_timeout", cleanup=True, milliseconds=previous)

    def start_online_reprogramming_mode(self, cpu_type: int) -> None:
        """Native RVA6e50 authenticates each CPU and keeps owned periodic traffic."""
        self._validate_selection()
        if type(cpu_type) is not int or not -0x80000000 <= cpu_type <= 0x7FFFFFFF:
            raise ValueError("Native CPU type required")
        request, response = central_gateway_can_ids(online=cpu_type == 0)
        identifier = self.diag.start_filter(request, response)
        try:
            self._reprog_session(request, response)
            if cpu_type == 0:
                start_sync_periodic(
                    self.runtime, central_gateway_can_ids()[0], su_regulation=True
                )
                seed = self._seed(request, response, 8, 7)
                key = self.runtime.call("calculate_dh_gateway_online_key", seed=seed)
                if not isinstance(key, bytes) or len(key) != 64:
                    raise CommonResponseError(0x11)
                self._send_key(request, response, key)
            self.security_table_kind = 1
            self._collate(request, response, 3)
        finally:
            self.runtime.release("stop_filter", identifier=identifier)

    def start_reprogramming_mode_for_multi_types(self) -> int:
        """Native RVA6e00 chooses one or two CPUs from the actual2105 probe."""
        self._validate_selection()
        specification, _unavailable = check_gateway_specification(self.runtime)
        if self.engine_state is not None:
            self.engine_state.set_central_gateway_type(2 if specification == 1 else 1)
        if specification == 1:
            self.start_online_reprogramming_mode(0)
            self.start_online_reprogramming_mode(1)
            self.runtime.call("wait", milliseconds=0)
            return 2
        self.start_reprogramming_mode()
        return 1

    def start_specific_service_mode(self) -> None:
        """Native RVA7180 uses1088 and option4/SecretInfo3, preserving timeout."""
        self._validate_selection()
        previous = self.runtime.call("get_timeout")
        if type(previous) is not int or not 0 <= previous <= 0xFFFFFFFF:
            raise ValueError("Native unsigned prior timeout required")
        request, response = central_gateway_can_ids()
        identifier = None
        try:
            self.runtime.call("set_timeout", milliseconds=0x3FC)
            identifier = self.diag.start_filter(request, response)
            if self._connected(request, response):
                session = self._call(request, response, b"\x10\x5f", b"\x50", 2, 0x62)[
                    1
                ]
                if session != 1:
                    self._default(request, response)
                self._call(
                    request, response, b"\x10\x88", b"\x50\x88", 2, 0x60, sync=False
                )
                self._collate(request, response, 4, service=True)
        finally:
            try:
                if identifier is not None:
                    self.runtime.release("stop_filter", identifier=identifier)
            finally:
                self.runtime.call("set_timeout", cleanup=True, milliseconds=previous)

    def end_two_cpu_sessions(self) -> None:
        """Native RVA3700 attempts both defaults, retains filters until both attempts."""
        self._validate_selection()
        identifiers = []
        errors: list[BaseException] = []
        try:
            for online in (True, False):
                request, response = central_gateway_can_ids(online=online)
                identifiers.append(self.diag.start_filter(request, response))
                try:
                    self._default(request, response)
                except (InterruptedError, KeyboardInterrupt):
                    raise
                except Exception as error:  # noqa: BLE001 - native per-CPU catch is best effort only for native faults
                    _raise_if_host_fault(error)
        except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - preserve primary failure through every release
            errors.append(exc)
        for identifier in identifiers:
            try:
                self.runtime.release("stop_filter", identifier=identifier)
            except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - attempt every native release
                errors.append(exc)
        for error in errors:
            _raise_if_host_fault(error)
        if len(errors) == 1:
            raise errors[0]
        if errors:
            raise BaseExceptionGroup("DH two-CPU session/cleanup failures", errors)

    def end_reprogramming_mode_for_multi_types(
        self, central_gateway_type: int | None = None
    ) -> None:
        """Native RVA3d90 selects the two-CPU or single-CPU cleanup procedure."""
        self._validate_selection()
        if central_gateway_type is None and self.engine_state is not None:
            central_gateway_type = self.engine_state.central_gateway_type
        if (
            type(central_gateway_type) is not int
            or not -0x80000000 <= central_gateway_type <= 0x7FFFFFFF
        ):
            raise ValueError("Native gateway type required")
        if central_gateway_type == 2:
            self.end_two_cpu_sessions()
        else:
            self.end_reprogramming_mode()


def bind_gateway_client(
    runtime: NativeRuntime2026,
    selection: NativeParameterBinding2026 | NativeControlParameterBase2026,
    state: DHControllerState2026,
    *,
    dh_utils_module: bytes,
    secret_info_module: bytes,
    cuw_module: bytes,
) -> DHGateway2026:
    """Actual shared engine enum and three hash-authenticated native dependencies."""
    if (
        not isinstance(runtime, NativeRuntime2026)
        or not isinstance(
            selection, (NativeParameterBinding2026, NativeControlParameterBase2026)
        )
        or not isinstance(state, DHControllerState2026)
        or any(
            not isinstance(value, bytes) or not 0 < len(value) <= 16 * 1024 * 1024
            for value in (dh_utils_module, secret_info_module, cuw_module)
        )
    ):
        raise ValueError(
            "Actual shared-engine gateway parameter and immutable native bytes required"
        )
    if isinstance(selection, NativeControlParameterBase2026):
        selection.validate(state.engine)
        if state.engine.worker.runtime is not runtime:
            raise ValueError("CONTROL BASE capability belongs to another runtime")
        if selection._pool is not None and state is not state.engine.dh_state:
            raise ValueError("CONTROL BASE capability requires its exact engine state")
    if (
        not isinstance(selection, NativeControlParameterBase2026)
        or selection._pool is None
    ):
        _dh_file_view(selection, state)
    if hashlib.sha256(cuw_module).hexdigest() != state.engine_sha256:
        raise ValueError(
            "Native gateway authorization caller differs from loaded engine"
        )
    identity = identify_native_module(
        hashlib.sha256(dh_utils_module).hexdigest(), "TCUWDHUtils.dll"
    )
    secret_info = SecretInfoClient.from_native_modules(secret_info_module, cuw_module)
    return DHGateway2026(runtime, selection, identity, secret_info, engine_state=state)


@dataclass(frozen=True)
class DHPhaseContext:
    """Actual native prepare dispatch and engine-owned CUW context."""

    identity: NativeModuleIdentity
    state: DHControllerState2026
    selection: CalibrationSelection | NativeParameterBinding2026 = field(repr=False)
    addresses: tuple[Address, ...]
    parameter_sources: tuple[tuple[str, str], ...]
    container: CalibrationContainer | None = field(default=None, repr=False)
    observed_cids: tuple[str, ...] = field(default=(), repr=False)

    def __post_init__(self):
        if (
            not isinstance(self.identity, NativeModuleIdentity)
            or self.identity
            != identify_native_module(self.identity.sha256, self.identity.module_name)
            or self.identity.cuw_build != "2026"
            or self.identity.module_name
            not in (
                "TCUWCanDHPrepareWriter.dll",
                "TCUWCanDHFlashWriter.dll",
                "TCUWCanDHGatewayPrepareWriter.dll",
                "TCUWCanDHUDSPrepareWriter.dll",
                "TCUWCanDHGatewayFlashWriter.dll",
                "TCUWCanDH19PFSURegGatewayFlashWriter.dll",
                "TCUWCanDH19PFSURegGatewayPrepareWriter.dll",
                "TCUWP5CanDHUDSPrepareWriter.dll",
                "TCUWCanDHMultiROMPrepareWriter.dll",
                "TCUWCanDHMultiROMFlashWriter.dll",
                "TCUWCanDHUSBReproFlashWriter.dll",
                "TCUWCanDHUDSFlashWriter.dll",
                "TCUWP5CanDHUDSFlashWriter.dll",
            )
            or not isinstance(self.state, DHControllerState2026)
            or not isinstance(
                self.selection, (CalibrationSelection, NativeParameterBinding2026)
            )
            or not isinstance(self.addresses, tuple)
            or not self.addresses
            or any(not isinstance(address, Address) for address in self.addresses)
            or not self.parameter_sources
        ):
            raise ValueError(
                "Exact native DH prepare dispatch and engine state required"
            )
        if isinstance(self.selection, NativeParameterBinding2026):
            if not isinstance(self.container, CalibrationContainer):
                raise TypeError("Actual2026 parameter container required")
            _dh_file_view(self.selection, self.state)
            if (
                self.selection._pool_issued
                and self.selection.module_name
                in ("TCUWCanDHPrepareWriter.dll", "TCUWCanDHFlashWriter.dll")
                and self.identity.module_name != self.selection.module_name
            ):
                from scripts.programming_2026_common import _control_export_dispatch2026

                if (self.selection.module_name, self.identity.module_name) != (
                    "TCUWCanDHFlashWriter.dll",
                    "TCUWCanDHPrepareWriter.dll",
                ):
                    raise ValueError("DH nested phase differs from its retained module")
                _control_export_dispatch2026(
                    self.state.engine._controller_export_target2026, "PrepareRetry"
                )


def _native_cpu0_address(context: DHPhaseContext) -> Address:
    """Rebuild only the native CPU0 address row; retain selected module parameters."""
    if context.state.global_cpu_index == 0:
        return context.addresses[0]
    selection = context.selection
    if not isinstance(selection, NativeParameterBinding2026):
        raise TypeError("Actual native catalogs required for CPU0 address selection")
    first = native2026_metadata_for_cpu(selection.metadata, 0)
    if first.source_container is None:
        raise ValueError("Actual CPU0 source container required")
    binding = bind_native_parameter2026(
        first.source_container,
        selection.catalog_sources,
        selection.operation,
        node=first.node,
        cpu_index=0,
        encoded=selection.encoded,
        metadata_state=first,
    )
    valid, addresses = communication_addresses_from_parameter(
        first.source_container,
        binding.parameter,
    ).resolve(
        binding.selector_functions,
        cids=context.observed_cids,
        location_id=native2026_location_id(first, 0) if first.cpus else None,
    )
    if not valid or not addresses:
        raise ValueError("Native CPU0 communication-address selector returned false")
    value = addresses[0]
    return Address(value.request, value.response, value.extended)


DHPrepareContext = DHPhaseContext


def bind_dh_prepare(
    selection: CalibrationSelection,
    context: SelectionContext,
    identity: NativeModuleIdentity,
    state: DHControllerState2026,
    *,
    module_version: str | None = None,
) -> DHPrepareContext:
    if identity.module_name != "TCUWCanDHPrepareWriter.dll":
        raise ValueError("Exact native classic DH prepare module required")
    dispatch = selection.dispatch(
        "prepare",
        context,
        {identity.module_name: identity.callable_exports},
        module_versions=None
        if module_version is None
        else {identity.module_name: module_version},
    )
    if dispatch["module"] != identity.module_name:
        raise ValueError("Selected prepare module differs from its inspected identity")
    return DHPrepareContext(
        identity,
        state,
        selection,
        tuple(
            Address(
                bytes.fromhex(row["request_hex"]),
                bytes.fromhex(row["response_hex"]),
                row["extended"],
            )
            for row in dispatch["addresses"]
        ),
        tuple((row["source"], row["sha256"]) for row in dispatch["sources"]),
    )


def prepare_dh(
    context: DHPrepareContext, runtime: NativeRuntime2026, gateway: DHGateway2026
) -> dict:
    """Classic native DH prepare1710/1470, including the bounded30 internal retries."""
    host_cleanup_errors: list[BaseException] = []
    if (
        not isinstance(context, DHPrepareContext)
        or not isinstance(runtime, NativeRuntime2026)
        or not isinstance(gateway, DHGateway2026)
        or gateway.runtime is not runtime
        or gateway.selection is not context.selection
    ):
        raise TypeError(
            "Same-selection native DH prepare context/runtime/gateway required"
        )
    context.__post_init__()
    if context.identity.module_name != "TCUWCanDHPrepareWriter.dll":
        raise ValueError("Exact native classic DH prepare dispatch required")
    selection, state = context.selection, context.state
    metadata, _native_cpu = _dh_file_view(selection, state)
    parser_cpu = native2026_global_cpu_index(metadata)

    def number(name, default=0):
        text = selection.value(name)
        if not text:
            return default
        if (
            not text.isascii()
            or not text.isdecimal()
            or len(text) > 10
            or int(text) > 0x7FFFFFFF
        ):
            raise ValueError("Native bounded unsigned DH parameter required")
        return int(text)

    def flag(name):
        value = selection.value(name)
        if value not in ("", "0", "1"):
            raise ValueError("Native Boolean DH parameter required")
        return value == "1"

    su = flag("FlagToSURegulation")
    no_retry = flag("FlagToNonPrepareWriteInternalRetryProcess")
    no_gateway = flag("FlagToNonChangeReprogGWModeProcess")
    no_seed_status = flag("FlagToNonSeedRespStatus")
    no_seed16_status = flag("FlagToNonSeed16ByteRespStatus")
    no_key_status = flag("FlagToNonSendKeyRespStatus")
    waits = {
        name: number(name)
        for name in (
            "WaitTimeBeforeDiagnosticMask1",
            "WaitTimeAfterDiagnosticMask",
            "WaitTimeAfterReprogrammingMode",
            "KindOfDiagnosticMask",
        )
    }
    timeout = number("ReceiveTimeoutBeforePrepareAndFlashWrite", 0x3FC) or 0x3FC
    rounds = (
        (
            selection.lines("SecurityKey")
            if isinstance(selection, NativeParameterBinding2026)
            else tuple(selection.value("SecurityKey").splitlines())
        )
        if not su
        else ()
    )
    if len(rounds) > 19 or any(
        len(value) != 4 or any(char not in "0123456789abcdefABCDEF" for char in value)
        for value in rounds
    ):
        raise ValueError("Native supplied SecurityKey table exceeds19 two-byte rounds")
    key_table = tuple(bytes.fromhex(value) for value in rounds)
    request, response = (
        context.addresses[0].request[:2],
        context.addresses[0].response[:2],
    )
    if state.alternate_can_address:
        request, response = replace_can_ids(
            request, response, selection.value("AlternateCanIDForPrepareAndFlashWrite")
        )
    request, response = b"\0\0" + request, b"\0\0" + response
    diag = CanDiag2026(runtime)
    old_receive, old_send = (
        runtime.call("get_timeout"),
        runtime.call("get_send_timeout"),
    )
    if any(
        type(value) is not int or not 0 <= value <= 0xFFFFFFFF
        for value in (old_receive, old_send)
    ):
        raise ValueError("Native unsigned prior receive/send timeouts required")
    result = {
        "state": "preparing",
        "family": context.identity.family,
        "physical_status": "PHYSICAL_UNCONFIRMED",
        "programming_completed": False,
        "native_return": False,
        "cleanup_errors": [],
        "internal_retry_count": 0,
    }
    identifier = None

    def call(ecu, payload):
        prefix, minimum, code = (
            (b"\x50\x85", 2, 0x12)
            if payload == b"\x10\x85"
            else (
                b"\x67\x01",
                2 + (16 + (not no_seed16_status) if su else 4 + (not no_seed_status)),
                0x10,
            )
        )
        if payload.startswith(b"\x27\x02"):
            prefix, code = b"\x67\x02" + (b"" if no_key_status else b"\x34"), 0x11
            minimum = len(prefix)
        return gateway._call(request, response, payload, prefix, minimum, code)

    channel = NativeProgrammingChannel(call, "DH")
    try:
        _require_dh_caller_channel(runtime)
        runtime.call("set_timeout", milliseconds=timeout)
        runtime.call("set_send_timeout", milliseconds=10000)
        identifier = diag.start_filter(request, response)
        for retry in range(31):
            result["internal_retry_count"] = retry
            try:
                specification, _ = check_gateway_specification(runtime)
                state.set_central_gateway_type(2 if specification else 1)
                if waits["WaitTimeBeforeDiagnosticMask1"]:
                    runtime.call(
                        "wait", milliseconds=waits["WaitTimeBeforeDiagnosticMask1"]
                    )
                if su:
                    diagnostic_mask_su(runtime)
                elif waits["KindOfDiagnosticMask"] == 1:
                    common_diagnostic_mask(
                        runtime, waits["WaitTimeAfterDiagnosticMask"]
                    )
                else:
                    runtime.release("stop_filter", identifier=identifier)
                    identifier = None
                    if runtime.owns_resource("disconnect"):
                        runtime.release("disconnect")
                    else:
                        runtime.call("disconnect")
                    runtime.call_owned("connect", "disconnect", protocol=5)
                    for _ in range(3):
                        count = runtime.call(
                            "write_messages",
                            protocol=5,
                            tx_flags=0,
                            data=bytes.fromhex("0000072002a027e916000000"),
                            count=1,
                        )
                        if type(count) is not int or count != 1:
                            raise ValueError("DH protocol5 mask write count differs")
                        runtime.call(
                            "wait", milliseconds=waits["WaitTimeAfterDiagnosticMask"]
                        )
                    if runtime.owns_resource("disconnect"):
                        runtime.release("disconnect")
                    else:
                        runtime.call("disconnect")
                    runtime.call_owned("connect", "disconnect", protocol=6)
                    identifier = diag.start_filter(request, response)
                diagnostic_mask(runtime, extended_addressing=True)
                if specification == 1:
                    gateway.start_online_reprogramming_mode(0)
                    gateway.start_online_reprogramming_mode(1)
                    runtime.call("wait", milliseconds=500)
                elif not no_gateway:
                    gateway.start_reprogramming_mode()
                if su:
                    change_phase5_session(runtime, extended=True)
                    start_sync_periodic_phase5(runtime, state.central_gateway_type)
                    runtime.call("wait", milliseconds=500)
                    diagnostic_mask_phase5(runtime)
                    runtime.call("wait", milliseconds=500)
                    stop_communication_phase5(runtime)
                change_reprogramming_mode(channel)
                if waits["WaitTimeAfterReprogrammingMode"]:
                    runtime.call(
                        "wait", milliseconds=waits["WaitTimeAfterReprogrammingMode"]
                    )
                if su:
                    seed = request_seed_specified_bytes(
                        channel,
                        16,
                        option=2,
                        flag_to_non_seed_16_byte_resp_status=no_seed16_status,
                    )
                    secret_type = secret_info_type(
                        metadata.vehicle.get("kindofecu", ""),
                        native2026_cpu_type(metadata, parser_cpu),
                    )
                    key = NativeSecurityComposer2026.calculate_security_key(
                        gateway.secret_info.get(secret_type), seed
                    )
                    if not isinstance(key, bytes) or len(key) != 16:
                        raise CommonResponseError(0x11)
                else:
                    seed = request_seed(
                        channel, flag_to_non_seed_resp_status=no_seed_status
                    )
                    key = calculate_seed_key(seed, key_table)
                send_key(channel, key, flag_to_non_send_key_resp_status=no_key_status)
                result["native_return"] = True
                result["state"] = "prepare_completed"
                break
            except NativeTransportError as exc:
                if no_retry or _dh_driver_status(exc) not in (9, 16) or retry == 30:
                    raise
                runtime.check()
    except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - preserve native result and unwind resources
        _raise_if_host_fault(exc)
        result["state"] = (
            "cancelled"
            if isinstance(exc, (InterruptedError, KeyboardInterrupt))
            else "failed"
        )
        if isinstance(exc, (InterruptedError, KeyboardInterrupt)):
            result["native_return"] = None
        result["error"] = type(exc).__name__
        result.update(_record_dh_error(state, exc, 1))
        try:
            if runtime.owns_resource("stop_sync_periodic"):
                runtime.release("stop_sync_periodic")
            else:
                runtime.call("stop_sync_periodic", cleanup=True)
        except (Exception, KeyboardInterrupt) as cleanup:  # noqa: BLE001 - preserve primary failure
            host_cleanup_errors.append(cleanup)
            result["cleanup_errors"].append(type(cleanup).__name__)
    finally:
        for operation, values in (
            ("stop_filter", {"identifier": identifier})
            if identifier is not None
            else ("", {}),
            ("set_timeout", {"milliseconds": old_receive}),
            ("set_send_timeout", {"milliseconds": old_send}),
        ):
            if operation:
                try:
                    if operation == "stop_filter":
                        runtime.release(operation, **values)
                    else:
                        runtime.call(operation, cleanup=True, **values)
                except (Exception, KeyboardInterrupt) as cleanup:  # noqa: BLE001 - attempt every compensation
                    host_cleanup_errors.append(cleanup)
                    result["cleanup_errors"].append(type(cleanup).__name__)
                    result["native_return"] = None
                    result["state"] = "failed"
        _raise_host_cleanup(host_cleanup_errors)
    _raise_host_cleanup(host_cleanup_errors)
    return result


def bind_dh_flash(
    selection: CalibrationSelection,
    context: SelectionContext,
    identity: NativeModuleIdentity,
    state: DHControllerState2026,
    *,
    module_version: str | None = None,
) -> DHPhaseContext:
    if identity.module_name != "TCUWCanDHFlashWriter.dll":
        raise ValueError("Exact native classic DH flash module required")
    dispatch = selection.dispatch(
        "write",
        context,
        {identity.module_name: identity.callable_exports},
        module_versions=None
        if module_version is None
        else {identity.module_name: module_version},
    )
    if dispatch["module"] != identity.module_name:
        raise ValueError("Selected writer differs from its inspected identity")
    return DHPhaseContext(
        identity,
        state,
        selection,
        tuple(
            Address(
                bytes.fromhex(row["request_hex"]),
                bytes.fromhex(row["response_hex"]),
                row["extended"],
            )
            for row in dispatch["addresses"]
        ),
        tuple((row["source"], row["sha256"]) for row in dispatch["sources"]),
    )


def flash_dh(
    context: DHPhaseContext, runtime: NativeRuntime2026, gateway: DHGateway2026
) -> dict:
    """Native classicDH1480/2070/2180: actual image/header, verify and lifecycle."""
    host_cleanup_errors: list[BaseException] = []
    if (
        not isinstance(context, DHPhaseContext)
        or not isinstance(runtime, NativeRuntime2026)
        or not isinstance(gateway, DHGateway2026)
        or gateway.runtime is not runtime
        or gateway.selection is not context.selection
    ):
        raise TypeError(
            "Same-selection native DH writer context/runtime/gateway required"
        )
    context.__post_init__()
    notification = context.state.notification
    if context.identity.module_name != "TCUWCanDHFlashWriter.dll":
        raise ValueError("Exact native classic DH writer dispatch required")
    state, selection = context.state, context.selection
    metadata, native_cpu = _dh_file_view(selection, state)
    parser_cpu = native2026_global_cpu_index(metadata)

    def flag(name):
        text = selection.value(name)
        if text not in ("", "0", "1"):
            raise ValueError("Native Boolean DH writer parameter required")
        return text == "1"

    def number(name, default):
        text = selection.value(name)
        if not text:
            return default
        if (
            not text.isascii()
            or not text.isdecimal()
            or len(text) > 10
            or int(text) > 0x7FFFFFFF
        ):
            raise ValueError("Native bounded unsigned DH writer parameter required")
        return int(text)

    su = flag("FlagToSURegulation")
    checksum_mode = flag("FlagToChecksumProcessInsteadOfVerification")
    hard_soft_info = flag("FlagToReadDataByIdentifierHardSoftInfoProcess")
    no_gateway = flag("FlagToNonChangeReprogGWModeProcess")
    timeout = number("ReceiveTimeoutBeforePrepareAndFlashWrite", 0x3FC) or 0x3FC
    subtract = number("ValueSubtractedFromMaxNumberBlockLength", 1)
    starts = (
        selection.lines("StartAddress")
        if isinstance(selection, NativeParameterBinding2026)
        else tuple(selection.value("StartAddress").splitlines())
    ) or ("",)
    if len(starts) > len(state.progress):
        raise ValueError("Native StartAddress list exceeds configured CPU count")
    start_index = 0
    if len(starts) >= 2:
        match = re.match(
            r"\s*[+-]?[0-9]+",
            native2026_location_id(metadata, parser_cpu),
        )
        if match is None:
            raise ValueError("Native decimal location index absent")
        start_index = int(match.group())
        if not -0x80000000 <= start_index <= 0x7FFFFFFF or not 0 <= start_index < len(
            starts
        ):
            raise ValueError("Native location index exceeds actual StartAddress list")
    start_text = starts[start_index]
    if (
        len(start_text) > 8
        or len(start_text) % 2
        or any(char not in "0123456789abcdefABCDEF" for char in start_text)
    ):
        raise ValueError("Native four-byte StartAddress hex text required")
    start = bytes.fromhex(start_text).rjust(4, b"\0")
    next_ignition = None
    if parser_cpu + 1 < native2026_cpu_count(metadata):
        if (
            not isinstance(selection, NativeParameterBinding2026)
            or "Parameter.ini" not in selection.catalog_sources
        ):
            raise ValueError(
                "Native global Parameter.ini dependency unavailable for next-CPU callback"
            )
        general = NativeGeneralParameters2026.from_binding(selection)
        next_ignition = general.boolean_with_keys(
            metadata.vehicle.get("kindofecu", ""),
            native2026_cpu_type(metadata, parser_cpu + 1),
            metadata.vehicle.get("contacttype", ""),
            "FlagToDoIGOFFONAtCPUTypeChange",
        )
    image_archive = native2026_archive(metadata)
    image = image_archive.data
    size = image_archive.flash_size
    if not isinstance(image, bytes) or not 0 < size <= len(image):
        raise ValueError("Native contiguous CPU image and bounded FlashSize required")
    image = image[:size]
    flash_code = b""
    if metadata.cpu.flash_code is not None:
        code_archive = native2026_archive(metadata, flash_code=True)
        if not isinstance(code_archive.data, bytes) or code_archive.length > len(
            code_archive.data
        ):
            raise ValueError("Native contiguous flash-code buffer required")
        flash_code = code_archive.data[: code_archive.length]
    address = context.addresses[0]
    request, response = address.request[:2], address.response[:2]
    if state.alternate_can_address:
        request, response = replace_can_ids(
            request, response, selection.value("AlternateCanIDForPrepareAndFlashWrite")
        )
    request, response = b"\0\0" + request, b"\0\0" + response
    diag = CanDiag2026(runtime)
    old_receive, old_send = (
        runtime.call("get_timeout"),
        runtime.call("get_send_timeout"),
    )
    if any(
        type(value) is not int or not 0 <= value <= 0xFFFFFFFF
        for value in (old_receive, old_send)
    ):
        raise ValueError("Native prior receive/send timeout required")
    result = {
        "state": "writing",
        "family": context.identity.family,
        "physical_status": "PHYSICAL_UNCONFIRMED",
        "programming_completed": False,
        "native_return": False,
        "cleanup_errors": [],
        "transferred_bytes": 0,
    }
    identifier = None

    def exchange(ecu, payload):
        if payload.startswith(b"\x34"):
            expected, minimum, code, sync = b"\x74\x20", 4, 0x1A, None
        elif payload.startswith(b"\x36"):
            expected, minimum, code, sync = b"\x76", 1, 0x22, None
        elif payload == b"\x37":
            expected, minimum, code, sync = b"\x77", 1, 0x1C, None
        elif payload == b"\x11\x01":
            expected, minimum, code, sync = b"\x51", 1, 0x18, None
        elif payload == bytes.fromhex("22fd10"):
            expected, minimum, code, sync = bytes.fromhex("62fd10"), 3, 0x57, False
        elif payload.startswith(bytes.fromhex("3101f011000144")):
            expected, minimum, code, sync = bytes.fromhex("7101f01120"), 7, 0x20, None
        elif payload == bytes.fromhex("3101f01101"):
            expected, minimum, code, sync = bytes.fromhex("7101f01100"), 5, 0x21, None
        elif payload == bytes.fromhex("3101f010"):
            expected, minimum, code, sync = (
                bytes.fromhex("7101f010") + bytes((checksum(image),)),
                5,
                0x59,
                False,
            )
        elif payload == bytes.fromhex("3101f01300"):
            expected, minimum, code, sync = bytes.fromhex("7101f01300"), 5, 0x59, True
        else:
            raise ValueError("Unexpected native classic DH writer request")
        if sync is True:
            return dh_sync_exchange(
                runtime,
                request,
                response,
                payload,
                expected,
                minimum=minimum,
                error_code=code,
            )
        return gateway._call(
            request, response, payload, expected, minimum, code, sync=sync is not False
        )

    channel = NativeProgrammingChannel(exchange, "DH")

    def transfer(data, maximum, phase):
        if type(maximum) is not int or not 0 < maximum <= channel.message_limit - 1:
            raise ValueError("Native transfer block length outside message bounds")
        offset = 0
        while offset < len(data):
            count = min(maximum, len(data) - offset)
            offset = transfer_data(channel, data, offset, count)
            if phase:
                state.record_dh_transfer(
                    count,
                    offset,
                    len(data),
                    verification=phase == 2,
                    checksum=checksum_mode,
                )
                result["transferred_bytes"] += count
            runtime.call(
                "notify_progress",
                cpu_index=native_cpu,
                transferred_bytes=result["transferred_bytes"],
                progress=state.progress[native_cpu],
            )
            runtime.check()

    try:
        _require_dh_caller_channel(runtime)
        runtime.call("set_timeout", milliseconds=timeout)
        runtime.call("set_send_timeout", milliseconds=10000)
        identifier = diag.start_filter(request, response)
        notification.assign(True)
        runtime.call("notify_programming_active", active=True)
        if hard_soft_info:
            read_hard_soft_info(channel)
        if su:
            for _ in range(2):
                _write_raw(runtime, request + b"\x3e\0")
                runtime.call("wait", milliseconds=100)
        maximum = request_download(
            channel, start, size, value_subtracted_from_max_number_block_length=subtract
        )
        if flash_code:
            transfer(flash_code, maximum, 0)
        transfer(image, maximum, 1)
        request_transfer_exit(channel)
        if not checksum_mode:
            maximum = request_verification_download(channel, start, size)
            transfer(image, maximum, 2)
            request_transfer_exit(channel)
            verify_result(channel)
        elif su:
            verify_su_checksum(channel)
        else:
            verify_checksum(channel, checksum(image))
        if su:
            resume_communication(runtime)
        ecu_reset(channel)
        if su:
            change_phase5_session(runtime)
        if state.central_gateway_type == 2:
            gateway.end_two_cpu_sessions()
        elif not no_gateway:
            gateway.end_reprogramming_mode(timeout)
        if runtime.owns_resource("stop_sync_periodic"):
            runtime.release("stop_sync_periodic")
        else:
            runtime.call("stop_sync_periodic")
        if next_ignition is False:
            runtime.call("notify_cpu_type_change", cpu_index=native_cpu + 1)
        notification.assign(False)
        runtime.call("notify_programming_active", active=False)
        result["native_return"] = True
        result["state"] = "writer_completed"
    except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - native outcome and comprehensive cleanup
        _raise_if_host_fault(exc)
        result["state"] = (
            "cancelled"
            if isinstance(exc, (InterruptedError, KeyboardInterrupt))
            else "failed"
        )
        if isinstance(exc, (InterruptedError, KeyboardInterrupt)):
            result["native_return"] = None
        result["error"] = type(exc).__name__
        result.update(_record_dh_error(state, exc, 2))
        try:
            if runtime.owns_resource("stop_sync_periodic"):
                runtime.release("stop_sync_periodic")
            else:
                runtime.call("stop_sync_periodic", cleanup=True)
            if isinstance(
                exc, (NativeTransportError, CommonResponseError, NativeNegativeResponse)
            ):
                state.reset_dh_count()
                runtime.call(
                    "notify_progress_count",
                    cleanup=True,
                    cpu_index=native_cpu,
                    transferred_bytes=0,
                )
                state.reset_dh_progress()
                runtime.call(
                    "notify_progress_percent",
                    cleanup=True,
                    cpu_index=native_cpu,
                    progress=0,
                )
        except (Exception, KeyboardInterrupt) as cleanup:  # noqa: BLE001 - retain primary native error
            host_cleanup_errors.append(cleanup)
            result["cleanup_errors"].append(type(cleanup).__name__)
    finally:
        for operation, values in (
            ("stop_filter", {"identifier": identifier})
            if identifier is not None
            else ("", {}),
            ("set_timeout", {"milliseconds": old_receive}),
            ("set_send_timeout", {"milliseconds": old_send}),
        ):
            if operation:
                try:
                    if operation == "stop_filter":
                        runtime.release(operation, **values)
                    else:
                        runtime.call(operation, cleanup=True, **values)
                except (Exception, KeyboardInterrupt) as cleanup:  # noqa: BLE001 - attempt every native compensation
                    host_cleanup_errors.append(cleanup)
                    result["cleanup_errors"].append(type(cleanup).__name__)
                    if operation == "stop_filter" and is_native_exception2026(cleanup):
                        continue  # Native empty Catch_All preserves the saved business BOOL.
                    result["native_return"] = None
                    result["state"] = "failed"
        _raise_host_cleanup(host_cleanup_errors)
    _raise_host_cleanup(host_cleanup_errors)
    return result


def prepare_retry_dh(
    context: DHPhaseContext,
    runtime: NativeRuntime2026,
    gateway: DHGateway2026,
    prepare_module: bytes,
) -> dict:
    """DHFlashWriter1d50/PrepareRetry24a0 calls the concrete native prepare client.

    The native retry retains the current parameter row and selected CPU's
    communication group; it does not reload a CPU0 prepare parameter file.
    """
    if (
        not isinstance(context, DHPhaseContext)
        or context.identity.module_name
        not in (
            "TCUWCanDHFlashWriter.dll",
            "TCUWCanDHUDSFlashWriter.dll",
            "TCUWP5CanDHUDSFlashWriter.dll",
        )
        or not isinstance(prepare_module, bytes)
        or not 0 < len(prepare_module) <= 16 * 1024 * 1024
    ):
        raise ValueError(
            "Exact native DH writer context and prepare dependency bytes required"
        )
    prepare_name = {
        "TCUWCanDHFlashWriter.dll": "TCUWCanDHPrepareWriter.dll",
        "TCUWCanDHUDSFlashWriter.dll": "TCUWCanDHUDSPrepareWriter.dll",
        "TCUWP5CanDHUDSFlashWriter.dll": "TCUWP5CanDHUDSPrepareWriter.dll",
    }[context.identity.module_name]
    modern = context.identity.module_name != "TCUWCanDHFlashWriter.dll"
    identity = identify_native_module(
        hashlib.sha256(prepare_module).hexdigest(), prepare_name
    )
    if (
        identity.cuw_build != "2026"
        or "StartPrepareWrite" not in identity.callable_exports
    ):
        raise ValueError("Native DH retry requires the exact2026 prepare dependency")
    context.__post_init__()
    if gateway.runtime is not runtime or gateway.selection is not context.selection:
        raise ValueError("Native retry must retain its exact parameter/runtime binding")
    try:
        if context.state.central_gateway_type == 2:
            gateway.end_two_cpu_sessions()
        else:
            text = context.selection.value("FlagToNonChangeReprogGWModeProcess")
            if text not in ("", "0", "1"):
                raise ValueError("Native Boolean gateway retry parameter required")
            if text != "1":
                gateway.end_reprogramming_mode()
        if modern:
            if runtime.owns_resource("stop_sync_periodic"):
                runtime.release("stop_sync_periodic")
            else:
                runtime.call("stop_sync_periodic")
        prepare_context = DHPhaseContext(
            identity,
            context.state,
            context.selection,
            context.addresses,
            context.parameter_sources,
            context.container,
            context.observed_cids,
        )
        result = (prepare_uds_dh if modern else prepare_dh)(
            prepare_context, runtime, gateway
        )
        if result["state"] == "prepare_completed":
            result["state"] = "prepare_retry_completed"
        return result
    except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - native retry Boolean/error outcome
        _raise_if_host_fault(exc)
        return {
            "state": "cancelled"
            if isinstance(exc, (InterruptedError, KeyboardInterrupt))
            else "failed",
            "family": context.identity.family,
            "physical_status": "PHYSICAL_UNCONFIRMED",
            "programming_completed": False,
            "native_return": None
            if isinstance(exc, (InterruptedError, KeyboardInterrupt))
            else False,
            "error": type(exc).__name__,
            "cleanup_errors": [],
            **_record_dh_error(context.state, exc, None),
        }


def prepare_gateway_dh(
    context: DHPhaseContext, runtime: NativeRuntime2026, gateway: DHGateway2026
) -> dict:
    """DHGatewayPrepare1070: masks, session and option2/SecretInfo2 or21 client."""
    host_cleanup_errors: list[BaseException] = []
    if (
        not isinstance(context, DHPhaseContext)
        or context.identity.module_name != "TCUWCanDHGatewayPrepareWriter.dll"
        or not isinstance(runtime, NativeRuntime2026)
        or not isinstance(gateway, DHGateway2026)
        or gateway.runtime is not runtime
        or gateway.selection is not context.selection
    ):
        raise ValueError("Actual DH gateway prepare context/runtime binding required")
    context.__post_init__()
    selection, state = context.selection, context.state

    def flag(name):
        if isinstance(selection, NativeParameterBinding2026):
            value = selection.parameter.boolean(name)
            return value is True
        value = selection.value(name)
        if value not in ("", "0", "1"):
            raise ValueError("Native Boolean DH gateway parameter required")
        return value == "1"

    su, no_default = (
        flag("FlagToSURegulation"),
        flag("FlagToNonChangeDefaultSessionProcess"),
    )
    no_seed = flag("FlagToNonSeed16ByteRespStatus")
    no_key = flag("FlagToNonSendKeyRespStatus")
    if isinstance(selection, NativeParameterBinding2026):
        wait = selection.parameter.long("WaitTimeAfterDiagnosticMask") or 0
    else:
        text = selection.value("WaitTimeAfterDiagnosticMask") or "0"
        if not text.isascii() or not text.isdecimal() or len(text) > 10:
            raise ValueError("Native unsigned diagnostic-mask wait required")
        wait = int(text)
    cpu0_address = _native_cpu0_address(context)
    request, response = (
        b"\0\0" + cpu0_address.request[:2],
        b"\0\0" + cpu0_address.response[:2],
    )
    previous, previous_send = (
        runtime.call("get_timeout"),
        runtime.call("get_send_timeout"),
    )
    if any(
        type(value) is not int or not 0 <= value <= 0xFFFFFFFF
        for value in (previous, previous_send)
    ):
        raise ValueError("Native prior unsigned timeout values required")
    identifier = None
    result = {
        "state": "preparing",
        "family": context.identity.family,
        "physical_status": "PHYSICAL_UNCONFIRMED",
        "programming_completed": False,
        "native_return": False,
        "cleanup_errors": [],
    }
    try:
        _require_dh_caller_channel(runtime)
        runtime.call("set_timeout", milliseconds=0x3FC)
        runtime.call("set_send_timeout", milliseconds=10000)
        identifier = gateway.diag.start_filter(request, response)
        if su:
            diagnostic_mask_su(runtime)
        else:
            common_diagnostic_mask(runtime, wait)
        diagnostic_mask(runtime, extended_addressing=True)
        if not no_default:
            current = gateway._call(request, response, b"\x10\x5f", b"\x50", 2, 0x62)
            if current[1] != 1:
                gateway._default(request, response)
        gateway._call(request, response, b"\x10\x85", b"\x50\x85", 2, 0x12)
        seed_reply = gateway._call(
            request,
            response,
            bytes.fromhex("270102"),
            bytes.fromhex("6701"),
            18 + (not no_seed),
            0x10,
        )
        key = NativeSecurityComposer2026.calculate_security_key(
            gateway.secret_info.get(0x15 if su else 2), seed_reply[2:18]
        )
        if not isinstance(key, bytes) or len(key) != 16:
            raise CommonResponseError(0x11)
        expected = bytes.fromhex("6702") + (b"" if no_key else b"\x34")
        gateway._call(
            request,
            response,
            bytes.fromhex("2702") + key,
            expected,
            len(expected),
            0x11,
        )
        result["native_return"] = True
        result["state"] = "prepare_completed"
    except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - native catch outcomes retain controller error fields
        _raise_if_host_fault(exc)
        result["state"] = (
            "cancelled"
            if isinstance(exc, (InterruptedError, KeyboardInterrupt))
            else "failed"
        )
        if isinstance(exc, (InterruptedError, KeyboardInterrupt)):
            result["native_return"] = None
        result["error"] = type(exc).__name__
        result.update(_record_dh_error(state, exc, 1))
        if "native_primary_error" not in result and result["state"] != "cancelled":
            state.record_native_error(1, 9999)
            result.update(
                native_error_kind=state.error_kind,
                native_primary_error=state.primary_error,
                native_passthru_error=state.passthru_error,
            )
    finally:
        for operation, values in (
            ("stop_filter", {"identifier": identifier})
            if identifier is not None
            else ("", {}),
            ("set_timeout", {"milliseconds": previous}),
            ("set_send_timeout", {"milliseconds": previous_send}),
        ):
            if operation:
                try:
                    if operation == "stop_filter":
                        runtime.release(operation, **values)
                    else:
                        runtime.call(operation, cleanup=True, **values)
                except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - attempt every acquired-resource compensation
                    host_cleanup_errors.append(exc)
                    result["cleanup_errors"].append(type(exc).__name__)
                    result["native_return"] = None
                    result["state"] = "failed"
        _raise_host_cleanup(host_cleanup_errors)
    _raise_host_cleanup(host_cleanup_errors)
    return result


def prepare_uds_dh(
    context: DHPhaseContext, runtime: NativeRuntime2026, gateway: DHGateway2026
) -> dict:
    """DHUDSPrepare1470/1070/1390: Phase5 broadcasts,1002 and SCM authentication."""
    host_cleanup_errors: list[BaseException] = []
    if (
        not isinstance(context, DHPhaseContext)
        or context.identity.module_name
        not in ("TCUWCanDHUDSPrepareWriter.dll", "TCUWP5CanDHUDSPrepareWriter.dll")
        or not isinstance(context.selection, NativeParameterBinding2026)
        or gateway.runtime is not runtime
        or gateway.selection is not context.selection
    ):
        raise ValueError("Actual native DHUDS prepare binding required")
    context.__post_init__()
    selection, state = context.selection, context.state
    cpu0_address = _native_cpu0_address(context)
    phase5 = context.identity.module_name == "TCUWP5CanDHUDSPrepareWriter.dll"
    request = b"\0\0" + cpu0_address.request[:2]
    response = b"\0\0" + cpu0_address.response[:2]
    previous = runtime.call("get_timeout")
    previous_send = runtime.call("get_send_timeout")
    if any(
        type(value) is not int or not 0 <= value <= 0xFFFFFFFF
        for value in (previous, previous_send)
    ):
        raise ValueError("Native prior unsigned timeout values required")
    identifier = None
    result = {
        "state": "preparing",
        "family": context.identity.family,
        "physical_status": "PHYSICAL_UNCONFIRMED",
        "programming_completed": False,
        "native_return": False,
        "cleanup_errors": [],
    }
    try:
        _require_dh_caller_channel(runtime)
        runtime.call("set_timeout", milliseconds=1000)
        runtime.call("set_send_timeout", milliseconds=10000)
        identifier = gateway.diag.start_filter(request, response)
        specification, _ = check_gateway_specification(runtime)
        state.set_central_gateway_type(2 if specification == 1 else 1)
        diagnostic_mask(runtime)
        diagnostic_mask(runtime, extended_addressing=True)
        if specification == 1:
            gateway.start_online_reprogramming_mode(0)
            gateway.start_online_reprogramming_mode(1)
            runtime.call("wait", milliseconds=500)
        elif (
            selection.parameter.boolean("FlagToNonChangeReprogGWModeProcess")
            is not True
        ):
            gateway.start_reprogramming_mode(0x3FC)
        change_phase5_session(runtime, extended=True)
        start_sync_periodic_phase5(runtime, state.central_gateway_type)
        runtime.call("wait", milliseconds=500)
        diagnostic_mask_phase5(runtime)
        runtime.call("wait", milliseconds=500)
        stop_communication_phase5(runtime)
        target_request, target_response = replace_can_ids(
            b"\0\0", b"\0\0", selection.value("CanIDForGetCID")
        )
        target_request = target_request.rjust(4, b"\0")
        target_response = target_response.rjust(4, b"\0")
        target_filter = gateway.diag.start_filter(target_request, target_response)
        try:
            if phase5:
                gateway.diag.call(
                    target_request,
                    target_response,
                    b"\x10\x02",
                    b"\x50\x02",
                    minimum=6,
                    error_code=0x12,
                    phase5=True,
                    pending_limit=0xB4,
                    busy_limit=0x159A,
                    send_tester_present=True,
                )
            else:
                dh_sync_exchange(
                    runtime,
                    target_request,
                    target_response,
                    b"\x10\x02",
                    b"\x50\x02",
                    minimum=6,
                    error_code=0x12,
                    pending_limit=99,
                    busy_limit=255,
                )
        finally:
            runtime.release("stop_filter", identifier=target_filter)
        wait = (
            1000
            if phase5
            else selection.parameter.long("WaitTimeAfterReprogrammingMode") or 1000
        )
        runtime.call("wait", milliseconds=wait)
        if phase5:
            seed = gateway.diag.call(
                request,
                response,
                b"\x27\x01",
                b"\x67\x01",
                minimum=18,
                error_code=0x10,
                phase5=True,
                pending_limit=0xB4,
                busy_limit=0x159A,
                send_tester_present=True,
            )[2:18]
        else:
            seed = gateway._seed(request, response, 16, 0)
        key = NativeSecurityComposer2026.calculate_security_key(
            gateway.secret_info.get(
                (0x35 if state.metadata.vehicle.get("kindofecu") == "168" else 0x3B)
                if phase5
                else (
                    0x17 if state.metadata.vehicle.get("kindofecu") == "109" else 0x18
                )
            ),
            seed,
        )
        if not isinstance(key, bytes) or len(key) != 16:
            raise CommonResponseError(0x11)
        if phase5:
            gateway.diag.call(
                request,
                response,
                b"\x27\x02" + key,
                b"\x67\x02",
                minimum=2,
                error_code=0x11,
                phase5=True,
                pending_limit=0xB4,
                busy_limit=0x159A,
                send_tester_present=True,
            )
        else:
            gateway._send_key(request, response, key)
        result["native_return"] = True
        result["state"] = "prepare_completed"
    except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - native EH continuation stops periodic and assigns kind1
        _raise_if_host_fault(exc)
        result["state"] = (
            "cancelled"
            if isinstance(exc, (InterruptedError, KeyboardInterrupt))
            else "failed"
        )
        if isinstance(exc, (InterruptedError, KeyboardInterrupt)):
            result["native_return"] = None
        result["error"] = type(exc).__name__
        try:
            if runtime.owns_resource("stop_sync_periodic"):
                runtime.release("stop_sync_periodic")
            else:
                runtime.call("stop_sync_periodic", cleanup=True)
        except (Exception, KeyboardInterrupt) as cleanup:  # noqa: BLE001 - retain primary failure
            host_cleanup_errors.append(cleanup)
            result["cleanup_errors"].append(type(cleanup).__name__)
        result.update(_record_dh_error(state, exc, 1))
        if "native_primary_error" not in result and result["state"] != "cancelled":
            state.record_native_error(1, 9999)
            result.update(
                native_error_kind=state.error_kind,
                native_primary_error=state.primary_error,
                native_passthru_error=state.passthru_error,
            )
    finally:
        for operation, values in (
            ("stop_filter", {"identifier": identifier})
            if identifier is not None
            else ("", {}),
            ("set_timeout", {"milliseconds": previous}),
            ("set_send_timeout", {"milliseconds": previous_send}),
        ):
            if operation:
                try:
                    if operation == "stop_filter":
                        runtime.release(operation, **values)
                    else:
                        runtime.call(operation, cleanup=True, **values)
                except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - attempt every acquired compensation
                    host_cleanup_errors.append(exc)
                    result["cleanup_errors"].append(type(exc).__name__)
                    result["native_return"] = None
                    result["state"] = "failed"
        _raise_host_cleanup(host_cleanup_errors)
    _raise_host_cleanup(host_cleanup_errors)
    return result


def flash_gateway_dh(
    context: DHPhaseContext, runtime: NativeRuntime2026, gateway: DHGateway2026
) -> dict:
    """GatewayFlash1070/1460: CPU0 image, separate count/percent notifications."""
    host_cleanup_errors: list[BaseException] = []
    if (
        not isinstance(context, DHPhaseContext)
        or context.identity.module_name
        not in (
            "TCUWCanDHGatewayFlashWriter.dll",
            "TCUWCanDH19PFSURegGatewayFlashWriter.dll",
        )
        or not isinstance(context.selection, NativeParameterBinding2026)
        or gateway.runtime is not runtime
        or gateway.selection is not context.selection
    ):
        raise ValueError("Actual native DH gateway writer binding required")
    context.__post_init__()
    notification = context.state.notification
    state, selection = context.state, context.selection
    nineteen = (
        context.identity.module_name == "TCUWCanDH19PFSURegGatewayFlashWriter.dll"
    )
    cpu0_address = _native_cpu0_address(context)
    cpu0_metadata = native2026_metadata_for_cpu(state.metadata, 0)
    archive = native2026_archive(cpu0_metadata)
    size, image = archive.flash_size, archive.data
    if not isinstance(image, bytes) or not 0 < size <= len(image):
        raise ValueError("Native contiguous CPU0 image and FlashSize required")
    image = image[:size]
    flash_code = b""
    if cpu0_metadata.cpu.flash_code is not None:
        code = native2026_archive(cpu0_metadata, flash_code=True)
        if not isinstance(code.data, bytes) or code.length > len(code.data):
            raise ValueError("Native contiguous CPU0 flash code required")
        flash_code = code.data[: code.length]
    start_text = selection.value("StartAddress")
    if (
        len(start_text) > 8
        or len(start_text) % 2
        or any(c not in "0123456789abcdefABCDEF" for c in start_text)
    ):
        raise ValueError("Native four-byte StartAddress required")
    start = bytes.fromhex(start_text).rjust(4, b"\0")
    subtract = selection.parameter.long("ValueSubtractedFromMaxNumberBlockLength")
    subtract = 1 if subtract is None else subtract
    request = b"\0\0" + cpu0_address.request[:2]
    response = b"\0\0" + cpu0_address.response[:2]
    previous, previous_send = (
        runtime.call("get_timeout"),
        runtime.call("get_send_timeout"),
    )
    if any(
        type(v) is not int or not 0 <= v <= 0xFFFFFFFF
        for v in (previous, previous_send)
    ):
        raise ValueError("Native prior unsigned timeout values required")
    result = {
        "state": "writing",
        "family": context.identity.family,
        "physical_status": "PHYSICAL_UNCONFIRMED",
        "programming_completed": False,
        "native_return": False,
        "transferred_bytes": 0,
        "cleanup_errors": [],
    }
    identifier = None

    def exchange(ecu, payload):
        ordinary = False
        if payload.startswith(b"\x34"):
            expected, minimum, error = b"\x74\x20", 4, 0x1A
        elif payload.startswith(b"\x36"):
            expected, minimum, error = b"\x76", 1, 0x22
        elif payload == b"\x37":
            expected, minimum, error = b"\x77", 1, 0x1C
        elif payload == b"\x11\x01":
            expected, minimum, error = b"\x51", 1, 0x18
        elif payload == bytes.fromhex("22fd10"):
            expected, minimum, error, ordinary = bytes.fromhex("62fd10"), 3, 0x57, True
        elif payload == bytes.fromhex("3101f010"):
            expected, minimum, error, ordinary = (
                bytes.fromhex("7101f010") + bytes((checksum(image),)),
                5,
                0x59,
                True,
            )
        elif payload == bytes.fromhex("3101f01300"):
            return dh_sync_exchange(
                runtime,
                request,
                response,
                payload,
                bytes.fromhex("7101f01300"),
                minimum=5,
                error_code=0x59,
            )
        else:
            raise ValueError("Unexpected native DH gateway writer PDU")
        return gateway._call(
            request, response, payload, expected, minimum, error, sync=not ordinary
        )

    channel = NativeProgrammingChannel(exchange, "DH")
    try:
        _require_dh_caller_channel(runtime)
        runtime.call(
            "set_timeout",
            milliseconds=(
                selection.parameter.long("ReceiveTimeoutBeforePrepareAndFlashWrite")
                or 0
            )
            if nineteen
            else 0x3FC,
        )
        runtime.call("set_send_timeout", milliseconds=10000)
        identifier = gateway.diag.start_filter(request, response)
        notification.assign(True)
        runtime.call("notify_programming_active", active=True)
        read_hard_soft_info(channel)
        maximum = request_download(
            channel, start, size, value_subtracted_from_max_number_block_length=subtract
        )
        if type(maximum) is not int or not 0 < maximum <= channel.message_limit - 1:
            raise ValueError("Native transfer block length outside message bounds")
        for phase, data in ((0, flash_code), (1, image)):
            offset = 0
            while offset < len(data):
                count = min(maximum, len(data) - offset)
                offset = transfer_data(channel, data, offset, count)
                if phase and nineteen:
                    state.set_native_count(
                        0, (state.transferred_bytes[0] + count) & 0xFFFFFFFF
                    )
                    state.set_native_percentage(0, 100 * offset // size)
                    result["transferred_bytes"] += count
                elif phase:
                    state.record_gateway_count(offset, size)
                    result["transferred_bytes"] = offset
                if phase or nineteen:
                    runtime.call(
                        "notify_progress_count",
                        cpu_index=0,
                        transferred_bytes=state.transferred_bytes[0],
                    )
                    if phase and not nineteen:
                        state.record_gateway_progress(offset, size)
                    runtime.call(
                        "notify_progress_percent",
                        cpu_index=0,
                        progress=state.progress[0],
                    )
                runtime.check()
        request_transfer_exit(channel)
        if nineteen or selection.parameter.boolean("FlagToSURegulation") is True:
            verify_su_checksum(channel)
        else:
            verify_checksum(channel, checksum(image))
        ecu_reset(channel)
        if nineteen:
            if runtime.owns_resource("stop_sync_periodic"):
                runtime.release("stop_sync_periodic")
            else:
                runtime.call("stop_sync_periodic")
            gateway.end_two_cpu_sessions()
        notification.assign(False)
        runtime.call("notify_programming_active", active=False)
        result["native_return"] = True
        result["state"] = "writer_completed"
    except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - source catch and independent cleanup
        _raise_if_host_fault(exc)
        result["state"] = (
            "cancelled"
            if isinstance(exc, (InterruptedError, KeyboardInterrupt))
            else "failed"
        )
        if isinstance(exc, (InterruptedError, KeyboardInterrupt)):
            result["native_return"] = None
        result["error"] = type(exc).__name__
        if nineteen:
            native_error = _record_dh_error(state, exc, None)
            if not native_error and result["state"] != "cancelled":
                state.record_native_error(None, 9999)
            try:
                if runtime.owns_resource("stop_sync_periodic"):
                    runtime.release("stop_sync_periodic")
                else:
                    runtime.call("stop_sync_periodic", cleanup=True)
            except (Exception, KeyboardInterrupt) as cleanup:  # noqa: BLE001 - retain primary failure
                host_cleanup_errors.append(cleanup)
                result["cleanup_errors"].append(type(cleanup).__name__)
        if is_native_exception2026(exc):
            try:
                state.set_native_count(0, 0)
                runtime.call(
                    "notify_progress_count",
                    cleanup=True,
                    cpu_index=0,
                    transferred_bytes=0,
                )
                state.set_native_percentage(0, 0)
                runtime.call(
                    "notify_progress_percent", cleanup=True, cpu_index=0, progress=0
                )
            except (Exception, KeyboardInterrupt) as cleanup:  # noqa: BLE001 - preserve primary native error
                host_cleanup_errors.append(cleanup)
                result["cleanup_errors"].append(type(cleanup).__name__)
        error_kind = (2 if bool(notification) else 1) if nineteen else 2
        result.update(_record_dh_error(state, exc, error_kind))
        if "native_primary_error" not in result and result["state"] != "cancelled":
            state.record_native_error(error_kind, 9999)
            result.update(
                native_error_kind=state.error_kind,
                native_primary_error=state.primary_error,
                native_passthru_error=state.passthru_error,
            )
    finally:
        for operation, values in (
            ("stop_filter", {"identifier": identifier})
            if identifier is not None
            else ("", {}),
            ("set_timeout", {"milliseconds": previous}),
            ("set_send_timeout", {"milliseconds": previous_send}),
        ):
            if operation:
                try:
                    if operation == "stop_filter":
                        runtime.release(operation, **values)
                    else:
                        runtime.call(operation, cleanup=True, **values)
                except (Exception, KeyboardInterrupt) as cleanup:  # noqa: BLE001 - attempt every acquired compensation
                    host_cleanup_errors.append(cleanup)
                    result["cleanup_errors"].append(type(cleanup).__name__)
                    if operation == "stop_filter" and is_native_exception2026(cleanup):
                        continue  # Native empty Catch_All preserves the saved business BOOL.
                    result["native_return"] = None
                    result["state"] = "failed"
        _raise_host_cleanup(host_cleanup_errors)
    _raise_host_cleanup(host_cleanup_errors)
    return result


def prepare_19pf_gateway_dh(
    context: DHPhaseContext, runtime: NativeRuntime2026, gateway: DHGateway2026
) -> dict:
    """19PFSUPrepare1090/1580/1780: physical44 or online03 authentication."""
    host_cleanup_errors: list[BaseException] = []
    if (
        not isinstance(context, DHPhaseContext)
        or context.identity.module_name != "TCUWCanDH19PFSURegGatewayPrepareWriter.dll"
        or not isinstance(context.selection, NativeParameterBinding2026)
        or gateway.runtime is not runtime
        or gateway.selection is not context.selection
    ):
        raise ValueError("Actual native 19PF DH prepare binding required")
    context.__post_init__()
    state, selection = context.state, context.selection
    cpu0_address = _native_cpu0_address(context)
    request = b"\0\0" + cpu0_address.request[:2]
    response = b"\0\0" + cpu0_address.response[:2]
    previous, previous_send = (
        runtime.call("get_timeout"),
        runtime.call("get_send_timeout"),
    )
    if any(
        type(v) is not int or not 0 <= v <= 0xFFFFFFFF
        for v in (previous, previous_send)
    ):
        raise ValueError("Native prior unsigned timeout values required")
    identifier = None
    result = {
        "state": "preparing",
        "family": context.identity.family,
        "physical_status": "PHYSICAL_UNCONFIRMED",
        "programming_completed": False,
        "native_return": False,
        "cleanup_errors": [],
    }
    try:
        _require_dh_caller_channel(runtime)
        timeout = (
            selection.parameter.long("ReceiveTimeoutBeforePrepareAndFlashWrite") or 0
        )
        runtime.call("set_timeout", milliseconds=timeout)
        runtime.call("set_send_timeout", milliseconds=10000)
        physical = request == bytes.fromhex("00000044")
        specification, unavailable = check_gateway_specification(
            runtime, allow_unavailable=physical and state.native_context_964
        )
        if specification == 0:
            raise CommonResponseError(0x3FE)
        state.set_central_gateway_type(2)
        diagnostic_mask_su(runtime)
        check_need_repro_center_authentication(runtime)
        if physical:
            identifier = gateway.diag.start_filter(request, response)
            gateway._call(request, response, b"\x10\x85", b"\x50\x85", 2, 0x12)
            start_sync_periodic(
                runtime, central_gateway_can_ids(online=True)[0], su_regulation=True
            )
            seed = gateway._seed(request, response, 8, 6)
            key = runtime.call("calculate_dh_gateway_online_key", seed=seed)
            if not isinstance(key, bytes) or len(key) != 64:
                raise CommonResponseError(0x11)
            gateway._send_key(request, response, key)
            gateway.set_security_table_kind(1)
            gateway._collate(request, response, 2)
            other_request, other_response = central_gateway_can_ids()
            other_filter = gateway.diag.start_filter(other_request, other_response)
            try:
                rejected = gateway._reprog_session(
                    other_request, other_response, allow_unavailable=unavailable
                )
                if not rejected:
                    gateway._collate(other_request, other_response, 3)
            finally:
                runtime.release("stop_filter", identifier=other_filter)
        elif request == bytes.fromhex("00000003"):
            other_request, other_response = central_gateway_can_ids()
            identifier = gateway.diag.start_filter(other_request, other_response)
            gateway.start_online_reprogramming_mode(0)
            gateway._call(
                other_request, other_response, b"\x10\x85", b"\x50\x85", 2, 0x12
            )
            gateway._collate(other_request, other_response, 2)
        else:
            raise CommonResponseError(9999)
        runtime.call("wait", milliseconds=500)
        result["native_return"] = True
        result["state"] = "prepare_completed"
    except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - native EH continuation stops periodic and assigns kind1
        _raise_if_host_fault(exc)
        result["state"] = (
            "cancelled"
            if isinstance(exc, (InterruptedError, KeyboardInterrupt))
            else "failed"
        )
        if isinstance(exc, (InterruptedError, KeyboardInterrupt)):
            result["native_return"] = None
        result["error"] = type(exc).__name__
        try:
            if runtime.owns_resource("stop_sync_periodic"):
                runtime.release("stop_sync_periodic")
            else:
                runtime.call("stop_sync_periodic", cleanup=True)
        except (Exception, KeyboardInterrupt) as cleanup:  # noqa: BLE001 - retain primary failure
            host_cleanup_errors.append(cleanup)
            result["cleanup_errors"].append(type(cleanup).__name__)
        result.update(_record_dh_error(state, exc, 1))
        if "native_primary_error" not in result and result["state"] != "cancelled":
            state.record_native_error(1, 9999)
            result.update(
                native_error_kind=state.error_kind,
                native_primary_error=state.primary_error,
                native_passthru_error=state.passthru_error,
            )
    finally:
        for operation, values in (
            ("stop_filter", {"identifier": identifier})
            if identifier is not None
            else ("", {}),
            ("set_timeout", {"milliseconds": previous}),
            ("set_send_timeout", {"milliseconds": previous_send}),
        ):
            if operation:
                try:
                    if operation == "stop_filter":
                        runtime.release(operation, **values)
                    else:
                        runtime.call(operation, cleanup=True, **values)
                except (Exception, KeyboardInterrupt) as cleanup:  # noqa: BLE001 - attempt every acquired compensation
                    host_cleanup_errors.append(cleanup)
                    result["cleanup_errors"].append(type(cleanup).__name__)
                    result["native_return"] = None
                    result["state"] = "failed"
        _raise_host_cleanup(host_cleanup_errors)
    _raise_host_cleanup(host_cleanup_errors)
    return result


def prepare_multirom_dh(
    context: DHPhaseContext, runtime: NativeRuntime2026, gateway: DHGateway2026
) -> dict:
    """MultiROMPrepare1810/1450/1570: restart timeout, mask, key then1085."""
    host_cleanup_errors: list[BaseException] = []
    if (
        not isinstance(context, DHPhaseContext)
        or context.identity.module_name != "TCUWCanDHMultiROMPrepareWriter.dll"
        or not isinstance(context.selection, NativeParameterBinding2026)
        or gateway.runtime is not runtime
        or gateway.selection is not context.selection
    ):
        raise ValueError("Actual native MultiROM DH prepare binding required")
    context.__post_init__()
    state, selection = context.state, context.selection
    cpu0_address = _native_cpu0_address(context)
    rounds = selection.lines("SecurityKey")
    if len(rounds) > 19 or any(
        len(v) != 4 or any(c not in "0123456789abcdefABCDEF" for c in v) for v in rounds
    ):
        raise ValueError("Native supplied SecurityKey table exceeds19 two-byte rounds")
    key_table = tuple(bytes.fromhex(value) for value in rounds)
    request, response = (
        b"\0\0" + cpu0_address.request[:2],
        b"\0\0" + cpu0_address.response[:2],
    )
    previous, previous_send = (
        runtime.call("get_timeout"),
        runtime.call("get_send_timeout"),
    )
    if any(
        type(v) is not int or not 0 <= v <= 0xFFFFFFFF
        for v in (previous, previous_send)
    ):
        raise ValueError("Native prior unsigned timeout values required")
    identifier = None
    result = {
        "state": "preparing",
        "family": context.identity.family,
        "physical_status": "PHYSICAL_UNCONFIRMED",
        "programming_completed": False,
        "native_return": False,
        "cleanup_errors": [],
    }
    try:
        _require_dh_caller_channel(runtime)
        runtime.call("set_timeout", milliseconds=1000)
        runtime.call("set_send_timeout", milliseconds=10000)
        identifier = gateway.diag.start_filter(request, response)
        try:
            dh_sync_exchange(
                runtime,
                bytes.fromhex("00000792"),
                bytes.fromhex("0000079a"),
                b"\x10\x83",
                None,
                error_code=1000,
                pending_limit=99,
                busy_limit=255,
            )
        except NativeTransportError as exc:
            if _dh_driver_status(exc) not in (9, 16):
                raise
        else:
            raise CommonResponseError(1000)
        common_diagnostic_mask(
            runtime, selection.parameter.long("WaitTimeAfterDiagnosticMask") or 0
        )
        gateway.start_reprogramming_mode(1000)
        seed = gateway._call(
            request,
            response,
            b"\x27\x01",
            b"\x67\x01",
            6 + (not gateway._flag("FlagToNonSeedRespStatus")),
            0x10,
        )[2:6]
        key = calculate_seed_key(seed, key_table)
        gateway._send_key(request, response, key)
        gateway._call(request, response, b"\x10\x85", b"\x50\x85", 2, 0x12)
        result["native_return"] = True
        result["state"] = "prepare_completed"
    except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - source catch outcomes and cleanup
        _raise_if_host_fault(exc)
        result["state"] = (
            "cancelled"
            if isinstance(exc, (InterruptedError, KeyboardInterrupt))
            else "failed"
        )
        if isinstance(exc, (InterruptedError, KeyboardInterrupt)):
            result["native_return"] = None
        result["error"] = type(exc).__name__
        result.update(_record_dh_error(state, exc, 1))
        if "native_primary_error" not in result and result["state"] != "cancelled":
            state.record_native_error(1, 9999)
            result.update(
                native_error_kind=state.error_kind,
                native_primary_error=state.primary_error,
                native_passthru_error=state.passthru_error,
            )
    finally:
        for operation, values in (
            ("stop_filter", {"identifier": identifier})
            if identifier is not None
            else ("", {}),
            ("set_timeout", {"milliseconds": previous}),
            ("set_send_timeout", {"milliseconds": previous_send}),
        ):
            if operation:
                try:
                    if operation == "stop_filter":
                        runtime.release(operation, **values)
                    else:
                        runtime.call(operation, cleanup=True, **values)
                except (Exception, KeyboardInterrupt) as cleanup:  # noqa: BLE001 - attempt every acquired compensation
                    host_cleanup_errors.append(cleanup)
                    result["cleanup_errors"].append(type(cleanup).__name__)
                    result["native_return"] = None
                    result["state"] = "failed"
        _raise_host_cleanup(host_cleanup_errors)
    _raise_host_cleanup(host_cleanup_errors)
    return result


def flash_multirom_dh(
    context: DHPhaseContext, runtime: NativeRuntime2026, gateway: DHGateway2026
) -> dict:
    """MultiROMFlash13b0/1970/1ca0: two S-record segments with sequence bytes."""
    host_cleanup_errors: list[BaseException] = []
    if (
        not isinstance(context, DHPhaseContext)
        or context.identity.module_name != "TCUWCanDHMultiROMFlashWriter.dll"
        or not isinstance(context.selection, NativeParameterBinding2026)
        or gateway.runtime is not runtime
        or gateway.selection is not context.selection
    ):
        raise ValueError("Actual native MultiROM DH writer binding required")
    context.__post_init__()
    state, selection = context.state, context.selection
    notification = state.notification
    cpu0_address = _native_cpu0_address(context)
    cpu0_metadata = native2026_metadata_for_cpu(state.metadata, 0)
    sizes_text, starts_text = (
        selection.lines("EachWriteDataSize"),
        selection.lines("StartAddress"),
    )
    if len(sizes_text) != 2 or len(starts_text) != 2:
        raise ValueError("Exactly two actual MultiROM sizes and addresses required")
    sizes, starts = [], []
    for text in sizes_text:
        match = re.match(r"\s*[+-]?[0-9]+", text)
        if match is None or not 0 < int(match.group()) <= 64 * 1024 * 1024:
            raise ValueError("Positive bounded native MultiROM decimal length required")
        sizes.append(int(match.group()))
    if sum(sizes) > 64 * 1024 * 1024:
        raise ValueError("Aggregate MultiROM allocation exceeds host budget")
    for text in starts_text:
        if (
            len(text) > 8
            or len(text) % 2
            or any(c not in "0123456789abcdefABCDEF" for c in text)
        ):
            raise ValueError("Native MultiROM four-byte start address required")
        starts.append(bytes.fromhex(text).rjust(4, b"\0"))
    archive = native2026_archive(cpu0_metadata)
    first, cursor = multirom_image_segment(
        archive, int.from_bytes(starts[0], "big"), sizes[0], 0
    )
    second, _ = multirom_image_segment(
        archive, int.from_bytes(starts[1], "big"), sizes[1], cursor + 1
    )
    subtract = selection.parameter.long("ValueSubtractedFromMaxNumberBlockLength")
    subtract = 1 if subtract is None else subtract
    request, response = (
        b"\0\0" + cpu0_address.request[:2],
        b"\0\0" + cpu0_address.response[:2],
    )
    previous, previous_send = (
        runtime.call("get_timeout"),
        runtime.call("get_send_timeout"),
    )
    if any(
        type(v) is not int or not 0 <= v <= 0xFFFFFFFF
        for v in (previous, previous_send)
    ):
        raise ValueError("Native prior unsigned timeout values required")
    identifier = None
    result = {
        "state": "writing",
        "family": context.identity.family,
        "physical_status": "PHYSICAL_UNCONFIRMED",
        "programming_completed": False,
        "native_return": False,
        "transferred_bytes": 0,
        "cleanup_errors": [],
    }

    def exchange(ecu, payload):
        if payload.startswith(b"\x34"):
            expected, minimum, error = b"\x74\x20", 4, 0x1A
        elif payload == b"\x37":
            expected, minimum, error = b"\x77", 1, 0x1C
        elif payload == bytes.fromhex("3101f01101"):
            expected, minimum, error = bytes.fromhex("7101f01100"), 5, 0x21
        elif payload == bytes.fromhex("22fd10"):
            return gateway._call(
                request, response, payload, bytes.fromhex("62fd10"), 3, 0x57, sync=False
            )
        else:
            raise ValueError("Unexpected native MultiROM DH writer PDU")
        return gateway._call(request, response, payload, expected, minimum, error)

    channel = NativeProgrammingChannel(exchange, "DH")
    try:
        _require_dh_caller_channel(runtime)
        runtime.call("set_timeout", milliseconds=1000)
        runtime.call("set_send_timeout", milliseconds=10000)
        identifier = gateway.diag.start_filter(request, response)
        notification.assign(True)
        runtime.call("notify_programming_active", active=True)
        read_hard_soft_info(channel)
        dh_sync_exchange(
            runtime,
            request,
            response,
            bytes.fromhex("3101ff00"),
            bytes.fromhex("7101ff00"),
            minimum=4,
            error_code=1001,
        )
        for start, data in zip(starts, (first, second), strict=True):
            maximum = (
                request_download(
                    channel,
                    start,
                    len(data),
                    value_subtracted_from_max_number_block_length=subtract,
                )
                - 1
            ) & 0xFFFFFFFF
            if not 0 < maximum <= channel.message_limit - 2:
                raise ValueError(
                    "Native MultiROM transfer block length outside message bounds"
                )
            offset, sequence = 0, 0
            while offset < len(data):
                count = min(maximum, len(data) - offset)
                sequence = (sequence + 1) & 255
                dh_sync_exchange(
                    runtime,
                    request,
                    response,
                    b"\x36" + bytes((sequence,)) + data[offset : offset + count],
                    b"\x76" + bytes((sequence,)),
                    minimum=2,
                    error_code=0x22,
                )
                offset += count
                state.record_multirom_transfer(count, selection)
                result["transferred_bytes"] += count
                runtime.call(
                    "notify_progress_count",
                    cpu_index=0,
                    transferred_bytes=state.transferred_bytes[0],
                )
                runtime.call(
                    "notify_progress_percent", cpu_index=0, progress=state.progress[0]
                )
            request_transfer_exit(channel)
        verify_result(channel)
        gateway.end_reprogramming_mode(1000)
        start_sync_periodic(runtime, bytes.fromhex("00000792"))
        notification.assign(False)
        runtime.call("notify_programming_active", active=False)
        result["native_return"] = True
        result["state"] = "writer_completed"
    except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - source EH tail and resource compensation
        _raise_if_host_fault(exc)
        result["state"] = (
            "cancelled"
            if isinstance(exc, (InterruptedError, KeyboardInterrupt))
            else "failed"
        )
        if isinstance(exc, (InterruptedError, KeyboardInterrupt)):
            result["native_return"] = None
        result["error"] = type(exc).__name__
        native = is_native_exception2026(exc)
        native_error = _record_dh_error(state, exc, None)
        if not native_error and result["state"] != "cancelled":
            state.record_native_error(None, 9999)
        try:
            if runtime.owns_resource("stop_sync_periodic"):
                runtime.release("stop_sync_periodic")
            else:
                runtime.call("stop_sync_periodic", cleanup=True)
            if native:
                state.set_native_count(0, 0)
                runtime.call(
                    "notify_progress_count",
                    cleanup=True,
                    cpu_index=0,
                    transferred_bytes=0,
                )
                state.set_native_percentage(0, 0)
                runtime.call(
                    "notify_progress_percent", cleanup=True, cpu_index=0, progress=0
                )
        except (Exception, KeyboardInterrupt) as cleanup:  # noqa: BLE001 - retain primary failure
            host_cleanup_errors.append(cleanup)
            result["cleanup_errors"].append(type(cleanup).__name__)
        if native:
            state.record_native_error(2, state.primary_error)
            result.update(
                native_error_kind=state.error_kind,
                native_primary_error=state.primary_error,
                native_passthru_error=state.passthru_error,
            )
    finally:
        for operation, values in (
            ("stop_filter", {"identifier": identifier})
            if identifier is not None
            else ("", {}),
            ("set_timeout", {"milliseconds": previous}),
            ("set_send_timeout", {"milliseconds": previous_send}),
        ):
            if operation:
                try:
                    if operation == "stop_filter":
                        runtime.release(operation, **values)
                    else:
                        runtime.call(operation, cleanup=True, **values)
                except (Exception, KeyboardInterrupt) as cleanup:  # noqa: BLE001 - attempt every acquired compensation
                    host_cleanup_errors.append(cleanup)
                    result["cleanup_errors"].append(type(cleanup).__name__)
                    if operation == "stop_filter" and is_native_exception2026(cleanup):
                        continue  # Native empty Catch_All preserves the saved business BOOL.
                    result["native_return"] = None
                    result["state"] = "failed"
        _raise_host_cleanup(host_cleanup_errors)
    _raise_host_cleanup(host_cleanup_errors)
    return result


def flash_uds_dh(
    context: DHPhaseContext, runtime: NativeRuntime2026, gateway: DHGateway2026
) -> dict:
    """DHUDS16a0/P5DHUDS16d0: source-selected archives, counters and checks."""
    if (
        not isinstance(context, DHPhaseContext)
        or context.identity.module_name
        not in ("TCUWCanDHUDSFlashWriter.dll", "TCUWP5CanDHUDSFlashWriter.dll")
        or not isinstance(context.selection, NativeParameterBinding2026)
        or gateway.runtime is not runtime
        or gateway.selection is not context.selection
    ):
        raise ValueError("Actual native DHUDS writer binding required")
    context.__post_init__()
    state, selection = context.state, context.selection
    notification = state.notification
    phase5 = context.identity.module_name == "TCUWP5CanDHUDSFlashWriter.dll"
    cpu = state.global_cpu_index
    check_type = selection.parameter.long("FalsificationCheckType") or 0
    request, response = (
        b"\0\0" + context.addresses[0].request[:2],
        b"\0\0" + context.addresses[0].response[:2],
    )
    previous, previous_send = (
        runtime.call("get_timeout"),
        runtime.call("get_send_timeout"),
    )
    if any(
        type(v) is not int or not 0 <= v <= 0xFFFFFFFF
        for v in (previous, previous_send)
    ):
        raise ValueError("Native prior unsigned timeout values required")
    result: dict = {
        "state": "writing",
        "family": context.identity.family,
        "physical_status": "PHYSICAL_UNCONFIRMED",
        "programming_completed": False,
        "native_return": False,
        "transferred_bytes": 0,
        "cleanup_errors": [],
    }
    identifier = None
    host_cleanup_errors: list[BaseException] = []

    def call(payload, expected, minimum, error, pending=99, *, ordinary=False):
        if phase5:
            return gateway.diag.call(
                request,
                response,
                payload,
                expected,
                minimum=minimum,
                error_code=error,
                phase5=True,
                pending_limit=180,
                busy_limit=5530,
                send_tester_present=True,
            )
        if ordinary:
            return gateway._call(request, response, payload, expected, minimum, error)
        return dh_sync_exchange(
            runtime,
            request,
            response,
            payload,
            expected,
            minimum=minimum,
            error_code=error,
            pending_limit=pending,
            busy_limit=255,
        )

    def address(text):
        if (
            len(text) > 8
            or len(text) % 2
            or any(c not in "0123456789abcdefABCDEF" for c in text)
        ):
            raise ValueError("Native four-byte DHUDS address hex required")
        return bytes.fromhex(text).rjust(4, b"\0")

    def verify(flash_code=False, *, force_crc=False):
        if force_crc or check_type == 1:
            call(
                bytes.fromhex("3101020100"), bytes.fromhex("7101020100"), 5, 0x3F3, 280
            )
        elif check_type == 2:
            cmac = native2026_cpu_cmac(
                state.metadata, flash_code=flash_code, cpu_index=cpu
            )
            if len(cmac) > 512:
                raise ValueError("Native CBytes CMAC capacity exceeded")
            call(
                bytes.fromhex("31010202") + cmac[:20].ljust(20, b"\0"),
                bytes.fromhex("7101020200"),
                5,
                0x3F4,
            )
        else:
            raise CommonResponseError(9999)

    def program(start, data, size, phase):
        if not isinstance(data, bytes) or not 0 <= size <= min(
            len(data), 64 * 1024 * 1024
        ):
            raise ValueError("Actual contiguous native DHUDS archive range required")
        reply = call(
            b"\x34\x01\x44" + start + size.to_bytes(4, "big"),
            b"\x74\x20",
            4,
            0x1A,
            ordinary=True,
        )
        subtract = (
            1
            if phase5
            else (
                selection.parameter.long("ValueSubtractedFromMaxNumberBlockLength") or 1
            )
        )
        maximum = (int.from_bytes(reply[2:4], "big") - subtract) & 0xFFFFFFFF
        if not 0 < maximum <= (4122 if phase5 else 4114):
            raise ValueError("Native DHUDS block length exceeds host message bounds")
        offset, sequence = 0, 0
        while offset < size:
            count = min(maximum, size - offset)
            sequence = (sequence + 1) & 255
            call(
                b"\x36" + bytes((sequence,)) + data[offset : offset + count],
                b"\x76" + bytes((sequence,)),
                2,
                0x22,
            )
            offset += count
            result["transferred_bytes"] += count
            if phase == 1:
                state.record_uds_transfer(count)
            runtime.call(
                "notify_progress_count",
                cpu_index=cpu,
                transferred_bytes=state.transferred_bytes[cpu],
            )
            runtime.call(
                "notify_progress_percent", cpu_index=cpu, progress=state.progress[cpu]
            )
        call(b"\x37", b"\x77", 1, 0x1C, ordinary=True)

    def erase(start, size):
        call(
            bytes.fromhex("3101ff0044") + start + size,
            bytes.fromhex("7101ff0000"),
            5,
            1001,
        )

    try:
        _require_dh_caller_channel(runtime)
        runtime.call("set_timeout", milliseconds=1000)
        runtime.call("set_send_timeout", milliseconds=10000)
        identifier = gateway.diag.start_filter(request, response)
        if cpu == 0 or state.native_context_964:
            first = native2026_metadata_for_cpu(state.metadata, 0)
            archive = native2026_archive(first, flash_code=True)
            program(
                address(selection.value("FlashCodeStartAddress")),
                archive.data or b"",
                archive.length,
                0,
            )
            verify(True)
        notification.assign(True)
        runtime.call("notify_programming_active", active=True)
        files = state.metadata.cpu.files if state.metadata.cpu is not None else ()
        multi = (
            not phase5
            and cpu == 0
            and state.metadata.format_version == 4
            and bool(files)
        )
        if multi:
            starts, sizes = (
                selection.lines("StartAddress"),
                selection.lines("LogicalBlockMemorySize"),
            )
            if len(starts) != 4 or len(sizes) != 4:
                raise CommonResponseError(9999)
            archives = [
                native2026_archive(state.metadata, file_index=i)
                for i in range(len(files))
            ]
            lengths = [
                archives[0].flash_size - sum(a.flash_size for a in archives[1:])
            ] + [a.flash_size for a in archives[1:]]
            state.resume_divided_image_count()
            while state.divided_image_index < len(files):
                index = state.divided_image_index
                state.notify_divided_image()
                slot = files[index].index - 1
                start = address(starts[slot])
                erase(start, address(sizes[slot]))
                program(start, archives[index].data or b"", lengths[index], 1)
                verify(force_crc=True)
                state.advance_divided_image(index)
            state.reset_divided_image()
            state.notify_divided_image()
        else:
            start = address(selection.value("StartAddress"))
            erase(start, address(selection.value("LogicalBlockMemorySize")))
            archive = native2026_archive(state.metadata)
            program(start, archive.data or b"", archive.flash_size, 1)
            verify()
        count = native2026_cpu_count(state.metadata)
        if cpu + 1 == count:
            call(bytes.fromhex("3101ff01"), bytes.fromhex("7101ff0100"), 5, 0x3F5)
            resume_communication(runtime)
            call(
                b"\x11\x01",
                b"\x51\x01" if phase5 else b"\x51",
                2 if phase5 else 1,
                0x18,
                ordinary=True,
            )
            wait = selection.parameter.long("WaitTimeAfterECUReset") or 0
            if wait:
                runtime.call("wait", milliseconds=wait)
            change_phase5_session(runtime)
            if state.central_gateway_type == 2:
                gateway.end_two_cpu_sessions()
            elif (
                selection.parameter.boolean("FlagToNonChangeReprogGWModeProcess")
                is not True
            ):
                gateway.end_reprogramming_mode(1020)
            if runtime.owns_resource("stop_sync_periodic"):
                runtime.release("stop_sync_periodic")
            else:
                runtime.call("stop_sync_periodic")
        if cpu + 1 < count:
            runtime.call("notify_cpu_type_change", cpu_index=cpu + 1)
        notification.assign(False)
        runtime.call("notify_programming_active", active=False)
        result.update(state="writer_completed", native_return=True)
    except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - native EH continuation and host compensation
        _raise_if_host_fault(exc)
        native = is_native_exception2026(exc)
        result.update(
            state="failed" if native else "cancelled", error=type(exc).__name__
        )
        if not native:
            result["native_return"] = None
        _record_dh_error(state, exc, None)
        try:
            if runtime.owns_resource("stop_sync_periodic"):
                runtime.release("stop_sync_periodic")
            else:
                runtime.call("stop_sync_periodic", cleanup=True)
            if native:
                state.reset_dh_count()
                runtime.call(
                    "notify_progress_count",
                    cleanup=True,
                    cpu_index=cpu,
                    transferred_bytes=0,
                )
                state.reset_dh_progress()
                runtime.call(
                    "notify_progress_percent", cleanup=True, cpu_index=cpu, progress=0
                )
        except (Exception, KeyboardInterrupt) as cleanup:  # noqa: BLE001 - preserve primary and finish compensation
            host_cleanup_errors.append(cleanup)
            result["cleanup_errors"].append(type(cleanup).__name__)
        if native:
            active = bool(notification)
            state.record_native_error(2 if active else 1, state.primary_error)
            if not active:
                state.mark_flash_code_failed()
            result.update(
                native_error_kind=state.error_kind,
                native_primary_error=state.primary_error,
                native_passthru_error=state.passthru_error,
            )
    finally:
        for operation, values in (
            ("stop_filter", {"identifier": identifier})
            if identifier is not None
            else ("", {}),
            ("set_timeout", {"milliseconds": previous}),
            ("set_send_timeout", {"milliseconds": previous_send}),
        ):
            if operation:
                try:
                    if operation == "stop_filter":
                        runtime.release(operation, **values)
                    else:
                        runtime.call(operation, cleanup=True, **values)
                except (Exception, KeyboardInterrupt) as cleanup:  # noqa: BLE001 - attempt each resource restoration
                    host_cleanup_errors.append(cleanup)
                    result["cleanup_errors"].append(type(cleanup).__name__)
                    if operation == "stop_filter" and is_native_exception2026(cleanup):
                        continue  # Native empty Catch_All preserves the saved business BOOL.
                    result.update(state="failed", native_return=None)
        _raise_host_cleanup(host_cleanup_errors)
    _raise_host_cleanup(host_cleanup_errors)
    return result


def _usb_recovery_needs_programming(context, runtime, gateway, current_request):
    """USB16e0: selected73c target match or changed59c nonempty software count."""
    worker = context.state.engine.worker
    if worker.runtime is not runtime:
        raise ValueError("USB recovery worker must own the writer runtime")
    prior = worker.usb_recovery_context()
    request, response = replace_can_ids(
        b"\0\0", b"\0\0", context.selection.value("CanIDForGetCID")
    )
    request, response = request.rjust(4, b"\0"), response.rjust(4, b"\0")
    identifier = None
    try:
        if request != current_request:
            identifier = gateway.diag.start_filter(request, response)

        def exchange(_ecu, payload):
            return gateway.diag.call(
                request,
                response,
                payload,
                b"\x5a\x88" + payload[2:3],
                minimum=3,
                error_code=3,
                pending_limit=99,
                busy_limit=255,
                send_tester_present=False,
            )

        _, values = get_software_info(NativeProgrammingChannel(exchange, "DH"))
        return (
            prior.target_calibration in values
            or sum(bool(v) for v in values) != prior.prior_software_count
        )
    finally:
        if identifier is not None:
            pending_error = sys.exception()
            try:
                runtime.release("stop_filter", identifier=identifier)
            except (Exception, KeyboardInterrupt) as error:
                if not is_native_exception2026(error):
                    if pending_error is None:
                        raise
                    pending_error.add_note(
                        "USB recovery filter cleanup: " + type(error).__name__
                    )


def flash_usb_dh(
    context: DHPhaseContext, runtime: NativeRuntime2026, gateway: DHGateway2026
) -> dict:
    """USBFlash1300: ECU-owned USB routines; notification handler is suspended."""
    if (
        not isinstance(context, DHPhaseContext)
        or context.identity.module_name != "TCUWCanDHUSBReproFlashWriter.dll"
        or not isinstance(context.selection, NativeParameterBinding2026)
        or gateway.runtime is not runtime
        or gateway.selection is not context.selection
    ):
        raise ValueError("Actual native DH USB writer binding required")
    context.__post_init__()
    state = context.state
    notification = state.notification
    request, response = (
        b"\0\0" + context.addresses[0].request[:2],
        b"\0\0" + context.addresses[0].response[:2],
    )
    previous, previous_send = (
        runtime.call("get_timeout"),
        runtime.call("get_send_timeout"),
    )
    if any(
        type(v) is not int or not 0 <= v <= 0xFFFFFFFF
        for v in (previous, previous_send)
    ):
        raise ValueError("Native prior unsigned timeout values required")
    identifier, suspended = None, False
    host_cleanup_errors: list[BaseException] = []
    result = {
        "state": "writing",
        "family": context.identity.family,
        "physical_status": "PHYSICAL_UNCONFIRMED",
        "programming_completed": False,
        "native_return": False,
        "cleanup_errors": [],
    }
    try:
        _require_dh_caller_channel(runtime)
        runtime.call("set_timeout", milliseconds=1000)
        runtime.call("set_send_timeout", milliseconds=10000)
        notification.disable_event_handler()
        suspended = True
        state.reset_usb_progress()
        runtime.call("notify_progress_percent", cpu_index=0, progress=0)
        identifier = gateway.diag.start_filter(request, response)
        notification.assign(True)
        runtime.call("notify_programming_active", active=True)
        if not state.native_context_964 or _usb_recovery_needs_programming(
            context, runtime, gateway, request
        ):
            for routine, code in ((9, 0x40E), (10, 0x20)):
                dh_sync_exchange(
                    runtime,
                    request,
                    response,
                    bytes((0x31, 1, 3, routine)),
                    bytes((0x71, 1, 3, routine)),
                    minimum=4,
                    error_code=code,
                    pending_limit=0x104,
                    busy_limit=255,
                )
            gateway._call(request, response, b"\x11\x01", b"\x51", 1, 0x18)
            dh_sync_exchange(
                runtime,
                request,
                response,
                b"\x3e\x01",
                b"\x7e",
                minimum=1,
                error_code=0x3EE,
                pending_limit=100,
                busy_limit=255,
            )
            status = dh_sync_exchange(
                runtime,
                request,
                response,
                b"\x1a\xb1",
                b"\x5a\xb1",
                minimum=3,
                error_code=0x40F,
                pending_limit=99,
                busy_limit=255,
            )
            if status[2] != 0:
                raise CommonResponseError(0x40F, status)
        change_phase5_session(runtime)
        gateway.end_two_cpu_sessions()
        if runtime.owns_resource("stop_sync_periodic"):
            runtime.release("stop_sync_periodic")
        else:
            runtime.call("stop_sync_periodic")
        notification.assign(False)
        runtime.call("notify_programming_active", active=False)
        state.set_native_percentage(0, 100)
        runtime.call("notify_progress_percent", cpu_index=0, progress=100)
        result["native_return"] = True
        result["state"] = "writer_completed"
    except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - source native catch; host faults propagate
        _raise_if_host_fault(exc)
        result["state"] = (
            "cancelled"
            if isinstance(exc, (InterruptedError, KeyboardInterrupt))
            else "failed"
        )
        if result["state"] == "cancelled":
            result["native_return"] = None
        result["error"] = type(exc).__name__
        native = is_native_exception2026(exc)
        if native:
            result.update(_record_dh_error(state, exc, None))
        try:
            if runtime.owns_resource("stop_sync_periodic"):
                runtime.release("stop_sync_periodic")
            else:
                runtime.call("stop_sync_periodic", cleanup=True)
            if native:
                state.reset_dh_count()
                runtime.call(
                    "notify_progress_count",
                    cleanup=True,
                    cpu_index=state.global_cpu_index,
                    transferred_bytes=0,
                )
                state.reset_dh_progress()
                runtime.call(
                    "notify_progress_percent",
                    cleanup=True,
                    cpu_index=state.global_cpu_index,
                    progress=0,
                )
        except (Exception, KeyboardInterrupt) as cleanup:  # noqa: BLE001 - preserve primary native fault
            host_cleanup_errors.append(cleanup)
            result["cleanup_errors"].append(type(cleanup).__name__)
        if native:
            state.record_native_error(
                2 if bool(notification) else 1, state.primary_error
            )
            result.update(
                native_error_kind=state.error_kind,
                native_primary_error=state.primary_error,
                native_passthru_error=state.passthru_error,
            )
    finally:
        for operation, values in (
            ("stop_filter", {"identifier": identifier})
            if identifier is not None
            else ("", {}),
            ("enable_notification", {}) if suspended else ("", {}),
            ("set_timeout", {"milliseconds": previous}),
            ("set_send_timeout", {"milliseconds": previous_send}),
        ):
            if operation:
                try:
                    if operation == "stop_filter":
                        runtime.release(operation, **values)
                    elif operation == "enable_notification":
                        notification.enable_event_handler()
                    else:
                        runtime.call(operation, cleanup=True, **values)
                except (Exception, KeyboardInterrupt) as cleanup:  # noqa: BLE001 - attempt every resource compensation
                    host_cleanup_errors.append(cleanup)
                    result["cleanup_errors"].append(type(cleanup).__name__)
                    if operation == "stop_filter" and is_native_exception2026(cleanup):
                        continue  # Source163c→1642 preserves the saved Boolean.
                    result["native_return"] = None
                    result["state"] = "failed"
        _raise_host_cleanup(host_cleanup_errors)
    _raise_host_cleanup(host_cleanup_errors)
    return result


_DH_BIND_TOKEN = object()


@dataclass(frozen=True)
class DHExecutionContext:
    """Canonical2026 binding; legacy catalog fixtures do not enter this path."""

    native: DHGetterContext | DHStatefulGetterContext | DHPhaseContext
    selection: NativeParameterBinding2026 = field(repr=False)
    gateway_identity: NativeModuleIdentity | None = None
    secret_info: SecretInfoClient | None = field(default=None, repr=False)
    _proof: object = field(default=None, repr=False)
    mode: str = "normal"
    retry_prepare_module: bytes | None = field(default=None, repr=False)
    engine_state: DHControllerState2026 | None = field(default=None, repr=False)

    def __post_init__(self):
        if (
            self._proof is not _DH_BIND_TOKEN
            or not isinstance(self.selection, NativeParameterBinding2026)
            or not isinstance(
                self.native, (DHGetterContext, DHStatefulGetterContext, DHPhaseContext)
            )
            or not isinstance(self.engine_state, DHControllerState2026)
        ):
            raise ValueError(
                "DH execution context must originate from actual native binding"
            )
        if (
            self.mode not in ("normal", "recovery")
            or self.mode == "recovery"
            and not isinstance(self.retry_prepare_module, bytes)
        ):
            raise ValueError("Native recovery dependency binding required")


def bind_native_context(
    container: CalibrationContainer,
    node: int,
    observed_cids: tuple[str, ...],
    selection: NativeParameterBinding2026,
    identity: NativeModuleIdentity,
    attachments: Mapping[str, bytes],
    observations: Mapping,
) -> DHExecutionContext:
    """Join actual31 parameter row,47 CUW metadata,48 selectedCPU addresses."""
    if (
        not isinstance(selection, NativeParameterBinding2026)
        or not isinstance(identity, NativeModuleIdentity)
        or not isinstance(attachments, Mapping)
        or not isinstance(observations, Mapping)
    ):
        raise TypeError(
            "Actual2026 parameter/module binding and native observations required"
        )
    if set(attachments) - {
        "selected_module",
        "dh_utils_module",
        "secret_info_module",
        "cuw_module",
        "retry_prepare_module",
    } or set(observations) - {
        "cpu_index",
        "stage",
        "dh_state",
        "previous_addresses",
        "response_canids",
        "module_version",
        "operation",
    }:
        raise ValueError(
            "DH native binding rejects manual geometry and undeclared overrides"
        )
    if (
        "selected_module" not in attachments
        or any(not isinstance(value, bytes) for value in attachments.values())
        or sum(map(len, attachments.values())) > 64 * 1024 * 1024
    ):
        raise ValueError("Exact immutable selected native module bytes required")
    cpu_index = observations.get("cpu_index", 0)
    mode = "recovery" if observations.get("operation") == "recovery" else "normal"
    if observations.get("operation", selection.operation) not in (
        selection.operation,
        "recovery",
    ):
        raise ValueError("Unsupported native DH execution operation")
    selection = selection.validate_against(
        container, operation=selection.operation, node=node, cpu_index=cpu_index
    )
    if observations.get("stage", selection.operation) != selection.operation:
        raise ValueError("Native requested DH stage differs from selected row")
    version = observations.get("module_version")
    dispatch = selection.dispatch(
        {identity.module_name: attachments["selected_module"]},
        module_versions=None if version is None else {identity.module_name: version},
    )
    if (
        dispatch["identity"] != identity
        or selection.module_name != identity.module_name
    ):
        raise ValueError(
            "Selected actual2026 DH module bytes differ from inspected identity"
        )
    resolver = communication_addresses_from_parameter(
        None if selection.operation == "get_cid" else container,
        selection.parameter,
        response_canids=observations.get("response_canids"),
        history=list(observations.get("previous_addresses", ())),
    )
    valid, native_addresses = resolver.resolve(
        selection.selector_functions,
        cids=observed_cids,
        location_id=native2026_location_id(
            selection.metadata, native2026_global_cpu_index(selection.metadata)
        )
        if selection.metadata.cpus
        else None,
    )
    addresses = tuple(
        Address(value.request, value.response, value.extended)
        for value in native_addresses
    )
    if identity.module_name == "TCUWP5CanDHVehicleInfoCIDGetter.dll":
        addresses, valid = (Address(b"\x07\xdf", b"\x07\xe8"),), True
    if not valid or not addresses:
        raise ValueError("Native2026 DH communication-address selector returned false")
    sources = ((selection.source_name, selection.source_sha256),)

    def flag(name):
        value = selection.parameter.boolean(name)
        return False if value is None else value

    def decimal(name, default=0):
        value = selection.parameter.long(name)
        return default if value is None else value

    state = observations.get("dh_state")
    _dh_file_view(selection, state)
    assert isinstance(state, DHControllerState2026)
    if selection.operation == "get_cid":
        pid_text = selection.value("PIDForReadSoftMaskID") or "A7"
        if len(pid_text) != 2 or any(
            char not in "0123456789abcdefABCDEF" for char in pid_text
        ):
            raise ValueError("Native one-byte soft-mask PID hex text required")
        pid = int(pid_text, 16)
        combined = identity.module_name == "TCUWCanDHSoftwareIDAndSoftMaskIDGetter.dll"
        complement = (
            selection.value("ComplementCID").encode("latin1")
            if identity.module_name != "TCUWCanDHUDSSoftwareIDGetter.dll"
            and identity.module_name != "TCUWP5CanDHVehicleInfoCIDGetter.dll"
            else b""
        )
        classic = identity.module_name == "TCUWCanDHSoftwareIDGetter.dll"
        writable_mask = (
            identity.module_name == "TCUWCanDHWritableSoftMaskIDAndCIDGetter.dll"
        )
        getter = DHGetterContext(
            identity,
            addresses,
            decimal("ReceiveTimeoutBeforeGetCID"),
            sources,
            complement,
            pid,
            decimal("SoftMaskIDRespDataSize", 10 if combined else 0),
            flag("FlagToSURegulation") if classic else False,
            flag("FlagToVerifySoftMaskIDProcess") if classic else False,
        )
        if getter.verify_softmask or "Writable" in identity.module_name:
            if (
                not isinstance(state, DHControllerState2026)
                or state.metadata != selection.metadata
            ):
                raise ValueError("Actual loaded-engine DH getter state required")
            native = DHStatefulGetterContext(
                getter,
                state,
                flag("FlagToChangeSpecificServiceCertificationModeProcess")
                if writable_mask
                else False,
                decimal("WriteSoftwareIDRespType"),
            )
        else:
            native = getter
    elif selection.operation in ("prepare", "write"):
        _dh_file_view(selection, state)
        native = DHPhaseContext(
            identity, state, selection, addresses, sources, container, observed_cids
        )
    else:
        raise NotImplementedError("Owned native DH phase is not implemented")
    needs_gateway = (
        isinstance(native, DHPhaseContext)
        or isinstance(native, DHStatefulGetterContext)
        and native.specific_service
    )
    gateway_identity, secret_info = None, None
    if needs_gateway:
        if not {"dh_utils_module", "secret_info_module", "cuw_module"} <= set(
            attachments
        ):
            raise ValueError(
                "Exact native DHUtils/SecretInfo/CUW dependency bytes required"
            )
        gateway_identity = identify_native_module(
            hashlib.sha256(attachments["dh_utils_module"]).hexdigest(),
            "TCUWDHUtils.dll",
        )
        assert isinstance(state, DHControllerState2026)
        if hashlib.sha256(attachments["cuw_module"]).hexdigest() != state.engine_sha256:
            raise ValueError(
                "Native DH authorization caller differs from loaded engine"
            )
        secret_info = SecretInfoClient.from_native_modules(
            attachments["secret_info_module"], attachments["cuw_module"]
        )
    retry_module = attachments.get("retry_prepare_module")
    if mode == "recovery":
        if (
            identity.module_name
            not in (
                "TCUWCanDHFlashWriter.dll",
                "TCUWCanDHUDSFlashWriter.dll",
                "TCUWP5CanDHUDSFlashWriter.dll",
            )
            or "PrepareRetry" not in identity.callable_exports
            or retry_module is None
        ):
            raise ValueError("Native DH retry export/dependency unavailable")
        retry_name = {
            "TCUWCanDHFlashWriter.dll": "TCUWCanDHPrepareWriter.dll",
            "TCUWCanDHUDSFlashWriter.dll": "TCUWCanDHUDSPrepareWriter.dll",
            "TCUWP5CanDHUDSFlashWriter.dll": "TCUWP5CanDHUDSPrepareWriter.dll",
        }[identity.module_name]
        retry_identity = identify_native_module(
            hashlib.sha256(retry_module).hexdigest(), retry_name
        )
        if retry_identity.cuw_build != "2026":
            raise ValueError("Native DH retry dependency belongs to another build")
    return DHExecutionContext(
        native,
        selection,
        gateway_identity,
        secret_info,
        _proof=_DH_BIND_TOKEN,
        mode=mode,
        retry_prepare_module=retry_module,
        engine_state=state,
    )


def _execute_context(context: DHExecutionContext, runtime: NativeRuntime2026) -> dict:
    """Execute one concrete native client; primitives never choose business success."""
    if not isinstance(context, DHExecutionContext) or not isinstance(
        runtime, NativeRuntime2026
    ):
        raise TypeError("Canonical2026 DH execution binding and runtime required")
    context.__post_init__()
    gateway = None
    if context.gateway_identity is not None and context.secret_info is not None:
        gateway = DHGateway2026(
            runtime,
            context.selection,
            context.gateway_identity,
            context.secret_info,
            engine_state=context.engine_state,
        )
    native = context.native
    if isinstance(native, DHGetterContext):
        result = get_dh_cids(native, runtime)
        if "native_primary_error" in result:
            assert context.engine_state is not None
            context.engine_state.record_native_error(
                None,
                result["native_primary_error"],
                result.get("native_passthru_error"),
            )
            result["native_error_kind"] = context.engine_state.error_kind
            result["native_passthru_error"] = context.engine_state.passthru_error
        return result
    if isinstance(native, DHStatefulGetterContext):
        return get_stateful_dh_cids(native, runtime, gateway=gateway)
    if gateway is None:
        raise ValueError("Native DH phase gateway dependency binding absent")
    if context.mode == "recovery":
        assert context.retry_prepare_module is not None
        return prepare_retry_dh(native, runtime, gateway, context.retry_prepare_module)
    if native.identity.module_name == "TCUWCanDHPrepareWriter.dll":
        return prepare_dh(native, runtime, gateway)
    if native.identity.module_name == "TCUWCanDHFlashWriter.dll":
        return flash_dh(native, runtime, gateway)
    if native.identity.module_name == "TCUWCanDHGatewayPrepareWriter.dll":
        return prepare_gateway_dh(native, runtime, gateway)
    if native.identity.module_name in (
        "TCUWCanDHUDSPrepareWriter.dll",
        "TCUWP5CanDHUDSPrepareWriter.dll",
    ):
        return prepare_uds_dh(native, runtime, gateway)
    if native.identity.module_name in (
        "TCUWCanDHGatewayFlashWriter.dll",
        "TCUWCanDH19PFSURegGatewayFlashWriter.dll",
    ):
        return flash_gateway_dh(native, runtime, gateway)
    if native.identity.module_name == "TCUWCanDH19PFSURegGatewayPrepareWriter.dll":
        return prepare_19pf_gateway_dh(native, runtime, gateway)
    if native.identity.module_name == "TCUWCanDHMultiROMPrepareWriter.dll":
        return prepare_multirom_dh(native, runtime, gateway)
    if native.identity.module_name == "TCUWCanDHMultiROMFlashWriter.dll":
        return flash_multirom_dh(native, runtime, gateway)
    if native.identity.module_name in (
        "TCUWCanDHUDSFlashWriter.dll",
        "TCUWP5CanDHUDSFlashWriter.dll",
    ):
        return flash_uds_dh(native, runtime, gateway)
    if native.identity.module_name == "TCUWCanDHUSBReproFlashWriter.dll":
        return flash_usb_dh(native, runtime, gateway)
    raise NotImplementedError("Owned native DH phase is not implemented")


def execute_context(context: DHExecutionContext, runtime: NativeRuntime2026) -> dict:
    """Host faults propagate unchanged after every remaining resource is released."""
    borrowed_control = False
    if type(runtime) is NativeRuntime2026:
        from scripts.cuw_2026 import CUWEngine2026
        from scripts.programming_2026_common import (
            _NATIVE_CONTROL_RAW_EXECUTIONS_2026,
            ControlCommPhase2026,
            NativeControlExportTarget2026,
        )

        try:
            active = getattr(runtime._device_calls, "control_export", None)
            if type(active) is tuple and len(active) == 3:
                engine, controller, target = active
                if (
                    type(engine) is CUWEngine2026
                    and type(controller) is ControlCommPhase2026
                    and type(target) is NativeControlExportTarget2026
                    and controller.runtime is runtime
                    and engine.worker.controller is controller
                    and engine.worker.runtime is runtime
                    and engine._controller_execution is controller
                    and engine._controller_export_target2026 is target
                ):
                    token = controller._native_control_raw_execution2026
                    control_context = controller.native_control_context2026(engine)
                    borrowed_control = (
                        token is not None
                        and _NATIVE_CONTROL_RAW_EXECUTIONS_2026.get(id(token))
                        == (token, engine, controller, control_context)
                        and target.validate(engine, controller) is None
                    )
        except (AttributeError, RuntimeError, TypeError, ValueError):
            borrowed_control = False
    try:
        return _execute_context(context, runtime)
    except BaseException:
        if isinstance(runtime, NativeRuntime2026) and not borrowed_control:
            runtime.close()
        raise
