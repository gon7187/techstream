"""Injected Toyota command execution; no device discovery or I/O on import.

Selected command bytes and status rules come from the vehicle database. Empty
requests to exchange mean receive-only continuation, never retransmission.
"""

from __future__ import annotations

import math
import struct
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Literal, Protocol, cast

if TYPE_CHECKING:
    from scripts.data_monitor import MonitorSignalMetadata
    from scripts.drive_recorder import NativeVimClient
    from scripts.freeze_p5 import P5FreezeState, P5SnapshotRequest
    from scripts.monitor_support import MonitorSupportCache
    from scripts.native_communication import NativeCommunication
    from scripts.profiles import SelectedFrame, VehicleProfile
    from scripts.signal_lsb import SignalLSB
    from scripts.toyota_workflows import ToyotaWorkflows

from scripts.signal_conversion import (
    affine,
    extract_bits,
    signal_metadata,
)
from scripts.signal_display import Pattern, render_signal
from scripts.support import correspondence_rows
from scripts.toyota import (
    INVALID_RECORD,
    INVALID_REPLY,
    SHORT_REPLY,
    CommandFrame,
    ToyotaCodecError,
    data_list_request,
    freeze_payload_p3,
    freeze_request_p3,
    freeze_request_p5,
    mask_comm_error,
    parse_kwp_dtc_reply,
    vin_payload_can,
)

Exchange = Callable[[str, bytes], bytes]
CountFamily = Literal["plain", "p4", "ac", "tt", "vgrs", "os_eng", "carb"]


@dataclass(frozen=True)
class NativeFrameSend:
    """Literal CCommFrameCtrl seven-argument send; no receive is implied.

    Parameter names retain their ABI positions: their meanings depend on the
    calling native helper. Ordinary SendInt/SendIntNoInit take a byte length;
    SendIntNoInitNoSession/SendIntExtDualMon/SendIntExt/SendIntNoInitExt
    take a ushort length.
    """

    operation: Literal[
        "SendInt",
        "SendIntNoInit",
        "SendIntNoInitNoSession",
        "SendIntExtDualMon",
        "SendIntExt",
        "SendIntNoInitExt",
    ]
    command_id: int
    request: bytes | None
    parameter4: int
    parameter5: int
    parameter6: int = 0
    parameter7: int = 1

    def __post_init__(self) -> None:
        if self.operation not in (
            "SendInt",
            "SendIntNoInit",
            "SendIntNoInitNoSession",
            "SendIntExtDualMon",
            "SendIntExt",
            "SendIntNoInitExt",
        ):
            raise ValueError("Unsupported native send primitive")
        if self.request is not None and not isinstance(self.request, bytes):
            raise TypeError("Native send request must be bytes or an explicit NULL")
        maximum = 255 if self.operation in ("SendInt", "SendIntNoInit") else 65535
        if self.request is not None and len(self.request) > maximum:
            raise ValueError("Native send length outside ABI bounds")
        for value, lower, upper in (
            (self.command_id, 0, 0xFFFFFFFF),
            (self.parameter4, 0, 0xFFFFFFFF),
            (self.parameter5, 0, 0xFFFF),
            (self.parameter6, -0x80000000, 0x7FFFFFFF),
            (self.parameter7, -0x80000000, 0x7FFFFFFF),
        ):
            if type(value) is not int or not lower <= value <= upper:
                raise ValueError("Native send argument outside ABI bounds")

    @property
    def arguments(self) -> tuple[int, bytes | None, int, int, int, int, int]:
        return (
            self.command_id,
            self.request,
            len(self.request) if self.request is not None else 0,
            self.parameter4,
            self.parameter5,
            self.parameter6,
            self.parameter7,
        )


NativeSend = Callable[[str, NativeFrameSend], int]


class FunctionCache(Protocol):
    """Native CFuncInfoCache lookup over an observed selected ECU tree."""

    def function(
        self, group: int, child: int = 0, leaf: int = 0
    ) -> tuple[bool, int]: ...


def _profile_frames(
    profile: VehicleProfile, function_id: int
) -> tuple[SelectedFrame, ...]:
    """Map exact native DB112 absence, preserving other descriptor failures."""
    if type(function_id) is not int or not 0 <= function_id <= 65535:
        raise ValueError("Function ID must be u16")
    management = profile.catalog.management
    if 18 not in management.sections:
        raise ToyotaCodecError("Function communication table absent", 0xA0030107)
    functions = correspondence_rows(management, 18, profile.exception_ids)
    if not any(
        struct.unpack_from("<HH", row) == (profile.category, function_id)
        for row in functions
    ):
        raise ToyotaCodecError("Selected native function group empty", 0xC0040101)
    return profile.frame_records(function_id)


class SessionError(RuntimeError):
    """Host policy failure, distinct from an original native result code."""


class Cancelled(SessionError):
    pass


class NativeStatus(ToyotaCodecError):
    """Transport adapter raises this for native status, never wire bytes."""

    def __init__(self, code: int, reply: bytes = b""):
        if type(code) is not int or not 0 < code <= 0xFFFFFFFF:
            raise ValueError("Native status must be a nonzero uint32")
        if not isinstance(reply, bytes):
            raise TypeError("Partial native reply must be bytes")
        self.reply = reply
        super().__init__(f"Native communication status 0x{code:08x}", code)


@dataclass(frozen=True)
class CommandSpec:
    frame: CommandFrame
    check: Literal["sid", "mask", "both", "raw", "p5_active"] = "sid"
    payload_offset: int = 0
    provenance: str = "selected-descriptor"
    extended: bool = False
    selected: SelectedFrame | None = None
    receive_capacity: int | None = None

    def __post_init__(self) -> None:
        if self.receive_capacity is not None and (
            type(self.receive_capacity) is not int
            or not 1 <= self.receive_capacity <= 65535
        ):
            raise ValueError("Native receive capacity must fit nonzero WORD")
        if self.check not in ("sid", "mask", "both", "raw", "p5_active"):
            raise ValueError("Unknown reply check")
        if type(self.payload_offset) is not int or self.payload_offset < 0:
            raise ValueError("Negative payload offset")
        if not self.frame.request:
            raise ToyotaCodecError("Empty selected request", INVALID_RECORD)
        if (
            self.check in ("sid", "both")
            and not self.extended
            and len(self.frame.request) > 255
        ):
            raise ToyotaCodecError(
                "Ordinary request exceeds byte length", INVALID_RECORD
            )
        if self.check in ("mask", "both") and len(self.frame.receive_check) < len(
            self.frame.receive_mask
        ):
            raise ToyotaCodecError("Selected mask lacks check bytes", INVALID_RECORD)

    def validate(self, reply: bytes) -> bytes:
        if self.check == "p5_active":
            active_reply_p5(self.frame.request, reply)
        if self.check in ("sid", "both"):
            if self.extended:
                if not 0 < len(reply) <= 0xFFFF:
                    raise ToyotaCodecError(
                        "Extended reply outside native bounds", SHORT_REPLY
                    )
                if reply[0] != self.frame.request[0] | 0x40:
                    raise ToyotaCodecError(
                        "Unexpected extended reply service", INVALID_REPLY
                    )
            else:
                self.frame.check_reply(reply)
        if self.check in ("mask", "both"):
            self.frame.check_mask(reply)
        if len(reply) < self.payload_offset:
            raise ToyotaCodecError("Reply lacks selected payload prefix", SHORT_REPLY)
        return reply[self.payload_offset :]


@dataclass(frozen=True)
class Limits:
    seconds: float = 10.0
    exchanges: int = 256

    def __post_init__(self) -> None:
        if not math.isfinite(self.seconds) or self.seconds <= 0:
            raise ValueError("Deadline must be finite and positive")
        if type(self.exchanges) is not int or self.exchanges <= 0:
            raise ValueError("Exchange limit must be positive")


@dataclass(frozen=True)
class StatusRule:
    diag_type: int
    mask: int
    expected: int

    def __post_init__(self) -> None:
        if type(self.diag_type) is not int or not 0 <= self.diag_type <= 0xFFFFFFFF:
            raise ValueError("Diagnostic type must fit uint32")
        if any(
            type(v) is not int or not 0 <= v <= 255 for v in (self.mask, self.expected)
        ):
            raise ValueError("Status mask/check must be bytes")

    @classmethod
    def from_record(cls, record: bytes, diag_type: int) -> StatusRule:
        """CDbDTCStatusMask row +8/+9 (CommandCommon RVA 0x7d0f1)."""
        if len(record) < 10:
            raise ToyotaCodecError("Truncated DTC status mask row", INVALID_RECORD)
        return cls(diag_type, record[8], record[9])


def dtc_status_rules_profile(
    profile: VehicleProfile, requested_types: int | None = None
) -> tuple[int, tuple[StatusRule, ...]]:
    """Common7CFB0/7D1A0 selected DB242 request mask and committed rules.

    A requested bitset is queried one bit at a time, low to high. The request
    mask combines EXPECTED bytes, not status masks; zero leaves the native
    cache count unwritten. None selects the separate all-records cache loader.
    """
    if requested_types is not None and (
        type(requested_types) is not int or not 0 <= requested_types <= 0xFFFFFFFF
    ):
        raise ValueError("Requested diagnostic types must fit uint32")
    rules: list[StatusRule] = []
    request_mask = 0
    if requested_types is None:
        if 66 not in profile.database.sections:
            raise ToyotaCodecError("Selected DTC status table absent", 0xA0030107)
        records = profile.records(66)
        if not records:
            raise ToyotaCodecError("No selected DTC status rows", 0xC0040101)
        for row in records:
            if len(row) != 12:
                raise ToyotaCodecError(
                    "Invalid selected DTC status row", INVALID_RECORD
                )
            rules.append(StatusRule.from_record(row, int.from_bytes(row[:4], "little")))
        return 0, tuple(rules)
    for index in range(32):
        bit = 1 << index
        if not requested_types & bit:
            continue
        for row in profile.dtc_status_records(bit):
            if len(row) != 12:
                raise ToyotaCodecError(
                    "Invalid selected DTC status row", INVALID_RECORD
                )
            rule = StatusRule.from_record(row, bit)
            request_mask |= rule.expected
            rules.append(rule)
    return request_mask, tuple(rules) if request_mask else ()


def diag_type(status: int, rules: Sequence[StatusRule]) -> int:
    if type(status) is not int or not 0 <= status <= 255:
        raise ValueError("Status must be a byte")
    result = 0
    for rule in rules:
        if status & rule.mask == rule.expected:
            result |= rule.diag_type
    return result


def parse_p5_dtcs(reply: bytes, rules: Sequence[StatusRule]) -> list[dict[str, int]]:
    """GetDiagCodeP5_DT 0x2910: 3-prefix then (DTC24,status) groups.

    Status availability is reply[2]; zero statuses/types are omitted. Duplicate
    DTCs merge both type and status using OR (CommandCommon 0x7ca84).
    Native integer division ignores incomplete trailing groups.
    """
    if len(reply) < 3:
        raise ToyotaCodecError("Truncated P5 DTC prefix", SHORT_REPLY)
    groups = (len(reply) - 3) // 4
    if not groups:
        return []
    if not rules:
        raise SessionError("P5 DTC status rules were not selected")
    available = 0
    for rule in rules:
        available |= reply[2] & rule.mask
    if not available:
        raise ToyotaCodecError("No selected DTC status available", INVALID_RECORD)
    values: dict[int, dict[str, int]] = {}
    for pos in range(3, 3 + groups * 4, 4):
        code = int.from_bytes(reply[pos : pos + 3], "big")
        status = reply[pos + 3]
        kind = diag_type(status, rules) if status else 0
        if kind:
            entry = values.setdefault(code, {"code": code, "status": 0, "diag_type": 0})
            entry["status"] |= status
            entry["diag_type"] |= kind
    return list(values.values())


def scale_signal(
    payload: bytes,
    freeze: bytes,
    physical: bytes,
    *,
    patterns: Sequence[Pattern] = (),
    minimum_raw: int | None = None,
    maximum_raw: int | None = None,
    extended: Sequence[tuple[int, int, int]] = (),
    raw_words: tuple[int, int] | None = None,
) -> dict[str, object]:
    """Selected Freeze/PhyData extraction and recovered native display semantics."""
    metadata = signal_metadata(freeze, physical)
    start, end = metadata["start_bit"], metadata["end_bit"]
    raw = extract_bits(payload, start, end)
    result = render_signal(
        raw,
        selector=metadata["selector"],
        sign_mode=metadata["sign_mode"],
        bits=end - start + 1,
        multiplier=metadata["multiplier"],
        divisor=metadata["divisor"],
        offset=metadata["offset"],
        precision=metadata["decimal_precision"],
        patterns=patterns,
        minimum_raw=minimum_raw,
        maximum_raw=maximum_raw,
        extended=extended,
        raw_words=raw_words,
    )
    result["unit_key"] = metadata["unit_key"]
    return result


def format_dtc(code: int, *, bits: Literal[16, 24] = 16) -> str:
    """Native GetStrDiagCode0x76c40 / DTCValue2DTCDisp0x7c860 fallback."""
    if bits not in (16, 24) or type(code) is not int or not 0 <= code < 1 << bits:
        raise ValueError("Native DTC must fit selected16/24-bit width")
    kind = code >> (bits - 2)
    return "PCBU"[kind] + f"{code & ((1 << (bits - 2)) - 1):0{4 if bits == 16 else 6}X}"


def parse_psa_dtcs(
    reply: bytes, diagnostic_type: int, *, no_status: bool = False
) -> list[dict[str, int]]:
    """Common PSA0x7d380/V2 0x7e5e0, NoStatus0x7ead0 selected reply layout.

    Prefix SID,count; DTC16/status triples (or DTC16 pairs for NoStatus).
    Diagnostic type1 omits status>0x28. Native stores floored group count in a
    byte, and ignores trailing incomplete bytes; retain both behaviors.
    """
    if type(diagnostic_type) is not int or not 0 <= diagnostic_type <= 0xFFFFFFFF:
        raise ValueError("Diagnostic type must fit uint32")
    if not 2 <= len(reply) <= 4095:
        raise ToyotaCodecError("PSA response outside native buffer", SHORT_REPLY)
    if not reply[1]:
        return []
    width = 2 if no_status else 3
    count = ((len(reply) - 2) // width) & 255
    result: list[dict[str, int]] = []
    for index in range(count):
        offset = 2 + index * width
        code = int.from_bytes(reply[offset : offset + 2], "big")
        if not code:
            break
        if no_status:
            result.append({"code": code})
        else:
            status = reply[offset + 2]
            if diagnostic_type != 1 or status <= 0x28:
                result.append({"code": code, "status": status})
    return result


def parse_psa_audio_dtcs(reply: bytes, diagnostic_type: int) -> list[int]:
    """PSA Audio0x7e140 DTC16 pairs; type1/2 select high nibble0x10/0x20."""
    if type(diagnostic_type) is not int or not 0 <= diagnostic_type <= 0xFFFFFFFF:
        raise ValueError("Diagnostic type must fit uint32")
    if not 2 <= len(reply) <= 4095:
        raise ToyotaCodecError("PSA Audio reply outside native buffer", SHORT_REPLY)
    count = ((len(reply) - 2) // 2) & 255
    if not count:
        raise ToyotaCodecError("PSA Audio reply has no code pairs", INVALID_REPLY)
    result: list[int] = []
    for index in range(count):
        offset = 2 + index * 2
        if diagnostic_type in (1, 2) and reply[offset] & 0xF0 != diagnostic_type << 4:
            continue
        code = int.from_bytes(reply[offset : offset + 2], "big")
        result.append(code)
    return result


def parse_psa_add_ht_dtcs(reply: bytes) -> list[int]:
    """PSA AddHt0x7dbb0: DTC16 at offset2, stride5, floor((len+1)/5)."""
    if not 2 <= len(reply) <= 4095:
        raise ToyotaCodecError("PSA AddHt response outside buffer", SHORT_REPLY)
    count = ((len(reply) + 1) // 5) & 255
    result: list[int] = []
    for index in range(count):
        offset = 2 + index * 5
        code = int.from_bytes(reply[offset : offset + 2], "big")
        if code:
            result.append(code)
    return result


def normalize_sienna_dtcs(reply: bytes) -> bytes:
    """Native Sienna Door removes two framing bytes from each six after byte 5."""
    if not 2 <= len(reply) <= 255:
        raise ToyotaCodecError("Sienna DTC response outside buffer", SHORT_REPLY)
    if len(reply) <= 6:
        return reply
    return reply[:5] + bytes(
        value for index, value in enumerate(reply[5:]) if index % 6 not in (0, 1)
    )


def parse_dk_iso_freeze(
    reply: bytes, freeze_lengths: Mapping[int, int], pid_lengths: Mapping[int, int]
) -> dict[int, bytes]:
    """DK ISO freeze14e0: first byte header, then PID/selected-length groups."""
    if not 2 <= len(reply) <= 255:
        raise ToyotaCodecError("DK ISO freeze reply lacks groups", SHORT_REPLY)
    result: dict[int, bytes] = {}
    cursor = 1
    while cursor < len(reply):
        pid = reply[cursor]
        cursor += 1
        length = (
            freeze_lengths.get(pid) if pid in freeze_lengths else pid_lengths.get(pid)
        )
        if length is None:
            raise ToyotaCodecError("DK ISO PID definition is absent", 0xC0040101)
        if type(length) is not int or not 1 <= length <= 255:
            raise ToyotaCodecError(
                "DK ISO PID definition has zero/invalid length", 0xC0050102
            )
        if cursor + length > len(reply):
            raise ToyotaCodecError("DK ISO PID group is truncated", SHORT_REPLY)
        # Native map appends duplicates; GetData searches from its head.
        result.setdefault(pid, reply[cursor : cursor + length])
        cursor += length
    return result


def dk_iso_freeze_value(freeze: bytes, data: Mapping[int, bytes]) -> int:
    """Common24c40 map lookup and selected Freeze WORD62/64 extraction."""
    if len(freeze) != 84:
        raise ToyotaCodecError("Invalid DK ISO Freeze record", INVALID_RECORD)
    payload = data.get(freeze[79])
    if payload is None:
        raise ToyotaCodecError("DK ISO selected PID data is absent", 0xC0040001)
    begin, end = struct.unpack_from("<HH", freeze, 62)
    if begin > end or end - begin >= 32 or end // 8 >= len(payload):
        raise ToyotaCodecError(
            "DK ISO selected PID bit range is unavailable", 0xC0040102
        )
    return extract_bits(payload, begin, end)


def parse_dk_iso_dtcs(payload: bytes) -> list[int]:
    """CGetDiagCodeDkIso9141 0x7ba90 consumes first selected payload bytewise."""
    codes: list[int] = []
    for code in payload:
        if not code:
            break
        codes.append(code)
    return codes


def p5_data_id_samples(
    payload: bytes,
    monitor_records: Sequence[bytes],
    physical_records: Mapping[int, bytes],
    supported: Mapping[int, bool],
    *,
    patterns: Mapping[int, Sequence[Pattern]] | None = None,
) -> list[dict[str, object]]:
    """AnalyzeSingleDataId873b0 and SetSignalInfo842a0, selected DB23e rows.

    The profile resolves SSR-DID->PID and exceptions; support values come from
    the native support cache/CheckSupportPid. No unsupported PID is synthesized.
    """
    if not 1 <= len(payload) <= 255:
        raise ToyotaCodecError(
            "P5 data-ID payload must fit native byte length", INVALID_RECORD
        )
    result: list[dict[str, object]] = []
    seen: set[int] = set()
    for record in monitor_records:
        if len(record) < 60:
            raise ToyotaCodecError("P5 monitor record truncated", INVALID_RECORD)
        pid = struct.unpack_from("<H", record, 0x24)[0]
        if pid in seen:
            continue
        seen.add(pid)
        if not record[0x20] & 2:
            continue
        begin, end = struct.unpack_from("<HH", record, 0x2C)
        if begin > end or end - begin >= 32:
            raise ToyotaCodecError("P5 monitor bit range invalid", 0xC0040102)
        if end // 8 >= len(payload):
            continue  # native8776a skips a PID whose selected data is too short
        if pid not in supported:
            raise SessionError(f"P5 PID support not selected for {pid:#x}")
        if not supported[pid]:
            continue
        key = struct.unpack_from("<H", record, 0x2A)[0]
        physical = physical_records.get(key)
        if physical is None:
            raise SessionError(f"P5 physical record not selected for {key:#x}")
        if len(physical) != 24 or struct.unpack_from("<H", physical, 12)[0] != key:
            raise ToyotaCodecError(
                "P5 selected physical key/record invalid", INVALID_RECORD
            )
        multiplier, divisor, offset = struct.unpack_from("<iii", physical)
        pattern_key = struct.unpack_from("<H", record, 0x32)[0]
        raw = extract_bits(payload, begin, end)
        rendered = render_signal(
            raw,
            selector=record[0x3A],
            sign_mode=physical[20],
            bits=end - begin + 1,
            multiplier=multiplier,
            divisor=divisor,
            offset=offset,
            precision=physical[21],
            patterns=() if patterns is None else patterns.get(pattern_key, ()),
        )
        rendered.update(
            pid=pid,
            unit_key=struct.unpack_from("<H", physical, 14)[0],
            native_04=struct.unpack_from("<I", record, 4)[0],
            native_08=struct.unpack_from("<I", record, 8)[0],
            native_0c=struct.unpack_from("<I", record, 12)[0],
            native_10=struct.unpack_from("<I", record, 16)[0],
            native_3b=record[0x3B],
        )
        result.append(rendered)
    return result


def parse_p5_freeze(
    reply: bytes,
    data_lengths: Mapping[int, int],
    *,
    zero_count_until_end: bool = False,
    decode: Callable[[int, bytes], object] | None = None,
    subaru_snapshot: bool = False,
) -> dict[str, object]:
    """GetDiagCodeP5_DT stored FFD analyzer0x34a3: code/status + records/DIDs.

    Header6; record byte0x10/0x12 and DID count; each DID16 is followed by
    selected DB0x23d row+4 bytes. A zero DID count can mean reading selected items to end
    only when caller supplies the proven request-specific fallback decision.
    Unknown lengths/record kinds remain explicit failures, never guessed sizes.
    """
    if not 6 <= len(reply) <= 65535:
        raise ToyotaCodecError("P5 freeze reply lacks DTC/status header", SHORT_REPLY)
    for did, length in data_lengths.items():
        if (
            type(did) is not int
            or not 0 <= did <= 65535
            or type(length) is not int
            or not 1 <= length <= 255
        ):
            raise ValueError("Selected data-ID keys/lengths must fit native fields")
    records: list[dict[str, object]] = []
    ignored_tail = b""
    cursor = 6
    while cursor < len(reply):
        if cursor + 2 > len(reply):
            raise ToyotaCodecError("P5 freeze record header truncated", SHORT_REPLY)
        number, count = reply[cursor : cursor + 2]
        cursor += 2
        kind = (
            ffd_type(number, subaru=True)
            if subaru_snapshot
            else {0x10: 1, 0x12: 2}.get(number, 0)
        )
        if not kind:
            raise SessionError(f"Stored P5 FFD record family not selected: {number:#x}")
        items: list[dict[str, object]] = []
        item_index = 0
        while item_index < count or (
            not count and zero_count_until_end and cursor < len(reply)
        ):
            item_index += 1
            if cursor + 2 > len(reply):
                raise ToyotaCodecError("P5 freeze data-ID truncated", SHORT_REPLY)
            did = int.from_bytes(reply[cursor : cursor + 2], "big")
            cursor += 2
            if did not in data_lengths:
                raise SessionError(f"P5 freeze data length not selected for {did:#x}")
            length = data_lengths[did]
            if cursor + length > len(reply):
                raise ToyotaCodecError("P5 freeze data value truncated", SHORT_REPLY)
            value = reply[cursor : cursor + length]
            cursor += length
            if not any(item["did"] == did for item in items):
                item: dict[str, object] = {"did": did, "payload": value.hex()}
                if decode is not None:
                    item["signals"] = decode(did, value)
                items.append(item)
        record: dict[str, object] = {"number": number, "kind": kind, "items": items}
        if subaru_snapshot:
            record["native_number"] = (number - 0x7F) & 255
        records.append(record)
        if not count and not zero_count_until_end:
            ignored_tail = reply[cursor:]
            break
    return {
        "code": int.from_bytes(reply[2:5], "big"),
        "status": reply[5],
        "records": records,
        "ignored_tail": ignored_tail.hex(),
    }


def parse_subaru_stored_freeze(
    reply: bytes,
    data_lengths: Mapping[int, int],
    *,
    request_number: int,
    decode: Callable[[int, bytes], object] | None = None,
) -> dict[str, object]:
    """Common88fc0 Subaru stored records: prefix2, number,DTC24,status,count.

    Native type is extended SUBARU10. Record status is retained as raw evidence;
    original89331 constructs its DTC metadata with zero status/type. Native
    MultiData record numbers are (wire_number-7f)&ff at896c4.
    """
    if type(request_number) is not int or not 0 <= request_number <= 255:
        raise ValueError("Subaru requested record number must fit byte")
    if not 2 <= len(reply) <= 65535:
        raise ToyotaCodecError("Subaru stored reply lacks prefix", SHORT_REPLY)
    # Reuse the native byte-length dependency validation, without parsing data.
    parse_p5_freeze(bytes(6), data_lengths)
    records: list[dict[str, object]] = []
    cursor = 2
    ignored_tail = b""
    while cursor < len(reply):
        begin = cursor
        if cursor + 6 > len(reply):
            raise ToyotaCodecError("Subaru stored record header truncated", SHORT_REPLY)
        number = reply[cursor]
        if not 1 <= number <= 0xFE:
            ignored_tail = reply[begin:]
            break
        code = int.from_bytes(reply[cursor + 1 : cursor + 4], "big")
        status_raw, count = reply[cursor + 4 : cursor + 6]
        cursor += 6
        items: list[dict[str, object]] = []
        item_index = 0
        fallback = not count and request_number != 255
        while item_index < count or (fallback and cursor < len(reply)):
            item_index += 1
            if cursor + 2 > len(reply):
                raise ToyotaCodecError("Subaru stored DID truncated", SHORT_REPLY)
            did = int.from_bytes(reply[cursor : cursor + 2], "big")
            cursor += 2
            if did not in data_lengths:
                raise SessionError(
                    f"Subaru stored DID length not selected for {did:#x}"
                )
            length = data_lengths[did]
            if cursor + length > len(reply):
                raise ToyotaCodecError("Subaru stored DID data truncated", SHORT_REPLY)
            value = reply[cursor : cursor + length]
            cursor += length
            if not any(item["did"] == did for item in items):
                item: dict[str, object] = {"did": did, "payload": value.hex()}
                if decode is not None:
                    item["signals"] = decode(did, value)
                items.append(item)
        records.append(
            {
                "code": code,
                "number": number,
                "native_number": (number - 0x7F) & 255,
                "kind": 0x10,
                "status_raw": status_raw,
                "status": 0,
                "diag_type": 0,
                "existence_flag": 1,
                "items": items,
            }
        )
        if not count:
            ignored_tail = reply[cursor:]
            break
    return {"records": records, "ignored_tail": ignored_tail.hex()}


def ffd_type(number: int, extended: bool = False, *, subaru: bool = False) -> int:
    """CommandCommon GetFFDType 0x82fd0, preserving unnamed native values."""
    if type(number) is not int or not 0 <= number <= 255:
        raise ValueError("FFD record number must fit byte")
    if not number:
        return 0
    if subaru:
        if extended:
            return 0x10 if number <= 0xFE else 0
        return 1 if number == 1 else 0x10 if 0x10 <= number <= 0x2F else 0
    if extended:
        if number <= 14:
            return 0x100 + number
        return 0x200 + (number & 0xF0) if 0x10 <= number <= 0xEF else 0
    if number in (1, 2):
        return number
    for first in (0x10, 0x30, 0x50):
        if first <= number <= first + 0x1F:
            return first
    return 0


def ffd_existence_flag(kind: int, flags: int = 0) -> int:
    """SetFFDExistFlag 0x880f0; unknown nonzero types leave existing flags."""
    if type(kind) is not int or not 1 <= kind <= 0xFFFFFFFF:
        raise ValueError("FFD type must be nonzero uint32")
    if type(flags) is not int or not 0 <= flags <= 0xFFFFFFFF:
        raise ValueError("FFD flags must fit uint32")
    bit = {1: 1, 2: 0x10}.get(
        kind, 1 << (kind - 0x101 + 8) if 0x101 <= kind <= 0x10E else 0
    )
    return flags | bit


def absolute_time_values(
    encoded_by_pid: Mapping[int, int], signal_pids: Mapping[int, int]
) -> dict[int, int]:
    """P5 absolute component BCD/range checks, with explicitly selected PID joins.

    Keys are original signal IDs, not an inferred calendar/year epoch. Inputs
    are already extracted uint32 values, before the native BCD conversion.
    """
    limits = (
        (0x3C, 0, 38),
        (0x3D, 1, 12),
        (0x3E, 1, 31),
        (0x3F, 0, 23),
        (0x40, 0, 59),
        (0x41, 0, 59),
    )
    for signal, _, _ in limits:
        if signal not in signal_pids:
            raise SessionError(f"Missing selected absolute-time signal {signal:#x}")
        pid = signal_pids[signal]
        if type(pid) is not int or not 0 <= pid <= 0xFFFF:
            raise ValueError("Absolute-time PID must fit uint16")
    for encoded in encoded_by_pid.values():
        if type(encoded) is not int or not 0 <= encoded <= 0xFFFFFFFF:
            raise ValueError("Absolute-time encoded value must fit uint32")
    result: dict[int, int] = {}
    for signal, minimum, maximum in limits:
        pid = signal_pids[signal]
        if not pid or pid not in encoded_by_pid:
            continue
        encoded = encoded_by_pid[pid]
        value, multiplier = 0, 1
        for _ in range(8):
            digit = encoded & 15
            if digit >= 10:
                break
            value += digit * multiplier
            multiplier *= 10
            encoded >>= 4
        else:
            if minimum <= value <= maximum:
                result[signal] = value
    return result


def compare_timestamp(first: int, second: int, first_odo: int, second_odo: int) -> int:
    """CompTimeStamp 0x84d90 returns 1 greater, 2 less, 3 equal (unsigned)."""
    for value in (first, second, first_odo, second_odo):
        if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
            raise ValueError("Timestamp/odometer must fit uint32")
    left, right = (first, first_odo), (second, second_odo)
    return 1 if left > right else 2 if left < right else 3


@dataclass(frozen=True)
class FreezeSample:
    kind: int
    number: int
    timestamp: int
    odometer: int
    payload: bytes
    time_index: int | None = None

    def __post_init__(self) -> None:
        if self.time_index is not None and (
            type(self.time_index) is not int or not -128 <= self.time_index <= 127
        ):
            raise ValueError("Native time index must fit signed byte")
        compare_timestamp(self.timestamp, self.timestamp, self.odometer, self.odometer)
        if type(self.number) is not int or not 0 <= self.number <= 255:
            raise ValueError("Freeze sample number must fit byte")


_FFD_GROUPS = ((1, 0x10, 0x30), (2, 0x50)) + tuple(
    (0x101 + index, 0x210 + index * 16) for index in range(14)
)


def order_freeze_samples(samples: Sequence[FreezeSample]) -> tuple[FreezeSample, ...]:
    """Common84dd0 paired timestamp/odo ordering, with native16 FFD groups.

    Native85f70 requires each group's anchor type before retaining companion
    timestamp entries. Its type ordering remains the stable tie order before
    Common84edb sorts each group by unsigned timestamp/odometer.
    """
    ranks = {
        kind: (group, rank)
        for group, kinds in enumerate(_FFD_GROUPS)
        for rank, kind in enumerate(kinds)
    }
    present = {sample.kind for sample in samples}
    ranked: list[tuple[int, int, int, FreezeSample]] = []
    for index, sample in enumerate(samples):
        if sample.kind not in ranks:
            raise SessionError(
                f"FFD display group not recovered for type {sample.kind:#x}"
            )
        group, rank = ranks[sample.kind]
        if _FFD_GROUPS[group][0] in present:
            ranked.append((group, rank, index, sample))
    for group in range(len(_FFD_GROUPS)):
        if sum(item[0] == group for item in ranked) > 255:
            raise SessionError("Paired FFD group exceeds native byte count")
    return tuple(
        item[3]
        for item in sorted(
            ranked,
            key=lambda item: (
                item[0],
                item[3].timestamp,
                item[3].odometer,
                item[1],
                item[2],
            ),
        )
    )


def index_freeze_samples(samples: Sequence[FreezeSample]) -> tuple[FreezeSample, ...]:
    """SetMultiTimeIndex85510: anchor0; equal adjacent time/odo share index.

    Indices propagate forward/backward from first anchor and retain signed-byte
    wrap. Inputs are the explicitly paired timestamp and odometer entries.
    """
    ordered = order_freeze_samples(samples)
    result: list[FreezeSample] = []

    def signed_byte(value: int) -> int:
        return (value + 128) % 256 - 128

    for kinds in _FFD_GROUPS:
        block = [sample for sample in ordered if sample.kind in kinds]
        if not block:
            continue
        anchor = next(i for i, sample in enumerate(block) if sample.kind == kinds[0])
        indices = [0] * len(block)
        for i in range(anchor + 1, len(block)):
            equal = (block[i].timestamp, block[i].odometer) == (
                block[i - 1].timestamp,
                block[i - 1].odometer,
            )
            indices[i] = signed_byte(indices[i - 1] + (not equal))
        for i in range(anchor - 1, -1, -1):
            equal = (block[i].timestamp, block[i].odometer) == (
                block[i + 1].timestamp,
                block[i + 1].odometer,
            )
            indices[i] = signed_byte(indices[i + 1] - (not equal))
        result.extend(
            replace(sample, time_index=index) for sample, index in zip(block, indices)
        )
    return tuple(result)


def apply_freeze_time_indices(
    signal_samples: Sequence[FreezeSample], paired_timestamps: Sequence[FreezeSample]
) -> tuple[FreezeSample, ...]:
    """SetTimeIndex85da0 first-match propagation into one selected signal list.

    A group without paired timestamps assigns0 only to its first anchor sample
    in this signal list (native858e4..85aa9). Other unmatched samples retain None.
    """
    indexed = index_freeze_samples(paired_timestamps)
    values: dict[tuple[int, int], int | None] = {}
    for kinds in _FFD_GROUPS:
        group = [sample for sample in indexed if sample.kind in kinds]
        if not group:
            continue
        anchor = next(i for i, sample in enumerate(group) if sample.kind == kinds[0])
        # 85b31..85bf5 writes anchor->end, then85c09..85cd6 walks
        # anchor-1 backwards. Duplicate source identities overwrite the first
        # matching target in this exact order.
        for sample in (*group[anchor:], *reversed(group[:anchor])):
            values[(sample.kind, sample.number)] = sample.time_index
    timestamp_kinds = {sample.kind for sample in indexed}
    seen: set[tuple[int, int]] = set()
    zeroed: set[int] = set()
    result: list[FreezeSample] = []
    for sample in signal_samples:
        key = (sample.kind, sample.number)
        value = sample.time_index
        if key not in seen:
            if key in values:
                value = values[key]
            else:
                for group, kinds in enumerate(_FFD_GROUPS):
                    if (
                        sample.kind == kinds[0]
                        and not timestamp_kinds.intersection(kinds)
                        and group not in zeroed
                    ):
                        value = 0
                        zeroed.add(group)
                        break
        seen.add(key)
        result.append(replace(sample, time_index=value))
    return tuple(result)


@dataclass(frozen=True)
class DtcFreeze:
    code: int
    supported: bool = False
    number: int = 0

    def __post_init__(self) -> None:
        if type(self.code) is not int or not 0 <= self.code <= 65535:
            raise ValueError("Freeze-linked DTC must fit uint16")
        if type(self.number) is not int or not 0 <= self.number <= 255:
            raise ValueError("Freeze number must fit byte")


@dataclass(frozen=True)
class CgwFreeze:
    """One native CGW appended Freeze result, preserving selected source order."""

    record: bytes
    payload: bytes
    metadata: MonitorSignalMetadata
    raw: int
    value: int


def freeze_support_request(template: bytes, number: int) -> bytes:
    """GetFrzSupport patches index 2 for length3, index1 for length4."""
    if type(number) is not int or not 0 <= number <= 255:
        raise ValueError("Freeze number must fit byte")
    request = bytearray(template)
    if len(request) == 3:
        request[2] = number
    elif len(request) == 4:
        request[1] = number
    return bytes(request)


def freeze_support_code(frame: CommandFrame, reply: bytes) -> int:
    """GetFrzSupport requires mask-length equality, extracts first two masks.

    This is the separate diagnostic-code extraction use of receive_mask, not
    `(reply & mask)==check` validation. Missing mask bytes become zero.
    """
    if len(reply) != len(frame.receive_mask):
        raise ToyotaCodecError(
            "Freeze support response/mask lengths differ", SHORT_REPLY
        )
    values = [
        value & mask
        for value, mask in zip(reply, frame.receive_mask, strict=True)
        if mask
    ][:2]
    values.extend([0] * (2 - len(values)))
    return (values[0] << 8) | values[1]


def comm_ecu_support_p4(
    record: bytes, enabled_pids: Mapping[int, int], support_masks: Mapping[int, bytes]
) -> bool:
    """Common25e50/559b0: enabled PID then ANY supported selected raw bit."""
    if len(record) != 12:
        raise ToyotaCodecError("Invalid CommEcuData record", INVALID_RECORD)
    pid = record[8]
    if pid not in enabled_pids:
        return False
    if pid not in support_masks:
        raise ToyotaCodecError("Selected PID support data absent", 0xC0040001)
    mask = support_masks[pid]
    begin, end = struct.unpack_from("<HH", record, 2)
    if not isinstance(mask, bytes) or len(mask) > 255:
        raise ValueError("Native PID support mask must fit byte length")
    if end >= len(mask) * 8:
        return False
    if begin > end:
        raise ToyotaCodecError("Invalid CommEcuData support bit range", 0xC0040102)
    return extract_bits(mask, begin, end) != 0


def associate_freeze(
    records: Sequence[DtcFreeze],
    code: int,
    number: int,
    *,
    kind: Literal["basic", "history", "timestamp"] = "basic",
    diagnostic_type: int = 0,
    other_records: Sequence[DtcFreeze] = (),
) -> tuple[tuple[DtcFreeze, ...], bool]:
    """Native SetSptFrzNum minimum-number and history/timestamp exclusions."""
    DtcFreeze(code, number=number)
    if kind not in ("basic", "history", "timestamp"):
        raise ValueError("Unknown freeze support variant")
    exclusion = 2 if kind == "history" else 1 if kind == "timestamp" else None
    suppress = diagnostic_type == exclusion and any(
        item.code == code and item.number == number and item.supported
        for item in other_records
    )
    result: list[DtcFreeze] = []
    added = False
    for item in records:
        if item.code == code and not suppress:
            added |= not item.supported
            item = replace(
                item,
                supported=True,
                number=min(item.number, number) if item.supported else number,
            )
        result.append(item)
    return tuple(result), added


@dataclass(frozen=True)
class TeslaDtcDefinition:
    """Selected DB0x231 row and its resolved native string getters."""

    record: bytes
    signature: str
    name: str
    comment: str = ""


def comm_did_request(
    template: bytes, record: bytes, positions: bytes, command: bytes
) -> bytes:
    """Common1aa30 SendDidData selected0x9d frame and DID support map."""
    if len(record) != 24 or not 1 <= len(template) <= 255:
        raise ToyotaCodecError(
            "Invalid selected CommDidData row/template", INVALID_RECORD
        )
    if not isinstance(positions, bytes) or len(positions) > 255:
        raise ToyotaCodecError("Invalid selected DID support positions", 0xC005100C)
    if not isinstance(command, bytes):
        raise ToyotaCodecError("Invalid DID command bytes", 0xC0040001)
    offset = struct.unpack_from("<H", record, 4)[0] >> 3
    if offset > len(positions):
        raise ToyotaCodecError(
            "DID support map ends before command offset", SHORT_REPLY
        )
    request = (
        template
        + bytes((record[21], record[14]))
        + bytes(sum(bool(flag) for flag in positions[:offset]))
        + command
        + bytes(sum(bool(flag) for flag in positions[offset + len(command) :]))
    )
    if len(request) > 255:
        raise ToyotaCodecError(
            "DID command exceeds ordinary frame bound", INVALID_RECORD
        )
    return request


def decode_comm_pid_reply(
    record: bytes,
    category_type: int,
    request: bytes,
    reply: bytes,
    *,
    positions: bytes | None = None,
    bcd: bool = False,
) -> int:
    """Common1B880 reply copy/support expansion/raw bits;1C500 optional BCD.

    Request is the actual patched selected6B/CA PDU. Native counts subtract
    the fixed2/3-byte prefix while copying after the full send length.
    """
    if (
        len(record) != 44
        or type(category_type) is not int
        or not 0 <= category_type <= 255
    ):
        raise ToyotaCodecError(
            "Invalid selected CommPidData row/category", INVALID_RECORD
        )
    if type(bcd) is not bool:
        raise ValueError("BCD conversion requires explicit boolean")
    begin, end = struct.unpack_from("<HH", record, 20)
    if begin > end or end - begin >= 32:
        raise ToyotaCodecError("Invalid CommPidData bit range", INVALID_RECORD)
    extended = category_type in (0x14, 0x15, 0x34)
    prefix, maximum = (3, 65535) if extended else (2, 255)
    if not isinstance(request, bytes) or not prefix <= len(request) <= maximum:
        raise ToyotaCodecError("Invalid CommPidData request length", 0xC0040102)
    if (
        not isinstance(reply, bytes)
        or not 0 < len(reply) <= maximum
        or reply[0] != request[0] | 0x40
    ):
        raise ToyotaCodecError(
            "Invalid native CommPidData reply service/length", INVALID_REPLY
        )
    count = (len(reply) - prefix) & maximum
    if not count or len(request) + count > len(reply):
        raise ToyotaCodecError("CommPidData reply lacks selected payload", SHORT_REPLY)
    payload = reply[len(request) : len(request) + count]
    if not extended:
        if positions is None:
            raise SessionError("CommPidData support positions not selected")
        if not isinstance(positions, bytes) or not 1 <= len(positions) <= 255:
            raise ToyotaCodecError("Invalid CommPidData support positions", 0xC0040001)
        payload = expand_supported_pid(payload, positions)
    try:
        value = extract_bits(payload, begin, end)
    except ValueError as error:
        raise ToyotaCodecError(
            "CommPidData reply lacks selected signal", SHORT_REPLY
        ) from error
    return decode_bcd32(value) if bcd else value


def comm_signal_data(
    record: bytes, raw: int, *, routine: bool = False, unit: str = ""
) -> dict[str, object]:
    """Common1c370/6b9c0 SetData conversion fields and raw MultiData item."""
    if len(record) != (36 if routine else 44):
        raise ToyotaCodecError(
            "Invalid selected communication signal row", INVALID_RECORD
        )
    if type(raw) is not int or not 0 <= raw <= 0xFFFFFFFF:
        raise ToyotaCodecError(
            "Communication signal raw value must fit uint32", 0xC0040001
        )
    begin, end = struct.unpack_from("<HH", record, 20)
    if begin > end or end - begin >= 32:
        raise ToyotaCodecError("Invalid communication signal width", INVALID_RECORD)
    multiplier, divisor, offset = struct.unpack_from("<iii", record)
    sign = record[33 if routine else 40]
    precision = record[34 if routine else 41]
    rendered = render_signal(
        raw,
        selector=2,
        sign_mode=sign,
        bits=end - begin + 1,
        multiplier=multiplier,
        divisor=divisor,
        offset=offset,
        precision=precision,
    )
    rendered.update(
        name="",
        short_name="",
        unit=unit,
        selector=2,
        precision=precision,
        sign_mode=sign,
        bits=end - begin + 1,
        multiplier=multiplier,
        divisor=divisor,
        offset=offset,
        native_58=struct.unpack_from("<H", record, 24 if routine else 28)[0],
        native_74=0,
        native_78=0,
        native_7c=0,
        native_80=0,
        multi_core_type=1,
        multi_core_version=0,
        multi_index=0,
    )
    return rendered


def decode_bcd32(raw: int) -> int:
    """Common1c5b0: all eight nibbles participate, including leading zeros."""
    if type(raw) is not int or not 0 <= raw <= 0xFFFFFFFF:
        raise ToyotaCodecError("BCD input must fit uint32", 0xC0040001)
    result, factor = 0, 1
    for shift in range(0, 32, 4):
        digit = (raw >> shift) & 15
        if digit >= 10:
            raise ToyotaCodecError("Invalid native BCD digit", 0xA0040208)
        result += digit * factor
        factor *= 10
    return result


def assemble_absolute_log(
    samples: Sequence[tuple[int, int, int]],
    log_number: int,
    *,
    pid_identifiers: bool = False,
) -> dict[int, int] | None:
    """AbsTimeStampSaveLog1c10/2170 selected component validity/copy order.

    Samples are (native component ID, raw value after optional BCD, bit width).
    PID IDs0x8f..0x9a and routine IDs1..12 address the same twelve slots.
    """
    if type(log_number) is not int or not 0 <= log_number <= 0xFFFFFFFF:
        raise ValueError("Absolute log number must fit uint32")
    result: dict[int, int] = {}
    for identifier, value, bits in samples:
        if any(type(item) is not int for item in (identifier, value, bits)):
            raise ToyotaCodecError("Invalid absolute log component type", 0xC0040001)
        component = identifier - 0x8E if pid_identifiers else identifier
        if (
            not 1 <= component <= 12
            or not 1 <= bits <= 32
            or not 0 <= value <= 0xFFFFFFFF
        ):
            raise ToyotaCodecError("Invalid absolute log component", 0xC0040001)
        sentinel = (1 << bits) - 1
        if component == 1:
            valid = value != sentinel and value == log_number
        elif component == 2:
            valid = value != sentinel
        else:
            low, high = {
                3: (0, 99),
                4: (1, 12),
                5: (1, 31),
                6: (0, 23),
                7: (0, 59),
                8: (0, 59),
                9: (0, 1),
                10: (0, 12),
                11: (0, 59),
                12: (0, 1),
            }[component]
            valid = low <= value <= high
        if not valid:
            return None
        result[component] = value
    return result


def routine_support_bit(payload: bytes, routine_id: int, mode: int) -> bool:
    """Common6b3c0 AnalyzeFrameData RID high/low support tables, MSB first."""
    if type(routine_id) is not int or not 0 < routine_id <= 65535 or mode not in (1, 2):
        raise ToyotaCodecError("Invalid routine support selector", 0xC0040001)
    value = routine_id >> 8 if mode == 1 else (routine_id & 255) - 1
    if value < 0:
        raise ToyotaCodecError("Routine low-byte support selector is zero", 0xC0040001)
    index, bit = divmod(value, 8)
    if index > len(payload):
        return False
    if index == len(payload):
        # Native tests count<index, then dereferences index==count. Reject
        # that unsafe original boundary instead of inventing a support bit.
        raise ToyotaCodecError(
            "Routine support table ends at selected byte", SHORT_REPLY
        )
    return bool(payload[index] & (0x80 >> bit))


def parse_dk_freeze(
    reply: bytes,
    request_length: int,
    freezes: Sequence[bytes],
    pid_lengths: Mapping[int, int],
) -> list[bytes]:
    """Common23d20 native sequential PID-group offsets, in selected row order."""
    if type(request_length) is not int or not 4 <= request_length <= 255:
        raise ToyotaCodecError("Invalid DK freeze request length", 0xC0040102)
    size = len(reply) - request_length - 2
    if size < 1:
        raise ToyotaCodecError("DK freeze reply has no group data", SHORT_REPLY)
    data = reply[request_length - 2 : request_length - 2 + size]
    previous_pid = previous_length = offset = 0
    result: list[bytes] = []
    for row in freezes:
        if len(row) != 84:
            raise ToyotaCodecError("Invalid DK Freeze row", INVALID_RECORD)
        pid = row[79]
        length = pid_lengths.get(pid)
        if type(length) is not int or not 0 < length <= 255:
            raise SessionError(f"Selected DK PID length unavailable: {pid}")
        begin, end = struct.unpack_from("<HH", row, 62)
        if begin > end or end >= length * 8:
            raise ToyotaCodecError("DK signal exceeds selected PID length", 0xC0040102)
        if previous_pid != pid or not previous_pid:
            if previous_pid:
                offset = (offset + previous_length) & 255
            previous_pid, previous_length = pid, length
        required = (offset + length) & 255
        if size < required or offset + length > len(data):
            raise ToyotaCodecError("DK freeze reply lacks PID group data", SHORT_REPLY)
        result.append(data[offset : offset + length])
    return result


def expand_supported_pid(data: bytes, positions: bytes) -> bytes:
    """Common55050 ConvertPid: expand selected cached byte-position flags."""
    if not data or not 0 < len(positions) <= 255:
        raise ToyotaCodecError("Selected PID position table absent/invalid", 0xC0040001)
    if len(data) > len(positions):
        raise ToyotaCodecError("Compressed PID exceeds native full length", 0xA0040201)
    if len(data) < sum(bool(flag) for flag in positions):
        # Original reads outside its input here; reject the unsafe malformed reply.
        raise ToyotaCodecError("Compressed PID lacks supported bytes", SHORT_REPLY)
    source = iter(data)
    return bytes(next(source) if flag else 0 for flag in positions)


def parse_tesla_dtcs(
    reply: bytes,
    definitions: Mapping[int, TeslaDtcDefinition],
    *,
    include_hidden: bool = False,
) -> list[dict[str, object]]:
    """Common7fdb0/80350: exactly nineteen expanded DTCs, order retained."""
    if len(reply) < 59:
        raise ToyotaCodecError("Short Tesla DTC response", SHORT_REPLY)
    result: list[dict[str, object]] = []
    for start in range(2, 59, 3):
        expanded = int.from_bytes(reply[start : start + 3], "big")
        if not expanded:
            continue
        definition = definitions.get(expanded)
        if definition is not None:
            row = definition.record
            if len(row) != 36 or struct.unpack_from("<I", row, 20)[0] != expanded:
                raise ToyotaCodecError(
                    "Invalid selected expanded DTC row", INVALID_RECORD
                )
            if not row[34] and not include_hidden:
                continue
        result.append(
            {
                "expanded_code": expanded,
                "code": expanded & 65535,
                "signature": definition.signature if definition else f"{expanded:06X}",
                "name": definition.name if definition else "???",
                "comment": definition.comment if definition else "",
                "native_field_18": struct.unpack_from("<I", definition.record, 24)[0]
                if definition
                else 0,
            }
        )
    return result


def dtc_metadata_profile(
    profile: VehicleProfile,
    code: int,
    *,
    lookup_mode: int = 0,
    include_disabled: bool = False,
) -> dict[str, object] | None:
    """Common77240 selected DB205 visibility/strings before native AddTail.

    None preserves native success without adding an invisible selected row.
    Lookup mode1 bypasses DB metadata and uses the native unknown fallback.
    """
    format_dtc(code)
    if type(lookup_mode) is not int or not 0 <= lookup_mode <= 0xFFFFFFFF:
        raise ValueError("Native diagnostic lookup mode must fit DWORD")
    if type(include_disabled) is not bool:
        raise ValueError("Native diagnostic visibility override must be boolean")
    item: dict[str, object] = {
        "code": code,
        "signature": format_dtc(code),
        "name": "???",
        "comment": "",
        "native_field_1c": 0,
    }
    if lookup_mode == 1:
        return item
    rows = profile.records(5)
    if any(len(row) != 28 for row in rows):
        raise ToyotaCodecError("Invalid selected DiagCode28 row", INVALID_RECORD)
    selected: list[bytes] = []
    for row in rows:
        if struct.unpack_from("<H", row, 20)[0] == code:
            selected.append(row)
        elif selected:
            break
    if not selected:
        return item
    # Native SetRecString hydrates every selected row before FIRST/visibility.
    strings = [
        tuple(
            profile.catalog.language.resolve(key)
            for key in struct.unpack_from("<II", row, 12)
        )
        for row in selected
    ]
    row = selected[0]
    if not row[26] and not include_disabled:
        return None
    item.update(
        signature=row[:12].decode("utf-16le").split("\0", 1)[0],
        name=strings[0][0],
        comment=strings[0][1],
        native_field_1c=struct.unpack_from("<I", row, 12)[0],
    )
    return item


def dtc_metadata_p5_profile(
    profile: VehicleProfile, code: int
) -> dict[str, object] | None:
    """Common7C9E0 first DB241 DWORD44 metadata, before native AddTail.

    Invisible selected rows return None; absent matching rows use the native
    seven-character fallback. Table/query failures propagate, never masquerade
    as an absent row. Raw fields retain neutral names until consumer proof.
    """
    signature = format_dtc(code, bits=24)
    if 65 not in profile.database.sections:
        raise ToyotaCodecError("Selected DiagCodeP5 table absent", 0xA0030107)
    rows = profile.records(65)
    if any(len(row) != 68 for row in rows):
        raise ToyotaCodecError("Invalid selected DiagCodeP5 row", INVALID_RECORD)
    selected: list[bytes] = []
    for row in rows:
        if struct.unpack_from("<I", row, 44)[0] == code:
            selected.append(row)
        elif selected:
            break
    item: dict[str, object] = {
        "code": code,
        "signature": signature,
        "name": "???",
        "division_name": "",
        "native_field_24": 0,
        "native_field_38": 0,
        "native_field_2de": 0,
        "native_field_2e0": 0,
    }
    if not selected:
        return item
    language = profile.catalog.language
    strings = [
        tuple(
            language.resolve(struct.unpack_from("<I", row, offset)[0])
            for offset in (48, 56, 52)
        )
        for row in selected
    ]
    row = selected[0]
    name, _subcomment, division = strings[0]
    if not row[64]:
        return None
    item.update(
        signature=row[:42].decode("utf-16le").split("\0", 1)[0],
        name=name,
        division_name=division,
        native_field_24=struct.unpack_from("<I", row, 48)[0],
        native_field_38=struct.unpack_from("<I", row, 52)[0],
        native_field_2de=struct.unpack_from("<H", row, 62)[0],
        native_field_2e0=row[65],
    )
    return item


def analyze_p5_diagnostic_reply_profile(
    profile: VehicleProfile,
    reply: bytes,
    rules: Sequence[StatusRule],
    *,
    maximum_groups: int = 0x3FF,
    requested_types: int | None = None,
    state: P5FreezeState | None = None,
) -> list[dict[str, object]]:
    """GetDiagCodeP5 local2910 + Common7C9E0 ordered metadata/duplicate merge.

    Empty, short, over-capacity and unavailable-status replies leave the native
    list empty successfully. Metadata is selected only for a new visible code;
    existing duplicates merge type/status without querying the DB again.
    """
    if state is not None:
        from scripts.freeze_p5 import P5Diagnostic, P5FreezeState

        if not isinstance(state, P5FreezeState) or state.profile is not profile:
            raise TypeError("P5 analysis requires the same concrete selected state")
        state._check()
    if type(maximum_groups) is not int or not 1 <= maximum_groups <= 0x3FFF:
        raise ValueError("P5 diagnostic group capacity exceeds native bounds")
    if not isinstance(reply, bytes):
        raise TypeError("P5 diagnostic reply must be bytes")
    groups = max(0, (len(reply) - 3) // 4)
    if not groups or groups > maximum_groups:
        return []
    if not rules:
        if requested_types is None:
            raise SessionError(
                "P5 availability requires the requested diagnostic types"
            )
        try:
            _, rules = dtc_status_rules_profile(profile, requested_types)
        except ToyotaCodecError:
            # CheckDTCStatusAvailability ignores the loader status and returns
            # zero when its native cache count remains unwritten.
            return []
    if not any(reply[2] & rule.mask for rule in rules):
        return []
    values: dict[int, dict[str, object]] = {}
    for pos in range(3, 3 + groups * 4, 4):
        status = reply[pos + 3]
        kind = diag_type(status, rules) if status else 0
        if not kind:
            continue
        code = int.from_bytes(reply[pos : pos + 3], "big")
        existing = values.get(code)
        native = None if state is None else state.diagnostic(code)
        if native is not None:
            native.status |= status
            native.diag_type |= kind
            existing = values.setdefault(code, dict(native.metadata))
            existing.update(status=native.status, diag_type=native.diag_type)
            continue
        if existing is not None:
            old_status, old_kind = existing["status"], existing["diag_type"]
            assert isinstance(old_status, int) and isinstance(old_kind, int)
            existing["status"] = old_status | status
            existing["diag_type"] = old_kind | kind
            continue
        item = dtc_metadata_p5_profile(profile, code)
        if item is not None:
            item.update(status=status, diag_type=kind)
            values[code] = item
            if state is not None:
                state._check()
                if len(state.diagnostics) >= state.diagnostic_limit:
                    raise SessionError(
                        "FFD diagnostic count exceeds native caller bound"
                    )
                state.diagnostics.append(P5Diagnostic(code, item, status, kind))
    return list(values.values())


def _hydrate_freeze_names_profile(
    profile: VehicleProfile, rows: Sequence[bytes]
) -> None:
    """CDbFreezeResRecords.SetRecString, before native FIRST/visibility getters."""
    for row in rows:
        profile.catalog.language.resolve(struct.unpack_from("<I", row, 48)[0])


def dtc_information(
    diagnostic_record: bytes,
    detail_records: Sequence[bytes],
    *,
    signature: str,
    name: str,
    highlighting: Mapping[int, Sequence[bytes]] | None = None,
) -> list[dict[str, object]]:
    """GetDiagCodeInfo_DT 0x1730 selected-record copy, with raw field names.

    String getters/vehicle lookup happen upstream. Detail+0xc resolves DB0x230;
    nonzero missing highlighting is a dependency failure, never an empty list.
    """
    if len(diagnostic_record) < 16:
        raise ToyotaCodecError("Truncated diagnostic information row", INVALID_RECORD)
    result: list[dict[str, object]] = []
    for row in detail_records:
        if len(row) < 18:
            raise ToyotaCodecError("Truncated diagnostic detail row", INVALID_RECORD)
        key = struct.unpack_from("<H", row, 12)[0]
        signals: list[dict[str, int]] = []
        if key:
            if highlighting is None or key not in highlighting or not highlighting[key]:
                raise SessionError(f"Highlighting records not selected: {key}")
            for signal in highlighting[key]:
                if len(signal) < 5:
                    raise ToyotaCodecError("Truncated highlighting row", INVALID_RECORD)
                signals.append(
                    {
                        "signal_key": struct.unpack_from("<H", signal, 2)[0],
                        "field_04": signal[4],
                    }
                )
        result.append(
            {
                "signature": signature,
                "name": name,
                "diagnostic_field_0c": struct.unpack_from("<I", diagnostic_record, 12)[
                    0
                ],
                "detail_field_00": struct.unpack_from("<I", row, 0)[0],
                "detail_field_04": struct.unpack_from("<I", row, 4)[0],
                "detail_field_0a": struct.unpack_from("<H", row, 10)[0],
                "detail_field_10": row[16],
                "detail_field_11": row[17],
                "highlighting": signals,
            }
        )
    return result


def dtc_information_profile(
    profile: VehicleProfile, signature: str | None = None
) -> dict[str, object]:
    """GetDiagCodeInfo Execute1010/1250/14F0 with native partial output.

    Native per-diagnostic helper failures leave earlier items and are overwritten
    by a later helper result. Return the final native status beside those items.
    Host language/format errors remain exceptions rather than invented statuses.
    """
    if signature is not None and not isinstance(signature, str):
        raise TypeError("DTC information signature must be text or None")
    query = (signature or "").split("\0", 1)[0]
    if len(query.encode("utf-8")) > 65535:
        raise ValueError("DTC signature exceeds native string bound")
    category = profile.category_record
    if len(category) < 73:
        raise ToyotaCodecError("Selected ECU category group empty", 0xC0050101)
    expanded = category[72] & 0x1F == 0x14
    try:
        rows = profile.records(65 if expanded else 5)
    except ToyotaCodecError as error:
        if error.code != 0xA0030107:
            return {"native_status": error.code, "items": [], "expanded": expanded}
        rows = ()
    width, visible, signature_size, name_offset = (
        (68, 64, 42, 48) if expanded else (28, 26, 12, 12)
    )
    language = profile.catalog.language
    names: list[str] = []
    for row in rows:
        if len(row) != width:
            raise ToyotaCodecError(
                "Invalid selected diagnostic information row", INVALID_RECORD
            )
        resolved = [
            language.resolve(struct.unpack_from("<I", row, offset)[0])
            for offset in ((48, 56, 52) if expanded else (12, 16))
        ]
        names.append(resolved[0])

    def item(sig: str, name: str, native_id: int = 0) -> dict[str, object]:
        return {
            "signature": sig,
            "name": name,
            "diagnostic_field_0c": native_id,
            "detail_field_00": 0,
            "detail_field_04": 0,
            "detail_field_0a": 0,
            "detail_field_10": 0,
            "detail_field_11": 0,
            "highlighting": [],
        }

    items: list[dict[str, object]] = []
    found, status = False, 0
    for row, name in zip(rows, names, strict=True):
        sig = row[:signature_size].decode("utf-16le").split("\0", 1)[0]
        if query and sig != query:
            continue
        found = True  # A disabled matching row still suppresses unknown fallback.
        if not row[visible]:
            continue
        native_id = struct.unpack_from("<I", row, name_offset)[0]
        if expanded:
            value = item(sig, name, native_id)
            value["detail_field_11"] = row[65]
            value["detail_field_0a"] = struct.unpack_from("<H", row, 62)[0]
            items.append(value)
            status = 0
            continue
        code = struct.unpack_from("<H", row, 20)[0]
        try:
            try:
                details = profile.detail_code_records(code)
            except ToyotaCodecError as error:
                if error.code != 0xA0030107:
                    raise
                details = ()
            if not details:
                items.append(item(sig, name, native_id))
            else:
                for detail in details:
                    if len(detail) != 20:
                        raise ToyotaCodecError(
                            "Invalid selected diagnostic detail row", INVALID_RECORD
                        )
                    key = struct.unpack_from("<H", detail, 12)[0]
                    highlighting = None
                    if key:
                        signals = profile.highlighting_records(key)
                        if not signals:
                            raise ToyotaCodecError(
                                "Diagnostic highlighting group empty", 0xC0040101
                            )
                        highlighting = {key: signals}
                    items.extend(
                        dtc_information(
                            row,
                            [detail],
                            signature=sig,
                            name=name,
                            highlighting=highlighting,
                        )
                    )
            status = 0
        except ToyotaCodecError as error:
            status = error.code
    if (
        not found
        and len(query) == (7 if expanded else 5)
        and query[0] in "PCBU"
        and query[1] in "0123"
        and all(c in "0123456789ABCDEF" for c in query[2:])
    ):
        items.append(item(query, "???"))
        status = 0
    return {"native_status": status, "items": items, "expanded": expanded}


def active_arguments_p5(
    record: bytes,
    data_id_records: Sequence[bytes],
    start_template: bytes,
    release_template: bytes,
    value: int,
    data_length: int,
    pattern: bytes,
    *,
    output_mask: int = 0,
) -> tuple[bytes, bytes, int]:
    """DataMonitorPhase5_DT d3e0 normal active selected-record assembler.

    ActTestP5(DB244), DataIdForAct(DB243), ActTestPattern(DB20c) and
    function9d/64 four-byte templates must already be selected by the profile.
    Data length is the selected ECU length or native special-protocol maximum.
    """
    if (
        len(record) < 0x36
        or not data_id_records
        or any(len(r) < 11 for r in data_id_records)
    ):
        raise ToyotaCodecError("Missing P5 selected active records", INVALID_RECORD)
    if len(start_template) != 4 or len(release_template) != 4 or len(pattern) != 24:
        raise ToyotaCodecError("Invalid P5 active templates/pattern", 0xC0040102)
    if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
        raise ValueError("P5 active value must fit uint32")
    if type(output_mask) is not int or not 0 <= output_mask <= 0xFFFFFFFF:
        raise ValueError("P5 output mask must fit uint32")
    if type(data_length) is not int or not 0 <= data_length <= 256:
        raise ValueError("Selected P5 data length must fit native local buffer")
    begin, end = struct.unpack_from("<HH", record, 0x28)
    did = struct.unpack_from("<H", record, 0x34)[0]
    mode = data_id_records[0][10]
    if mode not in (0, 1, 3, 4) or begin > end:
        raise ToyotaCodecError("Invalid native P5 active mode/range", 0xC0040102)
    payload, mask = bytearray(data_length), bytearray(256)
    mask_length = 0

    def put(offset: int, width: int, number: int) -> None:
        if not 1 <= width <= 4 or offset + width > data_length:
            raise ToyotaCodecError(
                "P5 active value exceeds selected data length", 0xC0040102
            )
        payload[offset : offset + width] = (number & ((1 << (8 * width)) - 1)).to_bytes(
            width, "big"
        )

    if mode in (0, 3):
        offset, width = begin // 8, (end - begin) // 8 + 1
        put(offset, width, value)
        if mode == 0:
            for row in data_id_records:
                ordinal, byte_offset, byte_width = struct.unpack_from("<HHH", row, 4)
                if (
                    offset <= byte_offset < offset + width
                    and byte_offset + byte_width <= offset + width
                ):
                    if not 0 <= ordinal <= 2048:
                        raise ToyotaCodecError(
                            "P5 active mask ordinal outside buffer", INVALID_RECORD
                        )
                    # Native signed division truncates -1 / 8 toward zero;
                    # ordinal zero therefore aliases ordinal eight, not -1.
                    index, bit = (0, 7) if ordinal == 0 else divmod(ordinal - 1, 8)
                    mask[index] |= 1 << (7 - bit)
                    mask_length = max(mask_length, index + 1)
            payload.extend(mask[:mask_length])
    elif mode == 1:
        if begin // 8 != end // 8:
            raise ToyotaCodecError("P5 bit value crosses selected byte", 0xC0040102)
        offset, shift = end // 8, 7 - end % 8
        if output_mask:
            put(offset, 1, value)
            mask[offset] = output_mask & 255
        else:
            if end - begin > 7:
                raise ToyotaCodecError("P5 active bit width exceeds byte", 0xC0040102)
            put(offset, 1, (value & 255) << shift)
            mask[offset] = (((1 << (end - begin + 1)) - 1) << shift) & 255
        mask_length = data_length
        payload.extend(mask[:mask_length])
    else:
        offset, width = begin // 8, end // 8 - begin // 8 + 1
        put(offset, width, (value << (7 - end % 8)) & 0xFFFFFFFF)
        for bit in range(begin, end + 1):
            mask[bit // 8] |= 1 << (7 - bit % 8)
        mask_length = data_length
        payload.extend(mask[:mask_length])
    start, release = bytearray(start_template), bytearray(release_template)
    start[1:3] = release[1:3] = did.to_bytes(2, "big")
    repeat_ms = struct.unpack_from("<H", pattern, 2)[0] if pattern[20] else 0
    return bytes(start + payload), bytes(release + mask[:mask_length]), repeat_ms


def routine_arguments_p5(
    record: bytes,
    start_template: bytes,
    release_template: bytes,
    command: bytes,
    output_mask: bytes,
    value: int = 0,
    *,
    input_bytes: bytes = b"",
    button_mask: bytes = b"",
    buttons: bytes = b"",
) -> tuple[bytes, bytes]:
    """DataMonitorPhase5_DT e1b0 selected routine command/mask argument packing.

    DB247 row+1c is RID. Variables are GetRoutineCommand/GetOutputMaskValue/
    GetOutputMaskButtonData; selected function d5/d6 templates have four bytes.
    """
    if len(record) < 0x1E or len(start_template) != 4 or len(release_template) != 4:
        raise ToyotaCodecError(
            "Invalid selected P5 routine records/templates", 0xC0040102
        )
    if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
        raise ValueError("Routine scalar argument must fit uint32")
    if max(len(command), len(output_mask), len(button_mask)) > 65531:
        raise ToyotaCodecError(
            "Routine variables exceed native request buffer", INVALID_RECORD
        )
    effective_buttons = button_mask if buttons else b""
    size = len(command) or len(output_mask) or len(effective_buttons)
    data = bytearray(max(len(command), len(output_mask), len(effective_buttons)))
    data[: len(command)] = command
    if input_bytes:
        cursor = 0
        for index, mask in enumerate(output_mask):
            if mask:
                if cursor >= len(input_bytes):
                    raise ToyotaCodecError(
                        "Routine byte arguments shorter than mask", INVALID_RECORD
                    )
                data[index] |= input_bytes[cursor] & mask
                cursor += 1
    else:
        shift = 0
        for index in range(len(output_mask) - 1, -1, -1):
            mask = output_mask[index]
            if mask:
                data[index] |= ((value >> (shift & 31)) & 255) & mask
                shift += 8
    for index, mask in enumerate(effective_buttons):
        if mask:
            if index >= len(buttons):
                raise ToyotaCodecError(
                    "Routine button arguments shorter than mask", INVALID_RECORD
                )
            data[index] |= buttons[index] & mask
    rid = struct.unpack_from("<H", record, 0x1C)[0].to_bytes(2, "big")
    start, release = bytearray(start_template), bytearray(release_template)
    start[2:4] = release[2:4] = rid
    return bytes(start + data[:size]), bytes(release)


def active_requests_p5(
    start_data: bytes, release_data: bytes, *, routine: bool = False
) -> tuple[bytes, bytes]:
    """DataListIF CCommEventPhase5AT 0xa080 prepends proven SID to selected data.

    Normal active data is DID16/control/parameters, routine data is
    control/RID16/parameters. Caller must resolve these selected byte lists.
    """
    if (
        not start_data
        or not release_data
        or max(len(start_data), len(release_data)) >= 65535
    ):
        raise ToyotaCodecError("Invalid P5 active command data", 0xE0000102)
    minimum = 3
    if len(start_data) < minimum or len(release_data) < minimum:
        raise ToyotaCodecError("P5 active data lacks DID/RID/control", 0xE0000102)
    sid = b"\x31" if routine else b"\x2f"
    return sid + start_data, sid + release_data


def active_reply_p5(
    request: bytes,
    reply: bytes,
    *,
    repeat_ms: int = 0,
    now_ms: int = 0,
    has_next: bool = False,
) -> dict[str, int]:
    """DataListIF 0xa520 CheckRcvFrame state transitions, native numeric states.

    3 waits until deadline;4 advances/releases;5 ends. State2f/control3 repeats;
    control0 completes. Routine control1 advances;control2 completes. Other
    controls keep the running state. This does not infer generic UDS semantics.
    """
    if type(repeat_ms) is not int or not 0 <= repeat_ms <= 65535:
        raise ValueError("Native repeat period must fit uint16")
    if type(now_ms) is not int or not 0 <= now_ms <= 0xFFFFFFFF:
        raise ValueError("Native tick must fit uint32")
    if not request or request[0] not in (0x2F, 0x31):
        raise ToyotaCodecError("Unknown P5 active service", 0xE0000102)
    normal = request[0] == 0x2F
    if (
        len(request) < (4 if normal else 2)
        or len(reply) < (3 if normal else 1)
        or reply[0] != request[0] | 0x40
    ):
        raise ToyotaCodecError(
            "P5 active reply fails native service/length", 0xE0000102
        )
    control = request[3] if normal else request[1]
    if normal and control == 3:
        return {
            "state": 3 if repeat_ms else 4,
            "next_tick": (now_ms + repeat_ms) & 0xFFFFFFFF if repeat_ms else 0,
        }
    if (normal and control == 0) or (not normal and control == 2):
        return {"state": 4 if has_next else 5, "next_tick": 0}
    if not normal and control == 1:
        return {"state": 4, "next_tick": 0}
    return {"state": 1, "next_tick": 0}


@dataclass
class LegacyActiveItem:
    request: bytes
    repeat_ms: int = 0
    state: int = 0
    next_tick: int = 0


class LegacyActiveQueue:
    """DataListIF ordinary/DK/PSA event queues; explicit, no driver I/O.

    Ordinary and DK enqueue the builder bytes after its SID. PSA enqueues
    the complete builder frame. Scheduler/driver lifecycle remains explicit.
    """

    def __init__(self, family: Literal["ordinary", "dk", "psa"] = "ordinary") -> None:
        if family not in ("ordinary", "dk", "psa"):
            raise ValueError("Unknown legacy active event family")
        self.family = family
        self.items: list[LegacyActiveItem] = []
        self.init_flag = False
        self.last_tick = 0
        self.control = 0

    @staticmethod
    def _tick(now_ms: int) -> None:
        if type(now_ms) is not int or not 0 <= now_ms <= 0xFFFFFFFF:
            raise ValueError("Native tick must fit uint32")

    def _current(self) -> LegacyActiveItem:
        if not self.items:
            raise SessionError("Legacy active queue is empty")
        return self.items[0] if self.family == "ordinary" else self.items[-1]

    def enqueue(self, data: bytes, *, repeat_ms: int = 0) -> None:
        if not isinstance(data, bytes) or len(data) > 65534:
            raise ToyotaCodecError("Invalid legacy active frame", 0xE0000102)
        if type(repeat_ms) is not int or not 0 <= repeat_ms <= 65535:
            raise ValueError("Native repeat period must fit uint16")
        if self.family == "psa" and len(data) < 3:
            raise ToyotaCodecError("PSA active frame lacks control", 0xE0000102)
        if self.items and self.family != "ordinary":
            tail = self.items[-1]
            if self.family == "psa" and tail.state == 1:
                raise ToyotaCodecError("PSA active repeat is outstanding", 0xE0000102)
            if tail.state:
                self.items[:] = [tail]
        prefix = {"ordinary": b"\x30", "dk": b"\x3d", "psa": b""}[self.family]
        self.items.append(LegacyActiveItem(prefix + data, repeat_ms))

    def stop(self, *, initialize: bool = False) -> None:
        if type(initialize) is not bool:
            raise ValueError("Initialization flag must be boolean")
        if self.family == "dk":
            raise SessionError("DK stop requires the selected driver lifecycle event")
        item = (
            self._current()
            if self.family == "ordinary"
            else self.items[-1]
            if self.items
            else None
        )
        if item is None:
            raise SessionError("Legacy stop has no prior active event")
        if self.family == "ordinary":
            self.init_flag = initialize
            self.items.append(LegacyActiveItem(b"\x30"))
        elif item.next_tick:
            data = item.request
            stop = data[:2] + b"\x11"
            if data[0] == 0x31 and len(data) > 3:
                stop += data[3:4]
            if item.state:
                self.items[:] = [item]
            self.items.append(LegacyActiveItem(stop))

    def advance(self) -> None:
        """Ordinary ProcNextCommItem13f90; DK/PSA base does not advance."""
        if (
            self.family == "ordinary"
            and len(self.items) > 1
            and self.items[0].state not in (0, 1, 2)
        ):
            self.items.pop(0)

    def skip_to_last(self) -> None:
        if self.family != "ordinary":
            raise SessionError("SkipEndCommItem is an ordinary active event operation")
        if self.items:
            self.items[:] = self.items[-1:]

    def next_request(self, now_ms: int) -> bytes | None:
        """Ordinary MultiMonThreadMain state gate; other schedulers are separate."""
        self._tick(now_ms)
        if self.family != "ordinary":
            raise SessionError("Selected driver owns DK/PSA scheduler state gates")
        self.advance()
        if not self.items:
            return None
        item = self.items[0]
        if item.state == 3:
            if now_ms >= item.next_tick:
                item.state = 0
            return None
        if item.state in (4, 5):
            return None
        return self.send_frame(now_ms)

    def send_frame(self, now_ms: int) -> bytes | None:
        """Native GetSndFrame; caller owns the outer scheduler state gate."""
        self._tick(now_ms)
        item = self._current()
        if self.family == "ordinary":
            item.state = 1
        elif self.family == "psa":
            if item.request[2] == 0x11 and now_ms < (
                (self.last_tick + 50) & 0xFFFFFFFF
            ):
                return None
            self.control = item.request[2]
        return item.request

    def accept(self, reply: bytes, now_ms: int) -> None:
        self._tick(now_ms)
        item = self._current()
        if self.family == "psa":
            self.last_tick = now_ms
        if not isinstance(reply, bytes) or not reply or len(reply) > 65535:
            raise ToyotaCodecError("Invalid legacy active reply", 0xE0000102)
        if self.family == "dk":
            if reply[0] != 0x7D:
                raise ToyotaCodecError("DK active reply SID mismatch", 0xE0030001)
            item.next_tick, item.state = 0, 1
            return
        if self.family == "ordinary":
            if reply[0] != 0x70:
                raise ToyotaCodecError("Ordinary active reply SID mismatch", 0xE0000102)
            if len(reply) == 1:
                item.next_tick, item.state = 0, 5
            elif len(reply) == 2:
                item.next_tick = (
                    (now_ms + item.repeat_ms) & 0xFFFFFFFF if item.repeat_ms else 0
                )
                item.state = 3 if item.repeat_ms else 4
            elif len(reply) == 3:
                raise ToyotaCodecError("Ordinary active command rejected", 0xE00001CC)
            return
        if len(reply) < 3 or reply[0] != (item.request[0] | 0x40):
            raise ToyotaCodecError("PSA active reply malformed", 0xE0000102)
        status = reply[2]
        if self.control not in (0, 1, 0x11, 0x20):
            return
        if status == 0:
            raise ToyotaCodecError("PSA active command rejected", 0xE00001CC)
        if self.control == 0x11:
            if status != 0x11:
                raise ToyotaCodecError("PSA active control mismatch", 0xE0000106)
            item.state = 2
        elif status in (2, 4):
            item.state = 2
        elif status != 1:
            raise ToyotaCodecError("PSA active control mismatch", 0xE0000106)
        elif self.control in (0, 0x20) and not item.repeat_ms:
            item.next_tick, item.state = 0, 2
        else:
            if self.control in (0, 0x20):
                length = 4 if reply[0] == 0x71 and len(reply) > 3 else 3
                if len(item.request) < length:
                    raise ToyotaCodecError(
                        "PSA repeat would overread original frame", SHORT_REPLY
                    )
                data = bytearray(item.request[:length])
                data[2] = 1
                item.request = bytes(data)
            item.next_tick = (now_ms + item.repeat_ms) & 0xFFFFFFFF
            item.state = 1


@dataclass
class P5ActiveItem:
    request: bytes
    repeat_ms: int = 0
    state: int = 0
    next_tick: int = 0


class P5ActiveQueue:
    """Selected P5 start/release queues from DataListIF a080/a430/13f90.

    Mutation is explicit and does not communicate. A caller drives one request
    at a time with next_request/accept; ToyotaSession provides bounded I/O.
    """

    def __init__(self, *, dual: bool = False) -> None:
        if type(dual) is not bool:
            raise ValueError("Dual queue selection must be boolean")
        self.dual = dual
        self.last_comm_time = 0
        self.items: list[P5ActiveItem] = []
        self.releases: list[P5ActiveItem] = []
        self.releasing = False

    def enqueue(
        self,
        start_data: bytes,
        release_data: bytes,
        *,
        repeat_ms: int = 0,
        routine: bool = False,
    ) -> None:
        start, release = active_requests_p5(start_data, release_data, routine=routine)
        if type(repeat_ms) is not int or not 0 <= repeat_ms <= 65535:
            raise ValueError("Native repeat period must fit uint16")
        if self.releasing:
            raise SessionError("Cannot append starts during release")
        key = release[2:4] if routine else release[1:3]
        duplicate = False
        for item in self.releases:
            if item.request[0] != release[0]:
                continue
            old_key = item.request[2:4] if routine else item.request[1:3]
            if old_key == key:
                duplicate = True
                break
            # a23e..a266 checks each different normal DID in list order.
            if not routine and (repeat_ms or any(x.repeat_ms for x in self.items)):
                raise ToyotaCodecError(
                    "P5 repeat conflicts with another DID", 0xE0000102
                )
        # Host preflight is atomic; native allocates the start before this check.
        self.items.append(P5ActiveItem(start, repeat_ms))
        if not duplicate:
            self.releases.append(P5ActiveItem(release))

    def stop(self) -> None:
        if not self.releasing:
            self.items = self.releases
            self.releases = []
            self.releasing = True

    def _advance(self) -> None:
        if len(self.items) > 1 and self.items[0].state not in (0, 1, 2):
            self.items.pop(0)

    def next_request(self, now_ms: int) -> bytes | None:
        if type(now_ms) is not int or not 0 <= now_ms <= 0xFFFFFFFF:
            raise ValueError("Native tick must fit uint32")
        self._advance()
        if not self.items:
            return None
        item = self.items[0]
        if item.state == 3:
            # Native ThreadMain12419 uses unsigned >=, including tick wrap.
            if now_ms >= item.next_tick:
                item.state = 0
            return None
        if item.state != 0:
            return None
        item.state = 1
        return item.request

    def accept(self, reply: bytes, now_ms: int) -> None:
        if not self.items or self.items[0].state != 1:
            raise SessionError("P5 queue has no outstanding request")
        item = self.items[0]
        result = active_reply_p5(
            item.request,
            reply,
            repeat_ms=item.repeat_ms,
            now_ms=now_ms,
            has_next=len(self.items) > 1,
        )
        item.state, item.next_tick = result["state"], result["next_tick"]
        # DualP5AT14520 updates DualBase+14 through vtable+28 (13620)
        # after every valid reply, including controls that leave state1.
        if self.dual:
            self.last_comm_time = now_ms

    def retry_current(self) -> None:
        if self.items:
            self.items[0].state = 0

    @property
    def finished(self) -> bool:
        return not self.items or (len(self.items) == 1 and self.items[0].state == 5)

    def report(self) -> dict[str, object]:
        def describe(item: P5ActiveItem) -> dict[str, int | str]:
            return {
                "request": item.request.hex(),
                "repeat_ms": item.repeat_ms,
                "state": item.state,
                "next_tick": item.next_tick,
            }

        return {
            "items": [describe(item) for item in self.items],
            "releases": [describe(item) for item in self.releases],
            "releasing": self.releasing,
            "dual": self.dual,
            "last_comm_time": self.last_comm_time,
        }


def routine_request_p5(template: bytes, routine_id: int, command: bytes = b"") -> bytes:
    """SingleRoutineActTstP5_DT 0x15a3: four-byte template, BE RID, command tail."""
    if type(routine_id) is not int or not 0 <= routine_id <= 65535:
        raise ValueError("Routine ID must fit uint16")
    if len(template) != 4 or len(command) > 65531:
        raise ToyotaCodecError(
            "Invalid native routine template/command size", INVALID_RECORD
        )
    return template[:2] + routine_id.to_bytes(2, "big") + command


def routine_status_p5(
    reply: bytes, expected_bytes: int, patterns: Sequence[bytes]
) -> bool:
    """Selected DB0x248 status patterns, native low16 matching at 0x1cd0.

    Expected byte length comes from PatDispVariable data length. Native compares
    only low16 after x86 shift-count wrapping; retain that even for long patterns.
    """
    if type(expected_bytes) is not int or not 0 <= expected_bytes <= 65531:
        raise ValueError("Routine status length outside native bounds")
    if len(reply) < expected_bytes + 4:
        raise ToyotaCodecError(
            "Routine response shorter than selected display data", SHORT_REPLY
        )
    payload = reply[4:]
    if not payload:
        return True
    if not patterns:
        raise SessionError("Routine status patterns were not selected")

    def native_value(data: bytes) -> int:
        result = 0
        for index, byte in enumerate(data):
            result |= (byte << (((len(data) - index - 1) * 8) & 31)) & 0xFFFFFFFF
        return result & 65535

    value = native_value(payload)
    if any(value == native_value(pattern) for pattern in patterns):
        return True
    raise ToyotaCodecError(
        "Routine status does not match selected completion patterns", 0xA004020D
    )


def _active_request(
    record: bytes,
    pattern: bytes,
    protocol: int,
    value: int,
    *,
    auxiliary: int = 0,
    support: bytes | None = None,
    psa: bool = False,
    comm_mode: bytes | None = None,
) -> tuple[bytes, int]:
    """DataMonitorPhase3 RVA 0x9e10 command-pattern interpreter.

    Returns native request and repeat-pattern key (zero disables repeat). Rows
    are already selected ActTest 0x20b and ActTestPattern 0x20c. Support bytes
    are the selected DID support list, required by protocol-low5 == 4.
    """
    if len(record) < 0x59 or len(pattern) < 0x15:
        raise ToyotaCodecError("Truncated active-test/pattern row", INVALID_RECORD)
    if type(protocol) is not int or not 0 <= protocol <= 255:
        raise ValueError("Protocol must be a byte")
    if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
        raise ValueError("Active-test value must fit uint32")
    if type(auxiliary) is not int or not 0 <= auxiliary <= 255:
        raise ValueError("Auxiliary value must fit byte")
    mode = protocol & 0x1F
    request = bytearray(
        (0x6D if mode in (1, 2) else 0x3D if mode == 7 else 0x30, record[0x52])
    )
    if psa:
        request[0] = 0x3D if mode == 7 else 0x30
        if comm_mode is not None:
            if len(comm_mode) < 3:
                raise ToyotaCodecError(
                    "Truncated PSA active communication mode", INVALID_RECORD
                )
            request[0] = comm_mode[2]
    if mode == 7:
        return bytes(request), 0
    if mode == 4 and support is None:
        raise SessionError("Selected active-test DID support is required")
    bits = struct.unpack_from("<H", record, 0x42)[0]
    shifted = (value << (7 - (struct.unpack_from("<H", record, 0x44)[0] & 7))) & 255
    instructions = struct.unpack_from("<H", record, 0x4A)[0]
    if not instructions:
        raise ToyotaCodecError("Empty active-test pattern", 0xC0050102)
    cursor = 0
    support_mode = False
    length = struct.unpack_from("<H", pattern, 8)[0] & 255
    length = length or 6
    for _ in range(4):
        opcode = instructions & 15
        instructions >>= 4
        if not opcode:
            break
        if support_mode and opcode not in (11, 12):
            assert support is not None
            if cursor >= len(support) or not support[cursor]:
                if psa:
                    raise ToyotaCodecError(
                        "PSA active parameter lacks DID support", 0xC0050443
                    )
                if cursor >= len(support):
                    break
                cursor += 1
                continue
        if opcode in (11, 12, 13) and mode != 4:
            raise ToyotaCodecError("Support pattern requires protocol 4", 0xC0050102)
        if opcode == 11:
            if len(request) != 2:
                raise ToyotaCodecError("Support length must be first", 0xC0050443)
            request.append(length)
            support_mode = True
            assert support is not None
            if bits // 8 > len(support):
                raise ToyotaCodecError(
                    "Support prefix exceeds DID list", INVALID_RECORD
                )
            request.extend(0 for item in support[: bits // 8] if item)
            cursor = bits // 8
            continue
        if opcode == 12:
            assert support is not None
            request.extend(0 for item in support[cursor:] if item)
            cursor = len(support)
            continue
        byte = {
            2: value,
            3: shifted,
            4: record[0x58],
            5: record[0x58],
            6: record[0x58] + value,
            7: length,
            8: auxiliary,
            10: value >> 8,
        }.get(opcode, 0)
        if opcode == 13:
            if not record[0x58]:
                raise ToyotaCodecError("Zero active-test support mask", 0xC0050102)
            assert support is not None
            if cursor >= len(support):
                raise ToyotaCodecError(
                    "Active mask exceeds DID support list", INVALID_RECORD
                )
            byte = record[0x58] & support[cursor]
            if psa and not byte:
                raise ToyotaCodecError(
                    "PSA active mask has no supported bits", 0xC0050443
                )
        request.append(byte & 255)
        cursor += 1
    if len(request) <= 2:
        raise ToyotaCodecError("Active-test pattern emitted no data", 0xC0050102)
    repeat_key = struct.unpack_from("<H", pattern, 2)[0] if pattern[0x14] else 0
    return bytes(request), repeat_key


def active_request_p3(
    record: bytes,
    pattern: bytes,
    protocol: int,
    value: int,
    *,
    auxiliary: int = 0,
    support: bytes | None = None,
) -> tuple[bytes, int]:
    """Native P3 selected ActTest/Pattern interpreter."""
    return _active_request(
        record, pattern, protocol, value, auxiliary=auxiliary, support=support
    )


# All 427 normalized instructions match P3; see private static comparison.
active_request_p4 = active_request_p3
active_request_dk = active_request_p3
active_request_dlc12 = active_request_p3


def active_request_psa(
    record: bytes,
    pattern: bytes,
    protocol: int,
    value: int,
    *,
    auxiliary: int = 0,
    support: bytes | None = None,
    comm_mode: bytes | None = None,
) -> tuple[bytes, int]:
    """PSA 0x6690: selected header override and stricter DID support failures."""
    return _active_request(
        record,
        pattern,
        protocol,
        value,
        auxiliary=auxiliary,
        support=support,
        psa=True,
        comm_mode=comm_mode,
    )


@dataclass(frozen=True)
class ActiveTest:
    start: tuple[str, ...]
    stop: tuple[str, ...]
    status: tuple[str, ...] = ()
    complete: Callable[[list[bytes]], bool] | None = None

    def __post_init__(self) -> None:
        if not self.start or not self.stop:
            raise ValueError("Active test requires explicit start and stop commands")


class ToyotaSession:
    """Bounded synchronous execution of already selected native descriptors.

    Exchange must impose its own blocking-I/O timeout. The host deadline is
    checked before AND after every call; Python cannot interrupt a blocked call.
    Cancellation cleanup uses a fresh bounded budget and bypasses the cancelled
    flag, so a selected stop sequence can still execute.
    """

    def __init__(
        self,
        exchange: Exchange,
        ecu: str,
        commands: Mapping[str, CommandSpec],
        *,
        limits: Limits | None = None,
        cancelled: Callable[[], bool] = lambda: False,
        clock: Callable[[], float] = time.monotonic,
        native_send: NativeSend | None = None,
        native_communication: NativeCommunication | None = None,
        native_transaction: Callable[[str, CommandSpec, bytes], bytes] | None = None,
        native_cleanup_transaction: Callable[[str, CommandSpec, bytes], bytes]
        | None = None,
        native_get_mode: Callable[[str], bytes] | None = None,
        native_set_mode: Callable[[str, bytes], None] | None = None,
        native_cleanup_set_mode: Callable[[str, bytes], None] | None = None,
    ):
        if not ecu:
            raise ValueError("Selected ECU identity required")
        self.exchange = exchange
        self.ecu = ecu
        self.commands = dict(commands)
        self.limits = limits or Limits()
        self.cancelled = cancelled
        self.clock = clock
        self.native_send = native_send
        self.native_transaction = native_transaction
        self.native_communication = native_communication
        self.native_cleanup_transaction = native_cleanup_transaction
        self.native_get_mode = native_get_mode
        self.native_set_mode = native_set_mode
        self.native_cleanup_set_mode = native_cleanup_set_mode
        self.active: ActiveTest | P5ActiveQueue | None = None
        self._stop_overrides: dict[str, CommandSpec] = {}
        self._p5_queue: P5ActiveQueue | None = None
        self.active_state = "idle"
        self.trace: list[dict[str, object]] = []
        self._deadline = 0.0
        self._remaining = 0

    def _begin(self) -> None:
        self._deadline = self.clock() + self.limits.seconds
        self._remaining = self.limits.exchanges

    def _check(self, cleanup: bool = False) -> None:
        if not cleanup and self.cancelled():
            raise Cancelled("Toyota operation cancelled")
        if self.clock() >= self._deadline:
            raise SessionError("Toyota operation deadline exceeded")

    def _call(
        self,
        request: bytes,
        *,
        cleanup: bool = False,
        spec: CommandSpec | None = None,
        receive_only: bool = False,
    ) -> bytes:
        self._check(cleanup)
        if self._remaining <= 0:
            raise SessionError("Toyota exchange budget exhausted")
        self._remaining -= 1
        event: dict[str, object] = {
            "ecu": self.ecu,
            "request": request.hex(),
            "receive_only": not request,
        }
        self.trace.append(event)
        try:
            transaction = (
                self.native_cleanup_transaction
                if cleanup and self.native_cleanup_transaction is not None
                else self.native_transaction
            )
            reply = (
                self._receive_can(spec)
                if receive_only
                else transaction(self.ecu, spec, request)
                if spec is not None and transaction is not None
                else self.exchange(self.ecu, request)
            )
        except ToyotaCodecError as error:
            event["native_status"] = error.code
            if isinstance(error, NativeStatus) and error.reply:
                event["partial_reply"] = error.reply.hex()
            self._check(cleanup)
            raise
        except BaseException as error:
            event["error"] = type(error).__name__
            self._check(cleanup)
            raise
        if not isinstance(reply, bytes):
            self._check(cleanup)
            raise TypeError("exchange must return bytes")
        event["reply"] = reply.hex()
        self._check(cleanup)
        return reply

    def _receive_can(self, spec: CommandSpec | None) -> bytes:
        """Common76240/76780 continuation: actual Receive, without SendInt."""
        from scripts.monitor_support import SupportQuery, SupportReceive
        from scripts.native_communication import NativeCommunication, receive_timeout

        communication = self.native_communication
        if (
            not isinstance(communication, NativeCommunication)
            or communication.ecu != self.ecu
            or spec is None
            or spec.selected is None
        ):
            raise SessionError(
                "CAN continuation requires retained selected communication"
            )
        selected = spec.selected
        communication.profile.validate_frame(selected)
        if len(selected.settings_record) != 16:
            raise ToyotaCodecError("CAN settings truncated", 0xC0040001)
        timeout = receive_timeout(
            communication.profile,
            spec.frame.request,
            communication.bus_id,
            struct.unpack_from("<I", selected.settings_record, 4)[0],
            communication.source_build,
        )
        query = SupportQuery(
            self.ecu,
            spec.frame.request,
            selected,
            communication.cache.identity,
            communication.bus_id,
            spec.extended,
        )
        status, reply = communication.receive(
            SupportReceive(
                query,
                4096 if spec.extended else 255,
                timeout,
                0,
                200 if not spec.extended and communication.bus_id == 0x0C else 100,
            )
        )
        if status:
            raise NativeStatus(status, reply)
        return reply

    def _native_retry_count(self, retries: int) -> int:
        # The typed provider executes the complete Common retry loop itself.
        return 0 if self.native_transaction is not None else retries

    def _spec(self, name: str) -> CommandSpec:
        try:
            return self.commands[name]
        except KeyError as error:
            raise SessionError(f"Command descriptor not selected: {name}") from error

    def native_frame_sends(
        self, calls: Sequence[NativeFrameSend], *, ignore_status: bool = False
    ) -> list[int]:
        """Execute literal sends under one budget, without an implicit receive.

        Mazda's native loop ignores returned native statuses. Host cancellation,
        deadlines, exhausted budgets and provider failures always propagate.
        """
        return self._frame_sends(calls, ignore_status=ignore_status)

    def _frame_sends(
        self,
        calls: Sequence[NativeFrameSend],
        *,
        ignore_status: bool = False,
        begin_operation: bool = True,
    ) -> list[int]:
        if self.native_send is None:
            raise SessionError("Native send provider was not injected")
        if any(not isinstance(call, NativeFrameSend) for call in calls):
            raise TypeError("Native sends require typed selected calls")
        if begin_operation:
            self._begin()
        statuses: list[int] = []
        for call in calls:
            self._check()
            if self._remaining <= 0:
                raise SessionError("Toyota exchange budget exhausted")
            self._remaining -= 1
            event: dict[str, object] = {
                "ecu": self.ecu,
                "operation": call.operation,
                "request": call.request.hex() if call.request is not None else None,
                "send_only": True,
                "command_id": call.command_id,
                "length": len(call.request) if call.request is not None else 0,
                "parameter4": call.parameter4,
                "parameter5": call.parameter5,
                "parameter6": call.parameter6,
                "parameter7": call.parameter7,
            }
            self.trace.append(event)
            try:
                status = self.native_send(self.ecu, call)
            except ToyotaCodecError as error:
                status = error.code
                event["native_status"] = status
                self._check()
                if not ignore_status:
                    raise
            except BaseException as error:
                event["error"] = type(error).__name__
                self._check()
                raise
            else:
                if type(status) is int and 0 <= status <= 0xFFFFFFFF:
                    event["native_status"] = status
                self._check()
            if type(status) is not int or not 0 <= status <= 0xFFFFFFFF:
                raise TypeError("Native send provider must return a uint32 status")
            event["native_status"] = status
            statuses.append(status)
            if status and not ignore_status:
                raise NativeStatus(status)
        return statuses

    def _diagnostic_mode(
        self, value: bytes | None = None, *, cleanup: bool = False
    ) -> bytes | None:
        self._check(cleanup)
        if self._remaining <= 0:
            raise SessionError("Toyota exchange budget exhausted")
        self._remaining -= 1
        event: dict[str, object] = {
            "ecu": self.ecu,
            "operation": "GetDiagnosticMode" if value is None else "SetDiagnosticMode",
            "cleanup": cleanup,
        }
        if value is not None:
            event["mode"] = value.hex()
        self.trace.append(event)
        try:
            if value is None:
                if self.native_get_mode is None:
                    raise SessionError("Diagnostic mode getter was not injected")
                result = self.native_get_mode(self.ecu)
                if not isinstance(result, bytes) or len(result) != 16:
                    raise TypeError("Diagnostic mode getter must return 16 bytes")
                event["mode"] = result.hex()
                return result
            setter = (
                self.native_cleanup_set_mode
                if cleanup and self.native_cleanup_set_mode is not None
                else self.native_set_mode
            )
            if setter is None:
                raise SessionError("Diagnostic mode setter was not injected")
            if setter(self.ecu, value) is not None:
                raise TypeError("Native SetDiagnosticMode is void")
            return None
        except ToyotaCodecError as error:
            event["native_status"] = error.code
            raise
        except BaseException as error:
            event["error"] = type(error).__name__
            raise
        finally:
            self._check(cleanup)

    @contextmanager
    def diagnostic_scope(self, mode_factory: Callable[[], bytes]) -> Iterator[None]:
        """Get mode, build selected mode, install, yield, restore its copy.

        Common62930/62a80 build CARB metadata after GetDiagnosticMode and select
        frame records after installation. The caller performs those local DB
        joins inside the factory/scope; no frame selection is performed early.
        """
        if self.native_get_mode is None or self.native_set_mode is None:
            raise SessionError("Diagnostic mode primitives were not injected")
        self._begin()
        previous = self._diagnostic_mode()
        assert previous is not None
        mode = mode_factory()
        if not isinstance(mode, bytes) or len(mode) != 16:
            raise ValueError("Selected diagnostic mode must be 16 bytes")
        failure: BaseException | None = None
        try:
            self._diagnostic_mode(mode)
            yield
        except BaseException as error:  # noqa: BLE001 - restore mode even after interruption
            failure = error
        self._begin()
        try:
            self._diagnostic_mode(previous, cleanup=True)
        except BaseException as error:
            if failure is not None:
                raise BaseExceptionGroup(
                    "Toyota diagnostic operation and mode restoration failed",
                    [failure, error],
                ) from None
            raise
        if failure is not None:
            raise failure

    def diagnostic_sequence(self, names: Sequence[str], mode: bytes) -> list[bytes]:
        """Temporary mode around ordinary selected frames, with bounded restore."""
        with self.diagnostic_scope(lambda: mode):
            specs = [self._spec(name) for name in names]
            return [self._native_call(spec, spec.frame.request) for spec in specs]

    def count_dtcs(
        self,
        names: Sequence[str],
        *,
        family: CountFamily = "plain",
        diagnostic_type: int = 1,
        retry_counts: Sequence[int] | None = None,
    ) -> dict[str, int]:
        """Original count wrappers: first frame not returning 91010009 wins.

        Frames must be selected for function 6+diagnostic_type. TT supports
        types1/2 only. VGRS drains receive-only calls until native no-response.
        """
        if family not in ("plain", "p4", "ac", "tt", "vgrs", "os_eng", "carb"):
            raise ValueError("Unknown native DTC count family")
        if type(diagnostic_type) is not int or diagnostic_type not in (
            (1,)
            if family == "carb"
            else (1, 2)
            if family in ("tt", "os_eng")
            else (1, 2, 3)
        ):
            raise ToyotaCodecError("Unsupported diagnostic count type", 0xC0040001)
        selected = [self._spec(name) for name in names]
        if not selected:
            raise ToyotaCodecError("No selected diagnostic count frames", 0xC0040101)
        retries = (
            tuple(retry_counts) if retry_counts is not None else (0,) * len(selected)
        )
        if len(retries) != len(selected) or any(
            type(value) is not int or not 0 <= value <= 255 for value in retries
        ):
            raise ValueError("Count retries must match selected ComSet bytes")
        retries = tuple(self._native_retry_count(value) for value in retries)
        self._begin()
        for index, descriptor in enumerate(selected):
            reply: bytes | None = None
            for attempt in range(retries[index] + 1):
                try:
                    reply = self._native_call(
                        replace(descriptor, check="sid", payload_offset=0),
                        descriptor.frame.request,
                    )
                    break
                except ToyotaCodecError as error:
                    if error.code != 0x90020323 and attempt < retries[index]:
                        continue
                    if error.code != 0x91010009:
                        raise
            if reply is None:
                continue
            offset = 1 if family == "p4" else 2
            if family in ("ac", "os_eng"):
                offset = 3 if diagnostic_type == 2 else 2
            if family == "carb":
                if len(descriptor.frame.receive_mask) < 3:
                    raise ToyotaCodecError(
                        "CARB count mask lacks byte2", INVALID_RECORD
                    )
                if len(reply) < len(descriptor.frame.receive_mask) or len(reply) < 3:
                    raise ToyotaCodecError(
                        "CARB count reply shorter than mask", SHORT_REPLY
                    )
                count = reply[2] & descriptor.frame.receive_mask[2]
            elif family == "tt":
                if len(reply) <= 2:
                    raise ToyotaCodecError("Truncated TT diagnostic count", SHORT_REPLY)
                count = (
                    reply[2] if len(reply) == 3 else reply[3] if len(reply) == 4 else 0
                )
            else:
                if len(reply) <= offset:
                    raise ToyotaCodecError(
                        "Truncated diagnostic count",
                        0x90040501 if family in ("ac", "os_eng") else SHORT_REPLY,
                    )
                count = reply[offset]
            if family == "vgrs":
                while True:
                    try:
                        self._call(b"")
                    except ToyotaCodecError as error:
                        if error.code == 0x91010009:
                            break
                        # The native drain ignores every other receive status.
            result = {
                "diagnostic_type": diagnostic_type,
                "count": count,
                "selected_frame": index,
            }
            if family not in ("p4", "os_eng"):
                result["shared_data_0d"] = index & 0xFF
            if family == "os_eng":
                result["reply_length"] = len(reply) & 0xFF
            return result
        raise NativeStatus(
            0x90040501
            if family in ("plain", "ac", "vgrs", "os_eng", "carb")
            else 0x91010009
        )

    def count_dtcs_profile(
        self,
        profile: VehicleProfile,
        *,
        family: CountFamily = "plain",
        diagnostic_type: int = 1,
    ) -> dict[str, int]:
        """Resolve native function7/8/9 through the actual selected profile."""
        if type(diagnostic_type) is not int or diagnostic_type not in (
            (1,)
            if family == "carb"
            else (1, 2)
            if family in ("tt", "os_eng")
            else (1, 2, 3)
        ):
            raise ToyotaCodecError("Unsupported diagnostic count type", 0xC0040001)
        frames = _profile_frames(profile, 6 + diagnostic_type)
        # Local descriptors keep profile source order and provenance. They do
        # not replace any caller-owned named command descriptors.
        commands = self.commands
        try:
            self.commands = {
                str(index): CommandSpec(
                    frame.frame, provenance=frame.provenance, selected=frame
                )
                for index, frame in enumerate(frames)
            }
            return self.count_dtcs(
                tuple(self.commands),
                family=family,
                diagnostic_type=diagnostic_type,
                retry_counts=[frame.settings_record[14] for frame in frames],
            )
        finally:
            self.commands = commands

    def count_dtcs_os_eng_profile(
        self,
        profile: VehicleProfile,
        diagnostic_type: int,
        *,
        connection_bus_id: int | None = None,
    ) -> dict[str, int]:
        """Common20e00 selected length-count and 7D/7E mask probes.

        The exceptional InitEcu branch requires an observed connection-cache
        bus, and performs an explicit NULL send with ignored native status.
        """
        result = self.count_dtcs_profile(
            profile, family="os_eng", diagnostic_type=diagnostic_type
        )
        result["native_40_idling"] = 0
        if not result["count"] or diagnostic_type == 2:
            return result
        for function_id in (0x7D, 0x7E):
            frames = _profile_frames(profile, function_id)
            if not frames:
                raise ToyotaCodecError("No selected OsEng probe frames", 0xC0040101)
            if len(frames) != 1:
                raise ToyotaCodecError("OsEng probe requires one frame", 0xC0040102)
            frame = frames[0]
            selected = CommandSpec(
                frame.frame, provenance=frame.provenance, selected=frame
            )
            try:
                for attempt in range(
                    self._native_retry_count(frame.settings_record[14]) + 1
                ):
                    try:
                        reply = self._native_call(selected, selected.frame.request)
                        break
                    except ToyotaCodecError as error:
                        if (
                            error.code == 0x90020323
                            or attempt
                            == self._native_retry_count(frame.settings_record[14])
                        ):
                            raise
            except ToyotaCodecError as error:
                if function_id != 0x7D or error.code not in (0x91010009, 0x90020323):
                    raise
                if connection_bus_id is None:
                    raise ToyotaCodecError(
                        "Connection cache for InitEcu absent", 0xC0040601
                    ) from error
                self._frame_sends(
                    [
                        NativeFrameSend(
                            "SendInt",
                            profile.category,
                            None,
                            struct.unpack_from("<I", frame.settings_record)[0],
                            connection_bus_id,
                            1,
                            1,
                        )
                    ],
                    ignore_status=True,
                    begin_operation=False,
                )
                return result
            mask, expected = frame.frame.receive_mask, frame.frame.receive_check
            mask_size = len(mask) & 0xFF
            if (
                not mask_size
                or not reply
                or len(reply) < mask_size
                or len(expected) < mask_size
            ):
                raise ToyotaCodecError("Invalid OsEng probe mask bounds", 0xC0040102)
            matches = all(
                reply[index] & mask[index] == expected[index]
                for index in range(mask_size)
            )
            if function_id == 0x7D and matches:
                return result
            if function_id == 0x7E:
                if matches:
                    result["native_40_idling"] = 1
                else:
                    result["count"] = 0
        return result

    def _native_call(
        self, spec: CommandSpec, request: bytes, *, extended: bool = False
    ) -> bytes:
        """Native ordinary/extended frame helpers always check positive SID."""
        selected = replace(
            spec,
            frame=replace(spec.frame, request=request),
            check="both" if spec.check in ("mask", "both") else "sid",
            extended=extended,
            payload_offset=0,
        )
        reply = self._call(request, spec=selected)
        if (
            not reply
            or len(reply) > (65535 if extended else 255)
            or reply[0] != request[0] | 0x40
        ):
            raise ToyotaCodecError(
                "Invalid native response service/length", INVALID_REPLY
            )
        selected.validate(reply)
        return reply

    def _execute(
        self, name: str, *, cleanup: bool = False, request: bytes | None = None
    ) -> bytes:
        spec = (
            self._stop_overrides.get(name, self._spec(name))
            if cleanup
            else self._spec(name)
        )
        if request is not None:
            spec = replace(spec, frame=replace(spec.frame, request=request))
        return spec.validate(self._call(spec.frame.request, cleanup=cleanup, spec=spec))

    def execute(self, name: str) -> bytes:
        self._begin()
        return self._execute(name)

    def sequence(self, names: Sequence[str]) -> list[bytes]:
        # Validate all dependencies before the first potentially stateful command.
        for name in names:
            self._spec(name)
        self._begin()
        return [self._execute(name) for name in names]

    def dtcs(self, name: str, *, retries: int = 0, mask_flags: int = 0) -> list[int]:
        """KWP native continuation/retry; timeout after a full chunk is success.

        Retry count is ComSet +0x0e; injected caller supplies it. 0x90020323
        bypasses MaskCommError. A masked terminal error clears the whole list.
        """
        return self._kwp_dtcs((self._spec(name),), retries, mask_flags)

    def _kwp_dtcs(
        self,
        specs: Sequence[CommandSpec],
        retries: int,
        mask_flags: int,
        *,
        begin_operation: bool = True,
        selected_profile: VehicleProfile | None = None,
    ) -> list[int]:
        if type(retries) is not int or not 0 <= retries <= 255:
            raise ValueError("Retry count must fit ComSet byte")
        mask_comm_error(0, mask_flags)
        if not specs:
            raise ToyotaCodecError("No selected KWP DTC frames", 0xC0040101)
        if begin_operation:
            self._begin()
        codes: list[int] = []
        receive_started = False
        last_error: ToyotaCodecError | None = None
        for spec in specs:
            for attempt in range(retries + 1):
                request = b"" if receive_started else spec.frame.request
                chunks = 0
                last_count = 0
                while True:
                    try:
                        reply = self._call(request)
                        chunk = parse_kwp_dtc_reply(spec.frame.request, reply)
                        receive_started = True
                    except ToyotaCodecError as error:
                        if error.code == 0x90020323:
                            raise
                        if error.code == 0x91010009 and chunks and last_count == 3:
                            return codes
                        if attempt < retries:
                            break
                        if mask_comm_error(error.code, mask_flags) == 0:
                            return []
                        last_error = error
                        break
                    for code in chunk.codes:
                        if (
                            selected_profile is None
                            or dtc_metadata_profile(selected_profile, code) is not None
                        ):
                            codes.append(code)
                    if not chunk.needs_more:
                        return codes
                    chunks += 1
                    last_count = len(chunk.codes)
                    request = b""
        assert last_error is not None
        raise last_error

    def dtcs_profile(
        self, profile: VehicleProfile, function_id: int, *, mask_flags: int = 0
    ) -> list[int]:
        """Common75810 selected KWP frame chain with shared receive state.

        The native byte argument preceding output-list is unused; it does not
        select a frame. Settings come from the FIRST selected function row.
        """
        frames = _profile_frames(profile, function_id)
        return self._kwp_dtcs(
            [
                CommandSpec(frame.frame, provenance=frame.provenance, selected=frame)
                for frame in frames
            ],
            frames[0].settings_record[14] if frames else 0,
            mask_flags,
            selected_profile=profile,
        )

    def dtcs_plain_profile(
        self,
        profile: VehicleProfile,
        diagnostic_type: int,
        functions: FunctionCache,
        *,
        shared_data_0d: int | None = None,
        connection_bus_id: int | None = None,
    ) -> dict[str, object]:
        """GetDiagCode Execute1010: DB113-selected count module before KWP.

        Native CountSnd is command0x13. Its cloned diagnostic type is WORD;
        the outer GetDiagCode checks the original DWORD only after positive
        count and the shared0D lookup. No vendor module is loaded or executed.
        """
        if type(diagnostic_type) is not int or not 0 <= diagnostic_type <= 0xFFFFFFFF:
            raise ValueError("Diagnostic type must fit native DWORD")
        if shared_data_0d is not None and (
            type(shared_data_0d) is not int or not 0 <= shared_data_0d <= 255
        ):
            raise ValueError("Shared0D observation must fit byte")
        rows = profile.dll_records(0x13)
        if not rows:
            raise ToyotaCodecError("Selected count DLL group empty", 0xC0040101)
        row = rows[0]
        module = row[:80].decode("utf-16le").split("\0", 1)[0]
        filename = module.replace("\\", "/").rsplit("/", 1)[-1].casefold()
        families: dict[str, CountFamily] = {
            "getdiagcodecount.dll": "plain",
            "getdiagcodecountp4.dll": "p4",
            "getdiagcodecount_ac.dll": "ac",
            "getdiagcodecount_tt.dll": "tt",
            "getdiagcodecount_vgrs.dll": "vgrs",
        }
        count_type = diagnostic_type & 65535
        if filename in families:
            count: dict[str, object] = dict(
                self.count_dtcs_profile(
                    profile, family=families[filename], diagnostic_type=count_type
                )
            )
        elif filename == "getdiagcodecount_oseng.dll":
            count = dict(
                self.count_dtcs_os_eng_profile(
                    profile, count_type, connection_bus_id=connection_bus_id
                )
            )
        elif filename == "getdiagcodecountdkiso9141.dll":
            count = dict(self.count_dtcs_dk_iso_profile(profile, count_type))
        elif filename == "getdiagcodecount_wcode.dll":
            count = self.count_dtcs_with_codes_profile(profile, count_type)
        else:
            raise SessionError(
                f"Selected count module has no recovered implementation: {module}"
            )
        if count["count"] == 0:
            return {
                "codes": [],
                "freeze_records": (),
                "count_observation": count,
                "count_module": module,
            }
        shared = count.get("shared_data_0d", shared_data_0d)
        if shared is None:
            raise ToyotaCodecError(
                "Shared0D cache absent after positive count", 0xC0040601
            )
        if diagnostic_type not in (1, 2, 3):
            raise ToyotaCodecError("Unsupported outer diagnostic type", 0xC0040001)
        frames = _profile_frames(profile, 9 + diagnostic_type)
        codes = self._kwp_dtcs(
            [
                CommandSpec(frame.frame, provenance=frame.provenance, selected=frame)
                for frame in frames
            ],
            frames[0].settings_record[14],
            0,
            begin_operation=False,
            selected_profile=profile,
        )
        records = tuple(DtcFreeze(code) for code in codes)
        if codes:
            _, supported = functions.function(1, 4, 3)
            if supported:
                records = self._freeze_support_profile(profile, records, 0)
        return {
            "codes": codes,
            "freeze_records": records,
            "count_observation": count,
            "count_module": module,
        }

    def dtcs_without_count_profile(
        self,
        profile: VehicleProfile,
        diagnostic_type: int,
        functions: FunctionCache,
    ) -> dict[str, object]:
        """GetDiagCode_woCount Execute1010: count, KWP, optional basic FFD.

        Despite its exported name, the original propagates count-stage errors
        and reads the DTC list even when the preliminary count is zero.
        """
        return self._dtcs_counted_profile(profile, diagnostic_type, functions)

    def dtcs_os_eng_profile(
        self,
        profile: VehicleProfile,
        diagnostic_type: int,
        functions: FunctionCache,
        *,
        connection_bus_id: int | None = None,
    ) -> dict[str, object]:
        """GetDiagCode_OsEng Execute1010 and bounded local reader1320.

        Current uses literal130000. Count determines receive calls in groups
        of three; zero codes are skipped, never terminate this native reader.
        The passed Get40Idling argument is unused by the original local reader.
        """
        count = self.count_dtcs_os_eng_profile(
            profile, diagnostic_type, connection_bus_id=connection_bus_id
        )
        codes: list[int] = []
        records: tuple[DtcFreeze, ...] = ()
        if not count["count"]:
            return {
                "codes": codes,
                "freeze_records": records,
                "count_observation": count,
            }
        frames = _profile_frames(profile, 9 + diagnostic_type)
        selected = frames[0]
        request = b"\x13\x00\x00" if diagnostic_type == 1 else selected.frame.request
        if not 1 <= len(request) <= 8 or len(selected.frame.request) > 8:
            raise ToyotaCodecError(
                "OsEng native request exceeds stack buffer", INVALID_RECORD
            )
        receive_started = False
        chunks = (count["count"] + 2) // 3
        last_error: ToyotaCodecError | None = None
        for attempt in range(selected.settings_record[14] + 1):
            for _ in range(chunks):
                try:
                    reply = self._call(b"" if receive_started else request)
                    if not 2 <= len(reply) <= 8 or reply[0] != request[0] | 0x40:
                        raise ToyotaCodecError(
                            "OsEng diagnostic reply service/length invalid",
                            INVALID_REPLY,
                        )
                    receive_started = True
                except ToyotaCodecError as error:
                    last_error = error
                    break
                for offset in range(1, min(len(reply) - 1, 6), 2):
                    code = int.from_bytes(reply[offset : offset + 2], "big")
                    if code and dtc_metadata_profile(profile, code) is not None:
                        codes.append(code)
            else:
                break
        else:
            assert last_error is not None
            raise last_error
        records = tuple(DtcFreeze(code) for code in codes)
        _, supported = functions.function(1, 4, 3)
        if supported:
            records = self._freeze_support_profile(profile, records, 0)
        return {"codes": codes, "freeze_records": records, "count_observation": count}

    def dtcs_carb_profile(
        self,
        profile: VehicleProfile,
        functions: FunctionCache,
        *,
        diagnostic_type: int = 1,
    ) -> dict[str, object]:
        """GetDiagCode_CARB Execute1460; masked count gates functionA read."""
        count = self.count_dtcs_profile(
            profile, family="carb", diagnostic_type=diagnostic_type
        )
        codes: list[int] = []
        records: tuple[DtcFreeze, ...] = ()
        if count["count"]:
            frames = _profile_frames(profile, 0x0A)
            codes = self._kwp_dtcs(
                [
                    CommandSpec(
                        frame.frame, provenance=frame.provenance, selected=frame
                    )
                    for frame in frames
                ],
                frames[0].settings_record[14],
                0,
                begin_operation=False,
                selected_profile=profile,
            )
            records = tuple(DtcFreeze(code) for code in codes)
            if codes:
                _, supported = functions.function(1, 4, 3)
                if supported:
                    records = self._freeze_support_profile(profile, records, 0)
        return {"codes": codes, "freeze_records": records, "count_observation": count}

    def dtcs_no_frame_number_profile(
        self, profile: VehicleProfile, diagnostic_type: int, functions: FunctionCache
    ) -> dict[str, object]:
        """GetDiagCode_NoFrmNo Execute1480 and local FFD helper1050."""
        return self._dtcs_counted_profile(
            profile, diagnostic_type, functions, no_frame_number=True
        )

    def _dtcs_counted_profile(
        self,
        profile: VehicleProfile,
        diagnostic_type: int,
        functions: FunctionCache,
        *,
        no_frame_number: bool = False,
    ) -> dict[str, object]:
        count = self.count_dtcs_profile(profile, diagnostic_type=diagnostic_type)
        frames = _profile_frames(profile, 9 + diagnostic_type)
        codes = self._kwp_dtcs(
            [
                CommandSpec(frame.frame, provenance=frame.provenance, selected=frame)
                for frame in frames
            ],
            frames[0].settings_record[14],
            0,
            begin_operation=False,
            selected_profile=profile,
        )
        records = tuple(DtcFreeze(code) for code in codes)
        if codes:
            _, supported = functions.function(1, 4, 3)
            if supported:
                records = self._freeze_support_profile(
                    profile, records, 0, no_frame_number=no_frame_number
                )
        return {"codes": codes, "freeze_records": records, "count_observation": count}

    def freeze_support_profile(
        self,
        profile: VehicleProfile,
        records: Sequence[DtcFreeze],
        *,
        mask_flags: int = 0,
    ) -> tuple[DtcFreeze, ...]:
        """Common76d20 basic FFD association using selected function6/DB202."""
        self._begin()
        return self._freeze_support_profile(profile, records, mask_flags)

    def _freeze_support_profile(
        self,
        profile: VehicleProfile,
        records: Sequence[DtcFreeze],
        mask_flags: int,
        *,
        no_frame_number: bool = False,
        trailing_code: bool = False,
    ) -> tuple[DtcFreeze, ...]:
        mask_comm_error(0, mask_flags)
        frames = _profile_frames(profile, 6)
        if len(frames) != 1:
            raise ToyotaCodecError(
                "Basic freeze support requires one frame", 0xC0040102
            )
        selected = frames[0]
        rows = profile.records(2)
        if any(len(row) != 4 for row in rows):
            raise ToyotaCodecError("Invalid selected SupFreeze row", INVALID_RECORD)
        result = tuple(records)
        for row in rows:
            number = row[2]
            request = freeze_support_request(selected.frame.request, number)
            spec = CommandSpec(
                replace(selected.frame, request=request),
                provenance=selected.provenance,
                selected=selected,
            )
            try:
                for attempt in range(
                    self._native_retry_count(selected.settings_record[14]) + 1
                ):
                    try:
                        reply = self._native_call(spec, request)
                        break
                    except ToyotaCodecError as error:
                        if (
                            error.code == 0x90020323
                            or attempt
                            == self._native_retry_count(selected.settings_record[14])
                        ):
                            raise
            except ToyotaCodecError as error:
                if (
                    error.code == 0x91010009
                    or mask_comm_error(error.code, mask_flags) == 0
                ):
                    continue
                raise
            if trailing_code:
                if len(reply) < len(request) + 2:
                    raise ToyotaCodecError(
                        "DK freeze code response too short", SHORT_REPLY
                    )
                code = int.from_bytes(reply[-2:], "big")
            elif no_frame_number:
                if len(reply) not in (4, 5):
                    raise ToyotaCodecError(
                        "NoFrmNo freeze code response length invalid", SHORT_REPLY
                    )
                code = int.from_bytes(reply[-2:], "big")
            else:
                code = freeze_support_code(selected.frame, reply)
            result, _ = associate_freeze(result, code, number)
        return result

    def count_dtcs_with_codes_profile(
        self, profile: VehicleProfile, diagnostic_type: int
    ) -> dict[str, object]:
        """GetDiagCodeCount_wCode: P3 count stage, then actual KWP list count."""
        result = self.count_dtcs_profile(profile, diagnostic_type=diagnostic_type)
        frames = _profile_frames(profile, 9 + diagnostic_type)
        codes = self._kwp_dtcs(
            [
                CommandSpec(frame.frame, provenance=frame.provenance, selected=frame)
                for frame in frames
            ],
            frames[0].settings_record[14] if frames else 0,
            0,
            begin_operation=False,
            selected_profile=profile,
        )
        return {**result, "count": len(codes) & 0xFF, "codes": codes}

    def dtcs_dlc12_profile(
        self, profile: VehicleProfile, client: NativeVimClient
    ) -> list[int]:
        """GetDiagCodeDLC12 -> literal ComTol307F request and CCmdBuffer reply.

        This explicit client uses the existing compact native VIM transport;
        ordinary diagnostic exchange is not substituted for the ComTol ABI.
        """
        from scripts.drive_recorder import NativeVimError

        frames = _profile_frames(profile, 0x0A)
        if len(frames) != 1:
            raise ToyotaCodecError(
                "DLC12 requires exactly one selected frame", 0xC0040102
            )
        frame = frames[0].frame
        if not frame.request or len(frame.receive_mask) < 2:
            raise ToyotaCodecError("DLC12 selector/mask bytes absent", INVALID_RECORD)
        payload = frame.request[:1] + frame.receive_mask[:2]
        self._begin()
        self._check()
        if self._remaining <= 0:
            raise SessionError("Toyota exchange budget exhausted")
        self._remaining -= 1
        event: dict[str, object] = {
            "ecu": self.ecu,
            "operation": "ComTol307F",
            "request": payload.hex(),
        }
        self.trace.append(event)
        try:
            reply = client.call(
                0x307F,
                payload,
                timeout=self._deadline - self.clock(),
                cancelled=self.cancelled,
            )
            event["reply"] = reply.payload.hex()
        except NativeVimError as error:
            if error.reply.control != 0x15:
                raise
            native = error.reply.error
            # ComTol04320 maps transport/NAK status before the reply-object
            # status at7e45 is inspected. Reply-object statuses stay literal.
            status = (
                8
                if native in (0x900D0017, 0x900D0018)
                else 7
                if native & 0xFFFF0000
                else native
            )
            event["native_status"] = status
            raise NativeStatus(status) from error
        finally:
            self._check()
        data = reply.payload
        if len(data) < 12:
            raise ToyotaCodecError("Truncated DLC12 native status/buffer", SHORT_REPLY)
        status, _, _, size = struct.unpack_from("<IHHI", data)
        if size != len(data) - 12:
            raise ToyotaCodecError("DLC12 CCmdBuffer size invalid", SHORT_REPLY)
        event["native_status"] = status
        if status:
            raise NativeStatus(status)
        # ComTol7e55 truncates CCmdBuffer.GetSize to BYTE and copies precisely
        # that many elements. Zero codes are retained by SetDiagCodeData here.
        return [
            code
            for code in data[12 : 12 + (size & 255)]
            if dtc_metadata_profile(profile, code) is not None
        ]

    def dtcs_can_profile(
        self,
        profile: VehicleProfile,
        diagnostic_type: int,
        functions: FunctionCache,
        *,
        family: Literal["p4", "p4_v2", "carb_can", "dk"] = "p4_v2",
    ) -> dict[str, object]:
        """Selected GetDiagCodeP4/P4V2/CARBCAN/Dk wrappers, no count stage.

        Both pass frame-index zero. Common76240's zero disables advancing to
        another frame after failure; the remaining selected frames are unused.
        P4V2 omits basic FFD for type3 and masks its communication errors with2;
        P4 uses mask0; CARBCAN uses extended receive and mask0 for all types.
        Dk uses ordinary CAN and last-two-byte FFD for all types.
        """
        if family not in ("p4", "p4_v2", "carb_can", "dk"):
            raise ValueError("Unknown selected CAN diagnostic wrapper")
        if type(diagnostic_type) is not int or diagnostic_type not in (1, 2, 3):
            raise ToyotaCodecError("Unsupported diagnostic type", 0xC0040001)
        frames = _profile_frames(profile, 9 + diagnostic_type)
        selected = frames[0]
        previous = self.commands
        try:
            self.commands = {
                "native-can": CommandSpec(
                    selected.frame, provenance=selected.provenance, selected=selected
                )
            }
            codes = self.dtcs_can(
                "native-can",
                extended=family == "carb_can",
                retries=selected.settings_record[14],
                selected_profile=profile,
            )
        finally:
            self.commands = previous
        records = tuple(DtcFreeze(code) for code in codes)
        if codes and (family in ("carb_can", "dk") or diagnostic_type != 3):
            _, supported = functions.function(1, 4, 3)
            if supported:
                records = self._freeze_support_profile(
                    profile,
                    records,
                    2 if family == "p4_v2" else 0,
                    trailing_code=family == "dk",
                )
        return {"codes": codes, "freeze_records": records}

    def dtcs_can(
        self,
        name: str,
        *,
        extended: bool = False,
        dk: bool = False,
        sienna: bool = False,
        retries: int = 0,
        mask_flags: int = 0,
        selected_profile: VehicleProfile | None = None,
        output: dict[str, object] | None = None,
    ) -> list[int]:
        """CommandCommon 0x76240/0x76780 counted CAN DTC receive loops.

        Ordinary replies contain SID,count,DTC16 pairs. Extended receives use
        4096-byte capacity and continue until a zero count or timeout following
        at least one result. No bus protocol numbers are inferred here.
        """
        if type(retries) is not int or not 0 <= retries <= 255:
            raise ValueError("Retry count must fit ComSet byte")
        if sum((extended, dk, sienna)) > 1:
            raise ValueError(
                "DK, extended and Sienna are distinct native receive variants"
            )
        mask_comm_error(0, mask_flags)
        spec = self._spec(name)
        self._begin()
        codes: list[int] = []
        records: list[DtcFreeze] = []
        if output is not None:
            output.update(codes=codes, freeze_records=records)
        retained_stream = self.native_communication is not None
        retries = retries if retained_stream else self._native_retry_count(retries)
        retry_budget = retries
        receive_started = False
        for attempt in range(retries + 1):
            request = b"" if receive_started else spec.frame.request
            chunks = received = 0
            count = -1
            while True:
                projecting = False
                try:
                    reply = self._call(
                        request,
                        spec=replace(
                            spec,
                            extended=extended,
                            receive_capacity=4096 if extended else None,
                        )
                        if request or retained_stream
                        else None,
                        receive_only=not request and retained_stream,
                    )
                    if (
                        request
                        and retained_stream
                        and self.native_transaction is not None
                    ):
                        communication = self.native_communication
                        assert communication is not None
                        initial = communication.last_result
                        if initial is None or initial.selected is not spec.selected:
                            raise SessionError(
                                "CAN initial typed attempt record absent"
                            )
                        retry_budget = max(0, retries - (initial.attempts - 1))
                    if extended:
                        receive_started = True
                    if not 2 <= len(reply) <= (4096 if extended else 255):
                        raise ToyotaCodecError(
                            "CAN DTC response outside buffer", SHORT_REPLY
                        )
                    if reply[0] != spec.frame.request[0] | 0x40:
                        raise ToyotaCodecError(
                            "Unexpected CAN DTC service", INVALID_REPLY
                        )
                    receive_started = True
                    if sienna:
                        reply = normalize_sienna_dtcs(reply)
                    count = reply[1]
                    if not count:
                        return codes
                    pair_count = (len(reply) - 2) // 2
                    for offset in range(2, 2 + pair_count * 2, 2):
                        code = int.from_bytes(reply[offset : offset + 2], "big")
                        if code == 0:
                            return codes
                        projecting = True
                        if (
                            selected_profile is None
                            or dtc_metadata_profile(selected_profile, code) is not None
                        ):
                            codes.append(code)
                            if output is not None:
                                records.append(DtcFreeze(code))
                        projecting = False
                    received = (received + pair_count) & (
                        0xFFFFFFFF if extended else 255
                    )
                    if not extended and not dk and not sienna and received >= count:
                        return codes
                except ToyotaCodecError as error:
                    if projecting:
                        raise
                    if not extended and error.code == 0x90020323:
                        raise
                    if (
                        error.code == 0x91010009
                        and chunks
                        and (
                            extended
                            or (dk and received == count)
                            or (sienna and received == 0)
                        )
                    ):
                        return codes
                    if attempt < retry_budget and (
                        not request or self.native_transaction is None
                    ):
                        break
                    if extended and mask_comm_error(error.code, mask_flags) == 0:
                        return []
                    raise
                chunks += 1
                request = b""
        raise AssertionError("Unreachable CAN DTC retry state")

    def dtcs_psa_audio(
        self, first: str, overflow: str, diagnostic_type: int, *, retries: int = 0
    ) -> list[int]:
        """PSA Audio overflow polling; native partial 90020321/byte2=12 ends it."""
        if type(retries) is not int or not 0 <= retries <= 255:
            raise ValueError("PSA retry count must fit ComSet byte")
        if type(diagnostic_type) is not int or not 0 <= diagnostic_type <= 0xFFFFFFFF:
            raise ValueError("Diagnostic type must fit uint32")
        if first == overflow:
            raise ValueError("PSA Audio first/overflow stages must be distinct names")
        self._spec(first)
        self._spec(overflow)
        self._begin()
        name = first
        codes: list[int] = []
        expected = received = 0
        while True:
            spec = self._spec(name)
            for attempt in range(retries + 1):
                try:
                    reply = self._call(spec.frame.request)
                    replace(
                        spec, check="sid", extended=True, payload_offset=0
                    ).validate(reply)
                    if len(reply) < 2:
                        raise ToyotaCodecError(
                            "PSA Audio missing count prefix", SHORT_REPLY
                        )
                    if name == first and not reply[1]:
                        return codes
                    entries = parse_psa_audio_dtcs(reply, diagnostic_type)
                    break
                except ToyotaCodecError as error:
                    if (
                        name == overflow
                        and isinstance(error, NativeStatus)
                        and error.code == 0x90020321
                        and len(error.reply) > 2
                        and error.reply[2] == 0x12
                    ):
                        return codes
                    if attempt < retries and error.code in (0x91010009, INVALID_REPLY):
                        continue
                    raise
            codes.extend(entries)
            if name == first:
                expected = reply[1]
            received = (received + (((len(reply) - 2) // 2) & 255)) & 255
            if expected < 10 or received >= expected:
                return codes
            name = overflow

    def dtcs_psa_add_ht(self, name: str, *, retries: int = 0) -> list[int]:
        if type(retries) is not int or not 0 <= retries <= 255:
            raise ValueError("PSA retry count must fit ComSet byte")
        spec = self._spec(name)
        self._begin()
        for attempt in range(retries + 1):
            try:
                reply = self._call(spec.frame.request)
                replace(spec, check="sid", extended=True, payload_offset=0).validate(
                    reply
                )
                return parse_psa_add_ht_dtcs(reply)
            except ToyotaCodecError as error:
                if attempt < retries and error.code in (0x91010009, INVALID_REPLY):
                    continue
                raise
        raise AssertionError("Unreachable AddHt retry state")

    def _dk_iso_call(self, spec: CommandSpec, retries: int) -> bytes:
        """Common5c450 native nonempty-byte-length check, WITHOUT SID check."""
        if not 1 <= len(spec.frame.request) <= 255:
            raise ToyotaCodecError("DK ISO request outside byte bounds", INVALID_RECORD)
        for attempt in range(retries + 1):
            try:
                reply = self._call(spec.frame.request)
                if not 1 <= len(reply) <= 255:
                    raise ToyotaCodecError(
                        "DK ISO reply outside byte bounds", INVALID_REPLY
                    )
                return replace(
                    spec,
                    payload_offset=0,
                    check="mask" if spec.check in ("mask", "both") else "raw",
                ).validate(reply)
            except ToyotaCodecError:
                if attempt == retries:
                    raise
        raise AssertionError("Unreachable DK ISO retry state")

    def dtcs_dk_iso(self, name: str, *, retries: int = 0) -> list[int]:
        """Native DK ISO sends/retries without positive-SID validation."""
        if type(retries) is not int or not 0 <= retries <= 255:
            raise ValueError("DK ISO retry count must fit ComSet byte")
        spec = self._spec(name)
        self._begin()
        reply = self._dk_iso_call(spec, retries)
        return parse_dk_iso_dtcs(reply[spec.payload_offset :])

    def dtcs_dk_iso_profile(
        self, profile: VehicleProfile, function_id: int
    ) -> list[int]:
        """Common7ba90 sends ALL selected frames, consumes FIRST full reply."""
        frames = _profile_frames(profile, function_id)
        if not frames:
            raise ToyotaCodecError("No selected DK ISO frames", 0xC0040101)
        self._begin()
        replies = [
            self._dk_iso_call(
                CommandSpec(
                    frame.frame,
                    check="raw",
                    provenance=frame.provenance,
                    selected=frame,
                ),
                frame.settings_record[14],
            )
            for frame in frames
        ]
        return [
            code
            for code in parse_dk_iso_dtcs(replies[0])
            if dtc_metadata_profile(profile, code) is not None
        ]

    def dtcs_dk_iso_wrapper_profile(
        self, profile: VehicleProfile, diagnostic_type: int, functions: FunctionCache
    ) -> dict[str, object]:
        """GetDiagCodeDkIso9141 Execute1010 and Common7BD10 raw BYTE FFD."""
        if type(diagnostic_type) is not int or diagnostic_type not in (1, 2, 3):
            raise ToyotaCodecError("Unsupported diagnostic type", 0xC0040001)
        codes = self.dtcs_dk_iso_profile(profile, 9 + diagnostic_type)
        records = tuple(DtcFreeze(code) for code in codes)
        if codes:
            _, supported = functions.function(1, 4, 3)
            if supported:
                frames = _profile_frames(profile, 6)
                if len(frames) != 1:
                    raise ToyotaCodecError(
                        "DK ISO freeze requires one frame", 0xC0040102
                    )
                selected = frames[0]
                try:
                    reply = self._dk_iso_call(
                        CommandSpec(
                            selected.frame,
                            check="raw",
                            provenance=selected.provenance,
                            selected=selected,
                        ),
                        selected.settings_record[14],
                    )
                except ToyotaCodecError as error:
                    if error.code != 0x91010009:
                        raise
                else:
                    if not reply:
                        raise ToyotaCodecError(
                            "DK ISO freeze code byte absent", SHORT_REPLY
                        )
                    if reply[0]:
                        records, _ = associate_freeze(records, reply[0], 0)
        return {"codes": codes, "freeze_records": records}

    def count_dtcs_dk_iso_profile(
        self, profile: VehicleProfile, diagnostic_type: int
    ) -> dict[str, int]:
        """GetDiagCodeCountDkIso9141 Execute10a6 always uses function7."""
        if type(diagnostic_type) is not int or not 0 <= diagnostic_type <= 65535:
            raise ValueError("Diagnostic type must fit native WORD")
        codes = self.dtcs_dk_iso_profile(profile, 7)
        return {"diagnostic_type": diagnostic_type, "count": len(codes) & 0xFF}

    def freeze_diagnostic_code_profile(
        self,
        profile: VehicleProfile,
        number: int,
        *,
        mask_flags: int = 0,
        begin_operation: bool = True,
    ) -> int | None:
        """Common77790 GetFrzDiagCode; None means native out-WORD unwritten."""
        freeze_support_request(b"\x00", number)
        mask_comm_error(0, mask_flags)
        frames = _profile_frames(profile, 6)
        if not frames:
            raise ToyotaCodecError("No selected freeze diagnostic frames", 0xC0040102)
        if begin_operation:
            self._begin()
        last_status = 0
        for frame in frames:
            request = freeze_support_request(frame.frame.request, number)
            selected = CommandSpec(
                replace(frame.frame, request=request),
                provenance=frame.provenance,
                selected=frame,
            )
            try:
                for attempt in range(
                    self._native_retry_count(frame.settings_record[14]) + 1
                ):
                    try:
                        reply = self._native_call(selected, request)
                        break
                    except ToyotaCodecError as error:
                        if (
                            error.code == 0x90020323
                            or attempt
                            == self._native_retry_count(frame.settings_record[14])
                        ):
                            raise
            except ToyotaCodecError as error:
                last_status = error.code
                if (
                    error.code == 0x91010009
                    or mask_comm_error(error.code, mask_flags) == 0
                ):
                    continue
                raise
            return freeze_support_code(frame.frame, reply)
        status = mask_comm_error(last_status, mask_flags)
        if status:
            raise NativeStatus(status)
        return None

    def freeze_dk_iso(
        self,
        names: Sequence[str],
        freezes: Sequence[bytes],
        freeze_lengths: Mapping[int, int],
        pid_lengths: Mapping[int, int],
        *,
        retries: int = 0,
    ) -> dict[int, int]:
        """Native function11 frame list then FIRST reply's selected PID map."""
        if not names:
            raise SessionError("DK ISO freeze frame descriptors not selected")
        if type(retries) is not int or not 0 <= retries <= 255:
            raise ValueError("DK ISO retry count must fit ComSet byte")
        specs = [self._spec(name) for name in names]
        if any(not 1 <= len(spec.frame.request) <= 255 for spec in specs):
            raise ToyotaCodecError(
                "DK ISO freeze request outside byte bounds", INVALID_RECORD
            )
        if any(len(row) != 84 for row in freezes):
            raise ToyotaCodecError(
                "Invalid DK ISO selected Freeze record", INVALID_RECORD
            )
        self._begin()
        replies = [self._dk_iso_call(spec, retries) for spec in specs]
        data = parse_dk_iso_freeze(replies[0], freeze_lengths, pid_lengths)
        return {
            index: dk_iso_freeze_value(row, data)
            for index, row in enumerate(freezes)
            if row[78] & 2 and row[77] != 2
        }

    def dtcs_psa(
        self,
        names: Sequence[str],
        diagnostic_type: int,
        *,
        no_status: bool = False,
        retries: int = 0,
    ) -> list[int]:
        return self._dtcs_psa(
            names, diagnostic_type, no_status=no_status, retries=retries
        )[0]

    def dtcs_psa_profile(
        self,
        profile: VehicleProfile,
        diagnostic_type: int,
        functions: FunctionCache,
        *,
        family: Literal["plain", "v2", "no_status"] = "plain",
    ) -> dict[str, object]:
        """Selected PSA read wrappers and native plain/numbered/DTC-keyed FFD."""
        if family not in ("plain", "v2", "no_status"):
            raise ValueError("Unknown PSA diagnostic wrapper")
        if type(diagnostic_type) is not int or diagnostic_type not in (1, 2):
            raise ToyotaCodecError("Unsupported PSA diagnostic type", 0xC0040001)
        frames = _profile_frames(profile, 0x0A)
        previous = self.commands
        try:
            self.commands = {
                str(index): CommandSpec(
                    frame.frame, provenance=frame.provenance, selected=frame
                )
                for index, frame in enumerate(frames)
            }
            codes, raw_count = self._dtcs_psa(
                tuple(self.commands),
                diagnostic_type,
                no_status=family == "no_status",
                retries=frames[0].settings_record[14],
                selected_profile=profile,
            )
        finally:
            self.commands = previous
        records = tuple(DtcFreeze(code) for code in codes)
        if codes:
            present, supported = functions.function(1, 4, 3)
            if family == "plain":
                if supported:
                    records = self._psa_freeze_support_profile(
                        profile, records, "plain", raw_count
                    )
            elif present:
                records = self._psa_freeze_support_profile(
                    profile, records, "numbered" if supported else "dtc", raw_count
                )
        return {"codes": codes, "freeze_records": records, "native_count": raw_count}

    def _psa_freeze_support_profile(
        self,
        profile: VehicleProfile,
        records: tuple[DtcFreeze, ...],
        mode: Literal["plain", "numbered", "dtc"],
        count: int,
    ) -> tuple[DtcFreeze, ...]:
        # Common7D820,7EFA0,7F320: no SupFreeze query in these families.
        frames = _profile_frames(profile, 6)
        if len(frames) != 1:
            raise ToyotaCodecError("PSA freeze support requires one frame", 0xC0040102)
        selected = frames[0]
        template = selected.frame.request
        if len(template) < (4 if mode == "dtc" else 3 if mode == "numbered" else 1):
            raise ToyotaCodecError(
                "PSA freeze request patch outside selected frame", INVALID_RECORD
            )
        selectors = (
            [0]
            if mode == "plain"
            else list(range(count - 1, -1, -1))
            if mode == "numbered"
            else [record.code for record in records]
        )
        result = records
        for selector in selectors:
            request = bytearray(template)
            number = selector & 255 if mode == "numbered" else 0
            if mode == "numbered":
                request[2] = number
            elif mode == "dtc":
                request[2:4] = selector.to_bytes(2, "big")
            frame = replace(selected.frame, request=bytes(request))
            spec = CommandSpec(frame, provenance=selected.provenance, selected=selected)
            try:
                for attempt in range(
                    self._native_retry_count(selected.settings_record[14]) + 1
                ):
                    try:
                        reply = self._native_call(spec, frame.request)
                        break
                    except ToyotaCodecError as error:
                        if (
                            error.code == 0x90020323
                            or attempt
                            == self._native_retry_count(selected.settings_record[14])
                        ):
                            raise
            except ToyotaCodecError as error:
                if mode != "plain" or error.code == 0x91010009:
                    continue
                raise
            if len(reply) < len(frame.receive_mask):
                raise ToyotaCodecError(
                    "PSA freeze reply shorter than selected mask", SHORT_REPLY
                )
            code = freeze_support_code(frame, reply[: len(frame.receive_mask)])
            result, _ = associate_freeze(result, code, number)
        return result

    def _dtcs_psa(
        self,
        names: Sequence[str],
        diagnostic_type: int,
        *,
        no_status: bool = False,
        retries: int = 0,
        selected_profile: VehicleProfile | None = None,
    ) -> tuple[list[int], int]:
        """PSA descriptor chain: first count>=10 enables overflow descriptors.

        Native failure in the second descriptor ends successfully; first failure
        propagates. Descriptor selection errors are preflight dependency failures.
        """
        if not names:
            raise SessionError("PSA DTC descriptor chain is empty")
        if type(retries) is not int or not 0 <= retries <= 255:
            raise ValueError("PSA retry count must fit ComSet byte")
        parse_psa_dtcs(b"\x00\x00", diagnostic_type, no_status=no_status)
        for name in names:
            self._spec(name)
        self._begin()
        codes: list[int] = []
        raw_count = 0
        for frame_index, name in enumerate(names):
            spec = self._spec(name)
            for attempt in range(retries + 1):
                try:
                    reply = self._call(spec.frame.request)
                    replace(
                        spec, check="sid", payload_offset=0, extended=True
                    ).validate(reply)
                    entries = parse_psa_dtcs(
                        reply, diagnostic_type, no_status=no_status
                    )
                    break
                except ToyotaCodecError as error:
                    if error.code != 0x90020323 and attempt < retries:
                        continue
                    if frame_index == 1:
                        return codes, raw_count
                    raise
            raw_count = min(
                256, raw_count + len(parse_psa_dtcs(reply, 2, no_status=no_status))
            )
            for entry in entries:
                if (
                    selected_profile is None
                    or dtc_metadata_profile(selected_profile, entry["code"]) is not None
                ):
                    codes.append(entry["code"])
            if not reply[1]:
                # V2/NoStatus jump directly to success cleanup before writing
                # the out-count; their wrapper initialized that DWORD to zero.
                return codes, 0
            if frame_index == 0 and reply[1] < 10:
                return codes, raw_count
        return codes, raw_count

    def dtcs_tesla(
        self,
        name: str,
        support_bytes: bytes,
        definitions: Mapping[int, TeslaDtcDefinition],
        *,
        include_hidden: bool = False,
    ) -> list[dict[str, object]]:
        """Selected native Tesla command; support cache is injected, never assumed."""
        spec = self._spec(name)
        if spec.payload_offset:
            raise ValueError("Tesla DTC parser requires full native response")
        if len(support_bytes) < 57 or support_bytes[:57] != b"\xff" * 57:
            raise ToyotaCodecError("Tesla support data unavailable", 0x90040501)
        # Validate selected metadata before making a request.
        for code, definition in definitions.items():
            if (
                type(code) is not int
                or not 0 < code <= 0xFFFFFF
                or len(definition.record) != 36
                or struct.unpack_from("<I", definition.record, 20)[0] != code
            ):
                raise ToyotaCodecError(
                    "Invalid selected expanded DTC row", INVALID_RECORD
                )
        self._begin()
        return parse_tesla_dtcs(
            self._native_call(spec, spec.frame.request),
            definitions,
            include_hidden=include_hidden,
        )

    def read_p5_diagnostic_reply_profile(
        self,
        profile: VehicleProfile,
        requested_types: int,
        *,
        native_cancel_value: int,
        connection_bus_id: int | None,
        begin_operation: bool = True,
        source_build: int = 18,
    ) -> dict[str, object]:
        """GetDiagCodeP5 local2570 selected request stage, before FFD association.

        CD may contain multiple frames; native patches/sends only FIRST. Ten
        native communication statuses clear read success, while DB/context
        failures propagate. This does not claim the exported outer workflow.
        """
        if type(source_build) is not int or source_build not in (12, 18):
            raise ValueError("Native P5 source build must be12or18")
        if (
            type(native_cancel_value) is not int
            or not 0 <= native_cancel_value <= 0xFFFFFFFF
        ):
            raise ValueError("Observed native cancellation value must fit DWORD")
        if connection_bus_id is not None and (
            type(connection_bus_id) is not int or not 0 <= connection_bus_id <= 65535
        ):
            raise ValueError("Observed bus ID must fit WORD")
        if begin_operation:
            self._begin()
        self._check()
        request_mask, rules = dtc_status_rules_profile(profile, requested_types)
        result: dict[str, object] = {
            "reply": b"",
            "rules": rules,
            "read_succeeded": False,
            "maximum_groups": 0x3FF,
            "request_mask": request_mask,
        }
        if not request_mask:
            return result
        if source_build == 18:
            category = profile.category_record
            if len(category) < 73:
                raise ToyotaCodecError("Selected ECU category group empty", 0xC0040101)
            if category[72] & 0xE0 == 0x20 and profile.category in (0x2DA, 0x2DB):
                request_mask = 0xAF
                result["request_mask"] = request_mask
        frames = _profile_frames(profile, 0xCD)
        if not frames:
            raise ToyotaCodecError("Selected P5 diagnostic group empty", 0xC0040101)
        frame = frames[0]
        request = bytearray(frame.frame.request)
        if len(request) < 3:
            raise ToyotaCodecError("P5 diagnostic request lacks mask byte", 0xC0040102)
        request[2] = request_mask
        if native_cancel_value == 1:
            raise ToyotaCodecError("Native P5 cancellation requested", 0xA0040003)
        if source_build == 18 and connection_bus_id is None:
            raise ToyotaCodecError("Native connection cache not observed", 0xC0040601)
        large_reply = source_build == 18 and connection_bus_id == 0x14
        capacity = 65535 if large_reply else 0x1000
        result["maximum_groups"] = 0x3FFF if large_reply else 0x3FF
        command = CommandSpec(
            frame.frame,
            extended=True,
            selected=frame,
            provenance=frame.provenance,
            receive_capacity=capacity,
        )
        try:
            retry_count = self._native_retry_count(frame.settings_record[14])
            for attempt in range(retry_count + 1):
                try:
                    result["reply"] = self._native_call(
                        command, bytes(request), extended=True
                    )
                    break
                except ToyotaCodecError as error:
                    if error.code != 0x90020323 and attempt < retry_count:
                        continue
                    raise
        except ToyotaCodecError as error:
            if error.code not in (
                0x91010009,
                0x90020321,
                0x90020323,
                0xA0040201,
                0xC0040001,
                0xA0040202,
                0x90020327,
                0x91020320,
                0x91020310,
                0x91020322,
            ):
                raise
            return result
        result["read_succeeded"] = True
        return result

    def dtcs_p5_profile(
        self,
        workflow: ToyotaWorkflows,
        requested_types: int,
        freeze_flags: int,
        *,
        native_cancel_value: int,
        log_control: int = 0,
    ) -> dict[str, object]:
        """GetDiagCodeP5 Execute: build18 conditional log14; build12 has none."""
        from scripts.toyota_workflows import ToyotaWorkflows

        if not isinstance(workflow, ToyotaWorkflows) or workflow.session is not self:
            raise TypeError("The owning concrete Toyota workflow is required")
        if type(log_control) is not int or not 0 <= log_control <= 0xFFFFFFFF:
            raise ValueError("Native log control must fit DWORD")
        workflow._begin(source12_verified=True)
        self._begin()
        if workflow.observations.source_version == 12 or log_control != 1:
            return self.p5_diagnostics_core_profile(
                workflow,
                requested_types,
                freeze_flags,
                native_cancel_value=native_cancel_value,
                begin_operation=False,
            )
        with workflow._comm_log(0x14) as lifecycle:
            result = self.p5_diagnostics_core_profile(
                workflow,
                requested_types,
                freeze_flags,
                native_cancel_value=native_cancel_value,
                begin_operation=False,
            )
            result["communication_log"] = lifecycle
        return result

    def p5_diagnostics_core_profile(
        self,
        workflow: ToyotaWorkflows,
        requested_types: int,
        freeze_flags: int,
        *,
        native_cancel_value: int,
        begin_operation: bool = True,
    ) -> dict[str, object]:
        """GetDiagCodeP5 local1110, normal/predictive12/18 and Subaru18.

        The exported conditional logger surrounds this phase.
        Concrete selected cache/state survive in native_output on later faults.
        """
        from scripts.freeze_p5 import P5FreezeState, P5SnapshotRequest
        from scripts.toyota_workflows import ToyotaWorkflows

        if not isinstance(workflow, ToyotaWorkflows) or workflow.session is not self:
            raise TypeError("The owning concrete Toyota workflow is required")
        if workflow._communication is None:
            raise SessionError(
                "P5 diagnostic orchestration requires native communication"
            )
        if type(freeze_flags) is not int or not 0 <= freeze_flags <= 0xFFFFFFFF:
            raise ValueError("Native freeze flags must fit DWORD")
        if begin_operation:
            workflow._begin(source12_verified=True)
            self._begin()
        profile = workflow.profile
        build: Literal[12, 18] = (
            12 if workflow.observations.source_version == 12 else 18
        )
        state = P5FreezeState(
            profile,
            source_build=build,
            cache=workflow._support(),
            native_cancel_value=native_cancel_value,
        )
        result: dict[str, object] = {
            "state": state,
            "communication_success": False,
            "native_status": 0,
        }
        workflow.native_output = result
        read = self.read_p5_diagnostic_reply_profile(
            profile,
            requested_types,
            native_cancel_value=native_cancel_value,
            connection_bus_id=workflow.observations.bus_id,
            begin_operation=False,
            source_build=build,
        )
        reply, rules, maximum = read["reply"], read["rules"], read["maximum_groups"]
        assert (
            isinstance(reply, bytes)
            and isinstance(rules, tuple)
            and isinstance(maximum, int)
        )
        succeeded = read["read_succeeded"] is True
        result["communication_success"] = succeeded
        analyze_p5_diagnostic_reply_profile(
            profile,
            reply,
            rules,
            maximum_groups=maximum,
            requested_types=requested_types,
            state=state,
        )
        category = profile.category_record
        if len(category) < 73:
            raise ToyotaCodecError("Selected category group empty", 0xC0040101)
        requests: tuple[P5SnapshotRequest, ...] = ()
        predictive = category[72] & 0x1F == 0x15
        if predictive:
            if freeze_flags & 1:
                requests = tuple(
                    P5SnapshotRequest(
                        item.code,
                        [
                            number
                            for bit, number in ((2, 0x10), (4, 0x12))
                            if item.diag_type & bit
                        ],
                    )
                    for item in state.diagnostics
                    if item.diag_type & 6
                )
            result["requests"] = requests
            if freeze_flags & 3 == 3:
                succeeded |= self.p5_predictive_freeze_profile(
                    state, requests, native_cancel_value=native_cancel_value
                )
        elif build == 18 and (category[72] & 0xE0 == 0x20 or profile.category == 0x26B):
            subaru = P5FreezeState(
                profile,
                source_build=18,
                cache=workflow._support(),
                subaru=True,
                native_cancel_value=native_cancel_value,
            )
            subaru.diagnostics = state.diagnostics
            state = subaru
            result["state"] = state
            if freeze_flags & 1 and profile.category != 0x26B:
                succeeded |= state.comm_execute_stored()
                state.analyze_stored_received()
            # Native59D0 checks the collected-frame list at this+2C, not success.
            if not state.snapshot_frames:
                if freeze_flags & 1:
                    success, requests = self.p5_freeze_existence_profile(
                        state,
                        native_cancel_value=native_cancel_value,
                        connection_bus_id=workflow.observations.bus_id,
                    )
                    succeeded |= success
                result["requests"] = requests
                if requests and freeze_flags & 3 == 3:
                    state.init_freeze_data()
                    succeeded |= state.comm_execute_snapshot(requests)
                    requests = tuple(item for item in requests if item.numbers)
                    result["requests"] = requests
                    state.analyze_snapshot_received(requests, create_diagnostics=False)
        else:
            if freeze_flags & 1:
                success, requests = self.p5_freeze_existence_profile(
                    state,
                    native_cancel_value=native_cancel_value,
                    connection_bus_id=workflow.observations.bus_id,
                )
                succeeded |= success
            result["requests"] = requests
            if requests and freeze_flags & 3 == 3:
                try:
                    phase = workflow.each_freeze_p5_core(
                        state, requests, begin=False, create_diagnostics=False
                    )
                    succeeded |= phase["communication_success"] is True
                finally:
                    if workflow.native_output is not result:
                        result["each_phase"] = workflow.native_output
                    workflow.native_output = result
            if freeze_flags & 4:
                succeeded |= self.p5_stored_freeze_profile(
                    state,
                    native_cancel_value=native_cancel_value,
                    connection_bus_id=workflow.observations.bus_id,
                )
        for diagnostic in state.diagnostics:
            self._check()
            state.sort_display_order(diagnostic)
        if not predictive:
            index = 0
            while index < len(state.diagnostics):
                self._check()
                diagnostic = state.diagnostics[index]
                state.set_timestamp_odometer_flags(diagnostic)
                if not diagnostic.existence_flags and not diagnostic.status:
                    del state.diagnostics[index]
                else:
                    index += 1
        result["communication_success"] = succeeded
        if not succeeded:
            result["native_status"] = 0xA004020B
            raise NativeStatus(0xA004020B)
        return result

    def p5_freeze_existence_profile(
        self,
        state: P5FreezeState,
        *,
        native_cancel_value: int,
        connection_bus_id: int | None,
    ) -> tuple[bool, tuple[P5SnapshotRequest, ...]]:
        """GetDiagCodeP5 CE7FA0/8150/8880 existence and mutable CF request list.

        The caller owns the shared operation budget and concrete Common state.
        Native group ordering, duplicate suppression and prerequisite records1/2
        are applied before any per-DTC freeze reads.
        """
        from scripts.freeze_p5 import P5FreezeState, P5SnapshotRequest

        if not isinstance(state, P5FreezeState):
            raise TypeError("Selected concrete P5 freeze state required")
        state._check()
        self._check()
        if state.cache.ecu != self.ecu:
            raise SessionError("P5 existence and diagnostic target differ")
        if (
            type(native_cancel_value) is not int
            or not 0 <= native_cancel_value <= 0xFFFFFFFF
        ):
            raise ValueError("Native cancellation must fit DWORD")
        if state.source_build == 18 and connection_bus_id is None:
            raise ToyotaCodecError("P5 existence connection cache absent", 0xC0040601)
        if connection_bus_id is not None and (
            type(connection_bus_id) is not int or not 0 <= connection_bus_id <= 65535
        ):
            raise ValueError("Native connection bus must fit WORD")
        frames = _profile_frames(state.profile, 0xCE)
        if not frames:
            raise ToyotaCodecError("P5 existence frame group empty", 0xC0040101)
        selected = frames[0]
        if native_cancel_value == 1:
            raise ToyotaCodecError("Native P5 command cancelled", 0xA0040003)
        large = state.source_build == 18 and connection_bus_id == 0x14
        spec = CommandSpec(
            selected.frame,
            selected=selected,
            provenance=selected.provenance,
            extended=True,
            receive_capacity=65535 if large else 0x1000,
        )
        try:
            retries = self._native_retry_count(selected.settings_record[14])
            for attempt in range(retries + 1):
                try:
                    reply = self._native_call(spec, spec.frame.request, extended=True)
                    break
                except ToyotaCodecError as error:
                    if error.code != 0x90020323 and attempt < retries:
                        continue
                    raise
        except ToyotaCodecError as error:
            if error.code in (
                0x91010009,
                0x90020321,
                0x90020323,
                0xA0040201,
                0xC0040001,
                0xA0040202,
                0x90020327,
                0x91020320,
                0x91020310,
                0x91020322,
            ):
                return False, ()
            raise
        count = max(0, (len(reply) - 2) // 4)
        if not 0 < count <= (0x3FFF if large else 0x3FF):
            return True, ()
        requests: dict[int, P5SnapshotRequest] = {}
        for at in range(2, 2 + count * 4, 4):
            code = int.from_bytes(reply[at : at + 3], "big")
            number = reply[at + 3]
            if not state.get_ffd_type(number):
                continue
            request = requests.setdefault(code, P5SnapshotRequest(code, []))
            if number not in request.numbers:
                request.numbers.append(number)
        result: list[P5SnapshotRequest] = []
        for request in requests.values():
            self._check()
            numbers = request.numbers
            numbers[:] = [
                number
                for number in numbers
                if number <= 15
                or (0x10 <= number < 0x50 and 1 in numbers)
                or (not state.subaru and 0x50 <= number < 0x70 and 2 in numbers)
            ]
            if not numbers:
                continue
            if state.add_diagnostic(request.code) is None:
                continue
            for number in numbers:
                state.set_ffd_exist_flag(request.code, number)
            result.append(request)
        state._check()
        self._check()
        return True, tuple(result)

    def p5_predictive_freeze_profile(
        self,
        state: P5FreezeState,
        requests: tuple[P5SnapshotRequest, ...],
        *,
        native_cancel_value: int,
    ) -> bool:
        """GetDiagCodeP5 CF2B50/3180, distinct from Each's D0 predictive data."""
        from scripts.freeze_p5 import (
            P5DataIdObservation,
            P5FreezeState,
            P5SnapshotRequest,
            P5Value,
        )

        if not isinstance(state, P5FreezeState) or state.subaru:
            raise TypeError("Selected normal P5 freeze state required")
        if (
            not isinstance(requests, tuple)
            or len(requests) > 0x3FFF
            or any(not isinstance(item, P5SnapshotRequest) for item in requests)
        ):
            raise TypeError("Typed native P5 snapshot requests required")
        if (
            type(native_cancel_value) is not int
            or not 0 <= native_cancel_value <= 0xFFFFFFFF
        ):
            raise ValueError("Native cancellation must fit DWORD")
        state._check()
        if state.cache.ecu != self.ecu:
            raise SessionError("P5 predictive and diagnostic target differ")
        self._check()
        frames = _profile_frames(state.profile, 0xCF)
        if not frames:
            raise ToyotaCodecError("P5 predictive frame group empty", 0xC0040101)
        selected = frames[0]
        spec = CommandSpec(
            selected.frame,
            selected=selected,
            provenance=selected.provenance,
            extended=True,
            receive_capacity=0x1000,
        )
        replies: list[bytes] = []
        captured_bytes = 0
        succeeded = False
        for request in requests:
            request.__post_init__()
            at = 0
            while at < len(request.numbers):
                self._check()
                wire = state.set_dtc(
                    selected.frame.request, request.code, request.numbers[at]
                )
                if native_cancel_value == 1:
                    raise ToyotaCodecError("Native P5 command cancelled", 0xA0040003)
                try:
                    retries = self._native_retry_count(selected.settings_record[14])
                    for attempt in range(retries + 1):
                        try:
                            reply = self._native_call(spec, wire, extended=True)
                            break
                        except ToyotaCodecError as error:
                            if error.code != 0x90020323 and attempt < retries:
                                continue
                            raise
                except ToyotaCodecError as error:
                    if error.code not in (
                        0x91010009,
                        0x90020321,
                        0x90020323,
                        0xA0040201,
                        0xC0040001,
                        0xA0040202,
                        0x90020327,
                        0x91020320,
                        0x91020310,
                        0x91020322,
                    ):
                        raise
                    del request.numbers[at]
                    continue
                succeeded = True
                if (
                    len(replies) >= 65535
                    or captured_bytes + len(reply) > 16 * 1024 * 1024
                ):
                    raise SessionError("Predictive capture budget exhausted")
                replies.append(reply)
                captured_bytes += len(reply)
                at += 1
        # Native captures all wire replies before any selected DID/metadata work.
        offset = 0
        for request in requests:
            end = offset + len(request.numbers)
            for reply in replies[offset:end]:
                self._check()
                if len(reply) <= 6:
                    continue
                code = int.from_bytes(reply[2:5], "big")
                diagnostic = state.diagnostic(code)
                if diagnostic is None:
                    continue
                cursor = 6
                while cursor < len(reply):
                    if cursor + 2 > len(reply) or reply[cursor] not in (0x10, 0x12):
                        break
                    number, count = reply[cursor : cursor + 2]
                    kind = 1 if number == 0x10 else 2
                    diagnostic.normal_numbers.append(number)
                    diagnostic.existence_flags = ffd_existence_flag(
                        kind, diagnostic.existence_flags
                    )
                    cursor += 2
                    if not count and request.numbers and request.numbers[0] == 255:
                        break
                    observations: list[P5DataIdObservation] = []
                    consumed = 0
                    while consumed < count or not count:
                        if cursor + 2 > len(reply):
                            cursor = len(reply)
                            break
                        did = int.from_bytes(reply[cursor : cursor + 2], "big")
                        cursor += 2
                        rows = [
                            row
                            for row in state._rows(61, 8)
                            if struct.unpack_from("<H", row, 2)[0] == did
                        ]
                        length = next((row[4] for row in rows if row[4]), 0)
                        if not length or cursor + length > len(reply):
                            break
                        data = reply[cursor : cursor + length]
                        cursor += length
                        if did and not any(item.did == did for item in observations):
                            observations.append(P5DataIdObservation(did, data))
                        consumed += 1
                        if not count and cursor >= len(reply):
                            break
                    items = tuple(observations)
                    index = ((number - 0x7F + 128) & 255) - 128
                    multi = P5Value(0, index, kind)
                    for item in items:
                        state.analyze_single_data_id(
                            code, item.did, multi, item.data, items
                        )
            offset = end
        state._check()
        self._check()
        return succeeded

    def p5_stored_freeze_profile(
        self,
        state: P5FreezeState,
        *,
        native_cancel_value: int,
        connection_bus_id: int | None,
    ) -> bool:
        """GetDiagCodeP5 D0 6230/65C0/6A60, temporary typed FFD then merge."""
        from scripts.freeze_p5 import P5DataIdObservation, P5FreezeState, P5Value
        from scripts.toyota_workflows import (
            merge_p5_diagnostics,
            parse_predictive_p5_reply,
        )

        if not isinstance(state, P5FreezeState) or state.subaru:
            raise TypeError("Selected normal P5 freeze state required")
        if (
            type(native_cancel_value) is not int
            or not 0 <= native_cancel_value <= 0xFFFFFFFF
        ):
            raise ValueError("Native cancellation must fit DWORD")
        state._check()
        self._check()
        if state.cache.ecu != self.ecu:
            raise SessionError("P5 stored and diagnostic target differ")
        frames = _profile_frames(state.profile, 0xD0)
        if not frames:
            raise ToyotaCodecError("P5 stored frame group empty", 0xC0040101)
        if native_cancel_value == 1:
            raise ToyotaCodecError("Native P5 command cancelled", 0xA0040003)
        if state.source_build == 18 and connection_bus_id is None:
            raise ToyotaCodecError("P5 stored connection cache absent", 0xC0040601)
        if connection_bus_id is not None and (
            type(connection_bus_id) is not int or not 0 <= connection_bus_id <= 65535
        ):
            raise ValueError("Native bus must fit WORD")
        selected = frames[0]
        template = selected.frame.request
        if len(template) < 3:
            raise ToyotaCodecError("P5 stored selector absent", 0xC0040102)
        large = state.source_build == 18 and connection_bus_id == 0x14
        spec = CommandSpec(
            selected.frame,
            selected=selected,
            provenance=selected.provenance,
            extended=True,
            receive_capacity=65535 if large else 0x1000,
        )
        captured: list[tuple[int, bytes]] = []
        succeeded = False
        captured_bytes = 0

        def receive(number: int | None) -> bytes | None:
            nonlocal succeeded, captured_bytes
            self._check()
            state._check()
            if native_cancel_value == 1:
                raise ToyotaCodecError("Native P5 command cancelled", 0xA0040003)
            wire = (
                template
                if number is None
                else template[:2] + bytes((number,)) + template[3:]
            )
            try:
                retries = self._native_retry_count(selected.settings_record[14])
                for attempt in range(retries + 1):
                    try:
                        reply = self._native_call(spec, wire, extended=True)
                        break
                    except ToyotaCodecError as error:
                        if error.code != 0x90020323 and attempt < retries:
                            continue
                        raise
            except ToyotaCodecError as error:
                if error.code in (
                    0x91010009,
                    0x90020321,
                    0x90020323,
                    0xA0040201,
                    0xC0040001,
                    0xA0040202,
                    0x90020327,
                    0x91020320,
                    0x91020310,
                    0x91020322,
                ):
                    return None
                raise
            succeeded = True
            return reply

        def capture(number: int, reply: bytes) -> None:
            nonlocal captured_bytes
            if len(reply) <= 2:
                return
            if len(captured) >= 65535 or captured_bytes + len(reply) > 16 * 1024 * 1024:
                raise SessionError("Stored FFD capture budget exhausted")
            captured.append((number, reply))
            captured_bytes += len(reply)

        initial = receive(None)
        if initial is None or len(initial) > 7 and initial[7] == 0:
            bases: list[int] = []
            for number in range(1, 15):
                reply = receive(number)
                if reply is not None and len(reply) > 2:
                    capture(number, reply)
                    bases.append(number)
            for base in bases:
                for low in range(16):
                    number = base << 4 | low
                    reply = receive(number)
                    if reply is not None:
                        capture(number, reply)
        elif initial is not None:
            capture(template[2], initial)
        if not captured:
            return succeeded
        temporary = P5FreezeState(
            state.profile, source_build=state.source_build, cache=state.cache
        )
        temporary.set_timestamp_odometer_pid_ids()
        for requested_number, reply in captured:
            parsed = parse_predictive_p5_reply(reply, requested_number=requested_number)
            records = parsed["records"]
            assert isinstance(records, list)
            for record in records:
                diagnostic = temporary.add_diagnostic(record["code"], diag_type=8)
                if diagnostic is None:
                    continue
                if record["number"] < 16:
                    temporary.set_ffd_exist_flag(
                        record["code"], record["number"], extended=True
                    )
                diagnostic.stored_all = requested_number == 255
                diagnostic.metadata["native_7c"] = int(requested_number == 255)
                items = tuple(
                    P5DataIdObservation(item["did"], bytes.fromhex(item["data"]))
                    for item in record["data_ids"]
                )
                multi = P5Value(0, record["index"], record["kind"])
                for item in items:
                    temporary.analyze_single_data_id(
                        record["code"], item.did, multi, item.data, items
                    )
        merge_p5_diagnostics(state, temporary)
        self._check()
        state._check()
        return succeeded

    def dtcs_p5(self, name: str, rules: Sequence[StatusRule]) -> list[dict[str, int]]:
        # Parser operates on full native prefix; selected payload slicing is not valid here.
        spec = self._spec(name)
        if spec.payload_offset:
            raise ValueError("P5 DTC parser requires full response prefix")
        self._begin()
        return parse_p5_dtcs(
            self._native_call(spec, spec.frame.request, extended=True), rules
        )

    def data_list(
        self,
        name: str,
        pid: int,
        protocol: int,
        *,
        freeze: bytes | None = None,
        physical: bytes | None = None,
        patterns: Sequence[Pattern] = (),
        minimum_raw: int | None = None,
        maximum_raw: int | None = None,
    ) -> bytes | dict[str, object]:
        spec = self._spec(name)
        request = data_list_request(spec.frame.request, pid, protocol)
        if (freeze is None) != (physical is None):
            raise ValueError("Freeze and PhyData must be supplied together")
        self._begin()
        reply = self._native_call(spec, request, extended=spec.extended)
        if len(reply) < spec.payload_offset:
            raise ToyotaCodecError("Reply lacks selected payload prefix", SHORT_REPLY)
        payload = reply[spec.payload_offset :]
        return (
            scale_signal(
                payload,
                freeze,
                physical,
                patterns=patterns,
                minimum_raw=minimum_raw,
                maximum_raw=maximum_raw,
            )
            if freeze is not None and physical is not None
            else payload
        )

    def _read_initial_p5(
        self, name: str, row: bytes, did_offset: int, bit_offset: int
    ) -> int:
        spec = self._spec(name)
        if len(row) < max(did_offset + 2, bit_offset + 4):
            raise ToyotaCodecError(
                "Selected P5 initial-value record truncated", INVALID_RECORD
            )
        if len(spec.frame.request) < 3:
            raise ToyotaCodecError(
                "P5 initial-value frame requires SID/DID", 0xC0040102
            )
        did = struct.unpack_from("<H", row, did_offset)[0]
        begin, end = struct.unpack_from("<HH", row, bit_offset)
        if begin > end or end - begin >= 32:
            raise ToyotaCodecError("P5 initial-value bit range invalid", 0xC0040102)
        request = (
            spec.frame.request[:1] + did.to_bytes(2, "big") + spec.frame.request[3:]
        )
        self._begin()
        reply = self._native_call(spec, request, extended=True)
        if len(reply) < 4 or end >= (len(reply) - 3) * 8:
            raise ToyotaCodecError("P5 initial-value data is too short", SHORT_REPLY)
        return extract_bits(reply[3:], begin, end)

    def routine_initial_status_p5(
        self, name: str, routine_id: int, required_bytes: int, *, subaru: bool = False
    ) -> bool:
        """GetRoutineActTstInitP5_DT2260 selected functionD7 support probe.

        required_bytes is the selected pattern payload size; native requires
        four additional prefix bytes. Wire statuses mean unsupported, except
        Subaru90020321 with partial reply byte2=24/33. Host policy propagates.
        """
        spec = self._spec(name)
        if type(required_bytes) is not int or not 0 <= required_bytes <= 65531:
            raise ValueError("Routine support payload size outside native buffer")
        if type(routine_id) is not int or not 0 <= routine_id <= 65535:
            raise ValueError("Routine ID must fit uint16")
        if len(spec.frame.request) < 4:
            raise ToyotaCodecError("Routine support frame lacks RID", 0xC0040102)
        request = (
            spec.frame.request[:2]
            + routine_id.to_bytes(2, "big")
            + spec.frame.request[4:]
        )
        self._begin()
        try:
            reply = self._native_call(spec, request, extended=True)
            return len(reply) >= required_bytes + 4
        except NativeStatus as error:
            return (
                subaru
                and error.code == 0x90020321
                and len(error.reply) > 2
                and error.reply[2] in (0x24, 0x33)
            )
        except ToyotaCodecError:
            return False

    def read_monitor_initial_p5(self, name: str, row: bytes) -> int:
        """GetActTstInitP5_DT2200: functionCA, DB23e DID36/bits2c..2e."""
        return self._read_initial_p5(name, row, 0x36, 0x2C)

    def read_active_initial_p5(self, name: str, row: bytes) -> int:
        """GetActTstInitP5_DT24e0: functionCA, DB244 DID34/bits28..2a."""
        return self._read_initial_p5(name, row, 0x34, 0x28)

    def read_ecu_p3(self, name: str, freeze: bytes) -> bytes:
        """Common21ca0 GetEcuDataP3; descriptor selects function0x6b."""
        spec = self._spec(name)
        if len(freeze) != 84 or len(spec.frame.request) < 2:
            raise ToyotaCodecError("P3 ECU data descriptor invalid", 0xC0040102)
        request = bytearray(spec.frame.request)
        request[1] = freeze[79]
        self._begin()
        reply = self._native_call(spec, bytes(request))
        payload = reply[len(request) :]
        begin, end = struct.unpack_from("<HH", freeze, 62)
        if begin > end or end >= len(payload) * 8:
            raise ToyotaCodecError("P3 ECU data lacks selected signal", SHORT_REPLY)
        return payload

    def _read_p4(
        self,
        name: str,
        freeze: bytes,
        positions: bytes | None,
        number: int | None,
        *,
        begin_operation: bool = True,
        response_cache: dict[bytes, bytes | ToyotaCodecError] | None = None,
        retries: int = 0,
        support_cache: MonitorSupportCache | None = None,
        operation_control: int | None = None,
    ) -> bytes:
        spec = self._spec(name)
        if type(retries) is not int or not 0 <= retries <= 255:
            raise ValueError("P4 retry count must fit selected ComSet byte")
        retries = self._native_retry_count(retries)
        minimum = 2 if number is None else 4
        if len(freeze) != 84 or not minimum <= len(spec.frame.request) <= 255:
            raise ToyotaCodecError("P4 data descriptor invalid", 0xC0040102)
        if positions is None and support_cache is None:
            raise SessionError("P4 PID support producer or observed positions required")
        if positions is not None and not 0 < len(positions) <= 255:
            raise ToyotaCodecError(
                "Selected PID position table absent/invalid", 0xC0040001
            )
        if number is not None and (type(number) is not int or not 0 <= number <= 255):
            raise ValueError("Freeze number must fit byte")
        request = bytearray(spec.frame.request)
        request[1] = freeze[79] if number is None else number
        if number is not None:
            request[3] = freeze[79]
        if operation_control is not None:
            if type(operation_control) is not int or not 0 <= operation_control <= 255:
                raise ValueError("Operation freeze control must fit byte")
            if number is None:
                raise ValueError("Operation freeze requires a frame number")
            if operation_control:
                request[2] = operation_control
        if begin_operation:
            self._begin()
        wire_request = bytes(request)
        self._check()
        if response_cache is not None and wire_request in response_cache:
            cached = response_cache[wire_request]
            if isinstance(cached, ToyotaCodecError):
                raise cached
            reply = cached
        else:
            for attempt in range(retries + 1):
                try:
                    reply = self._native_call(
                        replace(spec, check="sid", payload_offset=0), wire_request
                    )
                    break
                except ToyotaCodecError as error:
                    if error.code != 0x90020323 and attempt < retries:
                        continue
                    if response_cache is not None and error.code in (
                        0x91010009,
                        0x90020323,
                    ):
                        # Negative entries are added only after native retries.
                        response_cache[wire_request] = NativeStatus(0x91010009)
                    raise
            # CommFrameSendReceive validates SID before native success caching.
            # Selected signal bounds/host masks are checked after caching.
            if not reply or len(reply) > 255 or reply[0] != request[0] | 0x40:
                raise ToyotaCodecError(
                    "Invalid native P4 response service/length", INVALID_REPLY
                )
            if response_cache is not None:
                response_cache[wire_request] = reply
        replace(
            spec, frame=replace(spec.frame, request=bytes(request)), payload_offset=0
        ).validate(reply)
        # GetEcuDataP4 strips two bytes; GetFrzFrmDatP4 strips four.
        # ECU data copies from sendlength; freeze data from sendlength-2.
        # Preserve the native byte-sized data length in both paths.
        size = (len(reply) - minimum) & 255
        start = len(request) if number is None else len(request) - 2
        if len(reply) < minimum or start + size > len(reply):
            raise ToyotaCodecError("P4 reply data boundary invalid", SHORT_REPLY)
        if positions is None:
            assert support_cache is not None
            self._check()
            try:
                masks = support_cache.support_bits(1)
            finally:
                self._check()
            positions = masks.get(freeze[79])
            if positions is None or not 0 < len(positions) <= 255:
                raise ToyotaCodecError("Selected PID support data absent", 0xC0040001)
        payload = expand_supported_pid(reply[start : start + size], positions)
        begin, end = struct.unpack_from("<HH", freeze, 62)
        if begin > end or end >= len(payload) * 8:
            raise ToyotaCodecError("P4 data lacks selected signal", SHORT_REPLY)
        return payload

    def read_ecu_p4(self, name: str, freeze: bytes, positions: bytes) -> bytes:
        """Common22060; function0x6b and selected cached PID byte flags."""
        return self._read_p4(name, freeze, positions, None)

    def read_comm_ecu_p4(
        self,
        profile: VehicleProfile,
        record: bytes,
        positions: bytes,
        *,
        response_cache: dict[bytes, bytes | ToyotaCodecError] | None = None,
        begin_operation: bool = True,
    ) -> int:
        """Common261b0 selected CommEcuData12 raw DWORD read, without affine."""
        if len(record) != 12:
            raise ToyotaCodecError("Invalid CommEcuData record", INVALID_RECORD)
        begin, end = struct.unpack_from("<HH", record, 2)
        if begin > end:
            raise ToyotaCodecError("Invalid CommEcuData bit range", 0xC0040102)
        frames = _profile_frames(profile, 0x6B)
        if len(frames) != 1:
            raise ToyotaCodecError("CommEcuData requires one frame", 0xC0040102)
        frame = frames[0]
        selected = bytearray(84)
        struct.pack_into("<HH", selected, 62, begin, end)
        selected[79] = record[8]
        commands = self.commands
        try:
            self.commands = {
                "read": CommandSpec(
                    frame.frame, provenance=frame.provenance, selected=frame
                )
            }
            payload = self._read_p4(
                "read",
                bytes(selected),
                positions,
                None,
                begin_operation=begin_operation,
                response_cache=response_cache,
                retries=frame.settings_record[14],
            )
        finally:
            self.commands = commands
        return extract_bits(payload, begin, end)

    def multi_freeze_info(
        self,
        profile: VehicleProfile,
        functions: FunctionCache,
        *,
        support_cache: MonitorSupportCache,
        begin_operation: bool = True,
    ) -> dict[str, int | bool | None]:
        """Common445d0 neutral native out-argument state over selected DB226.

        Missing DB226 groups fall back to CFuncInfoCache(1,6,4/5/6).
        Unsupported rows leave the three output DWORDs unwritten (None).
        """

        def group(kind: int) -> tuple[bytes, ...]:
            if 38 not in profile.database.sections:
                return ()  # Native A0030107 alone is the missing-table fallback.
            return tuple(
                row
                for row in profile.records(38)
                if struct.unpack_from("<H", row)[0] == kind
            )

        def support(row: bytes) -> bool:
            self._check()
            try:
                masks = support_cache.support_bits(kind=1)
            finally:
                self._check()
            try:
                enabled = support_cache.enabled_pids(family="p4", kind=1, control=0)
            finally:
                self._check()
            return comm_ecu_support_p4(row, enabled, masks)

        if begin_operation:
            self._begin()
        groups: list[tuple[bytes, ...]] = []
        for kind in (1, 2, 3):
            rows = group(kind)
            groups.append(rows)
            if rows and not support(rows[0]):
                return {"supported": False, "out1": None, "out2": None, "out3": None}
            self._check()
        result: dict[str, int | bool | None] = {"supported": True}
        cache: dict[bytes, bytes | ToyotaCodecError] = {}
        for index, rows in enumerate(groups, 1):
            if rows:
                try:
                    masks = support_cache.support_bits(kind=1)
                finally:
                    self._check()
                pid = rows[0][8]
                if pid not in masks:
                    raise ToyotaCodecError(
                        "Selected PID support data absent", 0xC0040001
                    )
                value = self.read_comm_ecu_p4(
                    profile,
                    rows[0],
                    masks[pid],
                    response_cache=cache,
                    begin_operation=False,
                )
            else:
                present, value = functions.function(1, 6, index + 3)
                if not present:
                    raise ToyotaCodecError(
                        "Multi-freeze function value absent", 0xC0040601
                    )
                if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
                    raise ValueError("Native function value must fit DWORD")
            result[f"out{index}"] = value
            self._check()
        return result

    def freeze_p4(
        self,
        name: str,
        freeze: bytes,
        number: int,
        positions: bytes | None = None,
        *,
        response_cache: dict[bytes, bytes | ToyotaCodecError] | None = None,
        support_cache: MonitorSupportCache | None = None,
    ) -> bytes:
        """Common22f80; function0x11, frame number/PID bytes1/3.

        A supplied cache belongs to one native frame/context in one wrapper;
        it must never span ECU, addressing, selected frame or session changes.
        """
        return self._read_p4(
            name,
            freeze,
            positions,
            number,
            response_cache=response_cache,
            support_cache=support_cache,
        )

    def freeze_operation_p4(
        self,
        name: str,
        freeze: bytes,
        number: int,
        control: int,
        positions: bytes | None = None,
        *,
        response_cache: dict[bytes, bytes | ToyotaCodecError] | None = None,
        support_cache: MonitorSupportCache | None = None,
        retries: int = 0,
    ) -> bytes:
        """Common23850 selected functionE4; nonzero control replaces byte2."""
        return self._read_p4(
            name,
            freeze,
            positions,
            number,
            response_cache=response_cache,
            support_cache=support_cache,
            retries=retries,
            operation_control=control,
        )

    def freeze_p4_profile(
        self,
        profile: VehicleProfile,
        number: int,
        code: int,
        functions: FunctionCache,
        *,
        support_cache: MonitorSupportCache,
        lsb: SignalLSB,
        multi_control: int = 0,
        output: dict[str, object] | None = None,
    ) -> dict[str, object]:
        """GetFrzFrmDatP4 Execute: support, signals, then optional native list."""
        from scripts.toyota_workflows import ToyotaWorkflows, selected_freeze_metadata

        freeze_support_request(b"\0", number)
        if type(code) is not int or not 0 <= code <= 65535:
            raise ValueError("Freeze diagnostic must fit WORD")
        if type(multi_control) is not int or not 0 <= multi_control <= 0xFFFFFFFF:
            raise ValueError("Native multi control must fit DWORD")
        if lsb.cache is not support_cache or support_cache.profile is not profile:
            raise SessionError("P4 support and LSB selected contexts differ")
        self._begin()
        result = {} if output is None else output
        signals = result.setdefault("signals", [])
        numbers = result.setdefault("native_numbers", [])
        if not isinstance(signals, list) or any(
            not isinstance(item, CgwFreeze) for item in signals
        ):
            raise TypeError("P4 output signals must be a native freeze list")
        if not isinstance(numbers, list) or any(
            type(item) is not int or not 0 <= item <= 255 for item in numbers
        ):
            raise TypeError("P4 output numbers must be a native BYTE list")
        result["native_available"] = False
        masks = support_cache.support_bits(kind=1)
        self._check()
        enabled = support_cache.enabled_pids(family="p4_ignore", kind=3, control=number)
        self._check()
        if 10 not in profile.database.sections:
            raise ToyotaCodecError("Selected Freeze table absent", 0xA0030107)
        rows = profile.records(10)
        if len(rows) > 0x7FFF or any(len(row) != 84 for row in rows):
            raise ToyotaCodecError("Invalid selected Freeze group", 0xC0040102)
        _hydrate_freeze_names_profile(profile, rows)
        omitted = {
            0x91010009,
            0x90020321,
            0x90020323,
            0xA0040201,
            0xC0040001,
            0xA0040202,
            0x90020327,
            0x91020320,
            0x91020310,
            0x91020322,
        }
        cache: dict[bytes, bytes | ToyotaCodecError] = {}
        previous = self.commands
        try:
            for row in rows:
                self._check()
                if not row[78] & 2:
                    continue
                try:
                    supported = ToyotaWorkflows._freeze_supported_p4(
                        row, enabled, masks
                    )
                except ToyotaCodecError as error:
                    if error.code != 0xC0040001:
                        raise
                    continue
                if not supported:
                    continue
                frames = _profile_frames(profile, 0x11)
                if len(frames) != 1:
                    raise ToyotaCodecError("P4 freeze requires one frame", 0xC0040102)
                selected = frames[0]
                self.commands = {
                    "native-p4": CommandSpec(
                        selected.frame,
                        selected=selected,
                        provenance=selected.provenance,
                    )
                }
                try:
                    payload = self._read_p4(
                        "native-p4",
                        row,
                        None,
                        number,
                        begin_operation=False,
                        response_cache=cache,
                        retries=selected.settings_record[14],
                        support_cache=support_cache,
                    )
                except ToyotaCodecError as error:
                    if error.code in omitted:
                        continue
                    raise
                metadata = selected_freeze_metadata(profile, row, lsb)
                self._check()
                raw = extract_bits(payload, metadata.start_bit, metadata.end_bit)
                value = (
                    affine(
                        raw,
                        metadata.multiplier,
                        metadata.divisor,
                        metadata.offset,
                        metadata.end_bit - metadata.start_bit + 1,
                        metadata.sign_mode,
                    )
                    & 0xFFFFFFFF
                )
                signals.append(CgwFreeze(row, payload, metadata, raw, value))
        finally:
            self.commands = previous
        present, _value = functions.function(1, 6, 4)
        self._check()
        if not present or multi_control != 1:
            return result
        info = self.multi_freeze_info(
            profile, functions, support_cache=support_cache, begin_operation=False
        )
        if info["supported"] is not True:
            return result
        count, lower, upper = (info[key] for key in ("out1", "out2", "out3"))
        if type(count) is not int or type(lower) is not int or type(upper) is not int:
            raise SessionError("Supported multi-freeze outputs unwritten")
        count, lower, upper = count & 255, lower & 255, upper & 255
        if not count or not (lower or upper):
            return result

        # Native1E10 maps the circular high nibble onto signed BYTE chronology.
        def order(value: int) -> int:
            high = value >> 4
            return high if high < 3 else high - 16

        numbers.append(number & 15)
        encoded = (upper & 0xF0) | (number & 15)
        comparison = 0xFFFF
        for _index in range(order(upper), order(lower) - 1, -1):
            self._check()
            if encoded & 0xF0:
                try:
                    observed = self.freeze_diagnostic_code_profile(
                        profile, encoded, mask_flags=0, begin_operation=False
                    )
                except ToyotaCodecError as error:
                    if error.code not in omitted:
                        raise
                else:
                    if observed is not None:
                        comparison = observed
                    if comparison == code:
                        result["native_available"] = True
                        numbers.append(encoded)
            encoded = (encoded - 0x10) & 255
        return result

    def freeze_legacy_profile(
        self,
        profile: VehicleProfile,
        family: Literal[
            "plain", "multi", "dk_abs", "roof", "no_frame_number", "psa", "dk", "dk_at"
        ],
        number: int,
        *,
        support_cache: MonitorSupportCache,
        lsb: SignalLSB,
        output: list[CgwFreeze] | None = None,
        functions: FunctionCache | None = None,
        code: int = 0,
        begin_operation: bool = True,
    ) -> tuple[CgwFreeze, ...]:
        """Selected legacy exported FFD wrappers, with native partial appends.

        The supplied output list retains completed signals on failure. Support
        lists are produced before Freeze lookup; metadata/LSB follows wire data.
        """
        from scripts.toyota_workflows import selected_freeze_metadata

        if family not in (
            "plain",
            "multi",
            "dk_abs",
            "roof",
            "no_frame_number",
            "psa",
            "dk",
            "dk_at",
        ):
            raise ValueError("Unknown native legacy freeze wrapper")
        if type(code) is not int or not 0 <= code <= 65535:
            raise ValueError("Freeze DTC must fit WORD")
        if family == "roof" and support_cache.source_build != 18:
            raise SessionError("The selected original build has no Roof freeze export")
        if family == "psa" and functions is None:
            raise SessionError("PSA freeze requires selected function cache")
        if type(number) is not int or not 0 <= number <= 255:
            raise ValueError("Native freeze number must fit BYTE")
        if lsb.cache is not support_cache or support_cache.profile is not profile:
            raise SessionError("Freeze wire support/LSB must share selected source")
        if support_cache.ecu != self.ecu:
            raise SessionError("Freeze cache belongs to another ECU")
        if begin_operation:
            self._begin()
            support_cache.begin_operation(limits=self.limits)
        self._check()
        responses: dict[bytes, bytes | ToyotaCodecError] = {}
        if family == "dk_at":
            frames = _profile_frames(profile, 0x11)
            if len(frames) != 1:
                raise ToyotaCodecError("DK AT requires one freeze frame", 0xC0040102)
            selected = frames[0]
            if not 4 <= len(selected.frame.request) <= 255:
                raise ToyotaCodecError("DK AT request is short", 0xC0040102)
            self._frame_sends(
                [
                    NativeFrameSend(
                        "SendInt",
                        profile.category,
                        None,
                        struct.unpack_from("<I", selected.settings_record)[0],
                        0,
                        1,
                        1,
                    )
                ],
                ignore_status=True,
                begin_operation=False,
            )
            request = bytearray(selected.frame.request)
            request[1] = number
            wire = bytes(request)
            spec = CommandSpec(
                selected.frame, selected=selected, provenance=selected.provenance
            )
            for comparison in range(2):
                retries = self._native_retry_count(selected.settings_record[14])
                for attempt in range(retries + 1):
                    try:
                        reply = self._native_call(spec, wire)
                        break
                    except ToyotaCodecError as error:
                        if error.code != 0x90020323 and attempt < retries:
                            continue
                        raise
                observed = int.from_bytes(reply[-2:], "big") if len(reply) >= 4 else 0
                if observed == code:
                    responses[wire] = reply
                    break
                if comparison == 1:
                    raise ToyotaCodecError(
                        "DK AT freeze belongs to another DTC", 0x90040502
                    )
        freeze_lengths: dict[int, int] = {}
        normal_lengths: dict[int, int] = {}
        if family not in ("psa", "dk", "dk_at"):
            producer = "ext" if family in ("dk_abs", "roof") else "normal"
            freeze_lengths = support_cache.enabled_pids(
                family="no_frame_number" if family == "no_frame_number" else producer,
                kind=3,
                control=1 if family == "roof" else number,
            )
            self._check()
            normal_lengths = support_cache.enabled_pids(
                family=producer, kind=1, control=0
            )
            self._check()
        if 10 not in profile.database.sections:
            raise ToyotaCodecError("Selected Freeze table absent", 0xA0030107)
        rows = profile.records(10)
        if len(rows) > 0x7FFF or any(len(row) != 84 for row in rows):
            raise ToyotaCodecError("Malformed selected Freeze group", 0xC0040102)
        _hydrate_freeze_names_profile(profile, rows)
        if family == "dk_at" and not rows:
            raise ToyotaCodecError("DK AT Freeze group empty", 0xC0040101)
        result = [] if output is None else output
        # These are local CCommCachePlus instances, never the ECU Ever cache.
        multi_payloads: dict[bytes, bytes] = {}
        skipped = {
            0x91010009,
            0x90020321,
            0x90020323,
            0xA0040201,
            0xC0040001,
            0xA0040202,
            0x90020327,
            0x91020320,
            0x91020310,
            0x91020322,
        }
        indices = list(range(len(rows)))
        if family in ("dk", "dk_at"):
            # Native BYTE ranks overwrite equal keys; unfilled slots retain row0.
            keys = [(row[79], struct.unpack_from("<H", row, 56)[0]) for row in rows]
            indices = [0] * len(rows)
            for index, key in enumerate(keys):
                indices[sum(other < key for other in keys) & 255] = index
        pending: list[tuple[int, CgwFreeze]] = []
        dk_rows: list[bytes] = []
        dk_lengths: dict[int, int] = {}
        for index in indices:
            freeze = rows[index]
            self._check()
            if not freeze[78] & 2:
                continue
            if family not in ("psa", "dk", "dk_at"):
                try:
                    supported = support_cache.check_freeze_pid(
                        freeze, freeze_lengths, pid_lengths=normal_lengths
                    )
                except ToyotaCodecError as error:
                    if family in ("dk_abs", "roof") and error.code == 0x90020321:
                        continue
                    raise
                self._check()
                if not supported:
                    continue
            if family in ("dk", "dk_at"):
                if 6 not in profile.database.sections:
                    raise ToyotaCodecError("Selected PID table absent", 0xA0030107)
                pid_rows = [
                    row
                    for row in profile.records(6)
                    if len(row) == 8 and row[2] == freeze[79]
                ]
                if len(pid_rows) != 1:
                    raise ToyotaCodecError(
                        "DK requires one selected PID row", 0xC0040102
                    )
                length = pid_rows[0][3]
                begin, end = struct.unpack_from("<HH", freeze, 62)
                if begin > end or end >= length * 8:
                    raise ToyotaCodecError("DK selected PID bits invalid", 0xC0040102)
                dk_lengths[freeze[79]] = length
            numbered = True
            if family == "psa":
                assert functions is not None
                _, value = functions.function(1, 4, 3)
                self._check()
                numbered = bool(value)
            frames = _profile_frames(profile, 0x11)
            if len(frames) != 1:
                raise ToyotaCodecError("Freeze requires one selected frame", 0xC0040102)
            selected = frames[0]
            request = bytearray(selected.frame.request)
            minimum = (
                4
                if family == "psa" and not numbered
                else 4
                if family in ("dk_abs", "roof", "dk", "dk_at")
                else 3
            )
            if not minimum <= len(request) <= 255:
                raise ToyotaCodecError("Selected freeze request is short", 0xC0040102)
            if family in ("dk", "dk_at"):
                request[1] = number
            elif family == "psa":
                request[1] = freeze[79]
                if numbered:
                    request[2] = number
                else:
                    request[2:4] = code.to_bytes(2, "big")
            elif family == "roof":
                request[1], request[3] = 1, number
            elif family == "dk_abs":
                request[1], request[3] = number, freeze[79]
            else:
                request[1], request[2] = freeze[79], number
            wire = bytes(request)
            try:
                if family == "multi":
                    if wire not in multi_payloads:
                        stream_result = support_cache.multi_receive(
                            replace(
                                selected, frame=replace(selected.frame, request=wire)
                            )
                        )
                        self._check()
                        if stream_result.status:
                            raise ToyotaCodecError(
                                "Native multi-receive failed", stream_result.status
                            )
                        if any(
                            len(reply) < len(wire) for reply in stream_result.replies
                        ):
                            raise ToyotaCodecError(
                                "Freeze packet prefix absent", SHORT_REPLY
                            )
                        payload = b"".join(
                            reply[len(wire) :] for reply in stream_result.replies
                        )
                        if len(payload) > 255:
                            raise SessionError("Native freeze signal storage exceeded")
                        multi_payloads[wire] = payload
                    payload = multi_payloads[wire]
                else:
                    if wire in responses:
                        cached = responses[wire]
                        if isinstance(cached, ToyotaCodecError):
                            raise cached
                        reply = cached
                    else:
                        spec = CommandSpec(
                            selected.frame,
                            selected=selected,
                            provenance=selected.provenance,
                        )
                        retries = self._native_retry_count(selected.settings_record[14])
                        for attempt in range(retries + 1):
                            try:
                                reply = self._native_call(spec, wire)
                                break
                            except ToyotaCodecError as error:
                                if error.code != 0x90020323 and attempt < retries:
                                    continue
                                if error.code in (0x91010009, 0x90020323):
                                    responses[wire] = NativeStatus(0x91010009)
                                raise
                        responses[wire] = reply
                    if family in ("dk", "dk_at"):
                        dk_rows.append(freeze)
                        payload = parse_dk_freeze(
                            reply, len(wire), dk_rows, dk_lengths
                        )[-1]
                    elif family == "psa":
                        payload = reply[2:]
                    elif family == "dk_abs":
                        payload = reply[2:-2]
                    elif family == "roof":
                        size = len(reply) - len(wire) - 2
                        payload = reply[2 : 2 + max(0, size)]
                    elif family == "no_frame_number":
                        length = freeze_lengths.get(freeze[79], 0)
                        if len(reply) == length + 3:
                            start = len(wire)
                        elif len(reply) == length + 2:
                            start = len(wire) - 1
                        else:
                            raise ToyotaCodecError(
                                "Freeze PID reply length mismatch", SHORT_REPLY
                            )
                        payload = reply[start:]
                    else:
                        payload = reply[len(wire) :]
                    begin, end = struct.unpack_from("<HH", freeze, 62)
                    if not payload or begin > end or end >= len(payload) * 8:
                        raise ToyotaCodecError(
                            "Freeze selected bits absent", SHORT_REPLY
                        )
            except ToyotaCodecError as error:
                if family in ("dk_abs", "psa") and error.code in skipped:
                    continue
                raise
            if family in ("dk", "dk_at") and freeze[77] == 2:
                continue
            self._check()
            begin, end = struct.unpack_from("<HH", freeze, 62)
            if (
                not payload
                or begin > end
                or end - begin >= 32
                or end >= len(payload) * 8
            ):
                raise ToyotaCodecError("Freeze selected bits absent", SHORT_REPLY)
            try:
                metadata = selected_freeze_metadata(profile, freeze, lsb)
            finally:
                self._check()
            raw = extract_bits(payload, metadata.start_bit, metadata.end_bit)
            value = (
                affine(
                    raw,
                    metadata.multiplier,
                    metadata.divisor,
                    metadata.offset,
                    metadata.end_bit - metadata.start_bit + 1,
                    metadata.sign_mode,
                )
                & 0xFFFFFFFF
            )
            item = CgwFreeze(freeze, payload, metadata, raw, value)
            if family in ("dk", "dk_at"):
                pending.append((index, item))
            else:
                result.append(item)
        if family in ("dk", "dk_at") and pending:
            order = [0] * len(pending)
            for index, (source_index, _) in enumerate(pending):
                rank = sum(other[0] < source_index for other in pending) & 255
                order[rank] = index
            result.extend(pending[index][1] for index in order)
        return tuple(result)

    def freeze_dk_iso_profile(
        self,
        profile: VehicleProfile,
        communication: NativeCommunication,
        *,
        lsb: SignalLSB,
        output: list[CgwFreeze] | None = None,
        begin_operation: bool = True,
    ) -> tuple[CgwFreeze, ...]:
        """DK ISO exported FFD: raw ALL frames, FIRST reply map, then metadata.

        Common5C450 retries all statuses and uses its retained connection bus;
        raw byte replies intentionally have no positive-service validation.
        """
        from scripts.native_communication import CommunicationError, NativeCommunication
        from scripts.toyota_workflows import selected_freeze_metadata

        if not isinstance(communication, NativeCommunication):
            raise TypeError("Concrete selected native communication required")
        if (
            communication.profile is not profile
            or communication.ecu != self.ecu
            or lsb.cache is not communication.cache
        ):
            raise SessionError("DK ISO wire and metadata selected source differ")
        if begin_operation:
            self._begin()
            communication.begin_operation(limits=self.limits)
        self._check()
        frames = _profile_frames(profile, 0x11)
        if not frames:
            raise ToyotaCodecError("DK ISO freeze frame group empty", 0xC0040101)
        first: bytes | None = None
        for selected in frames:
            self._check()
            try:
                result = communication.execute_raw(selected)
            finally:
                self._check()
            if result.status:
                raise CommunicationError(result)
            if first is None:
                first = result.response
        assert first is not None
        if not 2 <= len(first) <= 255:
            raise ToyotaCodecError("DK ISO freeze reply lacks groups", SHORT_REPLY)
        data: dict[int, bytes] = {}
        cursor = 1
        while cursor < len(first):
            pid = first[cursor]
            cursor += 1
            if 20 not in profile.database.sections:
                raise ToyotaCodecError("Selected FreezePid table absent", 0xA0030107)
            freeze_pids = profile.records(20)
            if any(len(row) != 8 for row in freeze_pids):
                raise ToyotaCodecError("Invalid FreezePid definition", 0xC0040102)
            row = next((row for row in freeze_pids if row[4] == pid), None)
            if row is not None:
                length = row[5]
            else:
                if 6 not in profile.database.sections:
                    raise ToyotaCodecError("Selected PID table absent", 0xA0030107)
                pids = profile.records(6)
                if any(len(row) != 8 for row in pids):
                    raise ToyotaCodecError("Invalid PID definition", 0xC0040102)
                row = next((row for row in pids if row[2] == pid), None)
                if row is None:
                    raise ToyotaCodecError("DK ISO PID group empty", 0xC0040101)
                length = row[3]
            if not length:
                raise ToyotaCodecError("DK ISO PID length is zero", 0xC0050102)
            if cursor + length > len(first):
                raise ToyotaCodecError("DK ISO PID data truncated", SHORT_REPLY)
            data.setdefault(pid, first[cursor : cursor + length])
            cursor += length
        if 10 not in profile.database.sections:
            raise ToyotaCodecError("Selected Freeze table absent", 0xA0030107)
        rows = profile.records(10)
        if len(rows) > 0x7FFF or any(len(row) != 84 for row in rows):
            raise ToyotaCodecError("Invalid selected Freeze group", 0xC0040102)
        _hydrate_freeze_names_profile(profile, rows)
        result_items = [] if output is None else output
        for row in rows:
            self._check()
            if not row[78] & 2 or row[77] == 2:
                continue
            raw = dk_iso_freeze_value(row, data)
            try:
                metadata = selected_freeze_metadata(profile, row, lsb)
            finally:
                self._check()
            value = (
                affine(
                    raw,
                    metadata.multiplier,
                    metadata.divisor,
                    metadata.offset,
                    metadata.end_bit - metadata.start_bit + 1,
                    metadata.sign_mode,
                )
                & 0xFFFFFFFF
            )
            result_items.append(CgwFreeze(row, data[row[79]], metadata, raw, value))
        return tuple(result_items)

    def freeze_cgw_profile(
        self,
        profile: VehicleProfile,
        code: int,
        number: int,
        functions: FunctionCache,
        *,
        support_cache: MonitorSupportCache,
        lsb: SignalLSB,
        begin_operation: bool = True,
        response_cache: dict[bytes, bytes | ToyotaCodecError] | None = None,
        output: list[CgwFreeze] | None = None,
    ) -> tuple[CgwFreeze, ...]:
        """Common82480: selected DTC→SignalCheck→Freeze, wire then metadata.

        The native cache is shared by rows in this call. Metadata/LSB errors are
        fatal; only the ten statuses from the data-read branch omit a signal.
        """
        from scripts.toyota_workflows import selected_freeze_metadata

        if type(code) is not int or not 0 <= code <= 65535:
            raise ValueError("CGW DTC must fit uint16")
        if type(number) is not int or not 0 <= number <= 255:
            raise ValueError("CGW frame number must fit byte")
        if lsb.cache is not support_cache or support_cache.profile is not profile:
            raise SessionError("CGW wire support/LSB must share selected profile/cache")
        if begin_operation:
            self._begin()
        checks = profile.dtc_signal_checks(code)
        result = [] if output is None else output
        cache = {} if response_cache is None else response_cache
        skipped = {
            0x91010009,
            0x90020321,
            0x90020323,
            0xA0040201,
            0xC0040001,
            0xA0040202,
            0x90020327,
            0x91020320,
            0x91020310,
            0x91020322,
        }
        previous = self.commands
        try:
            for check in checks:
                self._check()
                if len(check) != 8:
                    raise ToyotaCodecError(
                        "Invalid selected SignalCheck row", INVALID_RECORD
                    )
                signal = struct.unpack_from("<H", check, 2)[0]
                # Native wildcard BYTE0x100 ignores Freeze.pid; FIRST signal match.
                if 10 not in profile.database.sections:
                    raise ToyotaCodecError("Selected Freeze table absent", 0xA0030107)
                rows: list[bytes] = []
                for row in profile.records(10):
                    if (
                        len(row) == 84
                        and struct.unpack_from("<H", row, 56)[0] == signal
                    ):
                        rows.append(row)
                    elif rows:
                        break
                _hydrate_freeze_names_profile(profile, rows)
                freeze = rows[0] if rows else None
                if freeze is None:
                    raise ToyotaCodecError("CGW Freeze signal group empty", 0xC0040101)
                if not freeze[78] & 2:
                    continue
                _, supported = functions.function(1, 4, 3)
                if not supported:
                    continue
                frames = _profile_frames(profile, 0x11)
                if len(frames) != 1:
                    raise ToyotaCodecError(
                        "P4 freeze requires one selected frame", 0xC0040102
                    )
                selected = frames[0]
                self.commands = {
                    "native-cgw": CommandSpec(
                        selected.frame,
                        provenance=selected.provenance,
                        selected=selected,
                    )
                }
                try:
                    payload = self._read_p4(
                        "native-cgw",
                        freeze,
                        None,
                        number,
                        begin_operation=False,
                        response_cache=cache,
                        retries=selected.settings_record[14],
                        support_cache=support_cache,
                    )
                except ToyotaCodecError as error:
                    if error.code in skipped:
                        continue
                    raise
                self._check()
                try:
                    metadata = selected_freeze_metadata(profile, freeze, lsb)
                finally:
                    self._check()
                raw = extract_bits(payload, metadata.start_bit, metadata.end_bit)
                value = (
                    affine(
                        raw,
                        metadata.multiplier,
                        metadata.divisor,
                        metadata.offset,
                        metadata.end_bit - metadata.start_bit + 1,
                        metadata.sign_mode,
                    )
                    & 0xFFFFFFFF
                )
                result.append(CgwFreeze(freeze, payload, metadata, raw, value))
        finally:
            self.commands = previous
        return tuple(result)

    def dtcs_dk_at_profile(
        self,
        profile: VehicleProfile,
        diagnostic_type: int,
        functions: FunctionCache,
        *,
        connection_bus_id: int | None = None,
    ) -> dict[str, object]:
        """GetDiagCodeDk_AT Execute1010 + Common7AF50 two-pass FFD.

        InitEcu's literal NULL SendInt ignores its native send status. Both FFD
        passes resend the same patched function6 frame; pass2 labels newly
        matched entries with the original ASCII string "1".
        """
        if type(diagnostic_type) is not int or diagnostic_type not in (1, 2, 3):
            raise ToyotaCodecError("Unsupported diagnostic type", 0xC0040001)
        function_id = 9 + diagnostic_type
        selected = _profile_frames(profile, function_id)[0]
        previous = self.commands
        try:
            self.commands = {
                "native-at-dtc": CommandSpec(
                    selected.frame, provenance=selected.provenance, selected=selected
                )
            }
            codes = self.dtcs_can(
                "native-at-dtc",
                retries=selected.settings_record[14],
                selected_profile=profile,
            )
        finally:
            self.commands = previous
        records = [DtcFreeze(code) for code in codes]
        labels = [""] * len(codes)
        if not codes:
            return {
                "codes": codes,
                "freeze_records": tuple(records),
                "freeze_labels": tuple(labels),
            }
        _, supported = functions.function(1, 4, 3)
        if not supported:
            return {
                "codes": codes,
                "freeze_records": tuple(records),
                "freeze_labels": tuple(labels),
            }
        # The wrapper repeats GetCommFrmInfo before InitEcu, preserving faults.
        initial = _profile_frames(profile, function_id)[0]
        if connection_bus_id is None:
            raise ToyotaCodecError("Connection cache for InitEcu absent", 0xC0040601)
        self._frame_sends(
            [
                NativeFrameSend(
                    "SendInt",
                    profile.category,
                    None,
                    struct.unpack_from("<I", initial.settings_record)[0],
                    connection_bus_id,
                    1,
                    1,
                )
            ],
            ignore_status=True,
            begin_operation=False,
        )
        frames = _profile_frames(profile, 6)
        if len(frames) != 1:
            raise ToyotaCodecError("DK AT freeze requires one frame", 0xC0040102)
        rows = profile.records(2)
        if len(rows) != 1 or len(rows[0]) != 4:
            raise ToyotaCodecError("DK AT requires one SupFreeze row", 0xC0040102)
        frame = frames[0]
        number = rows[0][2]
        request = freeze_support_request(frame.frame.request, number)
        command = CommandSpec(
            replace(frame.frame, request=request),
            provenance=frame.provenance,
            selected=frame,
        )
        for pass_number in range(2):
            try:
                for attempt in range(
                    self._native_retry_count(frame.settings_record[14]) + 1
                ):
                    try:
                        reply = self._native_call(command, request)
                        break
                    except ToyotaCodecError as error:
                        if (
                            error.code == 0x90020323
                            or attempt
                            == self._native_retry_count(frame.settings_record[14])
                        ):
                            raise
            except ToyotaCodecError as error:
                if error.code == 0x91010009:
                    continue
                raise
            if len(reply) < len(request) + 2:
                raise ToyotaCodecError("DK AT freeze response too short", SHORT_REPLY)
            code = int.from_bytes(reply[-2:], "big")
            for index, record in enumerate(records):
                if record.code != code:
                    continue
                if not record.supported:
                    records[index] = DtcFreeze(code, True, number)
                    labels[index] = "1" if pass_number else ""
                elif number < record.number:
                    records[index] = replace(record, number=number)
        return {
            "codes": codes,
            "freeze_records": tuple(records),
            "freeze_labels": tuple(labels),
        }

    def dtcs_dk_cgw_profile(
        self,
        profile: VehicleProfile,
        diagnostic_type: int,
        functions: FunctionCache,
        *,
        support_cache: MonitorSupportCache,
        lsb: SignalLSB,
        output: dict[str, object] | None = None,
    ) -> dict[str, object]:
        """GetDiagCodeDk_CGW Execute1010 + Common7B580 FFD association."""
        if type(diagnostic_type) is not int or diagnostic_type not in (1, 2, 3):
            raise ToyotaCodecError("Unsupported diagnostic type", 0xC0040001)
        selected = _profile_frames(profile, 9 + diagnostic_type)[0]
        result = {} if output is None else output
        previous = self.commands
        try:
            self.commands = {
                "native-cgw-dtc": CommandSpec(
                    selected.frame, provenance=selected.provenance, selected=selected
                )
            }
            codes = self.dtcs_can(
                "native-cgw-dtc",
                retries=selected.settings_record[14],
                selected_profile=profile,
                output=result,
            )
        finally:
            self.commands = previous
        records = cast(list[DtcFreeze], result["freeze_records"])
        if codes and diagnostic_type != 3:
            _, supported = functions.function(1, 4, 3)
            if supported:
                # Common7B580 queries SupFreeze directly; no function6 lookup.
                rows = profile.records(2)
                if len(rows) != 1 or len(rows[0]) != 4:
                    raise ToyotaCodecError("CGW requires one SupFreeze row", 0xC0040102)
                number = rows[0][2]
                cache: dict[bytes, bytes | ToyotaCodecError] = {}
                for index, code in enumerate(codes):
                    values = self.freeze_cgw_profile(
                        profile,
                        code,
                        number,
                        functions,
                        support_cache=support_cache,
                        lsb=lsb,
                        begin_operation=False,
                        response_cache=cache,
                    )
                    if len(values) > 1 and values[1].value:
                        records[index] = DtcFreeze(code, True, number)
        result["freeze_records"] = tuple(records)
        return result

    def freeze_cgw(
        self,
        name: str,
        freezes: Sequence[bytes],
        number: int,
        positions_by_pid: Mapping[int, bytes],
        *,
        function_supported: bool,
    ) -> dict[int, bytes]:
        """Common82480 selected CGW rows; native skip statuses and per-call cache."""
        if type(function_supported) is not bool:
            raise ValueError("CGW function support must be explicitly boolean")
        if not function_supported:
            return {}
        self._spec(name)
        for row in freezes:
            if len(row) != 84:
                raise ToyotaCodecError(
                    "Invalid selected CGW Freeze row", INVALID_RECORD
                )
            if row[78] & 2 and row[79] not in positions_by_pid:
                raise SessionError(f"Selected CGW PID positions absent: {row[79]}")
        self._begin()
        cache: dict[bytes, bytes | ToyotaCodecError] = {}
        result: dict[int, bytes] = {}
        skipped = {
            0x91010009,
            0x90020321,
            0x90020323,
            0xA0040201,
            0xC0040001,
            0xA0040202,
            0x90020327,
            0x91020320,
            0x91020310,
            0x91020322,
        }
        for index, row in enumerate(freezes):
            if not row[78] & 2:
                continue
            try:
                result[index] = self._read_p4(
                    name,
                    row,
                    positions_by_pid[row[79]],
                    number,
                    begin_operation=False,
                    response_cache=cache,
                )
            except ToyotaCodecError as error:
                if error.code not in skipped:
                    raise
        return result

    @staticmethod
    def _initial_value(payload: bytes, freeze: bytes, physical: bytes) -> int:
        metadata = signal_metadata(freeze, physical)
        begin, end = metadata["start_bit"], metadata["end_bit"]
        try:
            raw = extract_bits(payload, begin, end)
        except ValueError as error:
            raise ToyotaCodecError(
                "Initial value lacks selected bits", SHORT_REPLY
            ) from error
        # CCmdFrzFrmDat.GetValue A7D10 calls A927C/A929F directly: no
        # selector dispatch or decimal-precision/display conversion.
        return (
            affine(
                raw,
                metadata["multiplier"],
                metadata["divisor"],
                metadata["offset"],
                end - begin + 1,
                metadata["sign_mode"],
            )
            & 0xFFFFFFFF
        )

    def read_initial_p3(self, name: str, freeze: bytes, physical: bytes) -> int:
        signal_metadata(freeze, physical)
        return self._initial_value(self.read_ecu_p3(name, freeze), freeze, physical)

    def read_initial_p4(
        self, name: str, freeze: bytes, physical: bytes, positions: bytes
    ) -> int:
        signal_metadata(freeze, physical)
        return self._initial_value(
            self.read_ecu_p4(name, freeze, positions), freeze, physical
        )

    def freeze_p3(self, name: str, freeze: bytes, number: int) -> bytes:
        spec = self._spec(name)
        request = freeze_request_p3(spec.frame.request, freeze, number)
        self._begin()
        reply = self._native_call(spec, request)
        return freeze_payload_p3(replace(spec.frame, request=request), reply)

    def read_routine_data(
        self, name: str, routine_id: int, command: bytes = b""
    ) -> bytes:
        return self._read_routine_data(name, routine_id, command, begin_operation=True)

    def _read_routine_data(
        self, name: str, routine_id: int, command: bytes, *, begin_operation: bool
    ) -> bytes:
        """Common6b0f0 GetRIDReceiveData; selected0xcc/0xd7 template, prefix4."""
        spec = self._spec(name)
        if type(routine_id) is not int or not 0 <= routine_id <= 65535:
            raise ValueError("Routine ID must fit uint16")
        if (
            len(spec.frame.request) < 4
            or len(spec.frame.request) + len(command) > 65535
        ):
            raise ToyotaCodecError(
                "Routine data request outside native bounds", INVALID_RECORD
            )
        request = bytearray(spec.frame.request)
        request[2:4] = routine_id.to_bytes(2, "big")
        request.extend(command)
        if begin_operation:
            self._begin()
        reply = self._native_call(spec, bytes(request), extended=True)
        if len(reply) < 4:
            raise ToyotaCodecError(
                "Routine data lacks native four-byte prefix", SHORT_REPLY
            )
        return reply[4:]

    def routine_data_no_enable_list(
        self,
        routine_id: int,
        flags: int,
        *,
        command_name: str | None = None,
        status_name: str | None = None,
        command: bytes = b"",
        record: bytes = b"",
        response_cache: dict[tuple[str, int, bytes], bytes] | None = None,
    ) -> dict[str, object]:
        """Common6ae40: selected0xcc probes/command then0xd7 signal extraction."""
        if (
            type(routine_id) is not int
            or not 0 < routine_id <= 65535
            or type(flags) is not int
            or not 0 <= flags <= 255
            or not flags & 15
        ):
            raise ToyotaCodecError("Invalid native routine data arguments", 0xC0040001)
        self._begin()
        cache: dict[tuple[str, int, bytes], bytes] = (
            response_cache if response_cache is not None else {}
        )

        def read(name: str | None, selected_rid: int, tail: bytes) -> bytes:
            if name is None:
                raise SessionError("Routine phase descriptor not selected")
            self._check()
            key = name, selected_rid, tail
            if key not in cache:
                cache[key] = self._read_routine_data(
                    name, selected_rid, tail, begin_operation=False
                )
            return cache[key]

        result: dict[str, object] = {
            "phase": 0,
            "supported": None,
            "value": None,
            "payload": None,
        }
        for bit, probe_rid, mode in ((1, 0x1001, 1), (2, routine_id & 0xFF00, 2)):
            if flags & bit:
                support = routine_support_bit(
                    read(command_name, probe_rid, command), routine_id, mode
                )
                result["supported"] = support
                if not support:
                    return result
                result["phase"] = mode
        if flags & 4:
            if not command:
                raise ToyotaCodecError("Routine command bytes required", 0xC0040001)
            result["payload"] = read(command_name, routine_id, command)
        if flags & 8:
            payload = read(status_name, routine_id, b"")
            result["payload"] = payload
            if len(record) < 24:
                raise ToyotaCodecError(
                    "Routine signal record not selected", INVALID_RECORD
                )
            begin, end = struct.unpack_from("<HH", record, 20)
            if begin > end or end - begin >= 32:
                raise ToyotaCodecError(
                    "Routine signal bit range invalid", INVALID_RECORD
                )
            try:
                result["value"] = extract_bits(payload, begin, end)
            except ValueError as error:
                raise ToyotaCodecError(
                    "Routine reply lacks selected signal", SHORT_REPLY
                ) from error
        return result

    def send_comm_did(
        self, name: str, record: bytes, positions: bytes, command: bytes
    ) -> bytes:
        """Common1aa30..1b29c exact selected DID command/rejection contract."""
        spec = self._spec(name)
        request = comm_did_request(spec.frame.request, record, positions, command)
        self._begin()
        reply = self._native_call(spec, request)
        if len(reply) == 3 and reply[2] == 0:
            raise ToyotaCodecError("Native DID command rejected", 0xA0040207)
        return reply

    def read_comm_pid(
        self,
        name: str,
        record: bytes,
        category_type: int,
        *,
        positions: bytes | None = None,
        support_cache: MonitorSupportCache | None = None,
        bcd: bool = False,
        begin_operation: bool = True,
        response_cache: dict[bytes, bytes] | None = None,
    ) -> int:
        return self._read_comm_pid(
            name,
            record,
            category_type,
            positions=positions,
            support_cache=support_cache,
            bcd=bcd,
            begin_operation=begin_operation,
            response_cache=response_cache,
        )

    def _read_comm_pid(
        self,
        name: str,
        record: bytes,
        category_type: int,
        *,
        positions: bytes | None = None,
        support_cache: MonitorSupportCache | None = None,
        bcd: bool = False,
        begin_operation: bool = True,
        response_cache: dict[bytes, bytes] | None = None,
    ) -> int:
        """Common1b880 GetPidData from one selected CommPidData44 row.

        Category types0x14/0x15/0x34 select extended function0xca; all
        other types use ordinary function0x6b and cached support expansion.
        """
        if len(record) != 44:
            raise ToyotaCodecError("Invalid selected CommPidData row", INVALID_RECORD)
        if type(category_type) is not int or not 0 <= category_type <= 255:
            raise ToyotaCodecError("Invalid ECU category type", 0xC0040001)
        begin, end = struct.unpack_from("<HH", record, 20)
        if begin > end or end - begin >= 32:
            raise ToyotaCodecError("Invalid CommPidData bit range", INVALID_RECORD)
        extended = category_type in (0x14, 0x15, 0x34)
        spec = self._spec(name)
        request = bytearray(spec.frame.request)
        prefix = 3 if extended else 2
        if not prefix <= len(request) <= (65535 if extended else 255):
            raise ToyotaCodecError("Invalid CommPidData request length", 0xC0040102)
        if extended:
            request[1:3] = struct.unpack_from("<H", record, 34)[0].to_bytes(2, "big")
        else:
            request[1] = record[39]
            if positions is None and support_cache is None:
                raise SessionError("CommPidData support positions/cache not selected")
            if positions is not None and not 1 <= len(positions) <= 255:
                raise ToyotaCodecError(
                    "Invalid CommPidData support positions", 0xC0040001
                )
        if begin_operation:
            self._begin()
        self._check()
        key = bytes(request)
        if response_cache is not None and key in response_cache:
            reply = response_cache[key]
        else:
            reply = self._native_call(spec, key, extended=extended)
            if response_cache is not None:
                response_cache[key] = reply
        if not extended and positions is None:
            # Native1BD0C sends/caches data before1BF8A CreatePid/ConvertPid.
            size = (len(reply) - prefix) & 255
            if len(reply) < prefix or len(key) + size > len(reply):
                raise ToyotaCodecError(
                    "CommPidData reply boundary invalid", SHORT_REPLY
                )
            assert support_cache is not None
            self._check()
            try:
                masks = support_cache.support_bits(1)
            finally:
                self._check()
            positions = masks.get(record[39])
            if positions is None or not 1 <= len(positions) <= 255:
                raise ToyotaCodecError("Selected PID support data absent", 0xC0040001)
        return decode_comm_pid_reply(
            record, category_type, key, reply, positions=positions, bcd=bcd
        )

    def read_absolute_pid_logs(
        self,
        setter_name: str,
        reader_name: str,
        log_numbers: Sequence[int],
        setter_record: bytes,
        setter_positions: bytes,
        components: Sequence[tuple[int, bytes, bool]],
        positions_by_pid: Mapping[int, bytes],
    ) -> list[dict[str, object]]:
        """AbsSaveLog2940 selected category0x04 PID log loop and skip policy."""
        setter = self._spec(setter_name)
        self._spec(reader_name)
        for number in log_numbers:
            if type(number) is not int or not 0 <= number <= 0xFFFFFFFF:
                raise ToyotaCodecError("Invalid saved log number", 0xC0040001)
        comm_did_request(
            setter.frame.request, setter_record, setter_positions, b"\x00\x00"
        )
        for component, row, bcd in components:
            if type(component) is not int or not 0x8F <= component <= 0x9A:
                raise ToyotaCodecError("Invalid saved PID component ID", 0xC0040001)
            if len(row) != 44 or type(bcd) is not bool:
                raise ToyotaCodecError(
                    "Invalid selected CommPidData component", INVALID_RECORD
                )
            begin, end = struct.unpack_from("<HH", row, 20)
            if begin > end or end - begin >= 32:
                raise ToyotaCodecError(
                    "Invalid saved PID component bits", INVALID_RECORD
                )
            if row[39] not in positions_by_pid:
                raise SessionError("Saved PID support positions not selected")
        skip = {
            0x91010009,
            0x90020321,
            0x90020323,
            0xA0040201,
            0xC0040001,
            0xA0040202,
            0x90020327,
            0x91020320,
            0x91020310,
            0x91020322,
        }
        self._begin()
        result: list[dict[str, object]] = []
        for number in log_numbers:
            self._check()
            include = True
            request = comm_did_request(
                setter.frame.request,
                setter_record,
                setter_positions,
                (number & 65535).to_bytes(2, "big"),
            )
            try:
                reply = self._native_call(setter, request)
                if len(reply) == 3 and reply[2] == 0:
                    raise ToyotaCodecError(
                        "Native saved-log selection rejected", 0xA0040207
                    )
            except ToyotaCodecError as error:
                if error.code not in skip:
                    raise
                # Native still reads all components after a masked selector
                # failure but suppresses the completed log (2c07/2d6a).
                include = False
            cache: dict[bytes, bytes] = {}
            values: list[tuple[int, int, int]] = []
            assembled: dict[int, int] | None = {}
            for component, row, bcd in components:
                self._check()
                try:
                    value = self._read_comm_pid(
                        reader_name,
                        row,
                        4,
                        positions=positions_by_pid[row[39]],
                        bcd=bcd,
                        begin_operation=False,
                        response_cache=cache,
                    )
                except ToyotaCodecError as error:
                    if error.code not in skip:
                        raise
                    assembled = None
                    break
                begin, end = struct.unpack_from("<HH", row, 20)
                values.append((component, value, end - begin + 1))
                assembled = assemble_absolute_log(values, number, pid_identifiers=True)
                if assembled is None:
                    break
            if include and assembled is not None:
                result.append({"log_number": number, "components": assembled})
        return result

    def read_absolute_routine_logs(
        self,
        command_name: str,
        status_name: str,
        log_numbers: Sequence[int],
        components: Sequence[tuple[int, bytes, bool]],
    ) -> list[dict[str, object]]:
        """AbsTimeStampSaveLog36aa..3c33 selected/supported routine components.

        Each component is (logical ID1..12, selected CommRidData row, BCD flag).
        Metadata/support selection precedes this helper; no support is invented.
        """
        self._spec(command_name)
        self._spec(status_name)
        for number in log_numbers:
            if type(number) is not int or not 0 <= number <= 0xFFFFFFFF:
                raise ToyotaCodecError("Invalid saved log number", 0xC0040001)
        selected: list[tuple[int, int, int, bool]] = []
        for component, row, bcd in components:
            if type(component) is not int or not 1 <= component <= 12:
                raise ToyotaCodecError("Invalid saved log component ID", 0xC0040001)
            if len(row) != 36 or type(bcd) is not bool:
                raise ToyotaCodecError(
                    "Invalid selected CommRidData component", INVALID_RECORD
                )
            begin, end = struct.unpack_from("<HH", row, 20)
            if begin > end or end - begin >= 32:
                raise ToyotaCodecError(
                    "Invalid saved log component bits", INVALID_RECORD
                )
            selected.append((component, begin, end, bcd))
        self._begin()
        result: list[dict[str, object]] = []
        for number in log_numbers:
            self._check()
            # The original constructs one fresh CCommCachePlus per log; only
            # identical successful command/status frames share its replies.
            cache: dict[tuple[str, bytes], bytes] = {}
            values: list[tuple[int, int, int]] = []
            assembled: dict[int, int] | None = {}
            for component, begin, end, bcd in selected:
                self._check()
                try:
                    for name, tail in (
                        (command_name, (number & 65535).to_bytes(2, "big")),
                        (status_name, b""),
                    ):
                        key = name, tail
                        if key not in cache:
                            cache[key] = self._read_routine_data(
                                name, 0x1104, tail, begin_operation=False
                            )
                    try:
                        value = extract_bits(cache[status_name, b""], begin, end)
                    except ValueError as error:
                        raise ToyotaCodecError(
                            "Saved log reply lacks selected component", SHORT_REPLY
                        ) from error
                    if bcd:
                        value = decode_bcd32(value)
                    values.append((component, value, end - begin + 1))
                    assembled = assemble_absolute_log(values, number)
                except ToyotaCodecError:
                    # Native wire/BCD failures discard this log and continue
                    # with the next. Host cancellation/deadline are not caught.
                    assembled = None
                if assembled is None:
                    break
            if assembled is not None:
                result.append({"log_number": number, "components": assembled})
        return result

    def read_routine_signal(self, name: str, routine_id: int, record: bytes) -> int:
        """Common6b038 flag8 extraction from selected ECU-specific row20/22."""
        if len(record) < 24:
            raise ToyotaCodecError(
                "Selected routine signal row truncated", INVALID_RECORD
            )
        begin, end = struct.unpack_from("<HH", record, 20)
        if begin > end or end - begin >= 32:
            raise ToyotaCodecError(
                "Selected routine signal bit range invalid", INVALID_RECORD
            )
        payload = self.read_routine_data(name, routine_id)
        try:
            return extract_bits(payload, begin, end)
        except ValueError as error:
            raise ToyotaCodecError(
                "Routine reply lacks selected signal", SHORT_REPLY
            ) from error

    def freeze_multi_p3(
        self, name: str, freeze: bytes, number: int, *, retries: int = 0
    ) -> bytes:
        """Common24d60/61720: per-packet send-length prefix, timeout terminator."""
        if type(retries) is not int or not 0 <= retries <= 255:
            raise ValueError("Multi-receive retry count must fit ComSet byte")
        spec = self._spec(name)
        request = freeze_request_p3(spec.frame.request, freeze, number)
        if len(request) > 255:
            raise ToyotaCodecError(
                "Multi-receive send exceeds native byte length", INVALID_RECORD
            )
        self._begin()
        chunks: list[bytes] = []
        attempt = 0
        while True:
            try:
                reply = self._call(b"" if chunks else request)
                if not reply or len(reply) > 255 or reply[0] != request[0] | 0x40:
                    raise ToyotaCodecError(
                        "Invalid native multi-receive response", INVALID_REPLY
                    )
                chunks.append(reply)
            except ToyotaCodecError as error:
                if chunks and error.code == 0x91010009:
                    break
                if chunks or error.code == 0x90020323 or attempt >= retries:
                    raise
                attempt += 1
        if any(len(chunk) < len(request) for chunk in chunks):
            raise ToyotaCodecError(
                "Multi-receive response lacks packet prefix", SHORT_REPLY
            )
        payload = b"".join(chunk[len(request) :] for chunk in chunks)
        if len(payload) > 255:
            raise ToyotaCodecError(
                "Multi-receive exceeds native signal byte buffer", INVALID_RECORD
            )
        begin, end = struct.unpack_from("<HH", freeze, 62)
        if not payload or begin > end or end >= len(payload) * 8:
            raise ToyotaCodecError(
                "Multi-receive data lacks selected signal", SHORT_REPLY
            )
        return payload

    def freeze_dk(
        self,
        name: str,
        freezes: Sequence[bytes],
        number: int,
        pid_lengths: Mapping[int, int],
    ) -> list[bytes]:
        """Common23d20 selected series; successful identical frames use native cache."""
        spec = self._spec(name)
        if not 4 <= len(spec.frame.request) <= 255:
            raise ToyotaCodecError("DK freeze descriptor invalid", 0xC0040102)
        if type(number) is not int or not 0 <= number <= 255:
            raise ValueError("DK freeze number must fit byte")
        for row in freezes:
            if len(row) != 84:
                raise ToyotaCodecError("Invalid DK Freeze row", INVALID_RECORD)
            length = pid_lengths.get(row[79])
            if type(length) is not int or not 0 < length <= 255:
                raise SessionError(f"Selected DK PID length unavailable: {row[79]}")
            begin, end = struct.unpack_from("<HH", row, 62)
            if begin > end or end >= length * 8:
                raise ToyotaCodecError(
                    "DK signal exceeds selected PID length", 0xC0040102
                )
        if not freezes:
            return []
        request = bytearray(spec.frame.request)
        request[1] = number
        self._begin()
        reply = self._native_call(spec, bytes(request))
        return parse_dk_freeze(reply, len(request), freezes, pid_lengths)

    def freeze_psa(
        self,
        name: str,
        freeze: bytes,
        *,
        number: int | None = None,
        code: int | None = None,
    ) -> bytes:
        """Common25510/25980: PSA numbered or selected DTC16 freeze request."""
        if (number is None) == (code is None):
            raise ValueError("Select a PSA frame number or DTC code")
        spec = self._spec(name)
        if len(freeze) != 84 or len(spec.frame.request) < (3 if code is None else 4):
            raise ToyotaCodecError("PSA freeze descriptor invalid", 0xC0040102)
        selected = number if code is None else code
        if type(selected) is not int or not 0 <= selected <= (
            255 if code is None else 65535
        ):
            raise ValueError("PSA freeze selector outside native bounds")
        request = bytearray(spec.frame.request)
        request[1] = freeze[79]
        if code is None:
            request[2] = selected
        else:
            request[2:4] = selected.to_bytes(2, "big")
        self._begin()
        reply = self._native_call(spec, bytes(request))
        payload = reply[2:]
        begin, end = struct.unpack_from("<HH", freeze, 62)
        if not payload or begin > end or end >= len(payload) * 8:
            raise ToyotaCodecError(
                "PSA freeze response lacks selected bits", SHORT_REPLY
            )
        return payload

    def freeze_dk_abs(self, name: str, freeze: bytes, number: int) -> bytes:
        """Common24750: DK ABS frame number/PID bytes1/3, two-byte trailer."""
        spec = self._spec(name)
        if len(freeze) != 84 or len(spec.frame.request) < 4:
            raise ToyotaCodecError("DK ABS freeze descriptor invalid", 0xC0040102)
        if type(number) is not int or not 0 <= number <= 255:
            raise ValueError("DK ABS freeze number must fit byte")
        request = bytearray(spec.frame.request)
        request[1], request[3] = number, freeze[79]
        self._begin()
        reply = self._native_call(spec, bytes(request))
        payload = reply[2:-2]
        begin, end = struct.unpack_from("<HH", freeze, 62)
        if not payload or begin > end or end >= len(payload) * 8:
            raise ToyotaCodecError(
                "DK ABS freeze response lacks selected bits", SHORT_REPLY
            )
        return payload

    def freeze_dk_roof(self, name: str, freeze: bytes, number: int) -> bytes:
        """GetFrzFrmDatDk_Roof1050: fixed byte1=1, selected number byte3."""
        spec = self._spec(name)
        if len(freeze) != 84 or len(spec.frame.request) < 4:
            raise ToyotaCodecError("Roof freeze descriptor invalid", 0xC0040102)
        if type(number) is not int or not 0 <= number <= 255:
            raise ValueError("Roof freeze number must fit byte")
        request = bytearray(spec.frame.request)
        request[1], request[3] = 1, number
        self._begin()
        reply = self._native_call(spec, bytes(request))
        size = len(reply) - len(request) - 2
        begin, end = struct.unpack_from("<HH", freeze, 62)
        if size < 1 or begin > end or end >= size * 8:
            raise ToyotaCodecError(
                "Roof freeze response lacks selected bits", SHORT_REPLY
            )
        return reply[2 : 2 + size]

    def freeze_no_frame_number(
        self,
        name: str,
        freeze: bytes,
        number: int,
        pid_lengths: Mapping[int, int],
    ) -> bytes:
        """GetFrzFrmDat_NoFrmNo1050 accepts full or omitted frame-number echo."""
        spec = self._spec(name)
        request = freeze_request_p3(spec.frame.request, freeze, number)
        length = pid_lengths.get(freeze[79])
        if type(length) is not int or not 0 < length <= 255:
            raise SessionError("Selected freeze PID byte length unavailable")
        self._begin()
        reply = self._native_call(spec, request)
        if len(reply) == length + 3:
            start = len(request)
        elif len(reply) == length + 2:
            start = len(request) - 1
        else:
            raise ToyotaCodecError(
                "Freeze response length differs from selected PID", SHORT_REPLY
            )
        payload = reply[start:]
        begin, end = struct.unpack_from("<HH", freeze, 62)
        if begin > end or end >= len(payload) * 8:
            raise ToyotaCodecError("Freeze response lacks selected bits", SHORT_REPLY)
        return payload

    def freeze_p5(self, name: str, code: int, number: int | None = None) -> bytes:
        spec = self._spec(name)
        request = freeze_request_p5(spec.frame.request, code, number)
        self._begin()
        reply = self._native_call(spec, request, extended=True)
        if len(reply) < spec.payload_offset:
            raise ToyotaCodecError("Reply lacks selected payload prefix", SHORT_REPLY)
        return reply[spec.payload_offset :]

    def freeze_p5_data(
        self,
        name: str,
        code: int,
        data_lengths: Mapping[int, int],
        number: int | None = None,
        *,
        zero_count_until_end: bool = False,
        decode: Callable[[int, bytes], object] | None = None,
    ) -> dict[str, object]:
        spec = self._spec(name)
        request = freeze_request_p5(spec.frame.request, code, number)
        # Validate every selected length before starting the diagnostic exchange.
        parse_p5_freeze(bytes(6), data_lengths)
        self._begin()
        reply = self._call(request)
        replace(
            spec,
            frame=replace(spec.frame, request=request),
            check="sid",
            extended=True,
            payload_offset=0,
        ).validate(reply)
        result = parse_p5_freeze(
            reply,
            data_lengths,
            zero_count_until_end=zero_count_until_end,
            decode=decode,
        )
        if result["code"] != code:
            raise ToyotaCodecError(
                "P5 freeze response belongs to another DTC", INVALID_REPLY
            )
        return result

    def freeze_subaru_snapshot(
        self,
        name: str,
        code: int,
        data_lengths: Mapping[int, int],
        *,
        request_number: int,
        decode: Callable[[int, bytes], object] | None = None,
    ) -> dict[str, object]:
        """Common8abf0 ordinary Subaru snapshot, selected request/SSR number."""
        if type(request_number) is not int or not 0 <= request_number <= 255:
            raise ValueError("Subaru snapshot request number must fit byte")
        spec = self._spec(name)
        if spec.payload_offset:
            raise ValueError("Subaru snapshot parser requires full reply prefix")
        request = freeze_request_p5(spec.frame.request, code, request_number)
        parse_p5_freeze(bytes(6), data_lengths)
        self._begin()
        reply = self._call(request)
        replace(
            spec,
            frame=replace(spec.frame, request=request),
            check="sid",
            payload_offset=0,
            extended=True,
        ).validate(reply)
        result = parse_p5_freeze(
            reply,
            data_lengths,
            zero_count_until_end=request_number != 255,
            decode=decode,
            subaru_snapshot=True,
        )
        if result["code"] != code:
            raise ToyotaCodecError(
                "Subaru snapshot belongs to another DTC", INVALID_REPLY
            )
        return result

    def freeze_subaru_stored(
        self,
        name: str,
        data_lengths: Mapping[int, int],
        *,
        request_number: int,
        decode: Callable[[int, bytes], object] | None = None,
    ) -> dict[str, object]:
        """Execute the explicitly selected Subaru stored-record descriptor."""
        spec = self._spec(name)
        if spec.payload_offset:
            raise ValueError("Subaru stored parser requires full reply prefix")
        parse_subaru_stored_freeze(
            bytes(2), data_lengths, request_number=request_number
        )
        self._begin()
        reply = self._call(spec.frame.request)
        replace(spec, check="sid", extended=True).validate(reply)
        return parse_subaru_stored_freeze(
            reply, data_lengths, request_number=request_number, decode=decode
        )

    def freeze_support(
        self,
        name: str,
        support_rows: Sequence[bytes],
        records: Sequence[DtcFreeze],
        *,
        kind: Literal["basic", "history", "timestamp"] = "basic",
        diagnostic_type: int = 0,
        other_records: Sequence[DtcFreeze] = (),
        mask_flags: int = 0,
    ) -> tuple[DtcFreeze, ...]:
        """Execute selected SupFreeze rows and attach minimum native frame IDs."""
        spec = self._spec(name)
        if any(len(row) < 3 for row in support_rows):
            raise ToyotaCodecError("Truncated SupFreeze row", INVALID_RECORD)
        associate_freeze(records, 0, 0, kind=kind)
        mask_comm_error(0, mask_flags)
        self._begin()
        result = tuple(records)
        for row in support_rows:
            number = row[2]
            request = freeze_support_request(spec.frame.request, number)
            frame = replace(spec.frame, request=request)
            try:
                reply = self._call(request)
                frame.check_reply(reply)
            except ToyotaCodecError as error:
                if (
                    error.code == 0x91010009
                    or mask_comm_error(error.code, mask_flags) == 0
                ):
                    continue
                raise
            code = freeze_support_code(frame, reply)
            result, _ = associate_freeze(
                result,
                code,
                number,
                kind=kind,
                diagnostic_type=diagnostic_type,
                other_records=other_records,
            )
        return result

    def vin(self, name: str) -> bytes:
        spec = self._spec(name)
        self._begin()
        return vin_payload_can(spec.frame, self._call(spec.frame.request))

    def vin_multi(self, count_name: str, data_name: str) -> bytes:
        """GetVIN_DT functions 0x8b/0x86; prefix strip per receive, zero filter global."""
        count_spec, data_spec = self._spec(count_name), self._spec(data_name)
        self._begin()
        count_reply = self._call(count_spec.frame.request)
        count_spec.validate(count_reply)
        if len(count_reply) < 3:
            raise ToyotaCodecError("VIN count reply lacks byte 2", SHORT_REPLY)
        count = count_reply[2]
        payload = bytearray()
        for index in range(count):
            reply = self._call(data_spec.frame.request if index == 0 else b"")
            data_spec.validate(reply)
            if len(reply) < 3:
                raise ToyotaCodecError("VIN multi reply lacks prefix", SHORT_REPLY)
            payload.extend(reply[3:])
            if len(payload) > 255:
                raise ToyotaCodecError("VIN exceeds native local buffer", SHORT_REPLY)
        return bytes(value for index, value in enumerate(payload) if value or index > 2)

    def poll(self, names: Sequence[str], cycles: int) -> list[dict[str, object]]:
        if type(cycles) is not int or cycles <= 0:
            raise ValueError("Poll cycles must be positive and finite")
        for name in names:
            self._spec(name)
        self._begin()
        result: list[dict[str, object]] = []
        for cycle in range(cycles):
            self._check()
            for name in names:
                result.append(
                    {
                        "cycle": cycle,
                        "command": name,
                        "payload": self._execute(name).hex(),
                    }
                )
        return result

    def legacy_active_step(self, queue: LegacyActiveQueue, now_ms: int) -> bytes | None:
        """One bounded legacy event exchange; caller owns driver lifecycle.

        Ordinary uses its proven MultiMon state gate. DK/PSA callers invoke
        this only when their selected driver scheduler permits transmission.
        Errors propagate so that the owning driver can perform its own stop.
        """
        if self.active is not None:
            raise SessionError("An active test already owns this session")
        self._begin()
        self._check()
        request = (
            queue.next_request(now_ms)
            if queue.family == "ordinary"
            else queue.send_frame(now_ms)
        )
        if request is None:
            return None
        reply = self._call(request)
        queue.accept(reply, now_ms)
        return reply

    def start_p5_active(self, queue: P5ActiveQueue, now_ms: int = 0) -> bytes | None:
        """Own an explicitly assembled native P5 queue and send its first item."""
        if self.active is not None:
            raise SessionError("An active test already owns this session")
        if type(now_ms) is not int or not 0 <= now_ms <= 0xFFFFFFFF:
            raise ValueError("Native tick must fit uint32")
        if not queue.items or queue.releasing:
            raise SessionError("P5 queue requires pending selected start data")
        self._p5_queue = queue
        self.active = queue
        self.active_state = "running"
        return self.p5_active_step(now_ms)

    def p5_active_step(self, now_ms: int) -> bytes | None:
        queue = self._p5_queue
        if queue is None:
            raise SessionError("No P5 active queue owns this session")
        self._begin()
        try:
            self._check()
            request = queue.next_request(now_ms)
            if request is None:
                return None
            reply = self._call(request)
            queue.accept(reply, now_ms)
            return reply
        except BaseException as original:
            try:
                self.stop_active_test(now_ms=now_ms)
            except BaseException as cleanup:  # noqa: BLE001 -- retain both failures
                raise BaseExceptionGroup(
                    "P5 active step and release failed", [original, cleanup]
                ) from None
            raise

    def _stop_p5_active(self, queue: P5ActiveQueue, now_ms: int = 0) -> list[bytes]:
        queue.stop()
        queue.retry_current()
        replies: list[bytes] = []
        while not queue.finished:
            request = queue.next_request(now_ms)
            if request is None:
                raise SessionError(
                    "Native release did not reach a terminal queue state"
                )
            reply = self._call(request, cleanup=True)
            queue.accept(reply, now_ms)
            replies.append(reply)
        return replies

    def start_active_test(self, test: ActiveTest) -> list[bytes]:
        if self.active is not None:
            raise SessionError("An active test already owns this session")
        for name in (*test.start, *test.status, *test.stop):
            self._spec(name)
        self._begin()
        self._check()
        self.active = test
        self.active_state = "starting"
        try:
            result = [self._execute(name) for name in test.start]
            self.active_state = "running"
            return result
        except BaseException as original:
            # A lost start reply may mean the ECU already applied the command.
            try:
                self.stop_active_test()
            except BaseException as cleanup:  # noqa: BLE001 -- preserve both failures
                raise BaseExceptionGroup(
                    "Active start and cleanup failed", [original, cleanup]
                ) from None
            raise

    def active_test_status(self) -> list[bytes]:
        if self._p5_queue is not None:
            reply = self.p5_active_step(int(self.clock() * 1000) & 0xFFFFFFFF)
            return [] if reply is None else [reply]
        if not isinstance(self.active, ActiveTest):
            raise SessionError("No active test")
        self._begin()
        try:
            values = [self._execute(name) for name in self.active.status]
            complete = self.active.complete is not None and self.active.complete(values)
        except BaseException as original:
            try:
                self.stop_active_test()
            except BaseException as cleanup:  # noqa: BLE001 -- preserve both failures
                raise BaseExceptionGroup(
                    "Active status and cleanup failed", [original, cleanup]
                ) from None
            raise
        if complete:
            self.stop_active_test()
        return values

    def stop_active_test(self, *, now_ms: int = 0) -> list[bytes]:
        if type(now_ms) is not int or not 0 <= now_ms <= 0xFFFFFFFF:
            raise ValueError("Native tick must fit uint32")
        if self.active is None:
            return []
        test = self.active
        self._begin()
        self.active_state = "stopping"
        try:
            values = (
                self._stop_p5_active(self._p5_queue, now_ms)
                if self._p5_queue is not None
                else [self._execute(name, cleanup=True) for name in test.stop]
                if isinstance(test, ActiveTest)
                else []
            )
        except BaseException:
            self.active_state = "stop_failed"
            # Retain ownership so a caller can retry the exact stop operation.
            raise
        self.active = None
        self._p5_queue = None
        self._stop_overrides.clear()
        self.active_state = "stopped"
        return values

    def single_routine(
        self,
        start: str,
        status: str,
        stop: str,
        routine_id: int,
        command: bytes,
        expected_bytes: int,
        patterns: Sequence[bytes],
        *,
        wait: Callable[[float], None] = time.sleep,
    ) -> list[bytes]:
        """Original single-routine start, 200ms, status, 5s, release ordering.

        Tests inject a no-wait callback. Stop failures are surfaced even though
        the shipped stop helper discards its communication result.
        """
        if self.active is not None:
            raise SessionError("An active test already owns this session")
        if len({start, status, stop}) != 3:
            raise ValueError("Routine stage names must be distinct")
        prepared: dict[str, CommandSpec] = {}
        for name in (start, status, stop):
            spec = self._spec(name)
            request = routine_request_p5(
                spec.frame.request, routine_id, command if name == start else b""
            )
            prepared[name] = replace(
                spec,
                frame=replace(spec.frame, request=request),
                extended=True,
                check="both" if spec.check in ("mask", "both") else "sid",
            )
        # Keep patched descriptors local; existing profile commands stay immutable.
        self._begin()
        self._check()
        self.active = ActiveTest((start,), (stop,), (status,))
        self.active_state = "starting"
        replies: list[bytes] = []
        original: BaseException | None = None
        try:
            try:
                replies.append(
                    prepared[start].validate(self._call(prepared[start].frame.request))
                )
            except NativeStatus as error:
                if (
                    error.code == 0x90020321
                    and len(error.reply) > 2
                    and error.reply[2] == 0x22
                ):
                    raise ToyotaCodecError(
                        "Native routine start rejected", 0xA0040207
                    ) from error
                raise
            self.active_state = "running"
            wait(0.2)
            self._check()
            reply = prepared[status].validate(
                self._call(prepared[status].frame.request)
            )
            routine_status_p5(reply, expected_bytes, patterns)
            replies.append(reply)
            wait(5.0)
            self._check()
        except BaseException as error:  # noqa: BLE001 -- cleanup also runs on interrupt
            original = error
        self._begin()
        self.active_state = "stopping"
        try:
            replies.append(
                prepared[stop].validate(
                    self._call(prepared[stop].frame.request, cleanup=True)
                )
            )
        except BaseException as cleanup:
            self.active_state = "stop_failed"
            # Retain the patched release so the ordinary retry method is exact.
            self._stop_overrides[stop] = prepared[stop]
            if original is not None:
                raise BaseExceptionGroup(
                    "Routine and release failed", [original, cleanup]
                ) from None
            raise
        self.active = None
        self.active_state = "stopped"
        if original is not None:
            raise original
        return replies

    def report(self) -> dict[str, object]:
        return {
            "ecu": self.ecu,
            "active_state": self.active_state,
            "physical": "PHYSICAL_UNCONFIRMED",
            "commands": {name: spec.provenance for name, spec in self.commands.items()},
            "trace": [dict(event) for event in self.trace],
        }


def health_check(
    sessions: Mapping[str, ToyotaSession], commands: Sequence[str]
) -> dict[str, dict[str, object]]:
    """Independent ECU failures are recorded; cancellation always propagates."""
    result: dict[str, dict[str, object]] = {}
    for name, session in sessions.items():
        try:
            result[name] = {
                "status": "ok",
                "data": session.poll(commands, 1),
                "provenance": session.report(),
            }
        except Cancelled:
            raise
        except Exception as error:  # noqa: BLE001 -- health isolates every ECU failure
            result[name] = {
                "status": "error",
                "error": str(error),
                "native_status": getattr(error, "code", None),
                "provenance": session.report(),
            }
    return result
