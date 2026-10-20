"""Offline codecs recovered from Techstream 18 native command consumers.

These operate on already selected database records/application payloads. They do
not resolve vehicle support, transmit frames, or assume UDS service identifiers.
See docs/toyota-protocol.md for evidence and deliberate stricter input checks.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

INVALID_REPLY = 0xA0040201
SHORT_REPLY = 0xA0040202
INVALID_ARGUMENT = 0xC0040001
MISSING_RECORD = 0xC0040101
INVALID_RECORD = 0xC0040102


def _uint(value: int, bits: int) -> None:
    if type(value) is not int or not 0 <= value < 1 << bits:
        raise ValueError(f"Expected unsigned {bits}-bit integer")


class ToyotaCodecError(ValueError):
    """A bounded native codec failure; code is the original native status."""

    def __init__(self, message: str, code: int):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class VariableTable:
    """Decoded DDB variable section (directory followed by byte storage)."""

    payload: bytes
    count: int

    def __post_init__(self) -> None:
        if type(self.count) is not int or not 0 <= self.count <= 0xFFFF:
            raise ValueError("Variable count must fit a native reference")
        directory_size = self.count * 6
        if len(self.payload) < directory_size:
            raise ValueError("Truncated variable directory")
        for offset, size in struct.iter_unpack("<IH", self.payload[:directory_size]):
            if size and offset + size > len(self.payload) - directory_size:
                raise ValueError("Variable reference outside byte storage")

    def get(self, reference: int) -> bytes:
        _uint(reference, 16)
        if reference == 0:
            return b""
        if reference > self.count:
            raise ValueError("Variable reference outside directory")
        offset, size = struct.unpack_from("<IH", self.payload, (reference - 1) * 6)
        start = self.count * 6 + offset
        return self.payload[start : start + size] if size else b""


@dataclass(frozen=True)
class CommandFrame:
    """Selected native send/mask/check lists, without Windows pointer fields."""

    request: bytes
    receive_mask: bytes = b""
    receive_check: bytes = b""

    def __post_init__(self) -> None:
        if len(self.request) > 0xFFFF:
            raise ToyotaCodecError(
                "Request exceeds native variable length", INVALID_RECORD
            )
        if max(len(self.receive_mask), len(self.receive_check)) > 0xFFFF:
            raise ToyotaCodecError(
                "Mask/check exceeds native variable length", INVALID_RECORD
            )

    @classmethod
    def from_record(cls, record: bytes, variables: VariableTable) -> CommandFrame:
        """Resolve the proven +2/+4/+6 fields; caller retains other row fields."""
        if len(record) < 8:
            raise ToyotaCodecError("Truncated communication frame row", INVALID_RECORD)
        send, mask, check = struct.unpack_from("<HHH", record, 2)
        return cls(variables.get(send), variables.get(mask), variables.get(check))

    def check_reply(self, reply: bytes) -> bytes:
        """General non-Ext receive: SID check only, preserving application bytes."""
        if not self.request or len(self.request) > 255:
            raise ToyotaCodecError("Ordinary send needs 1..255 bytes", INVALID_RECORD)
        if not reply or len(reply) > 255:
            raise ToyotaCodecError("Reply outside native receive bounds", SHORT_REPLY)
        if reply[0] != self.request[0] | 0x40:
            raise ToyotaCodecError("Unexpected positive reply service", INVALID_REPLY)
        return reply

    def check_mask(self, reply: bytes) -> bytes:
        """The separate CCmdCommCidData mask check; not applied to every command."""
        size = len(self.receive_mask)
        if len(reply) < size or len(self.receive_check) < size:
            raise ToyotaCodecError("Mask check lacks input bytes", SHORT_REPLY)
        if any(
            value & mask != expected
            for value, mask, expected in zip(
                reply, self.receive_mask, self.receive_check, strict=False
            )
        ):
            raise ToyotaCodecError("Reply fails database mask/check", INVALID_REPLY)
        return reply


def mask_comm_error(code: int, flags: int) -> int:
    """CGetDiagCode::MaskCommError flags, without invented status names."""
    _uint(code, 32)
    _uint(flags, 16)
    bit = {0x91010009: 1, 0x90020321: 2, 0x90020323: 4}.get(code, 0)
    return 0 if flags & bit else code


@dataclass(frozen=True)
class DtcChunk:
    """A single native KWP receive chunk, before cross-chunk orchestration."""

    codes: tuple[int, ...]
    needs_more: bool
    zero_terminated: bool
    ignored_tail: bytes


def parse_kwp_dtc_reply(request: bytes, reply: bytes) -> DtcChunk:
    """Reproduce GetKwpDiagCode's <=8-byte chunk and zero-code termination."""
    frame = CommandFrame(request)
    if len(reply) > 8:
        raise ToyotaCodecError("DTC chunk exceeds native 8-byte buffer", SHORT_REPLY)
    frame.check_reply(reply)
    if len(reply) == 1:
        raise ToyotaCodecError("DTC reply has no code bytes", SHORT_REPLY)
    # Native code floors the pair count; preserve any odd leftover explicitly.
    pair_end = 1 + ((len(reply) - 1) // 2) * 2
    codes = []
    for position in range(1, pair_end, 2):
        code = int.from_bytes(reply[position : position + 2], "big")
        if code == 0:
            return DtcChunk(tuple(codes), False, True, reply[position + 2 :])
        codes.append(code)
    return DtcChunk(tuple(codes), len(reply) >= 7, False, reply[pair_end:])


def freeze_request_p3(
    template: bytes, freeze_record: bytes, frame_number: int
) -> bytes:
    """Patch DB-selected P3 request using the native 84-byte Freeze row."""
    _uint(frame_number, 8)
    if len(freeze_record) != 84 or len(template) < 3:
        raise ToyotaCodecError("Invalid P3 freeze row or template", INVALID_RECORD)
    CommandFrame(template)
    return template[:1] + bytes((freeze_record[0x4F], frame_number)) + template[3:]


def freeze_request_p5(
    template: bytes, dtc: int, record_number: int | None = None
) -> bytes:
    """SetDTCToSndFrame: 24-bit big-endian DTC at indices 2,3,4."""
    _uint(dtc, 24)
    if record_number is not None:
        _uint(record_number, 8)
        if record_number == 0:
            raise ToyotaCodecError("P5 record number must be nonzero", INVALID_ARGUMENT)
    if len(template) < (5 if record_number is None else 6):
        raise ToyotaCodecError("Truncated P5 freeze template", INVALID_RECORD)
    CommandFrame(template)
    result = bytearray(template)
    result[2:5] = dtc.to_bytes(3, "big")
    if record_number is not None:
        result[5] = record_number
    return bytes(result)


def freeze_payload_p3(frame: CommandFrame, reply: bytes) -> bytes:
    """Native P3 data extraction skips exactly the send-list length."""
    frame.check_reply(reply)
    if len(reply) <= len(frame.request):
        raise ToyotaCodecError("P3 freeze has no value bytes", SHORT_REPLY)
    return reply[len(frame.request) :]


def vin_payload_can(frame: CommandFrame, reply: bytes) -> bytes:
    """GetVIN_CAN_DT's first multi-receive result, not a generic VIN service."""
    frame.check_reply(reply)
    if len(reply) < 3:
        raise ToyotaCodecError("VIN reply lacks its 3-byte prefix", SHORT_REPLY)
    payload = reply[3:]
    # Native strips zeros only at original payload indices 0,1,2, not all zeros.
    return bytes(value for i, value in enumerate(payload) if value or i > 2)


def data_list_request(template: bytes, pid: int, protocol: int) -> bytes:
    """CCmdCommPidData's byte/word request patch after DB template selection.

    Caller supplies ECU record +0x27 for ordinary protocols, or the little-
    endian word at +0x22 for protocol values 0x14, 0x15, 0x34.
    """
    _uint(protocol, 8)
    extended = protocol in (0x14, 0x15, 0x34)
    _uint(pid, 16 if extended else 8)
    width = 2 if extended else 1
    if len(template) < width + 1:
        raise ToyotaCodecError("Truncated Data List template", INVALID_RECORD)
    CommandFrame(template)
    return template[:1] + pid.to_bytes(width, "big") + template[width + 1 :]


def pid_support_p3(freeze_record: bytes, available_bytes: int) -> bool | None:
    """Proven early support decision; None requires the native PidBit gate.

    This is not vehicle support resolution. available_bytes must be the selected
    PID's returned data length (CPidList::GetDataLength), not whole frame length.
    """
    _uint(available_bytes, 8)
    if len(freeze_record) != 84:
        raise ToyotaCodecError("Invalid Freeze record", INVALID_RECORD)
    mode = freeze_record[0x4D]
    if mode == 1:
        return True
    if mode == 2:
        return False
    if mode != 0:
        raise ToyotaCodecError("Unknown native support mode", 0xA0040004)
    bit_position = struct.unpack_from("<H", freeze_record, 0x40)[0]
    if available_bytes * 8 <= bit_position:
        return False
    bit_reference = struct.unpack_from("<H", freeze_record, 0x3A)[0]
    return True if bit_reference == 0 else None
