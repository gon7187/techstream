"""Source-bound TY business bodies; common lifecycle and scheduling live in utility_ex.

Reviewed diagnostic protocol constants are authored here; unreviewed exports fail closed.
The context supplies the shared native communication controller, never an OEM DLL.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from functools import lru_cache
from typing import Protocol

from scripts.toyota_session import Cancelled


class TYSourceError(ValueError):
    """No reviewed body for the exact supplied source."""


class TYComm(Protocol):
    def initialize(self, mode: int = 0) -> int: ...
    def finalize(self) -> None: ...
    def exchange(self, request: bytes) -> tuple[int, bytes]: ...
    def cleanup_exchange(self, request: bytes) -> tuple[int, bytes]: ...
    def configure(self, field: str, value: int) -> None: ...
    def support_snapshot(self, kind: int) -> tuple[int, bytes, tuple[int, ...]]: ...
    def read_field(self, field: str) -> int: ...
    def select_target(self, identifier: int, second: int = 0) -> None: ...
    def configure_target(
        self,
        first: int,
        second: int = 0,
        third: int = 0,
        fourth: int = 0,
        fifth: int = 0,
    ) -> None: ...
    def select_protocol(self, kind: int) -> int: ...
    def read_target(self) -> tuple[int, int]: ...
    def read_dtcs(
        self, mode: int = 0x80, capacity: int = 0x1000
    ) -> tuple[int, bytes]: ...
    def session(
        self,
        mode: int,
        keepalive: int = 1,
        *,
        normal_first: bool = False,
        stop_on_error: bool = False,
    ) -> int: ...
    def cleanup_session(
        self,
        mode: int,
        keepalive: int = 1,
        *,
        normal_first: bool = False,
        stop_on_error: bool = False,
    ) -> int: ...


class TYContext(Protocol):
    module_sha256: str
    module_bytes: bytes
    state: dict[str, object]

    @property
    def mode(self) -> int: ...

    def comm(self, kind: str, /) -> TYComm: ...
    def is_cancelled(self) -> bool: ...
    def sleep(self, ms: int, /) -> None: ...
    def native_sleep(self, milliseconds: int, /) -> None: ...
    def ticks(self) -> int: ...
    def set_parameter(self, key: int, value: int) -> int: ...
    def write_parameters(self) -> int: ...
    def refresh_parameters(self) -> None: ...


@dataclass(frozen=True)
class TYMessage:
    """FCHV16 native input DWORDs, preserving action and selection separately."""

    action: int
    selection: int = 0

    def __post_init__(self) -> None:
        for value in (self.action, self.selection):
            if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
                raise ValueError("TY message fields must be uint32")


@dataclass(frozen=True)
class TYContract:
    """A reviewed private contract, or an explicitly authored synthetic test vector."""

    source_sha256: str
    comm_kind: str
    exports: tuple[str, ...]
    numbers: Mapping[str, int]
    frames: Mapping[str, bytes]


# Reviewed against the exact 18 TY source; no filename or cross-version aliases.
# 18 RVAs: DOOR c3d80..c3ea4; FCHV16 c3eb0..c4350;
# FCHV04 8df0/8e30; session 12a80/12ba0/20260.
# Plus independently reviewed: DOOR c9fb0/c9f10, FCHV16 ca210/ca2f0/ca3d0,
# FCHV04 9eb0/9ef0, timer f950; distinct manager 101392d0.
@lru_cache(maxsize=4)
def load_contract(source_sha256: str) -> TYContract:
    if source_sha256 == SHA_12_TY:
        return TYContract(
            source_sha256,
            "selected",
            (
                "Ex2IG_01_DisableAutoPowerOffFunc",
                "Ex2MSW_01_SendMessage",
                "Ex2DMOT_01_SendMessage",
                "Ex2EV_02_SendMessage",
            ),
            {},
            {},
        )
    managers = {SHA_18_TY: "native:1011d4f0", SHA_PLUS_TY: "native:101392d0"}
    if source_sha256 not in managers:
        raise TYSourceError("TY variant has no reviewed native business contract")
    return TYContract(
        source_sha256,
        managers[source_sha256],
        EXPORTS_18_TY
        + (EXTRA_EXPORTS_18_TY if source_sha256 == SHA_18_TY else EXTRA_EXPORTS_PLUS_TY)
        + (
            "Ex2FCHV_05_SendMessage",
            "Ex2FCHV_06_SendMessage",
            "Ex2FCHV_07_SupportCheck",
            "Ex2FCHV_08_SupportCheck",
            "Ex2FCHV_09_SendMessage",
            "Ex2FCHV_07_Overwrite",
            "Ex2FCHV_02_ReadData",
            "Ex2HF_01_Com_TanksNumberValueClear",
            "Ex2ROOF_01_ImpactDetectionInfoClear",
            "Ex2IG_02_SendMessage",
            "Ex2IG_01_DisableAutoPowerOffFunc",
            "Ex2MIR_01_SendMessage",
            "Ex2SAS_02_SendMessage",
            "Ex2MS2MM_01_SendMessage",
            "Ex2MS2BSRL_01_SendMessage",
            "Ex2MSW_01_SendMessage",
            "Ex2DMOT_01_SendMessage",
            "Ex2EV_02_SendMessage",
        ),
        NUMBERS_18_TY,
        FRAMES_18_TY,
    )


SHA_12_TY = "e85b2456b26d3966ca243c03fa775cf81ad58bf05689bdb87b616eda4c8b6f5f"
SHA_18_TY = "79fc495c68eb099a7ebc0d1eefe0eafd80101ac0bc09a58d3f603ed556c84762"
SHA_PLUS_TY = "821bbfd9957679ceef4ac32c239b8840c984e98ac61050ce7348ac2bc88b04ce"
EXPORTS_18_TY = (
    "Ex2DOOR_01_StartConnectionHistoryClear",
    "Ex2FCHV_04_ChangeProtocol",
    "Ex2FCHV_04_CheckCanSendTime",
    "Ex2FCHV_16_SendMessage",
)
EXTRA_EXPORTS_18_TY = (
    "Ex2FCHV_10_SendMessage",
    "Ex2FCHV_13_SendMessage",
    "Ex2FCHV_14_SendMessage",
    "Ex2FCHV_02_EndExtendedSession",
    "Ex2GWY_02_TimeoutInit",
    "Ex2GWY_03_EndInitErr",
    "Ex2STRACT_03_EndExtendedSession",
    "Ex2SBW_01_EndExtendedSession",
)
EXTRA_EXPORTS_PLUS_TY = EXTRA_EXPORTS_18_TY[:3] + (
    "Ex2FCHV_02_EndExtendedSession",
    "Ex2FCHV_26_EndExtendedSession",
    "Ex2GWY_03_EndInitErr",
    "Ex2GWY_02_TimeoutInit",
    "Ex2SBW_01_EndExtendedSession",
    "Ex2STRACT_03_EndExtendedSession",
)
END_EXPORTS_TY = frozenset(EXTRA_EXPORTS_18_TY[3:] + EXTRA_EXPORTS_PLUS_TY[3:])
NUMBERS_18_TY = {
    "broker_protocol": 111,
    "broker_success": 1,
    "protocol_error": 2001,
    "retrywait": 0,
    "pendingms": 180000,
    "retries": 0,
    "door_before_ms": 200,
    "door_after_ms": 100,
    "door_error": 1000,
    "short_reply": 3,
    "session_normal": 1,
    "session_extended": 3,
    "routine_minimum": 4,
    "routine_echo": 3,
    "fchv_poll_ms": 200,
    "fchv_settle_ms": 3000,
    "fchv_timeout_ms": 5000,
    "ready_mask": 64,
    "fchv_enable_error": 2000,
    "fchv_drive_error": 2001,
    "fchv_read_error": 2002,
    "fchv_unknown_error": 2003,
    "fchv_timeout_other": 2003,
    "fchv_fallback": 2004,
    "fchv_special": 2032,
    "fchv_selection_1": 2020,
    "fchv_selection_2": 2030,
    "fchv_selection_3": 2031,
    "fchv_repeat": 2030,
}
FRAMES_18_TY = {
    "door_clear": b"1\x01\x11\n\x00",
    "fchv_enable": b"1\x01\x11\x1a\x01",
    "fchv_drive": b"1\x01\x11\x19\xc8",
    "fchv_stop_drive": b"1\x02\x11\x19",
    "fchv_start_read": b"1\x01\x11\x16",
    "fchv_stop_read": b"1\x02\x11\x16",
    "fchv_read": b'"\x1b\xbf',
    "session_normal": b"\x10\x01",
    "session_extended": b"\x10\x03",
}

# 18 c0900/c0a10/c0a90 pass complete variable-length 2F frames to c0b10;
# c0b10 C loses its echo-success branch, which is retained in the ASM.
FRAMES_18_TY.update(
    {
        "fchv13_enable_1": bytes.fromhex("2f281c0300010001"),
        "fchv13_enable_2": bytes.fromhex("2f280e030fa080"),
        "fchv13_enable_3": bytes.fromhex("2f2809033280"),
        "fchv13_continue_1": bytes.fromhex("2f281c0300000001"),
        "fchv13_continue_2": bytes.fromhex("2f280e0080"),
        "fchv13_stop_1": bytes.fromhex("2f281c000001"),
        "fchv13_stop_2": bytes.fromhex("2f280e0080"),
        "fchv13_stop_3": bytes.fromhex("2f28090080"),
        "fchv14_routine": bytes.fromhex("3101118801"),
        "fchv10_support": bytes.fromhex("221bbc"),
        "fchv10_routine": bytes.fromhex("31011185"),
        "ms2bsrl_start": bytes.fromhex("31010141"),
        "ms2bsrl_result": bytes.fromhex("31030141"),
        "ms2mm_routine": bytes.fromhex("31010050"),
        "mir_start": bytes.fromhex("31011101"),
        "mir_poll": bytes.fromhex("31031101"),
        "roof_clear": bytes.fromhex("3101b022"),
        "hf_clear": bytes.fromhex("2e20011f"),
        "fchv05_start": bytes.fromhex("3101111b"),
        "fchv05_result": bytes.fromhex("3103111b"),
        "fchv06_read": bytes.fromhex("222004"),
        "fchv06_write": bytes.fromhex("2e2004"),
    }
)


def elapsed_ticks(now: int, start: int) -> int:
    """Native TY timer deliberately subtracts one extra tick across DWORD wrap."""
    if not all(type(v) is int and 0 <= v <= 0xFFFFFFFF for v in (now, start)):
        raise ValueError("tick values must be uint32")
    return (now - start - (now < start)) & 0xFFFFFFFF


class TYEngine:
    def __init__(self, contract: TYContract) -> None:
        self.contract = contract
        self.n = contract.numbers
        self.f = contract.frames

    def _check(self, context: TYContext) -> None:
        if context.is_cancelled():
            raise Cancelled("TY business operation cancelled")

    def _exchange(
        self, comm: TYComm, context: TYContext, name: str, echo: int
    ) -> tuple[int, bytes]:
        self._check(context)
        request = self.f[name]
        status, reply = comm.exchange(request)
        if not status and (
            len(reply) < echo + 1 or reply[1 : echo + 1] != request[1 : echo + 1]
        ):
            status = self.n["short_reply"]
        return status, reply

    def _initialize(self, comm: TYComm, context: TYContext) -> int:
        self._check(context)
        status = comm.initialize()
        if not status:
            for field, key in (
                ("native_1080", "retrywait"),
                ("native_1084", "pendingms"),
                ("native_1064", "retries"),
            ):
                comm.configure(field, self.n[key])
        return status

    def _session(
        self,
        comm: TYComm,
        context: TYContext,
        name: str,
        *,
        normal_first: bool = False,
        stop_on_error: bool = False,
    ) -> int:
        self._check(context)
        return comm.session(
            self.f[name][1], 1, normal_first=normal_first, stop_on_error=stop_on_error
        )

    def _door(self, context: TYContext) -> int:
        comm = context.comm(self.contract.comm_kind)
        try:
            status = self._initialize(comm, context)
            if status:
                return status
            status = self._session(comm, context, "session_normal")
            if not status:
                status = self._session(comm, context, "session_extended")
            if status:
                return status
            context.sleep(self.n["door_before_ms"])
            status, _ = self._exchange(comm, context, "door_clear", 3)
            status = self.n["door_error"] if status else 0
            context.sleep(self.n["door_after_ms"])
            self._session(comm, context, "session_normal")
            return status
        finally:
            comm.finalize()

    def _drive(self, comm: TYComm, context: TYContext) -> int:
        status, _ = self._exchange(comm, context, "fchv_drive", 3)
        if status:
            self._exchange(comm, context, "fchv_stop_drive", 3)
            return self.n["fchv_drive_error"]
        context.sleep(self.n["fchv_settle_ms"])
        return 0

    def _poll(self, comm: TYComm, context: TYContext, selection: int) -> int:
        started: int | None = None
        while True:
            context.sleep(self.n["fchv_poll_ms"])
            status, reply = self._exchange(comm, context, "fchv_read", 2)
            if status or len(reply) < 5:
                return self.n[
                    "fchv_read_error"
                    if selection in (1, 2, 4)
                    else "fchv_unknown_error"
                ]
            if started is None:
                started = context.ticks()
            if reply[4] & self.n["ready_mask"]:
                context.sleep(self.n["fchv_settle_ms"])
                if selection in (1, 2, 3):
                    return self.n[f"fchv_selection_{selection}"]
                if selection == 4:
                    return 0
                return self.n["fchv_special" if selection == 5 else "fchv_fallback"]
            if elapsed_ticks(context.ticks(), started) >= self.n["fchv_timeout_ms"]:
                return self.n[
                    "fchv_drive_error"
                    if selection in (1, 2, 4)
                    else "fchv_timeout_other"
                ]

    def _read(self, comm: TYComm, context: TYContext, selection: int) -> int:
        status, _ = self._exchange(comm, context, "fchv_start_read", 3)
        if not status:
            status = self._poll(comm, context, selection)
        else:
            status = self.n[
                "fchv_drive_error" if selection in (1, 2, 4) else "fchv_unknown_error"
            ]
        self._exchange(comm, context, "fchv_stop_read", 3)
        if selection == 4 and not status:
            return (
                self.n["fchv_repeat"]
                if not self._drive(comm, context)
                else self.n["fchv_drive_error"]
            )
        return status

    def _fchv16(self, message: TYMessage, context: TYContext) -> int:
        comm = context.comm(self.contract.comm_kind)
        cleanup = False
        try:
            if message.action == 0:
                cleanup = True
                status = self._initialize(comm, context)
                if status:
                    return status
                status = self._session(
                    comm, context, "session_extended", normal_first=True
                )
                if not status:
                    status, _ = self._exchange(comm, context, "fchv_enable", 3)
                    if status:
                        self._session(
                            comm, context, "session_normal", stop_on_error=True
                        )
                        status = self.n["fchv_enable_error"]
                cleanup = bool(status)
                return status
            if message.action == 1:
                return self._drive(comm, context)
            if message.action == 2:
                # Native wrapper discards the stop helper's return value.
                self._exchange(comm, context, "fchv_stop_drive", 3)
                return 0
            if message.action == 3:
                status = self._read(comm, context, message.selection)
                cleanup = status in (
                    self.n["fchv_unknown_error"],
                    self.n["fchv_fallback"],
                    self.n["fchv_special"],
                )
                if cleanup:
                    self._session(comm, context, "session_normal", stop_on_error=True)
                return status
            # The default helper restores normal session; wrapper retains zero.
            cleanup = True
            self._session(comm, context, "session_normal", stop_on_error=True)
            return 0
        except BaseException:
            cleanup = True
            raise
        finally:
            if cleanup:
                comm.finalize()

    def _fchv13_cleanup(self, comm: TYComm, context: TYContext) -> None:
        try:
            for name in ("fchv13_stop_1", "fchv13_stop_2", "fchv13_stop_3"):
                self._exchange(comm, context, name, 3)
            self._session(comm, context, "session_normal", stop_on_error=True)
        finally:
            comm.finalize()

    def _fchv13(self, action: int, context: TYContext) -> int:
        comm = context.comm(self.contract.comm_kind)
        cleanup_started = False
        try:
            if action == 0:
                status = self._initialize(comm, context)
                if not status:
                    status = self._session(
                        comm, context, "session_extended", normal_first=True
                    )
                if status:
                    cleanup_started = True
                    comm.finalize()
                    return status
                names = ("fchv13_enable_1", "fchv13_enable_2", "fchv13_enable_3")
            elif action == 1:
                names = ("fchv13_continue_1", "fchv13_continue_2")
            else:
                cleanup_started = True
                self._fchv13_cleanup(comm, context)
                return 0
            for name in names:
                status, _ = self._exchange(comm, context, name, 3)
                if status:
                    cleanup_started = True
                    self._fchv13_cleanup(comm, context)
                    return 1008 if action == 0 else status
            return 0
        except BaseException:
            if not cleanup_started:
                comm.finalize()
            raise

    def _fchv14(self, context: TYContext) -> int:
        comm = context.comm(self.contract.comm_kind)
        try:
            status = self._initialize(comm, context)
            if not status:
                status = self._session(
                    comm, context, "session_extended", normal_first=True
                )
                if not status:
                    status, _ = self._exchange(comm, context, "fchv14_routine", 3)
                    status = 1005 if status else 0
                    self._session(comm, context, "session_normal", stop_on_error=True)
            return status
        finally:
            comm.finalize()

    def _ms2bsrl(self, data: bytearray, context: TYContext) -> int:
        comm = context.comm(self.contract.comm_kind)
        plus = self.contract.source_sha256 == SHA_PLUS_TY
        try:
            status = self._initialize(comm, context)
            if status:
                return status
            data[:3] = bytes(3)
            for name, minimum in (("ms2bsrl_start", 4), ("ms2bsrl_result", 10)):
                status, reply = self._exchange(comm, context, name, 3)
                if status in (2, 7):
                    context.sleep(0)
                    if status == 7:
                        address = "10153554" if plus else "1012ae38"
                        context.state["native_global:" + address] = (
                            reply[2] if len(reply) > 2 else 0
                        )
                if not status and len(reply) < minimum:
                    status = 3
                if status:
                    if status == 2:
                        return 2004
                    if status == 7:
                        return 2005 if comm.read_field("native_10b0") == 0x69 else 2003
                    return 2003
                if name == "ms2bsrl_start":
                    context.sleep(3000)
            result = reply[4]
            if result == 0:
                data[:3] = reply[5:8]
                return 0
            if result == 9:
                return 2002
            if result in (12, 13):
                reverse = plus and int.from_bytes(data[4:8], "little") == 0x2DA
                return 2000 + ((result == 13) != reverse)
            return 99
        finally:
            comm.finalize()

    def _ms2mm(self, context: TYContext) -> int:
        comm = context.comm(self.contract.comm_kind)
        try:
            status = self._initialize(comm, context)
            if not status:
                status, reply = self._exchange(comm, context, "ms2mm_routine", 3)
                if not status and len(reply) != 4:
                    status = 3
            return status
        finally:
            comm.finalize()

    def _mir(self, data: bytearray, context: TYContext) -> int:
        comm = context.comm(self.contract.comm_kind)
        cleanup = True
        try:
            if int.from_bytes(data[:4], "little") == 0:
                status = self._initialize(comm, context)
                if not status:
                    status = self._session(
                        comm, context, "session_extended", normal_first=True
                    )
                    if not status:
                        status, _ = self._exchange(comm, context, "mir_start", 3)
                        if not status:
                            cleanup = False
                            return 0
                        self._session(
                            comm, context, "session_normal", stop_on_error=True
                        )
                return status
            status = 0
            if int.from_bytes(data[4:8], "little") != 1:
                while True:
                    context.sleep(10)
                    status, reply = self._exchange(comm, context, "mir_poll", 3)
                    if not status and len(reply) < 5:
                        status = 3
                    if status:
                        break
                    if reply[4] != 1:
                        status = 0 if reply[4] == 2 else 1007
                        break
                    if int.from_bytes(data[4:8], "little") == 1:
                        break
            self._session(comm, context, "session_normal", stop_on_error=True)
            return status
        finally:
            if cleanup:
                comm.finalize()

    def _selected_fixed(
        self,
        context: TYContext,
        request: bytes,
        reply_length: int,
        required: bytes = b"",
    ) -> int:
        comm = context.comm("selected")
        setter = {
            SHA_12_TY: "native_rva:b940",
            SHA_PLUS_TY: "native_rva:142f0",
        }.get(self.contract.source_sha256, "native_rva:12180")
        try:
            self._check(context)
            status = comm.initialize()
            if not status:
                comm.configure(setter, 150)
                self._check(context)
                status, reply = comm.exchange(request)
                if not status and (
                    len(reply) != reply_length or not reply.startswith(required)
                ):
                    status = 3
            return status
        finally:
            comm.finalize()

    def _ig02(self, context: TYContext) -> int:
        classic = self.contract.source_sha256 == SHA_PLUS_TY and context.mode == 22
        comm = context.comm("native:1013e7d0" if classic else self.contract.comm_kind)
        did = b"\x21\x03" if classic else b"\x20\x01"
        mask = 1 if classic else 0x40
        try:
            status = self._initialize(comm, context)
            if not status:
                status = self._session(
                    comm, context, "session_extended", normal_first=True
                )
                if not status:
                    self._check(context)
                    status, reply = comm.exchange(b"\x22" + did)
                    if not status and (len(reply) < 5 or reply[1:3] != did):
                        status = 3
                    if not status and not reply[4] & mask:
                        payload = bytearray(reply[3:])
                        payload[1] |= mask
                        self._check(context)
                        status, reply = comm.exchange(b"\x2e" + did + bytes(payload))
                        if not status and (len(reply) < 3 or reply[1:3] != did):
                            status = 3
                        if not status:
                            context.sleep(500)
                            self._check(context)
                            status, reply = comm.exchange(b"\x22" + did)
                            if not status and (len(reply) < 5 or reply[1:3] != did):
                                status = 3
                            if not status and not reply[4] & mask:
                                status = 1000
                    self._session(comm, context, "session_normal")
            return status
        finally:
            comm.finalize()

    def _roof_clear(self, context: TYContext) -> int:
        comm = context.comm(self.contract.comm_kind)
        try:
            status = self._initialize(comm, context)
            if not status:
                status = self._session(
                    comm, context, "session_extended", normal_first=True
                )
                if not status:
                    context.sleep(200)
                    status, _ = self._exchange(comm, context, "roof_clear", 3)
                    if status == 7:
                        status = comm.read_field("native_10b0")
                    context.sleep(200)
                    self._session(comm, context, "session_normal")
            return status
        finally:
            comm.finalize()

    def _fixed_session_request(
        self, context: TYContext, name: str, echo: int, settle: int
    ) -> int:
        comm = context.comm(self.contract.comm_kind)
        try:
            status = self._initialize(comm, context)
            if not status:
                status = self._session(
                    comm, context, "session_extended", normal_first=True
                )
                if not status:
                    status, _ = self._exchange(comm, context, name, echo)
                    if not status and settle:
                        context.sleep(settle)
                    self._session(comm, context, "session_normal", stop_on_error=True)
            return status
        finally:
            comm.finalize()

    def _fchv02_read_data(self, data: bytearray, context: TYContext) -> int:
        for offset in range(0, 280, 56):
            if int.from_bytes(data[offset + 44 : offset + 48], "little"):
                start = int.from_bytes(data[offset + 4 : offset + 8], "little")
                count = int.from_bytes(data[offset + 12 : offset + 16], "little")
                produced = 2 if data[offset + 1] in (0x9A, 0x9B) else 4
                if start + count > produced:
                    raise ValueError(
                        "FCHV02 record reads outside the native produced bytes"
                    )
        comm = context.comm(self.contract.comm_kind)
        try:
            started = context.ticks()
            index = 2
            while True:
                self._check(context)
                offset = index * 56
                if int.from_bytes(data[offset + 44 : offset + 48], "little"):
                    request = b"\x22" + bytes(data[offset : offset + 2])
                    status, reply = comm.exchange(request)
                    produced = 2 if request[2] in (0x9A, 0x9B) else 4
                    if not status and (
                        len(reply) < produced + 3 or reply[1:3] != request[1:3]
                    ):
                        status = 3
                    if status:
                        return status
                    start = int.from_bytes(data[offset + 4 : offset + 8], "little")
                    count = int.from_bytes(data[offset + 12 : offset + 16], "little")
                    data[offset + 48 : offset + 48 + count] = reply[
                        3 + start : 3 + start + count
                    ]
                if index == 1:
                    elapsed = elapsed_ticks(context.ticks(), started)
                    if elapsed < 200:
                        context.sleep(200 - elapsed)
                    started = context.ticks()
                if index == 4:
                    index = 0
                    if not int.from_bytes(data[296:300], "little"):
                        data[296:300] = (1).to_bytes(4, "little")
                else:
                    index += 1
                if int.from_bytes(data[284:288], "little"):
                    return 0
        except BaseException:
            comm.finalize()
            raise

    def _fchv_support(self, data: bytearray, context: TYContext) -> int:
        comm = context.comm(self.contract.comm_kind)
        try:
            status = self._initialize(comm, context)
            if not status:
                status = self._session(
                    comm, context, "session_extended", normal_first=True
                )
                if not status:
                    for request in (b"\x22\x01\x01", b"\x22\x20\x00"):
                        self._check(context)
                        status, reply = comm.exchange(request)
                        if not status and (
                            len(reply) != 35 or reply[1:3] != request[1:3]
                        ):
                            status = 3
                        if status:
                            break
                        if request[1:] == b"\x01\x01":
                            if not reply[7] & 0x80:
                                status = 3
                                break
                        else:
                            for offset, value, mask in (
                                (8, reply[3], 8),
                                (12, reply[4], 1),
                                (16, reply[5], 0x80),
                            ):
                                if value & mask:
                                    data[offset : offset + 4] = (1).to_bytes(
                                        4, "little"
                                    )
                    self._session(comm, context, "session_normal")
            return status
        finally:
            comm.finalize()

    def _fchv05(self, data: bytearray, context: TYContext) -> int:
        action = int.from_bytes(data[:4], "little")
        if action not in (0, 1):
            return 0
        comm = context.comm(self.contract.comm_kind)
        cleanup = True
        try:
            if action == 1:
                self._session(comm, context, "session_normal", stop_on_error=True)
                return 0
            status = self._initialize(comm, context)
            if not status:
                status = self._session(
                    comm, context, "session_extended", normal_first=True
                )
            if status:
                return 2000
            if int.from_bytes(data[4:8], "little") != 1:
                status, _ = self._exchange(comm, context, "fchv05_start", 3)
                if int.from_bytes(data[4:8], "little") != 1:
                    if not status:
                        context.sleep(200)
                        if int.from_bytes(data[4:8], "little") != 1:
                            status, reply = self._exchange(
                                comm, context, "fchv05_result", 3
                            )
                            if int.from_bytes(data[4:8], "little") != 1:
                                if not status and len(reply) >= 5 and reply[4] == 1:
                                    cleanup = False
                                    return 0
                                status = 2002
                            else:
                                status = 2001
                        else:
                            status = 2001
                    else:
                        status = 2002
                else:
                    status = 2001
            else:
                status = 2001
            self._session(comm, context, "session_normal", stop_on_error=True)
            return status
        finally:
            if cleanup:
                comm.finalize()

    def _fchv06(self, data: bytearray, context: TYContext) -> int:
        comm = context.comm(self.contract.comm_kind)
        try:
            status = self._initialize(comm, context)
            action = int.from_bytes(data[4:8], "little")
            if status or action not in (0, 1):
                return status
            status = self._session(comm, context, "session_extended", normal_first=True)
            if status:
                return status
            self._check(context)
            if action == 0:
                request = self.f["fchv06_write"] + bytes(data[:2])
                status, reply = comm.exchange(request)
                if not status and (len(reply) < 3 or reply[1:3] != request[1:3]):
                    status = 3
                status = 2000 if status else 0
            else:
                status, reply = self._exchange(comm, context, "fchv06_read", 2)
                if not status:
                    if len(reply) < 5:
                        status = 3
                    else:
                        data[:2] = reply[3:5]
            restored = self._session(
                comm, context, "session_normal", stop_on_error=True
            )
            return restored if action == 1 and not status else status
        finally:
            comm.finalize()

    def _fchv09(self, data: bytearray, context: TYContext) -> int:
        comm = context.comm(self.contract.comm_kind)
        try:
            status = self._initialize(comm, context)
            if not status:
                status = self._session(
                    comm, context, "session_extended", normal_first=True
                )
                if not status:
                    self._check(context)
                    request = b"\x2e\x20\x05\x01" + bytes(data[:2])
                    status, reply = comm.exchange(request)
                    if not status and (len(reply) < 3 or reply[1:3] != request[1:3]):
                        status = 3
                    status = 2000 if status else 0
                    self._session(comm, context, "session_normal", stop_on_error=True)
            return status
        finally:
            comm.finalize()

    def _fchv10(self, data: bytearray, context: TYContext) -> int:
        # Native input has 21 records of 24 bytes followed by the action DWORD.
        indices = [
            int.from_bytes(data[i + 4 : i + 8], "little") for i in range(0, 504, 24)
        ]
        if int.from_bytes(data[504:508], "little") == 0 and any(
            index >= 0x1020 for index in indices
        ):
            raise ValueError("FCHV10 support index exceeds native response buffer")
        comm = context.comm(self.contract.comm_kind)
        try:
            status = self._initialize(comm, context)
            if status:
                return status
            status = self._session(comm, context, "session_extended", normal_first=True)
            if status:
                return status
            if int.from_bytes(data[504:508], "little") == 0:
                plus = self.contract.source_sha256 == SHA_PLUS_TY
                ready = True
                status = 0
                if plus:
                    for request, index in ((b"\x22\x01\x01", 3), (b"\x22\x1b\x00", 23)):
                        self._check(context)
                        status, reply = comm.exchange(request)
                        if not status and (
                            len(reply) < 35 or reply[1:3] != request[1:3]
                        ):
                            status = 3
                        if status or not reply[3 + index] & 0x10:
                            ready = False
                            break
                if ready:
                    status, reply = self._exchange(comm, context, "fchv10_support", 2)
                    if not status and len(reply) < 9:
                        status = 3
                if ready and not status:
                    supported = reply[3:9] + bytes(0x1020 - 6)
                    for offset, index in zip(range(0, 504, 24), indices, strict=True):
                        mask = data[offset + 8]
                        matches = supported[index] & mask == mask
                        if matches and not plus:
                            data[offset + 12 : offset + 16] = (1).to_bytes(4, "little")
                        elif not matches and plus:
                            data[offset + 12 : offset + 16] = bytes(4)
                    return self._session(
                        comm, context, "session_normal", stop_on_error=True
                    )
                restored = self._session(
                    comm, context, "session_normal", stop_on_error=True
                )
                return status or restored if plus else status
            else:
                status = 0
                for offset in range(0, 504, 24):
                    self._check(context)
                    if int.from_bytes(data[offset + 16 : offset + 20], "little") != 1:
                        continue
                    request = self.f["fchv10_routine"] + bytes((data[offset],))
                    status, reply = comm.exchange(request)
                    if not status and (reply + bytes(4))[1:4] != request[1:4]:
                        status = 3
                    if status:
                        break
            self._session(comm, context, "session_normal", stop_on_error=True)
            return status
        finally:
            comm.finalize()

    def run_body(
        self, export: str, args: tuple[object, ...], context: TYContext
    ) -> int:
        if hashlib.sha256(context.module_bytes).hexdigest() != context.module_sha256:
            raise TYSourceError(
                "TY module bytes do not match the selected source identity"
            )
        if context.module_sha256 != self.contract.source_sha256:
            raise TYSourceError("TY context source identity mismatch")
        if export not in self.contract.exports:
            raise TYSourceError("TY export has no reviewed native body")
        if export in END_EXPORTS_TY:
            if len(args) > 1:
                raise ValueError("TY end operation takes at most one unused pointer")
            classic = (
                self.contract.source_sha256 == SHA_PLUS_TY
                and export == "Ex2GWY_02_TimeoutInit"
                and context.mode == 22
            )
            comm = context.comm(
                "native:1013e7d0" if classic else self.contract.comm_kind
            )
            try:
                self._session(comm, context, "session_normal")
                return 1003
            finally:
                comm.finalize()
        self._check(context)
        if export in (
            "Ex2MSW_01_SendMessage",
            "Ex2DMOT_01_SendMessage",
            "Ex2EV_02_SendMessage",
        ):
            if args:
                raise ValueError(f"{export} takes no arguments")
            if export == "Ex2EV_02_SendMessage":
                return self._selected_fixed(context, b"\x3b\x22\x01", 2, b"\x7b\x22")
            return self._selected_fixed(context, b"\xa6\x00", 1)
        if export == "Ex2MS2BSRL_01_SendMessage":
            minimum = 8 if self.contract.source_sha256 == SHA_PLUS_TY else 3
            if (
                len(args) != 1
                or not isinstance(args[0], bytearray)
                or len(args[0]) < minimum
            ):
                raise ValueError(
                    f"MS2BSRL01 requires a native bytearray of at least {minimum} bytes"
                )
            return self._ms2bsrl(args[0], context)
        if export == "Ex2MS2MM_01_SendMessage":
            if len(args) > 1:
                raise ValueError("MS2MM01 takes at most one unused pointer")
            return self._ms2mm(context)
        if export == "Ex2SAS_02_SendMessage":
            if len(args) > 1:
                raise ValueError("SAS02 takes at most one unused pointer")
            return self._fixed_session_request(context, "mir_start", 3, 0)
        if export == "Ex2MIR_01_SendMessage":
            if len(args) != 1 or not isinstance(args[0], bytearray) or len(args[0]) < 4:
                raise ValueError(
                    "MIR01 requires a native bytearray of at least 4 bytes"
                )
            if int.from_bytes(args[0][:4], "little") and len(args[0]) < 8:
                raise ValueError("MIR01 polling requires the native cancel DWORD")
            return self._mir(args[0], context)
        if export == "Ex2IG_01_DisableAutoPowerOffFunc":
            if args:
                raise ValueError("IG01 takes no arguments")
            return self._selected_fixed(context, b"\x10\x70", 1)
        if export == "Ex2IG_02_SendMessage":
            if args:
                raise ValueError("IG02 takes no arguments")
            return self._ig02(context)
        if export == "Ex2ROOF_01_ImpactDetectionInfoClear":
            if args:
                raise ValueError("ROOF clear takes no arguments")
            return self._roof_clear(context)
        if export == "Ex2HF_01_Com_TanksNumberValueClear":
            if len(args) > 1:
                raise ValueError("HF clear takes at most one unused pointer")
            return self._fixed_session_request(context, "hf_clear", 2, 50)
        if export == "Ex2FCHV_02_ReadData":
            if (
                len(args) != 1
                or not isinstance(args[0], bytearray)
                or len(args[0]) < 300
            ):
                raise ValueError(
                    "FCHV02 read requires a native bytearray of at least 300 bytes"
                )
            return self._fchv02_read_data(args[0], context)
        if export == "Ex2FCHV_07_Overwrite":
            if len(args) > 1:
                raise ValueError("FCHV07 overwrite takes at most one unused pointer")
            return 1000
        if export == "Ex2FCHV_09_SendMessage":
            if len(args) != 1 or not isinstance(args[0], bytearray) or len(args[0]) < 2:
                raise ValueError(
                    "FCHV09 requires a native bytearray of at least 2 bytes"
                )
            return self._fchv09(args[0], context)
        if export in ("Ex2FCHV_07_SupportCheck", "Ex2FCHV_08_SupportCheck"):
            if (
                len(args) != 1
                or not isinstance(args[0], bytearray)
                or len(args[0]) < 20
            ):
                raise ValueError(
                    f"{export} requires a native bytearray of at least 20 bytes"
                )
            return self._fchv_support(args[0], context)
        if export in ("Ex2FCHV_05_SendMessage", "Ex2FCHV_06_SendMessage"):
            if len(args) != 1 or not isinstance(args[0], bytearray) or len(args[0]) < 8:
                raise ValueError(
                    f"{export} requires a native bytearray of at least 8 bytes"
                )
            if export == "Ex2FCHV_05_SendMessage":
                return self._fchv05(args[0], context)
            return self._fchv06(args[0], context)
        if export == "Ex2FCHV_14_SendMessage":
            if len(args) > 1:
                raise ValueError("FCHV14 takes at most one unused pointer")
            return self._fchv14(context)
        if export in EXTRA_EXPORTS_18_TY[:2]:
            minimum = 508 if export == "Ex2FCHV_10_SendMessage" else 4
            if (
                len(args) != 1
                or not isinstance(args[0], bytearray)
                or len(args[0]) < minimum
            ):
                raise ValueError(
                    f"{export} requires a native bytearray of at least {minimum} bytes"
                )
            if export == "Ex2FCHV_10_SendMessage":
                return self._fchv10(args[0], context)
            return self._fchv13(int.from_bytes(args[0][:4], "little"), context)
        if export == "Ex2DOOR_01_StartConnectionHistoryClear":
            if args:
                raise ValueError("DOOR clear takes no arguments")
            return self._door(context)
        if export == "Ex2FCHV_16_SendMessage":
            if len(args) != 1:
                raise ValueError("FCHV16 requires one native input")
            value = args[0]
            if isinstance(value, bytearray) and len(value) >= 8:
                message = TYMessage(
                    int.from_bytes(value[:4], "little"),
                    int.from_bytes(value[4:8], "little"),
                )
            elif isinstance(value, TYMessage):
                message = value
            else:
                raise ValueError(
                    "FCHV16 requires a native bytearray of at least 8 bytes"
                )
            return self._fchv16(message, context)
        if export == "Ex2FCHV_04_CheckCanSendTime":
            if len(args) != 2 or any(type(v) is not int for v in args):
                raise ValueError("send time requires start and interval uint32")
            start, interval = args
            assert isinstance(start, int) and isinstance(interval, int)
            if not 0 <= interval <= 0xFFFFFFFF:
                raise ValueError("send interval must be uint32")
            return int(interval <= elapsed_ticks(context.ticks(), start))
        if len(args) != 1 or type(args[0]) is not int:
            raise ValueError("protocol change requires one uint32")
        value = args[0]
        assert isinstance(value, int)
        if not 0 <= value <= 0xFFFFFFFF:
            raise ValueError("protocol must be uint32")
        if (
            context.set_parameter(self.n["broker_protocol"], value)
            == self.n["broker_success"]
            and context.write_parameters() == self.n["broker_success"]
        ):
            context.refresh_parameters()
            return 0
        return self.n["protocol_error"]


def supported_exports(module_sha256: str) -> tuple[str, ...]:
    """Exact union of independently reviewed TY domain bodies, never name aliases."""
    from scripts import (
        utility_ex_fchv,
        utility_ex_fchv_01,
        utility_ex_fchv_actions,
        utility_ex_fchv_plus,
        utility_ex_ms2,
        utility_ex_ty_body,
        utility_ex_ty_chassis,
        utility_ex_ty_powertrain,
        utility_ex_ty_retained_01,
        utility_ex_ty_retained_02,
        utility_ex_ty_retained_03,
        utility_ex_ty_retained_04,
        utility_ex_ty_retained_05,
        utility_ex_ty_retained_06,
        utility_ex_ty_retained_07,
        utility_ex_ty_retained_08,
        utility_ex_ty_retained_09,
        utility_ex_ty_retained_10,
        utility_ex_ty_retained_11,
        utility_ex_ty_retained_12,
    )

    try:
        own = load_contract(module_sha256).exports
    except TYSourceError:
        own = ()
    chassis = tuple(
        name
        for name in utility_ex_ty_chassis.SUPPORTED_EXPORTS
        if utility_ex_ty_chassis.supports(module_sha256, name)
    )
    return tuple(
        sorted(
            set(
                own
                + utility_ex_fchv.supported_exports(module_sha256)
                + utility_ex_fchv_01.supported_exports(module_sha256)
                + utility_ex_fchv_actions.supported_exports(module_sha256)
                + utility_ex_fchv_plus.supported_exports(module_sha256)
                + utility_ex_ms2.supported_exports(module_sha256)
                + chassis
                + utility_ex_ty_body.supported_exports(module_sha256)
                + utility_ex_ty_powertrain.supported_exports(module_sha256)
                + utility_ex_ty_retained_01.supported_exports(module_sha256)
                + utility_ex_ty_retained_02.supported_exports(module_sha256)
                + utility_ex_ty_retained_03.supported_exports(module_sha256)
                + utility_ex_ty_retained_04.supported_exports(module_sha256)
                + utility_ex_ty_retained_05.supported_exports(module_sha256)
                + utility_ex_ty_retained_06.supported_exports(module_sha256)
                + utility_ex_ty_retained_07.supported_exports(module_sha256)
                + utility_ex_ty_retained_08.supported_exports(module_sha256)
                + utility_ex_ty_retained_09.supported_exports(module_sha256)
                + utility_ex_ty_retained_10.supported_exports(module_sha256)
                + utility_ex_ty_retained_11.supported_exports(module_sha256)
                + utility_ex_ty_retained_12.supported_exports(module_sha256)
            )
        )
    )


def run_body(export: str, args: tuple[object, ...], context: TYContext) -> int:
    """Entry point for the common exact-variant dispatcher and scheduler."""
    if hashlib.sha256(context.module_bytes).hexdigest() != context.module_sha256:
        raise TYSourceError("TY module bytes do not match the selected source identity")
    from scripts import (
        utility_ex_fchv,
        utility_ex_fchv_01,
        utility_ex_fchv_actions,
        utility_ex_fchv_plus,
        utility_ex_ms2,
        utility_ex_ty_body,
        utility_ex_ty_chassis,
        utility_ex_ty_powertrain,
        utility_ex_ty_retained_01,
        utility_ex_ty_retained_02,
        utility_ex_ty_retained_03,
        utility_ex_ty_retained_04,
        utility_ex_ty_retained_05,
        utility_ex_ty_retained_06,
        utility_ex_ty_retained_07,
        utility_ex_ty_retained_08,
        utility_ex_ty_retained_09,
        utility_ex_ty_retained_10,
        utility_ex_ty_retained_11,
        utility_ex_ty_retained_12,
    )

    if export in utility_ex_ty_retained_01.supported_exports(context.module_sha256):
        return utility_ex_ty_retained_01.run_body(export, args, context)
    if export in utility_ex_ty_retained_02.supported_exports(context.module_sha256):
        return utility_ex_ty_retained_02.run_body(export, args, context)
    if export in utility_ex_ty_retained_03.supported_exports(context.module_sha256):
        return utility_ex_ty_retained_03.run_body(export, args, context)
    if export in utility_ex_ty_retained_04.supported_exports(context.module_sha256):
        return utility_ex_ty_retained_04.run_body(export, args, context)
    if export in utility_ex_ty_retained_05.supported_exports(context.module_sha256):
        return utility_ex_ty_retained_05.run_body(export, args, context)
    if export in utility_ex_ty_retained_06.supported_exports(context.module_sha256):
        return utility_ex_ty_retained_06.run_body(export, args, context)
    if export in utility_ex_ty_retained_07.supported_exports(context.module_sha256):
        return utility_ex_ty_retained_07.run_body(export, args, context)
    if export in utility_ex_ty_retained_08.supported_exports(context.module_sha256):
        return utility_ex_ty_retained_08.run_body(export, args, context)
    if export in utility_ex_ty_retained_09.supported_exports(context.module_sha256):
        return utility_ex_ty_retained_09.run_body(export, args, context)
    if export in utility_ex_ty_retained_10.supported_exports(context.module_sha256):
        return utility_ex_ty_retained_10.run_body(export, args, context)
    if export in utility_ex_ty_retained_11.supported_exports(context.module_sha256):
        return utility_ex_ty_retained_11.run_body(export, args, context)
    if export in utility_ex_ty_retained_12.supported_exports(context.module_sha256):
        return utility_ex_ty_retained_12.run_body(export, args, context)
    if export in utility_ex_fchv_plus.supported_exports(context.module_sha256):
        return utility_ex_fchv_plus.run_body(export, args, context)
    if export in utility_ex_ms2.supported_exports(context.module_sha256):
        return utility_ex_ms2.run_body(export, args, context)
    if export in utility_ex_fchv_actions.supported_exports(context.module_sha256):
        return utility_ex_fchv_actions.run_body(export, args, context)
    if export in utility_ex_fchv_01.supported_exports(context.module_sha256):
        return utility_ex_fchv_01.run_body(export, args, context)
    if export in utility_ex_fchv.supported_exports(context.module_sha256):
        return utility_ex_fchv.run_body(export, args, context)
    if utility_ex_ty_chassis.supports(context.module_sha256, export):
        return utility_ex_ty_chassis.run_body(export, args, context)
    if export in utility_ex_ty_body.supported_exports(context.module_sha256):
        return utility_ex_ty_body.run_body(export, args, context)
    if export in utility_ex_ty_powertrain.supported_exports(context.module_sha256):
        return utility_ex_ty_powertrain.run_body(export, args, context)
    return TYEngine(load_contract(context.module_sha256)).run_body(
        export, args, context
    )
