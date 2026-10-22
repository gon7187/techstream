"""Source-bound UtilityEx NK chassis and smart-key business bodies.

No OEM code executes. The injected comm object performs only selected driver
primitives; request construction, response predicates and polling live here.
Unsupported source identities and unrecovered operations fail before I/O.
"""

from __future__ import annotations

import hashlib
from typing import Protocol


class UtilityExComm(Protocol):
    def read_target(self) -> tuple[int, int]: ...
    def select_target(self, identifier: int, second: int = 0) -> None: ...
    def configure_target(
        self,
        first: int,
        second: int = 0,
        third: int = 0,
        fourth: int = 0,
        fifth: int = 0,
    ) -> None: ...
    def configure_parameters(self, parameters: tuple[tuple[int, int], ...]) -> None: ...
    def select_protocol(self, kind: int) -> int: ...
    def select_diagnostic_mode(self, mode: int) -> int: ...
    def keepalive(self, enabled: bool, wait: bool = False) -> int: ...
    def initialize(self, mode: int = 0) -> int: ...
    def cancellation_counters(self) -> dict[str, int]: ...
    def finalize(self) -> None: ...
    def exchange(self, request: bytes) -> tuple[int, bytes]: ...
    def support_snapshot(self, kind: int) -> tuple[int, bytes, tuple[int, ...]]: ...
    def append_support_profile(self, raw: bytes, kind: int) -> int: ...
    def refresh_support_cache(self, kind: int) -> int: ...
    def cached_support(self, kind: int) -> tuple[bytes, tuple[int, ...]] | None: ...
    def configure(self, field: str, value: int) -> None: ...
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


class UtilityExContext(Protocol):
    @property
    def mode(self) -> int: ...

    module_sha256: str
    module_bytes: bytes
    state: dict[str, object]

    def native_parameter(self, key: int) -> int: ...
    def set_parameter(self, key: int, value: int) -> int: ...
    def write_parameters(self) -> int: ...
    def refresh_parameters(self) -> None: ...
    def broker(self, key: int) -> int: ...
    def is_cancelled(self) -> bool: ...
    def sleep(self, ms: int, /) -> None: ...
    def ticks(self) -> int: ...
    def comm(self, kind: str, /) -> UtilityExComm: ...


NK18_SHA256 = "8d9623f028f23876f69cb02baa10e1881c01fa01a4f906013bd36266f7e0fb33"
NK12_SHA256 = "980435d6bb2d9c57aab29e8f281d2641e3822b3172728f223c975ec6493d3c1e"
NK_DS4_SHA256 = "797833dc0c798984fcb739c21ac6fbd5230871fb67495d3339698df2ee53753f"
NK_GTS_SHA256 = "36dcdad2e72e29aae813db5576daf0168dd032b08a9cdda3841078dfb0b7b9fd"
_FIELDS12 = {
    "native_rva:170a0": "native_rva:f830",
    "native_rva:170b0": "native_rva:f840",
    "native_rva:172d0": "native_rva:fa60",
    "native_rva:172f0": "native_rva:fa80",
    "native_rva:17320": "native_rva:fa90",
    "native_global:1517f0": "native_global:ea978",
    "native_global:1517f4": "native_global:ea97c",
    "native_rva:17ba0": "native_rva:10310",
}
_FIELDS_DS4 = {
    "native_rva:170a0": "native_rva:323d0",
    "native_rva:170b0": "native_rva:323e0",
    "native_rva:172d0": "native_rva:32410",
    "native_rva:172f0": "native_rva:32480",
    "native_rva:17320": "native_rva:32450",
    "native_global:1517f0": "native_global:1b8ad8",
    "native_global:1517f4": "native_global:1b8adc",
    "native_rva:17ba0": "native_rva:32470",
    "native_rva:18840": "native_rva:32b90",
}
_FIELDS_GTS = {
    "native_rva:170a0": "native_rva:332e0",
    "native_rva:170b0": "native_rva:332f0",
    "native_rva:172d0": "native_rva:33320",
    "native_rva:172f0": "native_rva:33390",
    "native_rva:17320": "native_rva:33360",
    "native_global:1517f0": "native_global:1c8008",
    "native_global:1517f4": "native_global:1c800c",
    "native_rva:17ba0": "native_rva:33380",
    "native_rva:18840": "native_rva:33aa0",
}


def _configure(
    context: UtilityExContext, comm: UtilityExComm, field: str, value: int
) -> None:
    if context.module_sha256 == NK12_SHA256:
        field = _FIELDS12.get(field, field)
    elif context.module_sha256 == NK_DS4_SHA256:
        field = _FIELDS_DS4.get(field, field)
    elif context.module_sha256 == NK_GTS_SHA256:
        field = _FIELDS_GTS.get(field, field)
    comm.configure(field, value)


# 18 NK wrappers 13b0..1640 -> workers 281d0/282b0/28390/28a50;
# helpers 27e10 and 28040, verified against ASM, including omitted stack args.
_ABS_START = {
    "Ex2ABS_BeginAirBleed_TRC": (0x244, 2000),
    "Ex2ABS_BeginAirBleed_Resurrection": (0x246, 1000),
    "Ex2ABS_BeginSolenoidDrive_TRC": (0x248, 2000),
    "Ex2ABS_BeginSolenoidDrive_ABS": (0x24A, 2000),
}
_ABS35 = {
    "Ex2ABS_35_" + operation
    for operation in ("ConfDIDBitInfo", "ConfPlumbigStatus", "SolenoidDriving")
}
_SMRT47 = {
    "Ex2SMRT_47_" + operation
    for operation in (
        "GetSupportInfo",
        "SetSupportInfo",
        "KeyCodeChk",
        "GetKeyStatus_NomalChk",
        "GetKeyStatus_RegistrationChk",
        "StopKeyCodeReset",
    )
}
_SMRT46 = {
    "Ex2SMRT_46_" + operation
    for operation in (
        "GetSupportInfo",
        "SetSupportInfo",
        "KeyCodeChk",
        "GetKeyStatus",
        "GetKeyStatus_RegistrationChk",
        "StopKeyCodeReset",
    )
}
_SMRT45 = {
    "Ex2SMRT_45_" + operation
    for operation in (
        "GetSupportInfo",
        "SetSupportInfo",
        "StartOwnersKeyReg",
        "GetKeyStatus_StatusNormal",
        "GetKeyStatus_WaitComp",
        "GetKeyStatus_RegNormal",
        "StopOwnersKeyReg",
    )
}
_SMRT42 = {
    "Ex2SMRT_42_" + operation
    for operation in (
        "GetSupportInfo",
        "GetKeyNum",
        "KeyCodeErasureChk",
        "GetKeyStatus",
        "KeyCodeErasure",
        "TerminateKeyCodeErasure",
        "SetSupportInfo",
    )
}
_SMRT41 = {
    "Ex2SMRT_41_" + operation
    for operation in (
        "Online_Certification",
        "Online_Certification_008",
        "KeepAlive",
        "SendTheKey",
    )
}
_ABS01_FLOW = {"Ex2ABS_01_Conf_typeof_AirBleeding", "Ex2ABS_01_Bleed_The_Air"}
_ABS25 = {
    "Ex2ABS_25_" + operation
    for operation in (
        "GetSupportInfo",
        "ForcedActuatorRefresh",
        "ConfirmActivatingFlg",
        "StopActiveTest",
    )
}
_ABS22 = {
    "Ex2ABS_22_" + operation
    for operation in ("GetDIDSupport", "AirBleeding", "StopActiveTest")
}
_ABS15 = {
    "Ex2ABS_15_" + operation
    for operation in (
        "GetSupportInfo",
        "StartAirBleeding",
        "ChkPatternFlg",
        "ExecuteAirBleeding",
        "EndActiveTest",
        "ShiftTestMode",
        "ShiftNormalMode",
    )
}
_ABS05 = {"Ex2ABS_05_GetDIDSupportInfo"}
_ABS03 = {"Ex2ABS_03_ADSV2PDecompAirBleed", "Ex2ABS_03_ActuatorCheck"}
_ABS_STOP = {
    "Ex2ABS_EndAirBleed_TRC": 0x245,
    "Ex2ABS_EndSolenoidDrive_TRC": 0x249,
    "Ex2ABS_EndSolenoidDrive_ABS": 0x24B,
}
_SMART = {
    f"Ex2SMRT_{family}_{operation}"
    for family in ("03", "08")
    for operation in (
        "GetEntryKey",
        "ModeEntry",
        "ModeEnd",
        "MasterKeyCheck",
        "CompleteCheck",
    )
}
_ABS36 = {
    "Ex2ABS_36_" + operation
    for operation in (
        "SupportInfo",
        "Start_ECBProhibitCtrl",
        "Stop_ECBProhibitCtrl",
        "Start_ZeroDownDrive",
        "Change_DealerMode",
        "Change_NormalMode",
        "Motor_Deactivate",
        "StopRoutine",
    )
}
_ABS37 = {
    "Ex2ABS_37_" + operation
    for operation in (
        "ForcedActuatorRefresh",
        "ForcedActuatorRefreshStop",
        "ConfirmRoutineResult",
    )
}
_ABS38 = {
    "Ex2ABS_38_" + operation
    for operation in (
        "GetSupportInfo",
        "ECBProhibitionControl",
        "VacuumFillingFlg",
        "AccumulatorZeroDown",
        "StopTheRoutine",
    )
}
_ABS14 = {
    "Ex2ABS_14_" + operation
    for operation in (
        "GetDIDSupportInfo",
        "StartSolenoidDrive",
        "StopSolenoidDrive_VSC",
        "StartRelayDrive",
        "StopRelayDrive",
        "EndAirBleeding",
    )
}
_ABS50 = {
    "Ex2ABS_50_" + operation
    for operation in (
        "ConfSupportInfo",
        "RearAirBleeding",
        "RearAirBleeding_Next_1",
        "RearAirBleeding_Next_2",
        "RearAirBleeding_Timeout",
        "ECBProhibitionControl",
        "ECBProhibitionControl_Next",
        "SLM2Refresh",
        "VacuumFillingIncompleteFlagReset",
        "EndExtendedSession",
    )
}
_SMRT58 = frozenset(("Ex2SMRT_58_StartIFBOXComIDReg", "Ex2SMRT_58_EndExtendedSession"))
_SMRT56 = frozenset(
    "Ex2SMRT_56_" + operation
    for operation in (
        "ConfirmDIDRIDSupport",
        "StartFingerprintMode",
        "TerminateFingerprintMode",
        "EndExtendedSession",
    )
)
_SMRT55 = frozenset(
    "Ex2SMRT_55_" + name
    for name in (
        "ConfirmDIDRIDSupport",
        "GetKeyDiagInfo",
        "CHKSupportStatus",
        "SetKeyDiag",
        "SetKeyDiag2",
        "TermKeyDiag",
        "TermKeyDiag2",
    )
)
_SMRT55_CHK = "Ex2SMRT_55_CHKSupportStatus"
_SMRT55_SOURCE = {
    NK18_SHA256: (
        "native:1014f5e0",
        "native_global:1014a5b0",
        "native_global:1014a694",
        "native_global:1014a695",
    ),
    NK_DS4_SHA256: (
        "native:101b6758",
        "native_global:101b19ac",
        "native_global:101b19b0",
        "native_global:101b19b1",
    ),
    NK_GTS_SHA256: (
        "native:101c18a0",
        "native_global:101bcaac",
        "native_global:101bcab0",
        "native_global:101bcab1",
    ),
}
_SMRT53 = frozenset(
    "Ex2SMRT_53_" + name
    for name in ("Online_Certification", "Online_Certification_007", "SendTheKey")
)
_SMRT50 = frozenset(
    "Ex2SMRT_50_" + name
    for name in (
        "GetSupportInfo",
        "StartKeyErasure",
        "KeyCodeReset",
        "EndExtendSession",
        "StartKeepAlive",
    )
)
_SMRT63 = frozenset(
    "Ex2SMRT_63_" + name
    for name in (
        "GetSupportInfo",
        "StartKeyErasure",
        "GetKeyStatus",
        "EndExtendSession",
        "StartKeepAlive",
    )
)
_FIXED_UDS = (
    _SMRT63
    | _SMRT50
    | _SMRT53
    | _SMRT55
    | _SMRT56
    | _SMRT58
    | _ABS35
    | _ABS36
    | _ABS37
    | _ABS38
    | _ABS50
)
_ABS40 = frozenset(("Ex2ABS_40_GetSupportInfo", "Ex2ABS_40_VSCLine_AirBleeding"))
_SMRT48 = frozenset(
    "Ex2SMRT_48_" + name
    for name in ("GetSupportInfo", "ReadVINCode", "GetTheDigitalKeySerialNo")
)
SUPPORTED_EXPORTS = (
    frozenset(_ABS_START)
    | {"Ex2ABS_01_BeginSolenoidDrive"}
    | frozenset(_ABS_STOP)
    | _SMART
    | _FIXED_UDS
    | _ABS40
    | _ABS14
    | _ABS03
    | _ABS05
    | _ABS15
    | _ABS22
    | _ABS25
    | _ABS01_FLOW
    | _SMRT41
    | _SMRT42
    | _SMRT45
    | _SMRT46
    | _SMRT47
    | _SMRT48
    | {
        "Ex2SMRT_32_GetRegKeyNum",
        "Ex2SMRT_32_GetSupportInfo",
        "Ex2SMRT_32_StartEraseMode",
        "Ex2SMRT_32_EndEraseMode",
        "Ex2SMRT_32_GetTheKeyStatus_003",
        "Ex2SMRT_32_GetTheKeyStatus_005",
        "Ex2SMRT_31_GetSupportInfo",
        "Ex2SMRT_31_GetTheKeyStatus",
        "Ex2SMRT_31_RequestKeyCodeRegistration",
        "Ex2SMRT_31_TerminateKeyCodeRegistration",
        "Ex2SMRT_31_TerminateKeyCodeRegistrationNoChk",
        "Ex2SMRT_31_TerminateKeyCodeRegistrationNoChkOnce",
        "Ex2SMRT_EraseGetKey",
        "Ex2SMRT_EraseModeEntry",
        "Ex2SMRT_EraseModeEnd",
        "Ex2SMRT_EraseModeStatus",
        "Ex2SMRT_EraseKeyStatus",
        "Ex2SMRT_EraseCheck",
        "Ex2SMRT_SetProgressTimeOutFlg",
    }
)


def supported_exports(module_sha256: str) -> frozenset[str]:
    """Named implemented operations present in the exact source variant."""
    if module_sha256 == NK12_SHA256:
        return (
            SUPPORTED_EXPORTS
            - _FIXED_UDS
            - _ABS40
            - _SMRT45
            - _SMRT46
            - _SMRT47
            - _SMRT48
            - _SMRT55
        )
    if module_sha256 in (NK18_SHA256, NK_DS4_SHA256, NK_GTS_SHA256):
        return SUPPORTED_EXPORTS
    return frozenset()


class UnsupportedChassisOperation(ValueError):
    """No recovered business implementation for this exact source/export."""


def _uint(value: object) -> int:
    if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
        raise ValueError("UtilityEx argument must be a uint32")
    return value


def _out(value: object) -> bytearray:
    if not isinstance(value, bytearray) or len(value) != 4:
        raise ValueError("UtilityEx uint32 output requires a four-byte bytearray")
    return value


def _state(context: UtilityExContext, key: str) -> int:
    return _uint(context.state.get("nk.chassis." + key, 0))


def _save(context: UtilityExContext, key: str, value: int) -> None:
    context.state["nk.chassis." + key] = value & 0xFFFFFFFF


def _reply(comm: UtilityExComm, request: bytes) -> tuple[int, bytes]:
    status, reply = comm.exchange(request)
    if type(status) is not int or not isinstance(reply, bytes):
        raise TypeError("UtilityEx exchange requires (native status, bytes)")
    if len(reply) > 0x1020:
        return 3, b""
    # Native 18ef0 checks the positive service before body-specific predicates.
    if status == 0 and (not reply or reply[0] != (request[0] + 0x40) & 255):
        return 3, reply
    return status, reply


def _actuator_request(operation: int, selection: int) -> bytes:
    if operation in (0x244, 0x245, 0x248, 0x249):
        mask = {0x226: 1, 0x227: 2, 0x228: 12, 0x229: 12}.get(selection, 0)
        sub = 5 if operation in (0x244, 0x245) else 0x22
        value = mask if operation in (0x244, 0x248) else 0
        request = bytes((0x30, sub, mask, value))
        return request + (b"\0" if sub == 0x22 else b"")
    if operation == 0x246:
        return bytes((0x30, 10, 0x40, {0x226: 1, 0x227: 2}.get(selection, 0)))
    if operation in (0x24A, 0x24B):
        mask = {0x230: 2, 0x231: 8, 0x232: 0x20}.get(selection, 0)
        return bytes((0x30, 0x21, mask, mask if operation == 0x24A else 0))
    raise UnsupportedChassisOperation("Unknown actuator helper selector")


def _checked(comm: UtilityExComm, request: bytes, minimum: int) -> tuple[int, bytes]:
    status, reply = _reply(comm, request)
    if status == 0 and (len(reply) < minimum or reply[1] != request[1]):
        return 3, reply
    return status, reply


def _end32(context: UtilityExContext, comm: UtilityExComm) -> int:
    # 3e040 ignores the exchange status, but restores the native short-call mode.
    _configure(context, comm, "native_rva:17320", 1)
    _configure(context, comm, "native_rva:172f0", 1)
    for field in ("172d0", "17320", "172f0", "17ba0"):
        _configure(context, comm, "native_rva:" + field, 1)
    try:
        comm.exchange(b"\xa5\xb6" + bytes(6))
        return 0
    finally:
        for field, value in (
            ("172d0", 100),
            ("17320", 100),
            ("172f0", 3),
            ("17ba0", 0),
            ("17320", 100),
            ("172f0", 3),
        ):
            _configure(context, comm, "native_rva:" + field, value)
        comm.finalize()


def _smart_support(comm: UtilityExComm, registration: bool = False) -> int:
    unsupported = 3101 if registration else 99
    status, reply = _checked(comm, b"\x21\x20", 3)
    if status:
        return status
    if not reply[2] & 0x80:
        return unsupported
    status, reply = _checked(comm, b"\x21\xe0", 5)
    if status:
        return status
    if not reply[3] & 1 or not reply[4] & 8:
        return unsupported
    status, reply = _checked(comm, b"\x21\xf0", 8 if registration else 5)
    if status:
        return status
    masks = (
        ((2, 0xC0), (3, 0x64), (4, 0x8F), (6, 0xF0), (7, 0xF0))
        if registration
        else ((3, 0x44), (7, 0xF0))
    )
    padded = reply.ljust(8, b"\0")
    if any(padded[offset] & mask != mask for offset, mask in masks):
        return unsupported
    status, reply = _checked(comm, b"\x21\xf5", 3)
    if status:
        return status
    if reply[2] & 0xC0 != 0xC0:
        return unsupported
    status, reply = _checked(comm, b"\xa5\xb0", 3)
    return status if status else 0 if reply[2] & 4 else 3102 if registration else 99


def _key32(export: str, context: UtilityExContext, comm: UtilityExComm) -> int:
    if export.endswith("EndEraseMode"):
        return _end32(context, comm)
    if export.endswith("GetSupportInfo"):
        try:
            status = comm.initialize()
            return status if status else _smart_support(comm)
        finally:
            comm.finalize()
    if export.endswith("StartEraseMode"):
        try:
            status = comm.initialize()
            if status == 0:
                status, _ = _checked(comm, b"\xa5\xb6\x80" + bytes(5), 2)
                if status == 0:
                    status, _ = _checked(comm, b"\x21\x21", 6)
            return status
        except BaseException:
            comm.finalize()
            raise
    status = 0
    started = context.ticks() & 0xFFFFFFFF
    try:
        while not context.is_cancelled():
            status, reply = _checked(comm, b"\x21\x21", 6)
            if status:
                break
            if export.endswith("003"):
                if not reply[3] & 0x40:
                    return 3001
            else:
                observed = context.ticks() & 0xFFFFFFFF
                if reply.ljust(8, b"\0")[7] & 0xF0 == 0x10:
                    status = 3002
                    break
                if (observed - started) & 0xFFFFFFFF > 30000:
                    # NK12 329b0 masks the whole nibble; later builds test bit2.
                    mask = 15 if context.module_sha256 == NK12_SHA256 else 4
                    status = 3003 if reply[3] & mask == 4 else 3004
                    break
        if status != 3001 or not export.endswith("003"):
            _end32(context, comm)
        return status
    except BaseException:
        comm.finalize()
        raise


def _actuator(
    comm: UtilityExComm, operation: int, selection: int, context: UtilityExContext
) -> int:
    _configure(context, comm, "native_rva:172d0", 100)
    driving = operation in (0x244, 0x246, 0x248, 0x24A)
    if driving:
        _configure(context, comm, "native_rva:172f0", 1)
        _configure(context, comm, "native_rva:17320", 1)
    request = _actuator_request(operation, selection)
    try:
        status, reply = _reply(comm, request)
        if status:
            return status
        if len(reply) == 2 and reply[1] == request[1]:
            return 0
        # 27e10/28040 do NOT require echo in this three-byte status branch.
        if len(reply) == 3 and reply[2] == 0:
            return 12
        return 3
    finally:
        if driving:
            _configure(context, comm, "native_rva:172f0", 3)
            _configure(context, comm, "native_rva:17320", 100)


def _abs_start(
    export: str, selection: int, context: UtilityExContext, comm: UtilityExComm
) -> int:
    operation, delay = _ABS_START[export]
    already_succeeded = False
    try:
        status = comm.initialize()
        if status == 0:
            while not context.is_cancelled():
                status = _actuator(comm, operation, selection, context)
                if status and not (operation == 0x246 and already_succeeded):
                    break
                already_succeeded = True
                context.sleep(delay)
        # 282b0 always closes. The other workers retain the comm on cancellation.
        if operation == 0x246 or (status and not context.is_cancelled()):
            comm.finalize()
        return status
    except BaseException:
        comm.finalize()
        raise


def _abs01_start(selection: int, context: UtilityExContext, comm: UtilityExComm) -> int:
    # 285f0/286b0 retain the session even on native failure; init maps to4.
    if context.is_cancelled():
        return 99
    try:
        if comm.initialize():
            return 4
        status = 0
        mask = {0x226: 2, 0x227: 8}.get(selection, 12)
        sub = 0x21 if selection in (0x226, 0x227) else 0x22
        request = bytes((0x30, sub, mask, mask))
        while not context.is_cancelled():
            _configure(context, comm, "native_rva:17320", 1)
            _configure(context, comm, "native_rva:172f0", 1)
            try:
                status, reply = _reply(comm, request)
                if status == 0:
                    if len(reply) == 2 and reply[1] == sub:
                        pass
                    elif len(reply) == 3 and reply[1:] == bytes((sub, 0)):
                        status = 12
                    else:
                        status = 3
            finally:
                _configure(context, comm, "native_rva:17320", 100)
                _configure(context, comm, "native_rva:172f0", 3)
            if status:
                break
            if not context.is_cancelled():
                context.sleep(2000)
        return status
    except BaseException:
        comm.finalize()
        raise


def _routine36(comm: UtilityExComm, command: bytes) -> int:
    status, reply = _reply(comm, command)
    if status == 0 and (len(reply) < 4 or reply[1:4] != command[1:4]):
        return 3
    return status


def _normal36(
    context: UtilityExContext, comm: UtilityExComm, *, stop_on_error: bool = True
) -> int:
    _configure(context, comm, "native_rva:18840", 1)
    try:
        return comm.session(1, 1, stop_on_error=stop_on_error)
    finally:
        _configure(context, comm, "native_rva:18840", 0)


def _motor36(context: UtilityExContext, comm: UtilityExComm) -> int:
    status, reply = _reply(comm, b"\x22\x20\x02")
    if status:
        return status
    if len(reply) < 5 or reply[1:3] != b"\x20\x02":
        return 3
    command = bytearray(reply)
    command[0], command[4] = 0x2E, 0x80
    status, written = _reply(comm, bytes(command))
    if status:
        return status
    if len(written) < 3 or written[1:3] != command[1:3]:
        return 3
    context.sleep(1000)
    status, verified = _reply(comm, b"\x22\x20\x02")
    if status:
        return status
    if len(verified) < 5 or verified[1:3] != b"\x20\x02":
        return 3
    return 0xE13 if verified[4] & 0x40 else 0


def _abs36(export: str, context: UtilityExContext, comm: UtilityExComm) -> int:
    operation = export.removeprefix("Ex2ABS_36_")
    stop_ecb = b"\x31\x02\x11\x35"
    stop_zero = b"\x31\x02\x11\x32"
    normal_mode = b"\x31\x01\x11\x0c\0"
    try:
        if operation == "StopRoutine":
            context.sleep(20000)
            _routine36(comm, stop_zero)
            _normal36(context, comm)
            comm.finalize()
            return 0
        status = comm.initialize()
        if operation in ("Stop_ECBProhibitCtrl", "Change_NormalMode"):
            if status == 0:
                status = _routine36(
                    comm,
                    stop_ecb if operation == "Stop_ECBProhibitCtrl" else normal_mode,
                )
            _normal36(context, comm)
            comm.finalize()
            return status
        if status == 0:
            if comm.session(3, 1, normal_first=True):
                comm.finalize()
                return 0xE11
            if operation == "SupportInfo":
                status, reply = _reply(comm, b"\x22\x20\x02")
                if status == 0:
                    if len(reply) < 5 or reply[1:3] != b"\x20\x02":
                        status = 3
                    elif not reply[3] & 0x40:
                        status = 0xE10
                if status == 0:
                    status = 0xE11 if comm.session(1, 1, stop_on_error=True) else 0
                    comm.finalize()
                    return status
            elif operation == "Motor_Deactivate":
                status = _motor36(context, comm)
            else:
                command = {
                    "Start_ECBProhibitCtrl": b"\x31\x01\x11\x35",
                    "Start_ZeroDownDrive": b"\x31\x01\x11\x32",
                    "Change_DealerMode": b"\x31\x01\x11\x0c\x01",
                }[operation]
                status = _routine36(comm, command)
                if status == 0:
                    return 0
                if operation == "Change_DealerMode":
                    status = 0xE14
        if status != 0xE11:
            if operation == "Start_ECBProhibitCtrl":
                _routine36(comm, stop_ecb)
            elif operation == "Start_ZeroDownDrive":
                context.sleep(3000)
                _routine36(comm, stop_zero)
            elif operation == "Change_DealerMode":
                _routine36(comm, normal_mode)
            _normal36(context, comm)
        # ECB/Dealer source's initialize-status E11 branch retains its manager.
        if status != 0xE11 or operation not in (
            "Start_ECBProhibitCtrl",
            "Change_DealerMode",
        ):
            comm.finalize()
        return status
    except BaseException:
        comm.finalize()
        raise


def _refresh37(context: UtilityExContext, comm: UtilityExComm, sub: int) -> int:
    if context.is_cancelled():
        return 99
    command = bytes((0x31, sub, 0x11, 0x38))
    status, reply = _reply(comm, command)
    minimum = 5 if sub == 3 else 4
    if status == 0:
        if len(reply) < minimum or reply[1:4] != command[1:4]:
            return 3
        if sub == 3:
            return 1001 if reply[4] in (0, 1) else 0 if reply[4] == 2 else 1002
    return status


def _abs37(export: str, context: UtilityExContext, comm: UtilityExComm) -> int:
    operation = export.removeprefix("Ex2ABS_37_")
    try:
        status = 0
        if not context.is_cancelled():
            status = comm.initialize()
            if operation == "ForcedActuatorRefreshStop":
                status = _refresh37(context, comm, 2)
                _normal36(context, comm, stop_on_error=False)
            elif status == 0 and operation == "ForcedActuatorRefresh":
                if comm.session(3, 1, normal_first=True):
                    status = 1000
                else:
                    status = _refresh37(context, comm, 1)
                    if status:
                        _refresh37(context, comm, 2)
                        _normal36(context, comm, stop_on_error=False)
            elif status == 0:
                while not context.is_cancelled():
                    context.sleep(1000)
                    status = _refresh37(context, comm, 3)
                    if status != 1001:
                        break
                if not context.is_cancelled():
                    if status:
                        # cc700 sends stop without cancellation/response predicates.
                        comm.exchange(b"\x31\x02\x11\x38")
                    _normal36(context, comm, stop_on_error=False)
        comm.finalize()
        return status
    except BaseException:
        comm.finalize()
        raise


def _support38(kind: int, context: UtilityExContext, comm: UtilityExComm) -> int:
    for command, minimum, offset, mask, unsupported in (
        (b"\x22\x01\x01", 8, 7, 0x80, 1200),
        (b"\x22\x20\0", 4, 3, 0x40, 1201),
        (b"\x22\x20\x02", 5, 3, 0xE0 if kind == 1 else 0xC0, 1202),
        (b"\x31\x01\x10\x01", 7, 6, 0x40, 1203),
        (b"\x31\x01\x11\0", 11, 10, 0x48, 1204),
    ):
        if unsupported == 1202:
            context.state["nk.chassis.abs38_cache"] = b""
        status, reply = _reply(comm, command)
        if status:
            return status
        if len(reply) < minimum or reply[1 : len(command)] != command[1:]:
            return 3
        if reply[offset] & mask != mask:
            return unsupported
        if unsupported == 1202:
            context.state["nk.chassis.abs38_cache"] = reply[3:]
    return 0


def _error38(output: bytearray | None, status: int) -> int:
    if status == 0:
        return 0
    if output is not None:
        output[:] = (status & 0xFFFFFFFF).to_bytes(4, "little")
    return 1206


def _command38(
    comm: UtilityExComm, sub: int, routine: int, output: bytearray | None
) -> int:
    return _error38(output, _routine36(comm, bytes((0x31, sub, 0x11, routine))))


def _vacuum38(
    output: bytearray, kind: int, context: UtilityExContext, comm: UtilityExComm
) -> int:
    status = _command38(comm, 2, 0x35, output)
    if status:
        return status
    context.sleep(1000)
    cache = context.state.get("nk.chassis.abs38_cache", b"")
    if not isinstance(cache, bytes) or len(cache) > 0x101D:
        raise ValueError("ABS38 cached native data must be bounded bytes")
    length = len(cache) + 3
    command = bytearray(b"\x2e\x20\x02" + cache).ljust(5, b"\0")
    command[3], command[4] = 0xE0 if kind == 1 else 0xC0, 0x40
    status, reply = _reply(comm, bytes(command[:length]))
    if status == 0 and (len(reply) != 3 or reply[1:3] != b"\x20\x02"):
        status = 3
    if status:
        return _error38(output, status)
    context.sleep(1000)
    status, reply = _reply(comm, b"\x22\x20\x02")
    if status == 0 and (len(reply) < 5 or reply[1:3] != b"\x20\x02" or reply[4] & 0x80):
        status = 3
    return _error38(output, status)


def _abs38(
    export: str,
    arguments: tuple[object, ...],
    context: UtilityExContext,
    comm: UtilityExComm,
) -> int:
    operation = export.removeprefix("Ex2ABS_38_")
    try:
        status = 99
        if not context.is_cancelled():
            if operation in (
                "GetSupportInfo",
                "ECBProhibitionControl",
                "AccumulatorZeroDown",
            ):
                status = comm.initialize()
                if status == 0:
                    if comm.session(3, 1, normal_first=True):
                        comm.finalize()
                        return 1205
                    if operation == "GetSupportInfo":
                        status = _support38(_uint(arguments[0]), context, comm)
                    else:
                        output = _out(arguments[0])
                        zero_down = operation == "AccumulatorZeroDown"
                        context.sleep(1000)
                        status = _command38(
                            comm, 1, 0x32 if zero_down else 0x35, output
                        )
                        if status == 0:
                            return 0
                        if zero_down:
                            context.sleep(3000)
                        _command38(comm, 2, 0x32 if zero_down else 0x35, None)
                if status == 1205:
                    comm.finalize()
                    return status
            elif operation == "VacuumFillingFlg":
                status = _vacuum38(
                    _out(arguments[0]), _uint(arguments[1]), context, comm
                )
            else:
                status = _command38(
                    comm, 2, 0x32, None if arguments[0] is None else _out(arguments[0])
                )
        session_status = comm.session(1, 1, stop_on_error=True)
        if status == 0 and session_status:
            status = 1205
        comm.finalize()
        return status
    except BaseException:
        comm.finalize()
        raise


def _command03(
    context: UtilityExContext, comm: UtilityExComm, request: bytes
) -> tuple[int, bytes]:
    timed = len(request) > 1
    if timed:
        _configure(context, comm, "native_rva:172d0", 150)
    try:
        status, reply = _reply(comm, request)
        if status == 0:
            if request == b"\x21\x08":
                if len(reply) < 3 or reply[1] != 8:
                    status = 3
            elif len(reply) != (2 if timed else 1) or (
                timed and reply[1] != request[1]
            ):
                status = 3
        return status, reply
    finally:
        if timed:
            _configure(context, comm, "native_rva:172d0", 100)


def _sleep03(context: UtilityExContext, milliseconds: int) -> None:
    started = context.ticks()
    while not context.is_cancelled():
        elapsed = (context.ticks() - started) & 0xFFFFFFFF
        if elapsed >= milliseconds:
            return
        context.sleep(min(100, milliseconds - elapsed))


def _abs03(
    export: str,
    arguments: tuple[object, ...],
    context: UtilityExContext,
    comm: UtilityExComm,
) -> int:
    try:
        if export.endswith("ActuatorCheck"):
            if comm.initialize():
                return 4
            status, reply = _command03(context, comm, b"\x21\x08")
            if status == 0:
                _buffer(arguments[0], 1)[0] = reply[2]
            return status
        status = 99
        if not context.is_cancelled():
            started = context.ticks()
            if comm.initialize():
                return 4
            while True:
                status, _ = _command03(context, comm, b"\x30\x21\0\xaa\xaa")
                if ((context.ticks() - started) & 0xFFFFFFFF) >= 5000 or status:
                    break
                _sleep03(context, 1500)
            if status == 0:
                _command03(context, comm, b"\x30")
                _sleep03(context, 1000)
                status, _ = _command03(context, comm, b"\x30\x03\0\x02\x02")
                if status == 0:
                    _sleep03(context, 5000)
        if status != 4:
            _command03(context, comm, b"\x30")
        return status
    finally:
        comm.finalize()


def _abs05(
    arguments: tuple[object, ...], context: UtilityExContext, comm: UtilityExComm
) -> int:
    first, second = (_out(argument) for argument in arguments)
    try:
        status = comm.initialize()
        if status:
            return status
        first[:] = (1).to_bytes(4, "little")
        _configure(context, comm, "native_rva:172d0", 150)
        try:
            status, raw, offsets = comm.support_snapshot(2)
            if status:
                return status
            for output, sub, required in ((first, 0x32, 0x40), (second, 0x2D, 0x20)):
                output[:] = (1).to_bytes(4, "little")
                record_status, masks = _record40(raw, offsets, sub)
                if (
                    record_status
                    or len(masks) < 2
                    or any(mask & required != required for mask in masks[:2])
                ):
                    output[:] = bytes(4)
            for sub in (0x2E, 0x2D, 0x32):
                record_status, masks = _record40(raw, offsets, sub)
                if record_status:
                    raise ValueError(
                        "ABS05 native count record exceeds support snapshot"
                    )
                _save(
                    context,
                    f"abs05_count_{sub}",
                    sum(bool(value) for value in masks[2:]),
                )
            return 0
        finally:
            _configure(context, comm, "native_rva:172d0", 100)
    finally:
        comm.finalize()


def _request15(context: UtilityExContext, comm: UtilityExComm, request: bytes) -> int:
    if request == b"\x30":
        return _command03(context, comm, request)[0]
    _configure(context, comm, "native_rva:172d0", 150)
    try:
        status, reply = _reply(comm, request)
        if status:
            return status
        if request[0] == 0x10:
            return 0 if len(reply) == 1 else 3
        if request == b"\x21\xbf":
            if len(reply) < 3 or reply[1] != 0xBF:
                return 3
            return 1503 if reply[2] & 1 else 0
        if len(reply) == 2 and reply[1] == request[1]:
            return 0
        return 12 if len(reply) == 3 and reply[1:] == bytes((request[1], 0)) else 3
    finally:
        _configure(context, comm, "native_rva:172d0", 100)


def _pattern15(index: int, context: UtilityExContext, comm: UtilityExComm) -> int:
    if index > 4:
        raise ValueError("ABS15 native pattern index must be zero through four")
    sub = 0x2E if index < 3 else 0x2D
    count = _state(context, f"abs15_count_{sub}") + (2 if index == 3 else 0)
    if count > 253:
        raise ValueError("ABS15 A8-derived padding exceeds its native field range")
    payload = (
        b"\x2e\0\x08\x08",
        b"\x2e\0\x10\x10",
        b"\x2e\0\x20\x20",
        b"\x2d\0\x40\x40",
        b"\x2d\0\0\0\x10\x10",
    )[index]
    return _request15(context, comm, b"\x30" + payload + bytes(count))


def _support15(context: UtilityExContext, comm: UtilityExComm) -> int:
    for kind in (1, 2):
        _configure(context, comm, "native_rva:172d0", 150)
        try:
            status, raw, offsets = comm.support_snapshot(kind)
            if status:
                return status
            if kind == 1:
                record_status, masks = _record40(raw, offsets, 0xBF)
                if record_status or not masks or masks[0] & 1 != 1:
                    return 1500
            else:
                status = 0
                for sub, required in (
                    (0x2D, (0x40, 0x40, 0x10, 0x10)),
                    (0x2E, (0x38, 0x38)),
                ):
                    record_status, masks = _record40(raw, offsets, sub)
                    if (
                        record_status
                        or len(masks) < len(required)
                        or any(mask & bit != bit for mask, bit in zip(masks, required))
                    ):
                        status = 1501
                        break
                for sub, skip in ((0x2D, 4), (0x2E, 2)):
                    record_status, masks = _record40(raw, offsets, sub)
                    if record_status:
                        raise ValueError(
                            "ABS15 native count record exceeds support snapshot"
                        )
                    _save(
                        context,
                        f"abs15_count_{sub}",
                        sum(bool(value) for value in masks[skip:]),
                    )
                return status
        finally:
            _configure(context, comm, "native_rva:172d0", 100)
    return 0


def _cancel15(status: int, context: UtilityExContext, comm: UtilityExComm) -> int:
    if context.is_cancelled() and status in (2, 27):
        counters = comm.cancellation_counters()
        native_keys = {
            NK12_SHA256: ("fab0", "fac0", "fad0", "fae0", "faf0"),
            NK18_SHA256: ("17340", "17350", "17360", "17370", "17380"),
            NK_DS4_SHA256: ("321b0", "321a0", "321c0", "321e0", "321f0"),
            NK_GTS_SHA256: ("330c0", "330b0", "330d0", "330f0", "33100"),
        }[context.module_sha256]

        def counter(rva: str) -> int:
            index = ("17340", "17350", "17360", "17370", "17380").index(rva)
            return _uint(counters["native_rva:" + native_keys[index]])

        if status == 27:
            status = (
                29 if counter("17340") or counter("17360") != counter("17350") else 28
            )
        elif counter("17380") != counter("17370"):
            status = 30
    return 0 if status in (29, 30) else status


def _poll15(context: UtilityExContext, comm: UtilityExComm, *, initialize: bool) -> int:
    status = 0
    while not context.is_cancelled():
        status = comm.initialize() if initialize else 0
        if status == 0:
            status = _request15(context, comm, b"\x21\xbf")
        if status != 1503:
            break
        _sleep03(context, 1000)
    if not initialize and context.is_cancelled():
        status = 0
    return _cancel15(status, context, comm)


def _execute15(context: UtilityExContext, comm: UtilityExComm) -> int:
    status = 99
    if not context.is_cancelled():
        status = comm.initialize()
        if status == 0:
            started = context.ticks()
            status = _pattern15(1, context, comm)
            if status == 0:
                while ((context.ticks() - started) & 0xFFFFFFFF) < 15000:
                    status = _request15(context, comm, b"\x21\xbf")
                    if status != 1503:
                        if status:
                            return status
                        break
                    _sleep03(context, 1000)
                status = _pattern15(2, context, comm)
                if status == 0:
                    status = _poll15(context, comm, initialize=False)
    return status


def _abs15(
    export: str,
    arguments: tuple[object, ...],
    context: UtilityExContext,
    comm: UtilityExComm,
) -> int:
    operation = export.removeprefix("Ex2ABS_15_")
    try:
        if operation == "ChkPatternFlg":
            return _poll15(context, comm, initialize=True)
        if operation == "ExecuteAirBleeding":
            status = _execute15(context, comm)
            _request15(context, comm, b"\x30")
            return status
        status = comm.initialize()
        if status:
            return status
        if operation == "GetSupportInfo":
            return _support15(context, comm)
        if operation == "StartAirBleeding":
            return _pattern15(_uint(arguments[0]), context, comm)
        return _request15(
            context,
            comm,
            {
                "EndActiveTest": b"\x30",
                "ShiftTestMode": b"\x10\x40",
                "ShiftNormalMode": b"\x10\x01",
            }[operation],
        )
    finally:
        comm.finalize()


def _support22(context: UtilityExContext, comm: UtilityExComm) -> int:
    _configure(context, comm, "native_rva:172d0", 150)
    try:
        status = comm.refresh_support_cache(2)
        if status:
            return status
        snapshot = comm.cached_support(2)
        if snapshot is None:
            raise UnsupportedChassisOperation("Native support cache was not populated")
        for sub, required, failure in ((3, 2, 801), (0x21, 255, 802)):
            status, masks = _record40(*snapshot, sub)
            if (
                status
                or len(masks) < 2
                or any(mask & required != required for mask in masks[:2])
            ):
                return failure
        return 0
    finally:
        _configure(context, comm, "native_rva:172d0", 100)


def _stop22(context: UtilityExContext, comm: UtilityExComm) -> int:
    for field in ("172d0", "17320", "172f0", "17ba0"):
        _configure(context, comm, "native_rva:" + field, 1)
    try:
        return _reply(comm, b"\x30")[0]
    finally:
        for field, value in (
            ("172d0", 100),
            ("17320", 100),
            ("172f0", 3),
            ("17ba0", 0),
        ):
            _configure(context, comm, "native_rva:" + field, value)


def _command22(context: UtilityExContext, comm: UtilityExComm, request: bytes) -> int:
    _configure(context, comm, "native_rva:172d0", 150)
    try:
        status, reply = _reply(comm, request)
        if status == 0:
            if len(reply) < 2 or reply[1] != request[1]:
                return 3
            if len(reply) > 2 and reply[2] == 0:
                return 12
        return status
    finally:
        _configure(context, comm, "native_rva:172d0", 100)


def _abs22(export: str, context: UtilityExContext, comm: UtilityExComm) -> int:
    try:
        status = comm.initialize()
        if status:
            return status
        if export.endswith("GetDIDSupport"):
            return _support22(context, comm)
        if export.endswith("StopActiveTest"):
            return _stop22(context, comm)
        first = b"\x30\x21\x02\xff\x55"
        full = b"\x30\x21\x02\xff\xff"
        release = b"\x30\x21\0\xff\0"
        for _ in range(2):
            for index, request in enumerate((first, full, full, first, release)):
                status = _command22(context, comm, request)
                if status:
                    return status
                _sleep03(context, 1000 if index < 4 else 3000)
        status = _command22(context, comm, b"\x30\x03\x05\x02\x02")
        if status == 0:
            _sleep03(context, 7000)
            _stop22(context, comm)
        return status
    finally:
        comm.finalize()


def _support25(context: UtilityExContext, comm: UtilityExComm) -> int:
    for kind, sub, indices, failure in ((1, 0xBF, (0,), 911), (2, 0x2E, (2, 3), 912)):
        _configure(context, comm, "native_rva:172d0", 150)
        try:
            status = comm.refresh_support_cache(kind)
            if status:
                return status
            snapshot = comm.cached_support(kind)
            if snapshot is None:
                raise UnsupportedChassisOperation(
                    "Native support cache was not populated"
                )
            status, masks = _record40(*snapshot, sub)
            required = 1 if kind == 1 else 8
            if (
                status
                or len(masks) <= max(indices)
                or any(masks[index] & required != required for index in indices)
            ):
                return failure
        finally:
            _configure(context, comm, "native_rva:172d0", 100)
    return 0


def _abs25(export: str, context: UtilityExContext, comm: UtilityExComm) -> int:
    operation = export.removeprefix("Ex2ABS_25_")
    try:
        if (
            operation in ("ForcedActuatorRefresh", "ConfirmActivatingFlg")
            and context.is_cancelled()
        ):
            return 0
        status = comm.initialize()
        if status:
            return status
        if operation == "GetSupportInfo":
            return _support25(context, comm)
        if operation == "StopActiveTest":
            return _stop22(context, comm)
        if operation == "ForcedActuatorRefresh":
            status = _command40(context, comm, b"\x30\x2e\0\0\0\x08\x08")
            if status:
                _stop22(context, comm)
            return status
        status = 0
        while not context.is_cancelled():
            _sleep03(context, 1000)
            status = _request15(context, comm, b"\x21\xbf")
            if status == 1503:
                status = 1
            if status != 1:
                break
        # Old sources explicitly stop on failure/cancel; modern workers omit it.
        if context.module_sha256 in (NK12_SHA256, NK18_SHA256) and (
            context.is_cancelled() or status
        ):
            _stop22(context, comm)
        return status
    finally:
        comm.finalize()


def _support_type01(
    output: bytearray, context: UtilityExContext, comm: UtilityExComm
) -> int:
    _configure(context, comm, "native_rva:172d0", 150)
    try:
        status, raw, offsets = comm.support_snapshot(2)
        if status:
            return status
        status22, masks22 = _record40(raw, offsets, 0x22)
        back = not status22 and len(masks22) >= 2
        strict = back and all(mask & 0xF == 0xF for mask in masks22[:2])
        partial = back and all(mask & 0xC == 0xC for mask in masks22[:2])
        if strict or partial:
            output[4:8] = sum(bool(value) for value in masks22[2:]).to_bytes(
                4, "little"
            )
        front = False
        if strict or partial:
            status21, masks21 = _record40(raw, offsets, 0x21)
            front = (
                not status21
                and len(masks21) >= 2
                and all(mask & 0xA == 0xA for mask in masks21[:2])
            )
            if front:
                output[:4] = sum(bool(value) for value in masks21[2:]).to_bytes(
                    4, "little"
                )
        return 0 if strict or front else 100
    finally:
        _configure(context, comm, "native_rva:172d0", 100)


def _flow01(
    export: str,
    arguments: tuple[object, ...],
    context: UtilityExContext,
    comm: UtilityExComm,
) -> int:
    if export.endswith("Conf_typeof_AirBleeding"):
        try:
            status = comm.initialize()
            if status:
                return status
            status, reply = _command03(context, comm, b"\x21\x08")
            if status:
                return status
            if reply[2] != 7:
                return 222
            return _support_type01(_buffer(arguments[0], 8), context, comm)
        finally:
            comm.finalize()
    try:
        status = comm.initialize()
        if status:
            return status
        selection = _uint(arguments[0])
        counts = _buffer(arguments[1], 8)
        front = selection in (0x226, 0x227)
        offset = 0 if front else 4
        count = int.from_bytes(counts[offset : offset + 4], "little")
        mask = (
            2
            if selection == 0x226
            else 8
            if selection == 0x227
            else 12
            if selection in (0x228, 0x229)
            else 0
        )
        return _request15(
            context,
            comm,
            bytes((0x30, 0x21 if front else 0x22, 0, mask, mask)) + bytes(count),
        )
    except BaseException:
        comm.finalize()
        raise


def _input41(value: object, length: int, maximum: int) -> bytes:
    if value is None and length == 0:
        return b""
    if (
        not isinstance(value, (bytes, bytearray))
        or length > maximum
        or len(value) < length
    ):
        raise ValueError("SMRT41 input must fit its native byte buffer")
    return bytes(value[:length])


def _validate41(operation: str, arguments: tuple[object, ...]) -> None:
    if operation == "Online_Certification":
        _out(arguments[0])
        _uint(arguments[1])
        _buffer(arguments[2], 8)
        _out(arguments[3])
        _buffer(arguments[4], 6)
        if _uint(arguments[8]):
            if _uint(arguments[5]) >= 0x1020:
                raise ValueError(
                    "SMRT41 reply offset exceeds the native response buffer"
                )
        else:
            _input41(arguments[7], _uint(arguments[6]), 0x1020)
    elif operation == "Online_Certification_008":
        _out(arguments[0])
        _buffer(arguments[1], 8)
        _out(arguments[2])
        _buffer(arguments[3], 6)
    elif operation == "KeepAlive":
        _out(arguments[0])
        _out(arguments[1])
    else:
        _input41(arguments[0], _uint(arguments[2]), 0x101E)
        _out(arguments[1])


def _frame41(
    context: UtilityExContext, comm: UtilityExComm, request: bytes
) -> tuple[int, bytes]:
    _configure(context, comm, "native_rva:172d0", 150)
    try:
        return _reply(comm, request)
    finally:
        _configure(context, comm, "native_rva:172d0", 100)


def _cert_state41(
    arguments: tuple[object, ...], context: UtilityExContext, comm: UtilityExComm
) -> int:
    output = _out(arguments[0])
    direct = bool(_uint(arguments[8]))
    _configure(context, comm, "native_rva:172d0", 150)
    try:
        if not direct:
            # Native20b90 returns99 even after committing; the caller ignores it.
            comm.append_support_profile(
                _input41(arguments[7], _uint(arguments[6]), 0x1020), 1
            )
        status, reply = _reply(comm, b"\x21\xd2")
        index = _uint(arguments[5]) if direct else 0
        if status == 0:
            if len(reply) < 2 or reply[1] != 0xD2:
                status = 3
            elif not direct:
                snapshot = comm.cached_support(1)
                if snapshot is not None:
                    record_status, masks = _record40(*snapshot, 0xD2)
                    if record_status == 0 and len(masks) >= 2 and masks[1]:
                        index = sum(bool(value) for value in masks[:2]) + 2
                if index == 0:
                    # The original reads before its buffer for an absent ordinal.
                    status = 3
            if status == 0 and len(reply) < index + (1 if direct else 0):
                status = 3
        if status:
            output[:] = (4001).to_bytes(4, "little")
            return status
        value = reply[index if direct else index - 1]
        if not value & 0x80:
            output[:] = (4003 if value & 0x40 else 4002).to_bytes(4, "little")
        return 0
    finally:
        _configure(context, comm, "native_rva:172d0", 100)


def _challenge41(
    challenge: bytearray,
    timestamp: bytearray,
    seed: bytearray,
    context: UtilityExContext,
    comm: UtilityExComm,
) -> int:
    status, reply = _frame41(context, comm, b"\x1a\x84")
    if status:
        return status
    if len(reply) < 10 or reply[1] != len(reply) - 2:
        return 3
    challenge[:8] = reply[2:10]
    status, reply = _frame41(context, comm, b"\x27\x09")
    if status:
        return status
    if len(reply) < 8 or reply[1] != 9:
        return 3
    seed[:6] = reply[2:8]
    timestamp[:] = (context.ticks() & 0xFFFFFFFF).to_bytes(4, "little")
    return _frame41(context, comm, b"\x3e")[0]


_ABS35_REQUESTS = {
    "A": bytes.fromhex("2f2801030055000000550000"),
    "B": bytes.fromhex("2f28010300ff000000ff0000"),
    "C": bytes.fromhex("2f28010000ff0000"),
    "D": bytes.fromhex("2f2801030000002000000020"),
    "E": bytes.fromhex("2f28010000000020"),
}


def _command35(comm: UtilityExComm, stage: str) -> int:
    request = _ABS35_REQUESTS[stage]
    status, reply = _reply(comm, request)
    return (
        3 if status == 0 and (len(reply) < 4 or reply[1:4] != request[1:4]) else status
    )


def _support35(comm: UtilityExComm, *, plumbing: bool = False) -> int:
    status, reply = _reply(comm, b"\x22\x10\x2d")
    if status:
        return status
    if len(reply) < 13 or reply[1:3] != b"\x10\x2d":
        return 3
    if plumbing:
        return 1004 if reply[12] & 0x20 else 1003
    if not reply[11] & 0x20:
        return 1000
    status, reply = _reply(comm, b"\x22\x28\x01")
    if status == 0:
        if len(reply) < 6 or reply[1:3] != b"\x28\x01":
            return 3
        if reply[3] != 0xFF or not reply[5] & 0x20:
            return 1001
    return status


def _solenoid35(context: UtilityExContext, comm: UtilityExComm) -> tuple[int, int]:
    phase = 0
    for cycle in range(2):
        for stage in "AABBBBAA":
            status = _command35(comm, stage)
            if status:
                return status, phase
            _sleep03(context, 1500)
        status = _command35(comm, "C")
        phase = 2
        if status:
            return status, phase
        _sleep03(context, 3000)
        if cycle == 0:
            phase = 0
    status = _command35(comm, "D")
    phase = 1
    if status:
        return status, phase
    _sleep03(context, 5000)
    status = _command35(comm, "E")
    return status, 2


def _abs35(export: str, context: UtilityExContext, comm: UtilityExComm) -> int:
    operation = export.removeprefix("Ex2ABS_35_")
    phase = 0
    try:
        status = comm.initialize()
        if status == 0:
            if comm.session(3, 1, normal_first=True):
                return 1002
            if operation == "SolenoidDriving":
                status, phase = _solenoid35(context, comm)
            else:
                status = _support35(comm, plumbing=operation == "ConfPlumbigStatus")
            if status == 0 or (
                operation == "ConfPlumbigStatus" and status in (1003, 1004)
            ):
                return 1002 if comm.session(1, 1, stop_on_error=True) else status
        if status != 1002:
            if operation == "SolenoidDriving" and phase in (0, 1):
                _command35(comm, "C" if phase == 0 else "E")
            _configure(context, comm, "native_rva:18840", 1)
            try:
                comm.session(1, 1, stop_on_error=True)
            finally:
                _configure(context, comm, "native_rva:18840", 0)
        return status
    finally:
        comm.finalize()


def _field47(context: UtilityExContext, index: int, *, support: bool = False) -> str:
    base = {
        NK18_SHA256: (0x1014A598, 0x1014A678),
        NK_DS4_SHA256: (0x101B1944, 0x101B195C),
        NK_GTS_SHA256: (0x101BCA44, 0x101BCA5C),
    }[context.module_sha256][int(support)]
    return f"native_global:{base + index * 4:08x}"


def _native47(
    context: UtilityExContext, index: int, *, support: bool = False
) -> object:
    return context.state.get(_field47(context, index, support=support), 0)


def _stop47(context: UtilityExContext, comm: UtilityExComm) -> None:
    # Its source void helper deliberately ignores even malformed stop replies.
    _frame41(context, comm, b"\x3b\x87" + bytes(6))


def _poll47(context: UtilityExContext, comm: UtilityExComm) -> int:
    started = context.ticks()
    mode = _uint(_native47(context, 1))
    backing = bytearray(0x1020)
    _configure(context, comm, "native_rva:172d0", 150)
    try:
        minimum = _packed42(comm, 5)
        status = 99
        while not context.is_cancelled():
            status, reply = _reply(comm, b"\x21\xd1")
            if status:
                break
            elapsed = (context.ticks() - started) & 0xFFFFFFFF
            backing[: len(reply)] = reply
            if len(reply) < minimum or backing[1] != 0xD1:
                return 3
            if mode not in (1, 2, 3, 4):
                return 0
            status = 4701
            if mode != 2 or not context.is_cancelled():
                if backing[4] & 0x10:
                    return 4702
                if (
                    (bool(backing[3] & 0x40) == (mode == 1))
                    if mode in (1, 2)
                    else (bool(backing[2] & 8) == (mode == 3))
                ):
                    return 0
                if elapsed >= 30000:
                    return {1: 4703, 2: 4706, 3: 4704, 4: 4705}[mode]
            if context.is_cancelled():
                break
            context.sleep(1)
        return status
    finally:
        _configure(context, comm, "native_rva:172d0", 100)


def _smrt47(
    export: str,
    arguments: tuple[object, ...],
    context: UtilityExContext,
    comm: UtilityExComm,
) -> int:
    operation = export.removeprefix("Ex2SMRT_47_")
    try:
        if operation == "SetSupportInfo":
            status = comm.initialize()
            for kind, data, length in (
                (1, arguments[0], arguments[2]),
                (3, arguments[1], arguments[3]),
            ):
                comm.append_support_profile(_input41(data, _uint(length), 0x1020), kind)
            return status
        if operation == "GetKeyStatus_RegistrationChk":
            status = 99
            if not context.is_cancelled():
                status = comm.initialize()
                if status:
                    return status
                context.state[_field47(context, 1)] = 3
                status = _poll47(context, comm)
                if status == 0:
                    context.state[_field47(context, 1)] = 4
                    status = _poll47(context, comm)
            _stop47(context, comm)
            return status
        if operation == "GetKeyStatus_NomalChk":
            status = 99
            if not context.is_cancelled():
                status = comm.initialize()
                if status == 0:
                    status = _poll47(context, comm)
            if not context.is_cancelled() and status not in (0, 4706):
                _stop47(context, comm)
            return status
        if context.is_cancelled():
            return 99
        status = comm.initialize()
        if operation == "StopKeyCodeReset":
            if status:
                return 14
            _stop47(context, comm)
            return 0
        if status:
            return status
        if operation == "GetSupportInfo":
            status = _support_key_registration(
                context,
                comm,
                1,
                _native47(context, 0, support=True),
                _native47(context, 2, support=True),
                family=47,
            )
            return (
                status
                if status
                else _support_key_registration(
                    context,
                    comm,
                    3,
                    _native47(context, 1, support=True),
                    _native47(context, 3, support=True),
                    family=47,
                )
            )
        for kind, pointer, length in ((1, 2, 4), (3, 3, 5)):
            comm.append_support_profile(
                _input41(
                    _native47(context, pointer),
                    _uint(_native47(context, length)),
                    0x1020,
                ),
                kind,
            )
        status = _command45(context, comm, 0x20)
        if status:
            return 4700
        status = _poll47(context, comm)
        if status:
            _stop47(context, comm)
        return status
    finally:
        comm.finalize()


def _field46(context: UtilityExContext, index: int, *, support: bool = False) -> str:
    base = {
        NK18_SHA256: (0x1014A6B0, 0x1014A530),
        NK_DS4_SHA256: (0x101B1914, 0x101B1934),
        NK_GTS_SHA256: (0x101BCA14, 0x101BCA34),
    }[context.module_sha256][int(support)]
    return f"native_global:{base + index * 4:08x}"


def _native46(
    context: UtilityExContext, index: int, *, support: bool = False
) -> object:
    return context.state.get(_field46(context, index, support=support), 0)


def _stop46(context: UtilityExContext, comm: UtilityExComm) -> None:
    # Its source void helper deliberately ignores even malformed stop replies.
    _frame41(context, comm, b"\x3b\x87" + bytes(6))


def _poll46(context: UtilityExContext, comm: UtilityExComm) -> int:
    started = context.ticks()
    mode = _uint(_native46(context, 3))
    backing = bytearray(0x1020)
    _configure(context, comm, "native_rva:172d0", 150)
    try:
        minimum = _packed42(comm, 5)
        status = 99
        while not context.is_cancelled():
            status, reply = _reply(comm, b"\x21\xd1")
            if status:
                break
            elapsed = (context.ticks() - started) & 0xFFFFFFFF
            backing[: len(reply)] = reply
            if len(reply) < minimum or backing[1] != 0xD1:
                return 3
            if mode not in (1, 2, 3, 4):
                return 0
            status = 4601
            if mode != 2 or not context.is_cancelled():
                if backing[4] & 0x10:
                    return 4602
                if (
                    (bool(backing[3] & 0x40) == (mode == 1))
                    if mode in (1, 2)
                    else (bool(backing[2] & 8) == (mode == 3))
                ):
                    return 0
                if elapsed >= 30000:
                    return {1: 4603, 2: 4606, 3: 4604, 4: 4605}[mode]
            if context.is_cancelled():
                break
            context.sleep(1)
        return status
    finally:
        _configure(context, comm, "native_rva:172d0", 100)


def _smrt46(
    export: str,
    arguments: tuple[object, ...],
    context: UtilityExContext,
    comm: UtilityExComm,
) -> int:
    operation = export.removeprefix("Ex2SMRT_46_")
    try:
        if operation == "SetSupportInfo":
            status = comm.initialize()
            for kind, data, length in (
                (1, arguments[0], arguments[2]),
                (3, arguments[1], arguments[3]),
            ):
                comm.append_support_profile(_input41(data, _uint(length), 0x1020), kind)
            return status
        if operation == "GetKeyStatus_RegistrationChk":
            status = 99
            if not context.is_cancelled():
                status = comm.initialize()
                if status:
                    return status
                context.state[_field46(context, 3)] = 3
                status = _poll46(context, comm)
                if status == 0:
                    context.state[_field46(context, 3)] = 4
                    status = _poll46(context, comm)
            _stop46(context, comm)
            return status
        if operation == "GetKeyStatus":
            status = 99
            if not context.is_cancelled():
                status = comm.initialize()
                if status == 0:
                    status = _poll46(context, comm)
            if not context.is_cancelled() and status not in (0, 4606):
                _stop46(context, comm)
            return status
        if context.is_cancelled():
            return 99
        status = comm.initialize()
        if operation == "StopKeyCodeReset":
            if status:
                return 14
            _stop46(context, comm)
            return 0
        if status:
            return status
        if operation == "GetSupportInfo":
            status = _support_key_registration(
                context,
                comm,
                1,
                _native46(context, 0, support=True),
                _native46(context, 2, support=True),
                family=46,
            )
            return (
                status
                if status
                else _support_key_registration(
                    context,
                    comm,
                    3,
                    _native46(context, 1, support=True),
                    _native46(context, 3, support=True),
                    family=46,
                )
            )
        for kind, pointer, length in ((1, 4, 6), (3, 5, 7)):
            comm.append_support_profile(
                _input41(
                    _native46(context, pointer),
                    _uint(_native46(context, length)),
                    0x1020,
                ),
                kind,
            )
        status = _command45(context, comm, 0x40)
        if status:
            return 4600
        status = _poll46(context, comm)
        if status:
            _stop46(context, comm)
        return status
    finally:
        comm.finalize()


def _field45(context: UtilityExContext, index: int, *, support: bool = False) -> str:
    base = {
        NK18_SHA256: (0x1014A618, 0x1014A6E0),
        NK_DS4_SHA256: (0x101B18F8, 0x101B18E8),
        NK_GTS_SHA256: (0x101BC9F8, 0x101BC9E8),
    }[context.module_sha256][int(support)]
    return f"native_global:{base + index * 4:08x}"


def _native45(
    context: UtilityExContext, index: int, *, support: bool = False
) -> object:
    return context.state.get(_field45(context, index, support=support), 0)


def _command45(context: UtilityExContext, comm: UtilityExComm, flag: int) -> int:
    status, reply = _frame41(context, comm, bytes((0x3B, 0x87, flag)) + bytes(5))
    return 3 if status == 0 and (len(reply) != 2 or reply[1] != 0x87) else status


def _support_key_registration(
    context: UtilityExContext,
    comm: UtilityExComm,
    kind: int,
    output: object,
    length: object,
    *,
    family: int = 45,
) -> int:
    _configure(context, comm, "native_rva:172d0", 150)
    try:
        status = comm.refresh_support_cache(kind)
        if status:
            return status
        snapshot = comm.cached_support(kind)
        if snapshot is None:
            raise UnsupportedChassisOperation(
                "SMRT45 support cache missing after refresh"
            )
        predicates = (
            ((0xD1, 3, 8), (0xD1, 4, 0x40), (0xD1, 5, 0x10), (0xD2, 4, 0x80))
            if kind == 1
            else ((0x87, 3, {45: 0x80, 46: 0x40, 47: 0x20}[family]),)
        )
        for sub, ordinal, mask in predicates:
            record_status, masks = _record40(*snapshot, sub)
            if (
                record_status
                or len(masks) < ordinal - 2
                or masks[ordinal - 3] & mask != mask
            ):
                return (4510 if kind == 1 else 4511) if family == 45 else 99
        raw, offsets = snapshot
        copied = bytearray()
        for sub in (0xD1, 0xD2) if kind == 1 else (0x87,):
            offset = offsets[sub]
            count = (raw[offset + 1] + 2) & 0xFF
            copied.extend(raw[offset : offset + count])
        _out(length)[:] = len(copied).to_bytes(4, "little")
        _buffer(output, len(copied))[: len(copied)] = copied
        return 0
    finally:
        _configure(context, comm, "native_rva:172d0", 100)


def _mode45(context: UtilityExContext) -> int:
    mode = _uint(_native45(context, 4))
    if mode > 3:
        raise ValueError("SMRT45 native status table index exceeds four entries")
    return mode


def _classify45(context: UtilityExContext, comm: UtilityExComm) -> int:
    field = _field45(context, 6)
    context.state[field] = 4506
    _configure(context, comm, "native_rva:172d0", 150)
    try:
        _mode45(context)
        first = _packed42(comm, 5)
        second = _packed42(comm, 4 if _mode45(context) < 2 else 3)
        status, reply = _reply(comm, b"\x21\xd1")
        if status:
            return status
        if len(reply) < first or len(reply) < 2 or reply[1] != 0xD1:
            return 3
        if not 1 <= first <= 0x1020 or not 1 <= second <= 0x1020:
            return 3
        backing = reply.ljust(0x1020, b"\0")
        mode = _mode45(context)
        context.state[field] = (
            4502
            if backing[first - 1] & 0x10
            else (4503 if mode < 2 else 4504)
            if backing[second - 1] & (0x40 if mode < 2 else 8)
            else 4500
        )
        return 0
    finally:
        _configure(context, comm, "native_rva:172d0", 100)


def _smrt45(
    export: str,
    arguments: tuple[object, ...],
    context: UtilityExContext,
    comm: UtilityExComm,
) -> int:
    operation = export.removeprefix("Ex2SMRT_45_")
    try:
        if operation == "SetSupportInfo":
            status = comm.initialize()
            for kind, pointer, length in (
                (1, arguments[0], arguments[2]),
                (3, arguments[1], arguments[3]),
            ):
                comm.append_support_profile(
                    _input41(pointer, _uint(length), 0x1020), kind
                )
            return status
        if operation == "StartOwnersKeyReg":
            _out(_native45(context, 5))[:] = (450).to_bytes(4, "little")
        if context.is_cancelled():
            return 99
        status = comm.initialize()
        if status:
            return status
        if operation == "GetSupportInfo":
            status = _support_key_registration(
                context,
                comm,
                1,
                _native45(context, 0, support=True),
                _native45(context, 2, support=True),
            )
            return (
                status
                if status
                else _support_key_registration(
                    context,
                    comm,
                    3,
                    _native45(context, 1, support=True),
                    _native45(context, 3, support=True),
                )
            )
        if operation == "StopOwnersKeyReg":
            return _command45(context, comm, 0)
        if operation == "StartOwnersKeyReg":
            for kind, pointer, length in ((1, 0, 2), (3, 1, 3)):
                comm.append_support_profile(
                    _input41(
                        _native45(context, pointer),
                        _uint(_native45(context, length)),
                        0x1020,
                    ),
                    kind,
                )
            status = _command45(context, comm, 0x80)
            if status:
                return status
        started = current = context.ticks()
        while not context.is_cancelled():
            if ((current - started) & 0xFFFFFFFF) >= 30000:
                if operation in ("StartOwnersKeyReg", "GetKeyStatus_WaitComp"):
                    _command45(context, comm, 0)
                return 4505
            if operation == "StartOwnersKeyReg":
                _out(_native45(context, 5))[:] = (451).to_bytes(4, "little")
            status = _classify45(context, comm)
            state = _uint(_native45(context, 6))
            pending = {
                "StartOwnersKeyReg": 4500,
                "GetKeyStatus_StatusNormal": 4503,
                "GetKeyStatus_WaitComp": 4500,
                "GetKeyStatus_RegNormal": 4504,
            }[operation]
            terminal = {
                "StartOwnersKeyReg": 4503,
                "GetKeyStatus_StatusNormal": 4500,
                "GetKeyStatus_WaitComp": 4504,
                "GetKeyStatus_RegNormal": None,
            }[operation]
            if state == pending:
                current = context.ticks()
            elif state == terminal:
                return state
            else:
                _command45(context, comm, 0)
                if state == 4502 or (
                    operation == "GetKeyStatus_RegNormal" and state == 4500
                ):
                    return state
            if status or context.is_cancelled():
                break
            context.sleep(1)
        return status
    finally:
        comm.finalize()


def _native42(context: UtilityExContext, index: int) -> object:
    base = {
        NK18_SHA256: 0x1014A640,
        NK12_SHA256: 0x100E5C90,
        NK_DS4_SHA256: 0x101B18C8,
        NK_GTS_SHA256: 0x101BC9C8,
    }[context.module_sha256]
    return context.state.get(f"native_global:{base + index * 4:08x}", 0)


def _packed42(comm: UtilityExComm, ordinal: int) -> int:
    snapshot = comm.cached_support(1)
    if snapshot is not None:
        status, masks = _record40(*snapshot, 0xD1)
        if status == 0 and 2 < ordinal <= len(masks) + 2 and masks[ordinal - 3]:
            count = sum(bool(value) for value in masks[: ordinal - 2])
            if count:
                return count + 2
    return 0


def _command42(comm: UtilityExComm, flag: int) -> tuple[int, bytes]:
    snapshot = comm.cached_support(3)
    if snapshot is None:
        return 82, b""
    status, masks = _record40(*snapshot, 0x81)
    count = len(masks) if status == 0 else 0
    # Native207a0 pads unchanged input; kind3 uses record length, not mask count.
    if count < 6:
        return 82, b""
    return _reply(comm, bytes((0x3B, 0x81, flag)) + bytes(count - 1))


def _request42(context: UtilityExContext, comm: UtilityExComm, flag: int) -> int:
    _configure(context, comm, "native_rva:172d0", 150)
    try:
        status, reply = _command42(comm, flag)
        return 3 if status == 0 and (len(reply) != 2 or reply[1] != 0x81) else status
    finally:
        _configure(context, comm, "native_rva:172d0", 100)


def _stop42(context: UtilityExContext, comm: UtilityExComm) -> int:
    for field in ("172d0", "17320", "172f0", "17ba0"):
        _configure(context, comm, "native_rva:" + field, 1)
    try:
        _command42(comm, 0)
        return 99
    finally:
        for field, value in (
            ("172d0", 100),
            ("17320", 100),
            ("172f0", 3),
            ("17ba0", 0),
        ):
            _configure(context, comm, "native_rva:" + field, value)


def _support42(
    context: UtilityExContext,
    comm: UtilityExComm,
    kind: int,
    output: object,
    length: object,
) -> int:
    _configure(context, comm, "native_rva:172d0", 150)
    try:
        status = comm.refresh_support_cache(kind)
        if status:
            return status
        snapshot = comm.cached_support(kind)
        if snapshot is None:
            raise UnsupportedChassisOperation(
                "SMRT42 refresh did not populate native cache"
            )
        predicates = (
            (
                (0xD1, 3, 0xC0),
                (0xD1, 4, 4),
                (0xD1, 7, 0xF0),
                (0xD1, 8, 0xF0),
                (0xD2, 4, 0x20),
            )
            if kind == 1
            else ((0x81, 3, 0xC0), (0x81, 3, 0x30))
        )
        matches = []
        for sub, ordinal, required in predicates:
            record_status, masks = _record40(*snapshot, sub)
            matches.append(
                record_status == 0
                and len(masks) >= ordinal - 2
                and masks[ordinal - 3] & required == required
            )
        status = 0 if (all(matches) if kind == 1 else any(matches)) else 99
        raw, offsets = snapshot
        copied = bytearray()
        for sub in (0xD1, 0xD2) if kind == 1 else (0x81,):
            record_status, _ = _record40(raw, offsets, sub)
            if record_status:
                raise ValueError(
                    "SMRT42 native record copy requires a bounded present record"
                )
            offset = offsets[sub]
            count = (raw[offset + 1] + 2) & 0xFF
            copied.extend(raw[offset : offset + count])
        # Native writes length first, including when support predicates failed.
        _out(length)[:] = len(copied).to_bytes(4, "little")
        _buffer(output, len(copied))[: len(copied)] = copied
        return status
    finally:
        _configure(context, comm, "native_rva:172d0", 100)


def _poll42(context: UtilityExContext, comm: UtilityExComm, started: int) -> int:
    first, second, mode = (
        _native42(context, 0),
        _native42(context, 1),
        _uint(_native42(context, 3)),
    )
    _configure(context, comm, "native_rva:172d0", 150)
    try:
        minimum, index_first, index_second = (
            _packed42(comm, 8),
            _packed42(comm, 8),
            _packed42(comm, 7),
        )
        backing = bytearray(0x1020)
        status = 99
        while not context.is_cancelled():
            status, reply = _reply(comm, b"\x21\xd1")
            if status:
                break
            now = context.ticks() if mode == 10 else 0
            backing[: len(reply)] = reply
            if len(reply) < minimum or backing[1] != 0xD1:
                return 3
            if mode == 8:
                if backing[2] & 0xC0 != 0x80:
                    return 3201
                # The increase helper recomputes its ordinal after each reply.
                index = _packed42(comm, 7)
                if not 1 <= index <= len(backing):
                    return 3
                count = backing[index - 1] >> 4
                count = count if count < 8 else 0
                output = _buffer(second, 1)
                status = 0 if output[0] < count else 3200
                output[0] = count
            elif mode == 9:
                status = 3200 if backing[2] & 0xC0 == 0x80 else 3201
            elif mode == 10:
                if backing[2] & 0xC0 == 0:
                    _stop42(context, comm)
                    return 3203 if backing[3] & 4 else 0
                status = 3202 if ((now - started) & 0xFFFFFFFF) >= 60000 else 3200
            elif mode in (11, 12):
                if not 1 <= index_first <= len(backing) or (
                    mode == 11 and not 1 <= index_second <= len(backing)
                ):
                    return 3
                count = backing[index_first - 1] >> 4
                if mode == 12:
                    # Native rereads struct[0] for the write, but clamps captured ptr.
                    _buffer(_native42(context, 0), 1)[0] = count
                    if _buffer(first, 1)[0] > 7:
                        _buffer(first, 1)[0] = 0
                else:
                    _buffer(first, 1)[0] = count if count < 8 else 0
                    count = backing[index_second - 1] >> 4
                    _buffer(second, 1)[0] = count if count < 8 else 0
                return 0
            else:
                return 0
            if status != 3200 or context.is_cancelled():
                break
            # Native polls without delay; host yield preserves elapsed thresholds.
            context.sleep(1)
        return status
    finally:
        _configure(context, comm, "native_rva:172d0", 100)


def _smrt42(
    export: str,
    arguments: tuple[object, ...],
    context: UtilityExContext,
    comm: UtilityExComm,
) -> int:
    operation = export.removeprefix("Ex2SMRT_42_")
    retained = False
    try:
        if operation == "GetKeyStatus":
            status = _poll42(context, comm, 0)
            retained = status == 0
            if status not in (0, 3200):
                _stop42(context, comm)
            return status
        status = comm.initialize()
        if operation == "SetSupportInfo":
            for kind, data, length in (
                (1, arguments[0], arguments[2]),
                (3, arguments[1], arguments[3]),
            ):
                comm.append_support_profile(_input41(data, _uint(length), 0x1020), kind)
            return status
        if operation == "TerminateKeyCodeErasure":
            if status == 0:
                _stop42(context, comm)
            return status
        if operation == "GetSupportInfo":
            if status == 0:
                status = _support42(context, comm, 1, arguments[0], arguments[2])
                if status == 0:
                    status = _support42(context, comm, 3, arguments[1], arguments[3])
            return status
        if operation == "GetKeyNum":
            return status if status else _poll42(context, comm, 0)
        if operation == "KeyCodeErasureChk":
            if status:
                return status
            for kind, pointer, length in ((1, 4, 6), (3, 5, 7)):
                comm.append_support_profile(
                    _input41(
                        _native42(context, pointer),
                        _uint(_native42(context, length)),
                        0x1020,
                    ),
                    kind,
                )
            status = _request42(
                context, comm, 0x30 if _uint(_native42(context, 2)) == 4004 else 0x80
            )
            if status:
                return 3204
            status = _poll42(context, comm, 0)
            retained = status == 0
            if status:
                _stop42(context, comm)
            return status
        if status == 0:
            status = _request42(context, comm, 4)
            status = _poll42(context, comm, context.ticks()) if status == 0 else 3204
        if status not in (0, 3203):
            _stop42(context, comm)
        return status
    finally:
        if not retained:
            comm.finalize()


def _native41(context: UtilityExContext, operation: str, index: int) -> object:
    bases = {
        NK18_SHA256: (0x1014A5C0, 0x1014A588, 0x1014A5B8, 0x1014A688),
        NK12_SHA256: (0x100E5C68, 0x100E5C50, 0x100E5C60, 0x100E5CB8),
        NK_DS4_SHA256: (0x101B19BC, 0x101B19E0, 0x101B19F0, 0x101B19F8),
        NK_GTS_SHA256: (0x101BCABC, 0x101BCAE0, 0x101BCAF0, 0x101BCAF8),
    }[context.module_sha256]
    operation_index = (
        "Online_Certification",
        "Online_Certification_008",
        "KeepAlive",
        "SendTheKey",
    ).index(operation)
    return context.state.get(
        f"native_global:{bases[operation_index] + index * 4:08x}", 0
    )


def _smrt41(
    export: str,
    arguments: tuple[object, ...],
    context: UtilityExContext,
    comm: UtilityExComm,
) -> int:
    operation = export.removeprefix("Ex2SMRT_41_")
    if operation == "Online_Certification":
        # The worker captures these fields before initialize, later branch fields after it.
        arguments = tuple(
            _native41(context, operation, index) for index in range(5)
        ) + (None, None, None, _native41(context, operation, 8))
    else:
        arguments = tuple(
            _native41(context, operation, index)
            for index in range(
                {"Online_Certification_008": 4, "KeepAlive": 2, "SendTheKey": 3}[
                    operation
                ]
            )
        )
        _validate41(operation, arguments)
    try:
        if operation == "KeepAlive":
            timestamp, output = (_out(argument) for argument in arguments)
            status = 99
            while not context.is_cancelled():
                status = comm.initialize()
                if status:
                    break
                if (
                    (context.ticks() - int.from_bytes(timestamp, "little")) & 0xFFFFFFFF
                ) >= 4000:
                    timestamp[:] = (context.ticks() & 0xFFFFFFFF).to_bytes(4, "little")
                    status, _ = _frame41(context, comm, b"\x3e")
                    if status:
                        output[:] = (4001).to_bytes(4, "little")
                        break
                # The native busy loop has no wait; yield without changing4s threshold.
                context.sleep(1)
            return status
        status = comm.initialize()
        if status:
            return status
        if operation == "SendTheKey":
            request = b"\x27\x0a" + _input41(arguments[0], _uint(arguments[2]), 0x101E)
            status, reply = _frame41(context, comm, request)
            if status == 0:
                status = (
                    3
                    if len(reply) != 3 or reply[1] != 10
                    else 0
                    if reply[2] == 0x34
                    else 4007
                )
            if status:
                _out(arguments[1])[:] = (4001).to_bytes(4, "little")
            return status
        if operation == "Online_Certification":
            branch_fields = (
                (_native41(context, operation, 5), None, None)
                if _uint(arguments[8])
                else (
                    None,
                    _native41(context, operation, 6),
                    _native41(context, operation, 7),
                )
            )
            arguments = arguments[:5] + branch_fields + arguments[8:]
            _validate41(operation, arguments)
            status = _cert_state41(arguments, context, comm)
            if status or int.from_bytes(_out(arguments[0]), "little") != 4005:
                return status
            if _uint(arguments[1]) != 1:
                return 4006
            challenge, timestamp, seed = arguments[2:5]
        else:
            challenge, timestamp, seed = arguments[1:4]
        status = _challenge41(
            _buffer(challenge, 8), _out(timestamp), _buffer(seed, 6), context, comm
        )
        if status:
            _out(arguments[0])[:] = (4001).to_bytes(4, "little")
        return status
    finally:
        comm.finalize()


def _support14(context: UtilityExContext, comm: UtilityExComm) -> int:
    status, raw, offsets = comm.support_snapshot(2)
    if status:
        return status
    for sub, required in ((0x21, 0xAA), (0x22, 3), (3, 2)):
        status, masks = _record40(raw, offsets, sub)
        if (
            status
            or len(masks) < 2
            or any(mask & required != required for mask in masks[:2])
        ):
            return 140
        _save(context, f"abs14_count_{sub}", sum(bool(value) for value in masks[2:]))
    return 0


def _command14(
    context: UtilityExContext, comm: UtilityExComm, sub: int, first: int, second: int
) -> int:
    count = _state(context, f"abs14_count_{sub}")
    if count > 253:
        raise ValueError("ABS14 A8-derived field count exceeds its native byte length")
    status, reply = _reply(comm, bytes((0x30, sub, 0, first, second)) + bytes(count))
    if status == 0:
        if len(reply) == 2 and reply[1] == sub:
            return 0
        if sub != 3 and len(reply) == 3 and reply[1:] == bytes((sub, 0)):
            return 12
        return 3
    return status


def _end14(context: UtilityExContext, comm: UtilityExComm) -> int:
    _configure(context, comm, "native_rva:172d0", 150)
    try:
        status, reply = _reply(comm, b"\x30")
        return 3 if status == 0 and len(reply) != 1 else status
    finally:
        _configure(context, comm, "native_rva:172d0", 100)


def _wait14(context: UtilityExContext, start: int, delay: int) -> None:
    target = (start + delay) & 0xFFFFFFFF
    while not context.is_cancelled():
        if ((context.ticks() + 100) & 0xFFFFFFFF) < target:
            context.sleep(100)
        else:
            remaining = (target - context.ticks()) & 0xFFFFFFFF
            if remaining <= 100:
                context.sleep(remaining)
            return


def _drive14(selection: int, context: UtilityExContext, comm: UtilityExComm) -> int:
    if context.is_cancelled():
        return 99
    status = comm.initialize()
    if status:
        return status
    mask = (2, 8, 0x20, 0x80)[selection - 1]
    group = 1 if selection in (1, 4) else 2
    started = context.ticks()
    while not context.is_cancelled():
        poll = context.ticks()
        status = _command14(context, comm, 0x21, mask, mask)
        if status or context.is_cancelled():
            break
        if ((context.ticks() - started) & 0xFFFFFFFF) >= 4000:
            status = _command14(context, comm, 0x21, mask, 0)
            break
        _wait14(context, poll, 2000)
        if ((context.ticks() - started) & 0xFFFFFFFF) >= 4000:
            status = _command14(context, comm, 0x21, mask, 0)
            break
    if status == 0:
        while not context.is_cancelled():
            poll = context.ticks()
            status = _command14(context, comm, 0x22, group, group)
            if status:
                break
            _wait14(context, poll, 2000)
    return status


def _abs14(
    export: str,
    arguments: tuple[object, ...],
    context: UtilityExContext,
    comm: UtilityExComm,
) -> int:
    operation = export.removeprefix("Ex2ABS_14_")
    if operation in ("StartSolenoidDrive", "StopSolenoidDrive_VSC") and _uint(
        arguments[0]
    ) not in (1, 2, 3, 4):
        return 99
    try:
        if operation == "StartSolenoidDrive":
            return _drive14(_uint(arguments[0]), context, comm)
        status = comm.initialize()
        if status == 0:
            if operation == "GetDIDSupportInfo":
                return _support14(context, comm)
            if operation == "EndAirBleeding":
                return _end14(context, comm)
            if operation == "StopSolenoidDrive_VSC":
                group = 1 if arguments[0] in (1, 4) else 2
                status = _command14(context, comm, 0x22, group, 0)
            else:
                status = _command14(
                    context, comm, 3, 2, 2 if operation == "StartRelayDrive" else 0
                )
        if status and operation not in ("GetDIDSupportInfo", "EndAirBleeding"):
            _end14(context, comm)
        return status
    finally:
        comm.finalize()


def _frame50(
    comm: UtilityExComm,
    context: UtilityExContext,
    request: bytes,
    minimum: int,
    echo: int,
) -> tuple[int, bytes]:
    if context.is_cancelled():
        return 99, b""
    status, reply = _reply(comm, request)
    if status == 0 and (
        len(reply) < minimum or reply[1 : 1 + echo] != request[1 : 1 + echo]
    ):
        status = 3
    return status, reply


def _support50(context: UtilityExContext, comm: UtilityExComm) -> int:
    for request, minimum, echo, masks in (
        (b"\x22\x01\x01", 8, 2, ((5, 0x80), (7, 0x80))),
        (b"\x22\x10\0", 9, 2, ((8, 8),)),
        (b"\x22\x10\x2d", 16, 2, ((15, 0x40),)),
        (b"\x22\x20\0", 4, 2, ((3, 0x40),)),
        (b"\x22\x20\x02", 5, 2, ((3, 0x80),)),
        (b"\x31\x01\x10\x01", 7, 3, ((6, 0x40),)),
        (b"\x31\x01\x11\0", 18, 3, ((10, 8), (16, 4), (17, 0x80))),
    ):
        status, reply = _frame50(comm, context, request, minimum, echo)
        if status:
            return status
        if any(reply[offset] & mask != mask for offset, mask in masks):
            return 0x11F9
        if request == b"\x22\x20\x02":
            context.state["nk.chassis.abs50_cache"] = reply[3:]
    return 0


def _routine50(
    context: UtilityExContext,
    comm: UtilityExComm,
    sub: int,
    routine: int,
    data: bytes = b"",
) -> int:
    return _frame50(comm, context, bytes((0x31, sub, 0x11, routine)) + data, 4, 3)[0]


def _slm50(context: UtilityExContext, comm: UtilityExComm) -> int:
    status = _routine50(context, comm, 1, 0x66, b"\x02")
    if status:
        _routine50(context, comm, 2, 0x66)
        return 0x11FA
    started = context.ticks()
    while not context.is_cancelled():
        if ((context.ticks() - started) & 0xFFFFFFFF) > 29999:
            return 0x11FB
        context.sleep(1000)
        status, reply = _frame50(comm, context, b"\x22\x10\x2d", 17, 2)
        if status:
            return 0x11FE
        if not reply[16] & 0x40:
            return 0
    return 0


def _reset50(context: UtilityExContext, comm: UtilityExComm) -> int:
    modern = context.module_sha256 == NK_GTS_SHA256 and context.mode == 22
    cache_key = "nk.chassis.abs50_cache22" if modern else "nk.chassis.abs50_cache"
    if modern:
        status, reply = _frame50(comm, context, b"\x22\x20\x02", 5, 2)
        if status:
            return status
        if not reply[3] & 0x80:
            return 0x11F9
        context.state[cache_key] = reply[3:]
    cache = context.state.get(cache_key, b"")
    if not isinstance(cache, bytes) or len(cache) > 0x101D:
        raise ValueError("ABS50 cached native data must be bounded bytes")
    size = len(cache) + 3
    request = bytearray(b"\x2e\x20\x02" + cache).ljust(5, b"\0")
    request[4] = 0
    status, reply = _frame50(comm, context, bytes(request[:size]), 3, 2)
    if status == 0 and len(reply) != 3:
        status = 3
    if status:
        return status
    context.sleep(1000)
    status, reply = _frame50(comm, context, b"\x22\x20\x02", 5, 2)
    return status if status else 0x11FC if reply[4] & 0x80 else 0


def _abs50(
    export: str,
    arguments: tuple[object, ...],
    context: UtilityExContext,
    comm: UtilityExComm,
) -> int:
    operation = export.removeprefix("Ex2ABS_50_")
    try:
        if operation == "RearAirBleeding_Timeout":
            if not context.is_cancelled():
                _routine50(context, comm, 2, 0x69)
            return 0x11FD
        if operation == "EndExtendedSession":
            if not context.is_cancelled():
                comm.session(1, 1, stop_on_error=True)
            comm.finalize()
            return 0x11F8
        if operation == "SLM2Refresh":
            return 99 if context.is_cancelled() else _slm50(context, comm)
        status = 99
        if operation == "ConfSupportInfo":
            if not context.is_cancelled():
                if comm.initialize():
                    comm.finalize()
                    return 0x11FF
                if comm.session(3, 1, normal_first=True):
                    comm.finalize()
                    return 0x11F8
                status = _support50(context, comm)
                if status == 0:
                    status = 0x11F8 if comm.session(1, 1, stop_on_error=True) else 0
                    comm.finalize()
                    return status
            if status not in (0x11F8, 0x11FF):
                comm.session(1, 1, stop_on_error=True)
            comm.finalize()
            return status
        if operation == "VacuumFillingIncompleteFlagReset":
            if not context.is_cancelled():
                status = _reset50(context, comm)
            comm.session(1, 1, stop_on_error=True)
            comm.finalize()
            return status
        if not context.is_cancelled():
            if operation == "RearAirBleeding":
                if comm.initialize():
                    comm.finalize()
                    return 0x11FF
                if comm.session(3, 1, normal_first=True):
                    comm.finalize()
                    return 0x11F8
                _out(arguments[0])[:] = (4).to_bytes(4, "little")
                context.sleep(1000)
                status = _routine50(context, comm, 1, 0x69)
                if status == 0:
                    return 0x125D
                _routine50(context, comm, 2, 0x69)
                if status == 0x125D:
                    return status
                if status not in (0x11F8, 0x11FF):
                    comm.session(1, 1, stop_on_error=True)
                comm.finalize()
                return status
            if operation == "RearAirBleeding_Next_2":
                context.sleep(20000)
                context.sleep(1000)
                status = _routine50(context, comm, 1, 0x69)
                if status == 0:
                    return 0x125F
                _routine50(context, comm, 2, 0x69)
            elif operation == "ECBProhibitionControl":
                context.sleep(1000)
                status = _routine50(context, comm, 1, 0x35)
                if status == 0:
                    return 0
                _routine50(context, comm, 2, 0x35)
            else:
                ecb = operation == "ECBProhibitionControl_Next"
                status = _routine50(context, comm, 2, 0x35 if ecb else 0x69)
                if status == 0:
                    return 0x125C if ecb else 0x125E
            comm.session(1, 1, stop_on_error=True)
            retained = {
                "RearAirBleeding_Next_1": 0x125E,
                "RearAirBleeding_Next_2": 0x125F,
                "ECBProhibitionControl_Next": 0x125C,
            }
            if status == retained.get(operation):
                return status
        comm.finalize()
        return status
    except BaseException:
        comm.finalize()
        raise


def _record40(raw: bytes, offsets: tuple[int, ...], sub: int) -> tuple[int, bytes]:
    if not isinstance(raw, bytes) or not isinstance(offsets, tuple):
        raise TypeError("Native support snapshot requires immutable bytes and offsets")
    if len(raw) != 0x1020 or len(offsets) != 256:
        raise ValueError("Native ABS40 support requires 0x1020 bytes and 256 offsets")
    offset = _uint(offsets[sub])
    if offset == 0x1020:
        return 22, b""
    if offset + 2 > len(raw) or offset + 2 + raw[offset + 1] > len(raw):
        return 99, b""
    return 0, raw[offset + 2 : offset + 2 + raw[offset + 1]]


def _support40(context: UtilityExContext, comm: UtilityExComm) -> int:
    _configure(context, comm, "native_rva:172d0", 150)
    try:
        status = comm.refresh_support_cache(2)
        if status:
            return status
        snapshot = comm.cached_support(2)
        if snapshot is None:
            raise UnsupportedChassisOperation("Native support cache was not populated")
        raw, offsets = snapshot
        for sub, index, mask in (
            (0x21, 0, 255),
            (0x21, 1, 255),
            (0x22, 0, 15),
            (0x22, 1, 15),
        ):
            status, payload = _record40(raw, offsets, sub)
            if status or index >= len(payload) or payload[index] & mask != mask:
                return 1100
        return 0
    finally:
        _configure(context, comm, "native_rva:172d0", 100)


def _command40(context: UtilityExContext, comm: UtilityExComm, request: bytes) -> int:
    _configure(context, comm, "native_rva:172d0", 150)
    try:
        snapshot = comm.cached_support(2)
        if not isinstance(snapshot, tuple) or len(snapshot) != 2:
            raise UnsupportedChassisOperation(
                "ABS40 requires the selected profile's native support cache"
            )
        raw, offsets = snapshot
        if not isinstance(raw, bytes) or not isinstance(offsets, tuple):
            raise TypeError("ABS40 native support cache is invalid")
        status, mask = _record40(raw, offsets, request[1])
        if status:
            raise UnsupportedChassisOperation(
                "ABS40 selected subfunction has no native support record"
            )
        if len(request) > len(mask) + 3:
            return 82
        packed = bytearray(request[:3])
        for value, allowed in zip(request[3:], mask):
            if allowed:
                packed.append(value)
            elif value:
                return 82
        packed.extend(bytes(3 + sum(bool(value) for value in mask) - len(packed)))
        status, reply = _reply(comm, bytes(packed))
        if status == 0:
            if len(reply) == 2 and reply[1] == request[1]:
                return 0
            if len(reply) == 3 and reply[2] == 0:
                return 12
            return 3
        return status
    finally:
        _configure(context, comm, "native_rva:172d0", 100)


def _bleed40(
    arguments: tuple[object, ...], context: UtilityExContext, comm: UtilityExComm
) -> int:
    stage, stop = (_out(argument) for argument in arguments)
    index = (int.from_bytes(stage, "little") - 1) & 0xFFFFFFFF
    if index >= 25:
        return 0
    commands = (
        b"\x30\x22\x02\x03\x03",
        b"\x30\x22\x02\x0f\x0f",
        b"\x30\x21\x01\xff\xff",
        b"\x30\x21\x02\xff\0",
        b"\x30\x22\0\x0c\0",
        b"\x30\x22\0\x0f\0",
    )
    keepalive_tick = 0
    errors = 0

    def command(which: int, bit: int, add: bool = False) -> None:
        nonlocal errors
        if _command40(context, comm, commands[which]):
            errors = errors + bit if add else errors | bit

    def wait(start: int, hold: int) -> None:
        nonlocal keepalive_tick
        while True:
            if ((context.ticks() - keepalive_tick) & 0xFFFFFFFF) > 1499:
                keepalive_tick = context.ticks()
                command(1, 2)
            elapsed = (context.ticks() - start) & 0xFFFFFFFF
            if elapsed >= hold:
                return
            # Host yields in the native busy wait without changing due predicates.
            context.sleep(min(hold - elapsed, 1))

    while True:
        command(0, 1)
        keepalive_tick = context.ticks()
        command(1, 2)
        previous = 0
        for repetition in range(5):
            if repetition:
                wait(previous, 3000)
            command(2, 4)
            wait(context.ticks(), 1000)
            command(3, 8)
            previous = context.ticks()
        command(4, 16, True)
        command(0, 64, True)
        context.sleep(1500)
        command(0, 128, True)
        context.sleep(1500)
        command(5, 32, True)
        context.sleep(22000)
        if errors:
            return 1100 + errors
        stage[:] = ((int.from_bytes(stage, "little") + 1) & 0xFFFFFFFF).to_bytes(
            4, "little"
        )
        index += 1
        if int.from_bytes(stop, "little") == 1 or index >= 25:
            return 0


def _abs40(
    export: str,
    arguments: tuple[object, ...],
    context: UtilityExContext,
    comm: UtilityExComm,
) -> int:
    try:
        status = 99
        if not context.is_cancelled():
            status = comm.initialize()
            if status == 0:
                status = (
                    _support40(context, comm)
                    if export.endswith("GetSupportInfo")
                    else _bleed40(arguments, context, comm)
                )
        return status
    finally:
        comm.finalize()


def _buffer(value: object, size: int) -> bytearray:
    if not isinstance(value, bytearray) or len(value) < size:
        raise ValueError(
            f"UtilityEx native structure requires at least {size} writable bytes"
        )
    return value


def _key31_state(mode: int, data: bytes, previous: list[int]) -> int:
    # 3d080..3d160: 3199 means keep polling; 3109 is a wrong mode result.
    if mode == 2:
        return 3199 if data[1] & 0x40 == 0 and data[1] & 0x20 else 0
    if mode == 6:
        return 0 if data[2] & 0x80 else 3199
    if mode not in (3, 4, 5, 7):
        return 0
    if data[0] & 0xC0 != 0x40:
        return 3109
    if mode == 3:
        return 3199 if data[1] & 0x40 else 0
    if mode == 5:
        return 3199
    if mode == 4:
        value = data[4] >> 4
        value = value if value <= 5 else 0
        if previous[0] < value:
            return 0
        previous[0] = value
    else:
        value = data[2] & 15
        value = value if value <= 5 else 0
        if value < previous[1]:
            return 0
        previous[1] = value
    return 3199


def _key31(
    export: str,
    arguments: tuple[object, ...],
    context: UtilityExContext,
    comm: UtilityExComm,
) -> int:
    if export.endswith("GetSupportInfo"):
        try:
            if comm.initialize():
                return 3103
            return _smart_support(comm, True)
        finally:
            comm.finalize()
    if export.endswith(("NoChk", "NoChkOnce")):
        return _end32(context, comm)
    structure = _buffer(arguments[0], 13 if export.endswith("GetTheKeyStatus") else 4)
    flag = int.from_bytes(structure[:4], "little")
    if export.endswith("RequestKeyCodeRegistration"):
        try:
            if flag and comm.initialize():
                status = 3103
            else:
                # 3d260 only checks echo; no native minimum-length predicate.
                status, reply = _reply(comm, b"\xa5\xb6\x40" + bytes(5))
                status = 3107 if status or reply.ljust(2, b"\0")[1] != 0xB6 else 0
            if status:
                comm.finalize()
            return status
        except BaseException:
            comm.finalize()
            raise
    if export.endswith("TerminateKeyCodeRegistration"):
        try:
            status, reply = _reply(comm, b"\xa5\xb6" + bytes(6))
            status = 3108 if status or reply.ljust(2, b"\0")[1] != 0xB6 else 0
            if flag or status:
                comm.finalize()
            return status
        except BaseException:
            comm.finalize()
            raise
    close = int.from_bytes(structure[4:8], "little")
    mode = structure[8]
    status = 99
    data = bytes(6)
    previous = [255, 0]
    try:
        if flag == 1:
            if comm.initialize():
                if close:
                    comm.finalize()
                return 3103
            status = 0
        if not context.is_cancelled():
            while True:
                status, reply = _checked(comm, b"\x21\x21", 8)
                data = reply[2:8] if status == 0 else bytes(6)
                if status:
                    status = 3105 if mode == 1 else 3104
                    break
                status = _key31_state(mode, data, previous)
                if status != 3199 or context.is_cancelled():
                    break
        values = (data[5] >> 4, data[2] & 15, data[4] >> 4)
        structure[9:12] = bytes(value if value <= 5 else 0 for value in values)
        structure[12] = data[1] >> 2 & 1
        if status == 3105 or (status != 3104 and close):
            comm.finalize()
        return status
    except BaseException:
        comm.finalize()
        raise


def _key_observation(
    comm: UtilityExComm, context: UtilityExContext
) -> tuple[int, tuple[int, int, int, int]]:
    # 3a980: four outputs; decompilation callers often hide three stack pointers.
    _address(comm, context)
    status, reply = _reply(comm, b"\x21\xe5")
    if status:
        return status, (0, 0, 0, 0)
    if len(reply) < 4 or reply[1] != 0xE5:
        return 3, (0, 0, 0, 0)
    return 0, (reply[2] & 7, reply[3] & 3, (reply[2] >> 4) & 1, (reply[3] >> 4) & 1)


def _address(comm: UtilityExComm, context: UtilityExContext) -> None:
    # 16f00(0x40,0) is a selected address plus extended address, not a protocol.
    _configure(context, comm, "native_global:1517f0", 0x40)
    _configure(context, comm, "native_global:1517f4", 0)


def _get_entry(
    family: str,
    arguments: tuple[object, ...],
    context: UtilityExContext,
    comm: UtilityExComm,
) -> int:
    first, second = (_out(argument) for argument in arguments)
    _address(comm, context)
    try:
        status = comm.initialize()
        if status:
            return status
        status, (master, sub, _, _) = _key_observation(comm, context)
        if status == 0:
            first[:] = master.to_bytes(4, "little")
            second[:] = sub.to_bytes(4, "little")
            _save(context, "master_count", master)
            _save(context, "sub_count", sub)
            if master > 5 or (family == "03" and sub > 2):
                return 103
        return status
    finally:
        comm.finalize()


def _mode(entry: bool, context: UtilityExContext, comm: UtilityExComm) -> int:
    # 3ad20/3b240: successful entry retains comm for subsequent checks.
    _address(comm, context)
    try:
        status = comm.initialize() if entry else 0
        if status == 0:
            status, reply = _reply(comm, bytes((0xA5, 0xB2, 0x20 if entry else 0)))
            if entry:
                _save(context, "entry_tick", context.ticks())
            if status == 0 and (len(reply) != 2 or reply[1] != 0xB2):
                status = 3
        if status or not entry:
            comm.finalize()
        return status
    except BaseException:
        comm.finalize()
        raise


def _since_entry(context: UtilityExContext) -> None:
    # Literal 14b60 unsigned comparisons preserve GetTickCount wrap behavior.
    target = (_state(context, "entry_tick") + 110) & 0xFFFFFFFF
    while not context.is_cancelled():
        now = context.ticks() & 0xFFFFFFFF
        if ((now + 30) & 0xFFFFFFFF) < target:
            context.sleep(30)
        else:
            remaining = (target - (context.ticks() & 0xFFFFFFFF)) & 0xFFFFFFFF
            if remaining <= 30:
                context.sleep(remaining)
            return


def _smart_poll(
    family: str,
    operation: str,
    arguments: tuple[object, ...],
    context: UtilityExContext,
    comm: UtilityExComm,
) -> int:
    master_check = operation == "MasterKeyCheck"
    try:
        if master_check or _uint(arguments[0]) & 255 == 1:
            _since_entry(context)
        while not context.is_cancelled():
            status, (master, sub, master_flag, sub_flag) = _key_observation(
                comm, context
            )
            observed = context.ticks() & 0xFFFFFFFF
            if status:
                if not context.is_cancelled():
                    comm.finalize()
                return status
            if master_check:
                if sub_flag == 0:
                    return 0
            else:
                status = 0
                if family == "03":
                    if master > 5 or sub > 2:
                        status = 103
                    elif master < 5 and sub < 2 and master_flag == 1:
                        status = 100
                    elif master == 5 and sub == 2:
                        status = 101
                    elif master > _state(context, "master_count") or sub > _state(
                        context, "sub_count"
                    ):
                        status = 102
                elif _uint(arguments[1]) == 0x6C:
                    if master > 5:
                        status = 103
                    elif master < 5 and master_flag == 1:
                        status = 100
                    elif master == 5:
                        status = 101
                    elif master > _state(context, "master_count"):
                        status = 102
                elif master_flag == 1:
                    status = 104
                if status:
                    if status == 103:
                        comm.finalize()
                    return status
            elapsed = ((context.ticks() & 0xFFFFFFFF) - observed) & 0xFFFFFFFF
            period = 35 if master_check else 40
            if elapsed < period:
                context.sleep(period - elapsed)
        return 0
    except BaseException:
        comm.finalize()
        raise


def _erase_mode(comm: UtilityExComm, entry: bool, context: UtilityExContext) -> int:
    _address(comm, context)
    status, reply = _reply(comm, bytes((0xA5, 0xB3, 0xC0 if entry else 0)))
    if status == 0 and (len(reply) != 2 or reply[1] != 0xB3):
        return 3
    return status


def _erase(
    operation: str,
    arguments: tuple[object, ...],
    context: UtilityExContext,
    comm: UtilityExComm,
) -> int:
    # 18 NK 3a980,3aae0,3b650,3b7a0 and exported df60..e1a0 wrappers.
    if operation == "EraseGetKey":
        first, second = (_out(argument) for argument in arguments)
        _address(comm, context)
        try:
            status = comm.initialize()
            if status == 0:
                status, (master, sub, _, _) = _key_observation(comm, context)
                if status == 0:
                    first[:] = master.to_bytes(4, "little")
                    second[:] = sub.to_bytes(4, "little")
            return status
        finally:
            comm.finalize()
    if operation == "EraseCheck":
        try:
            return _key_observation(comm, context)[0]
        finally:
            comm.finalize()
    if operation in ("EraseModeEntry", "EraseModeEnd"):
        try:
            if operation == "EraseModeEntry":
                _address(comm, context)
                status = comm.initialize()
                if status:
                    comm.finalize()
                    return status
            status = _erase_mode(comm, operation == "EraseModeEntry", context)
            if status:
                comm.finalize()
            return status
        except BaseException:
            comm.finalize()
            raise
    observed = False
    status = 0
    _configure(context, comm, "native_rva:172d0", 0xFFFFFFFF)
    try:
        while not context.is_cancelled():
            if operation == "EraseKeyStatus" and _state(context, "progress_timeout"):
                break
            started = context.ticks() & 0xFFFFFFFF
            status, (master, sub, _, sub_flag) = _key_observation(comm, context)
            if status:
                break
            observed = True
            if operation == "EraseModeStatus" and sub_flag == 0:
                break
            if operation == "EraseKeyStatus" and master == 1 and sub == 0:
                break
            elapsed = ((context.ticks() & 0xFFFFFFFF) - started) & 0xFFFFFFFF
            if elapsed < 100:
                context.sleep(100 - elapsed)
    except BaseException:
        comm.finalize()
        raise
    finally:
        _configure(context, comm, "native_rva:172d0", 100)
    if operation == "EraseModeStatus":
        if context.is_cancelled() and not observed:
            status = 8
        if status and not context.is_cancelled():
            comm.finalize()
    else:
        try:
            if _state(context, "progress_timeout"):
                status = _erase_mode(comm, False, context) if observed else 8
                if status == 0:
                    status = 103
            elif status == 0:
                status = _erase_mode(comm, False, context)
        except BaseException:
            comm.finalize()
            raise
        finally:
            _save(context, "progress_timeout", 0)
        if status:
            comm.finalize()
    # Native worker cleanup precedes the exported wrapper's separate close.
    if status != 15:
        comm.finalize()
    return status


def _support63(context: UtilityExContext, comm: UtilityExComm, output: object) -> int:
    try:
        if context.is_cancelled():
            return 99
        status = comm.initialize()
        if status:
            return status
        if comm.session(3, 1, normal_first=True):
            return 6398
        optional = False
        for index, (request, minimum, offset, mask) in enumerate(
            (
                (b"\x22\x01\x01", 6, 5, 0x40),
                (b"\x22\x11\x00", 4, 3, 0x80),
                (b"\x31\x01\x10\x01", 7, 6, 2),
                (b"\x31\x01\x16\x00", 5, 4, 0x20),
            )
        ):
            status, reply = _request50(context, comm, request, minimum)
            if status == 0 and reply[offset] & mask != mask:
                status = 6399
            if status:
                _short_normal50(context, comm)
                return status
            if index == 0:
                optional = bool(reply[5] & 0x80)
        value = 6350
        if optional:
            status, reply = _request50(context, comm, b"\x22\x10\x00", 6)
            if status:
                _short_normal50(context, comm)
                return status
            value += int(bool(reply[5] & 0x40))
        _out(output)[:] = value.to_bytes(4, "little")
        return 6398 if comm.session(1, 1, stop_on_error=True) else 0
    finally:
        comm.finalize()


def _poll63(context: UtilityExContext, comm: UtilityExComm) -> int:
    status, reply = _request50(context, comm, b"\x22\x11\x01", 24)
    if status or reply[5]:
        return status
    if reply[9]:
        return 6301
    if reply[13]:
        return 6302 if reply[22] else 6305
    if reply[14]:
        return 6303
    return 6306 if reply[22] else 6305


def _smrt63(
    export: str,
    arguments: tuple[object, ...],
    context: UtilityExContext,
    comm: UtilityExComm,
) -> int:
    operation = export.removeprefix("Ex2SMRT_63_")
    if operation == "EndExtendSession":
        _close50(context, comm)
        return 0
    if operation == "StartKeepAlive":
        status = comm.initialize()
        return status if status else comm.keepalive(True)
    if operation == "GetSupportInfo":
        return _support63(context, comm, arguments[0])
    if operation == "StartKeyErasure":
        if context.is_cancelled():
            return 99
        try:
            status, _ = _request50(context, comm, b"\x31\x01\x16\x03", 4)
        except BaseException:
            comm.finalize()
            raise
        if status:
            _close50(context, comm)
        return status
    counter = _out(arguments[0])
    status = 99
    try:
        if not context.is_cancelled():
            while True:
                status = _poll63(context, comm)
                if status and not context.is_cancelled():
                    break
                if int.from_bytes(counter, "little") >= 960:
                    status = 6304
                    break
                if status == 0:
                    context.sleep(1)
                if context.is_cancelled():
                    break
        if status:
            if status not in (6301, 6302, 6303, 6305, 6306):
                _stop50key(comm)
            _close50(context, comm)
        return status
    except BaseException:
        comm.finalize()
        raise


def _request50(
    context: UtilityExContext, comm: UtilityExComm, request: bytes, minimum: int
) -> tuple[int, bytes]:
    if context.is_cancelled():
        return 99, b""
    status, reply = comm.exchange(request)
    if status == 0 and (len(reply) < minimum or reply[1 : len(request)] != request[1:]):
        status = 3
    return status, reply


def _short_normal50(context: UtilityExContext, comm: UtilityExComm) -> None:
    try:
        _configure(context, comm, "native_rva:18840", 1)
        comm.session(1, 1)
    finally:
        _configure(context, comm, "native_rva:18840", 0)


def _global_byte(context: UtilityExContext, key: str) -> int:
    value = context.state.get(key, 0)
    if type(value) is not int or not 0 <= value <= 255:
        raise ValueError("SMRT55 native global must be a BYTE")
    return value


def _request55(
    context: UtilityExContext,
    comm: UtilityExComm,
    request: bytes,
    minimum: int,
    echo_bytes: int,
    *,
    cancelled_status: int = 99,
) -> tuple[int, bytes]:
    if context.is_cancelled():
        return cancelled_status, b""
    status, reply = comm.exchange(request)
    if status == 0 and (
        len(reply) < minimum or reply[1 : 1 + echo_bytes] != request[1 : 1 + echo_bytes]
    ):
        return 3, reply
    return status, reply


def _extended55(comm: UtilityExComm) -> int:
    return comm.session(3, 1, normal_first=True)


def _normal55(comm: UtilityExComm) -> int:
    return comm.cleanup_session(1, 1, stop_on_error=True)


def _short_normal55(context: UtilityExContext, comm: UtilityExComm) -> None:
    primary: BaseException | None = None
    try:
        _configure(context, comm, "native_rva:18840", 1)
        comm.cleanup_session(1, 1, stop_on_error=True)
    except BaseException as error:  # noqa: BLE001
        primary = error
    try:
        _configure(context, comm, "native_rva:18840", 0)
    except BaseException as error:
        if primary is not None:
            raise primary from error
        raise
    if primary is not None:
        raise primary


def _read_flags55(
    context: UtilityExContext,
    comm: UtilityExComm,
    key_a: str,
    key_b: str,
) -> int:
    status, reply = _request55(context, comm, b"\x22\x20\x27", 7, 2)
    if status == 0:
        context.state[key_a] = reply[3]
        context.state[key_b] = reply[5]
    return status


def _write_flags55(
    context: UtilityExContext,
    comm: UtilityExComm,
    value: int,
    selector: int,
    byte_a: int,
    byte_b: int,
) -> int:
    x, y = (value, 0) if selector == 0 else (0, value)
    request = bytes((0x2E, 0x20, 0x27, byte_a, x, byte_b, y))
    return _request55(context, comm, request, 3, 2)[0]


def _smrt55_chk(arguments: tuple[object, ...], context: UtilityExContext) -> int:
    bit, selector = (_uint(value) & 255 for value in arguments)
    if selector == 0:
        if bit not in (1, 2, 4, 8, 16, 32, 64, 128):
            return 99
        key = _SMRT55_SOURCE[context.module_sha256][2]
    elif selector == 2:
        if bit not in (4, 8, 16, 32, 64, 128):
            return 99
        key = _SMRT55_SOURCE[context.module_sha256][3]
    else:
        return 22
    return 0 if _global_byte(context, key) & bit else 22


def _smrt55(
    export: str,
    arguments: tuple[object, ...],
    context: UtilityExContext,
    comm: UtilityExComm,
) -> int:
    operation = export.removeprefix("Ex2SMRT_55_")
    _, pointer_key, key_a, key_b = _SMRT55_SOURCE[context.module_sha256]
    retained = False
    closed = False

    def close() -> None:
        nonlocal closed
        if not closed:
            closed = True
            comm.finalize()

    primary: BaseException | None = None
    try:
        if operation == "ConfirmDIDRIDSupport":
            status = 99 if context.is_cancelled() else comm.initialize()
            if status == 0:
                status = _extended55(comm)
                if status:
                    status = 199
                else:
                    status, reply = _request55(context, comm, b"\x22\x01\x01", 8, 2)
                    if status == 0 and not reply[7] & 0x80:
                        status = 101
                    if status == 0:
                        # The native worker rereads this global after probe one.
                        output = context.state.get(pointer_key)
                        status, reply = _request55(context, comm, b"\x22\x20\x00", 8, 2)
                        if status == 0 and not reply[7] & 0x02:
                            status = 101
                        elif status == 0 and reply[7] & 0x01:
                            _out(output)[:] = (1).to_bytes(4, "little")
                    if status == 0:
                        status, reply = _request55(
                            context, comm, b"\x31\x01\x10\x01", 7, 3
                        )
                        if status == 0 and not reply[6] & 0x04:
                            status = 102
                    if status == 0:
                        status, reply = _request55(
                            context, comm, b"\x31\x01\x15\x00", 5, 3
                        )
                        if status == 0 and not reply[4] & 0x80:
                            status = 102
                if status == 0:
                    status = 0 if _normal55(comm) == 0 else 199
                elif status != 199:
                    _short_normal55(context, comm)
            elif status != 199:
                _short_normal55(context, comm)
            return status

        if operation == "GetKeyDiagInfo":
            status = 0
            if not context.is_cancelled():
                status = comm.initialize()
                if status == 0:
                    status = _extended55(comm)
                    if status:
                        status = 199
                    else:
                        context.state[key_a] = 0
                        context.state[key_b] = 0
                        status = _read_flags55(context, comm, key_a, key_b)
            if status == 199:
                return status
            if status:
                _short_normal55(context, comm)
                return status
            return 0 if _normal55(comm) == 0 else 199

        if operation in ("SetKeyDiag", "SetKeyDiag2"):
            value = _uint(arguments[0]) & 255
            second = _uint(arguments[1]) & 255 if operation == "SetKeyDiag2" else 0
            selector = _uint(arguments[2 if operation == "SetKeyDiag2" else 1]) & 255
            # Native wrapper code loads B before A; an interleaved GetInfo may
            # publish a new A/B pair between these two independent BYTE reads.
            byte_b = _global_byte(context, key_b)
            byte_a = _global_byte(context, key_a)
            status = 99 if context.is_cancelled() else comm.initialize()
            if status == 0:
                status = _extended55(comm)
                if status:
                    status = 199
                else:
                    context.sleep(100)
                    status = _write_flags55(
                        context, comm, value, selector, byte_a, byte_b
                    )
                    if status == 0 and operation == "SetKeyDiag2":
                        context.sleep(100)
                        status, _ = _request55(
                            context, comm, bytes((0x2E, 0x20, 0x28, second)), 3, 2
                        )
                    if status == 0:
                        context.sleep(100)
                        status, _ = _request55(context, comm, b"\x31\x01\x15\x01", 4, 3)
                        if status == 0:
                            retained = True
                            return 0
            if status != 199:
                _short_normal55(context, comm)
            return status

        if operation == "TermKeyDiag":
            status = 199
            if not context.is_cancelled():
                stop_status, _ = _request55(
                    context,
                    comm,
                    b"\x31\x02\x15\x01",
                    4,
                    3,
                    cancelled_status=0,
                )
                if stop_status == 0:
                    status = 0 if _normal55(comm) == 0 else 199
                else:
                    _short_normal55(context, comm)
            else:
                _short_normal55(context, comm)
            return status

        if operation == "TermKeyDiag2":
            if not context.is_cancelled():
                _request55(
                    context,
                    comm,
                    b"\x31\x02\x15\x01",
                    4,
                    3,
                    cancelled_status=0,
                )
            _short_normal55(context, comm)
            return 199
        raise UnsupportedChassisOperation(f"Unrecovered SMRT55 operation: {operation}")
    except BaseException as error:
        primary = error
        raise
    finally:
        if not retained and not closed:
            try:
                close()
            except BaseException as cleanup_error:
                if primary is not None:
                    raise primary from cleanup_error
                raise


def _close50(context: UtilityExContext, comm: UtilityExComm) -> None:
    try:
        _short_normal50(context, comm)
    finally:
        comm.finalize()


def _support50key(
    context: UtilityExContext, comm: UtilityExComm, output: object
) -> int:
    try:
        if context.is_cancelled():
            return 99
        status = comm.initialize()
        if status:
            return status
        if comm.session(3, 1, normal_first=True):
            return 5098
        optional = False
        for index, (request, minimum, offset, mask) in enumerate(
            (
                (b"\x22\x01\x01", 6, 5, 0x40),
                (b"\x22\x11\x00", 4, 3, 0x80),
                (b"\x31\x01\x10\x01", 7, 6, 2),
                (b"\x31\x01\x16\x00", 5, 4, 0x20),
            )
        ):
            status, reply = _request50(context, comm, request, minimum)
            if status == 0 and reply[offset] & mask != mask:
                status = 5099
            if status:
                _short_normal50(context, comm)
                return status
            if index == 0:
                optional = bool(reply[5] & 0x80)
        value = 5050
        if optional:
            status, reply = _request50(context, comm, b"\x22\x10\x00", 6)
            if status:
                _short_normal50(context, comm)
                return status
            value += int(bool(reply[5] & 0x40))
        _out(output)[:] = value.to_bytes(4, "little")
        return 5098 if comm.session(1, 1, stop_on_error=True) else 0
    finally:
        comm.finalize()


def _poll50key(context: UtilityExContext, comm: UtilityExComm) -> int:
    status, reply = _request50(context, comm, b"\x22\x11\x01", 24)
    if status or reply[5]:
        return status
    if reply[9]:
        return 5001
    if not reply[13] and reply[14]:
        return 5003
    return 5002 if reply[22] else 5005


def _stop50key(comm: UtilityExComm) -> None:
    # Native stop has no cancellation guard and its parsed result is discarded.
    comm.exchange(b"\x31\x02\x16\x03")


def _smrt50(
    export: str,
    arguments: tuple[object, ...],
    context: UtilityExContext,
    comm: UtilityExComm,
) -> int:
    operation = export.removeprefix("Ex2SMRT_50_")
    if operation == "EndExtendSession":
        _close50(context, comm)
        return 0
    if operation == "StartKeepAlive":
        status = comm.initialize()
        return status if status else comm.keepalive(True)
    if operation == "GetSupportInfo":
        return _support50key(context, comm, arguments[0])
    if operation == "StartKeyErasure":
        if context.is_cancelled():
            return 99
        try:
            status, _ = _request50(context, comm, b"\x31\x01\x16\x03", 4)
        except BaseException:
            comm.finalize()
            raise
        if status:
            _close50(context, comm)
        return status
    status = 99
    try:
        if not context.is_cancelled():
            while True:
                status = _poll50key(context, comm)
                if status and not context.is_cancelled():
                    break
                if status == 0:
                    context.sleep(1)
                if context.is_cancelled():
                    break
        if status:
            if status not in (5001, 5002, 5003, 5005):
                _stop50key(comm)
            _close50(context, comm)
        if context.is_cancelled():
            _stop50key(comm)
            _close50(context, comm)
        return status
    except BaseException:
        comm.finalize()
        raise


def _fields53(context: UtilityExContext, operation: str) -> tuple[int, int]:
    online, follow, send, flag = {
        NK18_SHA256: (0x1014A508, 0x1014A6D0, 0x1014A520, 0x10164C50),
        NK_DS4_SHA256: (0x101B1A04, 0x101B1A18, 0x101B1A24, 0x101CFEC8),
        NK_GTS_SHA256: (0x101BCB04, 0x101BCB18, 0x101BCB24, 0x101E87F8),
    }[context.module_sha256]
    return (
        online
        if operation == "Online_Certification"
        else follow
        if operation.endswith("007")
        else send
    ), flag


def _wire53(
    context: UtilityExContext, comm: UtilityExComm, request: bytes, minimum: int
) -> tuple[int, bytes]:
    if context.is_cancelled():
        return 99, b""
    status, reply = comm.exchange(request)
    if status == 0 and (len(reply) < minimum or reply[1 : len(request)] != request[1:]):
        status = 3
    return status, reply


def _challenge53(
    context: UtilityExContext, comm: UtilityExComm, first: object, second: object
) -> int:
    status, reply = _wire53(context, comm, b"\x22\xf1\x8c", 21)
    if status:
        return status
    _buffer(first, 8)[:8] = reply[13:21]
    status, reply = _wire53(context, comm, b"\x27\x09", 8)
    if status == 0:
        _buffer(second, 6)[:6] = reply[2:8]
    return status


def _auth53(context: UtilityExContext, comm: UtilityExComm) -> tuple[int, bool]:
    for request, minimum, predicates in (
        (b"\x22\x01\x01", 34, ((5, 0x40), (33, 0x40))),
        (b"\x22\x11\x00", 4, ((3, 0x40),)),
        (b"\x22\xf1\x00", 21, ((20, 0x10),)),
        (b"\x22\x11\x02", 9, ()),
    ):
        status, reply = _wire53(context, comm, request, minimum)
        if status:
            return status, not predicates and status == 101
        if not predicates:
            return (0, False) if reply[8] == 1 else (101, True)
        if any(reply[index] & mask != mask for index, mask in predicates):
            return 109, False
    return 0, False


def _smrt53(export: str, context: UtilityExContext, comm: UtilityExComm) -> int:
    operation = export.removeprefix("Ex2SMRT_53_")
    base, flag = _fields53(context, operation)
    fields = tuple(
        context.state.get(f"native_global:{base + index * 4:08x}", 0)
        for index in range(5 if operation == "Online_Certification" else 3)
    )
    retained = False
    flag_key = f"native_global:{flag:08x}"
    try:
        if context.is_cancelled():
            return 99
        if operation == "SendTheKey":
            payload = _input41(fields[0], _uint(fields[2]), 0x101E)
            if context.is_cancelled():
                return 99
            status, reply = comm.exchange(b"\x27\x0a" + payload)
            if status == 0 and (len(reply) < 2 or reply[1] != 10):
                status = 4007
            if status not in (0, 4007):
                _out(fields[1])[:] = (4001).to_bytes(4, "little")
            return status
        if operation.endswith("007"):
            status = _challenge53(context, comm, fields[1], fields[2])
            if status == 0:
                retained = True
            else:
                _out(fields[0])[:] = (4001).to_bytes(4, "little")
            return status
        if _uint(fields[4]) != 0x1C2:
            comm.configure_target(0, 0xB5, 0, 0, 0)
            context.state[flag_key] = 1
        status = comm.initialize()
        if status == 0:
            status = comm.session(3, 1, normal_first=True)
            if status:
                _out(fields[0])[:] = (4005).to_bytes(4, "little")
            else:
                status, state_error = _auth53(context, comm)
                if status == 0:
                    if _uint(fields[1]) != 1:
                        retained = True
                        return 4006
                    status = _challenge53(context, comm, fields[2], fields[3])
                    state_error = False
                    if status == 0:
                        retained = True
                        return 0
                _out(fields[0])[:] = (4003 if state_error else 4001).to_bytes(
                    4, "little"
                )
        if status == 4006:
            retained = True
        return status
    finally:
        if not retained:
            comm.finalize()
            if context.state.get(flag_key, 0) == 1:
                comm.configure_target(0, 0, 0, 0, 0)


_SUPPORT56 = (
    (b"\x22\x01\x01", 6, 5, 0x80, 6001),
    (b"\x22\x10\x00", 6, 5, 0x40, 6002),
    (b"\x31\x01\x10\x01", 7, 6, 1, 6003),
    (b"\x31\x01\x17\x00", 5, 4, 0x80, 6004),
)


def _request56(
    comm: UtilityExComm, request: bytes, minimum: int = 4
) -> tuple[int, bytes]:
    status, reply = comm.exchange(request)
    if status == 0 and (len(reply) < minimum or reply[1 : len(request)] != request[1:]):
        status = 3
    return status, reply


def _smrt56(
    export: str,
    arguments: tuple[object, ...],
    context: UtilityExContext,
    comm: UtilityExComm,
) -> int:
    operation = export.removeprefix("Ex2SMRT_56_")
    retained = False
    try:
        if operation == "EndExtendedSession":
            if not context.is_cancelled():
                if arguments[0] == 1:
                    status = comm.initialize()
                    if status:
                        return status
                comm.session(1, 1, stop_on_error=True)
            return 0
        if operation == "TerminateFingerprintMode":
            if not context.is_cancelled():
                _request56(comm, b"\x31\x02\x17\x01")
            comm.session(1, 1, stop_on_error=True)
            return 6005
        status = 99 if context.is_cancelled() else comm.initialize()
        if operation == "StartFingerprintMode":
            if status == 0:
                comm.keepalive(True)
                status, _ = _request56(comm, b"\x31\x01\x17\x01")
                if status == 0:
                    retained = True
                    return 0
            comm.session(1, 1, stop_on_error=True)
            return status
        if status == 0:
            if comm.session(3, 1, normal_first=True):
                return 6000
            for request, minimum, index, mask, unsupported in _SUPPORT56:
                status, reply = _request56(comm, request, minimum)
                if status:
                    break
                if reply[index] & mask != mask:
                    status = unsupported
                    break
            if status == 0:
                return 6000 if comm.session(1, 1, stop_on_error=True) else 0
        if status != 6000:
            comm.session(1, 1, stop_on_error=True)
        return status
    finally:
        if not retained:
            comm.finalize()


def _request58(context: UtilityExContext, comm: UtilityExComm, sub: int) -> int:
    if context.is_cancelled():
        return 99
    request = bytes((0x31, sub, 0x13, 5))
    status, reply = comm.exchange(request)
    if sub == 2:
        return status
    if status:
        return 3 if sub == 3 else status
    if len(reply) < (5 if sub == 3 else 4) or reply[1:4] != request[1:]:
        return 3
    if sub == 1:
        return 0
    return 5802 if reply[4] <= 1 else 0 if reply[4] == 2 else 5803


def _smrt58(export: str, context: UtilityExContext, comm: UtilityExComm) -> int:
    try:
        if context.is_cancelled():
            return 99
        status = comm.initialize()
        if status:
            return status
        comm.keepalive(True)
        if export.endswith("EndExtendedSession"):
            comm.session(1, 1)
            return 0
        status = _request58(context, comm, 1)
        if status:
            comm.session(1, 1)
            return 5800
        started = context.ticks()
        while not context.is_cancelled():
            _sleep03(context, 50)
            status = _request58(context, comm, 3)
            if status != 5802:
                if status:
                    _request58(context, comm, 2)
                    status = 5801
                break
            if (context.ticks() - started) & 0xFFFFFFFF >= 30000:
                _request58(context, comm, 2)
                status = 5801
                break
        comm.session(1, 1)
        return status
    finally:
        comm.finalize()


def _wire48(
    context: UtilityExContext, comm: UtilityExComm, request: bytes, *, classic: bool
) -> tuple[int, bytes]:
    if classic:
        _configure(context, comm, "native_rva:172d0", 150)
    try:
        return (99, b"") if context.is_cancelled() else comm.exchange(request)
    finally:
        if classic:
            _configure(context, comm, "native_rva:172d0", 100)


def _vin_read48(
    context: UtilityExContext,
    comm: UtilityExComm,
    output: bytearray,
    request: bytes,
    *,
    classic: bool,
) -> int:
    status, reply = _wire48(context, comm, request, classic=classic)
    if status:
        return status
    expected = b"\x02\x01" if request == b"\x09\x02" else request[1:]
    if len(reply) < 4 or reply[1:3] != expected:
        return 3
    copied = reply[3:20]
    output[: len(copied)] = copied
    return 4802


def _vin_classic48(
    context: UtilityExContext, comm: UtilityExComm, output: bytearray
) -> int:
    target = comm.read_target()
    override = {
        NK18_SHA256: 0x1014AE60,
        NK_DS4_SHA256: 0x101B66D8,
        NK_GTS_SHA256: 0x101C1818,
    }[context.module_sha256]
    try:
        if context.is_cancelled():
            return 99
        for index, (profile, identifier) in enumerate(
            ((0xEA, 0x7E0), (0x147, 0x7D2), (0xEC, 0x7E2))
        ):
            if index:
                comm.finalize()
            _configure(context, comm, "native_rva:170a0", override)
            _configure(context, comm, "native_rva:170b0", profile)
            comm.select_target(identifier, 0)
            if comm.initialize():
                return 14
            status, reply = _wire48(context, comm, b"\x3e", classic=True)
            if status == 0 and len(reply) == 1:
                status = _vin_read48(context, comm, output, b"\x09\x02", classic=True)
                return 4802 if status == 4802 else 4803
        return 4803
    finally:
        comm.finalize()
        _configure(context, comm, "native_rva:170a0", 0)
        _configure(context, comm, "native_rva:170b0", 0)
        comm.select_target(*target)


_VIN48_PARAMETERS = (
    (0x10106, 0x3FC),
    (0x1010A, 0),
    (0x10105, 0),
    (0x10103, 0x300000),
    (1, 500000),
    (0x2A, 0),
)


def _vin_fixed48(
    context: UtilityExContext, comm: UtilityExComm, output: bytearray
) -> int:
    saved = context.native_parameter(0xAB)
    context.set_parameter(0xAB, 0)
    context.write_parameters()
    context.refresh_parameters()

    def configure(first: int, third: int = 0, fifth: int = 0) -> None:
        comm.configure_target(first, 0, third, 500000, fifth)
        comm.configure_parameters(_VIN48_PARAMETERS)

    try:
        if context.is_cancelled():
            return 99
        configure(0x700)
        comm.select_protocol(0x10)
        if comm.initialize():
            return 14
        status, reply = _wire48(context, comm, b"\x3e\x00", classic=False)
        comm.finalize()
        if status == 0 and len(reply) == 2 and reply[1] == 0:
            configure(0x700, 0x7DF, 0x7E0)
            if comm.select_diagnostic_mode(3):
                return 4805
            if comm.initialize():
                return 14
            if _vin_read48(context, comm, output, b"\x09\x02", classic=False) == 4802:
                return 4802
            comm.finalize()
            configure(0x700, 0x7DF, 0x7E0)
            if comm.initialize():
                return 14
            status = _vin_read48(context, comm, output, b"\x22\xf8\x02", classic=False)
        else:
            configure(0x7D2)
            if comm.select_diagnostic_mode(1):
                return 4805
            if comm.initialize():
                return 14
            status, reply = _wire48(context, comm, b"\x3e\x00", classic=False)
            if status or len(reply) != 2 or reply[1] != 0:
                return 4801
            status = _vin_read48(context, comm, output, b"\x22\xf1\x90", classic=False)
        return 4802 if status == 4802 else 4803
    finally:
        comm.finalize()
        comm.select_protocol(0)
        comm.select_diagnostic_mode(1)
        context.set_parameter(0xAB, saved)
        context.write_parameters()
        context.refresh_parameters()


def _smrt48(
    operation: str,
    arguments: tuple[object, ...],
    context: UtilityExContext,
    comm: UtilityExComm,
) -> int:
    if operation == "ReadVINCode":
        output = _buffer(arguments[1], 17)
        return (_vin_classic48 if arguments[0] == 4 else _vin_fixed48)(
            context, comm, output
        )
    try:
        if context.is_cancelled():
            return 99
        status = comm.initialize()
        if status:
            return status
        if operation == "GetTheDigitalKeySerialNo":
            status, reply = _wire48(context, comm, b"\x21\xcc", classic=True)
            if status:
                return status
            if len(reply) < 18 or reply[1] != 0xCC:
                return 3
            _buffer(arguments[0], 16)[:16] = reply[2:18]
            return 4804
        _configure(context, comm, "native_rva:172d0", 150)
        try:
            status = comm.refresh_support_cache(1)
            if status:
                return status
            snapshot = comm.cached_support(1)
            if snapshot is None:
                raise UnsupportedChassisOperation(
                    "SMRT48 support cache missing after refresh"
                )
            status, masks = _record40(*snapshot, 0xCC)
            return (
                0
                if not status and len(masks) >= 16 and masks[:16] == b"\xff" * 16
                else 4800
            )
        finally:
            _configure(context, comm, "native_rva:172d0", 100)
    finally:
        comm.finalize()


def run_body(
    export: str, arguments: tuple[object, ...], context: UtilityExContext
) -> int:
    """Execute one recovered exact-source body; scheduler stays in UtilityEx83."""
    if export not in SUPPORTED_EXPORTS:
        raise UnsupportedChassisOperation(f"Unrecovered NK chassis operation: {export}")
    if (
        context.module_sha256
        not in (NK18_SHA256, NK12_SHA256, NK_DS4_SHA256, NK_GTS_SHA256)
        or hashlib.sha256(context.module_bytes).hexdigest() != context.module_sha256
    ):
        raise UnsupportedChassisOperation(
            "NK chassis implementation requires exact audited module"
        )
    if (
        export in (_FIXED_UDS | _ABS40 | _SMRT45 | _SMRT46 | _SMRT47 | _SMRT48)
        and context.module_sha256 == NK12_SHA256
    ):
        raise UnsupportedChassisOperation(
            "This ABS family is absent from the NK12 source"
        )
    family = export.split("_")[1] if export.startswith("Ex2SMRT_") else ""
    operation = export.rsplit("_", 1)[-1]
    structure_size = 0
    if family == "31":
        if operation == "GetTheKeyStatus":
            structure_size = 13
        elif operation in (
            "RequestKeyCodeRegistration",
            "TerminateKeyCodeRegistration",
        ):
            structure_size = 4
    expected = (
        1
        if export in _ABS_START or export == "Ex2ABS_01_BeginSolenoidDrive"
        else 2
        if export in _ABS_STOP
        else 0
    )
    if export in _SMRT63:
        expected = int(operation in ("GetSupportInfo", "GetKeyStatus"))
    if export in _SMRT55:
        expected = {
            "ConfirmDIDRIDSupport": 1,
            "GetKeyDiagInfo": 0,
            "CHKSupportStatus": 2,
            "SetKeyDiag": 2,
            "SetKeyDiag2": 3,
            "TermKeyDiag": 0,
            "TermKeyDiag2": 0,
        }[operation]
    if export in _SMRT50:
        expected = int(operation == "GetSupportInfo")
    if export in _SMRT53:
        expected = 5 if export.endswith("Online_Certification") else 3
    if export in _SMRT56:
        expected = int(operation == "EndExtendedSession")
    if export in _SMRT48:
        expected = (
            2 if operation == "ReadVINCode" else int(operation != "GetSupportInfo")
        )
    if export in _SMRT47:
        expected = (
            4
            if operation in ("GetSupportInfo", "SetSupportInfo")
            else 6
            if operation == "KeyCodeChk"
            else 1
            if operation == "NomalChk"
            else 0
        )
    if export in _SMRT46:
        expected = (
            4
            if operation in ("GetSupportInfo", "SetSupportInfo")
            else 6
            if operation == "KeyCodeChk"
            else 1
            if operation == "GetKeyStatus"
            else 0
        )
    if export in _SMRT45:
        expected = (
            4
            if operation in ("GetSupportInfo", "SetSupportInfo")
            else 6
            if operation == "StartOwnersKeyReg"
            else 0
            if operation == "StopOwnersKeyReg"
            else 1
        )
    if export in _SMRT42:
        expected = {
            "GetSupportInfo": 4,
            "GetKeyNum": 2,
            "KeyCodeErasureChk": 8,
            "GetKeyStatus": 2,
            "KeyCodeErasure": 1,
            "TerminateKeyCodeErasure": 0,
            "SetSupportInfo": 4,
        }[operation]
    if export in _SMRT41:
        expected = {
            "Online_Certification": 9,
            "Online_Certification_008": 4,
            "KeepAlive": 2,
            "SendTheKey": 3,
        }[export.removeprefix("Ex2SMRT_41_")]
    if operation in ("GetEntryKey", "EraseGetKey"):
        expected = 2
    elif operation == "CompleteCheck":
        expected = 1 if family == "03" else 2
    elif export == "Ex2SMRT_32_EndEraseMode":
        expected = int(context.module_sha256 in (NK12_SHA256, NK18_SHA256))
    if export == "Ex2ABS_01_Conf_typeof_AirBleeding":
        structure_size = 8
    if export == "Ex2ABS_01_Bleed_The_Air":
        expected = 2
    if export == "Ex2ABS_03_ActuatorCheck":
        expected = 1
    if export in (
        "Ex2ABS_15_StartAirBleeding",
        "Ex2ABS_14_StartSolenoidDrive",
        "Ex2ABS_14_StopSolenoidDrive_VSC",
        "Ex2ABS_50_RearAirBleeding",
    ):
        expected = 1
    if export in _ABS05 or export == "Ex2ABS_40_VSCLine_AirBleeding":
        expected = 2
    if export in _ABS38:
        expected = 2 if operation == "VacuumFillingFlg" else 1
    if structure_size:
        expected = 1
    if len(arguments) != expected:
        raise ValueError(f"{export} requires {expected} arguments")
    if export in _SMRT48:
        if operation == "ReadVINCode":
            selector = _uint(arguments[0])
            if selector not in (4, 20):
                return 99
            _buffer(arguments[1], 17)
        elif operation == "GetTheDigitalKeySerialNo":
            _buffer(arguments[0], 16)
        if operation != "ReadVINCode" and context.mode != 4:
            return 99
        scope = (
            "selected"
            if operation != "ReadVINCode" or arguments[0] == 4
            else {
                NK18_SHA256: "native:1014f5e0",
                NK_DS4_SHA256: "native:101b6758",
                NK_GTS_SHA256: "native:101c18a0",
            }[context.module_sha256]
        )
        return _smrt48(operation, arguments, context, context.comm(scope))
    if export in _SMRT63:
        if operation in ("GetSupportInfo", "GetKeyStatus"):
            _out(arguments[0])
    elif export in _SMRT50:
        if operation == "GetSupportInfo":
            _out(arguments[0])
    elif export in _SMRT53:
        if export.endswith("SendTheKey"):
            _input41(arguments[0], _uint(arguments[2]), 0x101E)
            _out(arguments[1])
        else:
            _out(arguments[0])
            offset = int(export.endswith("Online_Certification"))
            if offset:
                _uint(arguments[1])
                _uint(arguments[4])
            if not offset or arguments[1] == 1:
                _buffer(arguments[1 + offset], 8)
                _buffer(arguments[2 + offset], 6)
    elif export in (_SMRT45 | _SMRT46 | _SMRT47):
        if operation == "SetSupportInfo":
            _input41(arguments[0], _uint(arguments[2]), 0x1020)
            _input41(arguments[1], _uint(arguments[3]), 0x1020)
    elif export in _SMRT42:
        if operation == "GetSupportInfo":
            _buffer(arguments[0], 0)
            _buffer(arguments[1], 0)
            _out(arguments[2])
            _out(arguments[3])
        elif operation == "SetSupportInfo":
            _input41(arguments[0], _uint(arguments[2]), 0x1020)
            _input41(arguments[1], _uint(arguments[3]), 0x1020)
    elif export in _SMRT41:
        _validate41(export.removeprefix("Ex2SMRT_41_"), arguments)
    elif export in _SMRT55:
        if operation in ("CHKSupportStatus", "SetKeyDiag", "SetKeyDiag2"):
            for argument in arguments:
                _uint(argument)
    elif export == "Ex2ABS_01_Bleed_The_Air":
        selection = _uint(arguments[0])
        counts = _buffer(arguments[1], 8)
        offset = 0 if selection in (0x226, 0x227) else 4
        if int.from_bytes(counts[offset : offset + 4], "little") > (
            255 if offset == 0 else 0x101B
        ):
            raise ValueError("ABS01 padding count exceeds native command buffer")
    elif export == "Ex2ABS_03_ActuatorCheck":
        if context.mode == 4:
            _buffer(arguments[0], 1)
    elif export == "Ex2ABS_50_RearAirBleeding":
        _out(arguments[0])
    elif export in _ABS05 or export == "Ex2ABS_40_VSCLine_AirBleeding":
        for argument in arguments:
            _out(argument)
    elif export in _ABS38 and operation != "GetSupportInfo":
        if operation != "StopTheRoutine" or arguments[0] is not None:
            _out(arguments[0])
        if operation == "VacuumFillingFlg":
            _uint(arguments[1])
    elif structure_size:
        _buffer(arguments[0], structure_size)
    elif operation in ("GetEntryKey", "EraseGetKey"):
        for argument in arguments:
            _out(argument)
    else:
        for argument in arguments:
            _uint(argument)
    modes = (
        (20,)
        if export in _FIXED_UDS
        else (3, 4)
        if export == "Ex2ABS_03_ActuatorCheck"
        else (4,)
        if export
        in (
            _ABS40
            | _ABS14
            | _ABS03
            | _ABS05
            | _ABS15
            | _ABS22
            | _ABS25
            | _ABS01_FLOW
            | _SMRT41
            | _SMRT42
            | _SMRT45
            | _SMRT46
            | _SMRT47
        )
        else (3,)
    )
    if (
        export in _ABS50
        and context.module_sha256 == NK_GTS_SHA256
        and export != "Ex2ABS_50_ConfSupportInfo"
    ):
        modes = (20, 22)
    if export != _SMRT55_CHK and context.mode not in modes:
        return 99
    if export == "Ex2ABS_15_StartAirBleeding" and _uint(arguments[0]) > 4:
        raise ValueError("ABS15 native pattern index must be zero through four")
    if operation == "SetProgressTimeOutFlg":
        _save(context, "progress_timeout", 1)
        return 0
    if export in _FIXED_UDS:
        scope = {
            NK18_SHA256: "native:1014f5e0",
            NK_DS4_SHA256: "native:101b6758",
            NK_GTS_SHA256: "native:101c18a0",
        }[context.module_sha256]
        if export in _SMRT55:
            if export == _SMRT55_CHK:
                return _smrt55_chk(arguments, context)
            return _smrt55(export, arguments, context, context.comm(scope))
        if export in _SMRT63:
            return _smrt63(export, arguments, context, context.comm(scope))
        if export in _SMRT50:
            return _smrt50(export, arguments, context, context.comm(scope))
        if export in _SMRT53:
            return _smrt53(export, context, context.comm(scope))
        if export in _SMRT56:
            return _smrt56(export, arguments, context, context.comm(scope))
        if export in _SMRT58:
            return _smrt58(export, context, context.comm(scope))
        if export in _ABS35:
            return _abs35(export, context, context.comm(scope))
        if export in _ABS50:
            if context.mode == 22:
                scope = "native:101c6da0"
            return _abs50(export, arguments, context, context.comm(scope))
        if export in _ABS38:
            return _abs38(export, arguments, context, context.comm(scope))
        worker = _abs36 if export in _ABS36 else _abs37
        return worker(export, context, context.comm(scope))
    if export == "Ex2ABS_03_ActuatorCheck" and context.mode == 3:
        return 0
    comm = context.comm("selected")
    if export in _SMRT47:
        return _smrt47(export, arguments, context, comm)
    if export in _SMRT46:
        return _smrt46(export, arguments, context, comm)
    if export in _SMRT45:
        return _smrt45(export, arguments, context, comm)
    if export in _SMRT42:
        return _smrt42(export, arguments, context, comm)
    if export in _SMRT41:
        return _smrt41(export, arguments, context, comm)
    if export in _ABS01_FLOW:
        return _flow01(export, arguments, context, comm)
    if export in _ABS25:
        return _abs25(export, context, comm)
    if export in _ABS22:
        return _abs22(export, context, comm)
    if export in _ABS15:
        return _abs15(export, arguments, context, comm)
    if export in _ABS05:
        return _abs05(arguments, context, comm)
    if export in _ABS03:
        return _abs03(export, arguments, context, comm)
    if export in _ABS14:
        return _abs14(export, arguments, context, comm)
    if export in _ABS40:
        return _abs40(export, arguments, context, comm)
    if family == "31":
        return _key31(export, arguments, context, comm)
    if export == "Ex2ABS_01_BeginSolenoidDrive":
        return _abs01_start(_uint(arguments[0]), context, comm)
    if export in _ABS_START:
        return _abs_start(export, _uint(arguments[0]), context, comm)
    if export in _ABS_STOP:
        if arguments[1] != 1:
            return _actuator(comm, _ABS_STOP[export], _uint(arguments[0]), context)
        # Computed worker entries 28470/28530/28b30 are absent from collector C.
        # Raw PE ASM proves repeated stop, no initialize, unconditional finalize.
        try:
            status = 0
            while not context.is_cancelled():
                status = _actuator(
                    comm, _ABS_STOP[export], _uint(arguments[0]), context
                )
                if status:
                    break
                context.sleep(2000)
            return status
        finally:
            comm.finalize()
    if operation == "GetEntryKey":
        return _get_entry(family, arguments, context, comm)
    if operation.startswith("Erase"):
        return _erase(operation, arguments, context, comm)
    if operation in ("ModeEntry", "ModeEnd"):
        return _mode(operation == "ModeEntry", context, comm)
    if family == "32" and export != "Ex2SMRT_32_GetRegKeyNum":
        return _key32(export, context, comm)
    if export == "Ex2SMRT_32_GetRegKeyNum":
        try:
            status = comm.initialize()
            if status:
                return status
            status, reply = _reply(comm, b"\x21\x21")
            if status:
                return status
            if len(reply) < 7 or reply[1] != 0x21:
                return 3
            # 3dd20 reads offset7, so native count7 zero-fill must be preserved.
            value = (reply[7] if len(reply) > 7 else 0) & 0xF0
            return {0x10: 3000, 0x20: 3005, 0x30: 3006, 0x40: 3007, 0x50: 3008}.get(
                value, 3009
            )
        finally:
            comm.finalize()
    return _smart_poll(family, operation, arguments, context, comm)
