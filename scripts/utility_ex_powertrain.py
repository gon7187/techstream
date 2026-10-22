"""Source-bound NK ECD/STR business bodies; the shared UtilityEx engine owns scheduling.

Unreconstructed operations are errors, never successful generic exchanges. Native
reply payloads include the positive service byte; transport status is separate.
"""

from __future__ import annotations

from contextlib import suppress
from typing import Protocol

NK18 = "8d9623f028f23876f69cb02baa10e1881c01fa01a4f906013bd36266f7e0fb33"
NK12 = "980435d6bb2d9c57aab29e8f281d2641e3822b3172728f223c975ec6493d3c1e"
CONFIG_RVAS = {
    NK18: {
        "delay": "native_rva:172d0",
        "busy_ms": "native_rva:172e0",
        "pending": "native_rva:17320",
        "retry": "native_rva:172f0",
    },
    NK12: {
        "delay": "native_rva:fa60",
        "busy_ms": "native_rva:fa70",
        "pending": "native_rva:fa90",
        "retry": "native_rva:fa80",
    },
}
NK_DS4 = "797833dc0c798984fcb739c21ac6fbd5230871fb67495d3339698df2ee53753f"
CONFIG_RVAS[NK_DS4] = {
    "delay": "native_rva:32410",
    "busy_ms": "native_rva:32420",
    "pending": "native_rva:32450",
    "retry": "native_rva:32480",
}
NK_GTSPLUS = "36dcdad2e72e29aae813db5576daf0168dd032b08a9cdda3841078dfb0b7b9fd"
CONFIG_RVAS[NK_GTSPLUS] = {
    "delay": "native_rva:33320",
    "busy_ms": "native_rva:33330",
    "pending": "native_rva:33360",
    "retry": "native_rva:33390",
}
STR41_LENGTH = {
    NK12: "native_global:100f5b50",
    NK18: "native_global:1015eb38",
    NK_DS4: "native_global:101c5d0c",
    NK_GTSPLUS: "native_global:101dd614",
}
STR41_MODE = {
    NK12: "native_global:100f5b4c",
    NK18: "native_global:1015eb34",
    NK_DS4: "native_global:101c5d08",
    NK_GTSPLUS: "native_global:101dd610",
}
STR41_COUNTERS = {
    NK12: ("native_global:100f5b44", "native_global:100f5b48"),
    NK18: ("native_global:1015eb2c", "native_global:1015eb30"),
    NK_DS4: ("native_global:101c5d10", "native_global:101c5d14"),
    NK_GTSPLUS: ("native_global:101dd618", "native_global:101dd61c"),
}
STR41_REPEAT_ARGUMENTS = {
    NK12: ("native_global:100e5d48", "native_global:100e5d4c"),
    NK18: ("native_global:1014a790", "native_global:1014a794"),
    NK_DS4: ("native_global:101b1aec", "native_global:101b1af0"),
    NK_GTSPLUS: ("native_global:101bcbec", "native_global:101bcbf0"),
}
STR41_STATUS_ARGUMENTS = {
    NK12: (
        "native_global:100e5d10",
        "native_global:100e5d14",
        "native_global:100e5d18",
    ),
    NK18: (
        "native_global:1014a738",
        "native_global:1014a73c",
        "native_global:1014a740",
    ),
    NK_DS4: (
        "native_global:101b1af4",
        "native_global:101b1af8",
        "native_global:101b1afc",
    ),
    NK_GTSPLUS: (
        "native_global:101bcbf4",
        "native_global:101bcbf8",
        "native_global:101bcbfc",
    ),
}
STR41_REGISTER_ARGUMENT_BASE = {
    NK12: 0x100E5D70,
    NK18: 0x1014A7D8,
    NK_DS4: 0x101B1A80,
    NK_GTSPLUS: 0x101BCB80,
}
STR42_LENGTH = {
    NK12: "native_global:100f5b54",
    NK18: "native_global:1015eb3c",
    NK_DS4: "native_global:101c5d18",
    NK_GTSPLUS: "native_global:101dd620",
}
IMBI_SELECTION = {
    NK12: ("native_rva:f830", "native_rva:f840", 0x100E6368, 0x100E6240),
    NK18: ("native_rva:170a0", "native_rva:170b0", 0x1014C0B0, 0x1014AEF0),
    NK_DS4: ("native_rva:323d0", "native_rva:323e0", 0x101B554C, 0x101B4208),
    NK_GTSPLUS: ("native_rva:332e0", "native_rva:332f0", 0x101C0674, 0x101BF318),
}
SUPPORTED_OPERATIONS = frozenset(
    {
        "Ex2ECD_InitialSupplyPump",
        "Ex2ECD_50_GetSupportInfo",
        "Ex2ECD_09_ChgNormalLearningMode",
        "Ex2ECD_10_ChgDetailLearningMode",
        "Ex2ECD_09_EraseDiagCode",
        "Ex2ECD_10_EraseDiagCode",
        "Ex2ECD_19_CheckCodeSupportInfo",
        "Ex2ECD_19_CheckCodeSupportWID20Info",
        "Ex2ECD_15_CheckCodeSupportWID20Info",
        "Ex2ECD_16_GetCodeSupportWID20",
        "Ex2ECD_20_CheckCodeSupportWID20Info",
        "Ex2ECD_14_CheckCodeSupportInfo",
        "Ex2ECD_14_CheckCodeSupportWID20Info",
        "Ex2ECD_24_GetCodeSupportInfo",
        "Ex2ECD_31_CheckCodeSupportInfo",
        "Ex2ECD_31_ReadCode",
        "Ex2ECD_22_GetCylinderNum",
        "Ex2ECD_13_ReadCylinderInfo",
        "Ex2ECD_17_ReadCylinderInfo",
        "_Ex2STR_43_CheckOnlineSupport@4",
        "Ex2ECD_25_ClearLearningValues",
        "Ex2ECD_26_ReadPresetValue",
        "Ex2ECD_26_WritePresetValue",
        "Ex2ECD_11_InitCrankTimeValue",
        "Ex2ECD_23_ClearDPFAshValue",
        "Ex2STR_ChangeRegistMode",
        "Ex2STR_ConfMasKey",
        "Ex2STR_Init",
        "Ex2STR_InitImbi",
        "Ex2STR_41_EndFactoryMode",
        "Ex2STR_41_GetRegKeySupportInfo",
        "Ex2STR_41_GetRegKeyNum",
        "Ex2STR_41_GetCurrentStatus",
        "Ex2STR_41_GetCurrentMode",
        "Ex2STR_41_GetCurrentModeRepeat",
        "Ex2STR_41_ResultTransponderID",
        "Ex2STR_41_GetCurrentStatusRepeat",
        "Ex2STR_41_RegTransponderID",
        "Ex2STR_41_RegNewKey",
        "Ex2STR_41_StartCommunication",
        "Ex2STR_41_StartKeepAliveCheck",
        "Ex2STR_43_CheckRegisteredKeyNum",
        "Ex2STR_43_GetSupportInfo",
        "Ex2STR_43_ReqSecuritySeed",
        "Ex2STR_43_ClearAllKey",
        "Ex2STR_43_StartCommunication",
        "Ex2STR_43_CheckModeThread",
        "Ex2STR_20_ComfirmSwitchAccOff",
        "Ex2STR_20_ComfirmSwitchAccOffIgOn",
        "Ex2STR_22_ComfirmSwitchAccOffIgOn",
        "Ex2STR_20_GetSupportBitInfo",
        "Ex2STR_20_GetTheKeyNumber",
        "Ex2STR_20_KeyRegist",
        "Ex2STR_53_GetKeySWStatus_Single",
        "Ex2STR_53_GetKeyStatus_Single",
        "Ex2STR_53_GetKeyStatus",
        "Ex2STR_53_GetKeySWStatus",
        "Ex2STR_53_GetImmobilizerMode",
        "Ex2STR_53_GetImmobilizerMode_OnExit",
        "Ex2STR_53_GetImmobilizerMode_Single",
        "Ex2STR_52_GetSupportInfo",
        "Ex2STR_52_GetDataInfo",
        "Ex2STR_52_KeepAlive",
        "EX2STR_52_SendTheKey",
        "Ex2STR_22_GetKeyNumber",
        "Ex2STR_20_StartKeyRegist",
        "Ex2STR_20_EndKeyRegist",
        "Ex2STR_22_GetSupportInfo",
        "Ex2STR_41_StartKeepAlive",
        "Ex2STR_42_StartKeepAlive",
        "Ex2STR_20_StartKeepAlive",
        "Ex2STR_22_StartKeepAlive",
        "Ex2STR_StartKeepAlive",
        "Ex2ECD_09_StartKeepAlive",
        "Ex2ECD_10_StartKeepAlive",
        "Ex2STR_42_ChkIDSupportInfo",
        "Ex2STR_42_ChkModeCondition",
        "Ex2STR_42_TransponderIDErasure",
        "Ex2STR_16_Foced_Termination_Of_FM",
        "Ex2STR_CngEraseModeImbi",
        "Ex2STR_ConfRegArea",
        "Ex2STR_CngEraseMode",
        "Ex2STR_ConfRegMode",
        "Ex2STR_GetRegistKey",
        "Ex2STR_WaitCompRegistKey",
        "Ex2STR_WaitCompEraseKey",
        "Ex2STR_02_WaitCompEraseKey",
        "Ex2STR_GetRegKeyNumBefore",
        "Ex2STR_GetRegKeyNumAfter",
        "Ex2STR_RegMasKeyConf",
        "Ex2STR_CheckIDCode",
        "Ex2STR_02_CheckIDCode",
        "Ex2ECD_12_InitAFSensorLearn",
        "Ex2ECD_12_GetSupportInfo",
        "Ex2ECD_22_ClearZFCLearningValues",
    }
)


POST12_OPERATIONS = frozenset(
    {
        "_Ex2STR_43_StartKeepAliveThread@4",
        "Ex2STR_55_StartKeepAlive",
        "Ex2STR_56_StartKeepAlive",
    }
)


def supported_operations(module_sha256: str) -> frozenset[str]:
    """Only independently recovered bodies for this exact supplied binary."""
    if module_sha256 not in CONFIG_RVAS:
        raise ValueError("Unknown exact NK module identity")
    return SUPPORTED_OPERATIONS | (
        POST12_OPERATIONS if module_sha256 != NK12 else frozenset()
    )


class UtilityExComm(Protocol):
    def initialize(self, mode: int = 0) -> int: ...
    def finalize(self) -> None: ...
    def exchange(self, request: bytes) -> tuple[int, bytes]: ...
    def support_snapshot(self, kind: int) -> tuple[int, bytes, tuple[int, ...]]: ...
    def refresh_support_cache(self, kind: int) -> int: ...
    def cached_support(self, kind: int) -> tuple[bytes, tuple[int, ...]] | None: ...
    def support_length(self, kind: int, selector: int) -> int: ...
    def configure(self, field: str, value: int) -> None: ...
    def select_target(self, identifier: int, second: int = 0) -> None: ...
    def read_target(self) -> tuple[int, int]: ...


class UtilityExContext(Protocol):
    module_sha256: str
    mode: int
    state: dict[str, object]

    def start_selected_cmn(
        self,
        interval_ms: int,
        skip_response_validation: int = 0,
        request: bytes | None = None,
        length: int = 0,
    ) -> int: ...
    def ticks(self) -> int: ...
    def broker(self, key: int) -> int: ...
    def is_cancelled(self) -> bool: ...
    def sleep(self, ms: int) -> None: ...
    def native_sleep(self, ms: int) -> None: ...
    def comm(self, kind: str) -> UtilityExComm: ...


def _exchange(
    comm: UtilityExComm, request: bytes, size: int, echo: int
) -> tuple[int, bytes]:
    status, reply = comm.exchange(request)
    if status == 0 and (len(reply) != size or reply[1] != echo):
        return 3, reply
    return status, reply


def _uint32_argument(arguments: tuple[object, ...]) -> int:
    if len(arguments) != 1 or type(arguments[0]) is not int:
        raise ValueError("This native operation requires one uint32 argument")
    value = arguments[0]
    if not isinstance(value, int) or not 0 <= value <= 0xFFFFFFFF:
        raise ValueError("Native argument is outside uint32")
    return value


def _argument(arguments: tuple[object, ...]) -> int:
    return _uint32_argument(arguments) & 0xFF


def _check_id(export: str, context: UtilityExContext) -> int:
    if context.mode != 3:
        return 99
    comm = context.comm("selected")
    config = CONFIG_RVAS[context.module_sha256]
    keep_open = False
    try:
        if context.is_cancelled():
            return 99
        status = comm.initialize(0)
        if status:
            return status
        key_type = context.broker(0xBF)
        canonical = {1: 1001, 2: 1002, 0x65: 1101, 0x66: 1102, 0x74: 1116}.get(
            key_type, key_type
        )
        request = b"\xa5\x99\x80" + (b"\0" if canonical in {1001, 1101} else b"")
        try:
            comm.configure(config["pending"], 1)
            comm.configure(config["retry"], 1)
            if context.is_cancelled():
                return 99
            status, reply = comm.exchange(request)
            if status:
                return status
            if len(reply) == 2:
                status = 0 if reply[1] == 0x99 else 3
            elif len(reply) == 3 and reply[2] == 0:
                status = 100 if export == "Ex2STR_02_CheckIDCode" else 0x41A
            else:
                status = 3
            keep_open = status == 0
            return status
        finally:
            comm.configure(config["pending"], 100)
            comm.configure(config["retry"], 3)
    finally:
        if not keep_open:
            comm.finalize()


def _confirm_master(context: UtilityExContext) -> int:
    if context.mode != 3:
        return 99
    comm = context.comm("selected")
    config = CONFIG_RVAS[context.module_sha256]
    try:
        status = comm.initialize(0)
        if status:
            return status
        try:
            comm.configure(config["pending"], 1)
            comm.configure(config["retry"], 4)
            status, reply = comm.exchange(b"\x21\x03")
            if status:
                return status
            if len(reply) == 1:
                return 100
            if len(reply) < 2 or reply[1] != 3:
                return 3
            return 0 if len(reply) > 2 and reply[2] & 0xC0 == 0x80 else 100
        finally:
            comm.configure(config["pending"], 100)
            comm.configure(config["retry"], 3)
    finally:
        comm.finalize()


def _terminate_factory(context: UtilityExContext) -> int:
    if context.mode != 3:
        return 99
    comm = context.comm("selected")
    status = 0
    try:
        if not context.is_cancelled():
            if comm.initialize(0):
                return 1601
            status, reply = comm.exchange(b"\xa5\x99\x01\0")
            if status == 0 and (len(reply) != 2 or reply[1] != 0x99):
                status = 3
            if status == 1601:
                return status
        comm.exchange(
            b"\x82"
        )  # Native secondary shutdown result is deliberately ignored.
        return status
    finally:
        comm.finalize()


def _erase_immobilizer(context: UtilityExContext) -> int:
    if context.mode != 3:
        return 99
    comm = context.comm("selected")
    config = CONFIG_RVAS[context.module_sha256]
    override = IMBI_SELECTION[context.module_sha256][0]
    try:
        comm.configure(config["pending"], 1)
        comm.configure(config["retry"], 1)
        status, reply = comm.exchange(b"\xa5\x99\0")
        if status:
            return status
        if len(reply) not in (2, 3) or reply[1] != 0x99:
            return 3
        return 0 if len(reply) == 2 else 401 + (reply[2] != 0)
    finally:
        try:
            comm.configure(config["pending"], 100)
            comm.configure(config["retry"], 3)
            comm.select_target(0xC1, 0)
            comm.configure(override, 0)
        finally:
            comm.finalize()


def _initialize_immobilizer(context: UtilityExContext) -> int:
    if context.mode != 3:
        return 99
    comm = context.comm("selected")
    override, profile, first, second = IMBI_SELECTION[context.module_sha256]
    keep_open = False
    try:
        comm.select_target(0x10, 0)
        comm.configure(override, first)
        comm.configure(profile, 1)
        status = comm.initialize(0)
        if status == 0:
            keep_open = True
            return 0
        comm.finalize()
        context.native_sleep(300)
        comm.select_target(0x13, 0)
        comm.configure(override, second)
        comm.configure(profile, 1)
        status = comm.initialize(0)
        if status == 0:
            keep_open = True
            return 0
        comm.select_target(0xC1, 0)
        return status
    finally:
        if not keep_open:
            comm.finalize()


def _change_erase_mode(context: UtilityExContext) -> int:
    if context.mode != 3:
        return 99
    comm = context.comm("selected")
    config = CONFIG_RVAS[context.module_sha256]
    keep_open = False
    try:
        comm.configure(config["pending"], 1)
        comm.configure(config["retry"], 1)
        comm.configure(config["busy_ms"], 10000)
        status = comm.initialize(0)
        if status:
            return status
        comm.configure(config["delay"], 3000)
        status, reply = comm.exchange(b"\xa5\x99\x80")
        if status:
            return status
        if len(reply) not in (2, 3) or reply[1] != 0x99:
            return 3
        if len(reply) == 3:
            return 12 if reply[2] == 0 else 3
        keep_open = True
        return 0
    finally:
        try:
            comm.configure(config["delay"], 100)
            comm.configure(config["busy_ms"], 0)
            comm.configure(config["pending"], 100)
            comm.configure(config["retry"], 3)
        finally:
            if not keep_open:
                comm.finalize()


def _registration_mode(context: UtilityExContext) -> int:
    if context.mode != 3:
        return 99
    comm = context.comm("selected")
    config = CONFIG_RVAS[context.module_sha256]
    keep_open = False
    try:
        while True:
            comm.configure(config["pending"], 1)
            comm.configure(config["retry"], 4)
            try:
                status, reply = comm.exchange(b"\x21\x06")
                if status:
                    return status
                if len(reply) < 3 or reply[1] != 6:
                    return 3
            finally:
                comm.configure(config["pending"], 100)
                comm.configure(config["retry"], 3)
            if not reply[2] & 0x40:
                keep_open = True
                return 0
            if context.is_cancelled():
                return 5
    finally:
        if not keep_open:
            comm.finalize()


def _registration_area(context: UtilityExContext) -> int:
    if context.mode != 3:
        return 99
    comm = context.comm("selected")
    config = CONFIG_RVAS[context.module_sha256]
    keep_open = False
    try:
        comm.configure(config["pending"], 1)
        comm.configure(config["retry"], 4)
        if context.is_cancelled():
            return 5
        for attempt in range(2):
            status = comm.initialize(0)
            if status == 0:
                break
            if attempt == 0:
                context.native_sleep(2000)
        if status:
            return status
        status, reply = comm.exchange(b"\x21\x03")
        if status:
            return status
        if len(reply) < 4 or reply[1] != 3:
            return 3
        if reply[3] & 0x80:
            return 440
        keep_open = True
        return 0
    finally:
        try:
            if not keep_open:
                comm.finalize()
        finally:
            comm.configure(config["pending"], 100)
            comm.configure(config["retry"], 3)


def _cancel_checked_key_query(
    comm: UtilityExComm, context: UtilityExContext, request: bytes
) -> tuple[int, bytes]:
    config = CONFIG_RVAS[context.module_sha256]
    comm.configure(config["pending"], 1)
    comm.configure(config["retry"], 4)
    try:
        if context.is_cancelled():
            return 99, b""
        return comm.exchange(request)
    finally:
        comm.configure(config["pending"], 100)
        comm.configure(config["retry"], 3)


def _registration_key(
    export: str, arguments: tuple[object, ...], context: UtilityExContext
) -> int:
    if context.mode != 3:
        return 99
    if (
        len(arguments) != 1
        or not isinstance(arguments[0], bytearray)
        or len(arguments[0]) != 1
    ):
        raise ValueError("Native registered-key output requires one mutable byte")
    output = arguments[0]
    wait = export == "Ex2STR_WaitCompRegistKey"
    comm = context.comm("selected")
    keep_open = False
    config = CONFIG_RVAS[context.module_sha256]
    try:
        if wait:
            status = 99
            while not context.is_cancelled():
                comm.configure(config["pending"], 1)
                comm.configure(config["retry"], 4)
                try:
                    if context.is_cancelled():
                        return 99
                    received, reply = comm.exchange(b"\x21\x06")
                    if received:
                        return 1003 if received == 2 else 1004
                    if len(reply) < 3 or reply[1] != 6:
                        return 1004
                    status = 0 if reply[2] & 0x40 else 170
                finally:
                    comm.configure(config["pending"], 100)
                    comm.configure(config["retry"], 3)
                if status:
                    break
            if status != 170:
                return status
        else:
            if context.is_cancelled():
                return 99
            status, reply = _cancel_checked_key_query(comm, context, b"\x21\x03")
            if status:
                return status
            if len(reply) < 4 or reply[1] != 3:
                return 3
            if reply[3] & 0xC0:
                return 1002
        status, reply = _cancel_checked_key_query(comm, context, b"\x21\x04")
        if status:
            return status
        if len(reply) < 3 or reply[1] != 4:
            return 3
        output[0] = reply[2]
        keep_open = not wait
        return 0
    finally:
        if not keep_open:
            comm.finalize()


def _wait_erase(export: str, context: UtilityExContext) -> int:
    if context.mode != 3:
        return 99
    comm = context.comm("selected")
    config = CONFIG_RVAS[context.module_sha256]
    malformed = 101 if export == "Ex2STR_02_WaitCompEraseKey" else 1051
    status = 99
    try:
        while not context.is_cancelled():
            comm.configure(config["pending"], 1)
            comm.configure(config["retry"], 4)
            try:
                if context.is_cancelled():
                    return 99
                received, reply = comm.exchange(b"\x21\x06")
                if received:
                    return malformed + (received == 2)
                if len(reply) < 3 or reply[1] != 6:
                    return malformed
                status = 171 if reply[2] & 0x40 else 0
            finally:
                comm.configure(config["pending"], 100)
                comm.configure(config["retry"], 3)
            if status != 171:
                break
        if status:
            return status
        comm.configure(config["pending"], 1)
        comm.configure(config["retry"], 4)
        try:
            if context.is_cancelled():
                return 99
            status, reply = comm.exchange(b"\x21\x04")
            if status:
                return status
            if len(reply) < 3 or reply[1] != 4:
                return 3
            return 0 if reply[2] == 0x10 else malformed + 2
        finally:
            comm.configure(config["pending"], 100)
            comm.configure(config["retry"], 3)
    finally:
        comm.finalize()


def _key_counts(
    export: str, arguments: tuple[object, ...], context: UtilityExContext
) -> int:
    if context.mode != 3:
        return 99
    if len(arguments) != 2 or any(
        not isinstance(x, bytearray) or len(x) != 4 for x in arguments
    ):
        raise ValueError("Native key counts require two mutable DWORD output buffers")
    first, second = arguments
    assert isinstance(first, bytearray) and isinstance(second, bytearray)
    before = export == "Ex2STR_GetRegKeyNumBefore"
    if before:
        first[:] = second[:] = bytes(4)
    comm = context.comm("selected")
    config = CONFIG_RVAS[context.module_sha256]
    try:
        if before:
            status = comm.initialize(0)
            if status:
                return status
        try:
            comm.configure(config["pending"], 1)
            comm.configure(config["retry"], 4)
            status, reply = comm.exchange(b"\x21\x04")
            if status:
                return status
            if len(reply) < 3 or reply[1] != 4:
                return 3
            first[:] = (reply[2] >> 4).to_bytes(4, "little")
            second[:] = (reply[2] & 15).to_bytes(4, "little")
            return 0
        finally:
            comm.configure(config["pending"], 100)
            comm.configure(config["retry"], 3)
    finally:
        comm.finalize()


def _registration_master(
    arguments: tuple[object, ...], context: UtilityExContext
) -> int:
    if context.mode != 3:
        return 99
    if context.module_sha256 in {NK12, NK18}:
        _argument(arguments)  # Native ABI retains an unused uint32 in these two builds.
    elif arguments:
        raise ValueError(
            "This exact native registration confirmation takes no arguments"
        )
    comm = context.comm("selected")
    config = CONFIG_RVAS[context.module_sha256]
    try:
        try:
            status = comm.initialize(0)
            if status:
                return status
            comm.configure(config["pending"], 1)
            comm.configure(config["retry"], 4)
            status, reply = comm.exchange(b"\x21\x03")
            if status:
                return status
            if len(reply) < 3 or reply[1] != 3:
                return 3
            return 0 if reply[2] & 0x80 else 480
        finally:
            comm.configure(config["pending"], 100)
            comm.configure(config["retry"], 3)
    finally:
        comm.finalize()


def _change_registration(context: UtilityExContext) -> int:
    if context.mode != 3:
        return 99
    comm = context.comm("selected")
    config = CONFIG_RVAS[context.module_sha256]
    keep_open = False
    try:
        if context.is_cancelled():
            return 99
        status = comm.initialize(0)
        if status:
            return status
        comm.configure(config["pending"], 1)
        comm.configure(config["retry"], 1)
        try:
            if context.is_cancelled():
                return 99
            status, reply = comm.exchange(b"\xa5\x99\x04\x00")
            if status:
                return status
            if len(reply) < 2 or reply[1] != 0x99:
                return 3
            if len(reply) == 2:
                keep_open = True
                return 0
            if len(reply) != 3 or reply[2] != 0:
                return 3
        finally:
            comm.configure(config["pending"], 100)
            comm.configure(config["retry"], 3)
        comm.configure(config["pending"], 1)
        comm.configure(config["retry"], 4)
        try:
            if context.is_cancelled():
                return 99
            status, reply = comm.exchange(b"\x21\x03")
            if status:
                return status
            if len(reply) < 3 or reply[1] != 3:
                return 3
            return 1001 if reply[2] & 0x80 else 1000
        finally:
            comm.configure(config["pending"], 100)
            comm.configure(config["retry"], 3)
    finally:
        if not keep_open:
            comm.finalize()


def _timed_exchange(
    comm: UtilityExComm, field: str, request: bytes, size: int, echo: int
) -> tuple[int, bytes]:
    comm.configure(field, 150)
    try:
        return _exchange(comm, request, size, echo)
    finally:
        comm.configure(field, 100)


def _timed_minimum_exchange(
    comm: UtilityExComm, field: str, request: bytes, size: int, echo: int
) -> tuple[int, bytes]:
    comm.configure(field, 150)
    try:
        status, reply = comm.exchange(request)
        if status == 0 and (len(reply) < size or reply[1] != echo):
            return 3, reply
        return status, reply
    finally:
        comm.configure(field, 100)


def _crank_or_ash(export: str, context: UtilityExContext) -> int:
    comm = context.comm("selected")
    delay = CONFIG_RVAS[context.module_sha256]["delay"]
    try:
        if context.is_cancelled():
            return 99
        status = comm.initialize(0)
        if status:
            return status
        if export == "Ex2ECD_11_InitCrankTimeValue":
            request = b"\x3b\x11" + b"\x80\0" * 18 + b"\0"
            status = _timed_exchange(comm, delay, request, 2, 0x11)[0]
            if status:
                return status
            status, reply = _timed_exchange(comm, delay, b"\x3b\0", 6, 0)
            if status or not reply[5] & 0x10:
                return status
            request = b"\x3b\x1c" + b"\x80\0" * 18 + b"\0"
            return _timed_exchange(comm, delay, request, 2, 0x1C)[0]
        status, reply = _timed_exchange(comm, delay, b"\x3b\0", 6, 0)
        if status:
            return 0x8FC
        request = b"\x3b\x18" + b"\0" * 14 if reply[4] & 1 else b"\x3b\x27" + b"\0" * 5
        return _timed_exchange(comm, delay, request, 2, request[1])[0]
    finally:
        comm.finalize()


def _read_preset(comm: UtilityExComm, delay: str) -> tuple[int, bytes]:
    comm.configure(delay, 150)
    try:
        status, reply = comm.exchange(b"\xa9\x5a")
        if status == 0 and (len(reply) < 3 or reply[1] != 0x5A):
            status = 3
        return status, reply
    finally:
        comm.configure(delay, 100)


def _preset(
    export: str, arguments: tuple[object, ...], context: UtilityExContext
) -> int:
    output = None
    selector = 0
    if export == "Ex2ECD_26_ReadPresetValue":
        if (
            len(arguments) != 1
            or not isinstance(arguments[0], bytearray)
            or len(arguments[0]) != 1
        ):
            raise ValueError("Preset output must be a one-byte mutable buffer")
        output = arguments[0]
    else:
        selector = _argument(arguments)
    comm = context.comm("selected")
    delay = CONFIG_RVAS[context.module_sha256]["delay"]
    try:
        status = comm.initialize(0)
        if status:
            return status
        if output is not None:
            status, reply = _read_preset(comm, delay)
            if status == 0:
                output[0] = reply[2]
            return status
        status = _timed_exchange(comm, delay, bytes((0x3B, 0x5A, selector)), 2, 0x5A)[0]
        if status:
            return status
        for _ in range(3):
            if context.is_cancelled():
                return status
            context.sleep(100)
            status, reply = _read_preset(comm, delay)
            if status or (reply[2] ^ selector) & 0x7F == 0:
                return status
        return 0xA28
    finally:
        comm.finalize()


def _clear_learning(arguments: tuple[object, ...], context: UtilityExContext) -> int:
    if (
        len(arguments) != 1
        or not isinstance(arguments[0], (bytes, bytearray))
        or len(arguments[0]) != 1
    ):
        raise ValueError("Learning selection must be a one-byte bitmap buffer")
    bitmap = arguments[0]
    comm = context.comm("selected")
    delay = CONFIG_RVAS[context.module_sha256]["delay"]
    try:
        if comm.initialize(0):
            return 4
        for cylinder in range(8):
            if bitmap[0] & (1 << cylinder):
                context.sleep(100)
                request = bytes((0x3B, 0x10, cylinder + 1)) + b"\0" * 16
                status = _timed_exchange(comm, delay, request, 2, 0x10)[0]
                if status:
                    return status
        return 0
    finally:
        comm.finalize()


def _read_ec31(arguments: tuple[object, ...], context: UtilityExContext) -> int:
    size = 176 if context.module_sha256 == NK12 else 181
    if (
        len(arguments) != 1
        or not isinstance(arguments[0], bytearray)
        or len(arguments[0]) < size
    ):
        raise ValueError(
            f"Native EC31 record must be a mutable buffer of at least {size} bytes"
        )
    record = arguments[0]
    comm = context.comm("selected")
    delay = CONFIG_RVAS[context.module_sha256]["delay"]
    # Native record offsets, copied payload lengths, and minimum response sizes.
    branches = (
        (0x80, 2, 1, 2, 50, 52),
        (0x40, 6, 0x34, 0x35, 32, 34),
        (0x20, 7, 0x55, 0x56, 8, 11),
        (0x10, 9, 0x76, 0x77, 4, 6),
        (8, 14, 0x7B, 0x7C, 4, 6),
        (4, 15, 0x80, 0x81, 24, 26),
        (2, 18, 0x99, 0x9A, 22, 24),
        (1, 21, 0xB0, 0xB1, 4, 4),
    )
    try:
        if context.is_cancelled():
            return 99
        status = comm.initialize(0)
        if status:
            return status
        for bit, selector, marker, offset, count, minimum in branches:
            if (bit == 1 and context.module_sha256 == NK12) or not record[0] & bit:
                continue
            for cylinder in range(1, 5) if selector == 7 else (0,):
                request = bytes((0xA9, selector)) + (
                    bytes((cylinder,)) if cylinder else b""
                )
                comm.configure(delay, 150)
                try:
                    status, reply = comm.exchange(request)
                    if status or len(reply) < minimum or reply[1] != selector:
                        return 1406
                    start = 3 if cylinder else 2
                    destination = (
                        offset + (cylinder - 1) * count if cylinder else offset
                    )
                    # Selector0x15 copies a DWORD from a native zero-filled receive buffer,
                    # even when the accepted reply contains only two payload bytes.
                    record[destination : destination + count] = reply[
                        start : start + count
                    ].ljust(count, b"\0")
                    record[marker] = selector
                finally:
                    comm.configure(delay, 100)
        return 0
    finally:
        comm.finalize()


def _online_support(arguments: tuple[object, ...], context: UtilityExContext) -> int:
    if (
        len(arguments) != 1
        or not isinstance(arguments[0], bytearray)
        or len(arguments[0]) != 4
    ):
        raise ValueError(
            "Native online support output requires one mutable DWORD buffer"
        )
    output = arguments[0]
    comm = context.comm("selected")
    delay = CONFIG_RVAS[context.module_sha256]["delay"]
    try:
        status = comm.initialize(0)
        if status:
            return status
        context.native_sleep(100)
        comm.configure(delay, 150)
        try:
            status, reply = comm.exchange(b"\x21\x12")
            if status:
                return status
            if len(reply) < 4 or reply[1] != 0x12:
                return 3
            if reply[3] & 2:
                output[:] = (reply[2] >> 7).to_bytes(4, "little")
                return 4311
            return 0
        finally:
            comm.configure(delay, 100)
    finally:
        comm.finalize()


def _support_position(
    data: bytes, offsets: tuple[int, ...], selector: int, required: int, mask: int
) -> int | None:
    if (
        type(data) is not bytes
        or len(data) != 0x1020
        or type(offsets) is not tuple
        or len(offsets) != 256
        or any(type(x) is not int or not 0 <= x <= 0x1020 for x in offsets)
    ):
        raise ValueError(
            "Native support snapshot requires 4128 bytes and 256 bounded offsets"
        )
    offset = offsets[selector]
    last = offset + required - 1
    # Native17790 counts preceding nonzero fields; host rejects one-past-end reads.
    if (
        last >= len(data)
        or data[offset + 1] < required - 2
        or offset + 1 + data[offset + 1] > len(data)
        or data[last] == 0
        or data[last] & mask != mask
    ):
        return None
    return 2 + sum(value != 0 for value in data[offset + 2 : last])


STR52_FIELDS = {
    NK18: {
        "support": (
            "native_global:1014a778",
            "native_global:1014a77c",
            "native_global:1014a780",
            "native_global:1014a784",
            "native_global:1014a788",
        ),
        "data": ("native_global:1014a7e8", "native_global:1014a7ec"),
        "key": ("native_global:1014a7d0", "native_global:1014a7d4"),
        "saved": (
            "native_global:1015eb4c",
            "native_global:1015eb50",
            "native_global:1015eb54",
        ),
    },
    NK12: {
        "support": (
            "native_global:100e5d30",
            "native_global:100e5d34",
            "native_global:100e5d38",
            "native_global:100e5d3c",
            "native_global:100e5d40",
        ),
        "data": ("native_global:100e5d80", "native_global:100e5d84"),
        "key": ("native_global:100e5d68", "native_global:100e5d6c"),
        "saved": (
            "native_global:100f5b5c",
            "native_global:100f5b60",
            "native_global:100f5b64",
        ),
    },
    NK_DS4: {
        "support": (
            "native_global:101b1aa4",
            "native_global:101b1aa8",
            "native_global:101b1aac",
            "native_global:101b1ab0",
            "native_global:101b1ab4",
        ),
        "data": ("native_global:101b1ab8", "native_global:101b1abc"),
        "key": ("native_global:101b1ac0", "native_global:101b1ac4"),
        "saved": (
            "native_global:101c5d20",
            "native_global:101c5d24",
            "native_global:101c5d28",
        ),
    },
    NK_GTSPLUS: {
        "support": (
            "native_global:101bcba4",
            "native_global:101bcba8",
            "native_global:101bcbac",
            "native_global:101bcbb0",
            "native_global:101bcbb4",
        ),
        "data": ("native_global:101bcbb8", "native_global:101bcbbc"),
        "key": ("native_global:101bcbc0", "native_global:101bcbc4"),
        "saved": (
            "native_global:101dd628",
            "native_global:101dd62c",
            "native_global:101dd630",
        ),
    },
}
STR52_MANAGER104 = {
    NK18: 0x101506D0,
    NK12: 0x100EA940,
    NK_DS4: 0x101B66A4,
    NK_GTSPLUS: 0x101C17E0,
}


def _str52_u32(value: object, label: str) -> int:
    if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
        raise ValueError(f"Native STR52 {label} must be a DWORD")
    return value


def _str52_output(value: object, size: int, label: str) -> bytearray:
    if not isinstance(value, bytearray) or len(value) < size:
        raise ValueError(f"Native STR52 {label} needs {size} writable bytes")
    return value


def _str52_fields(context: UtilityExContext, name: str, args: tuple[object, ...]):
    keys = STR52_FIELDS[context.module_sha256][name]
    if len(args) != len(keys):
        raise ValueError(f"Native STR52 {name} argument count mismatch")
    _prepare_shared_fields(context, keys, args)
    return tuple(context.state[key] for key in keys)


def _str52_exchange(comm: UtilityExComm, context: UtilityExContext, request: bytes):
    delay = CONFIG_RVAS[context.module_sha256]["delay"]
    comm.configure(delay, 150)
    try:
        result = comm.exchange(request)
    except BaseException:
        with suppress(BaseException):
            comm.configure(delay, 100)
        raise
    else:
        comm.configure(delay, 100)
        return result


def _str52_cache_and_precheck(comm: UtilityExComm, context: UtilityExContext):
    delay = CONFIG_RVAS[context.module_sha256]["delay"]
    comm.configure(delay, 150)
    try:
        status = comm.refresh_support_cache(1)
        if status:
            result = (status, None)
        else:
            cached = comm.cached_support(1)
            if cached is None:
                result = (99, None)
            else:
                snapshot, offsets = cached
                result = (
                    (99, None)
                    if _support_position(snapshot, offsets, 0x12, 4, 0x02) is None
                    else (0, None)
                )
    except BaseException:
        with suppress(BaseException):
            comm.configure(delay, 100)
        raise
    comm.configure(delay, 100)
    return result


def _str52_minimum_exchange(
    comm: UtilityExComm,
    context: UtilityExContext,
    request: bytes,
    minimum: int,
    echo: int,
):
    delay = CONFIG_RVAS[context.module_sha256]["delay"]
    comm.configure(delay, 150)
    try:
        status, reply = comm.exchange(request)
    except BaseException:
        with suppress(BaseException):
            comm.configure(delay, 100)
        raise
    comm.configure(delay, 100)
    if status == 0 and (len(reply) < minimum or reply[1] != echo):
        return 3, reply
    return status, reply


def _str52_restore(comm: UtilityExComm, context: UtilityExContext) -> None:
    saved = STR52_FIELDS[context.module_sha256]["saved"]
    if context.state.get(saved[2]) != 1:
        return
    override, profile, _, _ = IMBI_SELECTION[context.module_sha256]
    first, second = context.state[saved[0]], context.state[saved[1]]
    failures = []
    for operation in (
        lambda: comm.configure(override, 0),
        lambda: comm.configure(profile, 0),
        lambda: comm.select_target(
            _str52_u32(first, "saved target"), _str52_u32(second, "saved target")
        ),
    ):
        try:
            operation()
        except BaseException as error:  # noqa: BLE001 - attempt every native restore step
            failures.append(error)
    context.state[saved[0]] = 0
    context.state[saved[1]] = 0
    context.state[saved[2]] = 0
    if failures:
        raise failures[0]


def _str52_cleanup(comm: UtilityExComm, context: UtilityExContext) -> None:
    failure = None
    try:
        comm.finalize()
    except BaseException as error:  # noqa: BLE001 - preserve the first host cleanup fault
        failure = error
    try:
        _str52_restore(comm, context)
    except BaseException as error:  # noqa: BLE001 - preserve the first host cleanup fault
        if failure is None:
            failure = error
    if failure is not None:
        raise failure


def _str52_body(
    export: str, arguments: tuple[object, ...], context: UtilityExContext
) -> int:
    fields = STR52_FIELDS[context.module_sha256]
    comm = context.comm("selected")
    keep = False
    cleaned = False
    try:
        if export == "Ex2STR_52_GetSupportInfo":
            seed, mode, data, clock, profile = _str52_fields(
                context, "support", arguments
            )
            seed = _str52_output(seed, 6, "seed output")
            data = _str52_output(data, 8, "data output")
            clock = _str52_output(clock, 4, "clock DWORD")
            mode = _str52_u32(mode, "mode")
            profile = _str52_u32(profile, "profile")
            if profile != 0x104:
                first, second = comm.read_target()
                first = _str52_u32(first, "current target")
                second = _str52_u32(second, "current target")
                context.state[fields["saved"][0]] = first
                context.state[fields["saved"][1]] = second
                context.state[fields["saved"][2]] = 1
                override, setter, _, _ = IMBI_SELECTION[context.module_sha256]
                comm.configure(override, STR52_MANAGER104[context.module_sha256])
                comm.configure(setter, 0x104)
                comm.select_target(0xC1, 0)
            status = comm.initialize(0)
            if status:
                return status
            status, _ = _str52_cache_and_precheck(comm, context)
            if status:
                return status
            status, reply = _str52_exchange(comm, context, b"\x21\x12")
            if status:
                return status
            if len(reply) < 2 or reply[1] != 0x12:
                return 3
            cached = comm.cached_support(1)
            if cached is None:
                raise ValueError("STR52 successful 21 12 lacks bounded cache backing")
            snapshot, offsets = cached
            position = _support_position(snapshot, offsets, 0x12, 4, 0)
            if position is None:
                raise ValueError("STR52 successful 21 12 has invalid metadata index")
            wire_count = position + 1
            if len(reply) < wire_count:
                return 3
            if not reply[wire_count - 1] & 2:
                return 4407
            clock[:4] = (context.ticks() & 0xFFFFFFFF).to_bytes(4, "little")
            status, reply = _str52_minimum_exchange(comm, context, b"\x21\0", 2, 0)
            if status:
                return status
            if mode != 1:
                keep = True
                return 4406
            status, reply = _str52_exchange(comm, context, b"\x1a\x84")
            if status:
                return status
            if len(reply) < 10 or reply[1] != len(reply) - 2:
                return 3
            data[:8] = reply[2:10]
            status, reply = _str52_minimum_exchange(comm, context, b"\x27\x07", 8, 7)
            if status:
                return status
            seed[:6] = reply[2:8]
            keep = True
            return 0
        if export == "Ex2STR_52_GetDataInfo":
            seed, data = _str52_fields(context, "data", arguments)
            seed = _str52_output(seed, 6, "seed output")
            data = _str52_output(data, 8, "data output")
            status, reply = _str52_exchange(comm, context, b"\x1a\x84")
            if status:
                return status
            if len(reply) < 10 or reply[1] != len(reply) - 2:
                return 3
            data[:8] = reply[2:10]
            status, reply = _str52_minimum_exchange(comm, context, b"\x27\x07", 8, 7)
            if status:
                return status
            seed[:6] = reply[2:8]
            keep = True
            return 0
        if export == "Ex2STR_52_KeepAlive":
            (clock,) = arguments
            clock = _str52_output(clock, 4, "clock DWORD")
            status = 99
            for _ in range(65536):
                if context.is_cancelled():
                    keep = True
                    return status
                now = context.ticks() & 0xFFFFFFFF
                then = int.from_bytes(clock[:4], "little")
                if (now - then) & 0xFFFFFFFF >= 3000:
                    clock[:4] = (context.ticks() & 0xFFFFFFFF).to_bytes(4, "little")
                    status, reply = _str52_minimum_exchange(
                        comm, context, b"\x21\0", 2, 0
                    )
                    if status:
                        return status
                else:
                    # Native loop is intentionally a tight poll with no Sleep.
                    continue
            raise TimeoutError("STR52 native keepalive exceeds host call budget")
        if export == "EX2STR_52_SendTheKey":
            key, length = _str52_fields(context, "key", arguments)
            length = _str52_u32(length, "key length")
            if (
                not isinstance(key, (bytes, bytearray))
                or length > 4126
                or len(key) < length
            ):
                raise ValueError(
                    "Native STR52 key backing must cover declared length <= 4126"
                )
            status, reply = _str52_exchange(
                comm, context, b"\x27\x08" + bytes(key[:length])
            )
            if status:
                return status
            if len(reply) != 3 or reply[1] != 8:
                return 3
            return 0 if reply[2] == 0x34 else 4405
        raise NotImplementedError(export)
    except BaseException:
        cleaned = True
        with suppress(BaseException):
            _str52_cleanup(comm, context)
        raise
    finally:
        if not keep and not cleaned:
            _str52_cleanup(comm, context)


def _end_factory_mode(arguments: tuple[object, ...], context: UtilityExContext) -> int:
    mode = _uint32_argument(arguments)
    comm = context.comm("selected")
    delay = CONFIG_RVAS[context.module_sha256]["delay"]
    try:
        context.native_sleep(100)
        comm.configure(delay, 150)
        try:
            length = context.state.get(STR41_LENGTH[context.module_sha256], 0)
            if type(length) is not int or not 0 <= length <= 0x101E:
                raise ValueError("Native STR41 command exceeds bounded backing")
            size = max(length + 2, 5 if mode == 1 else 3)
            request = b"\x3b\x01\x08" + bytes(size - 3)
            comm.configure(delay, 150)
            status, reply = comm.exchange(request)
            if status == 0 and (len(reply) != 2 or reply[1] != 1):
                return 3
            if status == 7 and len(reply) > 2 and reply[2] == 0x22:
                return 26
            return status
        finally:
            comm.configure(delay, 100)
    finally:
        comm.finalize()


def _str41_keepalive_check(
    export: str, arguments: tuple[object, ...], context: UtilityExContext
) -> int:
    if (
        len(arguments) != 1
        or not isinstance(arguments[0], bytearray)
        or len(arguments[0]) != 4
    ):
        raise ValueError("STR41 keepalive check requires a mutable timestamp DWORD")
    timestamp = arguments[0]
    checked = export == "Ex2STR_41_StartKeepAliveCheck"
    if checked and context.broker(0x70) != 0x11:
        return 99
    comm = context.comm("selected")
    delay = CONFIG_RVAS[context.module_sha256]["delay"]
    interval = 2000 if checked else 4000
    status = 99
    try:
        if context.is_cancelled():
            return status
        for _ in range(65536):
            tick = context.ticks()
            if type(tick) is not int or not 0 <= tick <= 0xFFFFFFFF:
                raise ValueError("STR41 keepalive tick must be uint32")
            if (tick - int.from_bytes(timestamp, "little")) & 0xFFFFFFFF >= interval:
                tick = context.ticks()
                if type(tick) is not int or not 0 <= tick <= 0xFFFFFFFF:
                    raise ValueError("STR41 keepalive tick must be uint32")
                timestamp[:] = tick.to_bytes(4, "little")
                if checked:
                    status, _ = _timed_minimum_exchange(comm, delay, b"\x21\0", 2, 0)
                    if status:
                        return 0x1016
                else:
                    comm.configure(delay, 150)
                    try:
                        status, _ = comm.exchange(b"\x3e")
                    finally:
                        comm.configure(delay, 100)
            if context.is_cancelled():
                return status
        raise TimeoutError("STR41 keepalive loop exceeds host primitive budget")
    except BaseException:
        comm.finalize()
        raise


def _prepare_shared_fields(
    context: UtilityExContext, keys: tuple[str, ...], fallback: tuple[object, ...]
) -> None:
    present = tuple(key in context.state for key in keys)
    if not any(present):
        context.state.update(zip(keys, fallback, strict=True))
    elif not all(present):
        raise ValueError("Native shared argument structure is partially initialized")


def _shared_output(context: UtilityExContext, key: str, size: int) -> bytearray:
    value = context.state[key]
    if not isinstance(value, bytearray) or len(value) != size:
        raise ValueError("Native shared output has an invalid mutable footprint")
    return value


def _str41_register(
    export: str, arguments: tuple[object, ...], context: UtilityExContext
) -> int:
    transponder = export == "Ex2STR_41_RegTransponderID"
    starting = export == "Ex2STR_41_StartCommunication"
    arity = 3 if transponder else 4 if starting else 2
    if len(arguments) != arity:
        raise ValueError("Native STR41 registration argument count mismatch")
    if transponder:
        mode, length = (
            _uint32_argument((arguments[0],)),
            _uint32_argument((arguments[1],)),
        )
        clock, mode_output = arguments[2], None
        fields = (mode, 0, length, clock)
    elif starting:
        length, mode = (
            _uint32_argument((arguments[0],)),
            _uint32_argument((arguments[3],)),
        )
        clock, mode_output = arguments[1:3]
        fields = (mode, mode_output, length, clock)
    else:
        mode = _uint32_argument((arguments[1],))
        mode_output, clock, length = arguments[0], None, None
        fields = (mode, mode_output, 0, 0)
    base = STR41_REGISTER_ARGUMENT_BASE[context.module_sha256]
    field_keys = tuple(f"native_global:{base + index * 4:x}" for index in range(4))
    _prepare_shared_fields(context, field_keys, fields)
    mode = _uint32_argument((context.state[field_keys[0]],))
    length = context.state[field_keys[2]]
    clock, mode_output = context.state[field_keys[3]], context.state[field_keys[1]]
    if context.mode != 4:
        return 99
    if (starting or (transponder and mode == 1)) and (
        not isinstance(clock, bytearray) or len(clock) != 4
    ):
        raise ValueError("STR41 native timestamp requires a mutable DWORD")
    if not transponder and (
        not isinstance(mode_output, bytearray) or len(mode_output) != 4
    ):
        raise ValueError("STR41 registration mode requires a mutable DWORD")
    sha = context.module_sha256
    if starting or (transponder and mode == 1):
        context.state[STR41_LENGTH[sha]] = length
    comm = context.comm("selected")
    delay = CONFIG_RVAS[sha]["delay"]
    keep = False

    def command() -> int:
        mode = _uint32_argument((context.state[field_keys[0]],))
        size = context.state.get(STR41_LENGTH[sha], 0)
        if type(size) is not int or not 0 <= size <= 0x101E:
            raise ValueError(
                "STR41 native command length crosses bounded 4128-byte backing"
            )
        size = max(size + 2, 5 if mode == 1 else 3)
        request = bytearray(size)
        request[:2] = b"\x3b\x01"
        request[4 if mode == 1 else 2] = (
            (0x40 if mode == 1 else 0x20)
            if transponder
            else (0x80 if mode == 1 else 0x40)
        )
        comm.configure(delay, 150)
        try:
            if not transponder:
                comm.configure(delay, 150)
            status, reply = comm.exchange(bytes(request))
            if transponder:
                if status in (2, 5):
                    return status
                return (
                    0 if status == 0 and len(reply) == 2 and reply[1] == 1 else 0x100A
                )
            if status == 2:
                return 0x1011
            if status == 0 and (len(reply) != 2 or reply[1] != 1):
                return 3
            return status
        finally:
            comm.configure(delay, 100)

    def register_key() -> int:
        context.native_sleep(100)
        status, reply = _timed_minimum_exchange(comm, delay, b"\x21\x14", 3, 0x14)
        if status:
            return status
        key = STR41_COUNTERS[sha][0]
        previous = context.state.get(key, 0)
        if type(previous) is not int or not 0 <= previous <= 0xFFFFFFFF:
            raise ValueError("STR41 native key counts require packed DWORD")
        context.state[key] = (
            (previous & 0xFFFF0000) | (reply[2] >> 4) | ((reply[2] & 15) << 8)
        )
        context.native_sleep(100)
        status = command()
        if status in (0, 0x1011):
            return status
        context.native_sleep(100)
        status, reply = _timed_minimum_exchange(comm, delay, b"\x21\x16", 3, 0x16)
        if status:
            return status
        value = int(bool(reply[2] & 0x20))
        context.state[STR41_MODE[sha]] = value
        _shared_output(context, field_keys[1], 4)[:] = value.to_bytes(4, "little")
        return 0x1010

    try:
        if context.is_cancelled():
            return 99
        if transponder or starting:
            if starting:
                context.sleep(100)
            else:
                context.native_sleep(100)
            status = comm.initialize(0)
            if status:
                keep = starting and status in (0x1010, 0x1011)
                return status
            if transponder:
                context.native_sleep(100)
                status = command()
                if status:
                    return status
                if _uint32_argument((context.state[field_keys[0]],)) != 1:
                    keep = True
                    return 0
            tick = context.ticks()
            if type(tick) is not int or not 0 <= tick <= 0xFFFFFFFF:
                raise ValueError("Native STR41 timestamp must be uint32")
            _shared_output(context, field_keys[3], 4)[:] = tick.to_bytes(4, "little")
            status, _ = _timed_minimum_exchange(comm, delay, b"\x21\0", 2, 0)
            if status:
                keep = not transponder and status in (0x1010, 0x1011)
                return status
            if transponder:
                keep = True
                return 0
        status = register_key()
        keep = status in (0, 0x1010, 0x1011)
        return status
    finally:
        if not keep:
            comm.finalize()


def _str41_repeat_status(
    arguments: tuple[object, ...], context: UtilityExContext
) -> int:
    if len(arguments) != 3 or any(
        not isinstance(value, bytearray) or len(value) != size
        for value, size in zip(arguments, (4, 1, 1))
    ):
        raise ValueError("STR41 status repeat requires mutable DWORD, byte and byte")
    output, master, secondary = arguments
    assert (
        isinstance(output, bytearray)
        and isinstance(master, bytearray)
        and isinstance(secondary, bytearray)
    )
    output_keys = STR41_STATUS_ARGUMENTS[context.module_sha256]
    _prepare_shared_fields(context, output_keys, arguments)
    if context.mode != 4:
        return 99
    comm = context.comm("selected")
    delay = CONFIG_RVAS[context.module_sha256]["delay"]
    key, tail = STR41_COUNTERS[context.module_sha256]
    mode_key = STR41_MODE[context.module_sha256]
    status, supported = 99, False
    keep = False
    host_failure = True

    def packed_counts() -> int:
        value = context.state.get(key, 0)
        if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
            raise ValueError("STR41 native key counts require packed DWORD")
        return value

    def query_counts() -> int:
        context.sleep(100)
        result, reply = _timed_minimum_exchange(comm, delay, b"\x21\x14", 3, 0x14)
        if result == 0:
            context.state[key] = (
                (packed_counts() & 0xFFFF)
                | ((reply[2] >> 4) << 16)
                | ((reply[2] & 15) << 24)
            )
        return result

    try:
        if context.is_cancelled():
            keep = True
        else:
            for _ in range(65536):
                status = query_counts()
                if status:
                    keep = status in (0x1012, 0x1013)
                    break
                counts = packed_counts()
                increased = (counts & 255) < ((counts >> 16) & 255) or (
                    (counts >> 8) & 255
                ) < ((counts >> 24) & 255)
                if not increased:
                    if context.is_cancelled():
                        keep = True
                        break
                    context.sleep(100)
                    status, reply = _timed_minimum_exchange(
                        comm, delay, b"\x21\x12", 3, 0x12
                    )
                    if status:
                        keep = status in (0x1012, 0x1013)
                        break
                    supported = not bool(reply[2] & 1)
                if increased or not supported:
                    if not supported:
                        status = query_counts()
                        if status:
                            keep = status in (0x1012, 0x1013)
                            break
                    context.sleep(100)
                    status, reply = _timed_minimum_exchange(
                        comm, delay, b"\x21\x15", 3, 0x15
                    )
                    if status:
                        keep = status in (0x1012, 0x1013)
                        break
                    current = (reply[2] >> 4) | ((reply[2] & 15) << 8)
                    tail_value = context.state.get(tail, 0)
                    if type(tail_value) is not int or not 0 <= tail_value <= 0xFFFFFFFF:
                        raise ValueError(
                            "STR41 native count tail requires a DWORD backing"
                        )
                    context.state[tail] = (tail_value & 0xFFFF0000) | current
                    counts = packed_counts()
                    if counts >> 16 != current:
                        context.state[key] = (counts & 0xFFFF0000) | (counts >> 16)
                        status = 0x1013
                    _shared_output(context, output_keys[1], 1)[0] = (
                        packed_counts() & 255
                    )
                    _shared_output(context, output_keys[2], 1)[0] = (
                        packed_counts() >> 8
                    ) & 255
                    keep = True
                    break
                if context.is_cancelled():
                    keep = True
                    break
                context.sleep(100)
                status, reply = _timed_minimum_exchange(
                    comm, delay, b"\x21\x16", 3, 0x16
                )
                if status:
                    keep = status in (0x1012, 0x1013)
                    break
                mode = int(bool(reply[2] & 0x20))
                context.state[mode_key] = mode
                _shared_output(context, output_keys[0], 4)[:] = mode.to_bytes(
                    4, "little"
                )
                if mode == 0:
                    status = 0x1012
                    keep = True
                    break
                if context.is_cancelled():
                    keep = True
                    break
            else:
                raise TimeoutError("STR41 status polling exceeds host primitive budget")
        host_failure = False
        return status
    finally:
        if host_failure or (not keep and not context.is_cancelled()):
            comm.finalize()


def _str41_repeat_mode(arguments: tuple[object, ...], context: UtilityExContext) -> int:
    if len(arguments) != 2 or any(
        not isinstance(value, bytearray) or len(value) != 4 for value in arguments
    ):
        raise ValueError("STR41 repeat mode requires two mutable DWORD outputs")
    output, kind = arguments
    assert isinstance(output, bytearray) and isinstance(kind, bytearray)
    output_keys = STR41_REPEAT_ARGUMENTS[context.module_sha256]
    _prepare_shared_fields(context, output_keys, arguments)
    if context.mode != 4:
        return 99
    comm = context.comm("selected")
    delay = CONFIG_RVAS[context.module_sha256]["delay"]
    mode_key = STR41_MODE[context.module_sha256]
    context.state[mode_key] = 1
    _shared_output(context, output_keys[0], 4)[:] = (1).to_bytes(4, "little")
    status = 99
    host_failure = True
    try:
        if not context.is_cancelled():
            for _ in range(65536):
                if context.state.get(mode_key) != 1:
                    break
                context.sleep(100)
                status, reply = _timed_minimum_exchange(
                    comm, delay, b"\x21\x16", 3, 0x16
                )
                if status:
                    break
                mode = int(bool(reply[2] & 0x20))
                context.state[mode_key] = mode
                _shared_output(context, output_keys[0], 4)[:] = mode.to_bytes(
                    4, "little"
                )
                if mode == 0:
                    context.sleep(100)
                    status, reply = _timed_minimum_exchange(
                        comm, delay, b"\x21\x14", 3, 0x14
                    )
                    if status:
                        break
                    previous = context.state.get(
                        STR41_COUNTERS[context.module_sha256][0], 0
                    )
                    if type(previous) is not int or not 0 <= previous <= 0xFFFFFFFF:
                        raise ValueError("STR41 packed native counts require a DWORD")
                    if previous & 255 < reply[2] >> 4:
                        _shared_output(context, output_keys[1], 4)[:] = (1).to_bytes(
                            4, "little"
                        )
                    elif (previous >> 8) & 255 < reply[2] & 15:
                        _shared_output(context, output_keys[1], 4)[:] = bytes(4)
                    else:
                        status = 0x100D
                    break
                if context.is_cancelled():
                    break
            else:
                raise TimeoutError("STR41 mode polling exceeds host primitive budget")
        host_failure = False
        return status
    finally:
        if host_failure or not context.is_cancelled():
            comm.finalize()


def _str41_query(
    export: str, arguments: tuple[object, ...], context: UtilityExContext
) -> int:
    mode = export == "Ex2STR_41_GetCurrentMode"
    count = export == "Ex2STR_41_GetRegKeyNum"
    if mode:
        if (
            len(arguments) != 1
            or not isinstance(arguments[0], bytearray)
            or len(arguments[0]) != 4
        ):
            raise ValueError("STR41 current mode requires a mutable DWORD")
    elif arguments:
        raise ValueError("STR41 status and key-count queries take no arguments")
    comm = context.comm("selected")
    delay = CONFIG_RVAS[context.module_sha256]["delay"]
    keep = False
    try:
        context.native_sleep(100)
        if mode or count:
            selector = 0x16 if mode else 0x14
            status, reply = _timed_minimum_exchange(
                comm, delay, bytes((0x21, selector)), 3, selector
            )
            if count:
                result = (
                    (0x100F if reply[2] & 0xF0 else 0x100E) if status == 0 else status
                )
                keep = result in (0x100E, 0x100F)
                return result
            if status:
                return status
            value = int(bool(reply[2] & 0x20))
            context.state[STR41_MODE[context.module_sha256]] = value
            output = arguments[0]
            assert isinstance(output, bytearray)
            output[:] = value.to_bytes(4, "little")
            keep = True
            return 0
        status, reply = _timed_minimum_exchange(comm, delay, b"\x21\x12", 3, 0x12)
        if status:
            return status
        if reply[2] & 1:
            return 0x100B
        context.native_sleep(100)
        status, reply = _timed_minimum_exchange(comm, delay, b"\x21\x13", 4, 0x13)
        if status:
            return status
        if reply[3] & 0x80:
            return 0x100C
        context.native_sleep(100)
        status, reply = _timed_minimum_exchange(comm, delay, b"\x21\x14", 3, 0x14)
        if status:
            return status
        key = STR41_COUNTERS[context.module_sha256][0]
        previous = context.state.get(key, 0)
        if type(previous) is not int or not 0 <= previous <= 0xFFFFFFFF:
            raise ValueError("STR41 packed native key counts require a DWORD")
        context.state[key] = (
            (previous & 0xFFFF0000) | (reply[2] >> 4) | ((reply[2] & 15) << 8)
        )
        keep = True
        return 0
    finally:
        if not keep:
            comm.finalize()


def _str41_support(arguments: tuple[object, ...], context: UtilityExContext) -> int:
    if len(arguments) != 3 or any(
        not isinstance(value, bytearray) or len(value) != size
        for value, size in zip(arguments, (4, 4, 1))
    ):
        raise ValueError("STR41 support requires mutable DWORD, DWORD and byte outputs")
    first, size_output, raw_output = arguments
    assert isinstance(first, bytearray)
    assert isinstance(size_output, bytearray)
    assert isinstance(raw_output, bytearray)
    comm = context.comm("selected")
    sha = context.module_sha256
    delay = CONFIG_RVAS[sha]["delay"]
    mode_key, length_key = STR41_MODE[sha], STR41_LENGTH[sha]
    count_key, count_tail = STR41_COUNTERS[sha]
    context.state[count_key] = 0
    tail_value = context.state.get(count_tail, 0)
    if type(tail_value) is not int or not 0 <= tail_value <= 0xFFFFFFFF:
        raise ValueError("STR41 native count tail requires a DWORD backing")
    context.state[count_tail] = tail_value & 0xFFFF0000
    raw = 0
    online = False

    def scan(kind: int) -> tuple[int, bytes, tuple[int, ...]]:
        comm.configure(delay, 150)
        try:
            return comm.support_snapshot(kind)
        finally:
            comm.configure(delay, 100)

    def perform() -> int:
        nonlocal raw, online
        status = comm.initialize(0)
        if status:
            return status
        context.native_sleep(100)
        status, data, offsets = scan(1)
        if status:
            return status
        for selector, required, mask in (
            (0x12, 3, 1),
            (0x13, 3, 0x80),
            (0x13, 4, 0x80),
            (0x14, 3, 0xFF),
            (0x15, 3, 0xFF),
            (0x16, 3, 0x20),
        ):
            if _support_position(data, offsets, selector, required, mask) is None:
                return 0x1005
        extended = _support_position(data, offsets, 0x12, 4, 2) is not None
        context.native_sleep(100)
        status, data, offsets = scan(3)
        if status:
            return status
        if not extended and any(
            _support_position(data, offsets, 1, 3, mask) is None for mask in (0x20, 8)
        ):
            return 0x1006
        offset = offsets[1]
        if offset != 0x1020:
            if offset + 1 >= len(data):
                raise ValueError("Native STR41 command length crosses host backing")
            context.state[length_key] = data[offset + 1]
        registration = _support_position(data, offsets, 1, 3, 0x40) is not None
        context.native_sleep(100)
        if extended:
            status, reply = _timed_minimum_exchange(comm, delay, b"\x21\x12", 4, 0x12)
            if status:
                return status
            online = bool(reply[3] & 2)
        context.native_sleep(100)
        if registration or online:
            status, reply = _timed_minimum_exchange(comm, delay, b"\x21\x16", 3, 0x16)
            if status:
                return status
            context.state[mode_key] = int(bool(reply[2] & 0x20))
            context.native_sleep(100)
            status, reply = _timed_minimum_exchange(comm, delay, b"\x21\x14", 3, 0x14)
            if status:
                return status
            raw = reply[2]
            mode = context.state.get(mode_key, 0)
            if type(mode) is not int or not 0 <= mode <= 0xFFFFFFFF:
                raise ValueError("STR41 native mode requires a DWORD")
            if mode == 1:
                context.state[count_key] = (raw >> 4) | ((raw & 15) << 8)
            first[:] = mode.to_bytes(4, "little")
            raw_output[0] = raw
            return 0
        status, reply = _timed_minimum_exchange(comm, delay, b"\x21\x14", 3, 0x14)
        if status:
            return status
        raw = reply[2]
        return 0x1015 if raw else 0x1008

    try:
        status = perform()
        if context.state.get(mode_key, 0) == 0 and raw:
            comm.finalize()
        if online and status == 0:
            length = context.state.get(length_key, 0)
            if type(length) is not int or not 0 <= length <= 0x101E:
                raise ValueError("Native STR41 command exceeds bounded backing")
            size_output[:] = length.to_bytes(4, "little")
            return 0x1014
        return status
    except BaseException:
        comm.finalize()
        raise


def _str42_support(context: UtilityExContext) -> int:
    comm = context.comm("selected")
    delay = CONFIG_RVAS[context.module_sha256]["delay"]
    try:
        status = comm.initialize(0)
        if status:
            return status
        context.native_sleep(100)
        comm.configure(delay, 150)
        try:
            status, data, offsets = comm.support_snapshot(1)
            if status:
                return status
            if (
                _support_position(data, offsets, 0x14, 3, 0xFF) is None
                or _support_position(data, offsets, 0x16, 3, 0x20) is None
            ):
                return 700
        finally:
            comm.configure(delay, 100)
        context.native_sleep(100)
        comm.configure(delay, 150)
        try:
            status, data, offsets = comm.support_snapshot(3)
            if status:
                return status
            position = _support_position(data, offsets, 1, 3, 0x80)
            offset = offsets[1]
            if offset + 1 >= len(data):
                raise ValueError("Native STR42 support length crosses the host backing")
            context.state[STR42_LENGTH[context.module_sha256]] = data[offset + 1]
            return 0 if position is not None else 701
        finally:
            comm.configure(delay, 100)
    finally:
        comm.finalize()


def _str42_erase(context: UtilityExContext) -> int:
    comm = context.comm("selected")
    delay = CONFIG_RVAS[context.module_sha256]["delay"]
    keep_open = False
    try:
        context.native_sleep(100)
        status = comm.initialize(0)
        if status:
            return status
        context.native_sleep(100)
        length = context.state.get(STR42_LENGTH[context.module_sha256], 0)
        if type(length) is not int or not 0 <= length <= 255:
            raise ValueError("Native STR42 support length must retain its byte origin")
        request = b"\x3b\x01" + (b"\x80" + bytes(length - 1) if length else b"")
        comm.configure(delay, 150)
        try:
            status, reply = comm.exchange(request)
            if status == 0 and (len(reply) != 2 or reply[1] != 1):
                status = 3
        finally:
            comm.configure(delay, 100)
        keep_open = status == 0
        return status
    finally:
        if not keep_open:
            comm.finalize()


def _str42_condition(context: UtilityExContext) -> int:
    comm = context.comm("selected")
    delay = CONFIG_RVAS[context.module_sha256]["delay"]
    try:
        context.native_sleep(100)
        comm.configure(delay, 150)
        try:
            # Host call budget bounds the native uncancellable direct polling loop.
            for _ in range(65536):
                status, reply = comm.exchange(b"\x21\x16")
                if status:
                    return 702 if status == 2 else 703
                if len(reply) < 3 or reply[1] != 0x16:
                    return 703
                if not reply[2] & 0x20:
                    break
                context.native_sleep(100)
            else:
                raise TimeoutError(
                    "STR42 native condition polling exceeds host call budget"
                )
        finally:
            comm.configure(delay, 100)
        context.native_sleep(100)
        comm.configure(delay, 150)
        try:
            status, reply = comm.exchange(b"\x21\x14")
            if status:
                return status
            if len(reply) < 3 or reply[1] != 0x14:
                return 3
            return 0 if reply[2] == 0x10 else 704
        finally:
            comm.configure(delay, 100)
    finally:
        comm.finalize()


def _cylinder_count(
    export: str, arguments: tuple[object, ...], context: UtilityExContext
) -> int:
    dword = export != "Ex2ECD_22_GetCylinderNum"
    size = 4 if dword else 1
    timed = export != "Ex2ECD_17_ReadCylinderInfo"
    unsupported = {
        "Ex2ECD_13_ReadCylinderInfo": 1300,
        "Ex2ECD_17_ReadCylinderInfo": 1700,
        "Ex2ECD_22_GetCylinderNum": 1501,
    }[export]
    invalid = unsupported + 1 if dword else 3
    if (
        len(arguments) != 1
        or not isinstance(arguments[0], bytearray)
        or len(arguments[0]) != size
    ):
        raise ValueError(
            f"Native cylinder output requires a {size}-byte mutable buffer"
        )
    output = arguments[0]
    comm = context.comm("selected")
    delay = CONFIG_RVAS[context.module_sha256]["delay"]
    try:
        status = comm.initialize(0)
        if status:
            return status
        if timed:
            comm.configure(delay, 150)
        try:
            status, data, offsets = comm.support_snapshot(1)
            if status:
                return status
            position = _support_position(data, offsets, 0xC1, 16, 0xFF)
            if position is None:
                return unsupported
        finally:
            if timed:
                comm.configure(delay, 100)
        if timed:
            comm.configure(delay, 150)
        try:
            status, reply = comm.exchange(b"\x21\xc1")
            if status:
                return status
            if len(reply) <= position or reply[1] != 0xC1:
                return 3
            if reply[position] not in ((4, 6, 8) if dword else (3, 4, 6, 8)):
                return invalid
            output[:] = reply[position].to_bytes(size, "little")
            return 0
        finally:
            if timed:
                comm.configure(delay, 100)
    finally:
        comm.finalize()


def _str43_security(
    export: str, arguments: tuple[object, ...], context: UtilityExContext
) -> int:
    requesting = export == "Ex2STR_43_ReqSecuritySeed"
    if len(arguments) != (2 if requesting else 3):
        raise ValueError("Native STR43 security argument arity mismatch")
    bases = {
        NK12: (0x100E5D20, 0x100E5D00),
        NK18: (0x1014A758, 0x1014A728),
        NK_DS4: (0x101B1A90, 0x101B1A98),
        NK_GTSPLUS: (0x101BCB90, 0x101BCB98),
    }
    base = bases[context.module_sha256][0 if requesting else 1]
    keys = tuple(
        f"native_global:{base + index * 4:08x}" for index in range(len(arguments))
    )
    _prepare_shared_fields(context, keys, arguments)
    if context.mode != 4:
        return 99
    comm = context.comm("selected")
    delay = CONFIG_RVAS[context.module_sha256]["delay"]
    keep = False

    def buffer(index: int, size: int, mutable: bool = True) -> bytes | bytearray:
        value = context.state[keys[index]]
        if (
            not isinstance(value, (bytes, bytearray))
            or len(value) < size
            or (mutable and not isinstance(value, bytearray))
        ):
            raise ValueError("Native STR43 security buffer has an invalid footprint")
        return value

    try:
        if context.is_cancelled():
            return 99
        context.sleep(100)
        if requesting:
            status = comm.initialize(0)
            if status:
                keep = status == 4309
                return status
            context.sleep(100)
            mode_out = buffer(1, 4)
            assert isinstance(mode_out, bytearray)
            mode_out[:4] = (431).to_bytes(4, "little")
            status, reply = _timed_minimum_exchange(comm, delay, b"\x21\x12", 3, 0x12)
            if status == 0:
                if not reply[2] & 0x80:
                    status = 4308
                elif (
                    _str43_global_byte(context, option=True) & 0xC0 == 0xC0
                    and len(reply) > 3
                    and reply[3] & 0xC0 == 0x80
                ):
                    mode_out[:4] = (432).to_bytes(4, "little")
            if status:
                keep = status == 4309
                return status
            context.sleep(100)
            seed = buffer(0, 6)
            assert isinstance(seed, bytearray)
            seed[:4] = bytes(4)
            status, reply = _timed_exchange(comm, delay, b"\x27\x05", 8, 5)
            if status == 0:
                seed[:6] = reply[2:8]
                status = 4309
            keep = status == 4309
            return status
        mode = _uint32_argument((context.state[keys[1]],))
        if mode == 1:
            length = _uint32_argument((context.state[keys[2]],))
            _str43_global_byte(context, option=False, value=length)
        else:
            key = buffer(0, 6, False)
            status, reply = _timed_exchange(
                comm, delay, b"\x27\x06" + bytes(key[:6]), 3, 6
            )
            if status:
                return status
            if reply[2] != 0x34:
                return 22
        context.sleep(100)
        mode = _uint32_argument((context.state[keys[1]],))
        length = _str43_global_byte(context, option=False)
        request = bytearray(max(length + 2, 5 if mode == 1 else 4))
        request[:4] = b"\x3b\x01" + (b"\0\3" if mode == 1 else b"\4\3")
        if mode == 1:
            request[4] = 8
        status, _ = _timed_exchange(comm, delay, bytes(request), 2, 1)
        if status:
            return 4304
        context.sleep(100)
        status = _str43_query(context, comm, True)
        keep = status == 0
        return status
    finally:
        if not keep:
            comm.finalize()


def _str43_global_byte(
    context: UtilityExContext, *, option: bool, value: int | None = None
) -> int:
    sha = context.module_sha256
    if sha in (NK_DS4, NK_GTSPLUS):
        key, shift = STR41_COUNTERS[sha][1], 24 if option else 16
    elif sha == NK12:
        key, shift = "native_global:100f5b58", 0 if option else 8
    else:
        key, shift = (
            ("native_global:1015eb40" if option else "native_global:1015eb48"),
            0,
        )
    previous = context.state.get(key, 0)
    if type(previous) is not int or not 0 <= previous <= 0xFFFFFFFF:
        raise ValueError("Native STR43 shared global requires a DWORD backing")
    if value is not None:
        context.state[key] = (previous & ~(255 << shift)) | ((value & 255) << shift)
        return value & 255
    return (previous >> shift) & 255


def _str43_support(arguments: tuple[object, ...], context: UtilityExContext) -> int:
    if len(arguments) != 4 or any(
        not isinstance(value, bytearray) or len(value) < size
        for value, size in zip(arguments, (4, 4, 1, 1))
    ):
        raise ValueError("Native STR43 support requires two DWORD and two byte outputs")
    first, extended_out, option_out, registration_out = arguments
    assert all(isinstance(value, bytearray) for value in arguments)
    assert isinstance(first, bytearray) and isinstance(extended_out, bytearray)
    assert isinstance(option_out, bytearray) and isinstance(registration_out, bytearray)
    comm = context.comm("selected")
    delay = CONFIG_RVAS[context.module_sha256]["delay"]

    def scan(kind: int) -> tuple[int, bytes, tuple[int, ...]]:
        comm.configure(delay, 150)
        try:
            return comm.support_snapshot(kind)
        finally:
            comm.configure(delay, 100)

    def perform() -> int:
        status = comm.initialize(0)
        if status:
            return status
        context.native_sleep(100)
        status, data, offsets = scan(1)
        if status:
            return status
        if any(
            _support_position(data, offsets, selector, 3, mask) is None
            for selector, mask in ((0x12, 0x80), (0x14, 0xFF), (0x16, 0x20))
        ):
            return 4303
        extended = _support_position(data, offsets, 0x12, 4, 2) is not None
        if extended:
            option_out[0] = 2
        if _support_position(data, offsets, 0x12, 4, 0) is not None:
            _str43_global_byte(context, option=True, value=data[offsets[0x12] + 3])
        if extended:
            extended_out[:4] = (1).to_bytes(4, "little")
        context.native_sleep(100)
        status, data, offsets = scan(3)
        if status:
            return status
        if (
            _support_position(data, offsets, 1, 3, 4) is None
            and int.from_bytes(extended_out[:4], "little") == 0
        ):
            return 4303
        offset = offsets[1]
        if offset != 0x1020:
            _str43_global_byte(context, option=False, value=data[offset + 1])
        if _support_position(data, offsets, 1, 4, 0xFF) is None:
            return 4303
        if _support_position(data, offsets, 1, 3, 0x40) is not None:
            registration_out[0] = 0x40
            return 4302
        return 4301

    try:
        status = perform()
        first[:4] = _str43_global_byte(context, option=False).to_bytes(4, "little")
        return status
    finally:
        comm.finalize()


def _str53_poll(
    export: str, arguments: tuple[object, ...], context: UtilityExContext
) -> int:
    switch = export == "Ex2STR_53_GetKeySWStatus"
    exiting = export == "Ex2STR_53_GetImmobilizerMode_OnExit"
    immobilizer = export == "Ex2STR_53_GetImmobilizerMode"
    if (
        len(arguments) != (1 if switch or exiting else 3)
        or not isinstance(arguments[0], bytearray)
        or len(arguments[0]) != 4
        or any(not isinstance(value, bytearray) or not value for value in arguments[1:])
    ):
        raise ValueError(
            "Native STR53 worker requires clock DWORD and optional byte outputs"
        )
    if not (switch or exiting):
        base = {
            NK12: 0x100E5D58,
            NK18: 0x1014A7B0,
            NK_DS4: 0x101B1AD0,
            NK_GTSPLUS: 0x101BCBD0,
        }[context.module_sha256]
        field_keys = tuple(
            f"native_global:{base + index * 4:08x}" for index in range(3)
        )
        _prepare_shared_fields(context, field_keys, arguments)
        arguments = tuple(context.state[key] for key in field_keys)
    if context.mode != 4:
        return 99
    clock = arguments[0]
    assert isinstance(clock, bytearray)
    comm = context.comm("selected")
    delay = CONFIG_RVAS[context.module_sha256]["delay"]
    status, keep = 99, False
    try:
        if context.is_cancelled():
            return status
        for _ in range(65536):
            now = context.ticks() & 0xFFFFFFFF
            if (now - int.from_bytes(clock, "little")) & 0xFFFFFFFF >= 1000:
                status, reply = _timed_minimum_exchange(
                    comm, delay, b"\x21\x16", 3, 0x16
                )
                clock[:] = (context.ticks() & 0xFFFFFFFF).to_bytes(4, "little")
                if status:
                    keep = not (immobilizer or exiting) and status == 4501
                    return status
                if immobilizer and not reply[2] & 0x20:
                    return 4502
            if not exiting:
                retry = False
                if not immobilizer:
                    status, reply = _timed_minimum_exchange(
                        comm, delay, b"\x21\x11", 3, 0x11
                    )
                    if status:
                        keep = status == 4501
                        return status
                    retry = bool(reply[2] & 0x20) == switch
                    if retry:
                        status = 4501
                    elif switch:
                        keep = True
                        return 0
                if not retry:
                    status, reply = _timed_minimum_exchange(
                        comm, delay, b"\x21\x17", 3, 0x17
                    )
                    if status:
                        keep = not immobilizer and status == 4501
                        return status
                    high, low = arguments[1:]
                    assert isinstance(high, bytearray) and isinstance(low, bytearray)
                    high[0] = reply[2] >> 4
                    low[0] = reply[2] & 15
                    if not immobilizer:
                        keep = True
                        return 0
            if context.is_cancelled():
                keep = status == 0 if exiting else True
                return status
        raise TimeoutError("STR53 native polling exceeds host call budget")
    finally:
        if not keep:
            comm.finalize()


def _str53_single(
    export: str, arguments: tuple[object, ...], context: UtilityExContext
) -> int:
    switch = export == "Ex2STR_53_GetKeySWStatus_Single"
    immobilizer = export == "Ex2STR_53_GetImmobilizerMode_Single"
    if (
        len(arguments) != (1 if switch else 3)
        or not isinstance(arguments[0], bytearray)
        or len(arguments[0]) != 4
        or any(not isinstance(value, bytearray) or not value for value in arguments[1:])
    ):
        raise ValueError(
            "Native STR53 single query requires clock DWORD and optional byte outputs"
        )
    clock = arguments[0]
    assert isinstance(clock, bytearray)
    comm = context.comm("selected")
    delay = CONFIG_RVAS[context.module_sha256]["delay"]
    keep = False
    try:
        if context.is_cancelled():
            return 99
        now = context.ticks() & 0xFFFFFFFF
        if (now - int.from_bytes(clock, "little")) & 0xFFFFFFFF >= 1000:
            status, reply = _timed_minimum_exchange(comm, delay, b"\x21\x16", 3, 0x16)
            clock[:] = (context.ticks() & 0xFFFFFFFF).to_bytes(4, "little")
            if status:
                return status
            if immobilizer and not reply[2] & 0x20:
                return 4502
        if not immobilizer:
            status, reply = _timed_minimum_exchange(comm, delay, b"\x21\x11", 3, 0x11)
            if status:
                return status
            if bool(reply[2] & 0x20) == switch:
                return 4501
            if switch:
                keep = True
                return 0
        status, reply = _timed_minimum_exchange(comm, delay, b"\x21\x17", 3, 0x17)
        if status:
            return status
        high, low = arguments[1:]
        assert isinstance(high, bytearray) and isinstance(low, bytearray)
        high[0] = reply[2] >> 4
        low[0] = reply[2] & 15
        keep = not immobilizer
        return 0
    finally:
        if not keep:
            comm.finalize()


def _reductant_support(context: UtilityExContext) -> int:
    comm = context.comm("selected")
    delay = CONFIG_RVAS[context.module_sha256]["delay"]
    try:
        status = comm.initialize(0)
        if status:
            return status
        for kind, selector, fields, mask, failure in (
            (1, 0x4B, (5, 6, 7, 8), 0xFF, 3011),
            (2, 0x50, (3, 4), 0x44, 3012),
        ):
            comm.configure(delay, 150)
            try:
                status = comm.refresh_support_cache(kind)
                if status:
                    return status
                snapshot = comm.cached_support(kind)
                if snapshot is None:
                    return failure
                data, offsets = snapshot
                for field in fields:
                    if _support_position(data, offsets, selector, field, mask) is None:
                        return failure
            finally:
                comm.configure(delay, 100)
        return 0
    finally:
        comm.finalize()


def _switch_key_registration(
    arguments: tuple[object, ...], context: UtilityExContext
) -> int:
    if (
        len(arguments) != 1
        or not isinstance(arguments[0], bytearray)
        or len(arguments[0]) != 16
    ):
        raise ValueError("Native STR20 key registration requires four mutable DWORDs")
    record = arguments[0]
    comm = context.comm("selected")
    status = 0
    try:
        for _ in range(65536):
            if context.is_cancelled():
                return status
            context.sleep(1000)
            if context.is_cancelled():
                return status
            master, secondary = bytearray(4), bytearray(4)
            status = _switch_counts(
                "Ex2STR_20_GetTheKeyNumber", (master, secondary), context
            )
            if status:
                return status
            if int.from_bytes(record[8:12], "little") < int.from_bytes(
                master, "little"
            ) or int.from_bytes(record[12:16], "little") < int.from_bytes(
                secondary, "little"
            ):
                record[:4] = master
                record[4:8] = secondary
                return 0
            if context.is_cancelled():
                return status
            status, reply = _timed_minimum_exchange(
                comm, CONFIG_RVAS[context.module_sha256]["delay"], b"\x21\x22", 3, 0x22
            )
            if status == 0 and not reply[2] & 0x80:
                status = 503
            if status:
                return status
            if context.is_cancelled():
                return 0
        raise TimeoutError("STR20 key registration exceeds host call budget")
    except BaseException:
        comm.finalize()
        raise


def _switch_counts(
    export: str, arguments: tuple[object, ...], context: UtilityExContext
) -> int:
    if len(arguments) != 2 or any(
        not isinstance(value, bytearray) or len(value) != 4 for value in arguments
    ):
        raise ValueError("Native switch key counts require two mutable DWORD outputs")
    master, secondary = arguments
    assert isinstance(master, bytearray) and isinstance(secondary, bytearray)
    older = export == "Ex2STR_20_GetTheKeyNumber"
    comm = context.comm("selected")
    keep = older
    try:
        status, reply = _timed_minimum_exchange(
            comm, CONFIG_RVAS[context.module_sha256]["delay"], b"\x21\x24", 6, 0x24
        )
        if status:
            return status
        master_count, other_count = 0, 0
        fields = (
            (
                (5, 0, False),
                (5, 4, False),
                (4, 0, False),
                (4, 4, True),
                (3, 0, True),
                (3, 4, True),
                (2, 0, True),
                (2, 4, True),
            )
            if older
            else (
                (2, 4, True),
                (2, 0, True),
                (3, 4, True),
                (3, 0, True),
                (4, 4, True),
                (4, 0, False),
                (5, 4, False),
                (5, 0, False),
            )
        )
        for index, shift, primary in fields:
            value = (reply[index] >> shift) & 15
            if value in range(8, 15):
                return 505 if older else 2203
            if value == 0:
                continue
            if older:
                target = master if primary else secondary
                target[:] = (
                    (int.from_bytes(target, "little") + 1) & 0xFFFFFFFF
                ).to_bytes(4, "little")
            elif primary:
                master_count += 1
            else:
                other_count += 1
        if not older:
            master[:] = master_count.to_bytes(4, "little")
            secondary[:] = other_count.to_bytes(4, "little")
        keep = True
        return 0
    except BaseException:
        keep = False
        raise
    finally:
        if not keep:
            comm.finalize()


def _switch_registration(
    export: str, arguments: tuple[object, ...], context: UtilityExContext
) -> int:
    ending = export == "Ex2STR_20_EndKeyRegist"
    if arguments:
        raise ValueError("Native STR20 registration operation takes no arguments")
    comm = context.comm("selected")
    delay = CONFIG_RVAS[context.module_sha256]["delay"]
    try:
        comm.configure(delay, 150)
        try:
            length = comm.support_length(3, 0xC1)
            if type(length) is not int or not 0 <= length <= 255:
                raise ValueError("Native command support length requires a byte origin")
            if length == 0:
                return 82
            request = (
                b"\x3b\xc1" + bytes((0x80 if ending else 0x40,)) + bytes(length - 1)
            )
            status, reply = _exchange(comm, request, 2, 0xC1)
            if status == 7 and len(reply) > 2 and reply[2] == 0x22:
                status = 507
        finally:
            comm.configure(delay, 100)
        if status or ending:
            return status
        context.sleep(1000)
        status, reply = _timed_minimum_exchange(comm, delay, b"\x21\x22", 3, 0x22)
        if status:
            return 503 if status == 503 else 506
        return 0 if reply[2] & 0x80 else 503
    except BaseException:
        comm.finalize()
        raise


def _switch_support(export: str, context: UtilityExContext) -> int:
    older = export == "Ex2STR_20_GetSupportBitInfo"
    checks = [(0x21, 3, 10), *((0x24, size, 255) for size in range(3, 7))]
    if older:
        checks.insert(1, (0x22, 3, 0x80))
    comm = context.comm("selected")
    delay = CONFIG_RVAS[context.module_sha256]["delay"]
    keep = older
    host_failure = True
    try:
        status = comm.initialize(0)
        if status:
            host_failure = False
            return status
        for kind, requirements, failure in (
            (1, checks, 501 if older else 2201),
            (3, [(0xC1, 3, 0xC0)] if older else [(0xA4, 3, 2)], 502 if older else 2202),
        ):
            comm.configure(delay, 150)
            try:
                status = comm.refresh_support_cache(kind)
                if status:
                    host_failure = False
                    return status
                snapshot = comm.cached_support(kind)
                if snapshot is None:
                    host_failure = False
                    return failure
                data, offsets = snapshot
                for selector, size, mask in requirements:
                    if _support_position(data, offsets, selector, size, mask) is None:
                        host_failure = False
                        return failure
            finally:
                comm.configure(delay, 100)
        keep, host_failure = True, False
        return 0
    except BaseException:
        host_failure = True
        raise
    finally:
        if host_failure or not keep:
            comm.finalize()


def _switch_confirmation(export: str, context: UtilityExContext) -> int:
    # Literal PE tables in all four images: index2, mask02/value00 then08/value08.
    conditions = ((2, 2, 0),) if export.endswith("AccOff") else ((2, 2, 0), (2, 8, 8))
    mismatch = 2204 if export.startswith("Ex2STR_22_") else 504
    comm = context.comm("selected")
    delay = CONFIG_RVAS[context.module_sha256]["delay"]
    status, current = 0, 0
    try:
        for _ in range(65536):
            if context.is_cancelled():
                return status
            context.sleep(100)
            if context.is_cancelled():
                return status
            status, reply = _timed_minimum_exchange(comm, delay, b"\x21\x21", 3, 0x21)
            if status:
                return status
            index, mask, expected = conditions[current]
            if reply[index] & mask == expected:
                current += 1
                if current == len(conditions):
                    return 0
            else:
                status = mismatch
        raise TimeoutError("Native switch confirmation exceeds host primitive budget")
    except BaseException:
        comm.finalize()
        raise


def _str43_query(context: UtilityExContext, comm: UtilityExComm, mode: bool) -> int:
    delay = CONFIG_RVAS[context.module_sha256]["delay"]
    selector = 0x16 if mode else 0x14
    comm.configure(delay, 150)
    try:
        status, reply = comm.exchange(bytes((0x21, selector)))
        if status == 0 and len(reply) >= 3 and reply[1] == selector:
            if not mode:
                return 0x10D3 if reply[2] else 0
            if reply[2] & 0x20:
                return 0
        result = 0x10D1 if status in (2, 5) else 0x10D2
        context.native_sleep(100)
        comm.finalize()
        comm.initialize(0)  # The native recovery status is intentionally ignored.
        return result
    finally:
        comm.configure(delay, 100)


def _str43_state(export: str, context: UtilityExContext) -> int:
    comm = context.comm("selected")
    mode = export == "Ex2STR_43_CheckModeThread"
    keep = False

    try:
        if export == "Ex2STR_43_StartCommunication":
            status = comm.initialize(0)
            keep = status == 0
            return status
        if not mode:
            context.native_sleep(100)
            return _str43_query(context, comm, mode)
        status = 0x10D2
        if context.is_cancelled():
            return status
        for _ in range(65536):
            context.sleep(100)
            status = _str43_query(context, comm, mode)
            if status:
                return status
            if context.is_cancelled():
                keep = True
                return status
        raise TimeoutError("STR43 native mode polling exceeds host primitive budget")
    finally:
        if not keep:
            comm.finalize()


def _learning_control(
    export: str, arguments: tuple[object, ...], context: UtilityExContext
) -> int:
    erase = export.endswith("EraseDiagCode")
    mode = _uint32_argument(arguments)
    comm = context.comm("selected")
    keep = False
    try:
        if erase:
            if mode == 1:
                status = comm.initialize(0)
                if status:
                    return status
            status, reply = comm.exchange(b"\x04")
            return 3 if status == 0 and len(reply) != 1 else status
        status, reply = _timed_exchange(
            comm,
            CONFIG_RVAS[context.module_sha256]["delay"],
            b"\x3b\x10\xaa" + bytes((mode & 255,)),
            2,
            0x10,
        )
        if status == 7 and len(reply) > 2 and reply[2] == 0x22:
            status = 902 if export.startswith("Ex2ECD_09_") else 1002
        keep = status == 0
        return status
    finally:
        if not keep:
            comm.finalize()


def _wid20_flags(
    export: str, arguments: tuple[object, ...], context: UtilityExContext
) -> int:
    older = export == "Ex2ECD_15_CheckCodeSupportWID20Info"
    offset, size = (16, 2) if older else (32, 1)
    if (
        len(arguments) != 2
        or not isinstance(arguments[0], (bytes, bytearray))
        or len(arguments[0]) <= offset
        or not isinstance(arguments[1], bytearray)
        or len(arguments[1]) < size
    ):
        raise ValueError(
            "Native WID20 requires source record and bounded mutable flag bytes"
        )
    record, output = arguments
    assert isinstance(record, (bytes, bytearray)) and isinstance(output, bytearray)
    comm = context.comm("selected")
    delay = CONFIG_RVAS[context.module_sha256]["delay"]
    try:
        status = comm.initialize(0)
        if status:
            return status
        count = record[offset]
        comm.configure(delay, 150)
        try:
            status, reply = _exchange(comm, b"\x3b\x20", 6, 0x20)
            if status:
                return status
            if older:
                if count > 2 and reply[2] & 2:
                    output[0] |= 1
                if count > 3 and reply[3] & 4:
                    output[1] |= 0x80
                return 1501 if output[0] & 0xFB == 0 and output[1] & 0x80 == 0 else 0
            if count > 1 and reply[3] & 4:
                output[0] |= 2
            return 0 if output[0] else 2000
        finally:
            comm.configure(delay, 100)
    finally:
        comm.finalize()


def _code_support(
    export: str, arguments: tuple[object, ...], context: UtilityExContext
) -> int:
    mileage = export == "Ex2ECD_24_GetCodeSupportInfo"
    record_output = export == "Ex2ECD_16_GetCodeSupportWID20"
    cancellable = export.startswith("Ex2ECD_19_")
    size = 9 if record_output else 1 if mileage else 4
    if (
        len(arguments) != 1
        or not isinstance(arguments[0], bytearray)
        or (len(arguments[0]) < size if record_output else len(arguments[0]) != size)
    ):
        raise ValueError(f"Native support output must be a {size}-byte mutable buffer")
    output = arguments[0]
    comm = context.comm("selected")
    delay = CONFIG_RVAS[context.module_sha256]["delay"]
    selector = (
        0x20
        if export.endswith(("CheckCodeSupportWID20Info", "GetCodeSupportWID20"))
        else 0
    )
    try:
        status = comm.initialize(0)
        if status:
            return status
        comm.configure(delay, 150)
        try:
            if cancellable and context.is_cancelled():
                return 0
            status, reply = comm.exchange(bytes((0x3B if mileage else 0xA9, selector)))
            if status:
                return status
            if (
                len(reply) < 6
                or reply[1] != selector
                or ((mileage or cancellable) and len(reply) != 6)
            ):
                return 3
            if mileage:
                if reply[4] & 1:
                    output[0] |= 2
                if reply[5] & 0x80:
                    output[0] |= 1
                return 0 if output[0] else 2400
            if record_output:
                output[5:9] = reply[2:6]
            else:
                output[:] = reply[2:6]
            return 0
        finally:
            comm.configure(delay, 100)
    finally:
        comm.finalize()


def run_body(
    export: str, arguments: tuple[object, ...], context: UtilityExContext
) -> int:
    """Execute reviewed 12/18NK bodies through the selected native driver primitive.

    The caller must apply the matching native export wrapper and its scheduler.
    The mode guard is repeated here to keep direct calls from bypassing selection.
    """
    if context.module_sha256 not in CONFIG_RVAS:
        raise ValueError("Powertrain body is not reconstructed for this exact module")
    if export not in supported_operations(context.module_sha256):
        raise NotImplementedError(f"Native NK business body remains OPEN: {export}")
    if export in {
        "Ex2STR_41_RegTransponderID",
        "Ex2STR_41_RegNewKey",
        "Ex2STR_41_StartCommunication",
    }:
        return _str41_register(export, arguments, context)
    if export in {
        "Ex2STR_53_GetKeyStatus",
        "Ex2STR_53_GetKeySWStatus",
        "Ex2STR_53_GetImmobilizerMode",
        "Ex2STR_53_GetImmobilizerMode_OnExit",
    }:
        return _str53_poll(export, arguments, context)
    if export in {
        "Ex2STR_52_GetSupportInfo",
        "Ex2STR_52_GetDataInfo",
        "Ex2STR_52_KeepAlive",
        "EX2STR_52_SendTheKey",
    }:
        if context.mode not in ({4} if context.module_sha256 == NK12 else {4, 20}):
            return 99
        return _str52_body(export, arguments, context)
    if export in {"Ex2STR_43_ReqSecuritySeed", "Ex2STR_43_ClearAllKey"}:
        return _str43_security(export, arguments, context)
    if export == "Ex2STR_41_GetCurrentStatusRepeat":
        return _str41_repeat_status(arguments, context)
    if export == "Ex2STR_41_GetCurrentModeRepeat":
        return _str41_repeat_mode(arguments, context)
    if export == "Ex2STR_16_Foced_Termination_Of_FM":
        if arguments:
            raise ValueError("Native factory-mode termination takes no arguments")
        return _terminate_factory(context)
    if export == "Ex2STR_CngEraseModeImbi":
        if arguments:
            raise ValueError("Native immobilizer erase mode change takes no arguments")
        return _erase_immobilizer(context)
    if export == "Ex2STR_InitImbi":
        if arguments:
            raise ValueError("Native immobilizer initialization takes no arguments")
        return _initialize_immobilizer(context)
    if export == "Ex2STR_CngEraseMode":
        if arguments:
            raise ValueError("Native erase mode change takes no arguments")
        return _change_erase_mode(context)
    if export == "Ex2STR_ConfRegMode":
        if arguments:
            raise ValueError("Native registration mode confirmation takes no arguments")
        return _registration_mode(context)
    if export == "Ex2STR_ConfRegArea":
        if arguments:
            raise ValueError("Native registration area confirmation takes no arguments")
        return _registration_area(context)
    if export in {"Ex2STR_GetRegistKey", "Ex2STR_WaitCompRegistKey"}:
        return _registration_key(export, arguments, context)
    if export in {"Ex2STR_WaitCompEraseKey", "Ex2STR_02_WaitCompEraseKey"}:
        if arguments:
            raise ValueError("Native erase completion polling takes no arguments")
        return _wait_erase(export, context)
    if export in {"Ex2STR_GetRegKeyNumBefore", "Ex2STR_GetRegKeyNumAfter"}:
        return _key_counts(export, arguments, context)
    if export == "Ex2STR_RegMasKeyConf":
        return _registration_master(arguments, context)
    if export in {"Ex2ECD_09_StartKeepAlive", "Ex2ECD_10_StartKeepAlive"}:
        if context.broker(0x70) not in {0x11, 0x21, 0x51}:
            return 99
        if arguments:
            raise ValueError("Native ECD keepalive starter takes no semantic arguments")
        comm = context.comm("selected")
        try:
            comm.configure(CONFIG_RVAS[context.module_sha256]["retry"], 0)
            comm.configure(CONFIG_RVAS[context.module_sha256]["pending"], 0)
            context.start_selected_cmn(2000, 1, b"\x21\x0c", 2)
            return 0
        except BaseException:
            comm.finalize()
            raise
    if export == "Ex2STR_StartKeepAlive":
        if context.mode != 3:
            return 99
        interval = _uint32_argument(arguments)
        comm = context.comm("selected")
        try:
            comm.configure(CONFIG_RVAS[context.module_sha256]["retry"], 4)
            comm.configure(CONFIG_RVAS[context.module_sha256]["pending"], 1)
            return context.start_selected_cmn(interval)
        except BaseException:
            comm.finalize()
            raise
    if export == "Ex2STR_Init":
        if context.mode != 3:
            return 99
        if arguments:
            raise ValueError("Native steering initialization takes no arguments")
        comm = context.comm("selected")
        try:
            return comm.initialize(0)
        finally:
            comm.finalize()
    if export in {"Ex2STR_CheckIDCode", "Ex2STR_02_CheckIDCode"}:
        if arguments:
            raise ValueError("ID-code check takes no arguments")
        return _check_id(export, context)
    if export == "Ex2STR_ConfMasKey":
        if arguments:
            raise ValueError("Master-key confirmation takes no arguments")
        return _confirm_master(context)
    if export == "Ex2STR_ChangeRegistMode":
        if arguments:
            raise ValueError("Registration mode change takes no arguments")
        return _change_registration(context)
    if context.mode != 4:
        return 99
    if export in {
        "Ex2STR_53_GetKeySWStatus_Single",
        "Ex2STR_53_GetKeyStatus_Single",
        "Ex2STR_53_GetImmobilizerMode_Single",
    }:
        return _str53_single(export, arguments, context)
    if export == "Ex2ECD_50_GetSupportInfo":
        if arguments:
            raise ValueError("Native reductant support takes no arguments")
        return _reductant_support(context)
    if export == "Ex2STR_20_KeyRegist":
        return _switch_key_registration(arguments, context)
    if export == "Ex2STR_43_GetSupportInfo":
        return _str43_support(arguments, context)
    if export in {"Ex2STR_20_GetTheKeyNumber", "Ex2STR_22_GetKeyNumber"}:
        return _switch_counts(export, arguments, context)
    if export in {"Ex2STR_20_StartKeyRegist", "Ex2STR_20_EndKeyRegist"}:
        return _switch_registration(export, arguments, context)
    if export in {"Ex2STR_20_GetSupportBitInfo", "Ex2STR_22_GetSupportInfo"}:
        if arguments:
            raise ValueError("Native switch support checks take no arguments")
        return _switch_support(export, context)
    if export in {
        "Ex2STR_20_ComfirmSwitchAccOff",
        "Ex2STR_20_ComfirmSwitchAccOffIgOn",
        "Ex2STR_22_ComfirmSwitchAccOffIgOn",
    }:
        if arguments:
            raise ValueError("Native switch confirmation takes no arguments")
        return _switch_confirmation(export, context)
    if export in {
        "Ex2STR_43_CheckRegisteredKeyNum",
        "Ex2STR_43_StartCommunication",
        "Ex2STR_43_CheckModeThread",
    }:
        if arguments:
            raise ValueError("STR43 state operations take no arguments")
        return _str43_state(export, context)
    if export in {
        "Ex2STR_41_StartKeepAlive",
        "Ex2STR_42_StartKeepAlive",
        "Ex2STR_20_StartKeepAlive",
        "Ex2STR_22_StartKeepAlive",
        "Ex2STR_55_StartKeepAlive",
        "Ex2STR_56_StartKeepAlive",
    }:
        if export == "Ex2STR_41_StartKeepAlive" and context.broker(0x70) != 0x11:
            return 99
        if arguments:
            raise ValueError("Native STR keepalive starter takes no arguments")
        if export in {"Ex2STR_20_StartKeepAlive", "Ex2STR_22_StartKeepAlive"}:
            return context.start_selected_cmn(2000, 1, b"\x3e", 1)
        return context.start_selected_cmn(2000)
    if export in {"Ex2STR_41_StartKeepAliveCheck", "_Ex2STR_43_StartKeepAliveThread@4"}:
        return _str41_keepalive_check(export, arguments, context)
    if export == "Ex2STR_41_ResultTransponderID":
        if context.broker(0x70) != 0x11:
            return 99
        if arguments:
            raise ValueError("STR41 transponder result takes no arguments")
        comm = context.comm("selected")
        try:
            context.sleep(100)
            status = comm.initialize(0)
            if status:
                return status
            context.native_sleep(100)
            status, reply = _timed_minimum_exchange(
                comm, CONFIG_RVAS[context.module_sha256]["delay"], b"\x21\x13", 3, 0x13
            )
            if status:
                return status
            return 0 if reply[2] & 0x80 else 0x1009
        finally:
            comm.finalize()
    if export == "Ex2STR_41_EndFactoryMode":
        return _end_factory_mode(arguments, context)
    if export == "Ex2STR_41_GetRegKeySupportInfo":
        return _str41_support(arguments, context)
    if export in {
        "Ex2STR_41_GetRegKeyNum",
        "Ex2STR_41_GetCurrentMode",
        "Ex2STR_41_GetCurrentStatus",
    }:
        return _str41_query(export, arguments, context)
    if export in {
        "Ex2STR_42_ChkIDSupportInfo",
        "Ex2STR_42_ChkModeCondition",
        "Ex2STR_42_TransponderIDErasure",
    }:
        if arguments:
            raise ValueError("Native STR42 operations take no arguments")
        if export == "Ex2STR_42_ChkIDSupportInfo":
            return _str42_support(context)
        if export == "Ex2STR_42_TransponderIDErasure":
            return _str42_erase(context)
        return _str42_condition(context)
    if export in {
        "Ex2ECD_22_GetCylinderNum",
        "Ex2ECD_13_ReadCylinderInfo",
        "Ex2ECD_17_ReadCylinderInfo",
    }:
        return _cylinder_count(export, arguments, context)
    if export == "_Ex2STR_43_CheckOnlineSupport@4":
        return _online_support(arguments, context)
    if export == "Ex2ECD_31_ReadCode":
        return _read_ec31(arguments, context)
    if export in {
        "Ex2ECD_09_ChgNormalLearningMode",
        "Ex2ECD_10_ChgDetailLearningMode",
        "Ex2ECD_09_EraseDiagCode",
        "Ex2ECD_10_EraseDiagCode",
    }:
        return _learning_control(export, arguments, context)
    if export in {
        "Ex2ECD_15_CheckCodeSupportWID20Info",
        "Ex2ECD_20_CheckCodeSupportWID20Info",
    }:
        return _wid20_flags(export, arguments, context)
    if export in {
        "Ex2ECD_19_CheckCodeSupportInfo",
        "Ex2ECD_19_CheckCodeSupportWID20Info",
        "Ex2ECD_14_CheckCodeSupportInfo",
        "Ex2ECD_14_CheckCodeSupportWID20Info",
        "Ex2ECD_24_GetCodeSupportInfo",
        "Ex2ECD_31_CheckCodeSupportInfo",
        "Ex2ECD_16_GetCodeSupportWID20",
    }:
        return _code_support(export, arguments, context)
    if export in {"Ex2ECD_11_InitCrankTimeValue", "Ex2ECD_23_ClearDPFAshValue"}:
        if arguments:
            raise ValueError("Crank/ash initialization takes no arguments")
        return _crank_or_ash(export, context)
    if export in {"Ex2ECD_26_ReadPresetValue", "Ex2ECD_26_WritePresetValue"}:
        return _preset(export, arguments, context)
    if export == "Ex2ECD_25_ClearLearningValues":
        return _clear_learning(arguments, context)
    output: bytearray | None = None
    selector = 0
    if export in {"Ex2ECD_12_InitAFSensorLearn", "Ex2ECD_22_ClearZFCLearningValues"}:
        selector = _argument(arguments)
    elif export == "Ex2ECD_12_GetSupportInfo":
        if (
            len(arguments) != 1
            or not isinstance(arguments[0], bytearray)
            or len(arguments[0]) != 1
        ):
            raise ValueError("Support output must be a one-byte mutable buffer")
        output = arguments[0]
    elif arguments:
        raise ValueError("Initial supply pump takes no arguments")
    config = CONFIG_RVAS[context.module_sha256]
    comm = context.comm("selected")
    pump = export == "Ex2ECD_InitialSupplyPump"
    try:
        if pump:
            comm.configure(config["pending"], 1)
            comm.configure(config["retry"], 1)
        if context.is_cancelled() and output is None:
            return 99
        status = comm.initialize(0x13 if pump else 0)
        if status:
            return status
        if pump:
            if context.is_cancelled():
                return 0
            return _exchange(comm, b"\x3b\x06\x01", 2, 6)[0]
        comm.configure(config["delay"], 150)
        try:
            if export == "Ex2ECD_12_InitAFSensorLearn":
                return _exchange(
                    comm, bytes((0x3B, selector, 0, 0, 0, 0)), 2, selector
                )[0]
            if export == "Ex2ECD_22_ClearZFCLearningValues":
                for cylinder in range(8):
                    if context.is_cancelled():
                        break
                    if selector & (1 << cylinder):
                        context.sleep(100)
                        request = bytes(
                            (0x3B, 0x19, 0, cylinder + 1, 0, 0, 0, 0, 0, 0, 0)
                        )
                        status = _exchange(comm, request, 2, 0x19)[0]
                        if status:
                            break
                return status
            assert output is not None
            status, reply = _exchange(comm, b"\x3b\x00", 6, 0)
            if status:
                return status
            if reply[4] & 0x40:
                output[0] |= 1
            if reply[5] & 8:
                output[0] |= 4
            if not reply[5] & 1:
                return 0
        finally:
            comm.configure(config["delay"], 100)
        comm.configure(config["delay"], 150)
        try:
            status, reply = _exchange(comm, b"\x3b\x20", 6, 0x20)
            if status == 0 and reply[3] & 4:
                output[0] |= 2
            return status
        finally:
            comm.configure(config["delay"], 100)
    finally:
        try:
            comm.finalize()
        finally:
            if pump:
                comm.configure(config["pending"], 100)
                comm.configure(config["retry"], 3)
