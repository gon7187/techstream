"""Source-bound TY powertrain bodies over the shared UtilityEx communication layer.

Only individually recovered operations are callable. The core owns wrapper mode
checks, worker scheduling and native thread-result publication.
"""

from __future__ import annotations

import hashlib
import struct
from collections.abc import Callable, Iterator
from contextlib import contextmanager

from scripts.calibration import crc16
from scripts.toyota_session import Cancelled
from scripts.utility_ex_ty import TYComm, TYContext, TYSourceError

SHA_12 = "e85b2456b26d3966ca243c03fa775cf81ad58bf05689bdb87b616eda4c8b6f5f"
SHA_18 = "79fc495c68eb099a7ebc0d1eefe0eafd80101ac0bc09a58d3f603ed556c84762"
SHA_PLUS = "821bbfd9957679ceef4ac32c239b8840c984e98ac61050ce7348ac2bc88b04ce"
HV_BATTERY_WRITE = "Ex2HV_21_SendMessage"
HV_BATTERY_CLEAR = "Ex2HV_22_SendMessage"
HV_ACCELERATOR_CLEAR = "Ex2HV_19_SendMessage"
HV_ACCELERATOR = "Ex2HV_18_SendMessage"
HV_HISTORY_READ = "Ex2HV_20_SendMessage"
HV10_SUPPORT = "Ex2HV_10_SupportCheck"
HV10_READ = "Ex2HV_10_ReadBatteryStatus"
HV10_WAIT = "Ex2HV_10_WaitingEEPROMWrite"
HV10_JUDGE = "Ex2HV_10_JudgementOfStckToReplace"
HV12_SUPPORT = "Ex2HV_12_SupportCheck"
HV12_DTC_STATUS = "Ex2HV_12_GetDTCAndEEPROMStatus"
HV12_UPDATE = "Ex2HV_12_UpdateBatteryStatusInfo"
HV12_AFTER = "Ex2HV_12_JudgementAfterUpdateInfo"
HV14_SUPPORT = "Ex2HV_14_SupportCheck"
HV14_TEMPERATURE = "Ex2HV_14_ReadBatteryTemperature"
HV14_VOLTAGE = "Ex2HV_14_ReadBatteryBlockVoltage"
HV_READY_CANCEL = "Ex2HV_13_READYONProhibitionCancel"
HV_SERVICE = "Ex2HV_11_SendMessage"
HV_HISTORY_RESET = "Ex2HV_15_HiVltFsAccLdHstRst"
HV_BATTERY_RESET = "Ex2HV_17_BatteryStatusInfoReset"
ECO_STARTS_RESET = "Ex2ECO_10_TotalNumOfEngineStartsReset"
HNSCR_ADJUST = "Ex2HNSCR_02_SendMessage"
HNSCR_RESET = "Ex2HNSCR_01_SendMessage"
EFI_SESSION_TRANSITION = "Ex2EFI_44_SessionTransition"
EFI55_TABLE = "Ex2EFI_55_SendMessage"
EFI61_SUPPORT = "Ex2EFI_61_SupportCheck"
EFI61_WRITE = "Ex2EFI_61_WriteTotalShortTripEstimate"
EFI59_ROUTINE = "Ex2EFI_59_SendMessage"
EFI52_SWITCH = "Ex2EFI_52_SendMessage"
EFI53_ROUTINE = "Ex2EFI_53_SendMessage"
EFI62_VALUES = "Ex2EFI_62_SendMessage"
EFI_THROTTLE_LEARN = "Ex2EFI_54_ElectricThrottleLearning"
EFI_LEARNING_RESET = "Ex2EFI_28_LearningValueReset"
AMT_HISTORY_SUPPORT = "Ex2AMT_01_SupportCheck"
ASG_SUPPORT = "Ex2ASG_02_SupportCheck"
AMT_HISTORY_READ = "Ex2AMT_01_GetHistoryData"
AMT_HISTORY_WRITE = "Ex2AMT_01_WriteHistoryDataToECU"
ASG_INITIAL = "Ex2ASG_02_InitialLearning"
ASG_STATUS = "Ex2ASG_02_GetLearnedStatus"
ASG_STATUS_TIMEOUT = "Ex2ASG_02_GetLearnedStatusAfterTimeOut"
ASG_STATUS_004 = "Ex2ASG_02_GetLearnedStatusAt004"
ASG_LEARNED_FLAG = "Ex2ASG_02_CheckLearnedFlg"
EFI_PM_WAIT_STOP = "Ex2EFI_58_ReadGPFDealerVehicleStopRegenerateStop"
EFI_PM_START = "Ex2EFI_58_StartPMRegenerateMode"
EFI_PM_RESULT = "Ex2EFI_58_ResultPMRegenerateMode"
EFI_PM_STOP = "Ex2EFI_58_StopPMRegenerateMode"
EFI_PM_SUPPORT = "Ex2EFI_58_SupportCheck"
EFI_PM_READ = "Ex2EFI_58_ReadPMDeposition"
ECD_ASH_CLEAR = "Ex2ECD_57_DPFAshValueClear"
ECD_RESET55 = "Ex2ECD_55_SendMessage"
EFI_FREQUENCY_READ = "Ex2EFI_57_ReadDisplayFrequencyMode"
EFI_FREQUENCY_WRITE = "Ex2EFI_57_WriteDisplayFrequencyMode"
ECD_CHAR = "Ex2ECD_67_CharToInt"
ECD_HEX = "Ex2ECD_67_HexToByte"
ECD_DUMMY59 = "Ex2ECD_59_Dummy"
ECD_DUMMY60 = "Ex2ECD_60_Dummy"
PSA_ECD_RESET = "Ex2PSAECD_03_RequestResetECU"
PSA_EFI_RESET = "Ex2PSAEFI_01_SendMessage"
PSA_WATER = "Ex2PSAECD_01_ReadTempWater"
PSA_ECT_INIT = "Ex2PSAECT_01_InitializeECU"
PSA_OIL_READ = "Ex2PSAECT_01_ReadOilUsageCnt"
PSA_OIL_WRITE = "Ex2PSAECT_01_WriteOilUsageCnt"
PSA_WHEEL_READ = "Ex2PSADSG_01_ReadWheelIdentifires"
PSA_WHEEL_READ2 = "Ex2PSADSG_02_ReadWheelIdentifires"
PSA_WHEEL_CLEAR = "Ex2PSADSG_01_ClearWheelIdentifires"
PSA_WHEEL_MAIN = "Ex2PSADSG_02_WriteMainWheelIdentifires"
PSA_WHEEL_ADDITIONAL = "Ex2PSADSG_02_WriteAdditionalWheelIdentifires"
PSA_TRANSMITTER = "Ex2PSADSG_03_StartWheelTransmitter"
PSA_VALVE_CHECK = "Ex2PSADSG_04_ValveProgramCheck"
# Exact12 body3c9f0/helper3caf0 and45310/helper453e0;
# exact18 body48710/helper48810 and51070/helper51140. Full ASM, not truncated C.
_SOURCE_OPERATIONS: dict[str, tuple[str, ...]] = dict.fromkeys(
    (SHA_12, SHA_18),
    (
        PSA_ECD_RESET,
        PSA_EFI_RESET,
        PSA_WATER,
        PSA_ECT_INIT,
        ECO_STARTS_RESET,
        PSA_OIL_READ,
        PSA_OIL_WRITE,
        PSA_WHEEL_READ,
        PSA_WHEEL_READ2,
        PSA_WHEEL_CLEAR,
        PSA_VALVE_CHECK,
        PSA_WHEEL_MAIN,
        PSA_WHEEL_ADDITIONAL,
        PSA_TRANSMITTER,
        AMT_HISTORY_READ,
        ASG_SUPPORT,
        AMT_HISTORY_SUPPORT,
        EFI_LEARNING_RESET,
        AMT_HISTORY_WRITE,
        ASG_LEARNED_FLAG,
        ASG_INITIAL,
        ASG_STATUS,
        ASG_STATUS_TIMEOUT,
        ASG_STATUS_004,
    ),
)
_SOURCE_OPERATIONS[SHA_PLUS] = (
    EFI_LEARNING_RESET,
    AMT_HISTORY_SUPPORT,
    ASG_SUPPORT,
    AMT_HISTORY_READ,
    AMT_HISTORY_WRITE,
    ECO_STARTS_RESET,
    ASG_LEARNED_FLAG,
    ASG_INITIAL,
    ASG_STATUS,
    ASG_STATUS_TIMEOUT,
    ASG_STATUS_004,
)
_DIRECT = (ECD_CHAR, ECD_HEX)
for _source in (SHA_18, SHA_PLUS):
    _SOURCE_OPERATIONS[_source] += _DIRECT + (
        ECD_DUMMY59,
        ECD_DUMMY60,
        EFI_FREQUENCY_READ,
        EFI_FREQUENCY_WRITE,
        ECD_ASH_CLEAR,
        ECD_RESET55,
        HNSCR_RESET,
        HNSCR_ADJUST,
        EFI_PM_SUPPORT,
        EFI_PM_READ,
        EFI_PM_RESULT,
        EFI_PM_STOP,
        EFI_PM_START,
        EFI_PM_WAIT_STOP,
    )

for _source in (SHA_12, SHA_18, SHA_PLUS):
    _SOURCE_OPERATIONS[_source] += (
        HV_HISTORY_RESET,
        HV_BATTERY_RESET,
        HV_READY_CANCEL,
        HV_SERVICE,
        HV12_SUPPORT,
        HV12_DTC_STATUS,
        HV12_UPDATE,
        HV12_AFTER,
        HV14_SUPPORT,
        HV14_TEMPERATURE,
        HV14_VOLTAGE,
        HV10_SUPPORT,
        HV10_READ,
        HV10_WAIT,
        HV10_JUDGE,
        EFI_SESSION_TRANSITION,
    )

for _source in (SHA_18, SHA_PLUS):
    _SOURCE_OPERATIONS[_source] += (
        HV_HISTORY_READ,
        HV_ACCELERATOR,
        HV_ACCELERATOR_CLEAR,
        HV_BATTERY_WRITE,
        HV_BATTERY_CLEAR,
        EFI_THROTTLE_LEARN,
        EFI62_VALUES,
        EFI53_ROUTINE,
        EFI52_SWITCH,
        EFI59_ROUTINE,
        EFI61_SUPPORT,
        EFI61_WRITE,
        EFI55_TABLE,
    )


_ECT_ROUTINES = {
    "Ex2ECT_01_SendMessage": 0x8B,
    "Ex2ECT_02_SendMessage": 0x96,
    "Ex2ECT_03_SendMessage": 0x9B,
    "Ex2ECT_09_SendMessage": 0x9F,
    "Ex2ECT_10_SendMessage": 0x97,
    "Ex2ECT_12_SendMessage": 0xA2,
    "Ex2ECT_14_SendMessage": 0x95,
}
for _source in (SHA_18, SHA_PLUS):
    _SOURCE_OPERATIONS[_source] += tuple(_ECT_ROUTINES)


_ECT_MEMORY = {
    "Ex2ECT_04_SendMessage": 4,
    "Ex2ECT_05_SendMessage": 5,
    "Ex2ECT_08_SendMessage": 6,
    "Ex2ECT_11_SendMessage": 7,
}
for _source in (SHA_18, SHA_PLUS):
    _SOURCE_OPERATIONS[_source] += tuple(_ECT_MEMORY)


ECT_PREFIXED = "Ex2ECT_13_SendMessage"
ECT_BULK = "Ex2ECT_15_SendMessage"
ECT_CHECKSUM = "Ex2ECT_16_SendMessage"
for _source in (SHA_18, SHA_PLUS):
    _SOURCE_OPERATIONS[_source] += (ECT_PREFIXED, ECT_BULK, ECT_CHECKSUM)


def direct_exports(module_sha256: str) -> tuple[str, ...]:
    return _DIRECT if module_sha256 in (SHA_18, SHA_PLUS) else ()


_FIXED_P5 = {
    SHA_12: "native:100aed50",
    SHA_18: "native:1011d4f0",
    SHA_PLUS: "native:101392d0",
}
_PENDING_SETTER = {
    SHA_12: "native_rva:b940",
    SHA_18: "native_rva:12180",
    SHA_PLUS: "native_rva:142f0",
}


def supported_exports(module_sha256: str) -> tuple[str, ...]:
    return _SOURCE_OPERATIONS.get(module_sha256, ())


def _buffer(args: tuple[object, ...], minimum: int) -> bytearray:
    if (
        type(args) is not tuple
        or len(args) != 1
        or type(args[0]) is not bytearray
        or not minimum <= len(args[0]) <= 65536
    ):
        raise ValueError("One bounded mutable native TY argument buffer required")
    return args[0]


def _check(context: TYContext) -> None:
    if context.is_cancelled():
        raise Cancelled("TY powertrain operation cancelled")


def _status(value: int) -> int:
    if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
        raise TypeError("Native communication status must be uint32")
    return value


def _initialize(comm: TYComm, context: TYContext) -> int:
    _check(context)
    return _status(comm.initialize(0))


def _exchange(comm: TYComm, context: TYContext, request: bytes) -> tuple[int, bytes]:
    _check(context)
    status, reply = comm.exchange(request)
    _status(status)
    if type(reply) is not bytes or len(reply) > 4128:
        raise ValueError("Native immutable response buffer exceeds capacity")
    return status, reply


@contextmanager
def _managed(
    comm: TYComm, retained: Callable[[], bool] | None = None
) -> Iterator[None]:
    """Preserve this operation's HOST failure even when finalization also fails."""
    try:
        yield
    except BaseException as primary:
        try:
            comm.finalize()
        except BaseException as cleanup:  # noqa: BLE001 - preserve primary HOST failure
            primary.add_note(f"TY finalization also failed: {type(cleanup).__name__}")
        raise
    else:
        if retained is None or not retained():
            comm.finalize()


def _reset(export: str, args: tuple[object, ...], context: TYContext) -> int:
    data = _buffer(args, 4 if export == PSA_ECD_RESET else 1)
    # The constructor selects protocol from actual broker6F/70, not domain name.
    comm = context.comm("selected")
    with _managed(comm):
        status = _initialize(comm, context)
        if status:
            return status
        comm.configure(_PENDING_SETTER[context.module_sha256], 150)
        if export == PSA_ECD_RESET:
            # 4878d..487af maps full DWORD actions; every other action keeps zero.
            selector = {1: 0xAD, 2: 0xAE, 3: 0xA0}.get(
                int.from_bytes(data[:4], "little"), 0
            )
        else:
            selector = data[0]
        status, reply = _exchange(comm, context, bytes((0x11, selector)))
        if not status and (len(reply) != 2 or reply[1] != 0):
            return 3
        return status


def _water(args: tuple[object, ...], context: TYContext) -> int:
    # 18 body45df0/helper45ef0;12 body3a0d0/helper3a1d0, exact ASM.
    data = _buffer(args, 5)
    comm = context.comm("selected")
    with _managed(comm):
        _check(context)
        context.native_sleep(2000)
        status = _initialize(comm, context)
        if status:
            return status
        comm.configure(_PENDING_SETTER[context.module_sha256], 150)
        while True:
            status, reply = _exchange(comm, context, b"\x21\xcd\x80\x01")
            if status:
                return status
            # Native clears its whole receive buffer; short reads retain zeros.
            reply = reply.ljust(6, b"\0")
            if reply[1] != 0xFF:
                return 3
            data[4] = reply[5]
            if reply[5] >= 0x7A:
                return 0
            context.native_sleep(250)


def _ect_initialize(args: tuple[object, ...], context: TYContext) -> int:
    # 18 body46960/helper46ea0;12 body3ac40/helper3b180, exact ASM.
    _buffer(args, 0)
    comm = context.comm("selected")
    with _managed(comm):
        status = _initialize(comm, context)
        if status:
            return status
        comm.configure(_PENDING_SETTER[context.module_sha256], 150)
        context.native_sleep(1000)
        status, reply = _exchange(comm, context, b"\x11\xff")
        if reply == b"\x7f\x11\x22":
            return 0x2332
        if not status and (len(reply) != 2 or reply[1] != 0):
            return 3
        return status


def _engine_starts_reset(args: tuple[object, ...], context: TYContext) -> int:
    # 12:69fd0/6a050/68fc0;18:850e0/85160/851f0;Plus:87d00/87c60/83df0.
    if args:
        raise ValueError("Native engine-start reset takes no arguments")
    comm = context.comm(_FIXED_P5[context.module_sha256])
    with _managed(comm):
        status = _initialize(comm, context)
        if status:
            return status
        comm.configure("native_1080", 0)
        comm.configure("native_1084", 180000)
        for mode in (1, 3):
            _check(context)
            status = _status(comm.session(mode, 1))
            if status:
                return status
        status, reply = _exchange(comm, context, b"\x2e\x20\x02\0\0\0")
        if not status and (len(reply) != 3 or reply[1:3] != b"\x20\x02"):
            status = 3
        _check(context)
        restored = _status(comm.session(1, 1))
        return restored if restored else status


def _oil(write: bool, args: tuple[object, ...], context: TYContext) -> int:
    # 18:46a40/46fb0,46b20/470d0;12:3ad20/3b290,3ae00/3b3b0.
    data = _buffer(args, 4)
    comm = context.comm("selected")
    with _managed(comm):
        status = _initialize(comm, context)
        if status:
            return status
        comm.configure(_PENDING_SETTER[context.module_sha256], 150)
        context.native_sleep(1000)
        if write:
            request = b"\x34\xd1\0\0\0\x05\xda" + bytes(data[:4])
            # Native12 8d30 /18 e050 is the existing reflected CRC16 algorithm.
            request += crc16(request).to_bytes(2, "little")
        else:
            request = b"\x21\xd1\xda"
        status, reply = _exchange(comm, context, request)
        if status:
            return status
        if write:
            if len(reply) == 2:
                if reply[1] == 2:
                    return 0
                if reply[1] in (4, 10):
                    return 0x233F
            return 3
        if len(reply) != 7 or reply[1:3] != b"\xd1\xda":
            return 3
        data[:4] = reply[3:7]
        return 0


def _wheel_clear(args: tuple[object, ...], context: TYContext) -> int:
    # 12:3b8c0/3b9b0/3bae0;18:475e0/476d0/47800, no native argument.
    if args:
        raise ValueError("Native wheel identifier clear takes no arguments")
    comm = context.comm("selected")
    with _managed(comm):
        status = _initialize(comm, context)
        if status:
            return status
        context.native_sleep(1000)
        comm.configure(_PENDING_SETTER[context.module_sha256], 150)
        for index, request in enumerate(
            (
                b"\x34\xb3\0\0\0\x10" + bytes(16) + b"\x24\xad",
                b"\x34\xb4\0\0\0\x04" + bytes(4) + b"\x8c\x73",
            )
        ):
            if index:
                context.native_sleep(1000)
            status, reply = _exchange(comm, context, request)
            if status:
                return status
            if reply != b"\x74\x02":
                return 3
        return 0


def _dsg(export: str, args: tuple[object, ...], context: TYContext) -> int:
    # 12:3b6c0/3b7a0,3c820/3c920;18:473e0/474c0,48540/48640.
    wheel = export in (PSA_WHEEL_READ, PSA_WHEEL_READ2)
    full_wheel = export == PSA_WHEEL_READ2
    data = _buffer(args, 36 if full_wheel else 20 if wheel else 16)
    comm = context.comm("selected")
    with _managed(comm):
        status = _initialize(comm, context)
        if status:
            return status
        if wheel:
            context.native_sleep(1000)
        comm.configure(_PENDING_SETTER[context.module_sha256], 150)
        if wheel:
            status, reply = _exchange(comm, context, b"\x21\xb3")
            if full_wheel:
                # 12:3bfb0;18:47cd0 checks only byte1 and copies only on success.
                if status:
                    return status
                if len(reply) != 38 or reply[1] != 0xB3:
                    return 3
                data[:36] = reply[2:38]
                return 0
            if not status and reply[:2] != b"\x61\xb3":
                return 3
            # Native validates length and copies output even after a wire error.
            if len(reply) != 38:
                return 3
            data[:20] = reply[18:38]
            return status
        data[4:8] = (1).to_bytes(4, "little")
        while not int.from_bytes(data[8:12], "little"):
            status, reply = _exchange(comm, context, b"\x21\xd3")
            if status:
                return status
            reply = reply.ljust(3, b"\0")
            # The byte is written even when the echo mismatch sets status3.
            data[0] = reply[2]
            if reply[1] != 0xD3:
                return 3
            data[12:16] = (1).to_bytes(4, "little")
            context.native_sleep(40)
        return 0


def _wheel_write(export: str, args: tuple[object, ...], context: TYContext) -> int:
    # 12:3bcc0/3be40/3bfb0/3c0f0/3c220/3c350;18:479e0..48070.
    additional = export == PSA_WHEEL_ADDITIONAL
    data = _buffer(args, 40 if additional else 16)
    comm = context.comm("selected")
    with _managed(comm):
        status = _initialize(comm, context)
        if status:
            return status
        context.native_sleep(1000)
        comm.configure(_PENDING_SETTER[context.module_sha256], 150)
        saved = bytes(data[:40])
        status, reply = _exchange(comm, context, b"\x21\xb3")
        if status:
            return status
        if len(reply) != 38 or reply[1] != 0xB3:
            return 3
        if additional:
            # Read helper overwrites nine DWORDs; selector DWORD9 survives.
            data[:36] = reply[2:38]
            context.native_sleep(1000)
            selector = int.from_bytes(data[36:40], "little")
            if selector > 4:
                return 0
            offset = 16 if selector == 4 else 20 + 4 * selector
            data[offset : offset + 4] = saved[offset : offset + 4]
            payload = bytes(data[16:20] if selector == 4 else data[20:36])
            identifier = 0xB4 if selector == 4 else 0xB3
        else:
            if any(reply[2:18]):
                return 0x2337
            context.native_sleep(1000)
            payload, identifier = bytes(data[:16]), 0xB2
        request = bytes((0x34, identifier, 0, 0, 0, len(payload))) + payload
        request += crc16(request).to_bytes(2, "little")
        status, reply = _exchange(comm, context, request)
        # Native helpers check only length and byte1, not positive SID.
        return 3 if not status and (len(reply) != 2 or reply[1] != 2) else status


def _transmitter(args: tuple[object, ...], context: TYContext) -> int:
    # 12:3c460/3c5f0/3c6c0;18:48180/48310/483e0, exact ASM.
    data = _buffer(args, 9)
    comm = context.comm("selected")
    with _managed(comm):
        status = _initialize(comm, context)
        if status:
            return status
        comm.configure(_PENDING_SETTER[context.module_sha256], 150)
        selector = int.from_bytes(data[:4], "little")
        selector = selector if 1 <= selector <= 4 else 0
        status, reply = _exchange(comm, context, bytes((0x31, 0xB4, 0, selector)))
        if status or len(reply) != 3 or reply[1:] != b"\xb4\x01":
            return 0x2330
        started = context.ticks()
        data[4:8] = (1).to_bytes(4, "little")
        while True:
            _check(context)
            context.native_sleep(250)
            status, reply = _exchange(comm, context, b"\x31\xb4\x01")
            elapsed = (context.ticks() - started) & 0xFFFFFFFF
            if status or len(reply) != 3 or reply[1] != 0xB4:
                status = 0x2330
                break
            result = reply[2]
            if result == 1:
                status = 9999
                if elapsed < 120000:
                    continue
            elif result in (2, 4, 6, 8, 10, 16, 34):
                data[8] = result
                status = 0
            else:
                status = 0x2330
            break
        data[4:8] = bytes(4)
        return status


def _hnscr_read(
    comm: TYComm, context: TYContext, high: int, low: int, offset: int, count: int
) -> tuple[int, bytes]:
    # 18:96400 requires the DID echo plus offset+count native payload bytes.
    # EFI62 bf470 andPlus c58b0/7f1c0 have the same exact offset0/count contract.
    status, reply = _exchange(comm, context, bytes((0x22, high, low)))
    if status:
        return status, b""
    if len(reply) < 3 + offset + count or reply[1:3] != bytes((high, low)):
        return 3, b""
    return 0, reply[3 + offset : 3 + offset + count]


def _hnscr_routine(
    comm: TYComm, context: TYContext, mode: int, low: int, payload: bytes = b""
) -> int:
    # 18:942d0 full ASM retains the three-byte echo despite folded C.
    status, reply = _exchange(comm, context, bytes((0x31, mode, 0x11, low)) + payload)
    if not status and (len(reply) < 5 or reply[1:4] != bytes((mode, 0x11, low))):
        return 3
    return status


def _hnscr_adjust(args: tuple[object, ...], context: TYContext) -> int:
    # 18:93960 dispatches all eight workers939f0..93ed0; no Plus alias.
    data = _buffer(args, 4)
    action = int.from_bytes(data[:4], "little")
    if action > 7:
        return 0
    _buffer(args, 122)
    comm = context.comm(_FIXED_P5[context.module_sha256])
    close = True
    with _managed(comm, lambda: not close):
        if action in (0, 1):
            data[4:8] = bytes(4)
            if action == 0:
                data[8:12] = bytes(4)
                data[14:25] = bytes(11)
            data[12:14] = bytes(2)
            data[116:122] = bytes(6)
            for index in range(11):
                data[28 + index * 8 : 30 + index * 8] = bytes(2)
                data[32 + index * 8 : 36 + index * 8] = bytes(4)
            status = _initialize(comm, context)
            if status:
                return status
            for field, value in (
                ("native_1080", 0),
                ("native_1084", 180000),
                ("native_1064", 0),
            ):
                comm.configure(field, value)
            status = _status(comm.session(3, 1, normal_first=True))
            if status:
                return status
            if action == 0:
                status, reply = _hnscr_read(comm, context, 1, 1, 2, 1)
                if not status and reply[0] & 0x80:
                    status, reply = _hnscr_read(comm, context, 0x10, 0, 0, 6)
                    if not status:
                        for index, (offset, mask) in enumerate(
                            (
                                (4, 0x20),
                                (4, 0x10),
                                (0, 4),
                                (0, 2),
                                (0, 1),
                                (1, 0x20),
                                (1, 0 if context.module_sha256 == SHA_PLUS else 8),
                                (5, 0x40),
                                (1, 4),
                                (2, 0x40),
                                (2, 2),
                            )
                        ):
                            data[14 + index] = int(bool(reply[offset] & mask))
                if not status:
                    return _status(comm.session(1, 1, stop_on_error=True))
                _status(comm.session(1, 1))
                return status
            context.native_sleep(30)
            status = _hnscr_routine(comm, context, 1, 1)
            if status == 7:
                status = _status(comm.read_field("native_10b0"))
            if not status:
                close = False
                return 0
            _status(comm.session(1, 1))
            return status
        if action in (3, 6):
            _hnscr_routine(comm, context, 2, 1 if action == 3 else 2)
            _status(comm.session(1, 1))
            return 0
        if action in (4, 7):
            low = 1 if action == 4 else 2
            status, reply = _exchange(comm, context, bytes((0x31, 3, 0x11, low)))
            if not status and (len(reply) < 7 or reply[1:4] != bytes((3, 0x11, low))):
                status = 3
            if not status and reply[4]:
                status = 1001
                data[120:122] = bytes((reply[6], reply[5]))
            elif not status and action == 4:
                selector = int.from_bytes(data[8:12], "little")
                payload = {
                    0: b"\0\x48\2\x21",
                    1: b"\1\x68\0\xda",
                    2: b"\x09\xd8\0\x4e",
                }.get(selector, bytes(4))
                status = _hnscr_routine(comm, context, 1, 2, payload)
                if status == 7:
                    status = _status(comm.read_field("native_10b0"))
                if not status:
                    close = False
                    return 0
            _status(comm.session(1, 1))
            return status
        # Poll workers2/5 retain the existing initialized manager on all returns.
        enabled = (
            (1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1)
            if action == 2
            else (0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1)
        )
        order = (2, 3, 4, 5, 6, 8, 9, 10, 0, 1, 7)
        selected = [index for index in order if data[14 + index] & enabled[index]]
        for slot, index in enumerate(selected):
            data[32 + slot * 8 : 36 + slot * 8] = index.to_bytes(4, "little")
        data[116:120] = len(selected).to_bytes(4, "little")
        lows = (0x23, 0x24, 6, 7, 8, 0x0B, 0x0D, 0x2A, 0x0E, 0x12, 0x17)
        status = 1000
        while not data[12]:
            for slot, index in enumerate(selected):
                count = 2 if index in (6, 9) else 1
                status, reply = _hnscr_read(comm, context, 0x10, lows[index], 0, count)
                if status:
                    close = False
                    return status
                data[28 + slot * 8 : 30 + slot * 8] = (
                    reply if count == 2 else b"\0" + reply
                )
            status, reply = _hnscr_read(comm, context, 0x1A, 1, 1, 1)
            if status:
                close = False
                return status
            data[13] = 1
            if reply[0] & (0x80 if action == 2 else 0x40):
                close = False
                return 0
            context.native_sleep(100)
            status = 1000
        close = False
        return status


def _hnscr_reset(args: tuple[object, ...], context: TYContext) -> int:
    # 18:93820/93840/938c0;Plus:97550/97410/97490.
    if args:
        raise ValueError("Native HNSCR reset takes no arguments")
    comm = context.comm(_FIXED_P5[context.module_sha256])
    with _managed(comm):
        status = _initialize(comm, context)
        if status:
            return status
        for field, value in (
            ("native_1080", 0),
            ("native_1084", 180000),
            ("native_1064", 0),
        ):
            comm.configure(field, value)
        _check(context)
        status = _status(comm.session(3, 1, normal_first=True))
        if status:
            return status
        context.native_sleep(30)
        status, reply = _exchange(comm, context, b"\x31\x01\x12\x01")
        if not status and (len(reply) < 5 or reply[1:4] != b"\x01\x12\x01"):
            status = 3
        _check(context)
        # The restoring helper stops keepalive even when the restore fails.
        _status(comm.session(1, 1, stop_on_error=True))
        return status


def _ect_prefixed(args: tuple[object, ...], context: TYContext) -> int:
    # 18:badb0/bae20/baea0;Plus:c14c0/c1530/c13e0/bf5e0;
    # P6:7ed40/7edb0/7eb60/7ec60. The three payload layouts differ.
    data = _buffer(args, 4)
    action = int.from_bytes(data[:4], "little")
    if action == 0 and len(data) < 35:
        raise ValueError("ECT13 requires its native byte34 length")
    classic = context.module_sha256 == SHA_PLUS and context.mode == 22
    did = b"\x94\x21" if classic else b"\x23\4"
    comm = context.comm(
        "native:1013e7d0" if classic else _FIXED_P5[context.module_sha256]
    )
    with _managed(comm):
        status = _initialize(comm, context)
        if status:
            return status
        for field, value in (
            ("native_1080", 0),
            ("native_1084", 180000),
            ("native_1064", 0),
        ):
            comm.configure(field, value)
        if action != 0:
            return 0
        _check(context)
        status = _status(comm.session(3, 1, normal_first=True))
        if status:
            return status
        count = data[34]
        if count > len(data) - 4 or (context.module_sha256 == SHA_18 and count > 30):
            raise ValueError("ECT13 caller payload exceeds native/caller allocation")
        raw = bytes(data[4 : 4 + count])
        if context.module_sha256 == SHA_18:
            payload = bytes(46) + raw
        else:
            status, reply = _exchange(comm, context, b"\x22" + did)
            padded = reply.ljust(4128, b"\0")
            prefix = padded[5] if classic else padded[3]
            minimum = (
                padded[6 + prefix] + 7 + prefix
                if classic
                else padded[4 + prefix] + 5 + prefix
            )
            if not status and (
                len(reply) < minimum
                or reply[1:3] != did
                or (classic and int.from_bytes(padded[3:5], "big") + 5 > len(reply))
            ):
                status = 3
            if status:
                _check(context)
                _status(comm.session(1, 1))
                return status
            length = count + prefix + 1
            payload = (
                length.to_bytes(2, "big") + bytes(prefix + 1) + raw
                if classic
                else (bytes(prefix + 1) + raw)[: length & 255]
            )
        status, reply = _exchange(comm, context, b"\x2e" + did + payload)
        if not status and (len(reply) < 3 or reply[1:3] != did):
            status = 3
        if (
            context.module_sha256 == SHA_PLUS
            and status == 7
            and _status(comm.read_field("native_10b0")) == 0x66
        ):
            status = 1006
        _check(context)
        _status(comm.session(1, 1))
        return status


def _ect_bulk(args: tuple[object, ...], context: TYContext) -> int:
    # 18:bb1a0/bb210/bb290;Plus:c1850/c18c0/c1770.
    data = _buffer(args, 4)
    action = int.from_bytes(data[:4], "little")
    if action == 0 and len(data) < 4098:
        raise ValueError("ECT15 requires its native payload and word4096 length")
    comm = context.comm(_FIXED_P5[context.module_sha256])
    with _managed(comm):
        status = _initialize(comm, context)
        if status:
            return status
        for field, value in (
            ("native_1080", 0),
            ("native_1084", 180000),
            ("native_1064", 0),
        ):
            comm.configure(field, value)
        if action != 0:
            return 0
        _check(context)
        status = _status(comm.session(3, 1, normal_first=True))
        if status:
            return status
        count = int.from_bytes(data[4096:4098], "little")
        if count > 4092:
            raise ValueError("ECT15 payload exceeds native4092-byte allocation")
        status, reply = _exchange(
            comm, context, b"\x2e\x23\x08" + bytes(data[4 : 4 + count])
        )
        if not status and (len(reply) < 3 or reply[1:3] != b"\x23\x08"):
            status = 3
        _check(context)
        _status(comm.session(1, 1))
        return status


def _ect_checksum(args: tuple[object, ...], context: TYContext) -> int:
    # 18:bed70/bedb0/bef60/befb0/bee90;Plus:c5c30/c5a70/c5820/c5c70/c5990.
    data = _buffer(args, 4 if context.module_sha256 == SHA_PLUS else 0)
    selector = (
        int.from_bytes(data[:4], "little") if context.module_sha256 == SHA_PLUS else 1
    )
    count = 112 if selector == 1 else 71 if selector == 2 else 133
    positions = (82,) if selector == 1 else (38,) if selector == 2 else (38, 77)
    comm = context.comm(_FIXED_P5[context.module_sha256])
    with _managed(comm):
        status = _initialize(comm, context)
        if status:
            return status
        for field, value in (
            ("native_1080", 0),
            ("native_1084", 180000),
            ("native_1064", 0),
        ):
            comm.configure(field, value)
        _check(context)
        status = _status(comm.session(3, 1, normal_first=True))
        if status:
            return status
        status, raw = _hnscr_read(comm, context, 0x23, 3, 0, count)
        if not status:
            payload = bytearray(raw)
            zero = 80 if selector == 1 else 36
            payload[zero : zero + 2] = bytes(2)
            for position in positions:
                checksum = 0xA5
                for value in payload[1:position]:
                    checksum ^= value
                payload[position] = checksum
            context.native_sleep(200)
            status, reply = _exchange(comm, context, b"\x2e\x23\3" + bytes(payload))
            if not status and (len(reply) < 3 or reply[1:3] != b"\x23\3"):
                status = 3
        _check(context)
        _status(comm.session(1, 1))
        return status


def _ect_memory(export: str, args: tuple[object, ...], context: TYContext) -> int:
    # 18:ba420/ba530/ba640/bab40,readb3aa0/writeb23e0;
    # Plus:c0bc0/c0cd0/c0de0/c11c0;P6ECT04:7eaa0/7e8d0/7e9c0.
    data = _buffer(args, 4)
    action = int.from_bytes(data[:4], "little")
    if action == 0 and len(data) < 4136:
        raise ValueError("ECT read requires the native4128-byte output allocation")
    if action == 1 and len(data) < 8:
        raise ValueError("ECT write requires its native length DWORD")
    classic = context.module_sha256 == SHA_PLUS and context.mode == 22
    if classic and export != "Ex2ECT_04_SendMessage":
        raise TYSourceError("ECT memory operation has no exact Plus22 callback")
    did = b"\x94\x21" if classic else bytes((0x23, _ECT_MEMORY[export]))
    comm = context.comm(
        "native:1013e7d0" if classic else _FIXED_P5[context.module_sha256]
    )
    with _managed(comm):
        status = _initialize(comm, context)
        if status:
            return status
        for field, value in (
            ("native_1080", 0),
            ("native_1084", 180000),
            ("native_1064", 0),
        ):
            comm.configure(field, value)
        if export == "Ex2ECT_08_SendMessage":
            comm.configure(
                "native_rva:1a890"
                if context.module_sha256 == SHA_18
                else "native_rva:1e280",
                2000,
            )
        if action not in (0, 1):
            return 0
        _check(context)
        status = _status(comm.session(3, 1, normal_first=True))
        if status:
            return status
        if action == 0:
            data[8:4136] = bytes(4128)
            status, reply = _exchange(comm, context, b"\x22" + did)
            if not status:
                if len(reply) < 4 or reply[1:3] != did:
                    status = 3
                else:
                    # P6 deliberately copies the echoed DID too; standard strips3 bytes.
                    payload = reply[1:] if classic else reply[3:]
                    data[4:8] = len(payload).to_bytes(4, "little")
                    data[8 : 8 + len(payload)] = payload
        else:
            count = int.from_bytes(data[4:8], "little")
            if count > 4125 or count > len(data) - 8:
                raise ValueError("ECT write payload exceeds caller/native allocation")
            status, reply = _exchange(
                comm, context, b"\x2e" + did + bytes(data[8 : 8 + count])
            )
            if not status and (len(reply) < 3 or reply[1:3] != did):
                status = 3
        _check(context)
        _status(comm.session(1, 1))
        return status


def _ect_p6_poll(data: bytearray, comm: TYComm, context: TYContext) -> int:
    # ExactPlus7e460, not ordinary UDS pending/error handling.
    previous = _status(comm.read_field("native_10a4"))
    comm.configure("native_10a4", 0)
    try:
        status = 0
        while data[4] == 0:
            context.native_sleep(200)
            status, reply = _exchange(comm, context, b"\x31\3\x11\x8b")
            if not status:
                if len(reply) < 6 or reply[1:4] != b"\3\x11\x8b" or reply[5] != 2:
                    status = 3
                break
            if status == 7:
                if _status(comm.read_field("native_10b0")) not in (0x68, 0x6A):
                    break
            elif status != 28:
                break
        _exchange(comm, context, b"\x31\2\x11\x8b")
        _check(context)
        _status(comm.session(1, 1))
    except BaseException as primary:
        try:
            comm.configure("native_10a4", previous)
        except BaseException as secondary:  # noqa: BLE001 - preserve original HOST failure
            primary.add_note(
                f"TY field restoration also failed: {type(secondary).__name__}"
            )
        raise
    comm.configure("native_10a4", previous)
    return status


def _ect_routine(export: str, args: tuple[object, ...], context: TYContext) -> int:
    # Each exact18/Plus worker binds its own reviewed routine literal; no wildcard admission.
    data = _buffer(args, 4)
    starting = int.from_bytes(data[:4], "little") == 0
    if not starting and len(data) < 5:
        raise ValueError("ECT routine polling requires caller stop byte")
    classic = context.module_sha256 == SHA_PLUS and context.mode == 22
    if classic and export != "Ex2ECT_01_SendMessage":
        raise TYSourceError("ECT routine has no exact Plus22 callback")
    low = _ECT_ROUTINES[export]
    comm = context.comm(
        "native:1013e7d0" if classic else _FIXED_P5[context.module_sha256]
    )
    retained = False
    with _managed(comm, lambda: retained):
        if starting:
            status = _initialize(comm, context)
            if status:
                return status
            for field, value in (
                ("native_1080", 0),
                ("native_1084", 180000),
                ("native_1064", 0),
            ):
                comm.configure(field, value)
            _check(context)
            status = _status(comm.session(3, 1, normal_first=True))
            if status:
                return status
            status, reply = _exchange(comm, context, bytes((0x31, 1, 0x11, low)))
            if not status and (
                reply.ljust(4128, b"\0")[1:4] != bytes((1, 0x11, low))
                or (classic and len(reply) < 5)
            ):
                status = 3
            if not status:
                retained = True
                return 0
        elif classic:
            return _ect_p6_poll(data, comm, context)
        else:
            status = 0
            while data[4] == 0:
                context.native_sleep(200)
                status, reply = _exchange(comm, context, bytes((0x31, 3, 0x11, low)))
                if not status and (
                    len(reply) < 5 or reply[1:4] != bytes((3, 0x11, low))
                ):
                    status = 3
                if status:
                    break
                if reply[4] <= 1:
                    continue
                if reply[4] != 2:
                    status = 3
                break
        _exchange(comm, context, bytes((0x31, 2, 0x11, low)))
        _check(context)
        _status(comm.session(1, 1))
        return status


_EFI55_TABLES = (
    bytes.fromhex(
        "50000000ff810000fe0000fbfe11120efc00000207121612f9f8f8f9fc0a0b0af6f6f1f2f5020604f4f5f6f8fc090a09f7f6fafe0405090cfb010a060b0e140000000000000000000000000000000000dc00000000000000000000000000000000000000000000000000000000"
    ),
    bytes.fromhex(
        "52000000ff820000fe0000fbfe11120efc00000207121612f9f8f8f9fc0a0b0af6f6f1f2f5020604f4f5f6f8fc090a09f7f6fafe0405090cfb010a060b0e1400000000000000000000000000000000000000df0000000000000000000000000000000000000000000000000000000000"
    ),
)


def _efi55_table(args: tuple[object, ...], context: TYContext) -> int:
    # 18:a2580/a25a0/a2d30/a2c60;Plus:a7c50/a7730/a7b80/a7aa0.
    data = _buffer(args, 4)
    second = int.from_bytes(data[:4], "little") == 2
    payload = _EFI55_TABLES[second]
    compare = 83 if second else 81
    comm = context.comm(_FIXED_P5[context.module_sha256])
    with _managed(comm):
        status = _initialize(comm, context)
        if status:
            return status
        for field, value in (
            ("native_1080", 0),
            ("native_1084", 180000),
            ("native_1064", 0),
        ):
            comm.configure(field, value)
        _check(context)
        status = _status(comm.session(3, 1, normal_first=True))
        if status:
            return status
        status, reply = _exchange(comm, context, b"\x2e\x23\3" + payload)
        if not status and reply.ljust(4128, b"\0")[1:3] != b"\x23\3":
            status = 3
        if not status:
            context.native_sleep(200)
            status, reply = _hnscr_read(comm, context, 0x23, 3, 0, len(payload))
            if not status and reply[:compare] != payload[:compare]:
                status = 1000
        _check(context)
        _status(comm.session(1, 1))
        return status


def _efi61_values(export: str, args: tuple[object, ...], context: TYContext) -> int:
    # 18:befe0/bf060/bf100/bf1c0;Plus:c5d80/c5ea0 andP6:7ef80/7f0a0.
    supporting = export == EFI61_SUPPORT
    data = _buffer(args, 8 if supporting else 24)
    classic = context.module_sha256 == SHA_PLUS and context.mode == 22
    comm = context.comm(
        "native:1013e7d0" if classic else _FIXED_P5[context.module_sha256]
    )
    with _managed(comm):
        status = _initialize(comm, context)
        if status:
            return status
        for field, value in (
            ("native_1080", 0),
            ("native_1084", 180000),
            ("native_1064", 0),
        ):
            comm.configure(field, value)
        _check(context)
        status = _status(comm.session(3, 1, normal_first=True))
        if status:
            return status
        if supporting:
            did = b"\xa1\x20" if classic else b"\x20\0"
            status, reply = _exchange(comm, context, b"\x22" + did)
            if not status:
                valid = len(reply) >= 35 if classic else len(reply) == 35
                if not valid or reply[1:3] != did:
                    status = 3
                else:
                    flags = (
                        (reply[9] & 0x80, reply[9] & 0x40)
                        if classic
                        else (reply[8] & 1, reply[9] & 0x80)
                    )
                    for offset, value in zip((0, 4), flags, strict=True):
                        if value:
                            data[offset : offset + 4] = (1).to_bytes(4, "little")
        else:
            for slot, low in enumerate((0x30, 0x31)):
                if not int.from_bytes(data[16 + 4 * slot : 20 + 4 * slot], "little"):
                    continue
                status, reply = _exchange(
                    comm, context, bytes((0x2E, 0x20, low)) + bytes(4)
                )
                if not status and (len(reply) < 3 or reply[1:3] != bytes((0x20, low))):
                    status = 3
                if status:
                    break
        _check(context)
        _status(comm.session(1, 1))
        return status


def _efi59_routine(args: tuple[object, ...], context: TYContext) -> int:
    # 18:bbe80/bbeb0/bbf60/bc050/bc0f0/ba8c0;Plus:c2870/c28a0/c2550/c2680/c2730/c0650.
    data = _buffer(args, 128)
    starting = int.from_bytes(data[120:124], "little") == 0
    comm = context.comm(_FIXED_P5[context.module_sha256])
    retained = False
    with _managed(comm, lambda: retained):
        status = 0
        if starting:
            status = _initialize(comm, context)
            if status:
                return status
            for field, value in (
                ("native_1080", 0),
                ("native_1084", 180000),
                ("native_1064", 0),
            ):
                comm.configure(field, value)
            _check(context)
            status = _status(comm.session(3, 1, normal_first=True))
            if status:
                return status
            for index in range(10):
                offset = index * 12
                if int.from_bytes(data[offset + 4 : offset + 8], "little") != 1:
                    continue
                status, reply = _exchange(
                    comm, context, bytes((0x31, 1, 0x11, 0x4A, data[offset]))
                )
                if not status and reply.ljust(4128, b"\0")[1:4] != b"\1\x11\x4a":
                    status = 3
                if status:
                    break
            if not status:
                retained = True
                return 0
        else:
            while int.from_bytes(data[124:128], "little") != 1:
                context.native_sleep(200)
                status, reply = _exchange(comm, context, b"\x31\3\x11\x4a")
                if not status and (len(reply) < 14 or reply[1:4] != b"\3\x11\x4a"):
                    status = 3
                if status:
                    break
                values = reply[4:14]
                if any(
                    int.from_bytes(data[i * 12 + 4 : i * 12 + 8], "little") == 1
                    and values[i] in (0, 1)
                    for i in range(10)
                ):
                    continue
                for index, value in enumerate(values):
                    data[index * 12 + 1] = value
                if any(
                    int.from_bytes(data[i * 12 + 4 : i * 12 + 8], "little") == 1
                    and values[i] not in (2, 4)
                    for i in range(10)
                ):
                    status = 1008
                break
        # Both helpers' native statuses are discarded; the original business result survives.
        _exchange(comm, context, b"\x31\2\x11\x4a")
        _check(context)
        _status(comm.session(1, 1))
        return status


def _efi52_switch(args: tuple[object, ...], context: TYContext) -> int:
    # 18:99700/99720/99820/9dd00;Plus:9d4e0/9d500/9d430 andP6:7adb0/7add0/7ad00.
    data = _buffer(args, 7)
    classic = context.module_sha256 == SHA_PLUS and context.mode == 22
    comm = context.comm(
        "native:1013e7d0" if classic else _FIXED_P5[context.module_sha256]
    )
    with _managed(comm):
        status = _initialize(comm, context)
        if status:
            return status
        for field, value in (
            ("native_1080", 0),
            ("native_1084", 180000),
            ("native_1064", 0),
        ):
            comm.configure(field, value)
        _check(context)
        status = _status(comm.session(3, 1, normal_first=True))
        if status:
            return status
        while data[4] == 0:
            status, payload = _hnscr_read(comm, context, 0x20, 0x2B, 0, 1)
            if status:
                break
            value = payload[0]
            if value not in (0, 1):
                status = 1000
                break
            data[5], data[6] = 1, value
            if int.from_bytes(data[:4], "little") == 1:
                status, reply = _exchange(
                    comm, context, bytes((0x2E, 0x20, 0x2B, int(value == 0)))
                )
                # Native has no length check; zero-backed receive padding supplies missing bytes.
                if not status and reply.ljust(4128, b"\0")[1:3] != b"\x20\x2b":
                    status = 3
                data[:4] = (2 if status else 0).to_bytes(4, "little")
                if status:
                    break
            context.native_sleep(1000)
        _check(context)
        _status(comm.session(1, 1))
        return status


def _efi53_classic_poll(comm: TYComm, context: TYContext) -> tuple[int, bytes]:
    # Plus7b110 temporarily clears P6+10a4; this is NOT ordinary UDS busy_ms.
    previous = _status(comm.read_field("native_10a4"))
    comm.configure("native_10a4", 0)
    try:
        status, reply = _exchange(comm, context, b"\x31\x03\x11\x40")
    except BaseException as primary:
        try:
            comm.configure("native_10a4", previous)
        except BaseException as secondary:  # noqa: BLE001 - preserve original HOST failure
            primary.add_note(
                f"TY field restoration also failed: {type(secondary).__name__}"
            )
        raise
    comm.configure("native_10a4", previous)
    if status:
        if reply in (b"\x7f\x31\x21", b"\x7f\x31\x24"):
            return 3000, b""
        return status, b""
    if len(reply) < 6 or reply[1:4] != b"\x03\x11\x40":
        return 3, b""
    return 0, reply[5:6]


def _efi53_routine(args: tuple[object, ...], context: TYContext) -> int:
    # 18:998c0/99900/999a0/99a50/9dd00/a3ef0 (C drops native success/loops).
    # Plus:9d940/9d600/9d6a0 andP6:7b260/7aed0/7af70/7b110.
    data = _buffer(args, 4)
    action = int.from_bytes(data[:4], "little")
    if action not in (0, 1):
        return 0
    if action == 1 and len(data) < 9:
        raise ValueError("EFI53 routine requires caller selector and stop byte")
    classic = context.module_sha256 == SHA_PLUS and context.mode == 22
    comm = context.comm(
        "native:1013e7d0" if classic else _FIXED_P5[context.module_sha256]
    )
    retained = False
    with _managed(comm, lambda: retained):
        if action == 0:
            status = _initialize(comm, context)
            if status:
                return status
            for field, value in (
                ("native_1080", 0),
                ("native_1084", 180000),
                ("native_1064", 0),
            ):
                comm.configure(field, value)
            _check(context)
            status = _status(comm.session(3, 1, normal_first=True))
            if status:
                return status
            status, payload = _hnscr_read(comm, context, 0x20, 0x2B, 0, 1)
            if not status and payload == b"\1":
                retained = True
                return 0
            if not status:
                status = 1000
        else:
            selector = 2 if int.from_bytes(data[4:8], "little") == 0 else 0
            status, reply = _exchange(
                comm, context, bytes((0x31, 1, 0x11, 0x40, selector, 0x65))
            )
            if not status and (
                len(reply) < (5 if classic else 4) or reply[1:4] != b"\x01\x11\x40"
            ):
                status = 3
            if not status:
                context.native_sleep(200)
                while data[8] == 0:
                    if classic:
                        status, payload = _efi53_classic_poll(comm, context)
                        if status == 3000:
                            context.native_sleep(200)
                            continue
                    else:
                        status, reply = _exchange(comm, context, b"\x31\x03\x11\x40")
                        if not status and (
                            len(reply) < 5 or reply[1:4] != b"\x03\x11\x40"
                        ):
                            status = 3
                        payload = reply[4:5]
                    if status:
                        break
                    if not classic and payload == b"\1":
                        context.native_sleep(200)
                        continue
                    if payload != b"\2":
                        status = 2000
                    break
        _check(context)
        _status(comm.session(1, 1))
        return status


def _efi62_values(args: tuple[object, ...], context: TYContext) -> int:
    # 18:bf270..bf530;Plus:c6080/c6100/c5f40/c6190 andclassic7f360..7f470.
    data = _buffer(args, 28)
    action = int.from_bytes(data[:4], "little")
    classic = context.module_sha256 == SHA_PLUS and context.mode == 22
    comm = context.comm(
        "native:1013e7d0" if classic else _FIXED_P5[context.module_sha256]
    )
    with _managed(comm):
        status = _initialize(comm, context)
        if status:
            return status
        for field, value in (
            ("native_1080", 0),
            ("native_1084", 180000),
            ("native_1064", 0),
        ):
            comm.configure(field, value)
        if action == 1:
            data[4:12] = bytes(8)
        _check(context)
        status = _status(comm.session(3, 1, normal_first=True))
        if status:
            return status
        if action == 0:
            high, low = (0xA1, 0x20) if classic else (0x20, 0)
            status, payload = _hnscr_read(comm, context, high, low, 0, 32)
            if not status:
                enabled = (
                    (payload[6] & 0x80, payload[6] & 0x40)
                    if classic
                    else (payload[5] & 1, payload[6] & 0x80)
                )
                for offset, value in zip((12, 16), enabled, strict=True):
                    if value:
                        data[offset : offset + 4] = (1).to_bytes(4, "little")
        else:
            status = 0
            for slot, low in enumerate((0x30, 0x31)):
                if int.from_bytes(data[12 + slot * 4 : 16 + slot * 4], "little") != 1:
                    continue
                offset = 4 + slot * 4
                if action == 1:
                    status, payload = _hnscr_read(comm, context, 0x20, low, 0, 4)
                    if not status:
                        data[offset : offset + 4] = payload
                elif int.from_bytes(data[20 + slot * 4 : 24 + slot * 4], "little") == 1:
                    status, reply = _exchange(
                        comm,
                        context,
                        bytes((0x2E, 0x20, low)) + bytes(data[offset : offset + 4]),
                    )
                    if not status and (
                        len(reply) < 3 or reply[1:3] != bytes((0x20, low))
                    ):
                        status = 3
                if status:
                    break
        _check(context)
        _status(comm.session(1, 1))
        return status


def _efi_throttle(args: tuple[object, ...], context: TYContext) -> int:
    # 18:9b620/995a0;Plus:9fa30/9d280. Normal session, no restore afterward.
    _buffer(args, 0)
    comm = context.comm(_FIXED_P5[context.module_sha256])
    with _managed(comm):
        status = _initialize(comm, context)
        if status:
            return status
        for field, value in (
            ("native_1080", 0),
            ("native_1084", 180000),
            ("native_1064", 0),
        ):
            comm.configure(field, value)
        _check(context)
        status = _status(comm.session(1, 1))
        if status:
            return status
        status, reply = _exchange(comm, context, b"\x31\x01\x11\x93")
        if status == 7:
            return _status(comm.read_field("native_10b0"))
        if not status and (len(reply) < 4 or reply[1:4] != b"\x01\x11\x93"):
            return 3
        return status


def _efi_session_transition(args: tuple[object, ...], context: TYContext) -> int:
    # 12:67df0;18:82b50;Plus:855f0 versus77dd0 for mode22.
    _buffer(args, 0)
    selector = (
        "native:1013e7d0"
        if context.module_sha256 == SHA_PLUS and context.mode == 22
        else _FIXED_P5[context.module_sha256]
    )
    comm = context.comm(selector)
    with _managed(comm):
        _check(context)
        _status(comm.session(1, 1))
        return 0


def _efi_learning_reset(args: tuple[object, ...], context: TYContext) -> int:
    # 12:1f3c0/1f4b0/1f570;18:2a060/2a150/2a210;
    # Plus:2fde0/2fd10/2b250. Setter deliberately precedes initialization.
    if args:
        raise ValueError("Native EFI learning reset takes no arguments")
    comm = context.comm("selected")
    with _managed(comm):
        _check(context)
        comm.configure(_PENDING_SETTER[context.module_sha256], 150)
        status = _initialize(comm, context)
        if status:
            return status
        status, reply = _exchange(comm, context, b"\x3b\x1e\x5a")
        if not status and len(reply) != 2:
            status = 3
        if status:
            return status
        context.native_sleep(1000)
        status, reply = _exchange(comm, context, b"\x04")
        if not status and len(reply) != 1:
            status = 3
        if not status:
            context.native_sleep(2000)
        return status


def _support_record(
    raw: bytes, offsets: tuple[int, ...], pid: int
) -> tuple[int, bytes]:
    if (
        type(raw) is not bytes
        or len(raw) != 4128
        or type(offsets) is not tuple
        or len(offsets) != 256
        or any(type(offset) is not int or not 0 <= offset <= 4128 for offset in offsets)
    ):
        raise ValueError(
            "Native support requires4128 immutable bytes and256 bounded offsets"
        )
    offset = offsets[pid]
    if offset == 4128:
        return 22, b""
    if offset + 1 >= len(raw) or offset + 2 + raw[offset + 1] > len(raw):
        return 99, b""
    return 0, raw[offset + 2 : offset + 2 + raw[offset + 1]]


def _support_position(payload: bytes, position: int, mask: int) -> tuple[int, int]:
    # 12:ba30;18:12340;Plus:13f70 counts nonzero preceding support bytes.
    index = position - 3
    if index >= len(payload):
        return 22, 0
    result = 2 + sum(value != 0 for value in payload[:index])
    if not payload[index] or payload[index] & mask != mask:
        return 22, result
    return 0, result


def _hv14_selected(export: str, args: tuple[object, ...], context: TYContext) -> int:
    """Exact HV14 support and battery read workers for all three supplied images."""
    minimum = {
        HV14_SUPPORT: 8,
        HV14_TEMPERATURE: 16,
        HV14_VOLTAGE: 25,
    }[export]
    data = _buffer(args, minimum)
    comm = context.comm("selected")
    with _managed(comm):
        status = _initialize(comm, context)
        if status:
            return status
        comm.configure(_PENDING_SETTER[context.module_sha256], 150)
        if export == HV14_SUPPORT:
            _check(context)
            status, raw, offsets = comm.support_snapshot(1)
            if _status(status):
                return status
            status, payload81 = _support_record(raw, offsets, 0x81)
            if status:
                return status
            for position in range(3, 19):
                status, _ = _support_position(payload81, position, 0xFF)
                if status:
                    return status
            status, payload87 = _support_record(raw, offsets, 0x87)
            if status:
                return status
            for position in range(3, 35):
                status, _ = _support_position(payload87, position, 0xFF)
                if status:
                    return status

            # Publish only after both native validation loops have succeeded.
            data[:4] = (sum(value != 0 for value in payload81) + 2).to_bytes(
                4, "little"
            )
            count = sum(value != 0 for value in payload87)
            if not count:
                return 22
            data[4:8] = (count + 2).to_bytes(4, "little")
            return 0

        if export == HV14_TEMPERATURE:
            request = b"\x21\x87"
            expected_length = int.from_bytes(data[4:8], "little")
        else:
            request = b"\x21\x81"
            expected_length = int.from_bytes(data[:4], "little")
        status, reply = _exchange(comm, context, request)
        if status:
            return status
        receive = reply.ljust(34 if export == HV14_TEMPERATURE else 18, b"\0")
        if len(reply) != expected_length or receive[1] != (
            0x87 if export == HV14_TEMPERATURE else 0x81
        ):
            return 3
        if export == HV14_TEMPERATURE:
            minimum_word = min(
                int.from_bytes(receive[offset : offset + 2], "big")
                for offset in range(2, 34, 2)
            )
            struct.pack_into("<d", data, 8, minimum_word / 256 - 50)
            return 0
        total = 0
        included = 0
        mask = data[24]
        for group in range(4):
            if not mask & 1:
                start = 2 + group * 4
                total += int.from_bytes(receive[start : start + 2], "big")
                total += int.from_bytes(receive[start + 2 : start + 4], "big")
                included += 1
            mask >>= 1
        value = total * (5 / 4096) / included if included else float("nan")
        struct.pack_into("<d", data, 16, value)
        return 0


def _asg_support(args: tuple[object, ...], context: TYContext) -> int:
    # 12:1aac0/1abc0/1add0;18:25760/25860/25a70;
    # Plus:2c170/2bdf0/2b6b0, exact snapshots, never one flattened exchange.
    data = _buffer(args, 24)
    comm = context.comm("selected")
    with _managed(comm):
        status = _initialize(comm, context)
        if status:
            return status
        comm.configure(_PENDING_SETTER[context.module_sha256], 150)
        _check(context)
        status, raw, offsets = comm.support_snapshot(1)
        if _status(status):
            return status
        records: dict[int, bytes] = {}
        positions = {}
        for pid, position in (
            (0x89, 9),
            (0x89, 10),
            (0x8A, 0x17),
            (0x8A, 0x18),
            (0x8A, 0x24),
            (0x8A, 0x25),
            (0x8A, 0x26),
        ):
            if pid not in records:
                status, payload = _support_record(raw, offsets, pid)
                if status:
                    return status
                records[pid] = payload
            status, result = _support_position(records[pid], position, 255)
            if status:
                return status
            positions[pid, position] = result
        values = (
            sum(value != 0 for value in records[0x89]) + 2,
            positions[0x89, 9],
            sum(value != 0 for value in records[0x8A]) + 2,
            positions[0x8A, 0x18],
            positions[0x8A, 0x24],
        )
        for index, value in enumerate(values):
            data[index * 4 : index * 4 + 4] = value.to_bytes(4, "little")
        _check(context)
        status, raw, offsets = comm.support_snapshot(2)
        if _status(status):
            return status
        status, payload = _support_record(raw, offsets, 0x42)
        if status:
            return status
        for position in (3, 4):
            status, _ = _support_position(payload, position, 0x40)
            if status:
                return status
        data[20:24] = (sum(value != 0 for value in payload) + 3).to_bytes(4, "little")
        return 0


def _amt_history_support(args: tuple[object, ...], context: TYContext) -> int:
    # 12:1f620/1f710;18:2a2c0/2a3c0;Plus:301b0/30090.
    old = context.module_sha256 == SHA_12
    count, first = (34, 40) if old else (46, 52)
    data = _buffer(args, 108 if old else 148)
    comm = context.comm("selected")
    with _managed(comm):
        status = _initialize(comm, context)
        if status:
            return status
        comm.configure(_PENDING_SETTER[context.module_sha256], 150)
        previous_size = 0
        for kind, offset in ((4, first), (3, first + count)):
            _check(context)
            status, raw, offsets = comm.support_snapshot(kind)
            _status(status)
            if not status:
                status, payload = _support_record(raw, offsets, 0xA1)
                if not status:
                    if len(payload) > count:
                        raise ValueError(
                            "AMT support record exceeds native output allocation"
                        )
                    data[offset : offset + count] = payload.ljust(count, b"\0")
                    previous_size = len(payload)
            if kind == 3 and not old:
                # Shared native local retains the first size on second-call failure.
                data[144:148] = previous_size.to_bytes(4, "little")
            if status:
                return status
        return 0


def _amt_history(write: bool, args: tuple[object, ...], context: TYContext) -> int:
    # 12:1f830/1f900/1f9d0/1faa0;18:2a4e0/2a5b0/2a680/2a750;
    # Plus:2ffd0/2fec0/303a0/30290.12 copies34 bytes;18/Plus copy46.
    old = context.module_sha256 == SHA_12
    count = 34 if old else 46
    data = _buffer(args, count if write and old else 156 if write else count + 6)
    size = count + 2
    if write and not old:
        kind = int.from_bytes(data[152:156], "little")
        size = (
            ((int.from_bytes(data[148:152], "little") + 4) & 0xFFFFFFFF)
            if kind == 2
            else ((int.from_bytes(data[144:148], "little") + 2) & 0xFFFFFFFF)
            if kind == 3
            else 2
        )
        if size > 48:
            raise ValueError("AMT history write exceeds native request allocation")
    comm = context.comm("selected")
    with _managed(comm):
        status = _initialize(comm, context)
        if status:
            return status
        comm.configure(_PENDING_SETTER[context.module_sha256], 150)
        request = (b"\x3b\xa1" + bytes(data[:count]))[:size] if write else b"\xa9\xa1"
        status, reply = _exchange(comm, context, request)
        if not status and reply.ljust(2, b"\0")[1] != 0xA1:
            status = 3
        if not write:
            # Native copies fixed output and raw receive length even after error.
            data[:count] = reply.ljust(count + 2, b"\0")[2 : count + 2]
            data[count + 2 : count + 6] = len(reply).to_bytes(4, "little")
        return status


def _asg_status_read(data: bytearray, comm: TYComm, context: TYContext) -> int:
    # 12:1b3d0/1b500/1b5f0;18:26070/261a0/26290;Plus:2bb80/2b810/2bbc0.
    expected, index = (
        int.from_bytes(data[offset : offset + 4], "little") for offset in (0, 4)
    )
    status, reply = _exchange(comm, context, b"\x21\x89")
    if not status and len(reply) != expected:
        status = 3
    padded = reply.ljust(4128, b"\0")
    data[28:30] = bytes((padded[index + 1], padded[index]))
    if status:
        return status
    expected, first, second = (
        int.from_bytes(data[offset : offset + 4], "little") for offset in (8, 12, 16)
    )
    status, reply = _exchange(comm, context, b"\x21\x8a")
    if not status and len(reply) != expected:
        status = 3
    padded = reply.ljust(4128, b"\0")
    data[24:28] = bytes(
        (padded[first], padded[second], padded[second + 1], padded[second + 2])
    )
    return status


def _asg_learning(export: str, args: tuple[object, ...], context: TYContext) -> int:
    # 12:1af00..1b210;18:25ba0..25eb0;Plus:2b910..2bce0.
    data = _buffer(args, 36)
    index, first, second, size = (
        int.from_bytes(data[offset : offset + 4], "little")
        for offset in (4, 12, 16, 20)
    )
    if index >= 4127 or first >= 4128 or second >= 4126 or size > 4128:
        raise ValueError("ASG indexes or request size exceed native allocation")
    comm = context.comm("selected")
    close = True
    with _managed(comm, lambda: not close):
        if export == ASG_INITIAL:
            status = _initialize(comm, context)
            if not status:
                comm.configure(_PENDING_SETTER[context.module_sha256], 150)
                count = int.from_bytes(data[32:36], "little")
                if count < 2:
                    request = (b"\x30\x42\0\x40\x40" + bytes(4123))[:size]
                    while True:
                        status, reply = _exchange(comm, context, request)
                        if not status and len(reply) != 2:
                            status = 3
                        if not status or status in (1460, 5):
                            break
                        count += 1
                        data[32:36] = count.to_bytes(4, "little")
                        context.native_sleep(100)
                        if count >= 2:
                            break
                    if not status:
                        context.native_sleep(3000)
                        status = _asg_status_read(data, comm, context)
                        if not status:
                            data[30] = 1
            close = data[30] != 1
            return status
        if export == ASG_STATUS_004:
            for _ in range(10):
                status = _initialize(comm, context)
                if not status:
                    comm.configure(_PENDING_SETTER[context.module_sha256], 150)
                    status = _asg_status_read(data, comm, context)
                    break
                context.native_sleep(1000)
            close = data[24] == 255 or status != 0
            return status
        status = _initialize(comm, context) if data[30] == 1 else 0
        comm.configure(_PENDING_SETTER[context.module_sha256], 150)
        if export == ASG_STATUS_TIMEOUT:
            # Native discards initialize's return and always reads after timeout.
            return _asg_status_read(data, comm, context)
        if not status:
            status = _asg_status_read(data, comm, context)
        close = bool(status or (data[24] == 127 and data[31] == 0) or data[24] == 255)
        return status


def _asg_learned_flag(args: tuple[object, ...], context: TYContext) -> int:
    # 12:1b2e0/1b5f0;18:25f80/26290;Plus:2b5e0/2bbc0.
    data = _buffer(args, 28)
    expected, first, second = (
        int.from_bytes(data[offset : offset + 4], "little") for offset in (8, 12, 16)
    )
    # Host rejects the original helper's out-of-allocation pointer arithmetic.
    if first >= 4128 or second >= 4126:
        raise ValueError("ASG learned-flag indexes exceed native receive buffer")
    comm = context.comm("selected")
    with _managed(comm):
        status = _initialize(comm, context)
        if status:
            return status
        comm.configure(_PENDING_SETTER[context.module_sha256], 150)
        status, reply = _exchange(comm, context, b"\x21\x8a")
        if not status and len(reply) != expected:
            status = 3
        padded = reply.ljust(4128, b"\0")
        # Native writes all four output bytes even after wire/length failure.
        data[24:28] = bytes(
            (padded[first], padded[second], padded[second + 1], padded[second + 2])
        )
        return status


def _pm_wait_stop(args: tuple[object, ...], context: TYContext) -> int:
    # 18:bb8f0;Plus:c1ca0. Native stop flag1002 deliberately retains connection.
    data = _buffer(args, 8)
    comm = context.comm(_FIXED_P5[context.module_sha256])
    close = True
    with _managed(comm, lambda: not close):
        while True:
            _check(context)
            if int.from_bytes(data[4:8], "little"):
                close = False
                return 1002
            context.native_sleep(200)
            status, reply = _exchange(comm, context, b"\x31\x03\x11\x3e")
            if not status and (len(reply) < 5 or reply[1:4] != b"\x03\x11\x3e"):
                status = 3
            if status:
                status = 1001 if status == 2 else status
                _exchange(comm, context, b"\x31\x02\x11\x3e")
                break
            if reply[4] <= 1:
                continue
            if reply[4] != 2:
                status = 1001
                _exchange(comm, context, b"\x31\x02\x11\x3e")
                break
            status, reply = _exchange(comm, context, b"\x22\x12\x1a")
            if not status:
                if len(reply) < 4 or reply[1:3] != b"\x12\x1a":
                    status = 3
                else:
                    status = {
                        1: 1013,
                        3: 1014,
                        4: 1007,
                        5: 1008,
                        6: 1009,
                        7: 1010,
                        8: 1011,
                        9: 1012,
                    }.get(reply[3], 3)
            break
        _check(context)
        _status(comm.session(1, 1))
        close = status != 1002
        return status


def _pm_start(args: tuple[object, ...], context: TYContext) -> int:
    # 18:bb640/bbae0/bbc80/bbdd0;Plus:c2240/c2140/c2340/c1be0.
    data = _buffer(args, 1)
    comm = context.comm(_FIXED_P5[context.module_sha256])
    retained = False
    with _managed(comm, lambda: retained):
        status = _initialize(comm, context)
        if status:
            return status
        for field, value in (
            ("native_1080", 0),
            ("native_1084", 180000),
            ("native_1064", 0),
        ):
            comm.configure(field, value)
        for mode in (1, 3):
            _check(context)
            status = _status(comm.session(mode, 1))
            if status:
                return status
        status, reply = _exchange(
            comm, context, b"\x31\x01\x11\x3e" + bytes(((data[0] - 1) & 255,))
        )
        if status:
            first_error = _status(comm.read_field("native_10b0"))
            if first_error == 0x69:
                status = 1004
            elif _status(comm.read_field("native_10b0")) == 0x6B:
                status = 1006
        elif len(reply) < 4 or reply[1:4] != b"\x01\x11\x3e":
            status = 3
        if not status:
            # Native result/stop exports reuse this exact initialized manager.
            retained = True
            return 0
        _exchange(comm, context, b"\x31\x02\x11\x3e")
        if status == 1004:
            status, reply = _exchange(comm, context, b"\x22\x12\x1a")
            if not status:
                status = (
                    (1007 + reply[3] - 4)
                    if len(reply) >= 4
                    and reply[1:3] == b"\x12\x1a"
                    and 4 <= reply[3] <= 9
                    else 3
                )
        _check(context)
        _status(comm.session(1, 1))
        return status


def _pm_result(export: str, args: tuple[object, ...], context: TYContext) -> int:
    # 18:bb760/bbbd0/bb7e0/bbc80;Plus:c20d0/c2000/c23f0/c2340.
    if export == EFI_PM_STOP:
        if args:
            raise ValueError("Native PM stop takes no arguments")
        comm = context.comm(_FIXED_P5[context.module_sha256])
        # Stop discards its helper's native status and keeps the shared connection.
        with _managed(comm, lambda: True):
            _exchange(comm, context, b"\x31\x02\x11\x3e")
            return 0
    data = _buffer(args, 16)
    comm = context.comm(_FIXED_P5[context.module_sha256])
    with _managed(comm):
        status = 3
        while not int.from_bytes(data[12:16], "little"):
            _check(context)
            context.native_sleep(200)
            status, reply = _exchange(comm, context, b"\x31\x03\x11\x3e")
            if status:
                break
            if len(reply) < 5 or reply[1:4] != b"\x03\x11\x3e":
                status = 3
                break
            data[8:12] = (1).to_bytes(4, "little")
            if reply[4] != 1:
                break
            status = 3
        _check(context)
        _status(comm.session(1, 1))
        return status


def _pm_read(export: str, args: tuple[object, ...], context: TYContext) -> int:
    # 18:bb5c0/bba30/bb800/bbd20;Plus:c24d0/c2410/c1f30/c1e70.
    support = export == EFI_PM_SUPPORT
    data = _buffer(args, 17 if support else 19)
    # The native body snapshots support flags before initialization.
    identifiers = [
        identifier for bit, identifier in ((8, 0x75), (4, 0x76)) if data[16] & bit
    ]
    comm = context.comm(_FIXED_P5[context.module_sha256])
    with _managed(comm):
        status = _initialize(comm, context)
        if status:
            return status
        for field, value in (
            ("native_1080", 0),
            ("native_1084", 180000),
            ("native_1064", 0),
        ):
            comm.configure(field, value)
        for mode in (1, 3):
            _check(context)
            status = _status(comm.session(mode, 1))
            if status:
                return status
        for index, identifier in enumerate((0,) if support else identifiers):
            status, reply = _exchange(comm, context, bytes((0x22, 0x11, identifier)))
            if status:
                break
            if (len(reply) != 35 if support else len(reply) < 4) or reply[1:3] != bytes(
                (0x11, identifier)
            ):
                status = 3
                break
            data[16 if support else 17 + index] = reply[17 if support else 3]
        _check(context)
        _status(comm.session(1, 1))
        return status


def _ecd_reset(export: str, args: tuple[object, ...], context: TYContext) -> int:
    # 18:8d0e0/8d140/8d1a0/90a70;Plus:90310/90370/903d0/8f4d0.
    if args:
        raise ValueError("Native ECD reset takes no arguments")
    comm = context.comm(_FIXED_P5[context.module_sha256])
    with _managed(comm):
        status = _initialize(comm, context)
        if status:
            return status
        for field, value in (
            ("native_1080", 0),
            ("native_1084", 180000),
            ("native_1064", 0),
        ):
            comm.configure(field, value)
        for mode in (1, 3):
            _check(context)
            status = _status(comm.session(mode, 1))
            if status:
                return status
        request = (
            b"\x2e\x20\x14" + bytes(5)
            if export == ECD_ASH_CLEAR
            else b"\x2e\x20\x17" + bytes(4)
        )
        status, reply = _exchange(comm, context, request)
        # 18 helper C incorrectly folds the echo branch; complete ASM retains it.
        if not status and (len(reply) < 3 or reply[1:3] != request[1:3]):
            status = 3
        _check(context)
        restored = _status(comm.session(1, 1))
        return restored if restored else status


def _frequency(write: bool, args: tuple[object, ...], context: TYContext) -> int:
    # 18:bb360/bb410/bb490/bb520;Plus:c1a10/c1b60/c1ab0/c1950.
    data = _buffer(args, 5 if write else 1)
    comm = context.comm(_FIXED_P5[context.module_sha256])
    with _managed(comm):
        status = _initialize(comm, context)
        if status:
            return status
        for field, value in (
            ("native_1080", 0),
            ("native_1084", 180000),
            ("native_1064", 0),
        ):
            comm.configure(field, value)
        for mode in (1, 3):
            _check(context)
            status = _status(comm.session(mode, 1))
            if status:
                return status
        context.native_sleep(200)
        request = (
            b"\x2e\x20\x2e" + bytes(((data[4] - 1) & 255,))
            if write
            else b"\x22\x20\x2e"
        )
        status, reply = _exchange(comm, context, request)
        if not status:
            if len(reply) < (3 if write else 4) or reply[1:3] != b"\x20\x2e":
                status = 3
            elif not write:
                data[0] = reply[3]
        _check(context)
        # Both builds discard the restoration return, unlike ECO10.
        _status(comm.session(1, 1))
        if not write and not status and data[0] > 4:
            status = 3
        return status


def _char_to_int(value: int) -> int:
    value &= 0xFF
    for start, end, offset in (
        (0x30, 0x39, 0x30),
        (0x41, 0x46, 0x37),
        (0x61, 0x66, 0x57),
    ):
        if start <= value <= end:
            return value - offset
    return -1


def _hex_to_bytes(args: tuple[object, ...], *, wide: bool) -> int:
    # 18:92e0/9380 ANSI;Plus:a510/a4d0 UTF16 unit count, low-byte conversion.
    if type(args) is not tuple or len(args) != 3:
        raise ValueError("Native hex conversion requires three arguments")
    source, output, capacity = args
    if (
        type(source) is not bytes
        or not 1 <= len(source) <= 65536
        or type(output) is not bytearray
        or len(output) > 65536
        or type(capacity) is not int
        or not -0x80000000 <= capacity <= 0x7FFFFFFF
        or capacity > len(output)
    ):
        raise ValueError(
            "Bounded native input bytes, output buffer and signed capacity required"
        )
    step = 2 if wide else 1
    end = next(
        (i for i in range(0, len(source), step) if source[i : i + step] == bytes(step)),
        None,
    )
    if end is None:
        raise ValueError("Native hex input requires an aligned terminator")
    count = end // step
    if count % 2 or capacity < count // 2:
        return 0xFFFFFFFF
    for index in range(0, count, 2):
        high = _char_to_int(source[index * step])
        low = _char_to_int(source[(index + 1) * step])
        if high == -1 or low == -1:
            return 0xFFFFFFFF
        output[index // 2] = (high << 4) | low
    return 0


def _hv10_read(data: bytearray, comm: TYComm, context: TYContext) -> int:
    # 12:26980;18:31660;Plus:36700, unconditional outputs even native failure.
    first = int.from_bytes(data[:4], "little")
    flag = int.from_bytes(data[8:12], "little")
    if first >= 4127 or flag >= 4128:
        raise ValueError("HV10 indexes exceed native receive allocation")
    status, reply = _exchange(comm, context, b"\x21\x92")
    padded = reply.ljust(4128, b"\0")
    if status == 3 and padded[0] == 0:
        status = 1460
    data[24] = padded[flag] & data[21]
    data[22:24] = padded[first : first + 2]
    return status


def _hv10_selected(export: str, args: tuple[object, ...], context: TYContext) -> int:
    data = _buffer(
        args, 26 if export == HV10_JUDGE else 25 if export != HV10_SUPPORT else 22
    )
    started = context.ticks() & 0xFFFFFFFF if export in (HV10_WAIT, HV10_JUDGE) else 0
    if export == HV10_WAIT:
        data[23] = 0
    comm = context.comm("selected")
    with _managed(comm):
        status = _initialize(comm, context)
        if status:
            return status
        comm.configure(_PENDING_SETTER[context.module_sha256], 150)
        if export == HV10_SUPPORT:
            status, raw, offsets = comm.support_snapshot(1)
            if _status(status):
                return status
            status, primary = _support_record(raw, offsets, 0x92)
            if status:
                return status
            positions = []
            for position, mask in ((0x12, 0xFF), (0x13, 0xFF), (0x1C, 0x80)):
                status, result = _support_position(primary, position, mask)
                if status:
                    return status
                positions.append(result)
            optional_status, secondary = _support_record(raw, offsets, 0x93)
            optional_position = 0
            if not optional_status:
                optional_status, optional_position = _support_position(
                    secondary, 0x16, 0x80
                )
                if len(secondary) < 0x16 - 2:
                    optional_position = 0
            data[20] = secondary[0x16 - 3] if not optional_status else 0
            data[21] = primary[0x1C - 3]
            for offset, value in (
                (0, positions[0]),
                (4, optional_position),
                (8, positions[2]),
                (12, sum(v != 0 for v in primary) + 2),
            ):
                data[offset : offset + 4] = value.to_bytes(4, "little")
            count = sum(v != 0 for v in secondary)
            if count:
                data[16:20] = (count + 2).to_bytes(4, "little")
            return 0
        while True:
            status = _hv10_read(data, comm, context)
            if export == HV10_WAIT:
                elapsed = ((context.ticks() & 0xFFFFFFFF) - started) & 0xFFFFFFFF
                if not status and (data[23] == 0x14 or elapsed > 661000):
                    return 12000
            if status:
                return status
            if export != HV10_WAIT:
                break
            context.native_sleep(1000)
        if export == HV10_READ:
            return {0x13: 17000, 1: 12000, 0x14: 12000}.get(data[23], 10000)
        if data[22] == 3:
            return 13000
        if data[22] != 4:
            return 10000
        if not data[20]:
            return 11000
        position = int.from_bytes(data[4:8], "little")
        if position >= 4128:
            raise ValueError("HV10 secondary index exceeds native receive allocation")
        status, reply = _exchange(comm, context, b"\x21\x93")
        if status:
            return status
        if (
            len(reply) != int.from_bytes(data[16:20], "little")
            or len(reply) < 2
            or reply[1] != 0x93
        ):
            return 3
        data[25] = reply.ljust(4128, b"\0")[position] & data[20]
        return 11000


def _hv12_selected(export: str, args: tuple[object, ...], context: TYContext) -> int:
    # Full source12:26f60..276b0;18:31c40..32390;Plus:370e0..37850.
    data = (
        _buffer(args, 12 if export == HV12_SUPPORT else 8)
        if export in (HV12_SUPPORT, HV12_DTC_STATUS)
        else None
    )
    if data is None:
        # Wrapper still takes and forwards its pointer; these workers ignore it.
        _buffer(args, 0)
    comm = context.comm("selected")
    with _managed(comm):
        if export == HV12_DTC_STATUS:
            comm.configure(_PENDING_SETTER[context.module_sha256], 150)
        status = _initialize(comm, context)
        if status:
            return status
        if export != HV12_DTC_STATUS:
            comm.configure(_PENDING_SETTER[context.module_sha256], 150)
        if export == HV12_SUPPORT:
            assert data is not None
            status, raw, offsets = comm.support_snapshot(1)
            if _status(status):
                return status
            status, payload = _support_record(raw, offsets, 0x92)
            if status:
                return status
            status, position = _support_position(payload, 0x13, 0xFF)
            if status:
                return status
            data[:4] = position.to_bytes(4, "little")
            data[8:12] = (sum(value != 0 for value in payload) + 2).to_bytes(
                4, "little"
            )
            return 0
        if export == HV12_UPDATE:
            # Exact12/18 send zero; Plus passes1 to its parameterized helper.
            status, reply = _exchange(
                comm, context, b"\x3b\x1f" + bytes((context.module_sha256 == SHA_PLUS,))
            )
            if not status and reply.ljust(4128, b"\0")[1] != 0x1F:
                status = 3
            return 130000 if status else 120000
        _check(context)
        status, reply = comm.read_dtcs(0x80, 0x1000)
        _status(status)
        if type(reply) is not bytes or len(reply) > 4128:
            raise ValueError("Native HV12 DTC reply exceeds receive allocation")
        if not status and reply.ljust(2, b"\0")[1]:
            status = 100000
        if export == HV12_AFTER:
            return {0: 140000, 100000: 130000}.get(status, status)
        if status:
            return status
        assert data is not None
        position = int.from_bytes(data[:4], "little")
        if position >= 4128:
            raise ValueError("HV12 EEPROM index exceeds native allocation")
        context.native_sleep(1000)
        status, reply = _exchange(comm, context, b"\x21\x92")
        padded = reply.ljust(4128, b"\0")
        if status == 3 and padded[0] == 0:
            status = 1460
        data[4:8] = padded[position].to_bytes(4, "little")
        if not status:
            return {0x13: 110000, 0x14: 150000}.get(padded[position], 170000)
        return status


def _hv_battery_field(export: str, args: tuple[object, ...], context: TYContext) -> int:
    # 18:72810/72920/72a20/72af0/72c10 and72d20/72e40/72f40/73010/73100;
    # Plus:6a480/6a280/6a570/6a640/6a380 and6a950/6a860/6a760.
    writing = export == HV_BATTERY_WRITE
    data = _buffer(args, 80 if writing else 16)
    action_offset = 76 if writing else 12
    action = int.from_bytes(data[action_offset : action_offset + 4], "little")
    comm = context.comm("selected")
    with _managed(comm):
        status = _initialize(comm, context)
        if status:
            return status
        comm.configure(_PENDING_SETTER[context.module_sha256], 150)
        if action == 0:
            status, raw, offsets = comm.support_snapshot(1)
            if _status(status):
                return status
            status, payload = _support_record(raw, offsets, 0xB0)
            if status:
                return status
            status, position = _support_position(payload, 0x30, 0)
            if len(payload) >= 0x30 - 2:
                data[:4] = position.to_bytes(4, "little")
            if status:
                return status
            data[4:8] = sum(value != 0 for value in payload).to_bytes(4, "little")
            status, raw, offsets = comm.support_snapshot(3)
            if _status(status):
                return status
            # Unlike HV18, native performs no support check before raw+offset+1.
            _support_record(raw, offsets, 0x44)
            offset = offsets[0x44]
            if offset >= 4127:
                raise ValueError(
                    "HV44 support pointer exceeds native receive allocation"
                )
            data[8:12] = raw[offset + 1].to_bytes(4, "little")
            return 0
        if action == 1:
            length = (int.from_bytes(data[8:12], "little") + 2) & 0xFFFFFFFF
            capacity = 63 if writing else 4128
            if length > capacity:
                raise ValueError("HV44 request exceeds native allocation")
            request = bytearray(capacity)
            request[:3] = b"\x3b\x44\x08"
            if writing:
                request[11:13] = data[21:23]
            status, reply = _exchange(comm, context, bytes(request[:length]))
            return 3 if not status and (len(reply) < 2 or reply[1] != 0x44) else status
        if action == 2:
            position = int.from_bytes(data[:4], "little")
            if position >= 4127:
                raise ValueError("HV44 index exceeds native receive allocation")
            expected = (int.from_bytes(data[4:8], "little") + 2) & 0xFFFFFFFF
            context.native_sleep(3000)
            status, reply = _exchange(comm, context, b"\x21\xb0")
            if not status:
                if len(reply) < expected or len(reply) < 2 or reply[1] != 0xB0:
                    return 3
                desired = bytes(data[21:23]) if writing else bytes(2)
                if reply.ljust(4128, b"\0")[position : position + 2] != desired:
                    return 3
            return status
        return 0


def _hv_accelerator(
    args: tuple[object, ...], context: TYContext, *, clearing: bool = False
) -> int:
    # 18:6e140/6e260/6e390/6e4c0/6e5b0;
    # Plus:651e0/64fa0/652e0/64eb0/650e0. Four DWORDs, no pointers.
    # HV19 exact18:6e6d0/6e7f0/6e920/6ea50/6eb50;
    # Plus:65730/654f0/65830/65400/65630. Different masks and expected bytes.
    position_field, mask = (0x2E, 8) if clearing else (0x2C, 0x10)
    data = _buffer(args, 16)
    action = int.from_bytes(data[12:16], "little")
    comm = context.comm("selected")
    with _managed(comm):
        status = _initialize(comm, context)
        if status:
            return status
        comm.configure(_PENDING_SETTER[context.module_sha256], 150)
        if action == 0:
            status, raw, offsets = comm.support_snapshot(1)
            if _status(status):
                return status
            status, payload = _support_record(raw, offsets, 0xB0)
            if status:
                return status
            status, position = _support_position(payload, position_field, 0xFF)
            if len(payload) >= position_field - 2:
                # Source position helper publishes the index before mask failure.
                data[:4] = position.to_bytes(4, "little")
            if status:
                return status
            status, _ = _support_position(payload, position_field + 1, 0xFF)
            if status:
                return status
            data[4:8] = sum(value != 0 for value in payload).to_bytes(4, "little")
            status, raw, offsets = comm.support_snapshot(3)
            if _status(status):
                return status
            status, payload = _support_record(raw, offsets, 0x41)
            if status:
                return status
            for field in (3, 4):
                status, _ = _support_position(payload, field, mask)
                if status:
                    return status
            data[8:12] = len(payload).to_bytes(4, "little")
            return 0
        if action == 1:
            length = (int.from_bytes(data[8:12], "little") + 2) & 0xFFFFFFFF
            if length > 4128:
                raise ValueError("HV accelerator request exceeds native allocation")
            request = (bytes((0x3B, 0x41, mask, mask)) + bytes(4124))[:length]
            status, reply = _exchange(comm, context, request)
            if not status and (len(reply) < 2 or reply[1] != 0x41):
                return 3
            return status
        if action == 2:
            position = int.from_bytes(data[:4], "little")
            if position >= 4127:
                raise ValueError(
                    "HV accelerator index exceeds native receive allocation"
                )
            expected = (int.from_bytes(data[4:8], "little") + 2) & 0xFFFFFFFF
            context.native_sleep(3000)
            status, reply = _exchange(comm, context, b"\x21\xb0")
            if not status:
                if len(reply) < expected or len(reply) < 2 or reply[1] != 0xB0:
                    return 3
                desired = bytes(2) if clearing else b"\x10\x68"
                if reply.ljust(4128, b"\0")[position : position + 2] != desired:
                    return 1001
            return status
        return 0


def _hv_history(args: tuple[object, ...], context: TYContext) -> int:
    # 18:72640/72710;Plus:6a1c0/6a0c0. Native clears exactly61 bytes.
    data = _buffer(args, 68)
    comm = context.comm("selected")
    with _managed(comm):
        status = _initialize(comm, context)
        if status:
            return status
        comm.configure(_PENDING_SETTER[context.module_sha256], 150)
        status, reply = _exchange(comm, context, b"\xa9\x44")
        if status:
            return status
        if len(reply) < 3 or reply[1] != 0x44:
            return 3
        payload = reply[2:]
        if len(payload) > len(data):
            raise ValueError("HV history reply exceeds caller allocation")
        data[:61] = bytes(61)
        data[: len(payload)] = payload
        data[64:68] = len(payload).to_bytes(4, "little")
        return 0


def _hv_reset(export: str, args: tuple[object, ...], context: TYContext) -> int:
    # 12:59be0/59cb0,5f820/5f8f0;18:66260/66330,6c8e0/6c9b0;
    # Plus:5dc80/5dbc0,63800/63720. HV15 C loses success; full ASM retains it.
    if args:
        raise ValueError("Native HV reset takes no arguments")
    identifier = {
        HV_HISTORY_RESET: 0x31,
        HV_BATTERY_RESET: 0x1F,
        HV_READY_CANCEL: 0x23,
        HV_SERVICE: 0x21,
    }[export]
    comm = context.comm("selected")
    with _managed(comm):
        status = _initialize(comm, context)
        if status:
            return status
        comm.configure(_PENDING_SETTER[context.module_sha256], 150)
        if export == HV_READY_CANCEL:
            context.native_sleep(10000)
        status, reply = _exchange(comm, context, bytes((0x3B, identifier, 1)))
        if not status and (
            len(reply) != 2
            or (
                export in (HV_HISTORY_RESET, HV_BATTERY_RESET)
                and reply[1] != identifier
            )
        ):
            status = 3
        return status


def run_body(export: str, args: tuple[object, ...], context: TYContext) -> int:
    """Execute an exact reviewed business body; missing operations remain errors."""
    if (
        context.module_sha256 not in _SOURCE_OPERATIONS
        or hashlib.sha256(context.module_bytes).hexdigest() != context.module_sha256
    ):
        raise TYSourceError("Exact supplied TY powertrain source identity required")
    if export not in supported_exports(context.module_sha256):
        raise TYSourceError("TY powertrain export has no complete reviewed body")
    if export in (HV10_SUPPORT, HV10_READ, HV10_WAIT, HV10_JUDGE):
        return _hv10_selected(export, args, context)
    if export in (HV12_SUPPORT, HV12_DTC_STATUS, HV12_UPDATE, HV12_AFTER):
        return _hv12_selected(export, args, context)
    if export in (HV14_SUPPORT, HV14_TEMPERATURE, HV14_VOLTAGE):
        return _hv14_selected(export, args, context)
    if export in (HV_BATTERY_WRITE, HV_BATTERY_CLEAR):
        return _hv_battery_field(export, args, context)
    if export in (HV_ACCELERATOR, HV_ACCELERATOR_CLEAR):
        return _hv_accelerator(args, context, clearing=export == HV_ACCELERATOR_CLEAR)
    if export == HV_HISTORY_READ:
        return _hv_history(args, context)
    if export in (HV_HISTORY_RESET, HV_BATTERY_RESET, HV_READY_CANCEL, HV_SERVICE):
        return _hv_reset(export, args, context)
    if export == ECD_CHAR:
        if (
            len(args) != 1
            or type(args[0]) is not int
            or not -0x80000000 <= args[0] <= 0xFFFFFFFF
        ):
            raise ValueError("Native char integer argument required")
        return _char_to_int(args[0])
    if export == ECD_HEX:
        return _hex_to_bytes(args, wide=context.module_sha256 == SHA_PLUS)
    if export in (ECD_DUMMY59, ECD_DUMMY60):
        # 18 workers8d840/8de40 andPlus909b0/912a0 publish these exact statuses.
        _buffer(args, 0)
        return 1001 if export == ECD_DUMMY59 else 1000
    if export == HNSCR_ADJUST:
        return _hnscr_adjust(args, context)
    if export == HNSCR_RESET:
        return _hnscr_reset(args, context)
    if export == ECT_PREFIXED:
        return _ect_prefixed(args, context)
    if export == ECT_BULK:
        return _ect_bulk(args, context)
    if export == ECT_CHECKSUM:
        return _ect_checksum(args, context)
    if export in _ECT_MEMORY:
        return _ect_memory(export, args, context)
    if export in _ECT_ROUTINES:
        return _ect_routine(export, args, context)
    if export == EFI55_TABLE:
        return _efi55_table(args, context)
    if export in (EFI61_SUPPORT, EFI61_WRITE):
        return _efi61_values(export, args, context)
    if export == EFI59_ROUTINE:
        return _efi59_routine(args, context)
    if export == EFI52_SWITCH:
        return _efi52_switch(args, context)
    if export == EFI53_ROUTINE:
        return _efi53_routine(args, context)
    if export == EFI62_VALUES:
        return _efi62_values(args, context)
    if export == EFI_SESSION_TRANSITION:
        return _efi_session_transition(args, context)
    if export == EFI_THROTTLE_LEARN:
        return _efi_throttle(args, context)
    if export == EFI_LEARNING_RESET:
        return _efi_learning_reset(args, context)
    if export == AMT_HISTORY_SUPPORT:
        return _amt_history_support(args, context)
    if export == ASG_SUPPORT:
        return _asg_support(args, context)
    if export in (AMT_HISTORY_READ, AMT_HISTORY_WRITE):
        return _amt_history(export == AMT_HISTORY_WRITE, args, context)
    if export in (ASG_INITIAL, ASG_STATUS, ASG_STATUS_TIMEOUT, ASG_STATUS_004):
        return _asg_learning(export, args, context)
    if export == ASG_LEARNED_FLAG:
        return _asg_learned_flag(args, context)
    if export == EFI_PM_WAIT_STOP:
        return _pm_wait_stop(args, context)
    if export == EFI_PM_START:
        return _pm_start(args, context)
    if export in (EFI_PM_RESULT, EFI_PM_STOP):
        return _pm_result(export, args, context)
    if export in (EFI_PM_SUPPORT, EFI_PM_READ):
        return _pm_read(export, args, context)
    if export in (ECD_ASH_CLEAR, ECD_RESET55):
        return _ecd_reset(export, args, context)
    if export in (EFI_FREQUENCY_READ, EFI_FREQUENCY_WRITE):
        return _frequency(export == EFI_FREQUENCY_WRITE, args, context)
    if export in (PSA_WHEEL_MAIN, PSA_WHEEL_ADDITIONAL):
        return _wheel_write(export, args, context)
    if export == PSA_TRANSMITTER:
        return _transmitter(args, context)
    if export in (PSA_OIL_READ, PSA_OIL_WRITE):
        return _oil(export == PSA_OIL_WRITE, args, context)
    if export in (PSA_WHEEL_READ, PSA_WHEEL_READ2, PSA_VALVE_CHECK):
        return _dsg(export, args, context)
    if export == PSA_WHEEL_CLEAR:
        return _wheel_clear(args, context)
    if export == ECO_STARTS_RESET:
        return _engine_starts_reset(args, context)
    if export == PSA_WATER:
        return _water(args, context)
    if export == PSA_ECT_INIT:
        return _ect_initialize(args, context)
    return _reset(export, args, context)
