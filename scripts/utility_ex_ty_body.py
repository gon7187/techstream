"""Reviewed TY body algorithms over concrete communication primitives.

The common utility engine owns wrapper/thread scheduling. Exact source identities
are mandatory; names alone never enable an operation on another module build.
"""

from __future__ import annotations

import hashlib
from contextlib import suppress

from scripts.toyota_session import Cancelled
from scripts.utility_ex_ty import (
    SHA_12_TY,
    SHA_18_TY,
    SHA_PLUS_TY,
    TYComm,
    TYContext,
    TYSourceError,
    elapsed_ticks,
)

FCM_INFO = "Ex2FCM_13_SendMessage"
FCM_RADAR_START = "Ex2FCM_04_StartFrontRaderSensorMemory"
FCM_RADAR_CHECK = "Ex2FCM_04_RequestRoutineResult"
FCM_NAVI_START = "Ex2FCM_07_StartNaviInitialization"
FCM_NAVI_CHECK = "Ex2FCM_07_CheckNaviInitialization"
FCM_PCS_START = "Ex2FCM_12_StartPCSForcedBrakeActivation"
FCM_PCS_CHECK = "Ex2FCM_12_CheckPCSForcedBrakeActivation"
FCM_PCS_STOP = "Ex2FCM_12_StopPCSForcedBrakeActivation"
MM_HISTORY = "Ex2MM_09_GetSoftErrHistory"
MM_DISC = "Ex2MM_10_GetDiscErrInfo"
MM_SUPPORT = ("Ex2MM_09_GetPIDSupportInfo", "Ex2MM_10_SupportCheck")
MM_IMAGE = ("Ex2MM_08_SupportCheck", "Ex2MM_08_ImageLineCheckRequestAndOperate")
MM_INFORMATION = ("Ex2MM_11_13_SupportCheck", "Ex2MM_11_13_GetInformation")
MM_VALET = ("Ex2MM_20_SupportCheck", "Ex2MM_20_ValetModeCancel")
MM_DIAGNOSTIC = "Ex2MM_21_TransferToDiagnosticMode"
MM_MEDIA = "Ex2MM_31_SendMessage"
MM_RETAINED = "Ex2MM_39_SendMessage"
MM_RESET = "Ex2MM_40_SendMessage"
MM_CHECK = "Ex2MM_30_SendMessage"
MM_DATA_LIST = "Ex2MM_17_GetSupportInfoAndDataList"
MM_PAIRING = "Ex2MM_41_TransferToPairingMode"
APP_IR = tuple(
    f"Ex2APP_03_StartIRProjectorInspection{suffix}"
    for suffix in ("1st", "2nd", "3rd", "4th")
)
CSN_RESET = "Ex2CSN_10_SendMessage"
CSN_TIRE = ("Ex2CSN_05_GetTireCircumference", "Ex2CSN_05_ChangeTireCircumference")
AC_CLASSIC = (
    "Ex2AC_08_RefrigerantFillingModeRequest",
    "Ex2AC_09_RefrigerantHighPressureHistoryClear",
)
AC_SERVO = "Ex2AC_21_ServomotorForcibleDrive"
AC_RESET = ("Ex2AC_26_SendMessage", "Ex2AC_27_SendMessage")
AC_RETAINED = "Ex2AC_28_SendMessage"
AC_BATTERY_CLEAR = "Ex2AC_25_BattVoltLowCntClear"
DCM_NRC = ("Ex2DCM_37_SendMessage", "Ex2DCM_44_SendMessage")
DCM_SETTING = ("Ex2DCM_30_SendMessage", "Ex2DCM_40_SendMessage")
DCM_ENABLE = ("Ex2DCM_32_SendMessage", "Ex2DCM_41_SendMessage")
DCM_ROUTINE = "Ex2DCM_39_SendMessage"
DCM_CLEAR = ("Ex2DCM_38_SendMessage", "Ex2DCM_45_SendMessage")
DCM_ID = "Ex2DCM_21_GetTheDCMID"
DCM_SOFTWARE = "Ex2DCM_19_ReadoutSoftwareVersion"
DCM_INFORMATION = ("Ex2DCM_36_SendMessage", "Ex2DCM_43_SendMessage")
DCM_PAUSING = ("Ex2DCM_22_SupportCheck", "Ex2DCM_22_CancelComPausing")
DCM_AUTHENTICATION = "Ex2DCM_15_SendMessage"
DCM_BUB = ("Ex2DCM_12_SupportCheck", "Ex2DCM_12_ResetBUBMemory")
DCM_ACTIVATION = tuple(
    "Ex2DCM_20_" + name
    for name in ("SupportCheck", "ChangeSettings", "GetTheActivationStatus")
)
DCM_FOTA = tuple(
    "Ex2DCM_19_" + name for name in ("SupportCheck", "StartFOTA", "ReadoutFOTAStatus")
)
DCM_REMOTE = tuple(
    "Ex2DCM_07_08_09_10_16_" + name
    for name in ("SupportCheck", "ReadRemoteSettingData", "SetRemoteSettingData")
)
BDY_SEARCH = tuple(
    "Ex2BDY_23_" + name
    for name in (
        "SearchOfKey",
        "SearchResult",
        "SendKeyInfomation",
        "TerminateSearch",
        "EndExtendedSession",
    )
)
BDY_KEY = tuple(
    f"Ex2BDY_{family}_{name}"
    for family, names in (
        (
            "21",
            (
                "KeyNumGet",
                "StartKeyRegistration",
                "KeyRegistration",
                "StopKeyRegistration",
                "TimeoverKeyRegistration",
                "EndKeyRegistration",
            ),
        ),
        (
            "22",
            (
                "KeyNumGet",
                "StartKeyCodeErasure",
                "KeyCodeErasure",
                "StopKeyCodeErasure",
                "TimeoverKeyCodeErasure",
                "EndKeyCodeErasure",
            ),
        ),
    )
    for name in names
)
BDY53 = tuple(
    "Ex2BDY_53_" + name for name in ("SupportCheck", "StartRegECUID", "CheckRegECUID")
)
BDY52 = tuple(
    "Ex2BDY_52_" + name
    for name in (
        "SupportCheck",
        "GetRegedNumOfKeys",
        "StartEraseKeys",
        "CheckEraseKeys",
    )
)
BDY51_SUPPORT = "Ex2BDY_51_SupportCheck"
BDY51 = tuple(
    "Ex2BDY_51_" + name
    for name in (
        "StatusCheckInterval",
        "NewKeyRegistration",
        "ChkNumberOfTotalKeyRegistered",
        "ChkNumberOfKeyRegistered",
        "OtherKeyRegistration",
        "StatusChkAfterKeyRegist",
        "StatusChkAfterOwnerConfirmation",
        "StatusChkRegisteredKey",
        "RequestKeyRegistration",
        "RequestKeyRegistEnd",
        "OwnerConfirmation",
        "ExitCommunication",
        "NewKeyRegistration_Before_Remove_Key",
        "OtherKeyRegistration_Before_Remove_Key",
        "OwnerConfirmation_Before_Remove_Key",
    )
)
SMRT33_START = "Ex2SMRT_33_ECU_ID_Registration"
SMRT33_POLL = "Ex2SMRT_33_GetKeyStatus"
SMRT35_GET = "Ex2SMRT_35_GetSupportBitInformation"
SMRT35_REGET = "Ex2SMRT_35_ReGetSupportBitInformation"
SMRT35_CHECK = "Ex2SMRT_35_CommunicationCheck"
SMRT35_STOP = "Ex2SMRT_35_TerminateCommunicationCheck"
SMRT_EXPORTS = (
    SMRT33_START,
    SMRT33_POLL,
    SMRT35_GET,
    SMRT35_REGET,
    SMRT35_CHECK,
    SMRT35_STOP,
)
MS2SMRT_STATUS = "Ex2MS2SMRT_05_SendMessage"
MS2SMRT_ENABLE = "Ex2MS2SMRT_07_SendMessage"
MS2SMRT_READ = "Ex2MS2SMRT_08_SendMessage"
MS2SMRT_ERASE = "Ex2MS2SMRT_09_SendMessage"
SMRT62 = tuple(
    "Ex2SMRT_62_" + name
    for name in ("DigiKeySupArea", "StartDiagMode", "TerminateDiagMode")
)
PLG_CLASSIC = (
    "Ex2PLG_01_ReadChargeLidSW_QuickChargeRelayDiag",
    "Ex2PLG_01_QuickChargeRelayDiagnosis",
    "Ex2PLG_01_ReadChargeRelayDiagnosisStatus",
)
PLG3 = "Ex2PLG_03_SendMessage"
PLG_SUPPORT = "Ex2PLG_01_SupportCheck_Uds"
PLG_START = "Ex2PLG_01_StartDiagnosis_Uds"
PLG_POLL = "Ex2PLG_01_RequestRoutineResult_Uds"
PLG_RESULT = "Ex2PLG_01_RequestDiagnosisResult_Uds"
PLG_FINAL = "Ex2PLG_01_FinalCom"
EXPORTS_18 = (
    MM_DATA_LIST,
    MM_CHECK,
    MM_RESET,
    MM_MEDIA,
    MM_RETAINED,
    *MM_VALET,
    MM_DIAGNOSTIC,
    *MM_INFORMATION,
    *MM_IMAGE,
    *MM_SUPPORT,
    *DCM_REMOTE,
    *DCM_FOTA,
    *DCM_ACTIVATION,
    *DCM_BUB,
    DCM_AUTHENTICATION,
    *DCM_PAUSING,
    *DCM_INFORMATION,
    *BDY53,
    *BDY52,
    BDY51_SUPPORT,
    *BDY_SEARCH,
    *BDY_KEY,
    AC_RETAINED,
    MS2SMRT_STATUS,
    MS2SMRT_ENABLE,
    MS2SMRT_READ,
    MS2SMRT_ERASE,
    *SMRT62,
    CSN_RESET,
    *CSN_TIRE,
    *AC_CLASSIC,
    *DCM_NRC,
    *DCM_SETTING,
    *DCM_ENABLE,
    DCM_ROUTINE,
    FCM_INFO,
    *PLG_CLASSIC,
    MM_HISTORY,
    MM_DISC,
    *BDY51,
    *SMRT_EXPORTS,
    PLG3,
    AC_SERVO,
    *AC_RESET,
    AC_BATTERY_CLEAR,
    *DCM_CLEAR,
    DCM_ID,
    DCM_SOFTWARE,
    FCM_RADAR_START,
    FCM_RADAR_CHECK,
    FCM_NAVI_START,
    FCM_NAVI_CHECK,
    FCM_PCS_START,
    FCM_PCS_CHECK,
    FCM_PCS_STOP,
    MM_PAIRING,
    *APP_IR,
    PLG_SUPPORT,
    PLG_START,
    PLG_POLL,
    PLG_RESULT,
    PLG_FINAL,
)


def supported_exports(module_sha256: str) -> tuple[str, ...]:
    """Only reviewed exact builds are callable; all other branches remain open."""
    if module_sha256 == SHA_18_TY:
        return EXPORTS_18
    if module_sha256 == SHA_12_TY:
        return (*SMRT_EXPORTS, *MM_SUPPORT, MM_HISTORY, MM_DISC)
    return (
        (
            *DCM_INFORMATION,
            *DCM_SETTING,
            *DCM_NRC,
            DCM_ENABLE[1],
            DCM_ROUTINE,
            DCM_CLEAR[1],
            *BDY_KEY,
            AC_RETAINED,
            MS2SMRT_STATUS,
            MS2SMRT_ENABLE,
            MS2SMRT_READ,
            MS2SMRT_ERASE,
            *SMRT62,
            *APP_IR,
            MM_PAIRING,
            *AC_RESET,
            *MM_SUPPORT,
            MM_HISTORY,
            MM_DISC,
        )
        if module_sha256 == SHA_PLUS_TY
        else ()
    )


def _delay(context: TYContext, milliseconds: int) -> None:
    # Native Sleep(0) yields; the cancellable host wait returns without yielding.
    native_sleep = getattr(context, "native_sleep", None)
    (native_sleep if callable(native_sleep) else context.sleep)(milliseconds)


def _manager(context: TYContext) -> TYComm:
    return context.comm(
        "native:101392d0" if context.module_sha256 == SHA_PLUS_TY else "native:1011d4f0"
    )


def _routine(comm: TYComm, action: int, identifier: bytes) -> tuple[int, bytes]:
    # 18 TY b28b0/b2940/be620/be6c0/be770: service byte is checked by comm.
    request = bytes((0x31, action)) + identifier
    status, reply = comm.exchange(request)
    minimum = 5 if action == 3 else 4
    if status == 0 and (len(reply) < minimum or reply[1:4] != request[1:4]):
        return 3, reply
    return status, reply


def _normal(comm: TYComm) -> None:
    # 18 TY 8d860 discards restore status.
    comm.session(1, 1)


def _open(comm: TYComm) -> int:
    status = comm.initialize(0)
    if not status:
        for field, value in (
            ("native_1080", 0),
            ("native_1084", 180000),
            ("native_1064", 0),
        ):
            comm.configure(field, value)
    return status


def _initialize(comm: TYComm, session_error: int | None = None) -> int:
    status = _open(comm)
    if status == 0:
        # 18 TY 851f0: normal, then extended only if normal succeeds.
        status = comm.session(1, 1)
        if status == 0:
            status = comm.session(3, 1)
        if status and session_error is not None:
            return session_error
    return status


def _pairing(comm: TYComm, context: TYContext) -> int:
    # 18 TY c1980/c1a00/c1a30: init/session failures are mapped to 1000.
    try:
        if _initialize(comm):
            return 1000
        _delay(context, 200)
        status, _ = _routine(comm, 1, b"\x11\x10\x00")
        _normal(comm)
        return status
    finally:
        comm.finalize()


def _ir_projector(comm: TYComm, step: int) -> int:
    # 18 TY 98ea0..990cf: all four phases have distinct status precedence.
    try:
        status = _initialize(comm)
        if status:
            return 1001 if step == 2 else status
        value = {1: 0, 2: 2, 3: 1, 4: 0}[step]
        status, _ = _routine(comm, 1, b"\x17\x02" + bytes((value,)))
        restore = comm.session(1, 1)
        if step == 1:
            return 1005 if status or restore else 0
        if step == 2:
            return 1001 if status else 1000
        return status or restore
    finally:
        comm.finalize()


def _start(comm: TYComm, pcs: bool) -> int:
    # 18 TY b27c0/be4e0 leave the initialized extended session open on success.
    status = _initialize(comm)
    if status:
        comm.finalize()
        return status
    status, _ = _routine(comm, 1, b"\x16\x0c" if pcs else b"\x12\x09")
    if status:
        if pcs:
            _routine(comm, 2, b"\x16\x0c")
        _normal(comm)
        comm.finalize()
        return 1004 if pcs else status
    return 0


def _poll(
    comm: TYComm,
    cancel: bytearray,
    pcs: bool,
    context: TYContext,
    identifier: bytes | None = None,
) -> int:
    """Native b2840/be560 polling, with an explicit host deadline ceiling."""
    identifier = identifier or (b"\x16\x0c" if pcs else b"\x12\x09")
    start = context.ticks()
    # shortcut: native loop has no deadline; host caps it at 180 s/900 polls.
    try:
        for _ in range(900):
            if int.from_bytes(cancel[:4], "little") or context.is_cancelled():
                # PCS cancellation retains the session for explicit Stop; Navi restores.
                if not pcs:
                    _normal(comm)
                    comm.finalize()
                return 1001
            if ((context.ticks() - start) & 0xFFFFFFFF) >= 180000:
                raise TimeoutError("FCM routine exceeded host 180 second deadline")
            _delay(context, 200)
            status, reply = _routine(comm, 3, identifier)
            if not pcs:
                if status or reply[4] >= 2:
                    result = status or (1000 if reply[4] == 2 else 1002)
                    _normal(comm)
                    comm.finalize()
                    return result
            elif status or reply[4] != 1:
                result = 1000 if status == 0 and reply[4] == 2 else 1002
                if result == 1002:
                    _routine(comm, 2, b"\x16\x0c")
                _normal(comm)
                comm.finalize()
                return result
        raise TimeoutError("FCM routine exceeded host 900 poll ceiling")
    except BaseException:
        try:
            if pcs:
                _routine(comm, 2, b"\x16\x0c")
            _normal(comm)
        finally:
            comm.finalize()
        raise


def _radar_start(comm: TYComm) -> int:
    # 18 TY b6ba0..b6ea7: both availability bits precede the 110e routine.
    status = _initialize(comm)
    if status:
        comm.finalize()
        return status
    for identifier, mask, missing in (
        (b"\x10\xa0", 0x80, 1003),
        (b"\x10\x17", 0x40, 1004),
    ):
        status, reply = comm.exchange(b"\x22" + identifier)
        if not status:
            if len(reply) < 5 or reply[1:3] != identifier:
                status = 3
            elif not reply[4] & mask:
                status = missing
        if status:
            break
    if not status:
        status, _ = _routine(comm, 1, b"\x11\x0e")
    if status:
        _normal(comm)
        comm.finalize()
    return status


def _plg_support(comm: TYComm, data: bytearray) -> int:
    # 18 TY 7e020/7e590/7e640: PID availability and mutually exclusive support bits.
    try:
        status = _initialize(comm, 10000)
        if status:
            return status
        status, reply = comm.exchange(b"\x22\x01\x01")
        if not status and (len(reply) != 35 or reply[1:3] != b"\x01\x01"):
            status = 3
        if not status and reply[5] & 1:
            data[16:24] = b"\0" * 8
            status, reply = comm.exchange(b"\x22\x17\x00")
            if not status and (len(reply) != 35 or reply[1:3] != b"\x17\x00"):
                status = 3
            if not status:
                first, second = int(bool(reply[4] & 16)), int(bool(reply[7] & 2))
                data[16:20] = first.to_bytes(4, "little")
                data[20:24] = second.to_bytes(4, "little")
                if first != second:
                    return comm.session(1, 1)
                status = 1009
        elif not status:
            status = 1009
        _normal(comm)
        return status
    finally:
        comm.finalize()


def _plg_start(comm: TYComm) -> int:
    # 18 TY 7e100: successful start retains the session; 7f3122 maps to 10001.
    status = _initialize(comm, 10000)
    if status:
        return status
    status, reply = _routine(comm, 1, b"\x11\x0f")
    if status:
        if reply == b"\x7f\x31\x22":
            status = 10001
        else:
            comm.exchange(b"\x31\x02\x11\x0f")
        _normal(comm)
        comm.finalize()
    return status


def _plg_poll(comm: TYComm, context: TYContext) -> int:
    # 18 TY 7e1a0/7e3d0: 100 ms sampling; complete value 2; native 22000 ms bound.
    start = context.ticks()
    status = 3
    try:
        for _ in range(221):
            if context.is_cancelled():
                raise Cancelled("PLG result polling cancelled")
            _delay(context, 100)
            status, reply = _routine(comm, 3, b"\x11\x0f")
            if status or reply[4] == 2:
                break
            if elapsed_ticks(context.ticks(), start) >= 22000:
                status = 3
                break
        return status
    finally:
        try:
            comm.exchange(b"\x31\x02\x11\x0f")
            _normal(comm)
            if not status:
                _delay(context, 2000)
        finally:
            comm.finalize()


def _plg_result(comm: TYComm, data: bytearray) -> int:
    # 18 TY 7e200/7e4b0: DID depends on support DWORD at +10; result byte +3/+4.
    try:
        status = comm.initialize(0)
        if status:
            return status
        comm.configure("native_1080", 0)
        comm.configure("native_1084", 180000)
        first = bool(int.from_bytes(data[16:20], "little"))
        status, reply = comm.exchange(b"\x22\x17" + (b"\x0c" if first else b"\x27"))
        if not status:
            if len(reply) < 4 + first or reply[1:3] != (
                b"\x17\x0c" if first else b"\x17\x27"
            ):
                return 3
            value = reply[3 + first]
            return 10002 if value == 1 else 10003 if value in (5, 6) else 10004
        return status
    finally:
        comm.finalize()


def _plg3_stop(comm: TYComm, identifier: bytes) -> None:
    # 18 TY c1d10: both routine results and session restore result are discarded.
    _routine(comm, 2, identifier)
    _routine(comm, 2, b"\x11\x7e")
    comm.session(1, 1, stop_on_error=True)


def _plg3(comm: TYComm, data: bytearray, context: TYContext) -> int:
    # 18 TY c1ad0..c1e7a; native helper C loses the seven stack arguments.
    action = int.from_bytes(data[:4], "little")
    identifier = b"\x11" + (
        b"\x2b" if int.from_bytes(data[8:12], "little") == 1 else b"\x2a"
    )
    close = True
    try:
        if action in (0, 1):
            status = _open(comm)
            if status:
                return status
        if action == 0:
            status = comm.session(3, 1, normal_first=True)
            if status:
                return status
            status, reply = _routine(comm, 1, b"\x11\x00")
            if not status:
                if len(reply) < 36:
                    status = 3
                else:
                    if reply[5] & 0x40:
                        data[24:28] = (1).to_bytes(4, "little")
                    if reply[5] & 0x20:
                        data[16:20] = (1).to_bytes(4, "little")
            restore = comm.session(1, 1, stop_on_error=True)
            return status or restore
        if action == 1:
            status = comm.session(3, 1, normal_first=True)
            if status:
                return status
            status, _ = _routine(comm, 1, b"\x11\x7e")
            if not status:
                _delay(context, 1500)
                selected = data[36 + data[12] * 8]
                status, _ = _routine(comm, 1, identifier + bytes((selected,)))
            if status:
                _plg3_stop(comm, identifier)
                return 2000
            close = False
            return 0
        if action == 2:
            start = context.ticks()
            status = 0
            for _ in range(900):
                if int.from_bytes(data[4:8], "little"):
                    break
                if context.is_cancelled():
                    raise Cancelled("PLG3 polling cancelled")
                if elapsed_ticks(context.ticks(), start) >= 180000:
                    raise TimeoutError("PLG3 exceeded host 180 second deadline")
                _delay(context, 200)
                status, reply = _routine(comm, 3, identifier)
                if status or reply[4] == 1:
                    break
                if reply[4] != 0:
                    status = 3
                    break
            else:
                raise TimeoutError("PLG3 exceeded host 900 poll ceiling")
            if status == 0 and not int.from_bytes(data[4:8], "little"):
                close = False
                return 0
            _plg3_stop(comm, identifier)
            return status
        _plg3_stop(comm, identifier)
        return 0
    except BaseException:
        _plg3_stop(comm, identifier)
        raise
    finally:
        if close:
            comm.finalize()


def _dcm_read(comm: TYComm, data: bytearray, software: bool) -> int:
    # 18 TY 6d6d0/6d7b0 and 67690/67bc0: selected classic controller.
    if not software:
        data[:4132] = bytes(4132)
    try:
        status = comm.initialize(0)
        if status:
            return status
        comm.configure("native_global:100f8194", 150)
        if software:
            offset = int.from_bytes(data[:4], "little")
            size = int.from_bytes(data[8:12], "little")
            data[22:43] = bytes(21)
            status, reply = comm.exchange(b"\x21\x26")
            if not status and (len(reply) != size + 2 or reply[1:2] != b"\x26"):
                status = 3
            # Native copies from the zero-initialized reply buffer even after failure.
            source = reply[:4128].ljust(4128, b"\0")
            data[22 : 22 + size] = source[offset : offset + size]
            return status
        status, reply = comm.exchange(b"\x1a\x85")
        if not status:
            if not 4 <= len(reply) <= 4128:
                return 3
            data[:4] = (len(reply) - 2).to_bytes(4, "little")
            data[4 : len(reply) + 2] = reply[2:]
        return status
    finally:
        comm.finalize()


def _ac_battery_clear(comm: TYComm, context: TYContext) -> int:
    # 18 TY 8c140..8c323/8bc60: 50 ms session gaps; exact 30 s result deadline.
    try:
        status = _open(comm)
        if status:
            return status
        status = comm.session(1, 1)
        if status:
            return status
        _delay(context, 50)
        status = comm.session(3, 1)
        if status:
            return status
        _delay(context, 50)
        status, _ = _routine(comm, 1, b"\x11\x05")
        if not status:
            start = context.ticks()
            _delay(context, 500)
            for _ in range(601):
                if context.is_cancelled():
                    raise Cancelled("AC battery clear cancelled")
                _delay(context, 50)
                status, reply = _routine(comm, 3, b"\x11\x05")
                if status or reply[4] == 2:
                    break
                if reply[4] != 1 or elapsed_ticks(context.ticks(), start) >= 30000:
                    status = 1005
                    break
            else:
                raise TimeoutError("AC battery clear exceeded host poll ceiling")
        _delay(context, 50)
        restore = comm.session(1, 1)
        return status or restore
    finally:
        comm.finalize()


def _ac_command(comm: TYComm, context: TYContext, routine: int, action: int = 0) -> int:
    # 18 TY 8bb20/8bc60/97390..97543: 50 ms gaps and distinct result precedence.
    try:
        status = _open(comm)
        if status or action:
            return status
        status = comm.session(1, 1)
        if status:
            return status
        _delay(context, 50)
        status = comm.session(3, 1)
        if status:
            return status
        _delay(context, 50)
        status, _ = _routine(comm, 1, bytes((0x11, routine)))
        _delay(context, 50)
        restore = comm.session(1, 1)
        if status:
            return 1005 if routine == 1 else 2205
        return restore if routine == 1 else 0
    finally:
        comm.finalize()


def _dcm_clear(comm: TYComm, data: bytearray) -> int:
    # 18 TY c26c0/99440/99480/c2730; exports 38 and 45 share this exact body.
    try:
        status = _open(comm)
        if status:
            return status
        status = comm.session(3, 1, normal_first=True)
        if status:
            return status
        try:
            status, reply = comm.exchange(b"\x2e\x20\x61\x00")
            if not status and (len(reply) != 3 or reply[1:3] != b"\x20\x61"):
                status = 3
            if not status:
                status, reply = comm.exchange(b"\x22\x20\x61")
                if not status:
                    if len(reply) < 4 or reply[1:3] != b"\x20\x61":
                        status = 3
                    else:
                        data[0] = reply[3]
                        if data[0]:
                            status = 2005
            return status
        finally:
            _normal(comm)
    finally:
        comm.finalize()


def _smrt_write(comm: TYComm, register: int, value: int) -> int:
    # 18 TY 22720/23490: exact eight-byte A5 frame, two-byte response and register echo.
    request = (
        (bytes((0xA5, 0xB8, value)) + bytes(5))
        if register == 0xB8
        else (bytes((0xA5, 0xB2, 0, value)) + bytes(4))
    )
    status, reply = comm.exchange(request)
    return 3 if not status and (len(reply) != 2 or reply[1] != register) else status


def _smrt_bits(comm: TYComm, data: bytearray) -> int:
    # 18 TY 23280: ordered sparse support values; unused slots remain FF.
    status, reply = comm.exchange(b"\x21\x07")
    if not status:
        if len(reply) < 4 or reply[1] != 7:
            return 3
        data[:6] = b"\xff" * 6
        values = [
            value
            for byte, mask, value in (
                (2, 0x80, 0x80),
                (2, 0x40, 0x88),
                (3, 8, 0xE0),
                (3, 4, 0xE8),
                (3, 2, 0xF0),
                (3, 16, 0xD8),
            )
            if reply[byte] & mask
        ]
        data[: len(values)] = bytes(values)
    return status


def _smrt(export: str, comm: TYComm, data: bytearray, context: TYContext) -> int:
    if export in (SMRT33_START, SMRT35_GET, SMRT35_CHECK):
        status = comm.initialize(0)
        if status:
            if export == SMRT35_GET:
                comm.finalize()
            return status
        comm.configure(
            "native_rva:b940"
            if context.module_sha256 == SHA_12_TY
            else "native_global:100f8194",
            100,
        )
    if export == SMRT33_START:
        # 18 TY 22670 retains the controller even after request error.
        return _smrt_write(comm, 0xB8, 0x80)
    if export == SMRT33_POLL:
        start = context.ticks()
        try:
            for _ in range(64):
                if context.is_cancelled():
                    raise Cancelled("SMRT registration polling cancelled")
                _delay(context, 500)
                status, reply = comm.exchange(b"\x21\x21")
                if not status:
                    if len(reply) != 8 or reply[1] != 0x21:
                        status = 3
                    elif reply[2] & 0x20:
                        status = 1001
                    elif reply[3] & 4:
                        status = 1003
                if status != 1001:
                    return status
                if elapsed_ticks(context.ticks(), start) >= 31001:
                    return 1002
            raise TimeoutError("SMRT registration exceeded host poll ceiling")
        finally:
            try:
                _smrt_write(comm, 0xB8, 0)
            finally:
                comm.finalize()
    if export == SMRT35_CHECK:
        start = context.ticks()
        try:
            for _ in range(45):
                if int.from_bytes(data[8:12], "little") or int.from_bytes(
                    data[12:16], "little"
                ):
                    return 1001
                if context.is_cancelled():
                    raise Cancelled("SMRT communication polling cancelled")
                if elapsed_ticks(context.ticks(), start) >= 180000:
                    raise TimeoutError("SMRT communication exceeded host deadline")
                status = _smrt_write(comm, 0xB2, data[6])
                if status:
                    return status
                _delay(context, 4000)
            raise TimeoutError("SMRT communication exceeded host poll ceiling")
        except BaseException:
            try:
                _smrt_write(comm, 0xB2, 0)
            finally:
                comm.finalize()
            raise
    try:
        if export in (SMRT35_REGET, SMRT35_STOP):
            _smrt_write(comm, 0xB2, 0)
        if export == SMRT35_STOP:
            return 0
        return _smrt_bits(comm, data)
    finally:
        comm.finalize()


def _dword(data: bytearray, offset: int, value: int | None = None) -> int:
    if value is not None:
        data[offset : offset + 4] = (value & 0xFFFFFFFF).to_bytes(4, "little")
    return int.from_bytes(data[offset : offset + 4], "little")


def _bdy_read(comm: TYComm, data: bytearray) -> int:
    # 18 TY 2c4e0 copies the returned bytes even when transport/length fails.
    status, reply = comm.exchange(b"\x21\x82")
    if len(reply) > len(data) - 12 or len(reply) > 4128:
        raise ValueError("BDY reply exceeds supplied native context capacity")
    if not status and (len(reply) != _dword(data, 4) or reply[1:2] != b"\x82"):
        status = 3
    data[12 : 12 + len(reply)] = reply
    return status


def _bdy_request(comm: TYComm, enabled: bool) -> int:
    # 18 TY 2c5d0/2c6a0 only check response length; no echoed payload check.
    status, reply = comm.exchange(
        b"\x3b\x83" + bytes((0x40 if enabled else 0,)) + bytes(5)
    )
    return 3 if not status and len(reply) != 2 else status


def _bdy_dtc(comm: TYComm) -> int:
    # 18 TY 2c770/ffa0: native count-controlled big-endian 9402/9401/9405 matches.
    status, reply = comm.exchange(b"\x13")
    if status:
        return status
    native = reply[:512].ljust(512, b"\0")
    codes = {
        int.from_bytes(native[2 + i * 2 : 4 + i * 2], "big") for i in range(native[1])
    }
    if 0x9402 in codes:
        return 1021
    return 1022 if codes.intersection((0x9401, 0x9405)) else 1006


def _bdy_clear(comm: TYComm) -> int:
    status, reply = comm.exchange(b"\x14")
    return 3 if not status and len(reply) != 1 else status


def _bdy_before(
    comm: TYComm, data: bytearray, context: TYContext, cancellable: bool
) -> int:
    # 18 TY 2be50/2bf80/2c0c0 use the native 61000 ms timer and special cancel flag.
    start = context.ticks()
    for _ in range(611):
        if elapsed_ticks(context.ticks(), start) >= 61000:
            return 1027
        if cancellable and _dword(data, 36) == 1:
            _dword(data, 36, 0)
            return 1025
        if context.is_cancelled():
            raise Cancelled("BDY key-removal polling cancelled")
        status = _bdy_read(comm, data)
        if status:
            comm.finalize()
            return status
        if data[14] & 0xC0 != 0x40:
            _bdy_request(comm, False)
            comm.finalize()
            return 1006
        if not data[14] & 4:
            return 1026
        _delay(context, 100)
    raise TimeoutError("BDY key removal exceeded host poll ceiling")


def _bdy51(export: str, comm: TYComm, data: bytearray, context: TYContext) -> int:
    # 18 TY 2b150..2c1d4: persistent selected controller and mutable native UI state.
    name = export.removeprefix("Ex2BDY_51_")
    if name == "ExitCommunication":
        comm.finalize()
        return 1024
    if name == "ChkNumberOfKeyRegistered":
        status = comm.initialize(0)
        if status:
            comm.finalize()
            return status
    comm.configure("native_global:100f8194", 150)
    if name.endswith("Before_Remove_Key"):
        return _bdy_before(comm, data, context, not name.startswith("NewKey"))
    if name in ("RequestKeyRegistration", "RequestKeyRegistEnd"):
        status = _bdy_request(comm, name == "RequestKeyRegistration")
        if status:
            comm.finalize()
            return status
        if name == "RequestKeyRegistEnd":
            if not _dword(data, 32):
                comm.finalize()
            _dword(data, 32, 0)
        return 1020
    status = _bdy_read(comm, data)
    if status:
        if name != "StatusCheckInterval":
            comm.finalize()
        return status
    if name == "StatusCheckInterval":
        return 1023
    mode = data[14] & 0xC0 == 0x40
    inserted = bool(data[14] & 4)
    if name in ("NewKeyRegistration", "OtherKeyRegistration"):
        # Native signed multiply/divide computes /15, not the customary high nibble shift.
        count = (data[_dword(data, 0) + 12] & 0xF0) // 15
        if count > _dword(data, 28):
            _dword(data, 28, count)
            if (_dword(data, 20) + count) & 0xFFFFFFFF < 6:
                return 1009
            status = _bdy_request(comm, False)
            if status:
                comm.finalize()
                return status
            return 1010
        if mode:
            return 1007 if inserted else 1008
    elif name == "ChkNumberOfTotalKeyRegistered" and mode:
        if data[15] & 0x20:
            return 1005
        status = _bdy_request(comm, False)
        if status:
            comm.finalize()
            return status
        count = data[16] & 15
        if count:
            _dword(data, 24, count)
            return 1004
        return 1003
    elif name == "ChkNumberOfKeyRegistered":
        count = (data[_dword(data, 0) + 13] & 0xF0) // 15
        _dword(data, 20, count)
        if count >= 6:
            comm.finalize()
            return 1002
        if count:
            return 1001
        status = _bdy_request(comm, True)
        if status:
            comm.finalize()
            return status
        return 1000
    elif name == "StatusChkAfterKeyRegist":
        if mode:
            return 1014
        comm.exchange(b"\x14")  # Native ignores clear-DTC status here.
        count = (data[_dword(data, 0) + 13] & 0xF0) // 15
        expected = (_dword(data, 28) + _dword(data, 20)) & 0xFFFFFFFF
        comm.finalize()
        return (1012 if count > 5 else 1011) if count == expected else 1013
    elif name == "StatusChkAfterOwnerConfirmation" and mode:
        if not inserted:
            return 1008
        if not data[15] & 4:
            return 1017
        _bdy_request(comm, False)
        comm.finalize()
        return 1019
    elif name == "StatusChkRegisteredKey":
        if mode:
            if not inserted:
                return 1008
            if not data[15] & 4:
                return 1018
        status = _bdy_dtc(comm)
        if status == 1021:
            status = _bdy_clear(comm)
            if not status:
                _bdy_request(comm, False)
                status = 1019
        elif status == 1022:
            cleared = _bdy_clear(comm)
            status = cleared or 1022
        elif status == 1006:
            _bdy_request(comm, False)
        comm.finalize()
        return status
    elif name == "OwnerConfirmation" and mode:
        if not inserted:
            return 1008
        count = data[16] & 15
        if not count:
            return 1003
        if count < _dword(data, 24):
            _dword(data, 24, count)
            return 1015
        return 1016
    _bdy_request(comm, False)
    comm.finalize()
    return 1006


def _mm_data_list(comm: TYComm, data: bytearray) -> int:
    # 42790..42a97: require all thirty64 support bytes and copy five six-byte rows.
    try:
        status = comm.initialize(0)
        if status:
            return status
        comm.configure("native_global:100f8194", 150)
        status, raw, offsets = comm.support_snapshot(1)
        if status:
            return status
        status, payload = _classic_entry(raw, offsets, 0x64)
        if status:
            return status
        for minimum in range(3, 33):
            status, _ = _classic_mask(payload, minimum, 0xFF)
            if status:
                return status
        count = sum(bool(value) for value in payload)
        status, reply = comm.exchange(b"\x21\x64")
        if not status:
            if len(reply) != count + 2 or reply[:2] != b"\x61\x64":
                return 3
            data[:30] = reply[2:32]
        return status
    finally:
        comm.finalize()


def _mm_check(comm: TYComm, data: bytearray, context: TYContext) -> int:
    # a3fc0..a4250: retained1106 and exact ten-byte result flags.
    retained = False
    try:
        if not _dword(data, 4):
            status = _open(comm)
            if status:
                return status
            status = comm.session(3, 1, normal_first=True)
            if status:
                return status
            _delay(context, 200)
            status, _ = _routine(comm, 1, b"\x11\x06\x01")
            if status:
                comm.session(1, 1, stop_on_error=True)
            else:
                retained = True
            return status
        started = context.ticks()
        status = 0
        stop = True
        try:
            while _dword(data, 0) != 1:
                if context.is_cancelled():
                    raise Cancelled("MM check polling cancelled")
                _delay(context, 200)
                result, reply = _routine(comm, 3, b"\x11\x06")
                if result or len(reply) < 14 or reply[4] > 2:
                    status = 2000
                    break
                if reply[4] == 2:
                    stop = False
                    status = 2001 if reply[5] else 2002 if any(reply[10:14]) else 0
                    break
                if elapsed_ticks(context.ticks(), started) >= 180000:
                    raise TimeoutError("MM check host polling ceiling")
            if stop:
                _routine(comm, 2, b"\x11\x06")
            comm.session(1, 1, stop_on_error=True)
            return status
        except BaseException:
            with suppress(Exception):
                if context.is_cancelled():
                    comm.cleanup_exchange(b"\x31\x02\x11\x06")
                    comm.cleanup_session(1, 1, stop_on_error=True)
                else:
                    _routine(comm, 2, b"\x11\x06")
                    comm.session(1, 1, stop_on_error=True)
            raise
    finally:
        if not retained:
            comm.finalize()


def _mm_reset(comm: TYComm, data: bytearray, context: TYContext) -> int:
    # a44d0/a4560/a45b0/a4650: retained1115, result1002, failure1007 and cancel.
    retained = False
    try:
        if not _dword(data, 0):
            status = _open(comm)
            if status:
                return status
            status = comm.session(3, 1, normal_first=True)
            if status:
                return status
            _delay(context, 200)
            status, _ = _routine(comm, 1, b"\x11\x15\0")
            if not status:
                retained = True
                return 1005
            comm.session(1, 1, stop_on_error=True)
            return status
        started = context.ticks()
        try:
            while not _dword(data, 4):
                if context.is_cancelled():
                    raise Cancelled("MM reset polling cancelled")
                _delay(context, 200)
                status, reply = _routine(comm, 3, b"\x11\x15")
                if status or reply[4] > 2:
                    status = 1007
                    break
                if reply[4] == 2:
                    status = 1002
                    break
                if elapsed_ticks(context.ticks(), started) >= 180000:
                    raise TimeoutError("MM reset host polling ceiling")
            else:
                status, _ = _routine(comm, 2, b"\x11\x15")
            if status == 1007:
                _routine(comm, 2, b"\x11\x15")
            comm.session(1, 1, stop_on_error=True)
            return status
        except BaseException:
            with suppress(Exception):
                if context.is_cancelled():
                    comm.cleanup_exchange(b"\x31\x02\x11\x15")
                    comm.cleanup_session(1, 1, stop_on_error=True)
                else:
                    _routine(comm, 2, b"\x11\x15")
                    comm.session(1, 1, stop_on_error=True)
            raise
    finally:
        if not retained:
            comm.finalize()


def _mm_media(comm: TYComm, data: bytearray) -> int:
    # a4250/a42c0/9dd00: first ten bytes survive a later three-byte read failure.
    try:
        status = _open(comm)
        if status:
            return status
        status = comm.session(3, 1, normal_first=True)
        if status:
            return status
        try:
            for identifier, size, output in ((0x14, 10, 0), (0x15, 3, 10)):
                status, reply = comm.exchange(bytes((0x22, 0x10, identifier)))
                if status:
                    return status
                if len(reply) < size + 3 or reply[1:3] != bytes((0x10, identifier)):
                    return 3
                data[output : output + size] = reply[3 : 3 + size]
            return 0
        finally:
            comm.session(1, 1, stop_on_error=True)
    finally:
        comm.finalize()


def _mm_retained(comm: TYComm, data: bytearray, context: TYContext) -> int:
    # a4370/a4400/a4440/a8ef0: retain successful routine1108; explicit restore phase.
    retained = False
    try:
        if _dword(data, 0):
            return comm.session(1, 1, stop_on_error=True)
        status = _open(comm)
        if status:
            return status
        status = comm.session(3, 1, normal_first=True)
        if status:
            return status
        _delay(context, 200)
        status, _ = _routine(comm, 1, b"\x11\x08\x00\x01")
        if status:
            comm.session(1, 1, stop_on_error=True)
        else:
            retained = True
        return status
    finally:
        if not retained:
            comm.finalize()


def _mm_valet(comm: TYComm, data: bytearray, export: str) -> int:
    # 63400..63789/65ca0..65e22: source20 publish helper and one-byte21 reply.
    try:
        status = comm.initialize(0)
        if status:
            return status
        comm.configure("native_global:100f8194", 150)
        if export == MM_DIAGNOSTIC:
            status, reply = comm.exchange(b"\x10\x70")
            return 3 if not status and len(reply) != 1 else status
        if export == MM_VALET[0]:
            status, raw, offsets = comm.support_snapshot(2)
            if status:
                return status
            status, payload = _classic_entry(raw, offsets, 0x55)
            if status:
                return status
            status, _ = _classic_mask(payload, 3, 1)
            if not status:
                count = sum(bool(value) for value in payload)
                _dword(data, 0, count)
                return 0 if count else 22
            return status
        request = (b"\x30\x55\0\x01" + bytes(4124))[: _dword(data, 0) + 3]
        status, reply = comm.exchange(request)
        return (
            3 if not status and (len(reply) != 2 or reply[1:2] != b"\x55") else status
        )
    finally:
        comm.finalize()


def _mm_information(comm: TYComm, data: bytearray, support: bool) -> int:
    # 65e30..662ab: exact ten-byte52 and conditional three-byte53 fields.
    try:
        status = comm.initialize(0)
        if status:
            return status
        comm.configure("native_global:100f8194", 150)
        selector = _dword(data, 8)
        if support:
            status, raw, offsets = comm.support_snapshot(1)
            if status:
                return status
            for identifier, size, output in ((0x52, 10, 0), (0x53, 3, 4)):
                if identifier == 0x53 and selector != 1:
                    continue
                status, payload = _classic_entry(raw, offsets, identifier)
                if status:
                    return status
                for minimum in range(3, size + 3):
                    status, _ = _classic_mask(payload, minimum, 0xFF)
                    if status:
                        return status
                _dword(data, output, sum(bool(value) for value in payload))
            return 0
        for identifier, size, count_offset, output in (
            (0x52, 10, 0, 12),
            (0x53, 3, 4, 22),
        ):
            if identifier == 0x53 and not selector:
                continue
            status, reply = comm.exchange(bytes((0x21, identifier)))
            if status:
                return status
            if len(reply) != _dword(data, count_offset) + 2 or reply[1:2] != bytes(
                (identifier,)
            ):
                return 3
            data[output : output + size] = reply[2 : 2 + size]
        return 0
    finally:
        comm.finalize()


def _mm_image_read(
    comm: TYComm, data: bytearray, delay: int, context: TYContext
) -> int:
    # fef0's interruptible delay has no Sleep(0) when duration is zero.
    for _ in range(delay // 100):
        if context.is_cancelled():
            raise Cancelled("MM image delay cancelled")
        _delay(context, 100)
    status, reply = comm.exchange(b"\x21\x54")
    if not status:
        if len(reply) != _dword(data, 8) + 2 or reply[:2] != b"\x61\x54":
            return 3
        native = reply[:4128].ljust(4128, b"\0")
        index = _dword(data, 0)
        data[12:15] = bytes((native[2], native[index], native[index + 1]))
    return status


def _mm_image(comm: TYComm, data: bytearray, support: bool, context: TYContext) -> int:
    # 42100..42789: selected54 support and literal30540001 operation.
    try:
        status = comm.initialize(0)
        if status:
            return status
        comm.configure("native_global:100f8194", 150)
        if support:
            status, raw, offsets = comm.support_snapshot(1)
            if status:
                return status
            status, payload = _classic_entry(raw, offsets, 0x54)
            if status:
                return status
            for minimum, mask in ((3, 3), (6, 7)):
                status, _ = _classic_mask(payload, minimum, mask)
                if status:
                    return status
            if not payload[2]:
                return 3
            data[4] = payload[2]
            status, index = _classic_mask(payload, 5, 0)
            _dword(data, 0, index)
            if status:
                return status
            _dword(data, 8, sum(bool(value) for value in payload))
            status, raw, offsets = comm.support_snapshot(2)
            if status:
                return status
            status, payload = _classic_entry(raw, offsets, 0x54)
            if status:
                return status
            status, _ = _classic_mask(payload, 3, 1)
            if not status:
                _dword(data, 16, sum(bool(value) for value in payload))
            return status
        started = context.ticks()
        status = _mm_image_read(comm, data, 0, context)
        if status:
            return status
        force_first_poll = data[12] & 3 not in (0, 2)
        if not force_first_poll:
            size = _dword(data, 16) + 3
            request = (b"\x30\x54\0\x01" + bytes(4124))[:size]
            status, reply = comm.exchange(request)
            if status:
                return status
            if reply != b"\x70\x54":
                return 3
        while force_first_poll or elapsed_ticks(context.ticks(), started) < 15000:
            force_first_poll = False
            _dword(data, 20, 0)
            status = _mm_image_read(comm, data, 500, context)
            if status or data[12] & 3 == 2:
                return status
        _dword(data, 20, 1)
        return 0
    finally:
        comm.finalize()


def _mm_pending_field(module_sha256: str) -> str:
    if module_sha256 == SHA_12_TY:
        return "native_rva:b940"
    if module_sha256 == SHA_PLUS_TY:
        return "native_rva:142f0"
    return "native_global:100f8194"


def _mm_support(
    comm: TYComm,
    data: bytearray,
    disc: bool,
    pending_field: str = "native_global:100f8194",
) -> int:
    # 248f0/24ad0 and 24db0/24e70: A8 producers for the native history/disc buffers.
    try:
        status = comm.initialize(0)
        if status:
            return status
        if disc:
            _dword(data, 4128, 0)
        comm.configure(pending_field, 150)
        status, raw, offsets = comm.support_snapshot(1)
        if status:
            return status
        flag_status, flag_payload = _classic_entry(raw, offsets, 0x41)
        flag = int(not flag_status and any(flag_payload))
        status, payload = _classic_entry(raw, offsets, 0x61 if disc else 0x63)
        if not disc:
            if status:
                return status
            if len(payload) > 61:
                raise ValueError("MM history support exceeds native 63-byte local bank")
            count = sum(bool(value) for value in payload)
            if not count:
                return 22
            header = bytes((0x63, len(payload))) + payload
            data[:63] = header.ljust(63, b"\0")
            _dword(data, 64, count)
            _dword(data, 132, flag)
            return 0
        pairs, count = 0, 0
        if not status:
            for first in range(3, 59, 8):
                first_status, first_index = _classic_mask(payload, first, 0xFF)
                second_status, second_index = _classic_mask(payload, first + 1, 0xFF)
                if first_status or second_status:
                    continue
                output = 4132 + pairs * 12
                _dword(data, output, first_index)
                _dword(data, output + 4, second_index)
                count += 2
                _dword(data, 4128, count)
                checks = [
                    _classic_mask(payload, minimum, 0xFF)
                    for minimum in range(first + 2, first + 8)
                ]
                if all(not item[0] for item in checks):
                    _dword(data, output + 8, checks[0][1])
                    count += 6
                    _dword(data, 4128, count)
                pairs += 1
        _dword(data, 4216, flag)
        if not pairs:
            return 22
        _dword(data, 4128, count + 2)
        return 0
    finally:
        comm.finalize()


def _mm_history(
    comm: TYComm,
    data: bytearray,
    disc: bool,
    pending_field: str = "native_global:100f8194",
) -> int:
    # 18 TY 249f0/24c60 and 250e0/25190: selected classic response consumers.
    try:
        status = comm.initialize(0)
        if status:
            return status
        comm.configure(pending_field, 150)
        status, reply = comm.exchange(b"\x21\x61" if disc else b"\x21\x63")
        if disc:
            expected = _dword(data, 4128)
            if len(reply) > 4128:
                raise ValueError("MM disc reply exceeds native output buffer")
            data[: len(reply)] = reply
            return 3 if not status and len(reply) != expected else status
        if not status:
            if len(reply) != _dword(data, 64) + 2 or reply[:1] != b"\x61":
                return 3
            output = bytearray(63)
            output[:2] = reply[:2]
            source = 2
            for index in range(2, data[1] + 2):
                if data[index]:
                    output[index] = reply[source]
                    source += 1
            data[68:131] = output
        return status
    finally:
        comm.finalize()


def _plg_classic(export: str, comm: TYComm, data: bytearray) -> int:
    # 18 TY 3c440/3c520/3c5f0/3c840..3cac0: selected metadata lengths/indices.
    try:
        status = comm.initialize(0)
        if status:
            return status
        comm.configure("native_global:100f8194", 150)
        if export == PLG_CLASSIC[0]:
            status, reply = comm.exchange(b"\x21\x25")
            if status or len(reply) != _dword(data, 4) + 2 or reply[1:2] != b"\x25":
                return 1010
            native = reply.ljust(4128, b"\0")
            if native[_dword(data, 0)] & 0x20:
                return 1001
        if export in PLG_CLASSIC[:2]:
            status, reply = comm.exchange(b"\x3b\x24\x01")
            return (
                3
                if not status and (len(reply) != 2 or reply[1:2] != b"\x24")
                else status
            )
        status, reply = comm.exchange(b"\x21\x7f")
        if not status:
            if len(reply) != _dword(data, 12) + 2 or reply[1:2] != b"\x7f":
                return 3
            native = reply.ljust(4128, b"\0")
            return {
                0x80: 1002,
                0x81: 1003,
                0x82: 1004,
                0x83: 1005,
                0x85: 1006,
                0x86: 1007,
                0x87: 1008,
            }.get(native[_dword(data, 8)], 1009)
        return status
    finally:
        comm.finalize()


def _fcm_info(comm: TYComm, data: bytearray) -> int:
    # 18 TY c49a0/c4a10/9dd00: exact 16-byte DID10d2 consumer and session cleanup.
    try:
        status = _open(comm)
        if status:
            return status
        data[:16] = bytes(16)
        status = comm.session(3, 1, normal_first=True)
        if status:
            return status
        try:
            status, reply = comm.exchange(b"\x22\x10\xd2")
            if not status:
                if len(reply) < 19 or reply[1:3] != b"\x10\xd2":
                    return 3
                data[:16] = reply[3:19]
            return status
        finally:
            comm.session(1, 1, stop_on_error=True)
    finally:
        comm.finalize()


def _write_did(comm: TYComm, request: bytes) -> int:
    # 18 TY 909b0/90a70: minimum three response bytes and exact two-byte DID echo.
    status, reply = comm.exchange(request)
    return (
        3 if not status and (len(reply) < 3 or reply[1:3] != request[1:3]) else status
    )


def _dcm_setting(comm: TYComm, data: bytearray) -> int:
    # 18 TY 908e0/90950..90a6f/c1e80: write/readback and restore-error precedence.
    try:
        status = _initialize(comm)
        if status:
            return status
        status = _write_did(comm, b"\x2e\x20\x40" + data[:1])
        if not status:
            status, reply = comm.exchange(b"\x22\x20\x40")
            if not status:
                if len(reply) < 4 or reply[1:3] != b"\x20\x40":
                    status = 3
                else:
                    data[1] = reply[3]
                    if data[1] > 1:
                        status = 3
        restore = comm.session(1, 1)
        return restore or status
    finally:
        comm.finalize()


def _dcm_information_read(comm: TYComm, data: bytearray) -> int:
    # c23b0: clear the complete native 4080-byte output before transport.
    data[4:4085] = bytes(4081)
    status, reply = comm.exchange(b"\x22\xf1\x81")
    if status:
        return status
    if len(reply) < 4 or reply[1:3] != b"\xf1\x81":
        return 3
    count = reply[3]
    data[4] = count
    native = reply[:4128].ljust(4128, b"\0")
    data[5 : 5 + count * 16] = native[4 : 4 + count * 16]
    return 0


def _dcm_information_state(comm: TYComm) -> tuple[int, int]:
    # c24a0(20,01,0,1,&state): length four and exact DID echo.
    status, reply = comm.exchange(b"\x22\x20\x01")
    if not status and (len(reply) < 4 or reply[1:3] != b"\x20\x01"):
        status = 3
    return status, reply[3] if not status else 0


def _dcm_information(comm: TYComm, data: bytearray, context: TYContext) -> int:
    # 90af0/c2000 and ASM-recovered jump tables: source action1 retains comm.
    action = _dword(data, 0)
    if action != 2:
        status = _open(comm)
        if status:
            return status  # Native initialization failure does not finalize.
    retained = False
    try:
        if action not in (0, 1, 2, 3):
            return 0
        if action == 2:
            started = context.ticks()
            try:
                while not _dword(data, 4088):
                    if context.is_cancelled():
                        raise Cancelled("DCM information polling cancelled")
                    status, state = _dcm_information_state(comm)
                    if status:
                        return status
                    if state == 2:
                        return 0
                    if state == 0x11:
                        status = _dcm_information_read(comm, data)
                        return status or 1018
                    if state != 1:
                        return 1014 if state == 0xF0 else 1015
                    if elapsed_ticks(context.ticks(), started) >= 180000:
                        raise TimeoutError("DCM information host polling ceiling")
                return 0
            finally:
                if context.is_cancelled():
                    comm.cleanup_session(1, 1, stop_on_error=True)
                else:
                    comm.session(1, 1, stop_on_error=True)
        status = comm.session(3, 1, normal_first=True)
        if status:
            return 1011 if status == 2 and action != 1 else status
        if action == 1:
            # c2560 copies five bytes but sends length five: only 01/00 go on wire.
            status = _write_did(comm, b"\x2e\x20\x01\x01\x00")
            retained = status == 0
            if status:
                comm.session(1, 1, stop_on_error=True)
            return status
        try:
            status, state = _dcm_information_state(comm)
            if status:
                status = 1011 if status == 2 else status
            elif (
                action == 0 and context.module_sha256 == SHA_PLUS_TY and state != 2
            ) or state == (1 if action == 0 else 0x10):
                status = _dcm_information_read(comm, data)
            elif action == 0:
                status = {2: 1011, 0x11: 1016}.get(state, 1012)
            else:
                status = {1: 1013, 2: 1011, 0x11: 1016, 0xF0: 1014}.get(state, 1015)
        except BaseException:
            with suppress(Exception):
                comm.session(1, 1, stop_on_error=True)
            raise
        restore = comm.session(1, 1, stop_on_error=True)
        return status or restore
    finally:
        if not retained:
            comm.finalize()


def _dcm_enable(comm: TYComm, routine: bool) -> int:
    # 18 TY c1f50/c1fb0 and b1690/b16f0: restore overrides only the DID operation.
    try:
        status = _open(comm)
        if status:
            return status
        status = comm.session(3, 1, normal_first=True)
        if status:
            return status
        status = (
            _routine(comm, 1, b"\x11\x03")[0]
            if routine
            else _write_did(comm, b"\x2e\x20\x04\x01")
        )
        restore = comm.session(1, 1, stop_on_error=True)
        return status if routine else restore or status
    finally:
        comm.finalize()


def _dcm_nrc(comm: TYComm) -> int:
    # 18 TY 93640/936a0/c2620/1ab30: field10b0 is mapped native NRC, not raw byte.
    try:
        status = _open(comm)
        if status:
            return status
        status = comm.session(3, 1, normal_first=True)
        if status:
            return status
        try:
            status = _write_did(comm, b"\x2e\x20\x26\x01")
            if status == 7:
                read_field = getattr(comm, "read_field", None)
                if not callable(read_field):
                    raise TYSourceError("DCM37/44 requires concrete native_10b0 getter")
                mapped = read_field("native_10b0")
                if type(mapped) is not int or not 0 <= mapped <= 0xFFFFFFFF:
                    raise TYSourceError("native_10b0 getter returned invalid DWORD")
                if mapped == 0x69:
                    return 0x69
            return status
        finally:
            comm.session(1, 1, stop_on_error=True)
    finally:
        comm.finalize()


def _ac_classic(comm: TYComm, size: int, history: bool) -> int:
    # 18 TY 63f00/63fe0 and 641b0/64390: selected request size includes zero padding.
    try:
        status = comm.initialize(0)
        if status:
            return status
        comm.configure("native_global:100f8194", 150)
        identifier = 0xDA if history else 0x16
        request = (bytes((0x3B, identifier, 1)) + bytes(max(0, size - 1)))[: size + 2]
        status, reply = comm.exchange(request)
        return (
            3 if not status and (len(reply) != 2 or reply[1] != identifier) else status
        )
    finally:
        comm.finalize()


def _csn_reset(comm: TYComm, action: int) -> int:
    # 18 TY 97250/972c0/972f0: only native action0 issues routine1105.
    try:
        status = _open(comm)
        if status or action:
            return status
        status = comm.session(3, 1, normal_first=True)
        if status:
            return status
        try:
            return _routine(comm, 1, b"\x11\x05")[0]
        finally:
            comm.session(1, 1, stop_on_error=True)
    finally:
        comm.finalize()


def _csn_tire(comm: TYComm, data: bytearray, write: bool) -> int:
    # 18 TY 5dfc0/5e0a0/5e190/5e280: selected sparse mask packs input consecutively.
    try:
        status = comm.initialize(0)
        if status:
            return status
        comm.configure("native_global:100f8194", 150)
        if not write:
            status, reply = comm.exchange(b"\x21\x18")
            if not status:
                if len(reply) != _dword(data, 0) + 2 or reply[1:2] != b"\x18":
                    return 3
                data[4136 : 4136 + len(reply)] = reply
                data[8264] = data[4138] & 0xE0
            return status
        size = _dword(data, 4)
        payload = bytearray(data[8 : 8 + size])
        source = 4138
        for index, mask in enumerate(payload):
            if mask:
                payload[index] = data[source] & mask
                source += 1
        if size:
            payload[0] = (payload[0] & 0x1F) | data[8265]
        status, reply = comm.exchange(b"\x3b\x18" + payload)
        return (
            3 if not status and (len(reply) != 2 or reply[1:2] != b"\x18") else status
        )
    finally:
        comm.finalize()


def _classic_entry(
    raw: bytes, offsets: tuple[int, ...], identifier: int
) -> tuple[int, bytes]:
    # 18 TY12340/123f0 native4128-byte metadata bank; unsafe one-past access rejected.
    if len(offsets) != 256 or len(raw) > 4128:
        raise TYSourceError("Selected classic support bank has invalid native extent")
    offset = offsets[identifier & 255]
    if offset == 4128:
        return 22, b""
    bank = raw.ljust(4128, b"\x00")
    if not 0 <= offset < 4127:
        return 99, b""
    size = bank[offset + 1]
    if offset + 2 + size > 4128:
        return 99, b""
    return 0, bank[offset + 2 : offset + 2 + size]


def _classic_mask(payload: bytes, minimum: int, mask: int) -> tuple[int, int]:
    index = 2 + sum(value != 0 for value in payload[: minimum - 3])
    if len(payload) < minimum - 2:
        return 22, index
    value = payload[minimum - 3]
    return (0 if value and value & mask == mask else 22), index


def _dcm_remote_read(comm: TYComm, data: bytearray, identifier: int) -> int:
    status, reply = comm.exchange(bytes((0x21, identifier)))
    if not status:
        offset, output = (0, 28) if identifier == 0xC2 else (4, 29)
        if len(reply) != _dword(data, offset) + 2 or reply[1:2] != bytes((identifier,)):
            return 3
        data[output] = reply[:4128].ljust(4128, b"\0")[2]
    return status


def _dcm_remote_write(comm: TYComm, identifier: int, value: int, size: int) -> int:
    request = bytes((0x3B, identifier)) + (bytes((value,)) + bytes(4125))[:size]
    status, reply = comm.exchange(request)
    if status:
        return 0 if identifier == 0xC2 and reply == b"\x7f\x3b\x22" else status
    return 3 if len(reply) != 2 or reply[1:2] != bytes((identifier,)) else 0


def _dcm_remote(comm: TYComm, data: bytearray, export: str) -> int:
    # 418c0..420ff: native target/pending order, selected metadata and C2-only NRC.
    try:
        support = export == DCM_REMOTE[0]
        if support:
            comm.select_target(0x750, 0xC7)
        comm.configure("native_global:100f8194", 150)
        if not support:
            comm.select_target(0x750, 0xC7)
        status = comm.initialize(0)
        if status:
            return status
        if support:
            for kind in (1, 3):
                status, raw, offsets = comm.support_snapshot(kind)
                if status:
                    return status
                payloads = []
                for identifier, mask in (
                    (0xC2, 0xFF),
                    (0xC4, 1 if kind == 1 else 0x30),
                ):
                    status, payload = _classic_entry(raw, offsets, identifier)
                    if status:
                        return status
                    status, _ = _classic_mask(payload, 3, mask)
                    if status:
                        return status
                    payloads.append(payload)
                for index, payload in enumerate(payloads):
                    _dword(
                        data,
                        (0 if kind == 1 else 8) + index * 4,
                        sum(bool(v) for v in payload) if kind == 1 else len(payload),
                    )
            return 0
        if export == DCM_REMOTE[1]:
            return _dcm_remote_read(comm, data, 0xC4)
        status = _dcm_remote_write(comm, 0xC2, data[20], _dword(data, 8))
        if not status and not _dword(data, 16):
            value = 0x20 if _dword(data, 24) == 1 else 0x10
            status = _dcm_remote_write(comm, 0xC4, value, _dword(data, 12))
        if not status:
            status = _dcm_remote_read(comm, data, 0xC2)
        if not status and not _dword(data, 16):
            status = _dcm_remote_read(comm, data, 0xC4)
        return status
    finally:
        comm.finalize()


def _dcm_fota(comm: TYComm, data: bytearray, export: str, context: TYContext) -> int:
    # 67300..67bb7: twenty software bytes, two FOTA status bytes and native cancel.
    try:
        status = comm.initialize(0)
        if status:
            return status
        comm.configure("native_global:100f8194", 150)
        if export == DCM_FOTA[0]:
            status, raw, offsets = comm.support_snapshot(1)
            if status:
                return status
            for identifier, size, index_output, count_output in (
                (0x26, 20, 0, 8),
                (0x33, 2, 4, 12),
            ):
                status, payload = _classic_entry(raw, offsets, identifier)
                if status:
                    return status
                for index in range(size):
                    status, selected = _classic_mask(payload, index + 3, 0xFF)
                    if status:
                        return status
                _dword(data, index_output, selected - (size - 1))
                _dword(data, count_output, sum(bool(value) for value in payload))
            status, raw, offsets = comm.support_snapshot(3)
            if status:
                return status
            status, payload = _classic_entry(raw, offsets, 0x33)
            if status:
                return status
            for minimum in (3, 4):
                status, _ = _classic_mask(payload, minimum, 0xFF)
                if status:
                    return status
            _dword(data, 16, len(payload))
            return 0
        if export == DCM_FOTA[1]:
            size = _dword(data, 16)
            status, reply = comm.exchange(b"\x3b\x33" + (b"\x01" + bytes(4125))[:size])
            return (
                3
                if not status and (len(reply) != 2 or reply[1:2] != b"\x33")
                else status
            )
        started = context.ticks()
        while True:
            if context.is_cancelled():
                raise Cancelled("DCM FOTA status polling cancelled")
            status, reply = comm.exchange(b"\x21\x33")
            if status:
                return status
            if len(reply) != _dword(data, 12) + 2 or reply[1:2] != b"\x33":
                return 3
            native = reply[:4128].ljust(4128, b"\0")
            index = _dword(data, 4)
            data[20:22] = native[index : index + 2]
            if data[20] != 1 or _dword(data, 44):
                return 0
            _delay(context, 1000)
            if elapsed_ticks(context.ticks(), started) >= 180000:
                raise TimeoutError("DCM FOTA host polling ceiling")
    finally:
        comm.finalize()


def _dcm_activation(
    comm: TYComm, data: bytearray, export: str, context: TYContext
) -> int:
    # 6cf50..6d69f: optional read support, mandatory command support and bit polling.
    try:
        status = comm.initialize(0)
        if status:
            return status
        comm.configure("native_global:100f8194", 150)
        if export == DCM_ACTIVATION[0]:
            _dword(data, 8, 0)
            status, raw, offsets = comm.support_snapshot(1)
            if not status:
                status, payload = _classic_entry(raw, offsets, 0x99)
                if not status:
                    status, _ = _classic_mask(payload, 3, 0xF0)
                    if not status:
                        _dword(data, 8, sum(bool(v) for v in payload))
            # Native discards every result from the optional 99 producer.
            status, raw, offsets = comm.support_snapshot(3)
            if status:
                return status
            for identifier, output in ((0x9A, 0), (0x9B, 4)):
                status, payload = _classic_entry(raw, offsets, identifier)
                if status:
                    return status
                status, _ = _classic_mask(payload, 3, 0xFF)
                if status:
                    return status
                _dword(data, output, len(payload))
            return 0
        selector = data[12]
        if export == DCM_ACTIVATION[1]:
            identifier, value, size = {
                1: (0x9A, 0x30, _dword(data, 0)),
                2: (0x9B, 1, _dword(data, 4)),
                3: (0x9A, 0x31, _dword(data, 0)),
            }.get(selector, (0, 0, 0))
            request = bytes((0x3B, identifier)) + (bytes((value,)) + bytes(4125))[:size]
            status, reply = comm.exchange(request)
            if not status and (len(reply) < 2 or reply[1] != identifier):
                status = 3
            return status or 2009
        started = context.ticks()
        while True:
            if context.is_cancelled():
                raise Cancelled("DCM activation polling cancelled")
            _delay(context, 500)
            status, reply = comm.exchange(b"\x21\x99")
            if status:
                return status
            if len(reply) != _dword(data, 8) + 2 or reply[1:2] != b"\x99":
                return 3
            if _dword(data, 16) == 1:
                return 0
            value = reply[:4128].ljust(4128, b"\0")[2]
            if (
                (selector == 1 and value & 0xC0 == 0x40)
                or (selector == 2 and value & 0x30 == 0x10)
                or (selector == 3 and value & 0xC0 != 0x40)
            ):
                return 0
            if elapsed_ticks(context.ticks(), started) >= 180000:
                raise TimeoutError("DCM activation host polling ceiling")
    finally:
        comm.finalize()


def _dcm_bub(comm: TYComm, data: bytearray, support: bool) -> int:
    # 552a0..55654: target750/C7 capability and exact selected34 write length.
    try:
        if support:
            comm.select_target(0x750, 0xC7)
        status = comm.initialize(0)
        if status:
            return status
        comm.configure("native_global:100f8194", 150)
        if support:
            status, raw, offsets = comm.support_snapshot(3)
            if status:
                return status
            status, payload = _classic_entry(raw, offsets, 0x34)
            if status:
                return status
            status, _ = _classic_mask(payload, 3, 0xFF)
            if not status:
                _dword(data, 0, len(payload))
            return status
        size = _dword(data, 0)
        status, reply = comm.exchange(b"\x3b\x34" + (b"\x01" + bytes(4125))[:size])
        return (
            3 if not status and (len(reply) != 2 or reply[1:2] != b"\x34") else status
        )
    finally:
        comm.finalize()


def _dcm_authentication(comm: TYComm, data: bytearray) -> int:
    # 55660..55c9f: selected classic metadata, status 9100 and exact NRC 9101.
    try:
        status = comm.initialize(0)
        if status:
            return status
        comm.configure("native_global:100f8194", 150)
        action = _dword(data, 8)
        if action == 0:
            for kind, identifier, mask, output in ((1, 0x35, 0xFF, 0), (3, 0x38, 1, 4)):
                status, raw, offsets = comm.support_snapshot(kind)
                if status:
                    return status
                status, payload = _classic_entry(raw, offsets, identifier)
                if status:
                    return status
                status, _ = _classic_mask(payload, 3, mask)
                if status:
                    return status
                _dword(
                    data,
                    output,
                    sum(bool(v) for v in payload) if kind == 1 else len(payload),
                )
            status, reply = comm.exchange(b"\x21\x35")
            if not status:
                if len(reply) != _dword(data, 0) + 2 or reply[1:2] != b"\x35":
                    return 3
                if reply[2] == 1:
                    return 9100
            return status
        if action == 1:
            size = _dword(data, 4)
            status, reply = comm.exchange(b"\x3b\x38" + (b"\x01" + bytes(4125))[:size])
            if status:
                return 9101 if reply == b"\x7f\x3b\x22" else status
            return 3 if len(reply) != 2 or reply[1:2] != b"\x38" else 0
        return 0
    finally:
        comm.finalize()


def _dcm_pausing(comm: TYComm, data: bytearray, support: bool) -> int:
    # 6d880..6de32: selected classic C9 capability and zero-filled cancellation.
    try:
        status = comm.initialize(0)
        if status:
            return status
        comm.configure("native_global:100f8194", 150)
        if support:
            status, raw, offsets = comm.support_snapshot(3)
            if status:
                return status
            status, payload = _classic_entry(raw, offsets, 0xC9)
            if status:
                return status
            status, _ = _classic_mask(payload, 3, 1)
            if status:
                return status
            _dword(data, 0, len(payload))
            status, raw, offsets = comm.support_snapshot(1)
            if status:
                return status
            status, payload = _classic_entry(raw, offsets, 0xC9)
            # Native ignores 123f0's unsupported result and stores its zero count.
            _dword(data, 4, 0 if status == 22 else sum(bool(v) for v in payload))
            return status if status not in (0, 22) else 0
        status, reply = comm.exchange(b"\x21\xc9")
        if status:
            return status
        if len(reply) != _dword(data, 4) + 2 or reply[1:2] != b"\xc9":
            return 3
        if not reply[:4128].ljust(4128, b"\0")[2] & 1:
            return 1003
        status, reply = comm.exchange(b"\x3b\xc9" + bytes(_dword(data, 0)))
        return 3 if not status and (len(reply) != 2 or reply[1] != 0xC9) else status
    finally:
        comm.finalize()


def _bdy51_support(comm: TYComm, data: bytearray, family: int = 51) -> int:
    # 18 2b060/2c200/2c3d0: selected response length/index and command metadata.
    try:
        status = comm.initialize(0)
        if status:
            return status
        comm.configure("native_global:100f8194", 150)
        status, raw, offsets = comm.support_snapshot(1)
        if status:
            return status
        status, payload = _classic_entry(raw, offsets, 0x82)
        if status:
            return status
        checks = (
            ((3, 0xC4), (4, 0x24), (5, 0x0F), (7, 0xF0))
            if family == 51
            else ((3, 0xE0 if family == 52 else 0x20), (4, 0x20), (8, 0xF0))
        )
        for minimum, mask in checks:
            status, index = _classic_mask(payload, minimum, mask)
            if status:
                return status
        _dword(data, 0, index)
        if family == 51:
            status, _ = _classic_mask(payload, 8, 0xF0)
            if status:
                return status
        count = sum(value != 0 for value in payload)
        _dword(data, 4, count + 2)
        if not count:
            return 22
        status, raw, offsets = comm.support_snapshot(3)
        if status:
            return status
        status, payload = _classic_entry(raw, offsets, 0x85 if family == 53 else 0x83)
        if status:
            return status
        status, _ = _classic_mask(payload, 3, 0x40 if family == 51 else 0x80)
        if status:
            return status
        count = sum(value != 0 for value in payload)
        _dword(data, 8, count + 2)
        return 0 if count else 22
    finally:
        comm.finalize()


def _bdy52_read(comm: TYComm, data: bytearray, family: int = 52) -> int:
    status, reply = comm.exchange(b"\x21\x82")
    if not status:
        if len(reply) != _dword(data, 4) or reply[1:2] != b"\x82":
            return 3
        bank = reply.ljust(4128, b"\x00")
        data[12] = bank[_dword(data, 0)] >> 4
        if family == 53:
            data[13] = (bank[2] >> 5) & 1
            data[14] = (bank[3] >> 5) & 1
        else:
            data[13] = bank[2] >> 6
            data[14] = (bank[2] >> 5) & 1
            data[15] = (bank[3] >> 5) & 1
    return status


def _bdy52_write(comm: TYComm, enabled: bool, identifier: int = 0x83) -> int:
    # 18 2d220 ASM checks both reply length2 and echoed83; C loses that branch.
    status, reply = comm.exchange(
        bytes((0x3B, identifier, 0x80 if enabled else 0)) + bytes(5)
    )
    return 3 if not status and (len(reply) != 2 or reply[1] != identifier) else status


def _bdy52_wait(
    comm: TYComm, data: bytearray, field: int, timeout: int, context: TYContext
) -> int:
    # 18 2d040: Sleep500 before every read; timeout is strictly greater.
    started = context.ticks()
    while True:
        if context.is_cancelled():
            raise Cancelled("BDY52 state wait cancelled")
        _delay(context, 500)
        status = _bdy52_read(comm, data)
        if status:
            _bdy52_write(comm, False)
            return status
        if data[field] == 0:
            return 0
        if elapsed_ticks(context.ticks(), started) > timeout:
            status = _bdy52_write(comm, False)
            return status or 9000


def _bdy52(comm: TYComm, data: bytearray, export: str, context: TYContext) -> int:
    # 18 2ccc0..2d483: two timed state guards, DTC9401/02/05 clear and finalcount.
    if export == BDY52[0]:
        return _bdy51_support(comm, data, 52)
    try:
        status = comm.initialize(0)
        if status:
            return status
        comm.configure("native_global:100f8194", 150)
        if export == BDY52[1]:
            return _bdy52_read(comm, data)
        if export == BDY52[2]:
            status = _bdy52_write(comm, True)
            if not status:
                status = _bdy52_read(comm, data)
                if status:
                    _bdy52_write(comm, False)
            return status
        status = _bdy52_wait(comm, data, 15, 65000, context)
        if not status:
            status = _bdy52_wait(comm, data, 13, 25000, context)
        if not status:
            status = _bdy52_write(comm, False)
        if not status:
            _delay(context, 100)
            status, reply = comm.read_dtcs(0x81, 0x1000)
            if not status:
                bank = reply[:4128].ljust(4128, b"\x00")
                count = bank[1]
                codes = {
                    int.from_bytes(bank[2 + index * 2 : 4 + index * 2], "big")
                    for index in range(count)
                }
                if codes.intersection((0x9401, 0x9402, 0x9405)):
                    status, _ = comm.exchange(b"\x14")
                    if not status:
                        status = 9000
        if not status:
            status = _bdy52_read(comm, data)
            if not status and data[12] != 1:
                status = 9000
        return status
    finally:
        comm.finalize()


def _bdy53(comm: TYComm, data: bytearray, export: str, context: TYContext) -> int:
    # 18 2d490..2dea2: regECUID preconditions, 81001ms wait and DTC priority.
    if export == BDY53[0]:
        return _bdy51_support(comm, data, 53)
    try:
        status = comm.initialize(0)
        if status:
            return status
        comm.configure("native_global:100f8194", 150)
        if export == BDY53[1]:
            status = _bdy52_read(comm, data, 53)
            if status:
                return status
            if data[12] == 0:
                return 9000
            status = _bdy52_write(comm, True, 0x85)
            if status:
                return status
            status = _bdy52_read(comm, data, 53)
            if status:
                _bdy52_write(comm, False, 0x85)
                return status
            return 0 if data[13] else 9000
        started = context.ticks()
        while True:
            if context.is_cancelled():
                raise Cancelled("BDY53 registration check cancelled")
            _delay(context, 500)
            status = _bdy52_read(comm, data, 53)
            if status:
                _bdy52_write(comm, False, 0x85)
                return status
            if data[13] == 0 or data[14] == 0:
                break
            if elapsed_ticks(context.ticks(), started) >= 81001:
                status = _bdy52_write(comm, False, 0x85)
                return status or 9000
        status = _bdy52_write(comm, False, 0x85)
        if status:
            return status
        status, reply = comm.read_dtcs(0x81, 0x1000)
        if status:
            return status
        status, _ = comm.exchange(b"\x14")
        if status:
            return status
        bank = reply[:4128].ljust(4128, b"\x00")
        codes = {
            int.from_bytes(bank[2 + index * 2 : 4 + index * 2], "big")
            for index in range(bank[1])
        }
        if 0x9402 in codes:
            return 9000
        return 9001 if codes.intersection((0x9401, 0x9405)) else 0
    finally:
        comm.finalize()


def _bdy_search_read(comm: TYComm, data: bytearray) -> int:
    status, reply = comm.exchange(b"\x22\x22\xf0")
    if not status:
        if len(reply) < 10 or reply[1:3] != b"\x22\xf0":
            return 3
        data[1:8] = reply[3:10]
    return status


def _bdy_search(comm: TYComm, data: bytearray, export: str, context: TYContext) -> int:
    # 18 a1b00..a22af: two address phases, seven-key bit selection and toggle write.
    phase = export.rsplit("_", 1)[1]
    retained = False
    try:
        if phase == "EndExtendedSession":
            comm.session(1, 1)
            return 1004
        if phase == "TerminateSearch":
            _routine(comm, 2, b"\x11\x12")
            comm.session(1, 1)
            return 1003
        if phase == "SearchOfKey":
            comm.select_target(0x750, 0xB5)
            comm.select_protocol(0x11)
            status = _initialize(comm)
            if status:
                return status
            status, reply = comm.exchange(b"\x22\x10\x13")
            if not status and (len(reply) < 4 or reply[1:3] != b"\x10\x13"):
                status = 3
            if status:
                comm.session(1, 1)
                return status
            count = reply[3]
            if not 1 <= count <= 7:
                comm.session(1, 1)
                return 3
            status = comm.session(1, 1)
            if status:
                return status
            comm.finalize()
            comm.select_target(0x750, 0x40)
            status = _initialize(comm)
            if status:
                return status
            status, _ = _routine(
                comm, 1, b"\x11\x12\x01" + bytes(((1 << (count + 1)) - 2,))
            )
            if not status:
                retained = True
                return 1000
            comm.session(1, 1)
            return status
        if phase == "SendKeyInfomation":
            request = bytearray(b"\x2e\x22\xf0" + data[1:8])
            request[2 + data[0]] ^= 3
            status, reply = comm.exchange(bytes(request))
            if not status and (len(reply) < 3 or reply[1:3] != request[1:3]):
                status = 3
            if not status:
                _delay(context, 200)
                status = _bdy_search_read(comm, data)
                if not status and data[data[0]] not in (1, 2):
                    status = 3
            comm.session(1, 1)
            return status
        started = context.ticks()
        while True:
            if _dword(data, 8):
                retained = True
                return 1001
            if context.is_cancelled():
                raise Cancelled("BDY key search cancelled")
            if elapsed_ticks(context.ticks(), started) >= 180000:
                raise TimeoutError("BDY key search exceeded host deadline")
            status, reply = _routine(comm, 3, b"\x11\x12")
            if status:
                _routine(comm, 2, b"\x11\x12")
                break
            mask = reply[4] & 0xFE
            if not mask:
                continue
            data[0] = mask.bit_length() - 1 if mask & (mask - 1) == 0 else 0
            status, _ = _routine(comm, 2, b"\x11\x12")
            if not data[0]:
                status = 1002
                break
            if not status:
                status = _bdy_search_read(comm, data)
                if not status and data[data[0]] not in (1, 2):
                    status = 3
            if not status:
                retained = True
                return 0
            break
        retained = status == 1001
        if not retained:
            comm.session(1, 1)
        return status
    finally:
        if not retained:
            comm.finalize()


def _bdy_key_poll(
    comm: TYComm, data: bytearray, erasure: bool, wait: bool, context: TYContext
) -> tuple[int, int]:
    # 18 b4f0/b8a0 and Plus8e1f0/8e6e0: byte5 completion, byte7 count.
    started = context.ticks()
    while True:
        if context.is_cancelled():
            raise Cancelled("BDY key routine cancelled")
        if elapsed_ticks(context.ticks(), started) >= 180000:
            raise TimeoutError("BDY key routine exceeded host deadline")
        status, reply = comm.exchange(b"\x31\x03\x11\x06")
        if not status and (len(reply) < 8 or reply[1:4] != b"\x03\x11\x06"):
            status = 3
        if status:
            return status, 0
        count = reply[7]
        if not wait:
            return 0, count
        cancel = data[1 if erasure else 2]
        if cancel in (1, 2):
            return (1001 if cancel == 1 else 1003), count
        if reply[5] == 1:
            return 0, count


def _bdy_key(comm: TYComm, data: bytearray, export: str, context: TYContext) -> int:
    # 18 8b1f0..8ba5f / Plus8e1f0..8ea5f: distinct retained/published phases.
    erasure = export.startswith("Ex2BDY_22_")
    phase = export.rsplit("_", 1)[1]
    retained = False
    try:
        if phase.startswith(("Stop", "Timeover", "End")):
            status, _ = _routine(comm, 2, b"\x11\x06")
            restore = comm.session(1, 1)
            if phase.startswith("Stop"):
                return 1002
            if phase.startswith("Timeover"):
                return 1004
            return status or restore
        if phase in ("KeyRegistration", "KeyCodeErasure"):
            try:
                status, count = _bdy_key_poll(comm, data, erasure, True, context)
            except BaseException:
                # Preserve the initiating host fault if best-effort cleanup also fails.
                with suppress(BaseException):
                    if context.is_cancelled():
                        comm.cleanup_exchange(b"\x31\x02\x11\x06")
                        comm.cleanup_session(1, 1)
                    else:
                        _routine(comm, 2, b"\x11\x06")
                        comm.session(1, 1)
                raise
            if not status:
                if not erasure:
                    data[1] = count
                retained = True
                return 1000
            if status not in (1001, 1003):
                _routine(comm, 2, b"\x11\x06")
                comm.session(1, 1)
            retained = status in (1000, 1001, 1003)
            return status
        status = _initialize(comm)
        if status:
            return status
        status, _ = _routine(comm, 1, b"\x11\x06" + bytes((1 if erasure else 2,)))
        if status:
            comm.session(1, 1)
            return status
        if phase.startswith("Start"):
            retained = True
            return 0
        status, count = _bdy_key_poll(comm, data, erasure, False, context)
        if not status:
            if erasure:
                data[0] = count
            else:
                data[:2] = bytes((3, count))
        stop, _ = _routine(comm, 2, b"\x11\x06")
        restore = comm.session(1, 1)
        return status or stop or restore
    finally:
        if not retained:
            comm.finalize()


def _ac_retained(comm: TYComm, data: bytearray, context: TYContext) -> int:
    # 18 TY b13e0..b16bf / Plus b7410..b7720; routine1108 retains start session.
    retained = False

    def session(mode: int) -> int:
        status, reply = comm.exchange(bytes((0x10, mode)))
        return 3 if not status and (len(reply) < 6 or reply[1] != mode) else status

    try:
        if _dword(data, 4) == 0:
            status = _open(comm)
            if status:
                return status
            status = session(1)
            if status:
                return status
            _delay(context, 50)
            status = session(3)
            if status:
                return status
            _delay(context, 50)
            status, _ = _routine(comm, 1, b"\x11\x08")
            if not status:
                retained = True
                return 1005
            _delay(context, 50)
            session(1)
            return status
        try:
            started = context.ticks()
            for _ in range(3600):
                if data[0] == 1:
                    return 0
                if context.is_cancelled():
                    raise Cancelled("AC28 polling cancelled")
                if elapsed_ticks(context.ticks(), started) >= 180000:
                    raise TimeoutError("AC28 exceeded host polling deadline")
                _delay(context, 50)
                status, reply = _routine(comm, 3, b"\x11\x08")
                if status:
                    return status
                if reply[4] == 2:
                    return 0
                if reply[4] not in (0, 1):
                    return 1007
            raise TimeoutError("AC28 exceeded host polling ceiling")
        finally:
            _delay(context, 50)
            session(1)
    finally:
        if not retained:
            comm.finalize()


def _ms2_exchange(
    comm: TYComm, context: TYContext, request: bytes, minimum: int, echo: int
) -> tuple[int, bytes]:
    # 18 TY c5ba0/c5c40/c5ab0: four attempts, retry only transport 2/7.
    status, reply = 0, b""
    for _ in range(4):
        if context.is_cancelled():
            raise Cancelled("MS2SMRT exchange cancelled")
        status, reply = comm.exchange(request)
        if status not in (2, 7):
            break
        _delay(context, 0)
    if status == 7:
        context.state[
            "native_global:"
            + ("10153554" if context.module_sha256 == SHA_PLUS_TY else "1012ae38")
        ] = reply[2] if len(reply) > 2 else 0
    if not status and (
        len(reply) < minimum
        or len(reply) > 4128
        or reply[1 : echo + 1] != request[1 : echo + 1]
    ):
        status = 3
    return status, reply


def _ms2_support(
    comm: TYComm, context: TYContext, identifier: int
) -> tuple[int, bytearray]:
    # 18 TY c5d60/c5cc0: 1xxx/2xxx support banks, continuation bit in last byte.
    bitmap = bytearray(512)
    cursor = identifier & 0xF000
    stop = (identifier - ((identifier - 1) & 31) - 1) & 0xFFFF
    while True:
        status, reply = _ms2_exchange(
            comm, context, b"\x22" + cursor.to_bytes(2, "big"), 7, 2
        )
        if status:
            return status, bitmap
        offset = (cursor >> 3) & 0x1FF
        bitmap[offset : offset + 4] = reply[3:7]
        if cursor >= stop or not reply[6] & 1:
            return 0, bitmap
        cursor += 32


def _ms2_supported(bitmap: bytearray, identifier: int) -> bool:
    index = ((identifier & 0xFFF) - 1) >> 3
    return bool(bitmap[index] & (0x80 >> ((identifier - 1) & 7)))


def _ms2smrt_enable(comm: TYComm, data: bytearray, context: TYContext) -> int:
    # 18 TY afee0..b0017: support, write11b2=1, normal-session restore precedence.
    try:
        action = _dword(data, 0)
        if action == 0:
            status = _open(comm)
            if status:
                return status
            comm.configure("native_1098", 0)
            status, bitmap = _ms2_support(comm, context, 0x11B2)
            return status or (0 if _ms2_supported(bitmap, 0x11B2) else 3)
        if action == 1:
            status, _ = _ms2_exchange(comm, context, b"\x2e\x11\xb2\x01", 3, 2)
            restore, _ = _ms2_exchange(comm, context, b"\x10\x01", 6, 1)
            return status or (3000 if restore else 0)
        return _ms2_exchange(comm, context, b"\x10\x01", 6, 1)[0]
    finally:
        comm.finalize()


def _ms2smrt_status(comm: TYComm, data: bytearray, context: TYContext) -> int:
    # 18 TY af490..af6ff: explicit7b4 target, support alternatives and exact60s test.
    try:
        comm.configure_target(0x7B4)
        status = _open(comm)
        if status:
            return status
        comm.configure("native_1098", 0)
        if _dword(data, 0) == 0:
            status, primary = _ms2_support(comm, context, 0x12B3)
            if status:
                return status
            status, secondary = _ms2_support(comm, context, 0x201B)
            if status:
                return status
            if not _ms2_supported(primary, 0x12B3):
                return 22
            if _ms2_supported(primary, 0x1233):
                _dword(data, 4, 1)
                return 0
            return 0 if _ms2_supported(secondary, 0x201B) else 22
        identifier = _dword(data, 8) & 0xFFFF
        status, reply = _ms2_exchange(
            comm, context, b"\x22" + identifier.to_bytes(2, "big"), 4, 2
        )
        if not status:
            if reply[3] != 0xFF:
                return 1000
            started = context.ticks()
            for _ in range(60001):
                status, reply = _ms2_exchange(comm, context, b"\x22\x12\xb3", 4, 2)
                if status or reply[3] == 0xFF:
                    break
                # Native compares wrapped absolute start+60000 strictly below now.
                if ((started + 60000) & 0xFFFFFFFF) < context.ticks():
                    return 2000
            else:
                raise TimeoutError("MS2SMRT05 exceeded host tight-poll ceiling")
        if status in (5, 7):
            value = 0x78 if status == 5 else reply[2] if len(reply) > 2 else 0
            _dword(data, 12, value)
        return status
    finally:
        comm.finalize()


def _ms2smrt_read(comm: TYComm, data: bytearray, context: TYContext) -> int:
    # 18 TY b0030..b01b1: support bank 0..111, raw reply 112..4239, NRC4240.
    try:
        status = _open(comm)
        if status:
            return status
        comm.configure("native_1098", 0)
        if _dword(data, 4244) == 0:
            data[:112] = bytes(112)
            status, bitmap = _ms2_support(comm, context, 0x137A)
            data[:112] = bitmap[:112]
            return status or (0 if _ms2_supported(bitmap, 0x137A) else 1000)
        status, reply = _ms2_exchange(comm, context, b"\x22\x13\x7a", 4, 2)
        if not status:
            data[112:4240] = reply.ljust(4128, b"\x00")
        elif status in (5, 7):
            value = 0x78 if status == 5 else reply[2] if len(reply) > 2 else 0
            data[4240:4244] = value.to_bytes(4, "little")
        return status
    finally:
        comm.finalize()


def _ms2smrt_erase(comm: TYComm, data: bytearray, context: TYContext) -> int:
    # 18 TY b01c0..b042f: 10000 ms unsigned polling deadline and restore override.
    try:
        status = 0
        if _dword(data, 0) == 0:
            status, reply = _ms2_exchange(comm, context, b"\x31\x01\x50\x00", 4, 3)
            if not status:
                status, reply = _ms2_exchange(comm, context, b"\x31\x03\x50\x00", 6, 3)
                started = context.ticks()
                while not status:
                    result = int.from_bytes(reply[4:6], "big")
                    if result == 2:
                        break
                    if result != 1:
                        data[8:12] = result.to_bytes(4, "little")
                        status = 1000
                        break
                    if elapsed_ticks(context.ticks(), started) >= 10000:
                        status = 2000
                        break
                    status, reply = _ms2_exchange(
                        comm, context, b"\x31\x03\x50\x00", 6, 3
                    )
                    if not status and reply[4:6] == b"\x00\x01":
                        _delay(context, 100)
            if status in (5, 7):
                value = 0x78 if status == 5 else reply[2] if len(reply) > 2 else 0
                data[4:8] = value.to_bytes(4, "little")
        restore, _ = _ms2_exchange(comm, context, b"\x10\x01", 6, 1)
        if _dword(data, 0) == 0 and status in (0, 1000, 2000) and restore:
            status = 3
        return status
    finally:
        comm.finalize()


def _smrt62(comm: TYComm, data: bytearray, export: str, context: TYContext) -> int:
    # 18 TY b3c40..b414f; b3f40 ASM preserves successful echo despite bad C recovery.
    retained = False
    try:
        if export == SMRT62[2]:
            status, _ = _routine(comm, 2, b"\x15\x04")
            restore = comm.session(1, 1)
            return 1001 if _dword(data, 4) else status or restore
        status = _initialize(comm)
        if status:
            return status
        if export == SMRT62[0]:
            status, reply = comm.exchange(b"\x22\x10\x23")
            if not status:
                status = 3 if len(reply) < 4 or reply[1:3] != b"\x10\x23" else 0
                if not status and reply[3] >= 2:
                    status = 1000
            if not status:
                status, reply = comm.exchange(b"\x22\x20\x3d")
                if not status:
                    if len(reply) < 5 or reply[1:3] != b"\x20\x3d" or len(reply) > 4128:
                        status = 3
                    else:
                        data[8 : 8 + len(reply) - 3] = reply[3:]
                        data[4136:4140] = (len(reply) - 3).to_bytes(4, "little")
            restore = comm.session(1, 1)
            return status or restore
        _delay(context, 100)
        size = _dword(data, 4136)
        selector = _dword(data, 0)
        mask = 0x80 >> selector if selector <= 5 else 0
        request = b"\x2e\x20\x3d" + bytes((data[8], mask)) + data[10 : 8 + size]
        status, reply = comm.exchange(request)
        if not status and (len(reply) < 3 or reply[1:3] != b"\x20\x3d"):
            status = 3
        if not status:
            _delay(context, 100)
            status, _ = _routine(comm, 1, b"\x15\x04")
        if status:
            comm.session(1, 1)
        else:
            retained = True
        return status
    finally:
        if not retained:
            comm.finalize()


def run_body(export: str, args: tuple[object, ...], context: TYContext) -> int:
    """Execute a reviewed body with exact native argument and source guards."""
    if export not in supported_exports(context.module_sha256):
        raise TYSourceError("TY body export/build has no reviewed implementation")
    if hashlib.sha256(context.module_bytes).hexdigest() != context.module_sha256:
        raise TYSourceError("TY body module bytes do not match selected identity")
    # The native wrappers pass LPVOID even where the worker ignores it.
    if len(args) == 1 and export in (
        "Ex2BDY_51_ExitCommunication",
        SMRT33_START,
        SMRT33_POLL,
        SMRT35_STOP,
        FCM_NAVI_START,
        FCM_PCS_START,
        FCM_PCS_STOP,
        FCM_RADAR_START,
        PLG_FINAL,
        PLG_CLASSIC[1],
        PLG_POLL,
        PLG_START,
        MM_PAIRING,
        *APP_IR,
    ):
        args = tuple[object, ...]()
    if export in DCM_INFORMATION:
        if len(args) != 1 or not isinstance(args[0], bytearray) or len(args[0]) < 4092:
            raise ValueError("DCM information requires native 4092-byte context")
        if context.is_cancelled():
            raise Cancelled("TY body dispatch cancelled")
        return _dcm_information(_manager(context), args[0], context)
    if export in DCM_PAUSING:
        if len(args) != 1 or not isinstance(args[0], bytearray) or len(args[0]) < 8:
            raise ValueError("DCM pausing requires native two-DWORD metadata context")
        if export == DCM_PAUSING[1] and (
            _dword(args[0], 0) > 4126 or _dword(args[0], 4) > 4126
        ):
            raise ValueError("DCM pausing metadata exceeds native frame buffer")
        if context.is_cancelled():
            raise Cancelled("TY body dispatch cancelled")
        return _dcm_pausing(context.comm("selected"), args[0], export == DCM_PAUSING[0])
    if export == DCM_AUTHENTICATION:
        if len(args) != 1 or not isinstance(args[0], bytearray) or len(args[0]) < 12:
            raise ValueError("DCM authentication requires native three-DWORD context")
        if _dword(args[0], 8) == 1 and _dword(args[0], 4) > 4126:
            raise ValueError("DCM authentication payload exceeds native frame buffer")
        if context.is_cancelled():
            raise Cancelled("TY body dispatch cancelled")
        return _dcm_authentication(context.comm("selected"), args[0])
    if export in DCM_BUB:
        if len(args) != 1 or not isinstance(args[0], bytearray) or len(args[0]) < 4:
            raise ValueError("DCM BUB requires native selected-size DWORD")
        if export == DCM_BUB[1] and _dword(args[0], 0) > 4126:
            raise ValueError("DCM BUB selected payload exceeds native frame buffer")
        if context.is_cancelled():
            raise Cancelled("TY body dispatch cancelled")
        return _dcm_bub(context.comm("selected"), args[0], export == DCM_BUB[0])
    if export in DCM_ACTIVATION:
        minimum = 12 if export == DCM_ACTIVATION[0] else 20
        if (
            len(args) != 1
            or not isinstance(args[0], bytearray)
            or len(args[0]) < minimum
        ):
            raise ValueError(
                "DCM activation requires native metadata/action/cancel context"
            )
        if export != DCM_ACTIVATION[0] and any(
            _dword(args[0], offset) > 4126 for offset in (0, 4, 8)
        ):
            raise ValueError("DCM activation metadata exceeds native frame buffer")
        if context.is_cancelled():
            raise Cancelled("TY body dispatch cancelled")
        return _dcm_activation(context.comm("selected"), args[0], export, context)
    if export in DCM_FOTA:
        minimum = 48 if export == DCM_FOTA[2] else 20
        if (
            len(args) != 1
            or not isinstance(args[0], bytearray)
            or len(args[0]) < minimum
        ):
            raise ValueError(
                "DCM FOTA requires native selected metadata/status context"
            )
        data = args[0]
        if export == DCM_FOTA[1] and _dword(data, 16) > 4126:
            raise ValueError("DCM FOTA command exceeds native frame buffer")
        if export == DCM_FOTA[2] and (
            _dword(data, 4) > 4126 or _dword(data, 12) > 4126
        ):
            raise ValueError("DCM FOTA response metadata exceeds native extent")
        if context.is_cancelled():
            raise Cancelled("TY body dispatch cancelled")
        return _dcm_fota(context.comm("selected"), data, export, context)
    if export in DCM_REMOTE:
        minimum = 16 if export == DCM_REMOTE[0] else 30
        if (
            len(args) != 1
            or not isinstance(args[0], bytearray)
            or len(args[0]) < minimum
        ):
            raise ValueError("DCM remote settings requires native selected context")
        if export != DCM_REMOTE[0] and any(
            _dword(args[0], offset) > 4126 for offset in (0, 4, 8, 12)
        ):
            raise ValueError("DCM remote metadata exceeds native frame buffer")
        if context.is_cancelled():
            raise Cancelled("TY body dispatch cancelled")
        return _dcm_remote(context.comm("selected"), args[0], export)
    if export in BDY53:
        minimum = 12 if export == BDY53[0] else 15
        if (
            len(args) != 1
            or not isinstance(args[0], bytearray)
            or len(args[0]) < minimum
        ):
            raise ValueError(
                "BDY53 requires native selected metadata/status output buffer"
            )
        if export != BDY53[0] and (
            _dword(args[0], 0) >= 4128 or _dword(args[0], 4) > 4128
        ):
            raise ValueError("BDY53 selected response metadata exceeds native extent")
        if context.is_cancelled():
            raise Cancelled("TY body dispatch cancelled")
        return _bdy53(context.comm("selected"), args[0], export, context)
    if export in BDY52:
        minimum = 12 if export == BDY52[0] else 16
        if (
            len(args) != 1
            or not isinstance(args[0], bytearray)
            or len(args[0]) < minimum
        ):
            raise ValueError(
                "BDY52 requires native selected metadata/status output buffer"
            )
        if export != BDY52[0] and (
            _dword(args[0], 0) >= 4128 or _dword(args[0], 4) > 4128
        ):
            raise ValueError("BDY52 selected response metadata exceeds native extent")
        if context.is_cancelled():
            raise Cancelled("TY body dispatch cancelled")
        return _bdy52(context.comm("selected"), args[0], export, context)
    if export == BDY51_SUPPORT:
        if len(args) != 1 or not isinstance(args[0], bytearray) or len(args[0]) < 12:
            raise ValueError("BDY51 support requires mutable native output DWORDs")
        if context.is_cancelled():
            raise Cancelled("TY body dispatch cancelled")
        return _bdy51_support(context.comm("selected"), args[0])
    if export in BDY_SEARCH:
        if export in (BDY_SEARCH[1], BDY_SEARCH[2]):
            minimum = 12 if export == BDY_SEARCH[1] else 8
            if (
                len(args) != 1
                or not isinstance(args[0], bytearray)
                or len(args[0]) < minimum
            ):
                raise ValueError(
                    "BDY23 requires its mutable selected-key/cancel buffer"
                )
            data = args[0]
            if export == BDY_SEARCH[2] and data[0] > 7:
                raise ValueError("BDY23 selected key exceeds native write buffer")
        else:
            if len(args) > 1:
                raise ValueError("BDY23 phase accepts one ignored native pointer")
            data = bytearray()
        if context.is_cancelled():
            raise Cancelled("TY body dispatch cancelled")
        return _bdy_search(_manager(context), data, export, context)
    if export in BDY_KEY:
        phase = export.rsplit("_", 1)[1]
        if phase in ("KeyNumGet", "KeyRegistration", "KeyCodeErasure"):
            minimum = 3 if phase == "KeyRegistration" else 2
            if (
                len(args) != 1
                or not isinstance(args[0], bytearray)
                or len(args[0]) < minimum
            ):
                raise ValueError(
                    "BDY21/22 requires its mutable native count/cancel context"
                )
            data = args[0]
        else:
            if len(args) > 1:
                raise ValueError("BDY21/22 phase accepts one ignored native pointer")
            data = bytearray()
        if context.is_cancelled():
            raise Cancelled("TY body dispatch cancelled")
        return _bdy_key(_manager(context), data, export, context)
    if export == AC_RETAINED:
        if len(args) != 1 or not isinstance(args[0], bytearray) or len(args[0]) < 8:
            raise ValueError("AC28 requires a mutable native cancel/action context")
        if context.is_cancelled():
            raise Cancelled("TY body dispatch cancelled")
        return _ac_retained(_manager(context), args[0], context)
    if export in (MS2SMRT_STATUS, MS2SMRT_ENABLE, MS2SMRT_READ, MS2SMRT_ERASE):
        minimum = {
            MS2SMRT_STATUS: 16,
            MS2SMRT_ENABLE: 4,
            MS2SMRT_READ: 4248,
            MS2SMRT_ERASE: 12,
        }[export]
        if (
            len(args) != 1
            or not isinstance(args[0], bytearray)
            or len(args[0]) < minimum
        ):
            raise ValueError("MS2SMRT requires a bounded mutable native context")
        if context.is_cancelled():
            raise Cancelled("TY body dispatch cancelled")
        comm = _manager(context)
        return {
            MS2SMRT_STATUS: _ms2smrt_status,
            MS2SMRT_ENABLE: _ms2smrt_enable,
            MS2SMRT_READ: _ms2smrt_read,
            MS2SMRT_ERASE: _ms2smrt_erase,
        }[export](comm, args[0], context)
    if export in SMRT62:
        minimum = 8 if export == SMRT62[2] else 4140
        if (
            len(args) != 1
            or not isinstance(args[0], bytearray)
            or len(args[0]) < minimum
        ):
            raise ValueError("SMRT62 requires a bounded mutable native context")
        data = args[0]
        if export == SMRT62[1] and not 2 <= _dword(data, 4136) <= 4125:
            raise ValueError("SMRT62 payload exceeds native request buffer")
        if context.is_cancelled():
            raise Cancelled("TY body dispatch cancelled")
        return _smrt62(_manager(context), data, export, context)
    if export == CSN_RESET or export in CSN_TIRE:
        minimum = 4 if export == CSN_RESET else 8266
        if (
            len(args) != 1
            or not isinstance(args[0], bytearray)
            or len(args[0]) < minimum
        ):
            raise ValueError(
                "CSN operation requires a bounded mutable native selected context"
            )
        data = args[0]
        if (
            export in CSN_TIRE
            and _dword(data, 4 if export == CSN_TIRE[1] else 0) > 4126
        ):
            raise ValueError("CSN selected payload exceeds native buffer")
        if context.is_cancelled():
            raise Cancelled("TY body dispatch cancelled")
        if export == CSN_RESET:
            return _csn_reset(_manager(context), _dword(data, 0))
        return _csn_tire(context.comm("selected"), data, export == CSN_TIRE[1])
    if export in AC_CLASSIC:
        if (
            len(args) != 1
            or not isinstance(args[0], bytearray)
            or len(args[0]) < 4
            or _dword(args[0], 0) > 4126
        ):
            raise ValueError(
                "AC classic requires a bounded native selected command-size DWORD"
            )
        if context.is_cancelled():
            raise Cancelled("TY body dispatch cancelled")
        return _ac_classic(
            context.comm("selected"), _dword(args[0], 0), export == AC_CLASSIC[1]
        )
    if export in DCM_NRC:
        if args:
            raise ValueError("DCM37/44 takes no arguments")
        if context.is_cancelled():
            raise Cancelled("TY body dispatch cancelled")
        return _dcm_nrc(_manager(context))
    if export in (*DCM_SETTING, *DCM_ENABLE, DCM_ROUTINE):
        if export in DCM_SETTING:
            if len(args) != 1 or not isinstance(args[0], bytearray) or len(args[0]) < 2:
                raise ValueError(
                    "DCM setting requires mutable native input/readback bytes"
                )
            data = args[0]
        else:
            if args:
                raise ValueError("DCM enable/routine takes no arguments")
            data = bytearray()
        if context.is_cancelled():
            raise Cancelled("TY body dispatch cancelled")
        comm = _manager(context)
        return (
            _dcm_setting(comm, data)
            if export in DCM_SETTING
            else _dcm_enable(comm, export == DCM_ROUTINE)
        )
    if export == FCM_INFO:
        if len(args) != 1 or not isinstance(args[0], bytearray) or len(args[0]) < 16:
            raise ValueError("FCM13 requires a mutable native 16 byte output")
        if context.is_cancelled():
            raise Cancelled("TY body dispatch cancelled")
        return _fcm_info(_manager(context), args[0])
    if export in PLG_CLASSIC:
        if export == PLG_CLASSIC[1]:
            if args:
                raise ValueError("PLG classic diagnosis takes no arguments")
            data = bytearray()
        else:
            if (
                len(args) != 1
                or not isinstance(args[0], bytearray)
                or len(args[0]) < 16
            ):
                raise ValueError(
                    "PLG classic requires a mutable 16 byte selected metadata context"
                )
            data = args[0]
            length_offset = 4 if export == PLG_CLASSIC[0] else 12
            index_offset = length_offset - 4
            length = _dword(data, length_offset)
            index = _dword(data, index_offset)
            if length > 4126 or index >= length + 2:
                raise ValueError(
                    "PLG selected response length/index exceeds native buffer"
                )
        if context.is_cancelled():
            raise Cancelled("TY body dispatch cancelled")
        return _plg_classic(export, context.comm("selected"), data)
    if export == MM_DATA_LIST:
        if len(args) != 1 or not isinstance(args[0], bytearray) or len(args[0]) < 30:
            raise ValueError("MM data list requires native thirty-byte output")
        if context.is_cancelled():
            raise Cancelled("TY body dispatch cancelled")
        return _mm_data_list(context.comm("selected"), args[0])
    if export in (MM_MEDIA, MM_RETAINED, MM_RESET, MM_CHECK):
        minimum = (
            13 if export == MM_MEDIA else 8 if export in (MM_RESET, MM_CHECK) else 4
        )
        if (
            len(args) != 1
            or not isinstance(args[0], bytearray)
            or len(args[0]) < minimum
        ):
            raise ValueError("MM media operation requires native mutable context")
        if context.is_cancelled():
            raise Cancelled("TY body dispatch cancelled")
        if export == MM_RESET:
            return _mm_reset(_manager(context), args[0], context)
        if export == MM_CHECK:
            return _mm_check(_manager(context), args[0], context)
        return (
            _mm_media(_manager(context), args[0])
            if export == MM_MEDIA
            else _mm_retained(_manager(context), args[0], context)
        )
    if export in (*MM_VALET, MM_DIAGNOSTIC):
        if export == MM_DIAGNOSTIC:
            if args:
                raise ValueError("MM diagnostic takes no native arguments")
            data = bytearray()
        else:
            if len(args) != 1 or not isinstance(args[0], bytearray) or len(args[0]) < 4:
                raise ValueError("MM valet requires native selected-size DWORD")
            data = args[0]
            if export == MM_VALET[1] and _dword(data, 0) > 4125:
                raise ValueError("MM valet selected size exceeds native frame extent")
        if context.is_cancelled():
            raise Cancelled("TY body dispatch cancelled")
        return _mm_valet(context.comm("selected"), data, export)
    if export in MM_INFORMATION:
        minimum = 12 if export == MM_INFORMATION[0] else 25
        if (
            len(args) != 1
            or not isinstance(args[0], bytearray)
            or len(args[0]) < minimum
        ):
            raise ValueError("MM information requires native selected output context")
        data = args[0]
        if export == MM_INFORMATION[1] and (
            not 10 <= _dword(data, 0) <= 4126
            or (_dword(data, 8) and not 3 <= _dword(data, 4) <= 4126)
        ):
            raise ValueError(
                "MM information metadata cannot contain selected output fields"
            )
        if context.is_cancelled():
            raise Cancelled("TY body dispatch cancelled")
        return _mm_information(
            context.comm("selected"), data, export == MM_INFORMATION[0]
        )
    if export in MM_IMAGE:
        minimum = 20 if export == MM_IMAGE[0] else 24
        if (
            len(args) != 1
            or not isinstance(args[0], bytearray)
            or len(args[0]) < minimum
        ):
            raise ValueError(
                "MM image requires native selected metadata/status context"
            )
        if export == MM_IMAGE[1] and (
            _dword(args[0], 0) > 4126
            or _dword(args[0], 8) > 4126
            or _dword(args[0], 16) > 4125
        ):
            raise ValueError("MM image metadata exceeds native frame extent")
        if context.is_cancelled():
            raise Cancelled("TY body dispatch cancelled")
        return _mm_image(
            context.comm("selected"), args[0], export == MM_IMAGE[0], context
        )
    if export in MM_SUPPORT:
        minimum = 4220 if export == MM_SUPPORT[1] else 136
        if (
            len(args) != 1
            or not isinstance(args[0], bytearray)
            or len(args[0]) < minimum
        ):
            raise ValueError(
                "MM support requires complete native metadata/output context"
            )
        if context.is_cancelled():
            raise Cancelled("TY body dispatch cancelled")
        return _mm_support(
            context.comm("selected"),
            args[0],
            export == MM_SUPPORT[1],
            _mm_pending_field(context.module_sha256),
        )
    if export in (MM_HISTORY, MM_DISC):
        minimum = 4132 if export == MM_DISC else 131
        if (
            len(args) != 1
            or not isinstance(args[0], bytearray)
            or len(args[0]) < minimum
        ):
            raise ValueError("MM history requires a mutable native output context")
        data = args[0]
        if export == MM_HISTORY and (
            data[1] > 61
            or _dword(data, 64) > 4126
            or sum(bool(v) for v in data[2 : data[1] + 2]) > _dword(data, 64)
        ):
            raise ValueError("MM history support mask exceeds bounded selected payload")
        if export == MM_DISC and _dword(data, 4128) > 4128:
            raise ValueError("MM disc expected reply exceeds native output buffer")
        if context.is_cancelled():
            raise Cancelled("TY body dispatch cancelled")
        return _mm_history(
            context.comm("selected"),
            data,
            export == MM_DISC,
            _mm_pending_field(context.module_sha256),
        )
    if export in BDY51:
        exiting = export.endswith("ExitCommunication")
        if exiting:
            if args:
                raise ValueError("BDY exit takes no arguments")
            data = bytearray()
        else:
            if (
                len(args) != 1
                or not isinstance(args[0], bytearray)
                or len(args[0]) < 40
            ):
                raise ValueError(
                    "BDY51 requires a mutable native context of at least 40 bytes"
                )
            data = args[0]
            if _dword(data, 0) + 13 >= len(data) or _dword(data, 4) > len(data) - 12:
                raise ValueError("BDY selected metadata exceeds supplied context")
        if context.is_cancelled():
            raise Cancelled("TY body dispatch cancelled")
        comm = context.comm("selected")
        try:
            return _bdy51(export, comm, data, context)
        except BaseException:
            comm.finalize()
            raise
    if export in SMRT_EXPORTS:
        minimum = (
            16
            if export == SMRT35_CHECK
            else 6
            if export in (SMRT35_GET, SMRT35_REGET)
            else 0
        )
        if minimum and (
            len(args) != 1
            or not isinstance(args[0], bytearray)
            or len(args[0]) < minimum
        ):
            raise ValueError("SMRT operation requires a mutable selected native buffer")
        if not minimum and args:
            raise ValueError("SMRT start/poll/terminate takes no arguments")
        if context.is_cancelled():
            raise Cancelled("TY body dispatch cancelled")
        data = args[0] if minimum else bytearray()
        assert isinstance(data, bytearray)
        return _smrt(export, context.comm("selected"), data, context)
    if export == PLG3:
        if len(args) != 1 or not isinstance(args[0], bytearray) or len(args[0]) < 28:
            raise ValueError(
                "PLG3 requires mutable selected native context of at least 28 bytes"
            )
        if (
            int.from_bytes(args[0][:4], "little") == 1
            and len(args[0]) <= 36 + args[0][12] * 8
        ):
            raise ValueError("PLG3 selected item is outside supplied context")
    if export in AC_RESET and (
        len(args) != 1 or not isinstance(args[0], bytearray) or len(args[0]) < 4
    ):
        raise ValueError("AC reset requires a mutable native action DWORD")
    if export in DCM_CLEAR and (
        len(args) != 1 or not isinstance(args[0], bytearray) or len(args[0]) < 1
    ):
        raise ValueError("DCM clear requires a mutable native result byte")
    if export in (DCM_ID, DCM_SOFTWARE):
        minimum = 43 if export == DCM_SOFTWARE else 4132
        if (
            len(args) != 1
            or not isinstance(args[0], bytearray)
            or len(args[0]) < minimum
        ):
            raise ValueError(
                "DCM operation requires a bounded mutable native output context"
            )
        if export == DCM_SOFTWARE:
            offset = int.from_bytes(args[0][:4], "little")
            size = int.from_bytes(args[0][8:12], "little")
            if size > 21 or offset + size > 4128:
                raise ValueError(
                    "DCM software source/output slice exceeds native buffer"
                )
        if context.is_cancelled():
            raise Cancelled("TY body dispatch cancelled")
        return _dcm_read(context.comm("selected"), args[0], export == DCM_SOFTWARE)
    if export in (PLG_SUPPORT, PLG_RESULT) and (
        len(args) != 1 or not isinstance(args[0], bytearray) or len(args[0]) < 24
    ):
        raise ValueError("PLG operation requires mutable 24 byte selected context")
    polling = export in (FCM_NAVI_CHECK, FCM_PCS_CHECK, FCM_RADAR_CHECK)
    if polling:
        if len(args) != 1 or not isinstance(args[0], bytearray) or len(args[0]) < 4:
            raise ValueError("FCM check requires a mutable native cancel DWORD buffer")
    elif args and export not in (PLG_SUPPORT, PLG_RESULT, *DCM_CLEAR, *AC_RESET, PLG3):
        raise ValueError("TY operation takes no arguments")
    if context.is_cancelled():
        raise Cancelled("TY body dispatch cancelled")
    comm = _manager(context)
    if export == PLG3:
        data = args[0]
        assert isinstance(data, bytearray)
        return _plg3(comm, data, context)
    if export == AC_SERVO:
        return _ac_command(comm, context, 1)
    if export in AC_RESET:
        data = args[0]
        assert isinstance(data, bytearray)
        return _ac_command(
            comm,
            context,
            AC_RESET.index(export) + 6,
            int.from_bytes(data[:4], "little"),
        )
    if export == AC_BATTERY_CLEAR:
        return _ac_battery_clear(comm, context)
    if export in DCM_CLEAR:
        data = args[0]
        assert isinstance(data, bytearray)
        return _dcm_clear(comm, data)
    if export in (PLG_SUPPORT, PLG_RESULT):
        data = args[0]
        assert isinstance(data, bytearray)
        return (
            _plg_support(comm, data)
            if export == PLG_SUPPORT
            else _plg_result(comm, data)
        )
    if export == FCM_RADAR_START:
        return _radar_start(comm)
    if export == FCM_RADAR_CHECK:
        cancel = args[0]
        assert isinstance(cancel, bytearray)
        return _poll(comm, cancel, False, context, b"\x11\x0e")
    if export == PLG_START:
        return _plg_start(comm)
    if export == PLG_POLL:
        return _plg_poll(comm, context)
    if export == PLG_FINAL:
        comm.finalize()
        return 0
    if export == MM_PAIRING:
        return _pairing(comm, context)
    if export in APP_IR:
        return _ir_projector(comm, APP_IR.index(export) + 1)
    pcs = export in (FCM_PCS_START, FCM_PCS_CHECK, FCM_PCS_STOP)
    if polling:
        cancel = args[0]
        assert isinstance(cancel, bytearray)
        return _poll(comm, cancel, pcs, context)
    if export == FCM_PCS_STOP:
        # 18 TY be5f0: ignore stop/restore status and publish 1003.
        try:
            _routine(comm, 2, b"\x16\x0c")
            _normal(comm)
        finally:
            comm.finalize()
        return 1003
    try:
        return _start(comm, pcs)
    except BaseException:
        comm.finalize()
        raise
