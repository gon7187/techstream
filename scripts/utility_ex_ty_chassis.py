"""Source-bound TY chassis operations over the shared concrete communication core.

Unknown source/export pairs fail before I/O. The dispatcher owns native threads;
this module owns diagnostic predicates, selected UI buffers and cleanup policy.
"""

from __future__ import annotations

import hashlib
import struct
from contextlib import suppress
from dataclasses import dataclass
from fractions import Fraction
from typing import Protocol

from scripts.native_memory import NativeMemoryArena
from scripts.utility_ex_ty import (
    SHA_12_TY,
    SHA_18_TY,
    SHA_PLUS_TY,
    TYComm,
    TYSourceError,
    elapsed_ticks,
)


class ChassisContext(Protocol):
    module_sha256: str
    module_bytes: bytes
    state: dict[str, object]
    native_memory: NativeMemoryArena | None

    @property
    def native_memory_owner(self) -> object: ...

    @property
    def mode(self) -> int: ...

    def comm(self, kind: str, /) -> TYComm: ...
    def is_cancelled(self) -> bool: ...
    def sleep(self, ms: int, /) -> None: ...
    def ticks(self) -> int: ...


@dataclass(frozen=True)
class ChassisContract:
    source_sha256: str
    manager: str
    retry_setter: str
    pending_setter: str
    retries_setter: str
    legacy_setter: str = "native_rva:12180"
    asus13_start: bytes = b"\x30\6\x19\1"
    asus13_stop: bytes = b"\x30"
    nk_manager: str | None = None
    legacy_busy_setter: str = "native_rva:121d0"
    asus08_state: str = "native:1012ae1c"
    asus08_retries: bool = True
    asus08_tank_retries: bool = True
    asus10_discover: bool = True
    bsm_optional_support: bool = True


CONTRACT_18 = ChassisContract(
    SHA_18_TY,
    "native:1011d4f0",
    "native_rva:1a860",
    "native_rva:1a880",
    "native_rva:1a8c0",
)
CONTRACT_12 = ChassisContract(
    SHA_12_TY,
    "native:100aed50",
    "native_rva:12960",
    "native_rva:12980",
    "native_rva:129d0",
    "native_rva:b940",
    legacy_busy_setter="native_rva:b960",
    asus08_state="native:100ba458",
    asus08_retries=False,
    asus08_tank_retries=False,
    asus10_discover=False,
    bsm_optional_support=False,
)
TWELVE_EXPORTS = frozenset(
    {
        "Ex2BSM_03_04_SupportCheck",
        "Ex2BSM_03_04_ActiveTest",
        "Ex2BSM_05_06_SupportCheck",
        "Ex2BSM_05_06_ActiveTest",
        "Ex2ARS_01_A8SupportCheck",
        "Ex2ARS_01_ReturnActuatorCenterPos",
        "Ex2ARS_02_SupportCheck",
        "Ex2ARS_02_InitCompVal",
        "Ex2ARS_03_SupportCheck",
        "Ex2ARS_03_ActiveTest",
        "Ex24WD_03_SupportCheck",
        "Ex24WD_03_ChangePreventionMode",
        "Ex2ABS4WD_01_SupportCheck",
        "Ex2ABS4WD_01_ChangePreventionMode",
        "Ex2PSAABS_01_SendMessage",
        "Ex2PSAABS_02_SendMessage",
        "Ex2PSAABS_03_StartActiveTest",
        "Ex2PSAABS_03_ConfirmStatus",
        "Ex2TPW_03_SendMessage",
        "Ex2DRS_02_SupportCheck",
        "Ex2DRS_02_ReadModeStatus",
        "Ex2DRS_02_ReadRadarCruiseData",
        "Ex2DRS_03_SupportCheck",
        "Ex2DRS_03_ReadModeStatus",
        "Ex2DRS_03_ReadRadarCruiseData",
        "Ex2DRS_03_EndProcess",
        "Ex2DRS_04_SendMessage",
        "Ex2ASUS_10_GetStatOfHeightCtrlProhibition",
        "Ex2ASUS_10_ChgAndGetStatOfHeightCtrlProhibition",
        "Ex2ASUS_08_StartCompressRaisingCtrl",
        "Ex2ASUS_08_StartTankPressLowCtrl",
        "Ex2ASUS_08_ReadPressureSensor",
        "Ex2ASUS_08_ModeTransEnterHeightCtrlProhibit",
        "Ex2ARS_01_ReadDTCofVGRS",
        "Ex2ARS_01_ReadDTCofARS",
        "Ex2ARS_01_ClearOffSetValue",
        "Ex2ARS_02_ChkVGRSDtc",
        "Ex2ARS_02_ChkARSDtc",
        "Ex2ARS_02_ClrCompVal",
        "Ex2ASUS_05_ModifyVheightDownStart",
        "Ex2ASUS_05_ModifyVheightStop",
        "Ex2ASUS_05_CheckModifiedVheight",
        "Ex2ASUS_05_ModifyVheightTimeOver",
        "Ex2ASUS_05_LearnKneelDownVheight",
        "Ex2ASUS_05_ReturnVheightStart",
        "Ex2ASUS_05_CheckReturnedVheight",
        "Ex2ASUS_04_SupportCheck",
        "Ex2ASUS_04_ReturnVhight",
        "Ex2ASUS_04_LearnKneeldownVheight",
        "Ex2ASUS_04_CheckReturnedVhight",
        "Ex2ASUS_05_SupportCheck",
        "Ex2BSM_01_02_SupportCheck",
        "Ex2BSM_01_02_Mov2TestMode",
        "Ex2BSM_01_02_ChkStilInTestMode",
        "Ex2BSM_01_02_ExitTestMode",
        "Ex2BSM_07_08_SupportCheck",
        "Ex2BSM_07_08_GetAbnormalHistory",
        "Ex2BSM_07_08_ClearAbnormalHistory",
        "Ex2VGRS_04_SupportCheck",
        "Ex2VGRS_04_CheckDTC",
        "Ex2ASUS_06_AirPressure",
        "Ex2ASUS_07_AirPressure",
        "Ex2ASUS_06_ConditionCheck",
        "Ex2ASUS_07_ConditionCheck",
        "Ex2ASUS_06_TheHeightAndTank",
        "Ex2ASUS_07_TheHeightAndTank",
        "Ex2ASUS_06_LiftRise",
        "Ex2ASUS_07_LiftRise",
        "Ex2DRS_02_StopActiveTest",
        "Ex2DRS_03_StopActiveTest",
        "Ex2ASUS_04_ModifyVhight",
        "Ex2ASUS_08_EndExtendedSession",
        "Ex2EMPS_07_ConfirmTheAssistMap",
        "Ex2EMPS_07_ClearTheAssistMap",
        "Ex2VGRS_04_StartLockRelease",
        "Ex2VGRS_04_EndLockRelease",
        "Ex2VGRS_04_StartNeutralCompMode",
        "Ex2VGRS_04_EndNeutralCompMode",
        "Ex2VGRS_04_ClearDTC",
        "Ex2ABS_17_SupportCheck",
        "Ex2ABS_17_GetABSInfo",
        "Ex2ABS_17_SychronizingABSInfo",
        "Ex2ABS_18_SupportCheck",
        "Ex2ABS_18_SetNeutralPos",
        "Ex2ABS_21_SupportCheck",
        "Ex2ABS_21_ChangeMode",
        "Ex2ABS_21_CheckSensorStatus",
    }
)
CONTRACT_PLUS = ChassisContract(
    SHA_PLUS_TY,
    "native:101392d0",
    "native_rva:1e290",
    "native_rva:1e2b0",
    "native_rva:1e2d0",
    "native_rva:142f0",
    b"\x30\6\xff\4",
    b"\x30\6\xff\10",
    nk_manager="native:1013e7d0",
    legacy_busy_setter="native_rva:14320",
)
PLUS_EXPORTS = frozenset(
    {
        "Ex2ABS_52_ReadBrakePadResidualThickness",
        "Ex2ABS_52_WriteBrakePadResidualThickness",
        "Ex2ASUS_10_GetStatOfHeightCtrlProhibition",
        "Ex2ASUS_10_ChgAndGetStatOfHeightCtrlProhibition",
        "Ex2ASUS_06_ConditionCheck",
        "Ex2ASUS_06_LiftRise",
        "Ex2ASUS_06_AirPressure",
        "Ex2ASUS_06_TheHeightAndTank",
        "Ex2ASUS_07_LiftRise",
        "Ex2ASUS_07_AirPressure",
        "Ex2ASUS_07_TheHeightAndTank",
        "Ex2ASUS_07_ConditionCheck",
        "Ex2ARS_01_A8SupportCheck",
        "Ex2ARS_01_ReadDTCofVGRS",
        "Ex2ARS_01_ClearOffSetValue",
        "Ex2ARS_01_ReadDTCofARS",
        "Ex2ARS_01_ReturnActuatorCenterPos",
        "Ex2ARS_02_SupportCheck",
        "Ex2ARS_02_ChkVGRSDtc",
        "Ex2ARS_02_ClrCompVal",
        "Ex2ARS_02_ChkARSDtc",
        "Ex2ARS_02_InitCompVal",
        "Ex2ARS_03_ActiveTest",
        "Ex2ARS_03_SupportCheck",
        "Ex2BSM_03_04_SupportCheck",
        "Ex2BSM_03_04_ActiveTest",
        "Ex2BSM_03_04_ActiveTestCon3_5",
        "Ex2BSM_05_06_SupportCheck",
        "Ex2BSM_05_06_ActiveTest",
        "Ex24WD_03_SupportCheck",
        "Ex24WD_03_ChangePreventionMode",
        "Ex2ABS4WD_01_SupportCheck",
        "Ex2ABS4WD_01_ChangePreventionMode",
        "Ex2TPW_03_SendMessage",
        "Ex2BSM_01_02_SupportCheck",
        "Ex2BSM_01_02_Mov2TestMode",
        "Ex2BSM_01_02_ChkStilInTestMode",
        "Ex2BSM_01_02_ExitTestMode",
        "Ex2BSM_07_08_SupportCheck",
        "Ex2BSM_07_08_GetAbnormalHistory",
        "Ex2BSM_07_08_ClearAbnormalHistory",
        "Ex2DRS_02_SupportCheck",
        "Ex2DRS_02_ReadModeStatus",
        "Ex2DRS_02_ReadRadarCruiseData",
        "Ex2DRS_02_StopActiveTest",
        "Ex2DRS_03_SupportCheck",
        "Ex2DRS_03_ReadRadarCruiseData",
        "Ex2DRS_03_StopActiveTest",
        "Ex2DRS_03_ReadModeStatus",
        "Ex2DRS_03_EndProcess",
        "Ex2DRS_04_SendMessage",
        "Ex2ASUS_04_SupportCheck",
        "Ex2ASUS_04_ModifyVhight",
        "Ex2ASUS_04_ReturnVhight",
        "Ex2ASUS_04_LearnKneeldownVheight",
        "Ex2ASUS_04_CheckReturnedVhight",
        "Ex2ASUS_05_ModifyVheightDownStart",
        "Ex2ASUS_05_ModifyVheightStop",
        "Ex2ASUS_05_CheckModifiedVheight",
        "Ex2ASUS_05_ModifyVheightTimeOver",
        "Ex2ASUS_05_LearnKneelDownVheight",
        "Ex2ASUS_05_CheckReturnedVheight",
        "Ex2ASUS_05_ReturnVheightStart",
        "Ex2ASUS_05_SupportCheck",
        "Ex2ABS_33_ShiftNormalMode",
        "Ex2ABS_47_EndExtendedSession",
        "Ex2ABS_47_ErrorEndExtendedSession",
        "Ex2ABS_47_ExitEndExtendedSession",
        "Ex2ABS_18_SupportCheck",
        "Ex2ABS_18_SetNeutralPos",
        "Ex2ABS_29_SupportCheck",
        "Ex2ABS_29_ShiftDealerMode",
        "Ex2ABS_21_SupportCheck",
        "Ex2ABS_21_ChangeMode",
        "Ex2ABS_21_CheckSensorStatus",
        "Ex2AWD_04_Overwrite",
        "Ex2ABS_17_SupportCheck",
        "Ex2ABS_17_GetABSInfo",
        "Ex2ABS_17_SychronizingABSInfo",
        "Ex2EMPS_07_ConfirmTheAssistMap",
        "Ex2EMPS_07_ClearTheAssistMap",
        "Ex2AHC_03_ReadModeStatus",
        "Ex2AHC_03_SwitchServiceMode",
        "Ex2AHC_03_EndExtendedSession",
        "Ex2EMPS_12_AutoRackCentering",
        "Ex2EMPS_12_SteeringStart",
        "Ex2EMPS_12_SteeringAngleCheck",
        "Ex2ABS_48_RetrunWait",
        "Ex2ASUS_08_EndExtendedSession",
        "Ex2ABS_41_DriveMotor",
        "Ex2ABS_41_StopMotor",
        "Ex2ABS_44_SendMessage",
        "Ex2EPB_04_SendMessage",
        "Ex2ASUS_13_TestStart",
        "Ex2ASUS_13_TestStop",
        "Ex2ASUS_13_GetHeight",
        "Ex2ASUS_13_GetHeightSec50",
        "Ex2ASUS_13_HeightOffset",
        "Ex2ASUS_13_NormalMode",
        "Ex2ASUS_13_NormalMode005",
        "Ex2ASUS_13_NormalMode008",
        "Ex2VGRS_04_StartLockRelease",
        "Ex2VGRS_04_EndLockRelease",
        "Ex2VGRS_04_StartNeutralCompMode",
        "Ex2VGRS_04_EndNeutralCompMode",
        "Ex2VGRS_04_ClearDTC",
    }
)
ABS48_EXPORTS = frozenset(
    {
        "Ex2ABS_48_VacuumFillingIncomplete",
        "Ex2ABS_48_ConfirmBitInformation",
        "Ex2ABS_48_StartECBProhibitionControl",
        "Ex2ABS_48_StopTheRoutineControl",
        "Ex2ABS_48_StartRearAirBleedingDrive",
        "Ex2ABS_48_StopTheRoutine",
        "Ex2ABS_48_StopTheRoutineTimeOver",
        "Ex2ABS_48_RetrunWait",
        "Ex2ABS_48_ChangeToTheDealerMode",
        "Ex2ABS_48_ChangeToTheNormalMode",
    }
)
SUPPORTED_EXPORTS = ABS48_EXPORTS | frozenset(
    {
        "Ex2PSAABS_01_SendMessage",
        "Ex2PSAABS_02_SendMessage",
        "Ex2PSAABS_03_StartActiveTest",
        "Ex2PSAABS_03_ConfirmStatus",
        "Ex2ABS_41_DIDSupportCheck",
        "Ex2ABS_41_DriveSolenoid",
        "Ex2ABS_32_SupportCheck",
        "Ex2ABS_31_SupportCheck",
        "Ex2ABS_31_RoutineStart",
        "Ex2ABS_30_SendMessage",
        "Ex2ABS_46_SendMessage",
        "Ex2ARS_02_InitCompVal",
        "Ex2ARS_03_SupportCheck",
        "Ex2ARS_03_ActiveTest",
        "Ex2ARS_01_ReturnActuatorCenterPos",
        "Ex2VGRS_04_SupportCheck",
        "Ex2VGRS_04_CheckDTC",
        "Ex2ARS_01_ReadDTCofVGRS",
        "Ex2ARS_01_ReadDTCofARS",
        "Ex2ARS_01_ClearOffSetValue",
        "Ex2ARS_02_ChkVGRSDtc",
        "Ex2ARS_02_ChkARSDtc",
        "Ex2ARS_02_ClrCompVal",
        "Ex2BSM_09_10_19_20_SendMessage",
        "Ex2BSM_11_12_21_22_SendMessage",
        "Ex2AHC_04_SendMessage",
        "Ex24WD_05_SendMessage",
        "Ex24WD_05_WriteHistoryData",
        "Ex24WD_05_SupportCheck",
        "Ex24WD_06_SendMessage",
        "Ex24WD_08_SendMessage",
        "Ex2AWD_04_ReadValues",
        "Ex2TPW_03_SendMessage",
        "Ex2TPW_08_SendMessage",
        "Ex2TPW_06_SendMessage",
        "Ex2TPW_13_SendMessage",
        "Ex2DRS_04_SendMessage",
        "Ex2ARS_05_SendMessage",
        "Ex2ARS_04_SendMessage",
        "Ex2EMPS_13_SendMessage",
        "Ex2ABS4WD_01_SupportCheck",
        "Ex2ABS4WD_01_ChangePreventionMode",
        "Ex2ABS_51_SendMessage",
        "Ex2ABS_21_SupportCheck",
        "Ex2ABS_21_ChangeMode",
        "Ex2ABS_21_CheckSensorStatus",
        "Ex2ABS_18_SupportCheck",
        "Ex2ABS_18_SetNeutralPos",
        "Ex2ABS_17_SupportCheck",
        "Ex2ABS_17_GetABSInfo",
        "Ex2ABS_17_SychronizingABSInfo",
        "Ex2ABS_32_EPBFullReleaseAndCheck",
        "Ex2AWD_04_Overwrite",
        "Ex2BSM_13_14_23_24_SendMessage",
        "Ex2BSM_15_16_25_26_SendMessage",
        "Ex2BSM_01_02_SupportCheck",
        "Ex2BSM_01_02_Mov2TestMode",
        "Ex2BSM_01_02_ChkStilInTestMode",
        "Ex2BSM_01_02_ExitTestMode",
        "Ex2BSM_07_08_SupportCheck",
        "Ex2BSM_07_08_GetAbnormalHistory",
        "Ex2BSM_07_08_ClearAbnormalHistory",
        "Ex2BSM_27_SendMessage",
        "Ex2BSM_28_SendMessage",
        "Ex2BSM_03_04_ActiveTestCon3_5",
        "Ex2BSM_03_04_SupportCheck",
        "Ex2BSM_05_06_SupportCheck",
        "Ex2BSM_05_06_ActiveTest",
        "Ex2BSM_03_04_ActiveTest",
        "Ex24WD_07_SupportCheck",
        "Ex24WD_03_SupportCheck",
        "Ex24WD_03_ChangePreventionMode",
        "Ex24WD_07_BackupMemoryClear1st",
        "Ex24WD_07_BackupMemoryClear2nd",
        "Ex2ABS_29_SupportCheck",
        "Ex2ABS_29_ShiftDealerMode",
        "Ex2ASUS_10_GetStatOfHeightCtrlProhibition",
        "Ex2ASUS_13_NormalMode",
        "Ex2ASUS_13_NormalMode005",
        "Ex2ASUS_13_NormalMode008",
        "Ex2ASUS_13_TestStop",
        "Ex2ASUS_13_SupportCheck",
        "Ex2ASUS_04_SupportCheck",
        "Ex2ASUS_04_ReturnVhight",
        "Ex2ASUS_04_LearnKneeldownVheight",
        "Ex2ASUS_04_CheckReturnedVhight",
        "Ex2ASUS_04_ModifyVhight",
        "Ex2ASUS_05_SupportCheck",
        "Ex2ASUS_05_ModifyVheightDownStart",
        "Ex2ASUS_05_ModifyVheightStop",
        "Ex2ASUS_05_CheckModifiedVheight",
        "Ex2ASUS_05_ModifyVheightTimeOver",
        "Ex2ASUS_05_LearnKneelDownVheight",
        "Ex2ASUS_05_ReturnVheightStart",
        "Ex2ASUS_05_CheckReturnedVheight",
        "Ex2ASUS_06_TheHeightAndTank",
        "Ex2ASUS_07_TheHeightAndTank",
        "Ex2ASUS_06_ConditionCheck",
        "Ex2ASUS_08_StartCompressRaisingCtrl",
        "Ex2ASUS_08_StartTankPressLowCtrl",
        "Ex2ASUS_08_ReadPressureSensor",
        "Ex2ASUS_08_ModeTransEnterHeightCtrlProhibit",
        "Ex2ASUS_07_ConditionCheck",
        "Ex2ASUS_06_LiftRise",
        "Ex2ASUS_06_AirPressure",
        "Ex2ASUS_07_LiftRise",
        "Ex2ASUS_07_AirPressure",
        "Ex2ASUS_13_TestStart",
        "Ex2ASUS_13_GetHeight",
        "Ex2ASUS_13_GetHeightSec50",
        "Ex2ASUS_13_HeightOffset",
        "Ex2VGRS_04_StartLockRelease",
        "Ex2VGRS_04_EndLockRelease",
        "Ex2VGRS_04_StartNeutralCompMode",
        "Ex2VGRS_04_EndNeutralCompMode",
        "Ex2VGRS_04_ClearDTC",
        "Ex2ARS_01_A8SupportCheck",
        "Ex2ARS_02_SupportCheck",
        "Ex2ASUS_10_ChgAndGetStatOfHeightCtrlProhibition",
        "Ex2TPW_07_SupportCheck",
        "Ex2TPW_07_ReadSystemOperationMode",
        "Ex2TPW_07_WriteSystemOperationMode",
        "Ex2EPB_05_SendMessage",
        "Ex2ABS_44_SendMessage",
        "Ex2EPB_04_SendMessage",
        "Ex2EMPS_12_SteeringStart",
        "Ex2ABS_33_SupportCheck",
        "Ex2ABS_33_ShiftDealerMode",
        "Ex2ABS_33_CheckSensorStatus",
        "Ex2ABS_33_ShiftNormalMode",
        "Ex2ABS_34_InitAllMemVal",
        "Ex2EMPS_11_SendMessage",
        "Ex2ASUS_08_EndExtendedSession",
        "Ex2ABS_47_EndExtendedSession",
        "Ex2EMPS_09_ModeTransition",
        "Ex2EMPS_09_SupportCheck",
        "Ex2EMPS_07_ConfirmTheAssistMap",
        "Ex2EMPS_07_ClearTheAssistMap",
        "Ex2DRS_02_StopActiveTest",
        "Ex2DRS_02_SupportCheck",
        "Ex2DRS_02_ReadRadarCruiseData",
        "Ex2DRS_02_ReadModeStatus",
        "Ex2DRS_03_StopActiveTest",
        "Ex2DRS_03_SupportCheck",
        "Ex2DRS_03_ReadRadarCruiseData",
        "Ex2DRS_03_ReadModeStatus",
        "Ex2DRS_03_EndProcess",
        "Ex2EKDSS_01_SendMessage",
        "Ex2EKDSS_02_SendMessage",
        "Ex2ABS_52_ReadBrakePadResidualThickness",
        "Ex2ABS_52_WriteBrakePadResidualThickness",
        "Ex2AHC_03_ReadModeStatus",
        "Ex2AHC_03_SwitchServiceMode",
        "Ex2AHC_03_EndExtendedSession",
        "Ex2EMPS_12_AutoRackCentering",
        "Ex2EMPS_12_ReadRoutineStatus",
        "Ex2EMPS_12_SteeringAngleCheck",
        "Ex2ABS_47_ShiftToDealerMode",
        "Ex2ABS_47_CheckCalibrationStatus",
        "Ex2ABS_47_DIDRIDSupportCheck",
        "Ex2ABS_47_ErrorEndExtendedSession",
        "Ex2ABS_47_ExitEndExtendedSession",
        "Ex2ABS_41_DriveMotor",
        "Ex2ABS_41_StopMotor",
        "Ex2ABS_49_StartSLM2Refresh",
        "Ex2ABS_49_PatternDriveExecutingFlag",
        "Ex2ABS_49_PatternDriveExecutingFlagExit",
        "Ex2ABS_49_PatternDriveExecutingFlagError",
    }
)


UNUSED_WRAPPER_BUFFER_EXPORTS = frozenset(
    {
        "Ex2ABS_33_ShiftDealerMode",
        "Ex2ABS_33_ShiftNormalMode",
        "Ex2ABS_41_DIDSupportCheck",
        "Ex2ABS_41_DriveMotor",
        "Ex2ABS_41_StopMotor",
        "Ex2ABS_47_EndExtendedSession",
        "Ex2ABS_47_ErrorEndExtendedSession",
        "Ex2ABS_47_ExitEndExtendedSession",
        "Ex2ABS_47_ShiftToDealerMode",
        "Ex2ABS_48_ChangeToTheDealerMode",
        "Ex2ABS_48_ChangeToTheNormalMode",
        "Ex2ABS_48_ConfirmBitInformation",
        "Ex2ABS_48_StartECBProhibitionControl",
        "Ex2ABS_48_StartRearAirBleedingDrive",
        "Ex2ABS_48_StopTheRoutine",
        "Ex2ABS_48_StopTheRoutineControl",
        "Ex2ABS_48_StopTheRoutineTimeOver",
        "Ex2ABS_48_VacuumFillingIncomplete",
        "Ex2ABS_49_PatternDriveExecutingFlagError",
        "Ex2ABS_49_PatternDriveExecutingFlagExit",
        "Ex2ABS_49_StartSLM2Refresh",
        "Ex2AHC_03_EndExtendedSession",
        "Ex2ARS_01_ClearOffSetValue",
        "Ex2ARS_01_ReadDTCofARS",
        "Ex2ARS_01_ReadDTCofVGRS",
        "Ex2ARS_02_ChkARSDtc",
        "Ex2ARS_02_ChkVGRSDtc",
        "Ex2ARS_02_ClrCompVal",
        "Ex2ASUS_04_ReturnVhight",
        "Ex2ASUS_05_ModifyVheightTimeOver",
        "Ex2ASUS_05_ReturnVheightStart",
        "Ex2ASUS_06_ConditionCheck",
        "Ex2ASUS_06_TheHeightAndTank",
        "Ex2ASUS_07_ConditionCheck",
        "Ex2ASUS_07_TheHeightAndTank",
        "Ex2ASUS_08_EndExtendedSession",
        "Ex2ASUS_13_NormalMode",
        "Ex2ASUS_13_NormalMode005",
        "Ex2ASUS_13_NormalMode008",
        "Ex2ASUS_13_TestStop",
        "Ex2AWD_04_Overwrite",
        "Ex2BSM_01_02_ExitTestMode",
        "Ex2DRS_02_StopActiveTest",
        "Ex2DRS_03_StopActiveTest",
        "Ex2EMPS_07_ClearTheAssistMap",
        "Ex2EMPS_12_AutoRackCentering",
        "Ex2VGRS_04_CheckDTC",
        "Ex2VGRS_04_ClearDTC",
        "Ex2VGRS_04_EndLockRelease",
        "Ex2VGRS_04_EndNeutralCompMode",
        "Ex2VGRS_04_StartNeutralCompMode",
    }
)


def supports(source_sha256: str, export: str) -> bool:
    return export in {
        SHA_12_TY: TWELVE_EXPORTS,
        SHA_18_TY: SUPPORTED_EXPORTS,
        SHA_PLUS_TY: PLUS_EXPORTS,
    }.get(source_sha256, frozenset())


def _buffer(args: tuple[object, ...], minimum: int) -> bytearray:
    if len(args) != 1 or not isinstance(args[0], bytearray) or len(args[0]) < minimum:
        raise ValueError(
            f"chassis operation requires one mutable {minimum}-byte native buffer"
        )
    return args[0]


def _word(data: bytearray, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 4], "little")


def _bounded_word(data: bytearray, offset: int, maximum: int = 0x1020) -> int:
    value = _word(data, offset)
    if value > maximum:
        raise ValueError("live native buffer length/offset exceeds reply capacity")
    return value


def _put(data: bytearray, offset: int, value: int) -> None:
    data[offset : offset + 4] = value.to_bytes(4, "little")


def _support_record(
    raw: bytes, offsets: tuple[int, ...], identifier: int
) -> tuple[int, bytes]:
    if len(raw) != 0x1020 or len(offsets) != 256:
        raise ValueError("native support snapshot has invalid buffer/table size")
    offset = offsets[identifier & 255]
    if type(offset) is not int or not 0 <= offset <= 0x1020:
        raise ValueError("native support record offset is invalid")
    if offset == 0x1020:
        return 22, b""
    if offset + 2 > 0x1020:
        return 99, b""
    length = raw[offset + 1]
    if offset + 2 + length > 0x1020:
        return 99, b""
    return 0, raw[offset + 2 : offset + 2 + length]


def _support_required(
    raw: bytes, offsets: tuple[int, ...], identifier: int, index: int, mask: int
) -> tuple[int, int]:
    status, payload = _support_record(raw, offsets, identifier)
    if status:
        return status, 0
    position = index - 3
    if (
        len(payload) <= position
        or not payload[position]
        or payload[position] & mask != mask
    ):
        return 22, 0
    return 0, 2 + sum(bool(value) for value in payload[:position])


class ChassisEngine:
    def __init__(self, contract: ChassisContract) -> None:
        self.contract = contract

    @staticmethod
    def _reply(
        comm: TYComm,
        request: bytes,
        minimum: int,
        echo: int,
        *,
        positive_service: bool = True,
    ) -> tuple[int, bytes]:
        status, reply = comm.exchange(request)
        if type(status) is not int or not isinstance(reply, bytes):
            raise TypeError("native exchange must return (int, bytes)")
        if status == 0 and (
            len(reply) < minimum
            or len(reply) > 0x1020
            or (positive_service and reply[0] != (request[0] + 0x40) & 255)
            or reply[1 : 1 + echo] != request[1 : 1 + echo]
        ):
            return 3, reply
        return status, reply

    def _open(self, comm: TYComm) -> int:
        status = comm.initialize(0)
        if not status:
            for field, value in (
                (self.contract.retry_setter, 0),
                (self.contract.pending_setter, 180000),
                (self.contract.retries_setter, 0),
            ):
                comm.configure(field, value)
        return status

    def _initialize(self, comm: TYComm, *, grouped_session: bool = False) -> int:
        status = self._open(comm)
        if not status:
            if grouped_session:
                status = comm.session(3, 1, normal_first=True)
            else:
                status = comm.session(1, 1)
                if not status:
                    status = comm.session(3, 1)
        return status

    @staticmethod
    def _raw(comm: TYComm, request: bytes) -> tuple[int, bytes]:
        status, reply = comm.exchange(request)
        if type(status) is not int or not isinstance(reply, bytes):
            raise TypeError("native exchange must return (int, bytes)")
        return (3, b"") if len(reply) > 0x1020 else (status, reply)

    def _psa31(self, comm: TYComm, rid: int, phase: int, value: int = 0) -> int:
        request = bytes((0x31, rid, phase)) + (
            bytes((value,)) if rid == 0xB4 and phase == 0 else b""
        )
        status, reply = self._raw(comm, request)
        if status:
            return 9006 if reply[:3] == b"\x7f\x31\x22" else status
        if len(reply) != 3 or reply[1] != rid:
            return 3
        if phase == 0:
            return 9006 if reply[2] == 0 else 0
        return {1: 9099, 2: 0, 4: 9006}.get(reply[2], 3)

    def _psa_poll(self, comm: TYComm, rid: int, context: ChassisContext) -> int:
        start = context.ticks()
        while True:
            context.sleep(1000)
            status = self._psa31(comm, rid, 1)
            if status != 9099 or elapsed_ticks(context.ticks(), start) >= 120000:
                return status

    def _psa(
        self, export: str, data: bytearray, comm: TYComm, context: ChassisContext
    ) -> tuple[int, bool]:
        if export in ("Ex2PSAABS_01_SendMessage", "Ex2PSAABS_02_SendMessage"):
            status = comm.initialize(0)
            if export == "Ex2PSAABS_02_SendMessage" or not status:
                context.sleep(1000)
            if status:
                return status, True
            comm.configure(self.contract.legacy_setter, 150)
            rid = 0xBE if export == "Ex2PSAABS_01_SendMessage" else 0xB4
            status = self._psa31(comm, rid, 0)
            if not status:
                status = self._psa_poll(comm, rid, context)
                if not status and rid == 0xB4:
                    status = self._psa31(comm, rid, 0, 255)
                    if not status:
                        status = self._psa_poll(comm, rid, context)
            return status, True
        comm.configure(self.contract.legacy_setter, 150)
        if export == "Ex2PSAABS_03_StartActiveTest":
            status = comm.initialize(0)
            if status:
                return status, False
            context.sleep(1000)
            status, reply = self._raw(comm, b"\x30\xd1" + bytes(data[8:11]))
            if not status:
                if len(reply) != 3 or reply[1] != 0xD1:
                    status = 3
                else:
                    status = 9101 if reply[2] == 0 else 9100 if reply[2] == 1 else 9102
            return status, status != 9100
        start = context.ticks()
        while True:
            context.sleep(1000)
            native, reply = self._raw(comm, b"\x30\xd1\1")
            if reply == b"\x7f\x30\x22":
                status = 9014
            elif not native and len(reply) == 3 and reply[1] == 0xD1:
                status = {1: 9103, 2: 9009, 4: 9013}.get(reply[2], 9102)
            else:
                status = 9102
            if status == 9102 or elapsed_ticks(context.ticks(), start) > _word(
                data, 12
            ):
                context.sleep(1000)
                self._raw(comm, b"\x30\xd1\x11")
                return (9102 if status == 9102 else 9013), True
            if status != 9103:
                return status, True

    def _bsm_read(self, comm: TYComm, did: int) -> tuple[int, bytes]:
        status, reply = self._reply(comm, bytes((0x22, 0x20, did)), 5, 2)
        return status, reply[3:] if not status else b""

    def _bsm15(self, data: bytearray, comm: TYComm, context: ChassisContext) -> int:
        status, payload = self._bsm_read(comm, 0x50)
        if status:
            return status
        length = _word(data, 0x1024)
        if len(payload) != length or data[:2] != b"\x20\x50":
            return 2000
        status, _ = self._reply(
            comm, b"\x2e\x20\x50" + bytes(data[2 : 2 + length]), 3, 2
        )
        if status:
            return status
        context.sleep(100)
        status, payload = self._bsm_read(comm, 0x50)
        if status:
            return status
        if payload != data[2 : 2 + len(payload)]:
            return 2001
        if _word(data, 0x1028) in (0x12DB, 0x12DC):
            return 0
        status, payload = self._bsm_read(comm, 0x52)
        if status:
            return status
        changed = payload[:1] + bytes((payload[1] | 1,)) + payload[2:]
        status, _ = self._reply(comm, b"\x2e\x20\x52" + changed, 3, 2)
        if status:
            return status
        context.sleep(100)
        status, payload = self._bsm_read(comm, 0x52)
        return status or (0 if payload[1] & 1 else 2002)

    @staticmethod
    def _4wd_selector(data: bytearray, phase: int) -> int:
        mode = _word(data, 0)
        if mode == 2001:
            sequence = [4]
        elif mode == 2002:
            sequence = [
                code
                for offset, code in ((40, 4), (48, 6), (64, 0x18), (72, 0x1A))
                if _word(data, offset)
            ]
        elif mode == 2003:
            sequence = [
                code for offset, code in ((56, 0x14), (60, 0x15)) if _word(data, offset)
            ]
        elif mode == 2004:
            sequence = [5]
        elif mode == 2005:
            sequence = [
                code
                for offset, code in (
                    (44, 5),
                    (56, 0x14),
                    (60, 0x15),
                    (68, 0x19),
                    (76, 0x1B),
                )
                if _word(data, offset)
            ]
        elif mode == 2006:
            sequence = [8]
        else:
            sequence = []
        code = sequence[phase - 1] if phase <= len(sequence) else 0
        return 0 if code == 0x15 and _word(data, 32) else code

    def _4wd_start(self, comm: TYComm, data: bytearray, code: int) -> int:
        rid = 5 if _word(data, 32) else 9 if _word(data, 36) else 0
        return self._reply(comm, bytes((0x31, 1, 0x11, rid, code)), 4, 3)[0]

    def _4wd_poll(
        self, comm: TYComm, data: bytearray, code: int, context: ChassisContext
    ) -> int:
        short = bool(_word(data, 32))
        rid = 5 if short else 9
        if _word(data, 76):
            minimum = 0x2A if short else 0x3C
        elif _word(data, 72):
            minimum = 0x28 if short else 0x3A
        elif _word(data, 68):
            minimum = 0x26 if short else 0x38
        else:
            minimum = (
                (0x24 if _word(data, 64) else 0x22)
                if short
                else (0x36 if _word(data, 64) else 0x30)
            )
        offsets = (
            {
                4: 11,
                5: 13,
                6: 15,
                7: 17,
                8: 19,
                0x14: 31,
                0x18: 35,
                0x19: 37,
                0x1A: 39,
                0x1B: 41,
            }
            if short
            else {
                4: 13,
                5: 15,
                6: 17,
                7: 19,
                8: 21,
                0x14: 45,
                0x15: 47,
                0x18: 53,
                0x19: 55,
                0x1A: 57,
                0x1B: 59,
            }
        )
        while True:
            status, reply = self._reply(comm, bytes((0x31, 3, 0x11, rid)), minimum, 3)
            if status:
                return status
            value = (
                reply[offsets[code]]
                if code in offsets and len(reply) > offsets[code]
                else 0
            )
            if value != 1:
                return 0 if value == 2 else 3
            if _word(data, 28) or context.is_cancelled():
                return 1001

    def _4wd_support(self, comm: TYComm, data: bytearray) -> int:
        status, reply = self._reply(comm, b"\x31\1\x10\1", 36, 3)
        if status or len(reply) != 36:
            return status or 3
        if not reply[6] & 0x40:
            return 1003
        _put(data, 32, 0)
        _put(data, 36, 0)
        status, reply = self._reply(comm, b"\x31\1\x11\0", 36, 3)
        if status or len(reply) != 36:
            return status or 3
        _put(data, 32, int(bool(reply[4] & 8)))
        _put(data, 36, int(bool(reply[5] & 128)))
        if not (_word(data, 32) or _word(data, 36)):
            return 1003
        status, reply = self._reply(comm, b"\x22\1\1", 35, 2)
        if status or len(reply) != 35:
            return status or 3
        if not reply[7] & 0x20:
            return 1003
        data[40:80] = bytes(40)
        status, reply = self._reply(comm, b"\x22\x22\0", 35, 2)
        if status or len(reply) != 35:
            return status or 3
        for index, (offset, mask) in enumerate(
            (
                (3, 16),
                (3, 8),
                (3, 4),
                (3, 1),
                (5, 16),
                (5, 8),
                (5, 1),
                (6, 128),
                (6, 64),
                (6, 32),
            )
        ):
            _put(data, 40 + index * 4, int(bool(reply[offset] & mask)))
        return 0 if any(_word(data, offset) for offset in range(40, 80, 4)) else 1003

    def _brake_support(self, comm: TYComm, *, positive_service: bool = True) -> int:
        # 9b350/88ff0 share five query predicates, not their status/restore policy.
        for request, minimum, offset, mask in (
            (b"\x22\1\1", 6, 5, 128),
            (b"\x22\x10\0", 9, 8, 8),
            (b"\x22\x10\x2d", 12, 11, 8),
            (b"\x31\1\x10\1", 7, 6, 0x40),
            (b"\x31\1\x11\0", 6, 5, 0x10),
        ):
            status, reply = self._reply(
                comm,
                request,
                minimum,
                2 if request[0] == 0x22 else 3,
                positive_service=positive_service,
            )
            if status:
                return status
            if reply[offset] & mask != mask:
                return 3
        return 0

    def _abs29(self, export: str, comm: TYComm, context: ChassisContext) -> int:
        activated = False
        try:
            status = comm.initialize(0)
            if status:
                return status
            activated = True
            for field, value in (
                (self.contract.retry_setter, 0),
                (self.contract.pending_setter, 180000),
                (self.contract.retries_setter, 0),
            ):
                comm.configure(field, value)
            status = self._normal(comm)
            if not status:
                status = comm.session(3, 1)
            if status:
                return status
            if export == "Ex2ABS_29_SupportCheck":
                status = self._brake_support(comm, positive_service=False)
                normal = self._normal(comm)
                return 3 if status else normal
            status, _ = self._reply(
                comm,
                b"\x31\1\x11\x0c\1",
                4,
                3,
                positive_service=False,
            )
            if not status:
                context.sleep(4000)
                status, reply = self._reply(
                    comm,
                    b"\x22\x10\x2d",
                    13,
                    2,
                    positive_service=False,
                )
                if not status and not reply[12] & 8:
                    status = 3
            self._normal(comm)
            return 1006 if status else 0
        except BaseException:
            if activated:
                self._cleanup_normal_after_host_fault(comm)
            raise

    @staticmethod
    def _asus10_read(
        comm: TYComm, data: bytearray, identifier: int | None = None
    ) -> int:
        request = bytes((0x22, 0x21, data[1] if identifier is None else identifier))
        status, reply = comm.exchange(request)
        if type(status) is not int or not isinstance(reply, bytes):
            raise TypeError("native exchange must return (int, bytes)")
        if status:
            return status
        if len(reply) > 0x1020:
            return 3
        # 84e50 evaluates the data byte even when length/echo set error3.
        status = 0 if len(reply) >= 4 and reply[1:3] == request[1:3] else 3
        value = reply[3] if len(reply) > 3 else 0
        if value not in (0, 1):
            return 1001
        data[0] = value
        return status

    def _asus10(
        self, export: str, data: bytearray, context: ChassisContext, comm: TYComm
    ) -> int:
        changing = export == "Ex2ASUS_10_ChgAndGetStatOfHeightCtrlProhibition"
        status = self._initialize(comm) if changing else self._open(comm)
        if status:
            return status
        identifier = None if self.contract.asus10_discover else 1
        if changing:
            try:
                if data[0] < 2:
                    request = bytes(
                        (
                            0x2E,
                            0x21,
                            data[1] if identifier is None else identifier,
                            data[0] ^ 1,
                        )
                    )
                    status, reply = self._reply(
                        comm, request, 3, 2, positive_service=False
                    )
                    if not status and len(reply) != 3:
                        status = 3
                else:
                    status = 3
                if not status:
                    context.sleep(100)
                    status = self._asus10_read(comm, data, identifier)
                return self._normal(comm) or status
            except BaseException:
                self._cleanup_normal_after_host_fault(comm)
                raise
        if not self.contract.asus10_discover:
            return self._asus10_read(comm, data, identifier)
        status, reply = self._reply(comm, b"\x22\1\1", 35, 2, positive_service=False)
        if status:
            return status
        if not reply[7] & 0x40:
            return 99
        status, reply = self._reply(comm, b"\x22\x21\0", 35, 2, positive_service=False)
        if status:
            return status
        if reply[3] & 128:
            data[1] = 1
        elif reply[3] & 0x10:
            data[1] = 4
        else:
            return 99
        return self._asus10_read(comm, data, identifier)

    def _tpw07(self, export: str, data: bytearray, comm: TYComm) -> int:
        if export == "Ex2TPW_07_ReadSystemOperationMode":
            _put(data, 0, 1)
        status = self._initialize(comm)
        if status:
            return status
        if export == "Ex2TPW_07_SupportCheck":
            status, reply = self._reply(comm, b"\x22\1\1", 8, 2)
            if not status and reply[7] & 128:
                status, reply = self._reply(comm, b"\x22\x20\0", 8, 2)
                if not status and reply[3] & 128 and reply[7] & 8:
                    status, reply = self._reply(comm, b"\x22\x20\x25", 5, 2)
                    if not status:
                        data[0x102C : 0x102C + len(reply)] = reply
                        _put(data, 8, len(reply))
                        if not reply[3] & 128:
                            status = 3
                elif not status:
                    status = 3
            elif not status:
                status = 3
        elif export == "Ex2TPW_07_ReadSystemOperationMode":
            status, reply = self._reply(comm, b"\x22\x20\1", 4, 2)
            if not status:
                data[12 : 12 + len(reply)] = reply
                _put(data, 4, len(reply))
                if reply[3] & 3 == 3:
                    _put(data, 0, 0)
        else:

            def write_block(
                offset: int, length: int, mask: int, byte_index: int, set_bits: bool
            ) -> int:
                if not byte_index + 1 <= length <= 0x1020:
                    raise ValueError(
                        "live TPW saved reply length exceeds native bounds"
                    )
                request = bytearray(b"\x2e" + data[offset + 1 : offset + length])
                request[byte_index] = (
                    request[byte_index] | mask
                    if set_bits
                    else request[byte_index] & (255 ^ mask)
                )
                return self._reply(comm, bytes(request), 3, 2)[0]

            action = _word(data, 0)
            status = 0
            if action == 0:
                status = write_block(12, _word(data, 4), 3, 3, False)
            if not status:
                status = write_block(0x102C, _word(data, 8), 128, 4, action != 0)
                if not status and action == 1:
                    status = write_block(12, _word(data, 4), 3, 3, True)
            self._normal(comm)
            return status
        normal = self._normal(comm)
        return normal or status

    @staticmethod
    def _abs33_sensors(data: bytearray, reply: bytes) -> bool:
        active = False
        masks = [(3, 128 >> index) for index in range(8)] + [
            (5, 0x20),
            (5, 0x10),
            (5, 1),
        ]
        for index, (offset, mask) in enumerate(masks):
            data[index * 2] = int(bool(reply[offset] & mask))
            data[index * 2 + 1] = int(bool(reply[offset + 1] & mask))
            active = active or bool(data[index * 2])
        return active

    def _abs33_restore(self, comm: TYComm, minimum: int = 4) -> None:
        self._reply(comm, b"\x31\x01\x11\x0c\0", minimum, 3)
        self._normal(comm)

    def _abs33_support(self, comm: TYComm, data: bytearray) -> int:
        checks = (
            (b"\x22\x01\x01", 6, 5, 128),
            (b"\x22\x10\0", 9, 8, 9),
            (b"\x22\x10\x2d", 12, 11, 8),
        )
        status = 0
        for request, minimum, offset, mask in checks:
            status, reply = self._reply(comm, request, minimum, 2)
            if status or reply[offset] & mask != mask:
                status = 3
                break
        if not status:
            status, reply = self._reply(comm, b"\x22\x10\x30", 7, 2)
            if not status and not self._abs33_sensors(data, reply):
                status = 3
        if not status:
            for request, minimum, offset, mask in (
                (b"\x31\x01\x10\1", 7, 6, 0x40),
                (b"\x31\x01\x11\0", 6, 5, 0x10),
            ):
                status, reply = self._reply(comm, request, minimum, 3)
                if status or reply[offset] & mask != mask:
                    status = 3
                    break
        normal = self._normal(comm)
        return 3 if status or normal else 0

    def _abs48(
        self, export: str, context: ChassisContext, comm: TYComm
    ) -> tuple[int, bool]:
        # Each boolean is literal worker ownership: successful starts retain it.
        stops = {
            "Ex2ABS_48_StopTheRoutineControl": (b"\x31\x02\x11\x35", 0),
            "Ex2ABS_48_StopTheRoutine": (b"\x31\x02\x11\x69", 0),
            "Ex2ABS_48_StopTheRoutineTimeOver": (b"\x31\x02\x11\x69", 3),
            "Ex2ABS_48_ChangeToTheNormalMode": (b"\x31\x01\x11\x0c\0", None),
        }
        if export in stops:
            request, fixed = stops[export]
            status, _ = self._reply(comm, request, 4, 3)
            self._normal(comm)
            return status if fixed is None else fixed, True
        status = self._initialize(comm)
        if status:
            return status, True
        if export == "Ex2ABS_48_VacuumFillingIncomplete":
            status, reply = self._reply(comm, b"\x22\x20\x02", 5, 2)
            if not status:
                payload = reply[3:]
                # b8c10 ASM preserves returned payload except byte1 is forced 0x80.
                request = b"\x2e\x20\x02" + payload[:1] + b"\x80" + payload[2:]
                status, _ = self._reply(comm, request, 3, 2)
                if not status:
                    context.sleep(1000)
                    status, reply = self._reply(comm, b"\x22\x20\x02", 5, 2)
                    if not status and not reply[4] & 128:
                        status = 3
            self._normal(comm)
            return status, True
        if export == "Ex2ABS_48_ConfirmBitInformation":
            status, reply = self._reply(comm, b"\x22\x20\x02", 4, 2)
            if not status and reply[3] & 128:
                return self._normal(comm), True
            self._normal(comm)
            return status or 3, True
        requests = {
            "Ex2ABS_48_StartECBProhibitionControl": (
                b"\x31\x01\x11\x35",
                b"\x31\x02\x11\x35",
                0,
            ),
            "Ex2ABS_48_StartRearAirBleedingDrive": (
                b"\x31\x01\x11\x69",
                b"\x31\x02\x11\x69",
                3000,
            ),
            "Ex2ABS_48_ChangeToTheDealerMode": (
                b"\x31\x01\x11\x0c\1",
                b"\x31\x01\x11\x0c\0",
                0,
            ),
        }
        request, undo, delay = requests[export]
        status, _ = self._reply(comm, request, 4, 3)
        if not status:
            return 0, False
        if delay:
            context.sleep(delay)
        self._reply(comm, undo, 4, 3)
        self._normal(comm)
        if export == "Ex2ABS_48_ChangeToTheDealerMode":
            status = 1002
        return status, True

    def _abs47_support(self, comm: TYComm, data: bytearray) -> int:
        status = self._initialize(comm)
        if status:
            return status
        for request, minimum, exact, masks in (
            (b"\x22\1\1", 35, True, ((5, 128),)),
            (b"\x22\x10\0", 35, True, ((8, 8), (25, 16))),
            (b"\x22\x10\x2d", 12, False, ((11, 8),)),
            (b"\x22\x10\xb4", 5, False, ()),
            (b"\x31\1\x10\1", 36, True, ((6, 64),)),
            (b"\x31\1\x11\0", 36, True, ((5, 16),)),
        ):
            status, reply = self._reply(comm, request, minimum, len(request) - 1)
            if not status and (
                (exact and len(reply) != minimum)
                or any(reply[offset] & mask != mask for offset, mask in masks)
            ):
                status = 3
            if not status and request == b"\x22\x10\xb4":
                if not reply[3] & 0xFE:
                    status = 3
                else:
                    for index in range(7):
                        _put(data, 4 + 12 * index, int(bool(reply[3] & (128 >> index))))
            if status:
                self._normal(comm)
                return status
        return self._normal(comm)

    def _abs31(
        self, export: str, comm: TYComm, data: bytearray, context: ChassisContext
    ) -> int:
        support = export.endswith("SupportCheck")
        if support:
            _put(data, 4, 0)
        status = self._initialize(comm)
        if status:
            return status
        if support:
            selected = False
            for request, minimum, masks in (
                (b"\x22\1\1", 6, ((5, 128),)),
                (b"\x22\x10\0", 12, ((11, 12),)),
                (b"\x22\x10\x46", 4, ()),
                (b"\x31\1\x10\1", 7, ((6, 64),)),
                (b"\x31\1\x11\0", 7, ((6, 8),)),
            ):
                status, reply = self._reply(comm, request, minimum, len(request) - 1)
                if status or any(
                    reply[offset] & mask != mask for offset, mask in masks
                ):
                    self._normal(comm)
                    return 3
                if request == b"\x22\x10\x46":
                    selected = bool(reply[3] & 2)
            normal = self._normal(comm)
            observed = bool(reply[5] & 8)
            if normal or (selected != observed):
                return 3
            if not selected:
                _put(data, 4, 1)
            return 0
        action = _word(data, 0)
        rid, value, did, delay, expected = {
            1: (0x110D, 0, 0x1046, 3000, 0),
            2: (0x110D, 1, 0x1046, 3000, 2),
            3: (0x1115, 1, 0x1045, 4000, 0),
        }.get(action, (0, 0, 0, 0, 0))
        request = b"\x31\1" + rid.to_bytes(2, "big") + bytes((value,))
        status, _ = self._reply(comm, request, 4, 3)
        failed = bool(status)
        if not failed:
            context.sleep(delay)
            status, reply = self._reply(comm, b"\x22" + did.to_bytes(2, "big"), 5, 2)
            failed = bool(status)
            if not failed and action in (1, 2):
                failed = reply[4] & 2 != expected
            elif not failed and action == 3 and reply[3:5] != b"\0\0":
                context.sleep(5000)
                status, _ = self._reply(comm, request, 4, 3)
                failed = bool(status)
                if not failed:
                    context.sleep(4000)
                    status, reply = self._reply(comm, b"\x22\x10\x45", 5, 2)
                    failed = bool(status) or reply[3:5] != b"\0\0"
        self._normal(comm)
        return 3 if failed else 0

    def _abs49(
        self, export: str, data: bytearray, context: ChassisContext, comm: TYComm
    ) -> int:
        stop = b"\x31\x02\x11\x66"
        if export == "Ex2ABS_49_StartSLM2Refresh":
            status = self._initialize(comm)
            if status:
                return status
            status, _ = self._reply(comm, b"\x31\x01\x11\x66\x02", 4, 3)
            if not status:
                return 0
            self._reply(comm, stop, 4, 3)
            self._normal(comm)
            comm.finalize()
            return 1004
        if export in (
            "Ex2ABS_49_PatternDriveExecutingFlagExit",
            "Ex2ABS_49_PatternDriveExecutingFlagError",
        ):
            self._reply(comm, stop, 4, 3)
            self._normal(comm)
            comm.finalize()
            return 1001 if export.endswith("Exit") else 1004
        while True:
            if _word(data, 0) or context.is_cancelled():
                return 1000  # b8e65 retains the live manager on cancellation.
            if _word(data, 4):
                return 1003
            context.sleep(1000)
            status, reply = self._reply(comm, b"\x22\x10\x2d", 17, 2)
            if status:
                self._reply(comm, stop, 4, 3)
                break
            if not reply[16] & 0x40:
                break
        self._normal(comm)
        comm.finalize()
        return status

    @staticmethod
    def _normal(comm: TYComm) -> int:
        return comm.session(1, 1)

    @staticmethod
    def _cleanup_normal_after_host_fault(comm: TYComm) -> None:
        with suppress(BaseException):
            comm.cleanup_session(1, 1)

    def _ahc_read(self, comm: TYComm, data: bytearray) -> int:
        status, reply = self._reply(comm, b"\x22\x11\xa6", 5, 2)
        if not status:
            _put(data, 0, int(bool(reply[4] & 0x10)))
        return status

    def _bsm_active(
        self, export: str, comm: TYComm, data: bytearray, context: ChassisContext
    ) -> int:
        older = export.startswith("Ex2BSM_03_04_")
        conditional = export.endswith("ActiveTestCon3_5")
        start_offset, poll_offset, result_offset, output_offset, rid_offset = (
            (12, 20, 16, 24, 28) if older else (8, 16, 12, 20, 24)
        )
        status = comm.initialize(0)
        if status:
            return status
        comm.configure(self.contract.legacy_setter, 150)

        def angle() -> tuple[int, bytes]:
            status, reply = self._raw(comm, b"\x21\x68")
            if status:
                return status, b""
            if len(reply) != _word(data, 4) or len(reply) < 2 or reply[1] != 0x68:
                return 3, b""
            offset = _bounded_word(data, 20, 0x101D) + 1
            return 0, reply.ljust(0x1020, b"\0")[offset : offset + 2]

        before = b""
        if conditional:
            status, before = angle()
            if status:
                return status
        length = _bounded_word(data, start_offset)
        request = (bytes((0x30, data[rid_offset], 0, 128)) + bytes(max(0, length - 4)))[
            :length
        ]
        status, reply = self._raw(comm, request)
        if status or len(reply) != 2 or reply[1] != data[rid_offset]:
            return 9001
        started = context.ticks()
        while True:
            status, reply = self._raw(comm, b"\x21\x68")
            if not status:
                if len(reply) != _word(data, 4) or len(reply) < 2 or reply[1] != 0x68:
                    status = 3
                else:
                    padded = reply.ljust(0x1020, b"\0")
                    status = (
                        9000
                        if padded[_bounded_word(data, poll_offset, 0x101F)] & 128
                        else 9001
                    )
            if status == 9000:
                if conditional:
                    status, after = angle()
                    if not status and (
                        before == after
                        or not -500 < int.from_bytes(after, "big", signed=True) < 500
                    ):
                        status = 9001
                    break
                action = _word(data, 32) if older else 1
                if older and action not in (1, 2):
                    break
                did = 0x6B if action == 2 else 0x7B
                status, reply = self._raw(comm, bytes((0x21, did)))
                if not status:
                    if (
                        len(reply) != _word(data, 8 if action == 2 else 0)
                        or len(reply) < 2
                        or reply[1] != did
                    ):
                        status = 3
                    elif action == 2:
                        if not reply.ljust(3, b"\0")[2] & 32:
                            status = 9001
                    else:
                        offset = _bounded_word(data, result_offset, 0x101C)
                        padded = reply.ljust(0x1020, b"\0")
                        data[output_offset : output_offset + 2] = padded[
                            offset : offset + 2
                        ][::-1]
                        if older or _word(data, 28) == 1:
                            data[output_offset + 2 : output_offset + 4] = padded[
                                offset + 2 : offset + 4
                            ][::-1]
                break
            if status != 9001 or elapsed_ticks(context.ticks(), started) > 5000:
                break
            context.sleep(500)
        self._raw(comm, b"\x30")
        return status

    @staticmethod
    def _memory(context: ChassisContext) -> NativeMemoryArena:
        memory = context.native_memory
        if not isinstance(memory, NativeMemoryArena):
            raise TYSourceError(
                "native pointer body requires its actual bounded memory arena"
            )
        memory.assert_owner(context.module_sha256, context.native_memory_owner)
        return memory

    def _awd04_history(
        self, comm: TYComm, data: bytearray, context: ChassisContext
    ) -> int:
        memory = self._memory(context)
        previous = _word(data, 36)
        if previous:
            memory.free(previous)
            _put(data, 36, 0)
        _put(data, 32, 0)
        found = False
        for number in range(1, 28):
            identifier = number if number < 10 else number + 6
            status, reply = self._raw(comm, bytes((0x22, 0x22, identifier)))
            if status or len(reply) < 3 or reply[1:3] != bytes((0x22, identifier)):
                continue
            old_length = _word(data, 32)
            size = len(reply) + 1
            pointer = _word(data, 36)
            pointer = (
                memory.realloc(pointer, old_length + size)
                if pointer
                else memory.alloc(size)
            )
            _put(data, 36, pointer)
            memory.write(
                pointer + old_length,
                reply[1:3] + (len(reply) - 3).to_bytes(2, "little") + reply[3:],
            )
            _put(data, 32, old_length + size)
            found = True
        return 0 if found else 1015

    def _awd04(self, comm: TYComm, data: bytearray, context: ChassisContext) -> int:
        data[:32] = bytes(32)
        _put(data, 40, 0)
        data[44] = 0
        status = self._open(comm)
        if status:
            return status
        status = self._normal(comm)
        if not status:
            status = comm.session(3, 1)
        if status:
            return 1001

        def read(identifier: int, exact: int | None = None) -> tuple[int, bytes]:
            status, reply = self._raw(comm, b"\x22" + identifier.to_bytes(2, "big"))
            if not status and (
                len(reply) < 3
                or reply[1:3] != identifier.to_bytes(2, "big")
                or (exact is not None and len(reply) != exact)
            ):
                status = 3
            return status, reply[3:]

        status, support = read(0x0101, 35)
        capacity = not status and bool(support[2] & 0x80)
        system = not status and bool(support[4] & 0x80)
        values = False
        if not status and system:
            status, supported = read(0x2000, 35)
            values = not status and bool(supported[0] & 0x40)
            if not status and capacity:
                status, supported = read(0x1000, 35)
                _put(data, 40, int(not status and bool(supported[3] & 0x40)))
                if not status and _word(data, 40):
                    status, result = read(0x101A)
                    if not status and not result:
                        status = 3
                    if not status:
                        data[44] = result[0]
        if status:
            self._normal(comm)
            return 1022
        if values:
            status, result = read(0x2002)
            if not status and len(result) < 16:
                status = 3
            if not status:
                data[:16] = result[:16]
                if not _word(data, 40) or data[44] in (1, 4):
                    status, result = read(0x2003)
                    if not status and len(result) < 16:
                        status = 3
                    if not status:
                        data[16:32] = result[:16]
            if status:
                return 1001 if self._normal(comm) else 1022
        history = self._awd04_history(comm, data, context)
        if history == 1015 and not values:
            self._normal(comm)
            return 1015
        normal = self._normal(comm)
        return 1001 if normal else 0 if values else 1023

    def _tpw03_support(
        self,
        comm: TYComm,
        data: bytearray,
        context: ChassisContext,
        kind: int,
        base: int,
        count: int,
    ) -> int:
        memory = self._memory(context)
        status, raw, offsets = comm.support_snapshot(kind)
        if status:
            return status
        for number in range(count):
            descriptor = base + 20 * number
            masks = _bounded_word(data, descriptor + 8)
            for index in reversed(range(masks)):
                mask = memory.read(_word(data, descriptor + 4) + index, 1)[0]
                status, selected = _support_required(
                    raw,
                    offsets,
                    data[descriptor],
                    data[descriptor + 1] + 3 + index,
                    mask,
                )
                if status:
                    return status
                _put(data, descriptor + 12, selected)
            status, payload = _support_record(raw, offsets, data[descriptor])
            if status:
                return status
            selected_count = sum(bool(value) for value in payload)
            _put(data, descriptor + 16, selected_count)
            if not selected_count:
                return 22
        return 0

    def _tpw03_read(
        self,
        comm: TYComm,
        data: bytearray,
        context: ChassisContext,
        descriptor: int,
        capacity: int,
    ) -> tuple[int, bytes]:
        memory = self._memory(context)
        masks = _bounded_word(data, descriptor + 8, capacity)
        selected = _bounded_word(data, descriptor + 12)
        if selected + masks > 0x1020:
            raise ValueError("native TPW selected span exceeds reply capacity")
        count = _bounded_word(data, descriptor + 16, 0x101E)
        status, reply = self._raw(comm, bytes((0x21, data[descriptor])))
        padded = reply.ljust(0x1020, b"\0")
        if status == 0 and (len(reply) != count + 2 or padded[1] != data[descriptor]):
            status = 3
        if status:
            return status, b""
        mask = memory.read(_word(data, descriptor + 4), masks) if masks else b""
        return 0, bytes(padded[selected + i] & mask[i] for i in range(masks))

    def _tpw03(self, comm: TYComm, data: bytearray, context: ChassisContext) -> int:
        status = comm.initialize(0)
        if status:
            return status
        comm.configure(self.contract.legacy_setter, 150)
        action = _word(data, 0x20)
        if action == 0:
            status = self._tpw03_support(comm, data, context, 1, 0x24, 7)
            return status or self._tpw03_support(comm, data, context, 3, 0xB0, 1)
        if action == 1:
            status, state = self._tpw03_read(comm, data, context, 0x24, 1)
            if status:
                return 9007
            count = 0
            for index in range(5):
                descriptor = 0x38 + 20 * index
                if data[descriptor] == 0x13 and state.ljust(1, b"\0")[0] == 0x80:
                    break
                status, value = self._tpw03_read(comm, data, context, descriptor, 5)
                if status:
                    return 9007
                data[index * 5 : index * 5 + len(value)] = value
                count += 1
            _put(data, 0x1C, count)
            status, mapping = self._tpw03_read(comm, data, context, 0x9C, 5)
            if status:
                return 9007
            mapping = mapping.ljust(5, b"\0")
            for index in range(count):
                if mapping[index] not in (0, 1, 2, 3, 4, 5, 7):
                    return 9007
                data[4 + index * 5] = mapping[index]
            return 0
        if action == 2:
            count = _bounded_word(data, 0xC0, 0x101E)
            request = (b"\x3b\x36" + bytes(data[4 + i * 5] for i in range(5))).ljust(
                0x1020, b"\0"
            )[: count + 2]
            status, reply = self._raw(comm, request)
            if status == 0 and (len(reply) != 2 or reply[1] != 0x36):
                status = 3
            return 9007 if status else 0
        return 0

    def _4wd05_history(
        self, comm: TYComm, data: bytearray, context: ChassisContext
    ) -> None:
        memory = self._memory(context)
        offset = 0
        while offset < int.from_bytes(data[0x54:0x56], "little"):
            pointer = _word(data, 0x50)
            declared = int.from_bytes(data[0x54:0x56], "little")
            if offset + 4 > declared:
                raise ValueError("native history header exceeds declared UI span")
            header = memory.read(pointer + offset, 4)
            size = int.from_bytes(header[2:4], "little")
            if size > 0x101D or offset + 4 + size > declared:
                raise ValueError(
                    "native history record exceeds bounded diagnostic span"
                )
            payload = memory.read(pointer + offset + 4, size)
            # Both native callers deliberately discard every record-write status.
            self._raw(comm, b"\x2e" + header[:2] + payload)
            offset += 4 + size

    def _4wd05_write_history(
        self, comm: TYComm, data: bytearray, context: ChassisContext
    ) -> int:
        self._memory(context)
        status = self._initialize(comm)
        if not status:
            self._4wd05_history(comm, data, context)
            self._normal(comm)
        return status

    def _4wd05_write_values(
        self, comm: TYComm, data: bytearray, context: ChassisContext
    ) -> int:
        def write(identifier: int, payload: bytes) -> int:
            request = b"\x2e" + identifier.to_bytes(2, "big") + payload
            status, reply = self._raw(comm, request)
            return status or (
                0 if len(reply) >= 3 and reply[1:3] == request[1:3] else 3
            )

        action = _word(data, 4)
        if action in (10, 11):
            identifier = 0x2002 if action == 10 else 0x2003
            status = write(identifier, bytes(data[8:24]))
            if not status:
                status = write(
                    0x2003 if action == 10 else 0x2002, b"\xff" * 15 + b"\xf7"
                )
        else:
            status = write(0x2002, bytes(data[8:24])) if data[0] != 2 else 0
            if (
                not status
                and not (data[0] in (1, 5) or (_word(data, 0x48) and data[0] == 6))
                and _word(data, 0x38)
                and _word(data, 0x2C)
            ):
                status = write(0x2003, bytes(data[0x1C:0x2C]))
        if status:
            return status
        if data[0] in (4, 6):
            self._4wd05_history(comm, data, context)
        context.sleep(1000)
        status, reply = self._raw(comm, b"\xab\1")
        if status:
            return status
        if len(reply) < 2 or reply[1] != 1:
            return 3
        padded = reply + b"\0"
        if any(
            padded[i : i + 2] in (b"\x26\x18", b"\x26\x19", b"\x26\x3d")
            for i in range(0, len(reply), 2)
        ):
            return 2223
        for identifier, output in ((0x2002, 8), (0x2003, 0x1C)):
            if identifier == 0x2003 and not _word(data, 0x38):
                break
            status, payload = self._bsm_multi_read(comm, identifier)
            if not status and len(payload) < 16:
                status = 3
            if status:
                return status
            data[output : output + 16] = payload[:16]
        return 0

    def _4wd05(
        self, comm: TYComm, data: bytearray, context: ChassisContext
    ) -> tuple[int, bool]:
        if data[1] == 1:
            data[1] = 0
            status = self._initialize(comm)
            if status:
                data[2] = 1
                return status, True
        action = _word(data, 4)
        if action in range(8):
            if action in (0, 1):
                low = 2
            elif action in (4, 5):
                low = 3
            else:
                low = 5 if _word(data, 0x3C) else 9 if _word(data, 0x40) else 0
            if action in (0, 2, 4, 6):
                payload = bytes((1 if action == 2 else 2,)) if action in (2, 6) else b""
                status = self._ahc04_routine(comm, 1, low, payload)[0]
                if not status:
                    status = 6022
            else:
                index = (
                    (5 if low == 5 else 7)
                    if action == 3
                    else (7 if low == 5 else 9)
                    if action == 7
                    else 4
                )
                while True:
                    context.sleep(200)
                    status, payload = self._ahc04_routine(
                        comm, 3, low, output=index - 3
                    )
                    if status:
                        break
                    if data[0x30]:
                        break
                    if payload[index - 4] != 1:
                        status = 0 if payload[index - 4] == 2 else 3
                        break
                if status:
                    status = 2223
        elif action in (8, 10, 11):
            data[2] = 1
            status = self._4wd05_write_values(comm, data, context)
            if not status:
                status = 8008
        else:
            data[0x30] = 1
            status = 0
        if status in (0, 6022) and data[0x30] != 1:
            return status, data[2] == 1
        normal = self._normal(comm)
        data[2] = 1
        return normal or status, True

    def _bsm_multi_read(self, comm: TYComm, identifier: int) -> tuple[int, bytes]:
        request = b"\x22" + identifier.to_bytes(2, "big")
        status, reply = self._raw(comm, request)
        if not status and (len(reply) < 4 or reply[1:3] != request[1:3]):
            status = 3
        return status, reply[3:] if not status else b""

    def _bsm_multi_select(self, comm: TYComm, channel: int) -> int:
        comm.configure_target(0x750, channel, 0, 0, 0)
        status = self._open(comm)
        return 1999 if status else comm.session(3, 1, normal_first=True)

    def _bsm_multi_toggle(
        self, comm: TYComm, data: bytearray, older: bool, enable: bool
    ) -> int:
        flag, start = (22, 23) if older else (21, 22)
        failures = False
        channels = ([(15, 0x0204, 32)] if data[flag] else []) + [
            (channel, 0x2055, 1)
            for channel in bytes(data[start : start + 3]).split(b"\0", 1)[0]
        ]
        for index, (channel, identifier, mask) in enumerate(channels):
            status = self._bsm_multi_select(comm, channel)
            if not status:
                status, payload = self._bsm_multi_read(comm, identifier)
                if not status and bool(payload.ljust(2, b"\0")[1] & mask) != enable:
                    length = len(payload)
                    changed = bytearray(payload.ljust(2, b"\0"))
                    changed[1] = (changed[1] | mask) if enable else (changed[1] & ~mask)
                    request = (
                        b"\x2e"
                        + identifier.to_bytes(2, "big")
                        + bytes(changed[:length])
                    )
                    status, reply = self._raw(comm, request)
                    if not status and reply.ljust(3, b"\0")[1:3] != request[1:3]:
                        status = 3
                    if not status:
                        status, payload = self._bsm_multi_read(comm, identifier)
                        if (
                            not status
                            and bool(payload.ljust(2, b"\0")[1] & mask) != enable
                        ):
                            status = 3
            if status != 1999:
                comm.session(1, 1, stop_on_error=True)
            comm.finalize()
            if status:
                if enable:
                    # Source does not roll back a failing global0f pre-pass;
                    # selected ECU failures roll back every selected ECU.
                    if not (index == 0 and data[flag]):
                        self._bsm_multi_toggle(comm, data, older, False)
                    return status
                failures = True
        return 3 if failures else 0

    def _bsm_multi_support(self, comm: TYComm, data: bytearray, older: bool) -> int:
        status = comm.session(3, 1, normal_first=True)
        if not status:
            checks = (
                [(0x2000, 10, 8), (0x2055, 0, 1)]
                if older
                else [(0x0101, 4, 128), (0x2000, 10, 8), (0x2055, 0, 1)]
            )
            accepted = True
            for identifier, index, mask in checks:
                status, payload = self._bsm_multi_read(comm, identifier)
                if status or not payload.ljust(index + 1, b"\0")[index] & mask:
                    accepted = False
                    break
            if accepted:
                if older:
                    status, payload = self._bsm_multi_read(comm, 0x1000)
                    if not status:
                        if payload.ljust(12, b"\0")[11] & 1:
                            data[21] = 1
                        data[7] = 1
                        status = 1099
                else:
                    data[8] = 1
                    status = 1099
            comm.session(1, 1, stop_on_error=True)
        comm.finalize()
        if status != 1099:
            return status
        selected = _word(data, 16)
        choices = (
            (0x11FE, 0x11FF, 0x12D5, 0x12D6)
            if older
            else (0x1200, 0x1201, 0x12D7, 0x12D8)
        )
        if selected not in choices:
            raise ValueError(
                "native BSM selected ECU has no defined source channel list"
            )
        others = [
            channel
            for index, channel in enumerate((65, 66, 129, 130))
            if index != choices.index(selected)
        ]
        output = 23 if older else 22
        stored = 0
        for channel in (15, *others):
            comm.configure_target(0x750, channel, 0, 0, 0)
            status = self._open(comm)
            if not status:
                probe, reply = self._raw(comm, b"\x3e\0")
                status = 0
                if not probe and reply.ljust(2, b"\0")[1] == 0:
                    status = comm.session(3, 1, normal_first=True)
                    if not status:
                        checks = (
                            [(0x0204, 0, 32), (0x1000, 0, 16), (0x2000, 0, 32)]
                            if channel == 15
                            else [(0x0101, 4, 128), (0x2000, 10, 8), (0x2055, 0, 1)]
                        )
                        payload = b""
                        for step, (identifier, index, mask) in enumerate(checks):
                            previous = payload if older and step == 2 else b""
                            status, payload = self._bsm_multi_read(comm, identifier)
                            if status:
                                payload = previous
                            if not payload.ljust(index + 1, b"\0")[index] & mask:
                                break
                            if step == 2:
                                if channel == 15:
                                    data[22 if older else 21] = 1
                                else:
                                    data[output + stored] = channel
                                    stored += 1
                            if status:
                                break
                    comm.session(1, 1, stop_on_error=True)
            comm.finalize()
            if status:
                return status
        return 0

    def _bsm_multi_monitor(
        self,
        comm: TYComm,
        data: bytearray,
        context: ChassisContext,
        older: bool,
        extended: bool,
    ) -> int:
        low, failed = (2, 1005 if extended else 2205) if older else (1, 2005)
        status, value = 0, 4 if older else 0

        def normal() -> None:
            comm.session(1, 1, stop_on_error=True)

        def stop() -> int:
            result = self._ahc04_routine(comm, 2, low)[0]
            normal()
            return result

        def release(result: int) -> int:
            normal()
            comm.finalize()
            toggled = self._bsm_multi_toggle(comm, data, older, False)
            return failed if toggled else result

        while not data[4]:
            context.sleep(200)
            status, reply = self._ahc04_routine(comm, 3, low, output=1)
            if not status:
                value = reply[0]
            if not older and not extended and (status or value not in (1, 2, 3)):
                if value not in (1, 2, 3):
                    status = 3
                stop()
                break
            if value == 1:
                continue
            if value == 3:
                if extended:
                    return release(failed)
                normal()
                status = failed
                break
            if value != 2:
                if extended:
                    stop()
                    comm.finalize()
                    self._bsm_multi_toggle(comm, data, older, False)
                    return failed
                return stop()
            if not extended and data[4]:
                return status
            status, payload = self._bsm_multi_read(comm, 0x1061)
            if not status and len(payload) < 2:
                status = 3
            if status:
                if extended:
                    return release(failed)
                normal()
                return status
            if not extended and data[4]:
                return status
            confirmed = (
                bool(payload[1] & 1) if older or not extended else payload[1] == 1
            )
            if not confirmed:
                if extended:
                    return release(99 if older else 2008)
                normal()
                return 2208 if older else 2008
            if older:
                status, payload = self._bsm_multi_read(comm, 0x2052)
                if not status and len(payload) < 2:
                    status = 3
                if status:
                    if extended:
                        return release(failed)
                    normal()
                    return status
                if not extended and data[4]:
                    return status
                if not payload[1] & 1:
                    if extended:
                        return release(99)
                    normal()
                    return 2208
                if extended:
                    if not data[21]:
                        return release(failed)
                    status, payload = self._bsm_multi_read(comm, 0x1060)
                    if status or len(payload) <= 8:
                        return release(failed)
                    data[20] = payload[8]
                    return release(0)
                normal()
                return 2203
            status, payload = self._bsm_multi_read(comm, 0x1060)
            # Native9dd00 requests payload offset2,length2.
            if not status and len(payload) < 4:
                status = 3
            if status:
                if extended:
                    return release(failed)
                normal()
                return status
            data[6:8] = payload[2:4][::-1]
            if extended:
                return release(0)
            normal()
            return 2003
        if extended:
            data[8 if older else 9] = 1
        return status

    def _bsm_multi(
        self, export: str, comm: TYComm, data: bytearray, context: ChassisContext
    ) -> int:
        older = export == "Ex2BSM_09_10_19_20_SendMessage"
        action = _word(data, 0)
        low, failed = (2, 1005) if older else (1, 2005)

        def normal() -> None:
            comm.session(1, 1, stop_on_error=True)

        def stop() -> int:
            status = self._ahc04_routine(comm, 2, low)[0]
            normal()
            return status

        if older and action == 2:
            status = self._bsm_multi_monitor(comm, data, context, True, False)
            if not data[4]:
                comm.finalize()
                data[5] = 1
            return status
        if data[5]:
            if not older:
                data[5] = 0
            status = self._open(comm)
            if status:
                comm.finalize()
                data[5] = 1
                return status
            data[5] = 0
        if action == 0:
            status = comm.session(3, 1, normal_first=True)
            if not status:
                status = self._ahc04_routine(comm, 1, low, b"\x19\0\0")[0]
                if not status:
                    return 2206 if older else 0
                normal()
                status = 2205 if older else 2005
            comm.finalize()
            data[5] = 1
            return status
        if action == (1 if older else 2):
            status = stop()
            comm.finalize()
            if not older:
                data[5] = 1
            return status if older else 0
        if not older and action == 1:
            status = self._bsm_multi_monitor(comm, data, context, False, False)
            if not data[4]:
                comm.finalize()
                data[5] = 1
            return status
        if action == 3:
            return self._bsm_multi_support(comm, data, older)
        if action == 4:
            status = self._bsm_multi_toggle(comm, data, older, True)
            if not status:
                first = 0x11FE if older else 0x1200
                selector = _word(data, 16)
                channel_map: dict[int, int] = dict(
                    zip(
                        (
                            first,
                            first + 1,
                            0x12D5 if older else 0x12D7,
                            0x12D6 if older else 0x12D8,
                        ),
                        (65, 66, 129, 130),
                        strict=True,
                    )
                )
                channel = channel_map.get(selector, 0)
                status = self._bsm_multi_select(comm, channel)
                if not status:
                    control = 10 if _word(data, 12) == 2 else 25
                    status = self._ahc04_routine(comm, 1, low, bytes((control, 0, 0)))[
                        0
                    ]
                    if not status:
                        return 0
                    normal()
                comm.finalize()
                self._bsm_multi_toggle(comm, data, older, False)
            return failed
        if action == 5:
            stop()
            comm.finalize()
            return self._bsm_multi_toggle(comm, data, older, False)
        if action == 6:
            return self._bsm_multi_monitor(comm, data, context, older, True)
        return 0

    def _ahc04_routine(
        self, comm: TYComm, phase: int, low: int, payload: bytes = b"", output: int = 0
    ) -> tuple[int, bytes]:
        request = bytes((49, phase, 17, low)) + payload
        status, reply = self._raw(comm, request)
        if not status and (len(reply) < 4 + output or reply[1:4] != request[1:4]):
            status = 3
        return status, reply[4 : 4 + output] if not status else b""

    def _ahc04_poll(
        self,
        comm: TYComm,
        secondary: TYComm | None,
        data: bytearray,
        context: ChassisContext,
        action: int,
    ) -> int:
        _put(data, 8, 1028)
        cancelled = False
        started = context.ticks()
        low = 0xA8 if action == 15 else 0xA2

        def poll(controller: TYComm) -> tuple[int, int]:
            status, reply = self._ahc04_routine(controller, 3, low, output=1)
            return status, reply[0] if not status else 0

        def pending(
            controller: TYComm, deadline: int, stops: tuple[int, ...], timeout: int
        ) -> int:
            nonlocal cancelled
            while True:
                status, value = poll(controller)
                if status:
                    return status
                if value == 2:
                    return 0
                if value != 1:
                    return 3
                if elapsed_ticks(context.ticks(), started) >= deadline:
                    return timeout
                if _word(data, 4) in stops:
                    cancelled = True
                    return 0

        if action in (15, 17):
            status = pending(
                comm,
                35000 if action == 15 else 25000,
                (2, 3) if action == 15 else (3,),
                2002 if action == 15 else 3,
            )
        else:
            if action == 9:
                assert secondary is not None
                while True:
                    status, first = poll(comm)
                    if status:
                        break
                    status, second = poll(secondary)
                    if status:
                        break
                    if first not in (1, 2) or second not in (1, 2):
                        status = 3
                        break
                    if first == second == 2:
                        break
                    if elapsed_ticks(context.ticks(), started) >= 35000:
                        status = 3
                        break
                    if _word(data, 4) in (2, 3):
                        cancelled = True
                        break
                controller = secondary
                payload = b"\3" + b"\xc0\x40\0\x64" * 3 + bytes(8)
            else:
                status = pending(comm, 35000, (2, 3), 3)
                controller = comm
                payload = b"\3" + b"\x30\x10\0\x64" * 3 + bytes(8)
            # Cancellation leaves the first native pending result successful and
            # bypasses the additional start rather than inventing a failed reply.
            if not status and not cancelled:
                start, _ = self._ahc04_routine(controller, 1, 0xA2, payload)
                if start:
                    _put(data, 8, 2001)
                    status = 0
                else:
                    status = pending(
                        controller, 70000, (2, 3), 2000 if action == 9 else 3
                    )
                    if action == 9 and status:
                        status = 2000
                    if not status and not cancelled:
                        _put(data, 8, 1008)
        while _word(data, 4) == 4:
            if action == 9:
                assert secondary is not None
                context.sleep(1000)
                self._raw(comm, b"\x3e\0")
                self._raw(secondary, b"\x3e\0")
            else:
                context.ticks()
        selected = _word(data, 4)
        if selected == 3:
            _put(data, 8, 1030)
            return 0
        if selected == 2 and action != 17:
            _put(data, 8, 1010 if action == 15 else 1006)
            return 0
        return status

    def _ahc04(self, comm: TYComm, data: bytearray, context: ChassisContext) -> int:
        action = _word(data, 0)
        secondary = (
            context.comm("native:1011c400")
            if action in (6, 7, 8, 9, 10) or action > 17
            else None
        )

        def normal(controller: TYComm) -> None:
            controller.session(1, 1, stop_on_error=True)

        def close(controller: TYComm) -> None:
            normal(controller)
            controller.finalize()

        def initialize(controller: TYComm, channel: int) -> tuple[int, bool]:
            controller.configure_target(0x750, channel, 0, 0, 0)
            status = self._open(controller)
            if status:
                return status, False
            return controller.session(3, 1, normal_first=True), True

        def routine(
            phase: int, low: int = 0xA2, payload: bytes = b"", controller: TYComm = comm
        ) -> int:
            return self._ahc04_routine(controller, phase, low, payload)[0]

        if action in (0, 1):
            status, _ = initialize(comm, 0x36)
            if not status:
                if action == 0:
                    status, reply = self._raw(comm, b"\x22\x21\1")
                    if not status:
                        if len(reply) < 4 or reply[1:3] != b"\x21\1":
                            status = 3
                        elif len(reply) - 3 > len(data) - 24:
                            raise ValueError(
                                "AHC04 returned configuration exceeds UI buffer"
                            )
                        else:
                            _put(data, 20, len(reply) - 3)
                            data[24 : 24 + len(reply) - 3] = reply[3:]
                if not status and (action == 1 or data[24] != 1):
                    data[24] = 0 if action == 1 else 1
                    length = _bounded_word(data, 20, min(0x101D, len(data) - 24))
                    status, reply = self._raw(
                        comm, b"\x2e\x21\1" + bytes(data[24 : 24 + length])
                    )
                    if not status and (len(reply) < 3 or reply[1:3] != b"\x21\1"):
                        status = 3
                normal(comm)
            comm.finalize()
            return status
        if action in (2, 6, 11):
            if action == 11:
                _put(data, 8, 0)
            channel = 0x36 if action != 11 or _word(data, 16) == 1 else 0x3B
            status, _ = initialize(comm, channel)
            if status:
                comm.finalize()
                return status
            if action == 6:
                assert secondary is not None
                status, _ = initialize(secondary, 0x3B)
                if status:
                    secondary.finalize()
                    close(comm)
                    return status
                payload = b"\3" + b"\x0c\x40\0\x64" * 3 + bytes(8)
                status = routine(1, payload=payload, controller=secondary)
                if not status:
                    payload = b"\3" + b"\0\0\2\x64" * 3 + bytes(8)
                    status = routine(1, payload=payload)
                    if status:
                        routine(2, controller=secondary)
                if status:
                    close(comm)
                    close(secondary)
                return status
            payload = (
                b"\0\x32" if action == 11 else b"\3" + b"\3\x10\1\x64" * 3 + bytes(8)
            )
            status = routine(1, 0xA8 if action == 11 else 0xA2, payload)
            if status:
                close(comm)
            return status
        if action in (4, 9, 15, 17):
            return self._ahc04_poll(comm, secondary, data, context, action)
        if action in (12, 16):
            payload = b"\0\x32" if action == 12 else bytes(data[0x1038:0x104D])
            status = routine(1, 0xA8 if action == 12 else 0xA2, payload)
            if status:
                close(comm)
            return status
        if action == 14:
            routine(2, 0xA8)
            return 1013
        if action in (3, 5, 7, 8, 10, 13):
            status = _word(data, 8)
            if action in (3, 7, 13):
                routine(2, 0xA8 if action == 13 else 0xA2)
            close(comm)
            if secondary is not None:
                if action in (7, 8):
                    routine(2, controller=secondary)
                close(secondary)
            return status
        self._raw(comm, b"\x3e\0")
        assert secondary is not None
        self._raw(secondary, b"\x3e\0")
        return 0

    def _4wd05_support(self, comm: TYComm, data: bytearray) -> int:
        data[52:68] = bytes(16)
        data[68] = 255
        _put(data, 76, 0)
        status = self._initialize(comm)
        if status:
            return status

        def read(request: bytes, length: int, echo: int) -> tuple[int, bytes]:
            status, reply = self._raw(comm, request)
            if not status and (
                len(reply) != length or reply[1 : 1 + echo] != request[1 : 1 + echo]
            ):
                status = 3
            return status, reply

        def classify() -> int:
            status, reply = read(b"\x22\1\1", 35, 2)
            if status:
                return status
            capability, supported = bool(reply[5] & 128), bool(reply[7] & 128)
            routine_left = routine_right = feature = False
            if supported:
                status, reply = read(b"\x22\x20\0", 35, 2)
                if status:
                    return status
                _put(data, 52, int(bool(reply[3] & 64)))
                _put(data, 56, int(bool(reply[3] & 32)))
                status, reply = read(b"\x31\1\x10\1", 36, 3)
                if status:
                    return status
                if reply[6] & 64:
                    status, reply = read(b"\x31\1\x11\0", 36, 3)
                    if status:
                        return status
                    routine_left, routine_right = (
                        bool(reply[4] & 64),
                        bool(reply[4] & 32),
                    )
                    _put(data, 60, int(bool(reply[4] & 8)))
                    _put(data, 64, int(bool(reply[5] & 128)))
                    if capability:
                        status, reply = read(b"\x22\x10\0", 35, 2)
                        if status:
                            return status
                        feature = bool(reply[6] & 64)
                        if feature:
                            status, reply = self._raw(comm, b"\x22\x10\x1a")
                            if not status and (
                                len(reply) < 4 or reply[1:3] != b"\x10\x1a"
                            ):
                                status = 3
                            if status:
                                return status
                            data[68] = reply[3]
            left, right, extra, special = (
                _word(data, i) != 0 for i in (52, 56, 60, 64)
            )
            if (
                left
                and right
                and not feature
                and routine_left
                and routine_right
                and extra
                and not special
            ):
                mode = 1
            elif (
                left
                and right
                and feature
                and data[68] == 1
                and routine_left
                and routine_right
                and not extra
                and special
            ):
                mode = 2
            elif not left and not right:
                mode = 3
            elif (
                left
                and feature
                and data[68] != 1
                and routine_left
                and not extra
                and special
            ):
                mode = 4
            else:
                return 1001
            _put(data, 76, mode)
            return 0

        status = classify()
        normal = self._normal(comm)
        return status or normal

    def _4wd08_process(
        self, comm: TYComm, data: bytearray, context: ChassisContext, action: int
    ) -> int:
        def read(identifier: int, length: int) -> tuple[int, bytes]:
            status, reply = self._reply(
                comm, b"\x22" + identifier.to_bytes(2, "big"), 3 + length, 2
            )
            return status, reply[3 : 3 + length]

        def wheels() -> int:
            status, payload = read(0x1014, 8)
            if not status:
                data[36:44] = payload
            return status

        def control(payload: bytes) -> int:
            return self._reply(comm, b"\x2f\x28\4" + payload, 10, 3)[0]

        if action in (1, 2):
            while action == 1 or data[44] != 0:
                if action == 2:
                    context.sleep(200)
                status = wheels()
                if status or action == 1:
                    return status
            return 0
        if action not in (0, 3, 4):
            return 0
        mode = _word(data, 52)
        if action == 0:
            payload = b"\3\0\0\0\0\1\xf4\xe0"
            first, result, counter = (0, 0, 8) if mode in (0, 5) else (4, 4, 12)
        elif action == 3:
            first, result, counter = (0, 24, 16) if mode == 2 else (4, 28, 20)
            payload = (
                b"\3\x17\x70\0\0\1\xf4\xe0"
                if mode == 2
                else b"\3\0\0\x17\x70\1\xf4\xe0"
            )
        else:
            first, result, counter = 0, 0, 0
            payload = b"\3\x17\x70\x17\x70\1\xf4\xe0"
        status = control(payload)
        if status:
            return status
        started, stable, last_speed = context.ticks(), None, -1
        while True:
            context.sleep(20)
            if action != 4:
                status = wheels()
                if status:
                    break
            status, raw_speed = read(0x1020, 2)
            if status:
                break
            speed = int.from_bytes(raw_speed, "big")
            if action == 4:
                if speed >= 103:
                    for mask in (128, 64):
                        context.sleep(1000)
                        status = control(b"\3" + bytes(6) + bytes((mask,)))
                        if status:
                            break
                    if not status:
                        context.sleep(1000)
                    break
                if elapsed_ticks(context.ticks(), started) >= 7000:
                    break
                continue
            ready = all(
                int.from_bytes(data[36 + i : 38 + i], "big") >= 103
                for i in (first, first + 2)
            )
            if action == 3:
                ready = ready and speed == 0
            if not ready or (
                action == 0 and last_speed in (0, 1) and last_speed != int(speed > 0)
            ):
                stable = None
            if ready:
                if stable is None:
                    stable = context.ticks()
                    last_speed = int(speed > 0)
                elif elapsed_ticks(context.ticks(), stable) >= 500:
                    _put(data, result, int(last_speed != 0) if action == 0 else 0)
                    break
            if elapsed_ticks(context.ticks(), started) >= 5000:
                _put(data, counter, (_word(data, counter) + 1) & 0xFFFFFFFF)
                if action == 3:
                    _put(data, result, 1)
                break
        stop = control(b"\0\xe0")
        return stop or status

    def _4wd08(
        self, comm: TYComm, data: bytearray, context: ChassisContext
    ) -> tuple[int, bool]:
        action = _word(data, 48)
        if action in (0, 1):
            status = self._initialize(comm, grouped_session=True)
            if status:
                return status, True
        status = self._4wd08_process(comm, data, context, action)
        if action not in (0, 3, 4) and not status:
            return 0, False
        return self._normal(comm) or status, True

    def _4wd06_process(
        self, comm: TYComm, data: bytearray, context: ChassisContext, action: int
    ) -> int:
        def read(identifier: int, offset: int, length: int) -> tuple[int, bytes]:
            status, reply = self._reply(
                comm, b"\x22" + identifier.to_bytes(2, "big"), 3 + offset + length, 2
            )
            return status, reply[3 + offset : 3 + offset + length]

        def control(payload: bytes) -> int:
            status, _ = self._reply(comm, b"\x2f\x28\1" + payload, 12, 3)
            return status

        def status_byte() -> tuple[int, int]:
            status, payload = read(0x1024, 1, 1)
            return status, payload[0] if not status else 0

        if action == 0:
            status, value = status_byte()
            if not status:
                data[26] = value & 192
            return status
        if action in (1, 2):
            while True:
                if action == 2:
                    if data[32] == 1:
                        return 0
                    context.sleep(200)
                status, payload = read(0x1014, 0, 8)
                if not status:
                    data[18:26] = payload
                if status or action == 1:
                    return status
        if action not in (3, 4, 5):
            data[17] = 1
            return 0

        def finish() -> int:
            status = control(b"\0\xf0")
            if not status:
                context.sleep(1000)
                status, value = status_byte()
                if not status:
                    data[26] = value
            return status

        if action in (3, 4):
            payload = (
                b"\3\x17\x70\0\0\0\0\0\0\xf0"
                if action == 3
                else b"\3\0\0\x17\x70\5\xdc\5\xdc\xf0"
            )
            status = control(payload)
            if status:
                return status
            started = context.ticks()
            stable = None
            while True:
                context.sleep(20)
                status, value = status_byte()
                if status:
                    control(b"\0\xf0")
                    return status
                data[26] = value
                if value & 128:
                    stable = None
                elif stable is None:
                    stable = context.ticks()
                elif elapsed_ticks(context.ticks(), stable) >= 500:
                    break
                if elapsed_ticks(context.ticks(), started) >= 5000:
                    break
            return finish()
        status = control(b"\3\x17\x70\x17\x70\5\xdc\5\xdc\xf0")
        if status:
            return status
        started = context.ticks()

        def fault(status: int) -> int:
            control(b"\0\xf0")
            return finish() if status == 1046 else status

        while True:
            context.sleep(20)
            status, payload = read(0x1020, 0, 2)
            if status:
                return fault(status)
            # Static multiplier0.048828125 =25/512; native threshold is5.
            if int.from_bytes(payload, "big") >= 103:
                break
            if elapsed_ticks(context.ticks(), started) >= 10000:
                return finish()
        for mask in (128, 64):
            status = control(b"\3" + bytes(8) + bytes((mask,)))
            if status:
                return status
            stable = None
            while True:
                context.sleep(20)
                status, value = status_byte()
                if status:
                    return fault(status)
                if value & mask:
                    if stable is None:
                        stable = context.ticks()
                    elif elapsed_ticks(context.ticks(), stable) >= 500:
                        break
                else:
                    stable = None
                if elapsed_ticks(context.ticks(), started) > 10000:
                    return finish()
        return finish()

    def _4wd06(
        self, comm: TYComm, data: bytearray, context: ChassisContext
    ) -> tuple[int, bool]:
        status = 0
        if data[16] == 1:
            data[16] = 0
            status = self._open(comm)
            if status:
                return status, data[17] == 1
            status = self._normal(comm)
            if not status:
                status = comm.session(3, 1)
            if status:
                data[17] = 1
                return status, True
        status = self._4wd06_process(comm, data, context, _word(data, 12))
        if not status and data[17] != 1:
            return 0, False
        normal = self._normal(comm)
        data[17] = 1
        return normal or status, True

    def _tpw08_support(self, comm: TYComm, data: bytearray) -> int:
        def read(identifier: int, offset: int, length: int) -> tuple[int, bytes]:
            status, reply = self._reply(
                comm, b"\x22" + identifier.to_bytes(2, "big"), offset + length, 2
            )
            return status, reply[offset : offset + length]

        def fast_finish(status: int) -> int:
            comm.configure("native_rva:1a730", 1)
            normal = self._normal(comm)
            return status or normal

        status, payload = read(0x0101, 5, 3)
        if status:
            return fast_finish(status)
        if not payload[0] & 128 or not payload[2] & 128:
            return fast_finish(22)
        status, payload = read(0x2000, 3, 1)
        if status:
            return fast_finish(status)
        if not payload[0] & 64:
            return fast_finish(22)
        status, reply = self._reply(comm, b"\x31\1\x10\1", 7, 3)
        if status:
            return fast_finish(status)
        if not reply[6] & 64:
            return fast_finish(22)
        status, payload = read(0x1000, 9, 1)
        if status:
            return fast_finish(status)
        features = payload[0]
        status, reply = self._reply(comm, b"\x31\1\x11\0", 8, 3)
        if status:
            return fast_finish(status)
        routine = reply[4:8]
        if features & 64:
            status, mode = read(0x2002, 3, 1)
            if not status:
                status, registered = read(0x1032, 3, 2)
                if not status:
                    selected = mode[0] & 7
                    match = (selected == 4 and registered[0] & 248 == 240) or (
                        selected == 5 and registered[0] & 248 == 248
                    )
                    if match and routine[0] & 64:
                        data[4] = selected
                        data[12] |= 1
                    elif not match:
                        data[4] = 0
        if features & 32:
            status, payload = read(0x1033, 3, 2)
            if not status and payload[0] & 128 and routine[3] & 1:
                data[12] |= 2
        if features & 16:
            status, payload = read(0x1034, 3, 2)
            if not status and payload[0] & 128 and routine[1] & 1:
                data[12] |= 4
        if not data[12] & 7:
            return fast_finish(22)
        return self._normal(comm)

    def _tpw08(
        self, comm: TYComm, data: bytearray, context: ChassisContext
    ) -> tuple[int, bool]:
        action = _word(data, 0)
        if action > 6:
            return 0, False
        if action < 4:
            if action == 0:
                data[12] = 0
            status = self._initialize(comm)
            if status:
                return status, True
            if action == 0:
                return self._tpw08_support(comm, data), True
            identifier = {1: 0x1102, 2: 0x1120, 3: 0x1110}[action]
            status, _ = self._reply(
                comm, b"\x31\1" + identifier.to_bytes(2, "big"), 4, 3
            )
            if not status:
                return 0, False
            comm.configure("native_rva:1a730", 1)
            self._normal(comm)
            comm.configure("native_rva:1a730", 0)
            return status, True
        while True:
            context.sleep(500)
            status, reply = self._reply(comm, bytes((34, 16, 0x32 + action - 4)), 5, 2)
            if status:
                break
            data[20] = reply[4]
            _put(data, 16, 1)
            if _word(data, 24):
                break
        if status or data[21] == 2:
            comm.configure("native_rva:1a730", 1)
            self._normal(comm)
            comm.configure("native_rva:1a730", 0)
        else:
            status = self._normal(comm)
        return status, True

    def _tpw06(self, comm: TYComm, data: bytearray) -> int:
        status = self._open(comm)
        if status:
            return status
        action = _word(data, 32)
        if action not in (0, 1, 2, 3):
            return 0
        if action == 0:
            _put(data, 24, 0)
        status = self._normal(comm)
        if not status:
            status = comm.session(3, 1)
        if status:
            return status

        def read(identifier: int, offset: int, length: int) -> tuple[int, bytes]:
            status, reply = self._reply(
                comm, b"\x22" + identifier.to_bytes(2, "big"), offset + length, 2
            )
            return status, reply[offset : offset + length]

        if action == 0:
            status, payload = read(0x0101, 5, 3)
            if not status:
                if not payload[0] & 128 or not payload[2] & 128:
                    status = 22
                else:
                    status, payload = read(0x1000, 4, 4)
                    if not status:
                        if payload[0] & 4 != 4 or payload[3] & 60 != 60:
                            status = 22
                        else:
                            if payload[3] & 2:
                                _put(data, 24, 1)
                            status, payload = read(0x2000, 3, 1)
                            if not status and payload[0] & 96 != 96:
                                status = 22
        elif action == 1:
            status, payload = read(0x100E, 3, 1)
            if not status:
                data[0] = payload[0] & 3
                if data[0] != 1:
                    status, payload = read(0x2002, 3, 1)
                    if not status:
                        value = payload[0] & 7
                        if value not in (4, 5):
                            status = 3
                        else:
                            data[1] = value
        elif action == 2:
            for index, identifier in enumerate(range(0x1023, 0x1027)):
                status, payload = read(identifier, 3, 4)
                if status:
                    break
                data[2 + 4 * index : 6 + 4 * index] = payload
            if not status and not (
                (_word(data, 36) == 1 and _word(data, 28) == 1)
                or (_word(data, 36) == 0 and data[1] == 4)
            ):
                if not _word(data, 24):
                    status = 1008
                else:
                    status, payload = read(0x1027, 3, 4)
                    if not status:
                        data[18:22] = payload
        else:
            four = (_word(data, 36) == 1 and _word(data, 28) == 1) or (
                _word(data, 36) == 0 and data[1] == 4
            )
            payload = bytearray(data[2:22])
            if four:
                payload[16:20] = bytes(4)
            status, _ = self._reply(
                comm, bytes((46, 32, 3, 4 if four else 5)) + payload, 3, 2
            )
            self._normal(comm)
            return status
        normal = self._normal(comm)
        if normal:
            return normal
        if not status and action == 1:
            return 1002 if data[0] == 1 else 1009
        return status

    def _tpw13(self, comm: TYComm, data: bytearray) -> int:
        status = self._open(comm)
        if status:
            return status
        action = _word(data, 0)
        if action == 1:
            data[4:6] = bytes(2)
        elif action == 3:
            data[6:26] = bytes(20)
        status = comm.session(3, 1, normal_first=True)
        if status:
            return status

        def read(identifier: int, minimum: int) -> tuple[int, bytes]:
            status, reply = self._reply(
                comm, b"\x22" + identifier.to_bytes(2, "big"), minimum + 3, 2
            )
            return status, reply[3:]

        def write(identifier: int, payload: bytes) -> int:
            status, _ = self._reply(
                comm, b"\x2e" + identifier.to_bytes(2, "big") + payload, 3, 2
            )
            return status

        try:
            if action == 0:
                status, payload = read(0x0101, 32)
                if status:
                    return status
                if not payload[2] & 128 or not payload[4] & 128:
                    return 3
                status, saved = read(0x1000, 32)
                if status:
                    return status
                status, payload = read(0x2000, 32)
                if status:
                    return status
                return (
                    0
                    if saved[9] & 1
                    and saved[10] == 255
                    and saved[11] & 128
                    and payload[0] & 96 == 96
                    and payload[2] & 128
                    else 3
                )
            if action == 1:
                data[4:6] = bytes(2)
                for identifier, offset, mask in ((0x2002, 4, 7), (0x2011, 5, 3)):
                    status, payload = read(identifier, 1)
                    if status:
                        return status
                    data[offset] = payload[0] & mask
                return 0 if data[4] in (4, 5) and data[5] in (0, 3) else 3
            if action == 2:
                changed = False
                for identifier in range(0x1050, 0x1054):
                    status, payload = read(identifier, 4)
                    if status:
                        return status
                    changed |= bool(payload[0] & 15 or any(payload[1:4]))
                # Original static DAT100dbde8 is four zero bytes.
                return 0 if changed else 2000
            if action == 3:
                data[6:26] = bytes(20)
                for index in range(4):
                    identifier = (
                        0x1050 + index + (5 if data[27] == 0 and data[29] == 2 else 0)
                    )
                    status, payload = read(identifier, 4)
                    if status:
                        return status
                    data[6 + 4 * index : 10 + 4 * index] = payload[:4]
                fifth = data[28] == 2 if _word(data, 32) else data[4] == 5
                if fifth:
                    status, payload = read(0x1059 if data[29] == 2 else 0x1054, 4)
                    if status:
                        return status
                    data[22:26] = payload[:4]
                return 0
            saved = b""
            if data[27] == 1:
                status, saved = read(0x2033, 2)
                if status:
                    return status
                saved = bytes((saved[0], saved[1] & 127)) + saved[2:]
                status = write(0x2033, saved)
                if status:
                    return status
            payload = bytearray(21)
            payload[0] = 16 if data[26] == 1 else 0
            if data[27] == 0 and data[29] == 2:
                payload[0] |= 8
            four = data[28] == 1 if _word(data, 32) else data[4] == 4
            payload[0] |= 4 if four else 5
            payload[1:17] = data[6:22]
            fifth = data[28] == 2 if _word(data, 32) else data[4] == 5
            if fifth:
                payload[17:21] = data[22:26]
            status = write(0x2003, bytes(payload))
            if status and data[27] == 1:
                write(0x2033, bytes((saved[0], saved[1] | 128)) + saved[2:])
            return status
        finally:
            self._normal(comm)

    def _drs04(self, comm: TYComm, data: bytearray) -> int:
        status = comm.initialize(0)
        if status:
            return status
        comm.configure(self.contract.legacy_setter, 150)
        action = _word(data, 0x1028)
        if action == 0:
            for kind, identifier, shift in ((1, 10, 0), (3, 1, 12)):
                status, raw, offsets = comm.support_snapshot(kind)
                if status:
                    return status
                for base in (0x102C, 0x1048):
                    index = _bounded_word(data, base + shift, 0x101D)
                    status, selected = _support_required(
                        raw, offsets, identifier, index + 3, data[base + shift + 4]
                    )
                    _put(data, base + shift + 8, int(status == 0))
                    if not status and kind == 1:
                        _put(data, base, selected - 2)
                status, payload = _support_record(raw, offsets, identifier)
                if status:
                    return status
                if kind == 1:
                    count = sum(bool(value) for value in payload)
                    _put(data, 0, count)
                    if not count:
                        return 22
                else:
                    _put(data, 0x1024, len(payload))
            return (
                0
                if any(
                    _word(data, base + 8) == 1 and _word(data, base + 20) == 1
                    for base in (0x102C, 0x1048)
                )
                else 22
            )
        if action == 1:
            data[4:0x1022] = bytes(0x101E)
            status, reply = self._raw(comm, b"\x21\x0a")
            length = _bounded_word(data, 0, 0x101E)
            if not status:
                if len(reply) != length + 2 or len(reply) < 2 or reply[1] != 10:
                    return 3
                data[4 : 4 + length] = reply[2:]
            return status
        if action == 2:
            payload = bytearray(0x1020)
            for base in (0x102C, 0x1048):
                if _word(data, base + 8) == 1 and _word(data, base + 20) == 1:
                    read_index = _bounded_word(data, base, 0x101D)
                    mask = data[base + 4]
                    if data[read_index + 4] & mask == mask:
                        write_index = _bounded_word(data, base + 12, 0x101D)
                        payload[write_index] = (
                            payload[write_index] + data[base + 16]
                        ) & 255
            length = _bounded_word(data, 0x1024, 0x101E)
            status, reply = self._raw(comm, b"\x3b\1" + payload[:length])
            return status or (0 if len(reply) == 2 and reply[1] == 1 else 3)
        return 0

    def _ars05(
        self, comm: TYComm, data: bytearray, context: ChassisContext
    ) -> tuple[int, bool]:
        action = _word(data, 0)

        def read(identifier: int, length: int) -> tuple[int, bytes]:
            status, reply = self._reply(
                comm, b"\x22" + identifier.to_bytes(2, "big"), length + 3, 2
            )
            return status, reply[3 : 3 + length]

        def write(identifier: int, payload: bytes) -> int:
            status, _ = self._reply(
                comm, b"\x2e" + identifier.to_bytes(2, "big") + payload, 3, 2
            )
            return status

        if action in (0, 3):
            status = self._open(comm)
            if status:
                return status, True
            status = comm.session(3, 1, normal_first=True)
            if status:
                return status, True
            if action == 3:
                status = write(0x0204, bytes(data[12:14]))
                self._normal(comm)
                return status, True
            status, payload = read(0x0204, 2)
            if not status:
                data[12:14] = bytes((payload[0], payload[1] & 254))
                status = write(0x0204, bytes(data[12:14]))
                if not status:
                    status = write(0x2020, b"\1")
                    if not status:
                        return 0, False
            self._normal(comm)
            return status, True
        if action == 1:
            while _word(data, 4) != 1:
                context.sleep(200)
                status, payload = read(0x1022, 1)
                if status:
                    return 2000, False
                if payload[0] == 1:
                    if _word(data, 8) == 1:
                        return 2008, False
                    if _word(data, 4) != 1:
                        continue
                elif payload[0] != 2:
                    return 2008, False
                return 0, False
            return 0, False
        if action == 2:
            status, payload = read(0x0204, 2)
            if status:
                return status, True
            data[12:14] = bytes((payload[0], payload[1] & 254))
            status = write(0x0204, bytes((payload[0], payload[1] | 1)))
            if not status:
                status = self._normal(comm)
                if not status:
                    return 0, True
                if write(0x0204, bytes(data[12:14])):
                    return 0, True
            self._normal(comm)
            return 1008, True
        write(0x2020, b"\xff")
        self._normal(comm)
        return 99 if action == 4 else 1008, True

    def _asus_pressure(self, comm: TYComm, data: bytearray) -> int:
        status, reply = self._reply(comm, b"\x22\x10\7", 5, 2)
        if status:
            return status
        raw = int.from_bytes(reply[3:5], "big")
        _put(data, 16, 1004 if raw >= 2205 else 1003 if raw >= 1780 else 1002)
        scaled = int(raw * Fraction.from_float(0.00073) * 100) * 0.01
        struct.pack_into("<d", data, 8, scaled)
        return 0

    def _asus08_control(
        self, export: str, comm: TYComm, data: bytearray, context: ChassisContext
    ) -> tuple[int, bool]:
        tank = export.endswith("StartTankPressLowCtrl")
        retained = bool(context.state.get(self.contract.asus08_state, 0))
        status = 0
        if not retained:
            status = comm.initialize(0)
        if not status and (not retained or not tank):
            for field, value in (
                (self.contract.retry_setter, 0),
                (self.contract.pending_setter, 180000),
            ):
                comm.configure(field, value)
            if self.contract.asus08_retries:
                comm.configure(self.contract.retries_setter, 0)

        def normal() -> int:
            return 1000 if self._normal(comm) else 0

        def start(raising: bool) -> int:
            status, _ = self._reply(
                comm, b"\x31\1\x11\1\x0f" + (b"\2\x96" if raising else b"\4\x40"), 4, 3
            )
            return status

        def poll(low: int, waiting: bool = False, complete: bool = True) -> int:
            started = context.ticks()
            while True:
                if waiting:
                    context.sleep(500)
                status, reply = self._reply(comm, bytes((49, 3, 17, low)), 5, 3)
                if not status:
                    status = {1: 1001, 2: 0}.get(reply[4], 99)
                    if not status and not waiting and low == 1 and complete:
                        _put(data, 4, 1)
                if not status:
                    return 0
                if status != 1001:
                    self._reply(comm, bytes((49, 2, 17, low)), 4, 3)
                    return status
                if elapsed_ticks(context.ticks(), started) >= (
                    10000 if waiting else 40000
                ):
                    stop, _ = self._reply(comm, bytes((49, 2, 17, low)), 4, 3)
                    if waiting:
                        if stop:
                            return stop
                        context.sleep(60000)
                    return 1001

        if not tank:
            if not status:
                status = start(True)
                if not status:
                    context.sleep(100)
                    status = poll(1)
                if not status:
                    status = self._asus_pressure(comm, data)
            if status:
                normal()
            return status, bool(status) or not retained
        if not status:
            status, _ = self._reply(comm, b"\x2e\x21\1\0", 3, 2)
        if not status:
            for _ in range(10 if self.contract.asus08_tank_retries else 1):
                status = start(False)
                if status:
                    break
                if not self.contract.asus08_tank_retries:
                    context.sleep(100)
                status = poll(1, self.contract.asus08_tank_retries, False)
                if status == 1001:
                    continue
                if status:
                    break
                context.sleep(30000)
                status = start(True)
                if status:
                    break
                context.sleep(100)
                status = poll(1)
                if status:
                    break
                status = self._asus_pressure(comm, data)
                if status:
                    break
                if _word(data, 16) == 1004:
                    status, _ = self._reply(comm, b"\x31\1\x11\5\1\x10", 4, 3)
                    if status:
                        break
                    context.sleep(100)
                    status = poll(5)
                    if status:
                        break
                    status = self._asus_pressure(comm, data)
                    if status:
                        break
                if _word(data, 16) == 1003:
                    status = normal()
                    context.state[self.contract.asus08_state] = 0
                    return status, True
                break
        normal()
        context.state[self.contract.asus08_state] = 0
        return status, True

    def _abs4wd(
        self, export: str, comm: TYComm, data: bytearray, context: ChassisContext
    ) -> int:
        support = export.endswith("SupportCheck")
        comm.configure(self.contract.legacy_setter, 150)
        status = 0
        for index, target in enumerate((0x7B0, 0x7B1)):
            comm.select_target(target)
            status = comm.initialize(0)
            if status:
                continue
            try:
                if support:
                    for kind, identifier in ((1, 0xA6), (3, 11)):
                        status, raw, offsets = comm.support_snapshot(kind)
                        if status:
                            break
                        status, _ = _support_required(raw, offsets, identifier, 3, 128)
                        if status:
                            break
                        if kind == 1:
                            _, payload = _support_record(raw, offsets, identifier)
                            _put(data, index * 4, sum(bool(value) for value in payload))
                else:
                    status, reply = self._raw(comm, b"\x3b\x0b\x80")
                    if not status and reply != b"\x7b\x0b":
                        status = 3
                    if not status:
                        context.sleep(500)
                        status, reply = self._raw(comm, b"\x21\xa6")
                        if not status:
                            if (
                                len(reply) != _word(data, index * 4) + 2
                                or reply[:2] != b"\x61\xa6"
                            ):
                                status = 3
                            elif not reply.ljust(3, b"\0")[2] & 128:
                                status = 1000
            finally:
                comm.finalize()
            if status:
                break
        if status and not support:
            for target in (0x7B0, 0x7B1):
                comm.select_target(target)
                if not comm.initialize(0):
                    try:
                        self._raw(comm, b"\x3b\x0b\0")
                    finally:
                        comm.finalize()
        return status

    def _asus_height_tank(
        self, export: str, comm: TYComm, context: ChassisContext
    ) -> int:
        timeout = 20001 if export.startswith("Ex2ASUS_06_") else 40001

        def start(request: bytes) -> int:
            status, _ = self._reply(comm, request, 4, 3, positive_service=False)
            if status:
                self._normal(comm)
            return status

        def poll(low: int) -> int:
            started = context.ticks()
            while True:
                status, reply = self._reply(
                    comm, bytes((49, 3, 17, low)), 5, 3, positive_service=False
                )
                if not status:
                    status = {1: 1001, 2: 0}.get(reply[4], 1002)
                if status == 0:
                    return 0
                if status == 1001 and elapsed_ticks(context.ticks(), started) < timeout:
                    continue
                self._raw(comm, bytes((49, 2, 17, low)))
                self._normal(comm)
                return status

        def pressure(phase: int) -> int:
            status, reply = self._reply(
                comm, b"\x22\x10\7", 5, 2, positive_service=False
            )
            if status:
                self._normal(comm)
                return status
            value = int.from_bytes(reply[3:5], "big")
            if value >= 2205:
                if phase == 2:
                    self._normal(comm)
                return 1004
            if value <= 1779:
                self._normal(comm)
                return 1003
            return 1000 if self._normal(comm) else 0

        status, _ = self._reply(comm, b"\x2e\x21\1\0", 3, 2, positive_service=False)
        if status:
            self._normal(comm)
            return status
        for index, control in enumerate((4, 2)):
            if index:
                context.sleep(30000)
            status = start(bytes((49, 1, 17, 1, 15, control, 64)))
            if status:
                return status
            context.sleep(100)
            status = poll(1)
            if status:
                return status
        status = pressure(1)
        if status != 1004:
            return status
        status = start(b"\x31\1\x11\5\1\x10")
        if status:
            return status
        context.sleep(100)
        status = poll(5)
        return status or pressure(2)

    def _ars_calibrate(
        self, export: str, comm: TYComm, data: bytearray, context: ChassisContext
    ) -> int:
        second = export.startswith("Ex2ARS_02_")
        status = comm.initialize(0)
        if status:
            return status
        comm.configure(self.contract.legacy_setter, 150)
        for index, mode in enumerate((64, 96, 98) if second else (64,)):
            if index:
                context.sleep(500)
            status, reply = self._raw(comm, bytes((16, mode)))
            if status or len(reply) != 1:
                return status or 3
        pressure = 100
        if _word(data, 8):
            context.sleep(500)
            status, reply = self._raw(comm, b"\x21\x84")
            if status or len(reply) != _word(data, 8) or reply[:2] != b"\x61\x84":
                return status or 3
            pressure = reply.ljust(3, b"\0")[2]
        context.sleep(500)
        status, reply = self._raw(comm, bytes((48, 2, 0, 1, pressure, 5, 50, 1, 1)))
        if status or len(reply) != 2:
            self._raw(comm, b"\x30")
            return status or 3
        context.sleep(5000)
        status, reply = self._raw(comm, b"\x10\1")
        if status or len(reply) != 1:
            return status or 3
        context.sleep(500)
        status, reply = self._raw(comm, b"\x21\x81")
        valid = len(reply) == _word(data, 0) and len(reply) >= 2 and reply[1] == 0x81
        if not second:
            if status or not valid:
                return -0x6FFFFFFE
        elif status or not valid:
            return status or 3
        if reply.ljust(4, b"\0")[2:4] != b"\0\1":
            return -0x6FFFFFFF if not second else -0x6FFFFFFE
        if second:
            status, reply = comm.read_dtcs(0x80, 0x1000)
            if type(status) is not int or not isinstance(reply, bytes):
                raise TypeError("native DTC reader must return (int, bytes)")
            if status:
                return status
            if len(reply) < 2 or len(reply) > 0x1000:
                return 3
            if reply[1]:
                return -0x6FFFFFFF
        return 0

    def _abs51(
        self, comm: TYComm, data: bytearray, context: ChassisContext
    ) -> tuple[int, bool]:
        action = _word(data, 0)
        if action not in (2, 5):
            status = self._open(comm)
            if status:
                return status, True
        if action == 5:
            comm.session(1, 1)
            return 0, True
        if action > 5:
            return 0, True
        if action != 2:
            status = comm.session(3, 1, normal_first=True)
            if status:
                return status, True
        indices = (0, 1) if action in (1, 3) else (int.from_bytes(data[4:6], "little"),)
        if action == 1:
            data[10:0x204A] = bytes(0x2040)
        for index in indices:
            if index not in (0, 1):
                raise ValueError("ABS selected snapshot index exceeds two native slots")
            length = int.from_bytes(data[6 + 2 * index : 8 + 2 * index], "little")
            if length > 0x101D:
                raise ValueError("ABS snapshot payload exceeds native reply capacity")
            base = 10 + index * 0x1020
            did = bytes((0x20, 5 + index))
            if action == 0:
                data[base : base + 0x1020] = bytes(0x1020)
            if action in (2, 3, 4):
                write_length = length & 255
                status, reply = self._raw(
                    comm, b"\x2e" + did + data[base : base + write_length]
                )
                if not status and (len(reply) < 3 or reply[1:3] != did):
                    status = 3
                if status:
                    comm.session(1, 1)
                    return status, True
                context.sleep(1000)
            status, reply = self._raw(comm, b"\x22" + did)
            if not status and (len(reply) < 3 + length or reply[1:3] != did):
                status = 3
            if not status:
                payload = reply[3:]
                if action in (0, 1):
                    data[base : base + length] = payload[:length]
                elif len(payload) != length or payload != data[base : base + length]:
                    status = 3
            if status:
                comm.session(1, 1)
                return status, True
        if action == 0:
            return 0, False
        comm.session(1, 1)
        return 0, True

    def _ars_center(
        self, comm: TYComm, data: bytearray, context: ChassisContext
    ) -> int:
        comm.configure(self.contract.legacy_setter, 150)
        status = comm.initialize(0)
        if status:
            return status
        status, reply = self._raw(comm, b"\x10\x40")
        if status or len(reply) != 1:
            return status or 3
        context.sleep(500)
        length = _bounded_word(data, 4)
        request = (b"\x30\5\0\1" + bytes(max(0, length - 4)))[:length]
        status, reply = self._raw(comm, request)
        if not status and (len(reply) != 2 or reply[1] != 5):
            status = 3
        if status:
            self._raw(comm, b"\x30")
            return status
        context.sleep(10000)
        status, reply = self._raw(comm, b"\x10\1")
        if status or len(reply) != 1:
            return status or 3
        context.sleep(500)
        status, reply = self._raw(comm, b"\x21\x09")
        if status:
            return status
        if len(reply) != _word(data, 0) or len(reply) < 2 or reply[1] != 9:
            return 3
        angle = int.from_bytes(reply.ljust(4, b"\0")[2:4], "big") * 0.0054931640625
        return 0 if 170 <= angle <= 190 else 1100

    def _vgrs_support(
        self, export: str, comm: TYComm, data: bytearray, context: ChassisContext
    ) -> int:
        support = export.endswith("SupportCheck")
        if not support:
            comm.configure(self.contract.legacy_setter, 150)
        status = comm.initialize(0)
        if status:
            return status
        if support:
            comm.configure(self.contract.legacy_setter, 150)
        else:
            context.sleep(500)
        status, reply = comm.read_dtcs(0x80, 0x1000)
        if type(status) is not int or not isinstance(reply, bytes):
            raise TypeError("native DTC reader must return (int, bytes)")
        if status:
            return status
        if len(reply) < 2 or len(reply) > 0x1000 or reply[1] * 2 + 2 > len(reply):
            return 3
        allowed = (
            {0x5591, 0x5592, 0x5593, 0x55A4, 0x55A9, 0x55AA, 0x55AB, 0x55B4}
            if support
            else set()
        )
        if any(
            int.from_bytes(reply[i : i + 2], "big") not in allowed
            for i in range(2, 2 + 2 * reply[1], 2)
        ):
            return 10000
        if not support:
            return 0
        context.sleep(500)
        status, raw, offsets = comm.support_snapshot(2)
        if status:
            return status
        status, _ = _support_required(raw, offsets, 2, 3, 255)
        if status:
            return status
        _, payload = _support_record(raw, offsets, 2)
        _put(data, 0, sum(bool(value) for value in payload) + 3)
        return 0

    def _bsm_target(
        self, export: str, comm: TYComm, data: bytearray, context: ChassisContext
    ) -> int:
        key = (
            "native:1012ae14" if export.startswith("Ex2BSM_27_") else "native:1012ae18"
        )
        probing = _word(data, 0) == 0
        if probing:
            context.state[key] = comm.read_target()[0]
            target = 0x786
        else:
            target = context.state.get(key, 0)
            if type(target) is not int or not 0 <= target <= 0xFFFFFFFF:
                raise ValueError("invalid native saved BSM target")
        comm.select_target(target)
        status = comm.initialize(0)
        if status:
            return status
        comm.configure(self.contract.legacy_setter, 150)
        status, reply = self._raw(comm, b"\x3e\0" if probing else b"\x3b\x6b\0")
        if probing:
            _put(data, 4, status)
            return 0 if status == 2 else status
        return 0 if not status and len(reply) >= 2 and reply[1] == 0x6B else 2000

    def _ars_legacy(self, export: str, comm: TYComm, context: ChassisContext) -> int:
        second = export.startswith("Ex2ARS_02_")
        clearing = export.endswith(("ClearOffSetValue", "ClrCompVal"))
        vgrs = export.endswith(("ReadDTCofVGRS", "ChkVGRSDtc"))
        old_target = comm.read_target()[0] if vgrs else None
        try:
            if vgrs:
                comm.select_target(0x7A3)
            if not second:
                comm.configure(self.contract.legacy_setter, 150)
            status = comm.initialize(0)
            if status:
                return status
            if second:
                comm.configure(self.contract.legacy_setter, 150)
            if clearing:
                for index, request in enumerate((b"\x10\x40", b"\xa6\1", b"\x14")):
                    if index:
                        context.sleep(500)
                    status, reply = self._raw(comm, request)
                    if status or len(reply) != 1:
                        return status or 3
                return 0
            status, reply = comm.read_dtcs(0x80, 0x1000)
            if type(status) is not int or not isinstance(reply, bytes):
                raise TypeError("native DTC reader must return (int, bytes)")
            if status:
                return status
            if len(reply) < 2 or len(reply) > 0x1000 or reply[1] * 2 + 2 > len(reply):
                return 3
            allowed = {0x55C9} if vgrs else {0x5B01, 0x5B04}
            codes = (
                int.from_bytes(reply[i : i + 2], "big")
                for i in range(2, 2 + reply[1] * 2, 2)
            )
            return (
                (-0x6FFFFFFF if second else 1000)
                if any(code not in allowed for code in codes)
                else 0
            )
        finally:
            comm.finalize()
            if old_target is not None:
                # Native restores the first target DWORD and clears the second.
                comm.select_target(old_target)

    def _ars04(
        self, comm: TYComm, data: bytearray, context: ChassisContext
    ) -> tuple[int, bool]:
        action = _word(data, 0)

        def routine(phase: int) -> tuple[int, bytes]:
            return self._reply(
                comm,
                bytes((49, phase, 17, 5))
                + (b"\1\x46\x14\x32\x32\1" if phase == 1 else b""),
                5 if phase == 3 else 4,
                3,
            )

        def stop() -> None:
            routine(2)
            comm.session(1, 1)

        if action == 0:
            status = self._open(comm)
            if status:
                return status, True
            status = comm.session(3, 1, normal_first=True)
            if not status:
                context.sleep(500)
                status, _ = routine(1)
                if status:
                    comm.session(1, 1)
            return status, bool(status)
        if action == 1:
            started = context.ticks()
            status = 0
            while not _word(data, 4):
                context.sleep(500)
                status, reply = routine(3)
                if status:
                    break
                if reply[4] == 1:
                    if elapsed_ticks(context.ticks(), started) <= 11000:
                        continue
                    status = 2000
                elif reply[4] != 2:
                    status = 2000
                break
            if not _word(data, 4) and status in (0, 2000):
                return status, False
            stop()
            return status, True
        if action == 2:
            stop()
        elif action == 3:
            comm.session(1, 1)
        return 0, True

    def _emps13(self, comm: TYComm, data: bytearray) -> tuple[int, bool]:
        action = _word(data, 0)

        def routine(phase: int, high: int, low: int) -> tuple[int, bytes]:
            return self._reply(
                comm, bytes((49, phase, high, low)), 5 if phase == 3 else 4, 3
            )

        def normal() -> None:
            comm.session(1, 1)

        if action == 0:
            status = self._open(comm)
            if not status:
                status = comm.session(3, 1, normal_first=True)
            return status, bool(status)
        if action == 4:
            normal()
            return 1009, True
        if action in (6, 7, 8):
            low = {6: 24, 7: 22, 8: 23}[action]
            status, _ = self._reply(comm, bytes((46, 32, low, 0)), 3, 2)
            if status:
                if action != 6 and (
                    status != 7 or comm.read_field("native_10b0") != 0x69
                ):
                    status = 1010
                normal()
            return status, bool(status)
        if action != 1:
            return 0, False
        status, _ = routine(1, 16, 2)
        if status:
            normal()
            return status, True
        status = 0
        while _word(data, 4) != 1:
            status, reply = routine(3, 16, 2)
            if status or reply[4] not in (1, 2):
                status = 1010
                break
            if reply[4] == 2:
                break
        if not status and not _word(data, 4):
            _put(data, 12, 1)
            return 0, False
        if _word(data, 8) == 1:
            routine(2, 17, 16)
        normal()
        return status, True

    def _bsm_support(self, export: str, comm: TYComm, data: bytearray) -> int:
        status = comm.initialize(0)
        if status:
            return status
        comm.configure(self.contract.legacy_setter, 150)
        status, raw, offsets = comm.support_snapshot(1)
        if status:
            return status
        older = export.startswith("Ex2BSM_03_04_")
        status, selected = _support_required(raw, offsets, 0x68, 10, 128)
        if status:
            return status
        _put(data, 20 if older else 16, selected)
        high = all(
            _support_required(raw, offsets, 0x7B, i, 255)[0] == 0 for i in (10, 11)
        )
        if older and high:
            status, _ = _support_required(raw, offsets, 0x6B, 3, 32)
            if status:
                return status
            status = 22
            if self.contract.bsm_optional_support:
                status, _ = _support_required(raw, offsets, 0x6A, 7, 64)
            selector = 2
            if not status:
                for index in (11, 12):
                    status, _ = _support_required(raw, offsets, 0x68, index, 255)
                    if status:
                        return status
                selector = 3
        else:
            selector = 2 if high else 1
            for index in range(8, 10) if high else range(4, 8):
                status, selected = _support_required(raw, offsets, 0x7B, index, 255)
                if status:
                    return status
                if index == (8 if high else 4):
                    _put(data, 16 if older else 12, selected)
        _put(data, 32 if older else 28, selector)
        count = 0
        for identifier, output in (
            ((0x68, 4), (0x6B, 8), (0x7B, 0)) if older else ((0x68, 4), (0x7B, 0))
        ):
            status, payload = _support_record(raw, offsets, identifier)
            if not status:
                count = sum(bool(value) for value in payload)
            _put(data, output, count + 2)
        status, raw, offsets = comm.support_snapshot(2)
        if status:
            return status
        identifier = data[28 if older else 24]
        status, _ = _support_required(raw, offsets, identifier, 3, 128)
        if status:
            return status
        _, payload = _support_record(raw, offsets, identifier)
        _put(data, 12 if older else 8, sum(bool(value) for value in payload) + 3)
        return 0

    def _bsm_history(self, export: str, comm: TYComm, data: bytearray) -> int:
        status = comm.initialize(0)
        if status:
            return status
        comm.configure(self.contract.legacy_setter, 256)
        comm.configure(self.contract.legacy_busy_setter, 256)
        if export.endswith("SupportCheck"):
            for kind, output in ((1, 0), (3, 4)):
                status, raw, offsets = comm.support_snapshot(kind)
                if status:
                    return status
                status, _ = _support_required(raw, offsets, 0x6C, 3, 0xF8)
                if status:
                    return status
                _, payload = _support_record(raw, offsets, 0x6C)
                _put(data, output, sum(bool(value) for value in payload) + 2)
            return 0
        clearing = export.endswith("ClearAbnormalHistory")
        if clearing:
            status, reply = self._raw(comm, b"\x3b\x6c\0")
            if status or len(reply) != 2:
                return 1000
        status, reply = self._raw(comm, b"\x21\x6c")
        if not status and (
            len(reply) != _word(data, 0) or len(reply) < 2 or reply[1] != 0x6C
        ):
            status = 3
        _put(data, 8, reply.ljust(3, b"\0")[2])
        return (2000 if status else 0) if clearing else status

    def _bsm_testmode(self, export: str, comm: TYComm, data: bytearray) -> int:
        status = comm.initialize(0)
        if status:
            return status
        comm.configure(self.contract.legacy_setter, 256)
        comm.configure(self.contract.legacy_busy_setter, 256)

        def normal() -> int:
            status, reply = self._raw(comm, b"\x10\1")
            return status or (0 if len(reply) == 1 else 3)

        if export.endswith("SupportCheck"):
            status, raw, offsets = comm.support_snapshot(1)
            if status:
                return status
            status, _ = _support_required(
                raw, offsets, 0x69, 3, 0x30 if _word(data, 4) else 0xC0
            )
            if not status:
                _, payload = _support_record(raw, offsets, 0x69)
                _put(data, 0, sum(bool(value) for value in payload) + 2)
            return status
        if export.endswith("ExitTestMode"):
            return normal()
        moving = export.endswith("Mov2TestMode")
        status, reply = self._raw(comm, b"\x10\x60" if moving else b"\x10\x5f")
        if not status:
            if len(reply) != (1 if moving else 2):
                status = 3
            elif not moving and reply[1] != 0x60:
                return -0x6FFFFFFE
        if status:
            if moving:
                return -0x6FFFFFFF
            normal()
            return status
        status, reply = self._raw(comm, b"\x21\x69")
        if not status and (
            len(reply) != _word(data, 0) or len(reply) < 2 or reply[1] != 0x69
        ):
            status = 3
        else:
            byte = reply.ljust(3, b"\0")[2]
            data[8] = (byte & 0x30) >> 4 if _word(data, 4) else byte >> 6
        if status:
            normal()
        return status

    def _abs21(self, export: str, comm: TYComm, data: bytearray) -> int:
        status = comm.initialize(0)
        if status:
            return status
        comm.configure(self.contract.legacy_setter, 150)
        if export.endswith("SupportCheck"):
            data[:13] = bytes(13)
            status, raw, offsets = comm.support_snapshot(1)
            if status:
                return status
            status, payload = _support_record(raw, offsets, 0xBA)
            if status or not any(payload):
                return status or 22
            _put(data, 16, sum(bool(value) for value in payload) + 2)
            for output, index, bit in (
                *((i, 3, 128 >> i) for i in range(8)),
                *((i + 8, 4, 128 >> i) for i in range(5)),
            ):
                status, _ = _support_required(raw, offsets, 0xBA, index, bit)
                if not status:
                    data[output] = 1
            return 0
        if export.endswith("ChangeMode"):
            status, reply = self._raw(comm, bytes((16, 64 if _word(data, 20) else 1)))
            return status or (0 if len(reply) == 1 else 3)
        status, reply = self._raw(comm, b"\x21\xba")
        if not status:
            if len(reply) != _word(data, 16) or len(reply) < 2 or reply[1] != 0xBA:
                return 3
            status = 1000
        if status == 1000:
            if len(reply) < 2 or 13 + len(reply) - 2 > len(data):
                raise ValueError("ABS sensor payload exceeds selected output capacity")
            # Native copies on status1000 too, including overwriting saved metadata.
            data[13 : 11 + len(reply)] = reply[2:]
        return status

    def _abs18(
        self, export: str, comm: TYComm, data: bytearray, context: ChassisContext
    ) -> int:
        status = comm.initialize(0)
        if status:
            return status
        comm.configure(self.contract.legacy_setter, 150)
        if export.endswith("SupportCheck"):
            status, raw, offsets = comm.support_snapshot(1)
            if status:
                return status
            selected_offset = 0
            for identifier, index in ((5, 3), (5, 4), (6, 5), (6, 6), (0x43, 3)):
                status, selected = _support_required(
                    raw, offsets, identifier, index, 255
                )
                if status:
                    return status
                if identifier == 6 and index == 5:
                    selected_offset = selected
            _put(data, 0, selected_offset)
            for identifier, output in ((5, 4), (6, 8), (0x43, 12)):
                _, payload = _support_record(raw, offsets, identifier)
                _put(data, output, sum(bool(value) for value in payload) + 2)
            status, raw, offsets = comm.support_snapshot(3)
            if status:
                return status
            status, _ = _support_required(raw, offsets, 12, 3, 48)
            if status:
                return status
            _, payload = _support_record(raw, offsets, 12)
            _put(data, 16, len(payload) + 2)
            return 0
        for identifier, length_field in ((6, 8), (5, 4), (0x43, 12)):
            status, reply = self._raw(comm, bytes((0x21, identifier)))
            if status:
                return status
            if (
                len(reply) != _word(data, length_field)
                or len(reply) < 2
                or reply[1] != identifier
            ):
                return 3
            padded = reply.ljust(0x1020, b"\0")
            if identifier == 6:
                offset = _bounded_word(data, 0, 0x101E)
                if (
                    not 0x7F88
                    <= int.from_bytes(padded[offset : offset + 2], "big")
                    <= 0x8078
                ):
                    return 1000
            elif identifier == 5:
                if not 0x74 <= padded[2] <= 0x8C:
                    return 1001
                if not 0x74 <= padded[3] <= 0x8C:
                    return 1002
            elif padded[2] >= 8:
                return 1003
            if identifier != 0x43:
                context.sleep(500)
        length = _bounded_word(data, 16)
        request = (b"\x3b\x0c\x30" + bytes(max(0, length - 3)))[:length]
        status, reply = self._raw(comm, request)
        padded = reply.ljust(3, b"\0")
        if not status and padded[1] != 12:
            return 3
        if padded[2] in (0x12, 0x22, 0x33):
            return 1004
        if not status:
            context.sleep(5000)
        return status

    def _asus05(
        self, export: str, comm: TYComm, data: bytearray, context: ChassisContext
    ) -> int:
        checking = export.endswith(("CheckModifiedVheight", "CheckReturnedVheight"))
        started = context.ticks() if checking else 0
        status = comm.initialize(0)
        if status:
            return status
        comm.configure(self.contract.legacy_setter, 150)

        def send(request: bytes, length: int) -> int:
            status, reply = self._raw(comm, request)
            return status or (0 if len(reply) == length else 3)

        if checking:
            modified = export.endswith("CheckModifiedVheight")
            while True:
                context.sleep(1000)
                if modified and data[13] == 1:
                    return 1000
                status = self._asus04_read(comm, data)
                if status:
                    if modified:
                        send(b"\x10\1", 1)
                    return status
                if not data[12] & 32:
                    return 0
                if elapsed_ticks(context.ticks(), started) >= (
                    26001 if modified else 50001
                ):
                    return 1001
        if export.endswith("ReturnVheightStart"):
            return send(b"\x30", 1)
        if export.endswith("ModifyVheightTimeOver"):
            return send(b"\x10\1", 1)
        if export.endswith("LearnKneelDownVheight"):
            for request in (b"\x3b\x17", b"\x3b\7"):
                status = send(request, 2)
                if status:
                    send(b"\x10\1", 1)
                    return status
                context.sleep(500)
            status = self._asus04_read(comm, data)
            normal = send(b"\x10\1", 1)
            return status or normal or (0 if data[12] & 16 else 1002)
        starting = export.endswith("ModifyVheightDownStart")
        if starting:
            status = send(b"\x10\x60\0", 1)
            if status:
                return status
        length = _bounded_word(data, 8)
        prefix = b"\x30\6\x19\1" if starting else b"\x30\6\0\0"
        status = send((prefix + bytes(max(0, length - 4)))[:length], 2)
        if not starting or status:
            normal = send(b"\x10\1", 1)
            return status or normal
        return 0

    def _asus04_read(self, comm: TYComm, data: bytearray) -> int:
        status, reply = self._raw(comm, b"\x21\x10")
        if not status and len(reply) != _word(data, 4):
            status = 3
        data[12] = reply.ljust(0x1020, b"\0")[_bounded_word(data, 0, 0x101F)]
        return status

    def _asus04(
        self, export: str, comm: TYComm, data: bytearray, context: ChassisContext
    ) -> int:
        checking = export.endswith("CheckReturnedVhight")
        started = context.ticks() if checking else 0
        status = comm.initialize(0)
        if not status or checking:
            comm.configure(self.contract.legacy_setter, 150)
        if export.endswith("ModifyVhight"):
            if status:
                return status
            up = _word(data, 16) == 200
            length = _bounded_word(data, 8)
            request = (
                bytes((0x30, 6, 20 if up else 0, int(up))) + bytes(max(0, length - 4))
            )[:length]
            status, reply = self._raw(comm, request)
            return status or (0 if len(reply) == 2 else 3)
        if checking:
            if status:
                return status
            while True:
                context.sleep(1000)
                status = self._asus04_read(comm, data)
                if status or not data[12] & 32:
                    return status
                if elapsed_ticks(context.ticks(), started) >= 50001:
                    return 99
        if export.endswith("ReturnVhight"):
            if status:
                return status
            status, reply = self._raw(comm, b"\x30")
            return status or (0 if len(reply) == 1 else 3)
        if status:
            self._raw(comm, b"\x10\1\0")
            return status
        context.sleep(1000)
        for request, length in ((b"\x10\x60\0", 1), (b"\x3b\x17", 2), (b"\x3b\7", 2)):
            status, reply = self._raw(comm, request)
            if not status and len(reply) != length:
                status = 3
            if status:
                self._raw(comm, b"\x10\1\0")
                return status
        status, reply = self._raw(comm, b"\x10\1\0")
        if not status and len(reply) != 1:
            status = 3
        if not status:
            status = self._asus04_read(comm, data)
            if not status and not data[12] & 16:
                status = 99
        return status

    def _abs17(self, export: str, comm: TYComm, data: bytearray) -> int:
        status = comm.initialize(0)
        if status:
            return status
        comm.configure(self.contract.legacy_setter, 150)
        if export.endswith("SupportCheck"):
            for kind, identifier, checks, output in (
                (1, 10, (11, 12), 4),
                (3, 0xF1, (3,), 8),
            ):
                status, raw, offsets = comm.support_snapshot(kind)
                if status:
                    return status
                selected_offset = 0
                for index in checks:
                    status, selected = _support_required(
                        raw, offsets, identifier, index, 255
                    )
                    if status:
                        return status
                    if kind == 1 and index == 11:
                        selected_offset = selected
                if kind == 1:
                    _put(data, 0, selected_offset)
                _, payload = _support_record(raw, offsets, identifier)
                _put(data, output, sum(bool(value) for value in payload) + 2)
            return 0
        if export.endswith("GetABSInfo"):
            status, reply = self._raw(comm, b"\x21\x0a")
            if not status:
                if len(reply) != _word(data, 4) or len(reply) < 2 or reply[1] != 10:
                    return 3
                offset = _bounded_word(data, 0, 0x101E)
                data[12:14] = reply.ljust(0x1020, b"\0")[offset : offset + 2]
            return status
        length = _bounded_word(data, 8)
        for mode in (2, 1):
            request = (bytes((0x3B, 0xF1, mode)) + bytes(max(0, length - 3)))[:length]
            status, reply = self._raw(comm, request)
            if status or reply.ljust(2, b"\0")[1] != 0xF1:
                return 1000
        return 0

    def _drs02_start(self, comm: TYComm, data: bytearray) -> int:
        length = _bounded_word(data, 16)
        request = (b"\x30\1\xff\x21\0\6\0" + bytes(max(0, length - 7)))[:length]
        status, reply = self._raw(comm, request)
        return status or (0 if len(reply) == 2 and reply[1] == 1 else 3)

    def _drs02_read(self, comm: TYComm, data: bytearray) -> int:
        status, reply = self._raw(comm, b"\x21\x0e")
        if not status and (
            len(reply) != _word(data, 12) or len(reply) < 2 or reply[1] != 14
        ):
            status = 3
        padded = reply.ljust(0x1020, b"\0")
        data[24:27] = bytes(
            (
                padded[_bounded_word(data, 0, 0x101F)],
                padded[_bounded_word(data, 4, 0x101F)] & 63,
                padded[_bounded_word(data, 8, 0x101F)],
            )
        )
        return status

    def _drs02(
        self, export: str, comm: TYComm, data: bytearray, context: ChassisContext
    ) -> tuple[int, bool]:
        if export.endswith(("SupportCheck", "ReadModeStatus")):
            comm.select_target(0x790, 0)
            status = comm.initialize(0)
            if status:
                return status, True
        comm.configure(self.contract.legacy_setter, 150)
        if export.endswith("SupportCheck"):
            for kind, identifier, checks, output, extra in (
                (1, 14, ((4, 255), (5, 63), (9, 32)), 12, 2),
                (2, 1, ((3, 255), (4, 255), (5, 31), (6, 255)), 16, 3),
            ):
                status, raw, offsets = comm.support_snapshot(kind)
                if status:
                    return status, True
                indices = []
                for index, mask in checks:
                    status, selected = _support_required(
                        raw, offsets, identifier, index, mask
                    )
                    if status:
                        return status, True
                    indices.append(selected)
                if kind == 1:
                    for output_index, selected in enumerate(indices):
                        _put(data, output_index * 4, selected)
                _, payload = _support_record(raw, offsets, identifier)
                _put(data, output, sum(bool(value) for value in payload) + extra)
            return 0, True
        if export.endswith("ReadRadarCruiseData"):
            status = 0
            if _word(data, 20) == 2:
                status = self._drs02_start(comm, data)
                if not status:
                    _put(data, 20, 0)
            if not status:
                status = self._drs02_read(comm, data)
            if not status:
                return 0, False
        else:
            status = self._drs02_start(comm, data)
            if not status:
                started, last = context.ticks(), 0
                while (elapsed := elapsed_ticks(context.ticks(), started)) < 5000:
                    if elapsed - last > 1999:
                        status = self._drs02_start(comm, data)
                        last = elapsed
                        if status:
                            break
                    status = self._drs02_read(comm, data)
                    if status:
                        break
                    if data[26] & 32:
                        status = self._drs02_read(comm, data)
                        if not status:
                            return 0, False
                        break
                    context.sleep(1000)
                else:
                    status = 1460
        self._raw(comm, b"\x30")
        return status, True

    def _drs03_start(self, comm: TYComm, data: bytearray, phase: int) -> int:
        length = _bounded_word(data, 4)
        request = (
            bytes((0x30, 1, 255, 0x13, 0, phase, 0)) + bytes(max(0, length - 7))
        )[:length]
        status, reply = self._raw(comm, request)
        return status or (0 if len(reply) == 2 and reply[1] == 1 else 3)

    def _drs03_read(self, comm: TYComm, data: bytearray) -> int:
        status, reply = self._raw(comm, b"\x21\x0e")
        if not status:
            if len(reply) != _word(data, 0) or len(reply) < 2 or reply[1] != 14:
                return 3
            padded = reply.ljust(0x1020, b"\0")
            data[12:15] = bytes(
                (padded[3], padded[4] & 63, padded[_bounded_word(data, 16, 0x101F)])
            )
        return status

    def _drs03_wait(
        self,
        comm: TYComm,
        data: bytearray,
        offset: int,
        mask: int,
        context: ChassisContext,
    ) -> int:
        context.sleep(1000)
        started = context.ticks()
        while elapsed_ticks(context.ticks(), started) < (
            15000 if offset == 2 else 5000
        ):
            status, reply = self._raw(comm, b"\x21\x0e")
            if status:
                return status
            if len(reply) != _word(data, 0) or len(reply) < 2 or reply[1] != 14:
                return 3
            observed = reply.ljust(0x1020, b"\0")[offset] & mask == mask
            if observed == (offset == 2):
                return 0
            context.sleep(1000)
        return 1000

    def _drs03(
        self, export: str, comm: TYComm, data: bytearray, context: ChassisContext
    ) -> tuple[int, bool]:
        if export.endswith(("SupportCheck", "ReadModeStatus")):
            comm.select_target(0x790, 0)
            status = comm.initialize(0)
            if status:
                return status, True
        comm.configure(self.contract.legacy_setter, 150)
        if export.endswith("SupportCheck"):
            for kind, identifier, checks, output, extra in (
                (1, 14, ((3, 4), (4, 255), (5, 63), (9, 128)), 0, 2),
                (2, 1, ((3, 255), (4, 255), (5, 31), (6, 255)), 4, 3),
            ):
                status, raw, offsets = comm.support_snapshot(kind)
                if status:
                    return status, True
                for index, mask in checks:
                    status, selected = _support_required(
                        raw, offsets, identifier, index, mask
                    )
                    if status:
                        return status, True
                if kind == 1:
                    _put(data, 16, selected)
                _, payload = _support_record(raw, offsets, identifier)
                _put(data, output, sum(bool(value) for value in payload) + extra)
            return 0, True
        if export.endswith("EndProcess"):
            self._raw(comm, b"\x30")
            status = self._drs03_wait(
                comm, data, _bounded_word(data, 16, 0x101F), 128, context
            )
            if not status:
                status = self._drs03_start(comm, data, 1)
                if not status:
                    status = self._drs03_wait(comm, data, 2, 4, context)
                self._raw(comm, b"\x30")
            return status, True
        if export.endswith("ReadModeStatus"):
            status = self._drs03_start(comm, data, 0)
            if not status:
                context.sleep(1000)
                started = context.ticks()
                last = elapsed_ticks(context.ticks(), started)
                while (elapsed := elapsed_ticks(context.ticks(), started)) < 5000:
                    if elapsed - last > 1999:
                        status = self._drs03_start(comm, data, 0)
                        last = elapsed
                        if status:
                            break
                    status = self._drs03_read(comm, data)
                    if status:
                        break
                    if data[14] & 128:
                        status = self._drs03_read(comm, data)
                        if not status:
                            return 0, False
                        break
                    context.sleep(1000)
                else:
                    status = 1000
            self._raw(comm, b"\x30")
            return status, True
        status = 0
        if _word(data, 8) >= 2:
            status = self._drs03_start(comm, data, 0)
            if not status:
                _put(data, 8, 0)
        if not status:
            status = self._drs03_read(comm, data)
        if not status:
            return 0, False
        self._raw(comm, b"\x30")
        return status, True

    def _abs46(self, comm: TYComm, data: bytearray, context: ChassisContext) -> int:
        status = self._open(comm)
        if status:
            return status
        status = comm.session(3, 1)
        if status:
            return status
        for rid in (7, 8):
            context.sleep(50)
            status, _ = self._reply(comm, bytes((0x31, 1, 0x10, rid)), 4, 3)
            if status:
                context.sleep(50)
                comm.session(1, 1, stop_on_error=True)
                return status
            while not _word(data, 0):
                context.sleep(1000)
                status, reply = self._reply(comm, bytes((0x31, 3, 0x10, rid)), 5, 3)
                if status:
                    break
                if reply[4] == 2:
                    break
                if reply[4] != 1:
                    status = 3
                    break
            if rid == 8 or status or _word(data, 0):
                context.sleep(50)
                comm.session(1, 1, stop_on_error=True)
                return status
        return 0

    def _abs30(self, comm: TYComm, data: bytearray) -> int:
        status = comm.initialize(0)
        if status:
            return status
        comm.configure(self.contract.retry_setter, 0)
        comm.configure(self.contract.pending_setter, 180000)
        action = _word(data, 0)
        if action == 0:
            status = self._normal(comm)
            if not status:
                status = comm.session(3, 1)
            if status:
                return status
            for request, offset, mask in (
                (b"\x22\1\1", 5, 128),
                (b"\x22\x10\0", 8, 8),
                (b"\x22\x10\x2d", 5, 8),
                (b"\x31\1\x10\1", 6, 64),
                (b"\x31\1\x11\0", 5, 4),
            ):
                status, reply = self._reply(comm, request, offset + 1, len(request) - 1)
                if not status and reply[offset] & mask != mask:
                    status = 22
                if status:
                    break
            return self._normal(comm) or status
        if action == 1:
            status, _ = self._reply(comm, b"\x31\1\x11\x0e\1", 4, 3)
            if not status:
                status, reply = self._reply(comm, b"\x22\x10\x2d", 7, 2)
                if not status and not reply[6] & 8:
                    status = 3
            return status
        return 0

    def _emps07(self, export: str, comm: TYComm, data: bytearray) -> int:
        status = comm.initialize(0)
        if status:
            return status
        comm.configure(self.contract.legacy_setter, 150)
        if export.endswith("ClearTheAssistMap"):
            status, reply = self._raw(comm, b"\x3b\2")
            if not status:
                return 0 if len(reply) == 2 and reply[1] == 2 else 3
            return {b"\x7f\x3b\x22": 1002, b"\x7f\x3b\x10": 1003}.get(reply, status)
        status, reply = self._raw(comm, b"\x13\x81")
        if status:
            return status
        padded = reply.ljust(0x1020, b"\0")
        for offset in range(2, 2 + 2 * padded[1], 2):
            if int.from_bytes(padded[offset : offset + 2], "big") in (0x5581, 0x5534):
                return 1001
        status, reply = self._raw(comm, b"\xa9\3")
        if not status:
            padded = reply.ljust(4, b"\0")
            if padded[1] != 3:
                return 3
            data[:2] = padded[2:4]
        return status

    def _asus08_open(self, comm: TYComm) -> int:
        status = comm.initialize(0)
        if not status:
            comm.configure(self.contract.retry_setter, 0)
            comm.configure(self.contract.pending_setter, 180000)
            if self.contract.asus08_retries:
                comm.configure(self.contract.retries_setter, 0)
        return status

    def _asus08(
        self, export: str, comm: TYComm, data: bytearray, context: ChassisContext
    ) -> tuple[int, bool]:
        state_key = self.contract.asus08_state
        if export.endswith("ModeTransEnterHeightCtrlProhibit"):
            context.state[state_key] = 0
            status = self._asus08_open(comm)
            if status:
                return status, True
            if self._normal(comm) or comm.session(3, 1):
                return 1000, True
            status, _ = self._reply(comm, b"\x2e\x21\1\1", 3, 2)
            if not status and _word(data, 0) != 2001:
                context.state[state_key] = 1
                return 0, False
            normal = 1000 if self._normal(comm) else 0
            return status or normal, True
        retained = bool(context.state.get(state_key, 0))
        if not retained:
            status = self._asus08_open(comm)
            if status:
                return status, True
        status = self._asus_pressure(comm, data)
        if status:
            self._normal(comm)
            return status, True
        return 0, not retained

    def _asus_motion(
        self, export: str, comm: TYComm, data: bytearray, context: ChassisContext
    ) -> tuple[int, bool]:
        air = export.endswith("AirPressure")
        dual = export.startswith("Ex2ASUS_07_")
        if air:
            status = comm.initialize(0)
            if status:
                return status, True
            comm.configure(self.contract.retry_setter, 0)
            comm.configure(self.contract.pending_setter, 180000)
            status = self._normal(comm)
            if not status:
                status = comm.session(3, 1)
            if status:
                return 1000, True
        selected = _word(data, 4)
        if dual:
            if air:
                phases = (
                    ((3, 2, 0x88), (12, 4, 0x91))
                    if selected == 2001
                    else ((12, 2, 0x84), (3, 4, 0x87))
                )
            else:
                phases = (
                    ((12, 2, 0x8A), (3, 4, 0xA2))
                    if selected == 2001
                    else ((3, 2, 0x85), (12, 4, 0x9F))
                )
        else:
            mask = {2001: 2, 2002: 1, 2003: 8}.get(selected, 4)
            phases = (
                (
                    mask,
                    2 if air else 4,
                    (0x82 if selected in (2001, 2002) else 0x81)
                    if air
                    else (0x8F if selected in (2001, 2002) else 0x8C),
                ),
            )
        for phase in phases:
            status, _ = self._reply(
                comm, b"\x31\1\x11\1" + bytes(phase), 4, 3, positive_service=False
            )
            if status:
                self._normal(comm)
                return status, True
            context.sleep(100)
            started = context.ticks()
            while True:
                status, reply = self._reply(
                    comm, b"\x31\3\x11\1", 5, 3, positive_service=False
                )
                if not status:
                    status = {1: 1001, 2: 0}.get(reply[4], 1002)
                if status != 1001 or elapsed_ticks(context.ticks(), started) >= (
                    40001 if dual else 20001
                ):
                    break
            if status:
                self._raw(comm, b"\x31\2\x11\1")
                self._normal(comm)
                return status, True
        return (0, False) if air else (self._normal(comm), True)

    def _4wd03(
        self, export: str, comm: TYComm, data: bytearray, context: ChassisContext
    ) -> int:
        status = comm.initialize(0)
        if status:
            return status
        comm.configure(self.contract.legacy_setter, 150)
        if export.endswith("SupportCheck"):
            for kind, identifier in ((1, 0xA6), (3, 11)):
                status, raw, offsets = comm.support_snapshot(kind)
                if status:
                    return status
                status, _ = _support_required(raw, offsets, identifier, 3, 128)
                if status:
                    return status
                if kind == 1:
                    _, payload = _support_record(raw, offsets, identifier)
                    _put(data, 0, sum(bool(value) for value in payload))
            return 0
        status, reply = self._raw(comm, b"\x3b\x0b\x80")
        if not status and reply != b"\x7b\x0b":
            status = 3
        if not status:
            context.sleep(500)
            status, reply = self._raw(comm, b"\x21\xa6")
            if not status and (
                len(reply) != _word(data, 0) + 2 or reply[:2] != b"\x61\xa6"
            ):
                status = 3
            if not status:
                if reply.ljust(3, b"\0")[2] & 128:
                    return 0
                status = 1000
        self._raw(comm, b"\x3b\x0b\0")
        return status

    def _asus_support(self, comm: TYComm, data: bytearray) -> int:
        status = comm.initialize(0)
        if status:
            return status
        comm.configure(self.contract.legacy_setter, 150)
        for kind, identifier, index, mask, output, extra in (
            (1, 16, 5, 48, 4, 2),
            (2, 6, 3, 1, 8, 3),
        ):
            status, raw, offsets = comm.support_snapshot(kind)
            if status:
                return status
            status, selected = _support_required(raw, offsets, identifier, index, mask)
            if status:
                return status
            if kind == 1:
                _put(data, 0, selected)
            _, payload = _support_record(raw, offsets, identifier)
            _put(data, output, sum(bool(value) for value in payload) + extra)
        return 0

    def _ars_support(self, export: str, comm: TYComm, data: bytearray) -> int:
        first = export == "Ex2ARS_01_A8SupportCheck"
        if first:
            comm.configure(self.contract.legacy_setter, 150)
        status = comm.initialize(0)
        if status:
            return status
        if not first:
            comm.configure(self.contract.legacy_setter, 150)
        for kind, identifier, indexes, output, extra in (
            (1, 9 if first else 0x81, (3, 4), 0, 2),
            (2, 5 if first else 2, (3,) if first else tuple(range(3, 9)), 4, 3),
        ):
            status, raw, offsets = comm.support_snapshot(kind)
            if status:
                return status
            for index in indexes:
                status, _ = _support_required(raw, offsets, identifier, index, 255)
                if status:
                    return status
            status, payload = _support_record(raw, offsets, identifier)
            count = sum(bool(value) for value in payload)
            _put(data, output, count + extra)
            if status or not count:
                return status or 22
            if kind == 1 and not first:
                status, _ = _support_required(raw, offsets, 0x84, 3, 255)
                optional = 0
                if not status:
                    _, payload = _support_record(raw, offsets, 0x84)
                    optional = sum(bool(value) for value in payload) + 2
                _put(data, 8, optional)
        return 0

    def _vgrs04(
        self, export: str, comm: TYComm, data: bytearray, context: ChassisContext
    ) -> int:
        def send(request: bytes, length: int, echo: int | None = None) -> int:
            status, reply = self._raw(comm, request)
            if request == b"\x30":
                return status if len(reply) == 1 else 3
            return status or (
                0 if len(reply) == length and (echo is None or reply[1] == echo) else 3
            )

        comm.configure(self.contract.legacy_setter, 150)
        status = comm.initialize(0)
        if status:
            return status
        if export.endswith("ClearDTC"):
            status = send(b"\x10\x40", 1)
            if not status:
                context.sleep(500)
                status = send(b"\xa6\1", 1)
                if not status:
                    context.sleep(500)
                    status = send(b"\x14", 1)
            return status
        if export.endswith("StartLockRelease"):
            status = send(b"\x10\x40", 1)
            if not status:
                context.sleep(500)
                length = _bounded_word(data, 0)
                status = send(
                    (b"\x30\2\0\1" + bytes(max(0, length - 4)))[:length], 2, 2
                )
                if status:
                    send(b"\x30", 1)
            return status
        if export.endswith("EndLockRelease"):
            context.sleep(500)
            status = send(b"\x30", 1)
            if status:
                send(b"\x30", 1)
                return status
            return send(b"\x10\1", 1)
        if export.endswith("EndNeutralCompMode"):
            return send(b"\x10\1", 1)
        status = send(b"\x14", 1)
        if not status:
            context.sleep(500)
            status = send(b"\x10\x40", 1)
            if not status:
                context.sleep(500)
                status = send(b"\x10\x60", 1)
        return status

    def _asus13(
        self, export: str, comm: TYComm, data: bytearray, context: ChassisContext
    ) -> int:
        if export.endswith("SupportCheck"):
            status = comm.initialize(0)
            if status:
                return status
            comm.configure(self.contract.legacy_setter, 150)
            status, raw, offsets = comm.support_snapshot(1)
            if status:
                return status
            status, index = _support_required(raw, offsets, 0x10, 5, 0x30)
            if status:
                return 3
            _put(data, 8, index)
            status, raw, offsets = comm.support_snapshot(2)
            if status:
                return status
            status, _ = _support_required(raw, offsets, 6, 3, 1)
            if status:
                return 3
            _, payload = _support_record(raw, offsets, 6)
            _put(data, 12, sum(bool(value) for value in payload))
            return 0
        if export.endswith("TestStart"):
            status = comm.initialize(0)
            if status:
                return status
            comm.configure(self.contract.legacy_setter, 150)
            status, reply = self._raw(comm, b"\x10\x60\0")
            if not status and not reply:
                status = 3
            if status:
                return status
            length = _bounded_word(data, 12, 0x101D)
            request = (self.contract.asus13_start + bytes(max(0, length - 1)))[
                : length + 3
            ]
            status, reply = self._raw(comm, request)
            if not status and (len(reply) < 2 or reply[1] != 6):
                status = 3
            if status:
                self._raw(comm, b"\x10\1")
            return status
        if export in ("Ex2ASUS_13_GetHeight", "Ex2ASUS_13_GetHeightSec50"):
            cleanup = export.endswith("Sec50")
            status = comm.initialize(0)
            if status:
                return status
            comm.configure(self.contract.legacy_setter, 150)
            while not _word(data, 0):
                if not cleanup and _word(data, 4):
                    return 1000
                context.sleep(1000)
                status, reply = self._raw(comm, b"\x21\x10")
                offset = _bounded_word(data, 8, 0x101F)
                if not status and (len(reply) < max(2, offset + 1) or reply[1] != 16):
                    status = 3
                if status:
                    return status if cleanup else 1002
                if not reply[offset] & 32:
                    return 0
            return 1003 if cleanup else 1004
        if export.endswith("HeightOffset"):
            status = 0
            for request in (b"\x3b\x17", b"\x3b\7", b"\x21\x10"):
                status, reply = self._raw(comm, request)
                minimum = (
                    max(2, _bounded_word(data, 8, 0x101F) + 1)
                    if request[0] == 0x21
                    else 2
                )
                if not status and (len(reply) < minimum or reply[1] != request[1]):
                    status = 3
                if status:
                    break
                if request[0] == 0x3B:
                    context.sleep(500)
            normal, normal_reply = self._raw(comm, b"\x10\1")
            normal = normal or (0 if normal_reply else 3)
            if status:
                return status
            return normal or (0 if reply[_bounded_word(data, 8, 0x101F)] & 16 else 1003)
        if export.endswith("TestStop"):
            status = comm.initialize(0)
            if status:
                return status
            comm.configure(self.contract.legacy_setter, 150)
            request = self.contract.asus13_stop
            if len(request) > 1:
                length = _bounded_word(data, 12, 0x101D)
                request = (request + bytes(max(0, length - 1)))[: length + 3]
            status, reply = self._raw(comm, request)
            if len(request) > 1:
                return status or (0 if len(reply) >= 2 and reply[1] == 6 else 3)
            return status or (0 if reply else 3)
        status = 0
        if export.endswith("NormalMode005"):
            status, reply = self._raw(comm, b"\x30\6\0\0")
            if not status and (len(reply) < 2 or reply[1] != 6):
                status = 3
        normal, reply = self._raw(comm, b"\x10\1")
        normal = normal or (0 if reply else 3)
        if export.endswith("NormalMode"):
            return 3
        return status or normal or (1001 if export.endswith("005") else 1003)

    def _arguments(self, export: str, args: tuple[object, ...], mode: int) -> bytearray:
        # Native fields remain live while a scheduler worker runs.
        if export in ("Ex2PSAABS_03_StartActiveTest", "Ex2PSAABS_03_ConfirmStatus"):
            data = _buffer(args, 16)
        elif export in (
            "Ex2BSM_09_10_19_20_SendMessage",
            "Ex2BSM_11_12_21_22_SendMessage",
        ):
            data = _buffer(
                args, 26 if export == "Ex2BSM_09_10_19_20_SendMessage" else 25
            )
        elif export == "Ex2AHC_04_SendMessage":
            data = _buffer(args, 0x104D)
            if _word(data, 0) == 1:
                _bounded_word(data, 20, min(0x101D, len(data) - 24))
        elif export in ("Ex24WD_05_SendMessage", "Ex24WD_05_WriteHistoryData"):
            data = _buffer(args, 0x56)
        elif export == "Ex24WD_05_SupportCheck":
            data = _buffer(args, 80)
        elif export == "Ex24WD_08_SendMessage":
            data = _buffer(args, 56)
        elif export == "Ex24WD_06_SendMessage":
            data = _buffer(args, 33)
        elif export == "Ex2AWD_04_ReadValues":
            data = _buffer(args, 45)
        elif export == "Ex2TPW_03_SendMessage":
            data = _buffer(args, 0xC4)
        elif export == "Ex2TPW_08_SendMessage":
            data = _buffer(args, 28)
        elif export == "Ex2TPW_06_SendMessage":
            data = _buffer(args, 40)
        elif export == "Ex2TPW_13_SendMessage":
            data = _buffer(args, 36)
        elif export == "Ex2DRS_04_SendMessage":
            data = _buffer(args, 0x1064)
        elif export == "Ex2ARS_05_SendMessage":
            data = _buffer(args, 14)
        elif (
            export in ("Ex2BSM_27_SendMessage", "Ex2BSM_28_SendMessage")
            or export == "Ex2ARS_04_SendMessage"
        ):
            data = _buffer(args, 8)
        elif export in ("Ex2ARS_02_InitCompVal", "Ex2ARS_03_ActiveTest"):
            data = _buffer(args, 12)
            if any(_word(data, i) > 0x1020 for i in (0, 8)):
                raise ValueError("ARS selected response length exceeds native capacity")
        elif export == "Ex2ARS_01_ReturnActuatorCenterPos":
            data = _buffer(args, 8)
            if any(_word(data, i) > 0x1020 for i in (0, 4)):
                raise ValueError("ARS selected length exceeds native capacity")
        elif export == "Ex2VGRS_04_SupportCheck":
            data = _buffer(args, 4)
        elif export == "Ex2EMPS_13_SendMessage":
            data = _buffer(args, 16)
        elif export.startswith("Ex2ABS4WD_01_"):
            data = _buffer(args, 8)
            if not export.endswith("SupportCheck") and any(
                _word(data, i) > 0x101E for i in (0, 4)
            ):
                raise ValueError("ABS4WD selected read length exceeds native capacity")
        elif export == "Ex2ABS_51_SendMessage":
            data = _buffer(args, 0x204A)
            if int.from_bytes(data[4:6], "little") > 1 or any(
                int.from_bytes(data[i : i + 2], "little") > 0x101D for i in (6, 8)
            ):
                raise ValueError("ABS selected snapshot layout exceeds native capacity")
        elif export in (
            "Ex2ASUS_08_StartCompressRaisingCtrl",
            "Ex2ASUS_08_StartTankPressLowCtrl",
        ):
            data = _buffer(args, 20)
        elif export == "Ex2ABS_41_DriveSolenoid":
            data = _buffer(args, 4)
        elif export == "Ex2BSM_13_14_23_24_SendMessage":
            data = _buffer(args, 0x1024)
        elif export in ("Ex2BSM_03_04_SupportCheck", "Ex2BSM_05_06_SupportCheck"):
            data = _buffer(args, 36 if export.startswith("Ex2BSM_03_04_") else 32)
        elif export.startswith(
            ("Ex2BSM_01_02_", "Ex2BSM_07_08_")
        ) and not export.endswith("ExitTestMode"):
            data = _buffer(args, 12 if export.startswith("Ex2BSM_07_08_") else 9)
            if not export.endswith("SupportCheck") and _word(data, 0) > 0x1020:
                raise ValueError("BSM selected read length exceeds native capacity")
        elif export in (
            "Ex2BSM_03_04_ActiveTest",
            "Ex2BSM_03_04_ActiveTestCon3_5",
            "Ex2BSM_05_06_ActiveTest",
        ):
            older = export.startswith("Ex2BSM_03_04_")
            data = _buffer(args, 36 if older else 32)
            if (
                any(
                    _word(data, i) > 0x1020
                    for i in ((0, 4, 8, 12) if older else (0, 4, 8))
                )
                or _word(data, 20 if older else 16) >= 0x1020
                or _word(data, 16 if older else 12) > 0x101C
            ):
                raise ValueError(
                    "BSM selected lengths or byte offsets exceed native capacity"
                )
        elif export == "Ex2BSM_15_16_25_26_SendMessage":
            data = _buffer(args, 0x102C)
            if not 2 <= _word(data, 0x1024) <= 0x101D:
                raise ValueError("BSM selected payload length exceeds native buffer")
        elif export.startswith("Ex24WD_03_"):
            data = _buffer(args, 4)
            if export.endswith("ChangePreventionMode") and _word(data, 0) > 0x101E:
                raise ValueError("4WD selected response length exceeds native capacity")
        elif export.startswith("Ex24WD_07_"):
            data = _buffer(args, 80)
            if export != "Ex24WD_07_SupportCheck" and not (
                _word(data, 32) or _word(data, 36)
            ):
                raise ValueError(
                    "4WD clear requires selected supported routine metadata"
                )
        elif export == "Ex2ASUS_08_ReadPressureSensor":
            data = _buffer(args, 20)
        elif export == "Ex2ASUS_08_ModeTransEnterHeightCtrlProhibit":
            data = _buffer(args, 4)
        elif export in (
            "Ex2ASUS_06_LiftRise",
            "Ex2ASUS_06_AirPressure",
            "Ex2ASUS_07_LiftRise",
            "Ex2ASUS_07_AirPressure",
        ):
            data = _buffer(args, 8)
        elif export.startswith("Ex2ASUS_10_"):
            data = _buffer(args, 2 if self.contract.asus10_discover else 1)
        elif export in (
            "Ex2ASUS_13_GetHeight",
            "Ex2ASUS_13_GetHeightSec50",
            "Ex2ASUS_13_HeightOffset",
        ):
            data = _buffer(args, 12)
            if _word(data, 8) >= 0x1020:
                raise ValueError(
                    "ASUS selected byte offset exceeds native reply capacity"
                )
        elif export.startswith("Ex2TPW_07_"):
            data = _buffer(args, 0x204C)
            if export.endswith("WriteSystemOperationMode") and (
                not 4 <= _word(data, 4) <= 0x1020 or not 5 <= _word(data, 8) <= 0x1020
            ):
                raise ValueError("TPW saved reply lengths exceed native buffer bounds")
        elif export in (
            "Ex2ASUS_05_ModifyVheightDownStart",
            "Ex2ASUS_05_ModifyVheightStop",
        ):
            data = _buffer(args, 12)
            if _word(data, 8) > 0x1020:
                raise ValueError(
                    "ASUS selected active-test length exceeds native capacity"
                )
        elif export in (
            "Ex2ASUS_05_CheckModifiedVheight",
            "Ex2ASUS_05_CheckReturnedVheight",
            "Ex2ASUS_05_LearnKneelDownVheight",
        ):
            data = _buffer(args, 14 if export.endswith("CheckModifiedVheight") else 13)
            if _word(data, 0) >= 0x1020 or _word(data, 4) > 0x1020:
                raise ValueError("ASUS selected read layout exceeds native capacity")
        elif export == "Ex2ASUS_04_ModifyVhight":
            data = _buffer(args, 20)
            if _word(data, 8) > 0x1020:
                raise ValueError(
                    "ASUS selected active-test length exceeds native capacity"
                )
        elif export in (
            "Ex2ASUS_04_LearnKneeldownVheight",
            "Ex2ASUS_04_CheckReturnedVhight",
        ):
            data = _buffer(args, 13)
            if _word(data, 0) >= 0x1020 or _word(data, 4) > 0x1020:
                raise ValueError("ASUS selected read layout exceeds native capacity")
        elif export in ("Ex2ASUS_04_SupportCheck", "Ex2ASUS_05_SupportCheck"):
            data = _buffer(args, 12)
        elif export == "Ex2ASUS_13_SupportCheck":
            data = _buffer(args, 16)
        elif export == "Ex2ASUS_13_TestStart" or (
            export == "Ex2ASUS_13_TestStop" and len(self.contract.asus13_stop) > 1
        ):
            data = _buffer(args, 16)
            if _word(data, 12) > 0x101D:
                raise ValueError(
                    "ASUS selected active-test length exceeds native capacity"
                )
        elif export in (
            "Ex2ARS_01_A8SupportCheck",
            "Ex2ARS_02_SupportCheck",
            "Ex2ARS_03_SupportCheck",
        ):
            data = _buffer(args, 8 if export == "Ex2ARS_01_A8SupportCheck" else 12)
        elif export == "Ex2VGRS_04_StartLockRelease":
            data = _buffer(args, 4)
            if _word(data, 0) > 0x1020:
                raise ValueError(
                    "VGRS selected active-test length exceeds native capacity"
                )
        elif export in ("Ex2ABS_33_SupportCheck", "Ex2ABS_33_CheckSensorStatus"):
            data = _buffer(args, 22)
        elif export == "Ex2EPB_05_SendMessage":
            data = _buffer(args, 4)
        elif export in (
            "Ex2EMPS_09_ModeTransition",
            "Ex2EMPS_09_SupportCheck",
            "Ex2EMPS_11_SendMessage",
        ):
            data = _buffer(args, 8)
        elif export.startswith("Ex2DRS_02_") and not export.endswith("StopActiveTest"):
            data = _buffer(args, 28)
            if not export.endswith("SupportCheck") and (
                any(_word(data, i) >= 0x1020 for i in (0, 4, 8))
                or any(_word(data, i) > 0x1020 for i in (12, 16))
            ):
                raise ValueError("DRS selected lengths/offsets exceed native capacity")
        elif export.startswith("Ex2DRS_03_") and not export.endswith("StopActiveTest"):
            data = _buffer(args, 20)
            if not export.endswith("SupportCheck") and (
                any(_word(data, i) > 0x1020 for i in (0, 4))
                or _word(data, 16) >= 0x1020
            ):
                raise ValueError("DRS selected lengths/offset exceed native capacity")
        elif export == "Ex2EMPS_07_ConfirmTheAssistMap":
            data = _buffer(args, 2)
        elif export == "Ex2EKDSS_01_SendMessage":
            data = _buffer(args, 6)
        elif export.startswith("Ex2ABS_52_"):
            data = _buffer(
                args, 52 if export.endswith("WriteBrakePadResidualThickness") else 36
            )
        elif export == "Ex2ABS_47_CheckCalibrationStatus":
            data = _buffer(args, 85)
        elif export == "Ex2ABS_47_DIDRIDSupportCheck":
            data = _buffer(args, 80)
        elif export.startswith("Ex2ABS_21_"):
            data = _buffer(args, 24 if export.endswith("ChangeMode") else 20)
            if (
                export.endswith("CheckSensorStatus")
                and not 2 <= _word(data, 16) <= 0x1020
            ):
                raise ValueError("ABS selected sensor length exceeds native capacity")
        elif export.startswith("Ex2ABS_18_"):
            data = _buffer(args, 20)
            if not export.endswith("SupportCheck") and (
                _word(data, 0) > 0x101E
                or any(_word(data, i) > 0x1020 for i in (4, 8, 12, 16))
            ):
                raise ValueError("ABS selected lengths/offset exceed native capacity")
        elif export.startswith("Ex2ABS_17_"):
            data = _buffer(args, 14 if export.endswith("GetABSInfo") else 12)
            if export.endswith("GetABSInfo") and (
                _word(data, 0) > 0x101E or _word(data, 4) > 0x1020
            ):
                raise ValueError("ABS selected read layout exceeds native capacity")
            if export.endswith("SychronizingABSInfo") and _word(data, 8) > 0x1020:
                raise ValueError("ABS selected write length exceeds native capacity")
        elif export in ("Ex2ABS_30_SendMessage", "Ex2ABS_46_SendMessage"):
            data = _buffer(args, 4)
        elif export.startswith("Ex2ABS_31_"):
            data = _buffer(args, 8 if export.endswith("SupportCheck") else 4)
        elif export == "Ex2ABS_49_PatternDriveExecutingFlag":
            data = _buffer(args, 8)
        elif export == "Ex2EMPS_12_ReadRoutineStatus":
            data = _buffer(args, 20)
        elif export == "Ex2EMPS_12_AutoRackCentering" and mode == 22:
            data = _buffer(args, 0x1038)
        elif export == "Ex2EMPS_12_SteeringAngleCheck":
            data = _buffer(args, 19)
        elif export in ("Ex2AHC_03_ReadModeStatus", "Ex2AHC_03_SwitchServiceMode"):
            data = _buffer(args, 4)
        else:
            if args and export in UNUSED_WRAPPER_BUFFER_EXPORTS:
                data = _buffer(args, 0)
            else:
                if args:
                    raise ValueError("chassis operation takes no arguments")
                data = bytearray()
        return data

    def _selected_body(
        self, export: str, comm: TYComm, data: bytearray, context: ChassisContext
    ) -> tuple[int, bool] | None:
        if export in (
            "Ex2BSM_09_10_19_20_SendMessage",
            "Ex2BSM_11_12_21_22_SendMessage",
        ):
            return self._bsm_multi(export, comm, data, context), False
        if export == "Ex2AHC_04_SendMessage":
            return self._ahc04(comm, data, context), False
        if export == "Ex24WD_05_SendMessage":
            return self._4wd05(comm, data, context)
        if export == "Ex24WD_05_WriteHistoryData":
            return self._4wd05_write_history(comm, data, context), True
        if export == "Ex24WD_05_SupportCheck":
            return self._4wd05_support(comm, data), True
        if export == "Ex24WD_08_SendMessage":
            return self._4wd08(comm, data, context)
        if export == "Ex24WD_06_SendMessage":
            return self._4wd06(comm, data, context)
        if export == "Ex2AWD_04_ReadValues":
            return self._awd04(comm, data, context), True
        if export == "Ex2TPW_03_SendMessage":
            return self._tpw03(comm, data, context), True
        if export == "Ex2TPW_08_SendMessage":
            return self._tpw08(comm, data, context)
        if export == "Ex2TPW_06_SendMessage":
            return self._tpw06(comm, data), True
        if export == "Ex2TPW_13_SendMessage":
            return self._tpw13(comm, data), True
        if export == "Ex2DRS_04_SendMessage":
            return self._drs04(comm, data), True
        if export == "Ex2ARS_05_SendMessage":
            return self._ars05(comm, data, context)
        if export in (
            "Ex2ASUS_08_StartCompressRaisingCtrl",
            "Ex2ASUS_08_StartTankPressLowCtrl",
        ):
            return self._asus08_control(export, comm, data, context)
        if export in ("Ex2ASUS_06_TheHeightAndTank", "Ex2ASUS_07_TheHeightAndTank"):
            return self._asus_height_tank(export, comm, context), True
        if export in ("Ex2ARS_02_InitCompVal", "Ex2ARS_03_ActiveTest"):
            return self._ars_calibrate(export, comm, data, context), True
        if export == "Ex2ABS_51_SendMessage":
            return self._abs51(comm, data, context)
        if export == "Ex2ARS_01_ReturnActuatorCenterPos":
            return self._ars_center(comm, data, context), True
        if export in ("Ex2VGRS_04_SupportCheck", "Ex2VGRS_04_CheckDTC"):
            return self._vgrs_support(export, comm, data, context), True
        if export == "Ex2ARS_04_SendMessage":
            return self._ars04(comm, data, context)
        if export == "Ex2EMPS_13_SendMessage":
            return self._emps13(comm, data)
        if export in ("Ex2BSM_03_04_SupportCheck", "Ex2BSM_05_06_SupportCheck"):
            return self._bsm_support(export, comm, data), True
        if export.startswith("Ex2BSM_01_02_"):
            return self._bsm_testmode(export, comm, data), True
        if export.startswith("Ex2BSM_07_08_"):
            return self._bsm_history(export, comm, data), True
        if export.startswith("Ex2ABS_21_"):
            return self._abs21(export, comm, data), True
        if export.startswith("Ex2ABS_18_"):
            return self._abs18(export, comm, data, context), True
        if export.startswith("Ex2ASUS_05_") and not export.endswith("SupportCheck"):
            return self._asus05(export, comm, data, context), True
        if export.startswith("Ex2ASUS_04_") and not export.endswith("SupportCheck"):
            return self._asus04(export, comm, data, context), True
        if export.startswith("Ex2ABS_17_"):
            return self._abs17(export, comm, data), True
        if export.startswith("Ex2DRS_02_") and not export.endswith("StopActiveTest"):
            return self._drs02(export, comm, data, context)
        if export.startswith("Ex2DRS_03_") and not export.endswith("StopActiveTest"):
            return self._drs03(export, comm, data, context)
        if export == "Ex2ABS_46_SendMessage":
            return self._abs46(comm, data, context), True
        if export == "Ex2ABS_30_SendMessage":
            return self._abs30(comm, data), True
        return None

    def run_body(
        self, export: str, args: tuple[object, ...], context: ChassisContext
    ) -> int:
        if (
            context.module_sha256 != self.contract.source_sha256
            or hashlib.sha256(context.module_bytes).hexdigest() != context.module_sha256
        ):
            raise TYSourceError("chassis selected module identity mismatch")
        if export not in SUPPORTED_EXPORTS:
            raise TYSourceError("chassis export has no reviewed native body")
        data = self._arguments(export, args, context.mode)
        if export == "Ex2ASUS_04_ModifyVhight" and _word(data, 16) not in (100, 200):
            # Native worker returns without publishing; closed-handle status becomes99.
            return 99
        if export == "Ex2AWD_04_Overwrite":
            return (
                1024  # 86380 publishes this native status without touching a manager.
            )
        if export == "Ex2ABS_48_RetrunWait":
            # b84f0/7d7b0 only sleep and publish; they never acquire a manager.
            context.sleep(20000)
            return 1001
        if export in (
            "Ex2AWD_04_ReadValues",
            "Ex2TPW_03_SendMessage",
            "Ex24WD_05_WriteHistoryData",
        ) or (
            export == "Ex24WD_05_SendMessage"
            and _word(data, 4) in (8, 10, 11)
            and data[0] in (4, 6)
        ):
            self._memory(context)
        comm = context.comm(
            self.contract.nk_manager
            if self.contract.nk_manager is not None and context.mode == 22
            else "selected"
            if export.startswith(
                (
                    "Ex2ABS_17_",
                    "Ex2ABS_18_",
                    "Ex2ABS_21_",
                    "Ex2ABS4WD_01_",
                    "Ex2BSM_27_",
                    "Ex2BSM_28_",
                    "Ex2ARS_01_",
                    "Ex2ARS_02_",
                    "Ex2ARS_03_",
                    "Ex2BSM_01_02_",
                    "Ex2BSM_07_08_",
                    "Ex2ASUS_04_",
                    "Ex2ASUS_05_",
                    "Ex2PSAABS_",
                    "Ex2ASUS_13_",
                    "Ex2VGRS_04_",
                    "Ex24WD_03_",
                    "Ex2EMPS_07_",
                    "Ex2DRS_02_",
                    "Ex2DRS_03_",
                    "Ex2DRS_04_",
                    "Ex2TPW_03_",
                )
            )
            or export in ("Ex2ASUS_04_SupportCheck", "Ex2ASUS_05_SupportCheck")
            or export
            in (
                "Ex2ARS_01_A8SupportCheck",
                "Ex2ARS_02_SupportCheck",
                "Ex2ARS_03_SupportCheck",
            )
            or export
            in (
                "Ex2BSM_03_04_ActiveTest",
                "Ex2BSM_03_04_ActiveTestCon3_5",
                "Ex2BSM_05_06_ActiveTest",
                "Ex2BSM_03_04_SupportCheck",
                "Ex2BSM_05_06_SupportCheck",
            )
            else self.contract.manager
        )
        cleanup = True
        try:
            if export.startswith("Ex2ABS4WD_01_"):
                cleanup = False
                return self._abs4wd(export, comm, data, context)
            if export in ("Ex2BSM_27_SendMessage", "Ex2BSM_28_SendMessage"):
                return self._bsm_target(export, comm, data, context)
            if export in (
                "Ex2ARS_01_ReadDTCofVGRS",
                "Ex2ARS_01_ReadDTCofARS",
                "Ex2ARS_01_ClearOffSetValue",
                "Ex2ARS_02_ChkVGRSDtc",
                "Ex2ARS_02_ChkARSDtc",
                "Ex2ARS_02_ClrCompVal",
            ):
                cleanup = False
                return self._ars_legacy(export, comm, context)
            selected = self._selected_body(export, comm, data, context)
            if selected is not None:
                status, cleanup = selected
                return status
            if export in ("Ex2DRS_02_StopActiveTest", "Ex2DRS_03_StopActiveTest"):
                comm.configure(self.contract.legacy_setter, 150)
                status, reply = self._raw(comm, b"\x30")
                if export == "Ex2DRS_02_StopActiveTest":
                    return status if len(reply) == 1 else 3
                return status or (0 if len(reply) == 1 else 3)
            if export.startswith("Ex2EMPS_07_"):
                return self._emps07(export, comm, data)
            if export in (
                "Ex2ASUS_08_ReadPressureSensor",
                "Ex2ASUS_08_ModeTransEnterHeightCtrlProhibit",
            ):
                status, cleanup = self._asus08(export, comm, data, context)
                return status
            if export in (
                "Ex2ASUS_06_LiftRise",
                "Ex2ASUS_06_AirPressure",
                "Ex2ASUS_07_LiftRise",
                "Ex2ASUS_07_AirPressure",
            ):
                status, cleanup = self._asus_motion(export, comm, data, context)
                return status
            if export in ("Ex2ASUS_06_ConditionCheck", "Ex2ASUS_07_ConditionCheck"):
                status = comm.initialize(0)
                if status:
                    return status
                comm.configure(self.contract.retry_setter, 0)
                comm.configure(self.contract.pending_setter, 180000)
                status = self._normal(comm)
                if not status:
                    status = comm.session(3, 1)
                if status:
                    return status
                status, _ = self._reply(
                    comm, b"\x2e\x21\1\1", 3, 2, positive_service=False
                )
                if not status:
                    cleanup = False
                    return 0
                self._normal(comm)
                return status
            if export.startswith("Ex24WD_03_"):
                return self._4wd03(export, comm, data, context)
            if export in ("Ex2ASUS_04_SupportCheck", "Ex2ASUS_05_SupportCheck"):
                return self._asus_support(comm, data)
            if export in (
                "Ex2ARS_01_A8SupportCheck",
                "Ex2ARS_02_SupportCheck",
                "Ex2ARS_03_SupportCheck",
            ):
                return self._ars_support(export, comm, data)
            if export in (
                "Ex2BSM_03_04_ActiveTest",
                "Ex2BSM_03_04_ActiveTestCon3_5",
                "Ex2BSM_05_06_ActiveTest",
            ):
                return self._bsm_active(export, comm, data, context)
            if export.startswith("Ex2VGRS_04_"):
                return self._vgrs04(export, comm, data, context)
            if export.startswith("Ex2ASUS_13_"):
                cleanup = export != "Ex2ASUS_13_GetHeight"
                return self._asus13(export, comm, data, context)
            if export == "Ex2EMPS_09_SupportCheck":
                data[:8] = bytes(8)
                status = self._initialize(comm)
                if status:
                    return status
                status, reply = self._reply(comm, b"\x31\1\x10\1", 7, 3)
                flags = b"\0\0"
                if not status and reply[6] & 64:
                    status, reply = self._reply(comm, b"\x31\1\x11\0", 5, 3)
                    if not status:
                        # a3370 copies two bytes from its zero-filled reply buffer.
                        flags = reply[4:6].ljust(2, b"\0")
                normal = self._normal(comm)
                if not status:
                    _put(data, 0, int(bool(flags[0] & 32)))
                    _put(data, 4, int(bool(flags[1] & 128)))
                return status or normal
            if export.startswith("Ex2ABS_31_"):
                return self._abs31(export, comm, data, context)
            if export == "Ex2ABS_47_DIDRIDSupportCheck":
                return self._abs47_support(comm, data)
            if export.startswith("Ex2PSAABS_"):
                status, cleanup = self._psa(export, data, comm, context)
                return status
            if export == "Ex2ABS_41_DIDSupportCheck":
                status = self._initialize(comm)
                if status:
                    return status
                for request, minimum, exact, masks in (
                    (b"\x22\1\1", 35, True, ((8, 128),)),
                    (b"\x22\x28\0", 35, True, ((3, 0x40),)),
                    (b"\x22\x28\2", 6, False, ((3, 0xAA), (5, 0x38))),
                ):
                    status, reply = self._reply(comm, request, minimum, 2)
                    if not status and exact and len(reply) != minimum:
                        status = 3
                    if status:
                        self._normal(comm)
                        return status
                    if any(reply[offset] & mask != mask for offset, mask in masks):
                        self._normal(comm)
                        return 99
                return self._normal(comm)
            if export == "Ex2ABS_41_DriveSolenoid":
                status = self._initialize(comm)
                if status:
                    return status
                selection = _word(data, 0)
                inlet = {1: 2, 2: 8, 3: 32}.get(selection, 128)
                outlet = 16 if selection in (1, 4) else 32
                for on, off in (
                    (
                        b"\x2f\x28\2\3\0"
                        + inlet.to_bytes(4, "little")
                        + inlet.to_bytes(2, "little")
                        + b"\0",
                        b"\x2f\x28\2\0\0" + inlet.to_bytes(2, "little") + b"\0",
                    ),
                    (
                        b"\x2f\x28\2\3\0"
                        + (outlet << 16).to_bytes(4, "little")
                        + b"\0\0"
                        + bytes((outlet,)),
                        b"\x2f\x28\2\0\0\0\0" + bytes((outlet,)),
                    ),
                ):
                    start = context.ticks()
                    while True:
                        status, _ = self._reply(comm, on, 4, 3)
                        if status or context.is_cancelled():
                            self._reply(comm, off, 4, 3)
                            self._normal(comm)
                            return 1000
                        context.sleep(1000)
                        if elapsed_ticks(context.ticks(), start) >= 4000:
                            break
                    self._reply(comm, off, 4, 3)
                return self._normal(comm)
            if export in ("Ex2ABS_32_SupportCheck", "Ex2ABS_32_EPBFullReleaseAndCheck"):
                if export == "Ex2ABS_32_SupportCheck":
                    status = self._initialize(comm)
                    if status:
                        return status
                    for request, minimum, offset, mask in (
                        (b"\x22\1\1", 6, 5, 128),
                        (b"\x22\x10\0", 12, 11, 8),
                        (b"\x31\1\x10\1", 7, 6, 0x40),
                        (b"\x31\1\x11\0", 7, 6, 8),
                    ):
                        status, reply = self._reply(
                            comm, request, minimum, 2 if request[0] == 0x22 else 3
                        )
                        if status:
                            break
                        if not reply[offset] & mask:
                            status = 99
                            break
                    normal = self._normal(comm)
                    return status or normal
                status = self._open(comm)
                if status:
                    return status
                status = comm.session(1, 1)
                if not status:
                    status = comm.session(3, 1)
                if status:
                    return 1001
                status, _ = self._reply(comm, b"\x31\1\x11\x15\2", 4, 3)
                if not status:
                    context.sleep(10000)
                    status, reply = self._reply(comm, b"\x22\x10\x45", 5, 2)
                    if not status and reply[3:5] != b"\5\5":
                        status = 1003
                self._normal(comm)
                return status
            if export in (
                "Ex2BSM_13_14_23_24_SendMessage",
                "Ex2BSM_15_16_25_26_SendMessage",
            ):
                reading = export == "Ex2BSM_13_14_23_24_SendMessage"
                if reading:
                    data[:0x1024] = bytes(0x1024)
                status = self._initialize(comm, grouped_session=True)
                if status:
                    return status
                if reading:
                    status, payload = self._bsm_read(comm, 0x50)
                    if status:
                        status = 2000
                    else:
                        data[: len(payload)] = payload
                        _put(data, 0x1020, len(payload))
                else:
                    status = self._bsm15(data, comm, context)
                comm.session(1, 1, stop_on_error=True)
                return status
            if export.startswith("Ex24WD_07_"):
                if export == "Ex24WD_07_SupportCheck":
                    status = self._initialize(comm)
                    if status:
                        return status
                    status = self._4wd_support(comm, data)
                    normal = self._normal(comm)
                    return status or normal
                code = self._4wd_selector(data, 1)
                if export == "Ex24WD_07_BackupMemoryClear1st":
                    status = self._initialize(comm)
                    if not status:
                        status = self._4wd_start(comm, data, code)
                        if not status:
                            cleanup = False
                            return 1000
                        self._normal(comm)
                    cleanup = status != 1000
                    return status
                for phase in range(1, 6):
                    code = self._4wd_selector(data, phase)
                    if phase > 1:
                        if not code:
                            continue
                        status = self._4wd_start(comm, data, code)
                        if status:
                            self._normal(comm)
                            return status
                    status = self._4wd_poll(comm, data, code, context)
                    if status:
                        normal = self._normal(comm)
                        return 1001 if status == 1001 else normal or 1002
                return self._normal(comm)
            if export in ("Ex2ABS_29_SupportCheck", "Ex2ABS_29_ShiftDealerMode"):
                return self._abs29(export, comm, context)
            if export.startswith("Ex2ASUS_10_"):
                return self._asus10(export, data, context, comm)
            if export == "Ex2EPB_05_SendMessage":
                status = self._open(comm)
                if status or _word(data, 0) not in (0, 1):
                    return status
                status = comm.session(3, 1, normal_first=True)
                if status:
                    return status
                if _word(data, 0) == 0:
                    status = self._brake_support(comm)
                    normal = comm.session(1, 1, stop_on_error=True)
                    return status or normal
                status, _ = self._reply(comm, b"\x31\1\x11\x0c\1", 4, 3)
                if not status:
                    context.sleep(4000)
                    status, reply = self._reply(comm, b"\x22\x10\x2d", 13, 2)
                    if not status and not reply[12] & 8:
                        status = 3
                self._normal(comm)
                return 2001 if status else 0
            if export.startswith("Ex2TPW_07_"):
                return self._tpw07(export, data, comm)
            if export == "Ex2EMPS_12_SteeringStart":
                status = self._initialize(comm)
                cleanup = bool(status)
                return status
            if export in ("Ex2ABS_44_SendMessage", "Ex2EPB_04_SendMessage"):
                status = self._initialize(comm, grouped_session=True)
                if not status:
                    context.sleep(500)
                    status, _ = self._reply(comm, b"\x31\1\x11\x1e", 4, 3)
                    comm.session(1, 1, stop_on_error=True)
                return status
            if export == "Ex2EMPS_11_SendMessage":
                if _word(data, 0) != 1:
                    status = self._initialize(comm, grouped_session=True)
                    if status:
                        return status
                    status, _ = self._reply(comm, b"\x31\1\x11\x0b", 4, 3)
                    if status:
                        comm.session(1, 1, stop_on_error=True)
                    cleanup = bool(status)
                    return status
                status = 0
                while not _word(data, 4) and not context.is_cancelled():
                    status, reply = self._reply(comm, b"\x31\3\x11\x0b", 5, 3)
                    if status or reply[4] != 1:
                        break
                else:
                    reply = b""
                if status or not reply or reply[4] != 2:
                    self._reply(comm, b"\x31\2\x11\x0b", 4, 3)
                    if not status and reply and reply[4] not in (1, 2):
                        status = 2000
                comm.session(1, 1, stop_on_error=True)
                return status
            if export == "Ex2ABS_34_InitAllMemVal":
                status = self._initialize(comm)
                if not status:
                    context.sleep(500)
                    status, _ = self._reply(comm, b"\x31\1\x11\x1b", 4, 3)
                    self._normal(comm)
                return status
            if export == "Ex2ABS_33_ShiftNormalMode":
                minimum = 5 if self.contract.nk_manager and context.mode == 22 else 4
                self._abs33_restore(comm, minimum)
                return 0
            if export == "Ex2ABS_33_CheckSensorStatus":
                status, reply = self._reply(comm, b"\x22\x10\x30", 7, 2)
                if not status:
                    if self._abs33_sensors(data, reply):
                        cleanup = False
                        return 1000
                    status = 3
                if status == 1000:
                    cleanup = False
                    return 1000
                self._abs33_restore(comm)
                return 3
            if export in ("Ex2ABS_33_SupportCheck", "Ex2ABS_33_ShiftDealerMode"):
                status = self._initialize(comm)
                if status:
                    return status
                if export == "Ex2ABS_33_SupportCheck":
                    return self._abs33_support(comm, data)
                status, _ = self._reply(comm, b"\x31\1\x11\x0c\1", 4, 3)
                if status:
                    self._abs33_restore(comm)
                    return 1001
                cleanup = False
                return 0
            if export == "Ex2ASUS_08_EndExtendedSession":
                return 1000 if self._normal(comm) else 0
            if export == "Ex2ABS_47_EndExtendedSession":
                self._normal(comm)
                return 0
            if export == "Ex2EMPS_09_ModeTransition":
                status = self._initialize(comm)
                if status:
                    return status
                if _word(data, 4):
                    status, _ = self._reply(comm, b"\x31\x01\x11\x09", 4, 3)
                if not status:
                    status, _ = self._reply(comm, b"\x31\x01\x10\x02", 4, 3)
                    if not status and _word(data, 0):
                        context.sleep(5000)
                        status, _ = self._reply(comm, b"\x31\x01\x11\x03", 4, 3)
                if status:
                    self._normal(comm)
                    return 1007
                return 0
            if export == "Ex2EKDSS_01_SendMessage":
                if not _word(data, 0):
                    status = self._initialize(comm, grouped_session=True)
                    if status:
                        return status
                    status, reply = self._reply(
                        comm, b"\x31\x01\x11\x01" + bytes((data[5], 0, 0)), 4, 3
                    )
                    if not status and len(reply) != 4:
                        status = 3
                    if not status:
                        cleanup = False
                        return 0
                    comm.session(1, 1, stop_on_error=True)
                    return status
                status, reply = self._reply(comm, b"\x31\x02\x11\x01", 4, 3)
                if not status and len(reply) != 4:
                    status = 3
                comm.session(1, 1, stop_on_error=True)
                return status
            if export == "Ex2EKDSS_02_SendMessage":
                status = self._initialize(comm, grouped_session=True)
                if status:
                    return status
                status, _ = self._reply(comm, b"\x31\x01\x11\x02\0", 4, 3)
                comm.session(1, 1, stop_on_error=True)
                return 1000 if status else 0
            if export.startswith("Ex2ABS_52_"):
                status = self._initialize(comm)
                if status:
                    return status
                try:
                    writing = export == "Ex2ABS_52_WriteBrakePadResidualThickness"
                    if writing:
                        status, _ = self._reply(
                            comm,
                            b"\x2e\x20\x07" + bytes(data[36:52]),
                            3,
                            2,
                            positive_service=False,
                        )
                        if status:
                            self._normal(comm)
                            return status
                        context.sleep(1000)
                    status, reply = self._reply(
                        comm, b"\x22\x10\xb9", 19, 2, positive_service=False
                    )
                    if status:
                        self._normal(comm)
                        return status
                    data[4:20] = reply[3:19]
                    status, reply = self._reply(
                        comm, b"\x22\x20\x07", 19, 2, positive_service=False
                    )
                    if not status:
                        data[20:36] = reply[3:19]
                        if writing and (
                            data[36:52] != data[4:20] or data[36:52] != data[20:36]
                        ):
                            status = 3
                    self._normal(comm)
                    return status
                except BaseException:
                    self._cleanup_normal_after_host_fault(comm)
                    raise
            if export in ABS48_EXPORTS:
                status, cleanup = self._abs48(export, context, comm)
                return status
            if export in (
                "Ex2ABS_47_ErrorEndExtendedSession",
                "Ex2ABS_47_ExitEndExtendedSession",
            ):
                self._normal(comm)
                return 3 if export == "Ex2ABS_47_ErrorEndExtendedSession" else 1002
            if export == "Ex2ABS_47_CheckCalibrationStatus":
                # b7b00 deliberately keeps manager/session alive after worker exit.
                cleanup = False
                while not _word(data, 0) and not context.is_cancelled():
                    context.sleep(500)
                    status, reply = self._reply(comm, b"\x22\x10\xb4", 5, 2)
                    if status:
                        return status
                    for index in range(7):
                        data[(index + 1) * 12] = int(bool(reply[4] & (128 >> index)))
                return 1000
            if export == "Ex2ABS_47_ShiftToDealerMode":
                status = self._initialize(comm)
                if status:
                    return status
                status, _ = self._reply(comm, b"\x31\x01\x11\x0c\x01", 4, 3)
                if not status:
                    context.sleep(4000)
                    status, reply = self._reply(comm, b"\x22\x10\x2d", 13, 2)
                    if not status and reply[12] & 8:
                        cleanup = False
                        return 0
                self._normal(comm)
                return 1001
            if export in ("Ex2ABS_41_DriveMotor", "Ex2ABS_41_StopMotor"):
                stop = b"\x2f\x28\x02\0\0\0\0\x08"
                if export == "Ex2ABS_41_DriveMotor":
                    status = self._initialize(comm)
                    if status:
                        return status
                    status, _ = self._reply(
                        comm, b"\x2f\x28\x02\x03\0\0\0\x08\0\0\0\x08", 4, 3
                    )
                    if not status:
                        cleanup = False
                        return 0
                    self._reply(comm, stop, 4, 3)
                    self._normal(comm)
                    return 1000
                status, _ = self._reply(comm, stop, 4, 3)
                normal = self._normal(comm)
                return 1000 if status else normal
            if export.startswith("Ex2ABS_49_"):
                cleanup = False
                return self._abs49(export, data, context, comm)
            if export == "Ex2AHC_03_EndExtendedSession":
                self._normal(comm)
                return 1000  # c2890 discards restore status and publishes cancellation.
            if export in ("Ex2AHC_03_ReadModeStatus", "Ex2EMPS_12_AutoRackCentering"):
                status = self._initialize(comm)
                if status:
                    return status
                try:
                    if export == "Ex2AHC_03_ReadModeStatus":
                        status = self._ahc_read(comm, data)
                    elif context.mode == 22:
                        status, reply = self._reply(
                            comm, b"\x22\x20\x13", 5, 2, positive_service=False
                        )
                        if not status:
                            data[0x13 : 0x13 + len(reply)] = reply
                            _put(data, 0x1034, len(reply))
                            request = b"\x2e\x20\x13\x01\x90" + reply[5:]
                            status, _ = self._reply(
                                comm, request, 3, 2, positive_service=False
                            )
                        if not status:
                            status, _ = self._reply(
                                comm,
                                b"\x31\x01\x11\x0a",
                                5,
                                3,
                                positive_service=False,
                            )
                    else:
                        status, _ = self._reply(
                            comm,
                            b"\x31\x01\x11\x0a",
                            4,
                            3,
                            positive_service=False,
                        )
                    cleanup = bool(status)
                    if status:
                        self._normal(comm)
                    return status
                except BaseException:
                    if export == "Ex2EMPS_12_AutoRackCentering":
                        self._cleanup_normal_after_host_fault(comm)
                    raise
            if export == "Ex2AHC_03_SwitchServiceMode":
                request = b"\x31\x01\x11\xa6" + bytes((0 if _word(data, 0) else 255,))
                status, _ = self._reply(comm, request, 4, 3)
                if not status:
                    context.sleep(200)
                    status = self._ahc_read(comm, data)
                    if not status:
                        return self._normal(comm)
                self._normal(comm)
                return status
            if export == "Ex2EMPS_12_SteeringAngleCheck":
                status = 0
                host_cancelled = False
                try:
                    while not _word(data, 8):
                        if context.is_cancelled():
                            status = 1000
                            host_cancelled = True
                            break
                        status, reply = self._reply(
                            comm, b"\x22\x11\x2e", 5, 2, positive_service=False
                        )
                        if status:
                            break
                        data[17:19] = reply[3:5]
                        _put(data, 12, 1)
                except BaseException:
                    self._cleanup_normal_after_host_fault(comm)
                    raise
                if host_cancelled:
                    comm.cleanup_session(1, 1)
                else:
                    try:
                        self._normal(comm)
                    except BaseException:
                        self._cleanup_normal_after_host_fault(comm)
                        raise
                return status
            if export != "Ex2EMPS_12_ReadRoutineStatus":
                raise TYSourceError("chassis operation has no concrete native dispatch")
            # b1920 polls result byte 0x10; cancel flag 0, exit flag 4.
            while True:
                if _word(data, 0) or context.is_cancelled():
                    status = 1000
                    break
                if _word(data, 4):
                    status = 1001
                    break
                context.sleep(500)
                status, reply = self._reply(comm, b"\x31\x03\x11\x0a", 5, 3)
                if status:
                    break
                data[16] = reply[4]
                if reply[4] == 2:
                    return self._normal(comm)
                if reply[4] != 1:
                    status = 1001
                    break
            self._reply(comm, b"\x31\x02\x11\x0a", 4, 3)
            self._normal(comm)
            return status
        except BaseException:
            if export in (
                "Ex2EMPS_12_AutoRackCentering",
                "Ex2EMPS_12_SteeringAngleCheck",
                "Ex2EMPS_12_SteeringStart",
                "Ex2ASUS_10_GetStatOfHeightCtrlProhibition",
                "Ex2ASUS_10_ChgAndGetStatOfHeightCtrlProhibition",
                "Ex2ABS_52_ReadBrakePadResidualThickness",
                "Ex2ABS_52_WriteBrakePadResidualThickness",
                "Ex2ABS_29_SupportCheck",
                "Ex2ABS_29_ShiftDealerMode",
            ):
                cleanup = False
                with suppress(BaseException):
                    comm.finalize()
            else:
                cleanup = True
            raise
        finally:
            if cleanup:
                comm.finalize()


def run_body(export: str, args: tuple[object, ...], context: ChassisContext) -> int:
    if not supports(context.module_sha256, export):
        raise TYSourceError("chassis source/export pair has no reviewed native body")
    if context.module_sha256 == SHA_PLUS_TY and export == "Ex2AWD_04_Overwrite":
        # Plus88a30 independently checked: wrapper admits20/21, body publishes1024.
        if hashlib.sha256(context.module_bytes).hexdigest() != context.module_sha256:
            raise TYSourceError("chassis selected module identity mismatch")
        if args:
            _buffer(args, 0)
        return 1024
    contract = {SHA_12_TY: CONTRACT_12, SHA_PLUS_TY: CONTRACT_PLUS}.get(
        context.module_sha256, CONTRACT_18
    )
    return ChassisEngine(contract).run_body(export, args, context)
